// Package mcpoauth owns F13's resource-bound OAuth authorization-code flow.
// It stores only sealed credentials and has no runtime credential handoff;
// F14 is the first story allowed to consume a connected credential.
package mcpoauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/publicurl"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
)

var (
	ErrInvalidInput     = errors.New("invalid MCP OAuth input")
	ErrFlowNotFound     = errors.New("MCP OAuth flow not found")
	ErrExchange         = errors.New("MCP OAuth exchange failed")
	ErrMetadata         = errors.New("MCP OAuth issuer metadata rejected")
	ErrAlreadyConnected = errors.New("MCP OAuth connection is already connected")
	ErrLease            = errors.New("MCP OAuth runtime lease is unavailable")
)

type StartInput struct {
	OrgID, DeviceID, ActorID   uuid.UUID
	Endpoint, Resource, Issuer string
	Scopes                     []string
	ClientID, ClientSecret     string
}

type StartResult struct {
	ConnectionID uuid.UUID
	RedirectURL  string
	// Binding is returned to the browser that started consent, as a cookie. The
	// callback must present it: a forwarded authorization link is useless in
	// any other browser.
	Binding string
}

type Connection struct {
	ID                         uuid.UUID
	Endpoint, Resource, Issuer string
	Scopes                     []string
	ClientID                   string
	ClientSecretFingerprint    *string
	State                      string
	FailureCode                *string
	TokenExpiresAt             *time.Time
	ConnectedAt                *time.Time
	CreatedAt, UpdatedAt       time.Time
}

type Service struct {
	queries     *sqlc.Queries
	sealer      *crypto.Sealer
	rdb         *redis.Client
	callbackURL string
	http        *http.Client
}

func New(queries *sqlc.Queries, sealer *crypto.Sealer, rdb *redis.Client, callbackURL string) *Service {
	return &Service{queries: queries, sealer: sealer, rdb: rdb, callbackURL: strings.TrimSuffix(callbackURL, "/") + "/api/v1/mcp/oauth/callback", http: newOAuthHTTPClient()}
}

func (s *Service) Start(ctx context.Context, in StartInput) (StartResult, error) {
	if s == nil || s.queries == nil || s.sealer == nil || s.rdb == nil || in.OrgID == uuid.Nil || in.DeviceID == uuid.Nil || in.ActorID == uuid.Nil || !validURL(in.Endpoint) || !validURL(in.Resource) || !validURL(in.Issuer) || strings.TrimSpace(in.ClientID) == "" {
		return StartResult{}, ErrInvalidInput
	}
	in.Endpoint, in.Resource, in.Issuer = canonicalURL(in.Endpoint), canonicalURL(in.Resource), canonicalURL(in.Issuer)
	in.Scopes = cleanScopes(in.Scopes)
	if len(in.Scopes) == 0 {
		return StartResult{}, ErrInvalidInput
	}
	metadata, err := s.authorizationMetadata(ctx, in.Issuer)
	if err != nil || !metadata.allowsResource(in.Resource) {
		return StartResult{}, ErrMetadata
	}
	existing, err := s.List(ctx, in.OrgID, in.DeviceID)
	if err != nil {
		return StartResult{}, err
	}
	for _, connection := range existing {
		if connection.Endpoint == in.Endpoint && connection.State == "connected" {
			return StartResult{}, ErrAlreadyConnected
		}
	}
	var sealed *string
	var fingerprint *string
	if strings.TrimSpace(in.ClientSecret) != "" {
		value, err := s.sealer.Seal([]byte(in.ClientSecret))
		if err != nil {
			return StartResult{}, err
		}
		sealed = &value
		fp := s.sealer.Fingerprint([]byte(in.ClientSecret))
		fingerprint = &fp
	}
	scopesJSON, _ := json.Marshal(in.Scopes)
	row, err := s.queries.UpsertAgentMCPOAuthConnection(ctx, sqlc.UpsertAgentMCPOAuthConnectionParams{OrgID: in.OrgID, DeviceID: in.DeviceID, Endpoint: in.Endpoint, ProtectedResource: in.Resource, Issuer: in.Issuer, Scopes: scopesJSON, ClientID: strings.TrimSpace(in.ClientID), ClientSecretSealed: sealed, ClientSecretFingerprint: fingerprint, State: "pending_consent"})
	if err != nil {
		return StartResult{}, err
	}
	state, err := sso.RandomToken()
	if err != nil {
		return StartResult{}, err
	}
	verifier, challenge, err := sso.PKCE()
	if err != nil {
		return StartResult{}, err
	}
	callbackURL := s.callbackURL
	if base := publicurl.From(ctx, ""); base != "" {
		callbackURL = strings.TrimSuffix(base, "/") + "/api/v1/mcp/oauth/callback"
	}
	binding, err := sso.RandomToken()
	if err != nil {
		return StartResult{}, err
	}
	flow, err := json.Marshal(flowState{ConnectionID: row.ID, OrgID: in.OrgID, ActorID: in.ActorID, DeviceID: in.DeviceID, Resource: in.Resource, Verifier: verifier, TokenEndpoint: metadata.TokenEndpoint, CallbackURL: callbackURL, BindingHash: bindingHash(binding)})
	if err != nil {
		return StartResult{}, err
	}
	if err := s.rdb.Set(ctx, flowKey(state), flow, 10*time.Minute).Err(); err != nil {
		return StartResult{}, err
	}
	auth, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return StartResult{}, ErrMetadata
	}
	q := auth.Query()
	q.Set("response_type", "code")
	q.Set("client_id", strings.TrimSpace(in.ClientID))
	q.Set("redirect_uri", callbackURL)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", in.Resource)
	q.Set("scope", strings.Join(in.Scopes, " "))
	auth.RawQuery = q.Encode()
	return StartResult{ConnectionID: row.ID, RedirectURL: auth.String(), Binding: binding}, nil
}

// Complete finishes consent. binding is the value Start handed to the browser
// that began the flow; code is empty when the authorization server reports that
// consent was refused. The returned device lets the caller send the browser
// back to the agent it was configuring, and is uuid.Nil when the flow is
// unknown.
func (s *Service) Complete(ctx context.Context, state, code, binding string) (uuid.UUID, error) {
	if strings.TrimSpace(state) == "" {
		return uuid.Nil, ErrFlowNotFound
	}
	data, err := s.rdb.GetDel(ctx, flowKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, ErrFlowNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	var flow flowState
	if json.Unmarshal(data, &flow) != nil || flow.ConnectionID == uuid.Nil || flow.OrgID == uuid.Nil || flow.ActorID == uuid.Nil || flow.Verifier == "" || !validURL(flow.Resource) || !validURL(flow.TokenEndpoint) {
		return uuid.Nil, ErrFlowNotFound
	}
	// The flow is single-use and already consumed, so a wrong or missing
	// binding cannot be retried against the same state.
	if flow.BindingHash == "" || subtle.ConstantTimeCompare([]byte(bindingHash(binding)), []byte(flow.BindingHash)) != 1 {
		s.failWith(ctx, flow, "consent_browser_mismatch")
		return flow.DeviceID, ErrFlowNotFound
	}
	if strings.TrimSpace(code) == "" {
		s.failWith(ctx, flow, "consent_refused")
		return flow.DeviceID, ErrExchange
	}
	return flow.DeviceID, s.exchange(ctx, flow, code)
}

func (s *Service) exchange(ctx context.Context, flow flowState, code string) error {
	row, err := s.queries.GetAgentMCPOAuthConnectionForCallback(ctx, sqlc.GetAgentMCPOAuthConnectionForCallbackParams{ID: flow.ConnectionID, OrgID: flow.OrgID})
	if err != nil || row.ProtectedResource != canonicalURL(flow.Resource) || row.State != "pending_consent" || !sameOrigin(row.Issuer, flow.TokenEndpoint) {
		return ErrFlowNotFound
	}
	secret := ""
	if row.ClientSecretSealed != nil {
		plain, err := s.sealer.Open(*row.ClientSecretSealed)
		if err != nil {
			return ErrExchange
		}
		secret = string(plain)
	}
	// Bind the exchange to the address used at consent time, even if the
	// administrator changed the canonical portal URL during the round trip.
	callbackURL := flow.CallbackURL
	if callbackURL == "" {
		callbackURL = s.callbackURL // Flows created before runtime domain settings.
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callbackURL}, "client_id": {row.ClientID}, "code_verifier": {flow.Verifier}, "resource": {flow.Resource}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, flow.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrExchange
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.doOAuthRequest(req)
	if err != nil {
		s.fail(ctx, flow)
		return ErrExchange
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		s.fail(ctx, flow)
		return ErrExchange
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil || strings.TrimSpace(token.AccessToken) == "" {
		s.fail(ctx, flow)
		return ErrExchange
	}
	access, err := s.sealer.Seal([]byte(token.AccessToken))
	if err != nil {
		return err
	}
	var refresh *string
	if token.RefreshToken != "" {
		value, err := s.sealer.Seal([]byte(token.RefreshToken))
		if err != nil {
			return err
		}
		refresh = &value
	}
	expires := pgtype.Timestamptz{}
	if token.ExpiresIn > 0 && token.ExpiresIn <= 31_536_000 {
		expires = pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second), Valid: true}
	}
	changed, err := s.queries.ConnectAgentMCPOAuthConnection(ctx, sqlc.ConnectAgentMCPOAuthConnectionParams{ID: row.ID, OrgID: flow.OrgID, AccessTokenSealed: &access, RefreshTokenSealed: refresh, TokenExpiresAt: expires, ConnectedByUserID: pgtype.UUID{Bytes: flow.ActorID, Valid: true}})
	if err != nil || changed != 1 {
		return ErrExchange
	}
	s.audit(ctx, flow.OrgID, flow.ActorID, "agent.mcp_oauth.connected", row.ID, map[string]any{"device_id": row.DeviceID.String(), "endpoint": row.Endpoint, "issuer": row.Issuer})
	return nil
}

// Disconnect discards the sealed tokens so the runtime stops receiving a
// credential at its next lease. Consent can be started again afterwards.
func (s *Service) Disconnect(ctx context.Context, orgID, deviceID, connectionID, actor uuid.UUID) error {
	if s == nil || s.queries == nil || orgID == uuid.Nil || deviceID == uuid.Nil || connectionID == uuid.Nil {
		return ErrInvalidInput
	}
	row, err := s.queries.GetAgentMCPOAuthConnection(ctx, sqlc.GetAgentMCPOAuthConnectionParams{ID: connectionID, OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return ErrFlowNotFound
	}
	changed, err := s.queries.DisconnectAgentMCPOAuthConnection(ctx, sqlc.DisconnectAgentMCPOAuthConnectionParams{ID: connectionID, OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return err
	}
	if changed == 1 {
		s.audit(ctx, orgID, actor, "agent.mcp_oauth.disconnected", connectionID, map[string]any{"device_id": deviceID.String(), "endpoint": row.Endpoint})
	}
	return nil
}

// List is deliberately a secret-free projection. It does not select any sealed
// ciphertext and is safe for the privileged agent-read surface.
func (s *Service) List(ctx context.Context, orgID, deviceID uuid.UUID) ([]Connection, error) {
	rows, err := s.queries.ListAgentMCPOAuthConnections(ctx, sqlc.ListAgentMCPOAuthConnectionsParams{OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(rows))
	for _, row := range rows {
		var scopes []string
		_ = json.Unmarshal(row.Scopes, &scopes)
		item := Connection{ID: row.ID, Endpoint: row.Endpoint, Resource: row.ProtectedResource, Issuer: row.Issuer, Scopes: scopes, ClientID: row.ClientID, ClientSecretFingerprint: row.ClientSecretFingerprint, State: row.State, FailureCode: row.FailureCode, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
		if row.TokenExpiresAt.Valid {
			v := row.TokenExpiresAt.Time
			item.TokenExpiresAt = &v
		}
		if row.ConnectedAt.Valid {
			v := row.ConnectedAt.Time
			item.ConnectedAt = &v
		}
		out = append(out, item)
	}
	return out, nil
}

// Lease is the narrow F14 token handoff. It is called only by a runtime bearer
// for its own device and returns plaintext only in that TLS response; callers
// must retain it in memory and must never report, log, or persist it locally.
func (s *Service) Lease(ctx context.Context, orgID, deviceID uuid.UUID, endpoint string) (string, time.Time, error) {
	if s == nil || s.queries == nil || s.sealer == nil || orgID == uuid.Nil || deviceID == uuid.Nil || !validURL(endpoint) {
		return "", time.Time{}, ErrLease
	}
	row, err := s.queries.GetAgentMCPOAuthConnectionForRuntime(ctx, sqlc.GetAgentMCPOAuthConnectionForRuntimeParams{OrgID: orgID, DeviceID: deviceID, Endpoint: canonicalURL(endpoint)})
	if err != nil || row.AccessTokenSealed == nil {
		return "", time.Time{}, ErrLease
	}
	now := time.Now().UTC()
	// An issuer that sends no expires_in issued a token without a stated
	// lifetime. It is handed out on a short lease horizon so a later disconnect
	// or re-consent still takes effect at the runtime within minutes.
	if !row.TokenExpiresAt.Valid || row.TokenExpiresAt.Time.After(now.Add(30*time.Second)) {
		plain, openErr := s.sealer.Open(*row.AccessTokenSealed)
		if openErr != nil || len(plain) == 0 {
			return "", time.Time{}, ErrLease
		}
		if !row.TokenExpiresAt.Valid {
			return string(plain), now.Add(nonExpiringLeaseHorizon), nil
		}
		return string(plain), row.TokenExpiresAt.Time, nil
	}
	if row.RefreshTokenSealed == nil {
		s.expire(ctx, row, "token_expired")
		return "", time.Time{}, ErrLease
	}
	refresh, openErr := s.sealer.Open(*row.RefreshTokenSealed)
	if openErr != nil || len(refresh) == 0 {
		return "", time.Time{}, ErrLease
	}
	metadata, metadataErr := s.authorizationMetadata(ctx, row.Issuer)
	if metadataErr != nil {
		return "", time.Time{}, ErrLease
	}
	secret := ""
	if row.ClientSecretSealed != nil {
		value, secretErr := s.sealer.Open(*row.ClientSecretSealed)
		if secretErr != nil {
			return "", time.Time{}, ErrLease
		}
		secret = string(value)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {string(refresh)}, "client_id": {row.ClientID}, "resource": {row.ProtectedResource}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if requestErr != nil {
		return "", time.Time{}, ErrLease
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, requestErr := s.doOAuthRequest(req)
	if requestErr != nil {
		return "", time.Time{}, ErrLease
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized {
		// RFC 6749 section 5.2: the issuer refused this refresh token. Retrying
		// cannot succeed, so the connection asks for consent again instead of
		// showing as connected while every call goes out unauthenticated.
		s.expire(ctx, row, "refresh_rejected")
		return "", time.Time{}, ErrLease
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", time.Time{}, ErrLease
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.NewDecoder(response.Body).Decode(&token) != nil || strings.TrimSpace(token.AccessToken) == "" || token.ExpiresIn < 0 || token.ExpiresIn > 31_536_000 {
		return "", time.Time{}, ErrLease
	}
	access, sealErr := s.sealer.Seal([]byte(token.AccessToken))
	if sealErr != nil {
		return "", time.Time{}, ErrLease
	}
	var nextRefresh *string
	if token.RefreshToken != "" {
		value, err := s.sealer.Seal([]byte(token.RefreshToken))
		if err != nil {
			return "", time.Time{}, ErrLease
		}
		nextRefresh = &value
	}
	stored, expires := pgtype.Timestamptz{}, now.Add(nonExpiringLeaseHorizon)
	if token.ExpiresIn > 0 {
		expires = now.Add(time.Duration(token.ExpiresIn) * time.Second)
		stored = pgtype.Timestamptz{Time: expires, Valid: true}
	}
	changed, updateErr := s.queries.RefreshAgentMCPOAuthConnection(ctx, sqlc.RefreshAgentMCPOAuthConnectionParams{ID: row.ID, OrgID: orgID, AccessTokenSealed: &access, RefreshTokenSealed: nextRefresh, TokenExpiresAt: stored})
	if updateErr != nil || changed != 1 {
		return "", time.Time{}, ErrLease
	}
	return token.AccessToken, expires, nil
}

const nonExpiringLeaseHorizon = 5 * time.Minute

type flowState struct {
	ConnectionID, OrgID, ActorID      uuid.UUID
	DeviceID                          uuid.UUID `json:",omitempty"`
	Resource, Verifier, TokenEndpoint string
	CallbackURL                       string `json:",omitempty"`
	BindingHash                       string `json:",omitempty"`
}

func bindingHash(binding string) string {
	if strings.TrimSpace(binding) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(binding))
	return hex.EncodeToString(sum[:])
}

func (s *Service) expire(ctx context.Context, row sqlc.AgentMcpOauthConnection, code string) {
	changed, err := s.queries.ExpireAgentMCPOAuthConnection(ctx, sqlc.ExpireAgentMCPOAuthConnectionParams{ID: row.ID, OrgID: row.OrgID, FailureCode: &code})
	if err == nil && changed == 1 {
		s.audit(ctx, row.OrgID, uuid.Nil, "agent.mcp_oauth.reconsent_required", row.ID, map[string]any{"device_id": row.DeviceID.String(), "endpoint": row.Endpoint, "reason": code})
	}
}

// audit is best effort: a credential state change must not be undone because
// its audit row could not be written, and the row never carries token material.
func (s *Service) audit(ctx context.Context, orgID, actor uuid.UUID, action string, connectionID uuid.UUID, meta map[string]any) {
	targetType, targetID := "agent_mcp_oauth_connection", connectionID.String()
	b, _ := json.Marshal(meta)
	_, _ = s.queries.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: actor != uuid.Nil}, Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: b})
}

func flowKey(state string) string { return "mcpoauth:" + state }

func (s *Service) fail(ctx context.Context, flow flowState) { s.failWith(ctx, flow, "exchange_failed") }

func (s *Service) failWith(ctx context.Context, flow flowState, code string) {
	changed, err := s.queries.FailAgentMCPOAuthConnection(ctx, sqlc.FailAgentMCPOAuthConnectionParams{ID: flow.ConnectionID, OrgID: flow.OrgID, FailureCode: &code})
	if err == nil && changed == 1 {
		s.audit(ctx, flow.OrgID, flow.ActorID, "agent.mcp_oauth.failed", flow.ConnectionID, map[string]any{"device_id": flow.DeviceID.String(), "reason": code})
	}
}

type authorizationMetadata struct {
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	ProtectedResources    []string `json:"protected_resources"`
}

func (m authorizationMetadata) allowsResource(resource string) bool {
	if len(m.ProtectedResources) == 0 {
		return true
	}
	for _, r := range m.ProtectedResources {
		if canonicalURL(r) == resource {
			return true
		}
	}
	return false
}
func (s *Service) authorizationMetadata(ctx context.Context, issuer string) (authorizationMetadata, error) {
	if !validURL(issuer) {
		return authorizationMetadata{}, ErrMetadata
	}
	u, _ := url.Parse(issuer)
	u.Path = strings.TrimSuffix(u.Path, "/") + "/.well-known/oauth-authorization-server"
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return authorizationMetadata{}, err
	}
	resp, err := s.doOAuthRequest(req)
	if err != nil {
		return authorizationMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authorizationMetadata{}, fmt.Errorf("metadata HTTP %d", resp.StatusCode)
	}
	var metadata authorizationMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return authorizationMetadata{}, err
	}
	if !validURL(metadata.AuthorizationEndpoint) || !validURL(metadata.TokenEndpoint) ||
		!sameOrigin(issuer, metadata.AuthorizationEndpoint) || !sameOrigin(issuer, metadata.TokenEndpoint) {
		return authorizationMetadata{}, ErrMetadata
	}
	return metadata, nil
}
func validURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func canonicalURL(raw string) string {
	u, _ := url.Parse(strings.TrimSpace(raw))
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}
func cleanScopes(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, scope := range in {
		scope = strings.TrimSpace(scope)
		if scope != "" && len(scope) <= 256 && !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	return out
}
