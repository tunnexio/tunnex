// Package mcpoauth owns F13's resource-bound OAuth authorization-code flow.
// It stores only sealed credentials and has no runtime credential handoff;
// F14 is the first story allowed to consume a connected credential.
package mcpoauth

import (
	"context"
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
	flow, err := json.Marshal(flowState{ConnectionID: row.ID, OrgID: in.OrgID, ActorID: in.ActorID, Resource: in.Resource, Verifier: verifier, TokenEndpoint: metadata.TokenEndpoint})
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
	q.Set("redirect_uri", s.callbackURL)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", in.Resource)
	q.Set("scope", strings.Join(in.Scopes, " "))
	auth.RawQuery = q.Encode()
	return StartResult{ConnectionID: row.ID, RedirectURL: auth.String()}, nil
}

func (s *Service) Complete(ctx context.Context, state, code string) error {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(code) == "" {
		return ErrFlowNotFound
	}
	data, err := s.rdb.GetDel(ctx, flowKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrFlowNotFound
	}
	if err != nil {
		return err
	}
	var flow flowState
	if json.Unmarshal(data, &flow) != nil || flow.ConnectionID == uuid.Nil || flow.OrgID == uuid.Nil || flow.ActorID == uuid.Nil || flow.Verifier == "" || !validURL(flow.Resource) || !validURL(flow.TokenEndpoint) {
		return ErrFlowNotFound
	}
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
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.callbackURL}, "client_id": {row.ClientID}, "code_verifier": {flow.Verifier}, "resource": {flow.Resource}}
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
	if row.TokenExpiresAt.Valid && row.TokenExpiresAt.Time.After(now.Add(30*time.Second)) {
		plain, openErr := s.sealer.Open(*row.AccessTokenSealed)
		if openErr != nil || len(plain) == 0 {
			return "", time.Time{}, ErrLease
		}
		return string(plain), row.TokenExpiresAt.Time, nil
	}
	if row.RefreshTokenSealed == nil {
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
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", time.Time{}, ErrLease
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.NewDecoder(response.Body).Decode(&token) != nil || strings.TrimSpace(token.AccessToken) == "" || token.ExpiresIn <= 0 || token.ExpiresIn > 31_536_000 {
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
	expires := now.Add(time.Duration(token.ExpiresIn) * time.Second)
	changed, updateErr := s.queries.RefreshAgentMCPOAuthConnection(ctx, sqlc.RefreshAgentMCPOAuthConnectionParams{ID: row.ID, OrgID: orgID, AccessTokenSealed: &access, RefreshTokenSealed: nextRefresh, TokenExpiresAt: pgtype.Timestamptz{Time: expires, Valid: true}})
	if updateErr != nil || changed != 1 {
		return "", time.Time{}, ErrLease
	}
	return token.AccessToken, expires, nil
}

type flowState struct {
	ConnectionID, OrgID, ActorID      uuid.UUID
	Resource, Verifier, TokenEndpoint string
}

func flowKey(state string) string { return "mcpoauth:" + state }

func (s *Service) fail(ctx context.Context, flow flowState) {
	code := "exchange_failed"
	_, _ = s.queries.FailAgentMCPOAuthConnection(ctx, sqlc.FailAgentMCPOAuthConnectionParams{ID: flow.ConnectionID, OrgID: flow.OrgID, FailureCode: &code})
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
