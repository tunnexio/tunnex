package appaccess

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/packages/apptransport"
)

type parentSessionPort interface {
	GetNoTouch(context.Context, string) (session.Session, time.Time, error)
}
type SessionAuthority struct {
	parents parentSessionPort
	apps    *AppSessionStore
	sealer  *appcrypto.Sealer
	mfaGate func(context.Context, uuid.UUID) (bool, error)
}

func (s *Service) WithSessionAuthority(parents parentSessionPort, apps *AppSessionStore, sealer *appcrypto.Sealer, gate func(context.Context, uuid.UUID) (bool, error)) *Service {
	s.sessionAuthority = &SessionAuthority{parents, apps, sealer, gate}
	return s
}
func (s *Service) sessionReady() bool {
	a := s.sessionAuthority
	return a != nil && a.parents != nil && a.apps != nil && a.apps.rdb != nil && a.sealer != nil && a.mfaGate != nil
}
func appInfrastructureUnavailable() error {
	return apierr.New(503, "app_access_unavailable", "application authority unavailable")
}
func appLoginRequired() error {
	return apierr.New(401, "app_login_required", "sign in again to use applications")
}
func appAuthorityUnavailable() error {
	return apierr.Forbidden("browser_authority_unavailable", "application authority unavailable")
}
func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// Parent validation never refreshes native idle. Epoch zero is intentionally
// incompatible legacy authority, rather than upgraded by reading a newer epoch.
func (s *Service) validateParent(ctx context.Context, user uuid.UUID, parentID string, epoch int64) (session.Session, time.Time, error) {
	if !s.sessionReady() {
		return session.Session{}, time.Time{}, appAuthorityUnavailable()
	}
	parent, until, e := s.sessionAuthority.parents.GetNoTouch(ctx, parentID)
	if e != nil {
		if errors.Is(e, session.ErrNotFound) {
			return parent, time.Time{}, appLoginRequired()
		}
		return parent, time.Time{}, appInfrastructureUnavailable()
	}
	if parent.ID != parentID || parent.UserID != user || parent.AppAuthEpoch <= 0 || (epoch > 0 && parent.AppAuthEpoch != epoch) || (parent.AuthMethod != authctx.AuthLocalPassword && parent.AuthMethod != authctx.AuthSSO) {
		return parent, time.Time{}, appLoginRequired()
	}
	q := sqlc.New(s.pool)
	current, e := q.GetUserByID(ctx, user)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return parent, time.Time{}, appAuthorityUnavailable()
		}
		return parent, time.Time{}, appInfrastructureUnavailable()
	}
	hash, e := hex.DecodeString(secretHash(parentID))
	if e != nil {
		return parent, time.Time{}, appAuthorityUnavailable()
	}
	revoked, e := q.IsAppParentLogoutRevoked(ctx, hash)
	if e != nil {
		return parent, time.Time{}, appInfrastructureUnavailable()
	}
	if revoked || current.AppAuthEpoch != parent.AppAuthEpoch {
		return parent, time.Time{}, appLoginRequired()
	}
	if current.Status != "active" || current.DeletedAt.Valid || !current.EmailVerifiedAt.Valid || (current.MustChangePassword && current.PasswordHash != nil) {
		return parent, time.Time{}, appAuthorityUnavailable()
	}
	if parent.AuthMethod == authctx.AuthLocalPassword {
		gated, e := s.sessionAuthority.mfaGate(ctx, user)
		if e != nil {
			return parent, time.Time{}, appInfrastructureUnavailable()
		}
		if gated {
			return parent, time.Time{}, appAuthorityUnavailable()
		}
	}
	if !until.After(s.now()) {
		return parent, time.Time{}, appLoginRequired()
	}
	return parent, until, nil
}
func (s *Service) appEligibility(ctx context.Context, org, app, user uuid.UUID, entitled bool) (*time.Time, error) {
	q := sqlc.New(s.pool)
	identity, e := q.AppAccessEvaluationUser(ctx, sqlc.AppAccessEvaluationUserParams{OrgID: org, ID: user})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return nil, appAuthorityUnavailable()
		}
		return nil, appInfrastructureUnavailable()
	}
	if identity.Status != "active" || identity.AccessRevokedAt.Valid || !identity.EmailVerifiedAt.Valid {
		return nil, appAuthorityUnavailable()
	}
	roles := identity.Roles
	if len(roles) == 0 {
		roles = []string{identity.Role}
	}
	if !rbac.CanAny(roles, rbac.PermAppAccessUse) {
		return nil, appAuthorityUnavailable()
	}
	settings, e := s.GetSettings(ctx, org)
	if e != nil {
		return nil, e
	}
	if !entitled || !settings.Enabled || !settings.DomainReady {
		return nil, appAuthorityUnavailable()
	}
	matches, e := q.MatchingAppAccessGrants(ctx, sqlc.MatchingAppAccessGrantsParams{OrgID: org, AppID: app, UserID: user, EvaluatedAt: s.now()})
	if e != nil {
		return nil, appInfrastructureUnavailable()
	}
	if len(matches) == 0 {
		return nil, appAuthorityUnavailable()
	}
	var next *time.Time
	for _, g := range matches {
		if !g.ExpiresAt.Valid {
			return nil, nil
		}
		if next == nil || g.ExpiresAt.Time.After(*next) {
			v := g.ExpiresAt.Time
			next = &v
		}
	}

	return next, nil
}
func (s *Service) validateAppRecord(ctx context.Context, r AppSessionRecord, entitled bool) (time.Time, *time.Time, error) {
	if e := s.validateInstallation(ctx, r.InstallationGeneration); e != nil {
		return time.Time{}, nil, e
	}
	if r.ID != uuid.Nil {
		revoked, e := sqlc.New(s.pool).AppAccessSessionRevoked(ctx, sqlc.AppAccessSessionRevokedParams{OrgID: r.Binding.OrgID, AppID: r.Binding.AppID, UserID: r.UserID, SessionID: r.ID, InstallationGeneration: r.InstallationGeneration})
		if e != nil {
			return time.Time{}, nil, appInfrastructureUnavailable()
		}
		if revoked {
			return time.Time{}, nil, appAuthorityUnavailable()
		}
	}
	parentID, e := s.sessionAuthority.sealer.Open(r.ParentSealed)
	if e != nil || secretHash(string(parentID)) != r.ParentHash {
		return time.Time{}, nil, appAuthorityUnavailable()
	}
	parent, until, e := s.validateParent(ctx, r.UserID, string(parentID), r.ParentEpoch)
	if e != nil {
		return time.Time{}, nil, normalizeAppAuthorityError(e)
	}
	if parent.AuthMethod != r.AuthMethod {
		return time.Time{}, nil, appAuthorityUnavailable()
	}
	next, e := s.appEligibility(ctx, r.Binding.OrgID, r.Binding.AppID, r.UserID, entitled)
	if e != nil {
		return time.Time{}, nil, e
	}
	route, e := s.lookupServingRoute(ctx, r.Binding.Hostname, entitled)
	if e != nil {
		return time.Time{}, nil, normalizeAppAuthorityError(e)
	}
	if route.RouteBinding != r.Binding {
		return time.Time{}, nil, appAuthorityUnavailable()
	}
	mfaUntil, e := s.requireAppMFA(ctx, r.Binding.OrgID, r.Binding.AppID, parent)
	if e != nil {
		return time.Time{}, nil, normalizeAppAuthorityError(e)
	}
	if !mfaUntil.IsZero() {
		until = minTime(until, mfaUntil)
	}
	return until, next, nil
}

type MyApp struct {
	RequireMFA, MFARequired, MFASetupRequired bool
	ID                                        uuid.UUID
	Name, Description, Icon, LaunchURL        string
	IconDataURL                               string
}
type MyApps struct {
	Items        []MyApp
	Availability string
}
type MyAppSession struct {
	ID, AppID            uuid.UUID
	AppLabel             string
	CreatedAt, ExpiresAt time.Time
	CurrentParent        bool
}
type LaunchResult struct{ RedirectURL string }
type RedeemResult struct {
	AppSessionToken, RelativeTarget string
	ExpiresAt                       time.Time
}

func (s *Service) MyApps(ctx context.Context, org, user uuid.UUID, parentID, search string, limit, offset int32, entitled bool) (MyApps, error) {
	out := MyApps{Items: []MyApp{}, Availability: "available"}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 || !utf8.ValidString(search) || utf8.RuneCountInString(search) > 100 {
		return out, apierr.BadRequest("invalid_pagination", "invalid application search or pagination")
	}
	parent, _, parentErr := s.validateParent(ctx, user, parentID, 0)
	if e := parentErr; e != nil {
		var typed *apierr.Error
		if errors.As(e, &typed) && typed.Code == "app_login_required" {
			out.Availability = "parent_unavailable"
			return out, nil
		}
		return out, e
	}
	settings, e := s.GetSettings(ctx, org)
	if e != nil {
		return out, e
	}
	switch {
	case !entitled:
		out.Availability = "feature_unavailable"
	case !settings.Enabled:
		out.Availability = "feature_disabled"
	case !settings.DomainReady:
		out.Availability = "domain_unavailable"
	}
	if out.Availability != "available" {
		return out, nil
	}
	rows, e := sqlc.New(s.pool).ListMyAppAccessPublishedCandidates(ctx, sqlc.ListMyAppAccessPublishedCandidatesParams{OrgID: org, UserID: user, EvaluatedAt: s.now(), Search: search, PageLimit: limit, PageOffset: offset, EligibleRoles: appUseRoles()})
	if e != nil {
		return out, appInfrastructureUnavailable()
	}
	for _, r := range rows {
		required, err := s.currentMFAPolicy(ctx, org, r.AppID)
		if err != nil {
			return out, err
		}
		status, err := s.applicationMFAStatus(ctx, required, parent)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, MyApp{RequireMFA: required, MFARequired: status.Required, MFASetupRequired: status.SetupRequired, ID: r.AppID, Name: r.Name, Description: r.Description, Icon: r.Icon, IconDataURL: r.IconDataUrl, LaunchURL: "https://" + r.Hostname + "/__tunnex_app/start"})
	}
	return out, nil
}

func safeAppTarget(raw string) (string, error) {
	u, e := url.ParseRequestURI(raw)
	if e != nil {
		return "", appAuthorityUnavailable()
	}
	target, e := apptransport.RelativeTarget(u)
	if e != nil {
		return "", appAuthorityUnavailable()
	}
	return target, nil
}
func (s *Service) LaunchApp(ctx context.Context, org, app, user uuid.UUID, parentID, nonceHash, target string, entitled bool) (LaunchResult, error) {
	out := LaunchResult{}
	if !appProxyHash(nonceHash) {
		return out, apierr.BadRequest("invalid_launch", "invalid browser nonce")
	}
	target, e := safeAppTarget(target)
	if e != nil {
		return out, e
	}
	parent, until, e := s.validateParent(ctx, user, parentID, 0)
	if e != nil {
		return out, e
	}
	if _, e = s.appEligibility(ctx, org, app, user, entitled); e != nil {
		return out, e
	}
	route, e := s.lookupServingApplication(ctx, org, app, entitled)
	if e != nil {
		return out, normalizeAppAuthorityError(e)
	}
	if _, e = s.requireAppMFA(ctx, org, app, parent); e != nil {
		return out, e
	}
	pending, pendingRaw, e := s.sessionAuthority.apps.LoadPending(ctx, nonceHash)
	if e != nil {
		if errors.Is(e, ErrAppSessionMissing) {
			return out, appAuthorityUnavailable()
		}
		return out, appInfrastructureUnavailable()
	}
	if pending.Binding != route.RouteBinding || pending.RelativeTarget != target || pending.NonceHash != nonceHash {
		return out, appAuthorityUnavailable()
	}
	if e = s.validateInstallation(ctx, pending.InstallationGeneration); e != nil {
		return out, e
	}
	if e = s.currentProxy(ctx, AuthenticatedProxy{CredentialID: pending.ProxyID, CredentialVersion: pending.ProxyVersion}); e != nil {
		return out, normalizeAppAuthorityError(e)
	}
	revision, e := s.GetRevision(ctx, org, app, route.Revision)
	if e != nil {
		return out, normalizeAppAuthorityError(e)
	}
	sealed, e := s.sessionAuthority.sealer.Seal([]byte(parentID))
	if e != nil {
		return out, e
	}
	now := s.now()
	absolute := minTime(parent.ExpiresAt, now.Add(time.Duration(revision.AbsoluteTimeoutSeconds)*time.Second))
	r := LaunchRecord{AppSessionRecord: AppSessionRecord{InstallationGeneration: pending.InstallationGeneration, UserID: user, Binding: route.RouteBinding, Label: revision.Name, ParentHash: secretHash(parentID), ParentSealed: sealed, ParentEpoch: parent.AppAuthEpoch, AuthMethod: parent.AuthMethod, CreatedAt: now, ExpiresAt: absolute, IdleMillis: int64(revision.IdleTimeoutSeconds) * 1000}, NonceHash: nonceHash, RelativeTarget: target, CodeExpiresAt: minTime(now.Add(time.Minute), until)}
	code, e := s.sessionAuthority.apps.CreateLaunch(ctx, r, pendingRaw)
	if e != nil {
		if errors.Is(e, ErrAppSessionCapacity) {
			return out, apierr.New(429, "app_launch_capacity", "too many pending application launches")
		}
		return out, appInfrastructureUnavailable()
	}
	s.emit(sessionEvent(r.AppSessionRecord, pending.ProxyID, uuid.Nil, "launch_created", "completed", "none"))
	out.RedirectURL = "https://" + route.Hostname + "/__tunnex_app/redeem?code=" + code
	return out, nil
}
func appProxyHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, e := hex.DecodeString(value)
	return e == nil && hex.EncodeToString(decoded) == value
}
func (s *Service) RedeemApp(ctx context.Context, proxy AuthenticatedProxy, code, nonce, host string, entitled bool) (RedeemResult, error) {
	out := RedeemResult{}
	if e := s.currentProxy(ctx, proxy); e != nil {
		return out, e
	}
	if !s.sessionReady() || !validAppSecret(code, "") || !validAppSecret(nonce, "") {
		return out, appAuthorityUnavailable()
	}
	r, raw, e := s.sessionAuthority.apps.LoadLaunch(ctx, code)
	if e != nil {
		if errors.Is(e, ErrAppSessionMissing) {
			return out, appAuthorityUnavailable()
		}
		return out, appInfrastructureUnavailable()
	}
	if host != r.Binding.Hostname || subtle.ConstantTimeCompare([]byte(secretHash(nonce)), []byte(r.NonceHash)) != 1 {
		return out, appAuthorityUnavailable()
	}
	if _, _, e = s.validateAppRecord(ctx, r.AppSessionRecord, entitled); e != nil {
		return out, e
	}
	target, e := safeAppTarget(r.RelativeTarget)
	if e != nil {
		return out, e
	}
	r.CreatedAt = s.now()
	if !r.ExpiresAt.After(r.CreatedAt) {
		return out, appAuthorityUnavailable()
	}
	token, e := s.sessionAuthority.apps.Redeem(ctx, code, raw, r.AppSessionRecord)
	if e != nil {
		if errors.Is(e, ErrAppSessionMissing) || errors.Is(e, ErrAppSessionCapacity) {
			return out, appAuthorityUnavailable()
		}
		return out, appInfrastructureUnavailable()
	}
	if s.events != nil {
		if minted, _, err := s.sessionAuthority.apps.Peek(ctx, token); err == nil {
			s.emit(sessionEvent(minted, proxy.CredentialID, uuid.Nil, "session_created", "completed", "none"))
		}
	}
	return RedeemResult{token, target, r.ExpiresAt}, nil
}
func (s *Service) MySessions(ctx context.Context, org, user uuid.UUID, parentID string, limit, offset int32) ([]MyAppSession, error) {
	if !s.sessionReady() {
		return nil, appAuthorityUnavailable()
	}
	parent, _, e := s.sessionAuthority.parents.GetNoTouch(ctx, parentID)
	if e != nil {
		if errors.Is(e, session.ErrNotFound) {
			return nil, appLoginRequired()
		}
		return nil, appInfrastructureUnavailable()
	}
	if parent.UserID != user {
		return nil, appLoginRequired()
	}
	generation, e := s.installationGeneration(ctx)
	if e != nil {
		return nil, e
	}
	records, e := s.sessionAuthority.apps.List(ctx, org, user, limit, offset, generation)
	if e != nil {
		return nil, appInfrastructureUnavailable()
	}
	out := []MyAppSession{}
	for _, r := range records {
		revoked, err := sqlc.New(s.pool).AppAccessSessionRevoked(ctx, sqlc.AppAccessSessionRevokedParams{OrgID: org, AppID: r.Binding.AppID, UserID: user, SessionID: r.ID, InstallationGeneration: generation})
		if err != nil {
			return nil, appInfrastructureUnavailable()
		}
		if revoked {
			continue
		}
		// Retained label was derived from this immutable published revision at mint.
		label := r.Label
		out = append(out, MyAppSession{r.ID, r.Binding.AppID, label, r.CreatedAt, r.ExpiresAt, r.ParentHash == secretHash(parentID)})
	}
	return out, nil
}
func (s *Service) RevokeMySession(ctx context.Context, org, user, id uuid.UUID) error {
	if !s.sessionReady() {
		return appAuthorityUnavailable()
	}
	q := sqlc.New(s.pool)
	_, e := q.GetAppAccessSessionRevocationForUser(ctx, sqlc.GetAppAccessSessionRevocationForUserParams{OrgID: org, UserID: user, SessionID: id})
	if e == nil {
		// Durable revocation remains authoritative even when Redis cleanup fails.
		_ = s.sessionAuthority.apps.RevokeOwn(ctx, org, user, id)
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return appInfrastructureUnavailable()
	}
	r, e := s.sessionAuthority.apps.RecordByID(ctx, id)
	if errors.Is(e, ErrAppSessionMissing) {
		_, retryErr := q.GetAppAccessSessionRevocationForUser(ctx, sqlc.GetAppAccessSessionRevocationForUserParams{OrgID: org, UserID: user, SessionID: id})
		if retryErr == nil {
			return nil
		}
		if !errors.Is(retryErr, pgx.ErrNoRows) {
			return appInfrastructureUnavailable()
		}
		return apierr.NotFound("app_session_unavailable", "app session unavailable")
	}
	if e != nil {
		return appInfrastructureUnavailable()
	}
	if r.Binding.OrgID != org || r.UserID != user || r.InstallationGeneration == uuid.Nil {
		return apierr.NotFound("app_session_unavailable", "app session unavailable")
	}
	newRevocation := false
	e = s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, err := q.LockActiveAppAccessOrganization(ctx, org); err != nil {
			return err
		}
		already, err := q.AppAccessSessionRevoked(ctx, sqlc.AppAccessSessionRevokedParams{OrgID: org, AppID: r.Binding.AppID, UserID: user, SessionID: id, InstallationGeneration: r.InstallationGeneration})
		if err != nil || already {
			return err
		}
		inserted, err := q.TryInsertAppAccessSessionRevocation(ctx, sqlc.TryInsertAppAccessSessionRevocationParams{OrgID: org, AppID: r.Binding.AppID, UserID: user, SessionID: id, InstallationGeneration: r.InstallationGeneration, LiveUserID: pgtype.UUID{Bytes: user, Valid: true}, AbsoluteExpiresAt: r.ExpiresAt, ActorUserID: pgtype.UUID{Bytes: user, Valid: true}, ActorUserSnapshot: pgtype.UUID{Bytes: user, Valid: true}, Reason: "self"})
		if err != nil {
			return err
		}
		if inserted == 0 {
			return nil
		}
		newRevocation = true
		return audit(ctx, q, org, user, id.String(), "app_access.session_revoked", 1)
	})
	if e != nil {
		return appInfrastructureUnavailable()
	}
	_ = s.sessionAuthority.apps.RevokeOwn(ctx, org, user, id)
	if newRevocation {
		s.emit(sessionEvent(r, uuid.Nil, uuid.Nil, "session_revoked", "revoked", "self"))
	}
	return nil
}

// Foreground is qualified browser navigation evidence, not proof of human
// presence. Script fetches, assets, missing metadata and lease renewal do not touch.
func appForeground(r RequestInput) bool {
	return r.FetchMode == "navigate" && r.FetchDest == "document" && r.FetchUser == "?1"
}
func appSameOrigin(r RequestInput) bool {
	if r.Origin != "" && r.Origin != "https://"+r.Binding.Hostname {
		return false
	}
	safe := r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS"
	if safe {
		return true
	}
	if r.Origin == "https://"+r.Binding.Hostname {
		return true
	}
	u, e := url.Parse(r.Referer)
	return e == nil && u.Scheme == "https" && u.Host == r.Binding.Hostname && u.User == nil && u.Fragment == ""
}
func appMethodValid(method string) bool {
	if len(method) == 0 || len(method) > 32 || method == "CONNECT" || method == "TRACE" {
		return false
	}
	for _, r := range method {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func appUseRoles() []string {
	roles := []string{}
	for role := range rbac.Policy() {
		if rbac.CanAny([]string{role}, rbac.PermAppAccessUse) {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	return roles
}

func (s *Service) authorizeAppRequest(ctx context.Context, proxy AuthenticatedProxy, in RequestInput, entitled bool) (Decision, error) {
	start := s.now()
	if e := s.currentProxy(ctx, proxy); e != nil {
		return Decision{}, e
	}
	if !s.sessionReady() {
		return Decision{}, appAuthorityUnavailable()
	}
	route, e := s.lookupServingRoute(ctx, in.Binding.Hostname, entitled)
	if e != nil {
		return Decision{}, normalizeAppAuthorityError(e)
	}
	if route.RouteBinding != in.Binding {
		return Decision{}, appAuthorityUnavailable()
	}
	if !appMethodValid(in.Method) || !appSameOrigin(in) {
		return Decision{}, appAuthorityUnavailable()
	}
	if _, e = safeAppTarget(in.RelativePath); e != nil {
		return Decision{}, appAuthorityUnavailable()
	}
	record, idle, e := s.sessionAuthority.apps.Peek(ctx, in.SessionToken)
	if errors.Is(e, ErrAppSessionMissing) {
		return Decision{}, apierr.Forbidden("app_session_invalid", "app session unavailable")
	}
	if e != nil {
		return Decision{}, appInfrastructureUnavailable()
	}
	if record.Binding != in.Binding {
		return Decision{}, appAuthorityUnavailable()
	}
	parentUntil, grantUntil, e := s.validateAppRecord(ctx, record, entitled)
	if e != nil {
		s.emit(sessionEvent(record, proxy.CredentialID, uuid.Nil, "request_denied", "denied", "session_invalid"))
		return Decision{}, e
	}

	until := minTime(start.Add(4*time.Second), minTime(idle, parentUntil))
	until = minTime(until, record.ExpiresAt)
	if grantUntil != nil {
		until = minTime(until, *grantUntil)
	}
	if !until.After(s.now()) || ctx.Err() != nil {
		return Decision{}, appAuthorityUnavailable()
	}
	stream, e := s.sessionAuthority.apps.createStream(ctx, in.SessionToken, proxy, in.Binding, until, record)
	if e != nil {
		return Decision{}, appStoreAuthorityError(e)
	}
	if appForeground(in) {
		if _, e = s.sessionAuthority.apps.TouchForeground(ctx, in.SessionToken, record); e != nil {
			return Decision{}, appStoreAuthorityError(e)
		}
	}
	if !until.After(s.now()) || ctx.Err() != nil {
		return Decision{}, appAuthorityUnavailable()
	}
	s.emit(sessionEvent(record, proxy.CredentialID, stream, "request_allowed", "allowed", "none"))
	return Decision{StreamID: stream, Allowed: true, LeaseUntil: &until}, nil
}
func (s *Service) renewAppLease(ctx context.Context, proxy AuthenticatedProxy, in LeaseInput, entitled bool) (Decision, error) {
	start := s.now()
	if e := s.currentProxy(ctx, proxy); e != nil {
		return Decision{}, e
	}
	if !s.sessionReady() {
		return Decision{}, appAuthorityUnavailable()
	}
	stream, raw, e := s.sessionAuthority.apps.loadStream(ctx, in.StreamID)
	if e != nil {
		if errors.Is(e, ErrAppSessionMissing) {
			return Decision{}, appAuthorityUnavailable()
		}
		return Decision{}, appInfrastructureUnavailable()
	}
	if stream.Binding != in.Binding || stream.CredentialID != proxy.CredentialID || stream.CredentialVersion != proxy.CredentialVersion {
		return Decision{}, appAuthorityUnavailable()
	}
	record, idle, e := s.sessionAuthority.apps.peekKey(ctx, stream.SessionKey)
	if e != nil {
		if errors.Is(e, ErrAppSessionMissing) {
			return Decision{}, appAuthorityUnavailable()
		}
		return Decision{}, appInfrastructureUnavailable()
	}
	if record.Binding != stream.Binding || record.InstallationGeneration != stream.InstallationGeneration {
		return Decision{}, appAuthorityUnavailable()
	}
	parentUntil, grantUntil, e := s.validateAppRecord(ctx, record, entitled)
	if e != nil {
		s.emit(sessionEvent(record, proxy.CredentialID, in.StreamID, "stream_denied", "denied", "session_invalid"))
		return Decision{}, e
	}
	until := minTime(start.Add(4*time.Second), minTime(idle, parentUntil))
	until = minTime(until, record.ExpiresAt)
	if grantUntil != nil {
		until = minTime(until, *grantUntil)
	}
	if !until.After(s.now()) || ctx.Err() != nil {
		return Decision{}, appAuthorityUnavailable()
	}
	if e = s.sessionAuthority.apps.renewStream(ctx, in.StreamID, raw, stream, until, record); e != nil {
		return Decision{}, appStoreAuthorityError(e)
	}
	if !until.After(s.now()) || ctx.Err() != nil {
		return Decision{}, appAuthorityUnavailable()
	}
	s.emit(sessionEvent(record, proxy.CredentialID, in.StreamID, "stream_renewed", "allowed", "none"))
	return Decision{StreamID: in.StreamID, Allowed: true, LeaseUntil: &until}, nil
}

func normalizeAppAuthorityError(e error) error {
	var typed *apierr.Error
	if errors.As(e, &typed) {
		if typed.Status >= 500 {
			return e
		}
		return appAuthorityUnavailable()
	}
	return appInfrastructureUnavailable()
}

func (s *Service) RegisterPendingLaunch(ctx context.Context, proxy AuthenticatedProxy, binding RouteBinding, nonceHash, target string, entitled bool) (time.Time, error) {
	if e := s.currentProxy(ctx, proxy); e != nil {
		return time.Time{}, e
	}
	if !s.sessionReady() || !appProxyHash(nonceHash) {
		return time.Time{}, appAuthorityUnavailable()
	}
	normalized, e := safeAppTarget(target)
	if e != nil {
		return time.Time{}, e
	}
	route, e := s.lookupServingRoute(ctx, binding.Hostname, entitled)
	if e != nil {
		return time.Time{}, normalizeAppAuthorityError(e)
	}
	if route.RouteBinding != binding {
		return time.Time{}, appAuthorityUnavailable()
	}
	generation, e := s.installationGeneration(ctx)
	if e != nil {
		return time.Time{}, e
	}
	until := s.now().Add(10 * time.Minute)
	e = s.sessionAuthority.apps.RegisterPending(ctx, PendingLaunch{InstallationGeneration: generation, Binding: binding, NonceHash: nonceHash, RelativeTarget: normalized, ProxyID: proxy.CredentialID, ProxyVersion: proxy.CredentialVersion, ExpiresAt: until})
	if errors.Is(e, ErrAppSessionCapacity) {
		return time.Time{}, apierr.New(429, "app_launch_capacity", "too many pending application launches")
	}
	if errors.Is(e, ErrAppSessionMissing) {
		return time.Time{}, appAuthorityUnavailable()
	}
	if e != nil {
		return time.Time{}, appInfrastructureUnavailable()
	}
	return until, nil
}

func appStoreAuthorityError(e error) error {
	if errors.Is(e, ErrAppSessionMissing) || errors.Is(e, ErrAppSessionCapacity) {
		return appAuthorityUnavailable()
	}
	return appInfrastructureUnavailable()
}

// Proxy close reports are best-effort lifecycle evidence, never a substitute
// for independent authority expiry. The stream must belong to this principal.
func (s *Service) StreamTerminated(ctx context.Context, proxy AuthenticatedProxy, binding RouteBinding, id uuid.UUID, reason string) error {
	if err := s.currentProxy(ctx, proxy); err != nil {
		return err
	}
	if !s.sessionReady() || (reason != "connection_closed" && reason != "lease_expired") {
		return appAuthorityUnavailable()
	}
	stream, raw, err := s.sessionAuthority.apps.loadStream(ctx, id)
	if errors.Is(err, ErrAppSessionMissing) {
		// Expired metadata cannot be assigned to a caller-asserted tenant.
		if s.events != nil {
			s.events.dropped.Add(1)
		}
		return nil
	}
	if err != nil {
		return appInfrastructureUnavailable()
	}
	if stream.Binding != binding || stream.CredentialID != proxy.CredentialID || stream.CredentialVersion != proxy.CredentialVersion {
		return appAuthorityUnavailable()
	}
	record, _, err := s.sessionAuthority.apps.peekKey(ctx, stream.SessionKey)
	if errors.Is(err, ErrAppSessionMissing) {
		if s.events != nil {
			s.events.dropped.Add(1)
		}
		return nil
	}
	if err != nil {
		return appInfrastructureUnavailable()
	}
	if record.Binding != binding || record.InstallationGeneration != stream.InstallationGeneration {
		return appAuthorityUnavailable()
	}
	removed, err := s.sessionAuthority.apps.rdb.Eval(ctx, `if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end;return redis.call('DEL',KEYS[1])`, []string{"aa:stream:" + id.String()}, raw).Int()
	if err != nil {
		return appInfrastructureUnavailable()
	}
	if removed == 1 {
		s.emit(sessionEvent(record, proxy.CredentialID, id, "stream_terminated", "completed", reason))
	}
	return nil
}
