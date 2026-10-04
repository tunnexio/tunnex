package appaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const ProxyTokenPrefix = "tnxap_"

type ProxyCredential struct {
	ID        uuid.UUID
	Name      string
	Version   int64
	CreatedAt time.Time
	RevokedAt *time.Time
}
type AuthenticatedProxy struct {
	CredentialID      uuid.UUID
	CredentialVersion int64
}
type RouteBinding struct {
	OrgID, AppID, GatewayID, Generation uuid.UUID
	Revision, AuthorityVersion          int64
	Digest, Hostname, Purpose           string
}
type Route struct {
	RouteBinding
	OriginURL                   string
	AllowedDestinationCIDRs     []string
	OriginCAPEM, OriginCADigest string
}
type RequestInput struct {
	Binding                                             RouteBinding
	SessionToken, Method, RelativePath, Origin, Referer string
	FetchMode, FetchDest, FetchUser                     string
}
type LeaseInput struct {
	StreamID uuid.UUID
	Binding  RouteBinding
}
type Decision struct {
	StreamID   uuid.UUID
	Allowed    bool
	DenyReason string
	LeaseUntil *time.Time
}

func proxyCredential(r sqlc.AppAccessProxyCredential) ProxyCredential {
	return ProxyCredential{ID: r.ID, Name: r.Name, Version: r.Version, CreatedAt: r.CreatedAt, RevokedAt: timePointer(r.RevokedAt)}
}
func proxyUnauthenticated() error {
	return apierr.New(401, "proxy_unauthenticated", "proxy authentication required")
}
func proxyUnavailable() error {
	return apierr.New(404, "route_unavailable", "application route unavailable")
}
func proxyProvisionAudit(ctx context.Context, q *sqlc.Queries, id uuid.UUID, action string, version int64) error {
	actor, kind, target := "app-proxy-provisioning", "app_access_proxy_credential", id.String()
	metadata, _ := json.Marshal(map[string]any{"version": version})
	_, e := q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{ActorSystem: &actor, Action: action, TargetType: &kind, TargetID: &target, Metadata: metadata})
	return e
}

// IssueProxyCredential is reserved for the later local operator provisioning tool.
// No human or agent HTTP route exposes this operation.
func (s *Service) IssueProxyCredential(ctx context.Context, name string) (ProxyCredential, string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return ProxyCredential{}, "", apierr.BadRequest("invalid_proxy_credential", "invalid proxy credential name")
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return ProxyCredential{}, "", e
	}
	token := ProxyTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	var out ProxyCredential
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		r, e := q.CreateAppAccessProxyCredential(ctx, sqlc.CreateAppAccessProxyCredentialParams{Name: name, TokenHash: hash[:]})
		if e != nil {
			return e
		}
		out = proxyCredential(r)
		return proxyProvisionAudit(ctx, q, r.ID, "app_access.proxy_credential_issued", r.Version)
	})
	if e != nil {
		return ProxyCredential{}, "", mapDB(e)
	}
	return out, token, nil
}
func (s *Service) AuthenticateProxy(ctx context.Context, raw string) (AuthenticatedProxy, error) {
	var out AuthenticatedProxy
	if !strings.HasPrefix(raw, ProxyTokenPrefix) {
		return out, proxyUnauthenticated()
	}
	decoded, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, ProxyTokenPrefix))
	if e != nil || len(decoded) != 32 || ProxyTokenPrefix+base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return out, proxyUnauthenticated()
	}
	hash := sha256.Sum256([]byte(raw))
	r, e := sqlc.New(s.pool).AuthenticateAppAccessProxyCredential(ctx, hash[:])
	if e != nil {
		return out, proxyUnauthenticated()
	}
	return AuthenticatedProxy{CredentialID: r.ID, CredentialVersion: r.Version}, nil
}
func (s *Service) currentProxy(ctx context.Context, proxy AuthenticatedProxy) error {
	if proxy.CredentialID == uuid.Nil || proxy.CredentialVersion < 1 {
		return proxyUnauthenticated()
	}
	_, e := sqlc.New(s.pool).CurrentAppAccessProxyCredential(ctx, sqlc.CurrentAppAccessProxyCredentialParams{ID: proxy.CredentialID, Version: proxy.CredentialVersion})
	if e != nil {
		return proxyUnauthenticated()
	}
	return nil
}
func (s *Service) RevokeProxyCredential(ctx context.Context, id uuid.UUID, expectedVersion int64) (ProxyCredential, error) {
	var out ProxyCredential
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		r, e := q.LockAppAccessProxyCredential(ctx, id)
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if r.RevokedAt.Valid {
			out = proxyCredential(r)
			return nil
		}
		if r.Version != expectedVersion {
			return conflict()
		}
		r, e = q.RevokeAppAccessProxyCredential(ctx, id)
		if e != nil {
			return e
		}
		out = proxyCredential(r)
		return proxyProvisionAudit(ctx, q, id, "app_access.proxy_credential_revoked", r.Version)
	})
	return out, mapDB(e)
}
func (s *Service) LookupRoute(ctx context.Context, proxy AuthenticatedProxy, host string, entitled bool) (Route, error) {
	if e := s.currentProxy(ctx, proxy); e != nil {
		return Route{}, e
	}
	return s.lookupServingRoute(ctx, host, entitled)
}

// lookupServingRoute remains internal: callers must establish their own principal.
func (s *Service) lookupServingRoute(ctx context.Context, host string, entitled bool) (Route, error) {
	var out Route
	if !entitled || !s.publicationDomainReadyContext(ctx) || !validHost(host) || host != strings.ToLower(host) {
		return out, proxyUnavailable()
	}
	if _, err := s.installationGeneration(ctx); err != nil {
		return out, err
	}
	r, e := sqlc.New(s.pool).LookupAppAccessServingRoute(ctx, host)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return out, proxyUnavailable()
		}
		return out, apierr.New(503, "app_authority_unavailable", "application authority unavailable")
	}
	application, ae := sqlc.New(s.pool).GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: r.OrgID, ID: r.AppID})
	if ae != nil && !errors.Is(ae, pgx.ErrNoRows) {
		return out, appInfrastructureUnavailable()
	}
	if ae != nil || application.State != "draft" {
		return out, proxyUnavailable()
	}
	node, ne := sqlc.New(s.pool).GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{OrgID: r.OrgID, ID: r.GatewayID})
	if ne != nil && !errors.Is(ne, pgx.ErrNoRows) {
		return out, appInfrastructureUnavailable()
	}
	runtime, re := sqlc.New(s.pool).GetAppAccessBrowserGatewayRuntime(ctx, sqlc.GetAppAccessBrowserGatewayRuntimeParams{OrgID: r.OrgID, GatewayID: r.GatewayID})
	if re != nil && !errors.Is(re, pgx.ErrNoRows) {
		return out, appInfrastructureUnavailable()
	}
	if ne != nil || re != nil || runtime.CapabilityVersion != 1 || runtime.ReportedCertSerial != node.CertSerial || !runtime.ReportedAt.Add(30*time.Second).After(s.now()) {
		return out, proxyUnavailable()
	}
	settings, e := s.GetSettings(ctx, r.OrgID)
	if e != nil {
		return out, apierr.New(503, "app_authority_unavailable", "application authority unavailable")
	}
	if !settings.Enabled {
		return out, proxyUnavailable()
	}
	out = Route{RouteBinding: RouteBinding{OrgID: r.OrgID, AppID: r.AppID, GatewayID: r.GatewayID, Generation: r.Generation, Revision: r.Revision, AuthorityVersion: r.AuthorityVersion, Digest: r.Digest, Hostname: r.Hostname, Purpose: r.Purpose}, OriginURL: r.OriginUrl, AllowedDestinationCIDRs: append([]string{}, r.AllowedDestinationCidrs...), OriginCAPEM: r.OriginCaPem, OriginCADigest: r.OriginCaDigest}
	return out, nil
}

// The ports deliberately deny until authoritative sessions and publication exist.
func (s *Service) AuthorizeRequest(ctx context.Context, proxy AuthenticatedProxy, in RequestInput, entitled bool) (Decision, error) {
	return s.authorizeAppRequest(ctx, proxy, in, entitled)
}
func (s *Service) RenewLease(ctx context.Context, proxy AuthenticatedProxy, in LeaseInput, entitled bool) (Decision, error) {
	return s.renewAppLease(ctx, proxy, in, entitled)
}

// ChannelAuthorize binds browser channels to current serving or claimed diagnostic
// authority. Pending tuples never become a public route or session authority.
func (s *Service) ChannelAuthorize(ctx context.Context, proxy AuthenticatedProxy, binding RouteBinding, certificateSerial string, entitled bool) (time.Time, error) {
	start := s.now()
	until := start.Add(4 * time.Second)
	if !entitled || !s.publicationDomainReadyContext(ctx) || binding.Purpose != "browser_proxy" || certificateSerial == "" {
		return time.Time{}, appAuthorityUnavailable()
	}
	if _, err := s.installationGeneration(ctx); err != nil {
		return time.Time{}, err
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		credential, e := q.LockAppAccessProxyCredential(ctx, proxy.CredentialID)
		if e != nil || credential.RevokedAt.Valid || credential.Version != proxy.CredentialVersion {
			return proxyUnauthenticated()
		}
		if e = lockGrantOrg(ctx, q, binding.OrgID); e != nil {
			return e
		}
		if _, e = q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: binding.OrgID, ID: binding.AppID}); e != nil {
			return appAuthorityUnavailable()
		}
		if e = s.gateway(ctx, q, AuthenticatedGateway{OrgID: binding.OrgID, GatewayID: binding.GatewayID, CertSerial: certificateSerial}); e != nil {
			return e
		}
		enabled, e := q.LockAppAccessSettings(ctx, binding.OrgID)
		if e != nil || !enabled {
			return appAuthorityUnavailable()
		}
		runtime, e := q.GetAppAccessBrowserGatewayRuntime(ctx, sqlc.GetAppAccessBrowserGatewayRuntimeParams{OrgID: binding.OrgID, GatewayID: binding.GatewayID})
		if e != nil || runtime.CapabilityVersion != 1 || runtime.ReportedCertSerial != certificateSerial || !runtime.ReportedAt.Add(30*time.Second).After(s.now()) {
			return appAuthorityUnavailable()
		}
		application, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: binding.OrgID, ID: binding.AppID})
		if e != nil || application.State != "draft" {
			return appAuthorityUnavailable()
		}
		publication, e := q.GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: binding.OrgID, AppID: binding.AppID})
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return appInfrastructureUnavailable()
		}
		if e == nil && publication.State == "active" && publication.GatewayID == binding.GatewayID && publication.Generation == binding.Generation && publication.Revision == binding.Revision && publication.Digest == binding.Digest && publication.Hostname == binding.Hostname && publication.AuthorityVersion == binding.AuthorityVersion {
			return nil
		}
		op, e := q.PendingAppAccessPublicationOperation(ctx, sqlc.PendingAppAccessPublicationOperationParams{OrgID: binding.OrgID, AppID: binding.AppID})
		if e != nil {
			return appAuthorityUnavailable()
		}
		if op.Status != "checking" || !op.Deadline.After(s.now()) || op.GatewayID != binding.GatewayID || op.Generation != binding.Generation || op.Revision != binding.Revision || op.Digest != binding.Digest || op.Hostname != binding.Hostname || op.AuthorityVersion != binding.AuthorityVersion || op.GatewayCertSerial != certificateSerial || !op.ProxyCredentialID.Valid || uuid.UUID(op.ProxyCredentialID.Bytes) != proxy.CredentialID || op.ProxyCredentialVersion == nil || *op.ProxyCredentialVersion != proxy.CredentialVersion {
			return appAuthorityUnavailable()
		}
		app, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: binding.OrgID, ID: binding.AppID})
		if e != nil || app.State != "draft" || app.Version != op.ExpectedAppVersion || app.DraftRevision != op.Revision {
			return appAuthorityUnavailable()
		}
		if op.Deadline.Before(until) {
			until = op.Deadline
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	if ctx.Err() != nil || !until.After(s.now()) {
		return time.Time{}, appAuthorityUnavailable()
	}
	return until, nil
}

// lookupServingApplication derives the exact serving hostname from the tenant-scoped publication.
func (s *Service) lookupServingApplication(ctx context.Context, org, app uuid.UUID, entitled bool) (Route, error) {
	host, err := sqlc.New(s.pool).GetAppAccessServingApplicationHostname(ctx, sqlc.GetAppAccessServingApplicationHostnameParams{OrgID: org, AppID: app})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Route{}, proxyUnavailable()
		}
		return Route{}, apierr.New(503, "app_authority_unavailable", "application authority unavailable")
	}
	return s.lookupServingRoute(ctx, host, entitled)
}
