package http

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
)

// ssoAdapter bridges the enterprise sso.Service to the http ssoPort interface,
// resolving org slugs to ids (start) and org ids straight through (config).
type ssoAdapter struct {
	pool *pgxpool.Pool
	svc  *sso.Service
}

// NewSSOPort builds the enterprise SSO port. Present only in the enterprise
// build; the open build's stub returns nil (see sso_wire_open.go).
// ⚠ THE LICENCE MANAGER IS A PARAMETER, NOT A LOOKUP. SSO onboarding (JIT provisioning) stops when the
// entitlement lapses — see sso.Service.mayOnboard — and a service that reached for a package-level manager
// would be untestable at exactly the boundary that matters.
func NewSSOPort(pool *pgxpool.Pool, sealer *crypto.Sealer, rdb *redis.Client, baseURL string, lic *licence.Manager, logger *slog.Logger) ssoPort {
	configs := sso.NewConfigService(pool, sealer)
	flows := sso.NewFlowStore(rdb, 10*time.Minute)
	svc := sso.NewService(pool, configs, flows, sso.DefaultProviderFactory, baseURL, logger).WithLicence(lic)
	return &ssoAdapter{pool: pool, svc: svc}
}

// StartLogin resolves the org whose IdP credentials build the redirect. An EMPTY slug is the
// normal browser case, not an error: the login page asks for an email and a provider and nothing
// else, so the tenant has to be derived rather than typed.
func (a *ssoAdapter) StartLogin(ctx context.Context, orgSlug, provider string) (string, error) {
	q := sqlc.New(a.pool)
	if orgSlug == "" {
		orgID, err := soleSSOOrg(ctx, q, provider)
		if err != nil {
			return "", err
		}
		return a.svc.StartLogin(ctx, orgID, provider)
	}
	org, err := q.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return "", apierr.NotFound("org_not_found", "organization not found")
	}
	return a.svc.StartLogin(ctx, org.ID, provider)
}

// enabledSSOOrgLister is the single query soleSSOOrg needs; *sqlc.Queries satisfies it.
type enabledSSOOrgLister interface {
	ListEnabledSSOOrgsByProvider(ctx context.Context, provider string) ([]uuid.UUID, error)
}

// soleSSOOrg derives the org for a slug-less SSO start: the ONE org with this provider enabled.
//
// ⛔ FAILS CLOSED IN BOTH DIRECTIONS. Zero configured orgs rejects, and so does two-or-more —
// picking either of two tenants would hand one org's user to another org's identity provider,
// and "first row" is not a security decision anyone made. Ambiguity sends the caller back to
// supplying the slug explicitly, which is what the query param is still there for.
//
// ⚠ The two codes are distinguishable to an unauthenticated caller, and that is deliberate: both
// state deployment-level facts (`/api/v1/meta` already advertises which providers exist), and a
// login page that cannot tell "nobody configured this" from "say which tenant" cannot guide anyone.
// Neither code names an org.
//
// Takes the ONE query it uses rather than *sqlc.Queries, so the three-way fail-closed decision is
// testable without a database — a decision reachable only through a live pool is a decision nobody
// re-checks after the next edit.
func soleSSOOrg(ctx context.Context, q enabledSSOOrgLister, provider string) (uuid.UUID, error) {
	orgs, err := q.ListEnabledSSOOrgsByProvider(ctx, provider)
	if err != nil {
		return uuid.Nil, err
	}
	switch len(orgs) {
	case 1:
		return orgs[0], nil
	case 0:
		return uuid.Nil, apierr.NotFound("sso_not_configured",
			"single sign-on is not configured for this provider")
	default:
		return uuid.Nil, apierr.BadRequest("sso_org_ambiguous",
			"more than one organization uses this provider — specify your organization to continue")
	}
}

func (a *ssoAdapter) HandleCallback(ctx context.Context, provider, code, state string) (uuid.UUID, error) {
	return a.svc.HandleCallback(ctx, provider, code, state)
}

func (a *ssoAdapter) SetConfig(ctx context.Context, actor, orgID uuid.UUID, provider, clientID, clientSecret, tenantID string, enabled bool) error {
	return a.svc.Configs().Set(ctx, actor, orgID, provider, clientID, clientSecret, tenantID, enabled)
}

func (a *ssoAdapter) ViewConfig(ctx context.Context, orgID uuid.UUID, provider string) (SSOConfigView, error) {
	v, err := a.svc.Configs().View(ctx, orgID, provider)
	if err != nil {
		return SSOConfigView{}, err
	}
	return SSOConfigView{
		Provider:          v.Provider,
		ClientID:          v.ClientID,
		TenantID:          v.TenantID,
		SecretFingerprint: v.SecretFingerprint,
		Enabled:           v.Enabled,
		UpdatedAt:         v.UpdatedAt,
	}, nil
}
