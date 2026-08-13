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

func (a *ssoAdapter) StartLogin(ctx context.Context, orgSlug, provider string) (string, error) {
	org, err := sqlc.New(a.pool).GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return "", apierr.NotFound("org_not_found", "organization not found")
	}
	return a.svc.StartLogin(ctx, org.ID, provider)
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
