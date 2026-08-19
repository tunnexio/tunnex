// Command dev-sso-config points a LOCAL stack at a REAL identity provider so the SSO login can be
// walked end to end on a laptop.
//
// ⛔ DEVELOPMENT ONLY, AND IT EXISTS BECAUSE THE SUPPORTED PATH IS CLOSED LOCALLY. The shipped way to
// configure SSO is PUT /api/v1/organizations/{orgId}/sso/{provider}, which `requireSSOAdmin` gates on
// the SSO entitlement — a laptop stack runs Community, so that endpoint answers 403 edition_required
// and there is no way in. This writes the same row the endpoint would, sealing the client secret under
// the master key exactly as sso.ConfigService.Set does. It is `seed-enterprise` with the values
// supplied instead of hardcoded.
//
// It does NOT bypass any login-time check: the redirect, PKCE, nonce, state and callback all run the
// shipped code. The only thing skipped is the admin-config gate.
//
//	TUNNEX_SSO_ORG_SLUG=demo TUNNEX_SSO_PROVIDER=microsoft \
//	TUNNEX_SSO_CLIENT_ID=... TUNNEX_SSO_CLIENT_SECRET=... TUNNEX_SSO_TENANT_ID=... \
//	go run ./cmd/dev-sso-config
//
// ⚠ THE SECRET ARRIVES BY ENVIRONMENT, NEVER BY FLAG. A flag lands in shell history and in the process
// table where any local user can read it with `ps`.
package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/secrets"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Load()

	orgSlug := os.Getenv("TUNNEX_SSO_ORG_SLUG")
	provider := os.Getenv("TUNNEX_SSO_PROVIDER")
	clientID := os.Getenv("TUNNEX_SSO_CLIENT_ID")
	clientSecret := os.Getenv("TUNNEX_SSO_CLIENT_SECRET")
	tenantID := os.Getenv("TUNNEX_SSO_TENANT_ID") // microsoft only

	switch {
	case cfg.DatabaseURL == "":
		fail(logger, "DATABASE_URL is required")
	case orgSlug == "":
		fail(logger, "TUNNEX_SSO_ORG_SLUG is required (e.g. demo)")
	case provider != "google" && provider != "microsoft":
		fail(logger, "TUNNEX_SSO_PROVIDER must be google or microsoft")
	case clientID == "":
		fail(logger, "TUNNEX_SSO_CLIENT_ID is required")
	case clientSecret == "":
		fail(logger, "TUNNEX_SSO_CLIENT_SECRET is required")
	case provider == "microsoft" && tenantID == "":
		// Entra's authorize URL is per-tenant; without it the provider would build a URL against the
		// wrong directory and fail at Microsoft rather than here, where the cause is legible.
		fail(logger, "TUNNEX_SSO_TENANT_ID is required for microsoft")
	}

	// Same guard as seed-enterprise: LoadOrInit would MINT a fresh key against an empty/mismatched
	// secrets dir and seal the secret under a key the running API can never open.
	if _, err := os.Stat(filepath.Join(cfg.SecretsDir, "master.key")); err != nil {
		fail(logger, "no master key at "+cfg.SecretsDir+" — boot the API first and mount its secrets volume")
	}
	sec, err := secrets.LoadOrInit(cfg.SecretsDir)
	if err != nil {
		fail(logger, "secrets load failed: "+err.Error())
	}
	sealer, err := crypto.NewSealer(sec.MasterKey)
	if err != nil {
		fail(logger, "sealer failed: "+err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fail(logger, "connect failed: "+err.Error())
	}
	defer pool.Close()

	q := sqlc.New(pool)
	org, err := q.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		fail(logger, "no organization with slug "+orgSlug+" — run `make seed` first")
	}

	sealed, err := sealer.Seal([]byte(clientSecret))
	if err != nil {
		fail(logger, "seal failed: "+err.Error())
	}
	var tid *string
	if tenantID != "" {
		tid = &tenantID
	}
	if _, err := q.UpsertSSOConfig(ctx, sqlc.UpsertSSOConfigParams{
		OrgID:              org.ID,
		Provider:           provider,
		ClientID:           clientID,
		ClientSecretSealed: []byte(sealed),
		SecretFingerprint:  sealer.Fingerprint([]byte(clientSecret)),
		TenantID:           tid,
		Enabled:            true,
	}); err != nil {
		fail(logger, "upsert failed: "+err.Error())
	}

	// The fingerprint is the keyed 12-hex digest the admin View shows; the secret itself is never
	// logged, printed or returned — the same rule the real config endpoint follows.
	logger.Info("dev_sso_config_written",
		slog.String("org", orgSlug),
		slog.String("provider", provider),
		slog.String("client_id", clientID),
		slog.String("secret_fingerprint", sealer.Fingerprint([]byte(clientSecret))),
		slog.String("redirect_uri", cfg.AppBaseURL+"/api/v1/auth/sso/"+provider+"/callback"),
		slog.String("next", "register that EXACT redirect_uri on the IdP app, then click the button at /login"))
}

func fail(logger *slog.Logger, msg string) {
	logger.Error("dev_sso_config_failed", slog.String("error", msg))
	os.Exit(1)
}
