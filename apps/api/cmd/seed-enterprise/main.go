// Command seed-enterprise lays down the ENTERPRISE seed fixtures ON TOP of the
// base `seed` (S7.4c). It never forks the base data — it assumes the demo org +
// owner already exist and adds only what the enterprise e2e assertions need:
//
//   - an sso_configs row (client secret SEALED under the master key) so the SSO
//     config View (S4.5) returns a real non-secret projection to assert on;
//   - a gateway node row + a device holding a pool IP (10.99.0.200) so a pool
//     shrink strands it and the resize endpoint returns the REAL 409 orphan list
//     (S4.5b) — no enrolled agent/mTLS is involved; the orphan check reads device
//     rows purely from the DB (verified S7.4c D-c4).
//
// Idempotent (upserts on the fixed seeddata IDs) and non-destructive: it refuses
// to run until the base seed exists. Development/CI only — never real data.
package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/secrets"
	"github.com/tunnexio/tunnex/apps/api/internal/seeddata"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Load()

	if cfg.DatabaseURL == "" {
		logger.Error("seed_enterprise_config_error", slog.String("error", "DATABASE_URL is required"))
		os.Exit(1)
	}

	// The master key MUST already exist (the API bootstrap wrote it). LoadOrInit
	// would silently MINT a fresh key if the secrets dir is empty/mismatched (e.g.
	// a wrong compose-project volume name) — sealing the secret under a key the
	// running API can never open. Fail loud if the key file is absent instead.
	if _, err := os.Stat(filepath.Join(cfg.SecretsDir, "master.key")); err != nil {
		logger.Error("seed_enterprise_no_master_key",
			slog.String("secrets_dir", cfg.SecretsDir),
			slog.String("hint", "the API must have booted (and its secrets volume mounted here) before seed-enterprise; check SECRETS_VOL"),
			slog.String("error", err.Error()))
		os.Exit(1)
	}
	// LoadOrInit on the SAME secrets dir now yields the SAME key the API uses.
	sec, err := secrets.LoadOrInit(cfg.SecretsDir)
	if err != nil {
		logger.Error("seed_enterprise_secrets_failed",
			slog.String("secrets_dir", cfg.SecretsDir), slog.String("error", err.Error()))
		os.Exit(1)
	}
	sealer, err := crypto.NewSealer(sec.MasterKey)
	if err != nil {
		logger.Error("seed_enterprise_sealer_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("seed_enterprise_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	orgID := uuid.MustParse(seeddata.DemoOrgID)
	ownerID := uuid.MustParse(seeddata.DemoOwnerUserID)

	// Compose-on-top guard: the base seed must have run first. Check BOTH the org
	// AND the owner user — the device INSERT below has FKs on both, so guarding
	// only the org would pass then abort mid-seed (sso+node written, device fails
	// on the user FK), leaving the fixtures half-applied.
	var baseSeedPresent bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1 AND deleted_at IS NULL)
		    AND EXISTS (SELECT 1 FROM users WHERE id = $2)`,
		orgID, ownerID).Scan(&baseSeedPresent); err != nil {
		logger.Error("seed_enterprise_check_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if !baseSeedPresent {
		logger.Error("seed_enterprise_refused",
			slog.String("hint", "base seed (org + owner user) missing; run `make seed` before `make seed-enterprise`"),
			slog.String("demo_org_id", seeddata.DemoOrgID))
		os.Exit(1)
	}

	q := sqlc.New(pool)

	// 1) SSO config — seal the secret, then upsert. Mirrors sso.ConfigService.Set
	//    minus the audit row (a seed makes no actor-attributed audit event).
	sealed, err := sealer.Seal([]byte(seeddata.DemoSSOClientSecret))
	if err != nil {
		logger.Error("seed_enterprise_seal_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	fingerprint := sealer.Fingerprint([]byte(seeddata.DemoSSOClientSecret))
	if _, err := q.UpsertSSOConfig(ctx, sqlc.UpsertSSOConfigParams{
		OrgID:              orgID,
		Provider:           seeddata.DemoSSOProvider,
		ClientID:           seeddata.DemoSSOClientID,
		ClientSecretSealed: []byte(sealed),
		SecretFingerprint:  fingerprint,
		Enabled:            true,
	}); err != nil {
		logger.Error("seed_enterprise_sso_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// 2) Gateway node row (fixed ID). CreateNode is a plain INSERT, so upsert via
	//    raw SQL to stay idempotent on the fixed seed ID. No cert/enrollment — the
	//    row only satisfies the device's node_id FK.
	nodeID := uuid.MustParse(seeddata.DemoGatewayNodeID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO nodes (id, org_id, name, status, cert_serial, agent_version)
		 VALUES ($1, $2, $3, 'active', 'demo-seed-no-cert', 'seed')
		 ON CONFLICT (id) DO UPDATE
		   SET org_id = EXCLUDED.org_id, name = EXCLUDED.name, status = EXCLUDED.status`,
		nodeID, orgID, seeddata.DemoGatewayNodeName); err != nil {
		logger.Error("seed_enterprise_node_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// 3) A device holding a pool IP a shrink strands (fixed ID, idempotent upsert).
	deviceID := uuid.MustParse(seeddata.DemoStrandableDeviceID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO devices (id, org_id, user_id, node_id, name, platform, public_key, assigned_ip, full_tunnel, status)
		 VALUES ($1, $2, $3, $4, $5, 'seed', $6, $7, false, 'active')
		 ON CONFLICT (id) DO UPDATE
		   SET assigned_ip = EXCLUDED.assigned_ip, status = EXCLUDED.status,
		       node_id = EXCLUDED.node_id, name = EXCLUDED.name`,
		deviceID, orgID, ownerID, nodeID,
		seeddata.DemoStrandableDeviceName, seeddata.DemoStrandableDevicePubKey,
		seeddata.DemoStrandableDeviceIP); err != nil {
		logger.Error("seed_enterprise_device_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("seed_enterprise_complete",
		slog.String("sso_provider", seeddata.DemoSSOProvider),
		slog.String("secret_fingerprint", fingerprint),
		slog.String("gateway_node_id", seeddata.DemoGatewayNodeID),
		slog.String("strandable_device_ip", seeddata.DemoStrandableDeviceIP),
	)
}
