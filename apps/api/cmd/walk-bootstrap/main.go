// Command walk-bootstrap stands up the S7.5.2 IdP-sync box-walk fixtures on top of the base `seed`
// (demo org + owner). Privileged/dev-only, like cmd/seed-enterprise — it talks to the DB + master
// key directly, so the walk needs no HTTP-auth dance for setup. Two phases:
//
//	-phase=1  seed the two Entra-matched users (+ memberships), mint a join token pinned to the
//	          gateway node name, and mint an owner CLI bearer. PRINTS the token + bearer.
//	-phase=2  (run after the gateway has enrolled) seed a device for each user on the enrolled
//	          node, flip the org to enforcing, and create a destination resource. PRINTS the ids.
//
// Idempotent (fixed UUIDs, upserts). NEVER for real data.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/secrets"
	"github.com/tunnexio/tunnex/apps/api/internal/seeddata"
)

const (
	nodeName    = "demo-gw"
	testUserID  = "01900000-0000-7000-8000-0000000000a1"
	linkUserID  = "01900000-0000-7000-8000-0000000000a2"
	testUserEml = "testuser@iotunnexoutlook.onmicrosoft.com"
	linkUserEml = "linkuser@iotunnexoutlook.onmicrosoft.com"
	testDevID   = "01900000-0000-7000-8000-0000000000b1"
	linkDevID   = "01900000-0000-7000-8000-0000000000b2"
	testDevIP   = "10.80.0.10"
	linkDevIP   = "10.80.0.11"
	dstCIDR     = "10.80.9.0/24"
)

func main() {
	phase := flag.Int("phase", 1, "1 = users+token+bearer (before enroll); 2 = devices+mode+resource (after enroll)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		fatal(log, "DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatal(log, "connect: "+err.Error())
	}
	defer pool.Close()

	orgID := uuid.MustParse(seeddata.DemoOrgID)
	ownerID := uuid.MustParse(seeddata.DemoOwnerUserID)

	switch *phase {
	case 1:
		phase1(ctx, log, pool, cfg, orgID, ownerID)
	case 2:
		phase2(ctx, log, pool, orgID)
	default:
		fatal(log, "phase must be 1 or 2")
	}
}

func phase1(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, cfg config.Config, orgID, ownerID uuid.UUID) {
	// 1. the two directory-matched users + memberships (emails = the Entra join keys).
	for _, u := range []struct{ id, email string }{{testUserID, testUserEml}, {linkUserID, linkUserEml}} {
		exec(ctx, log, pool,
			`INSERT INTO users (id,email,name,status) VALUES ($1,$2,$3,'active')
			 ON CONFLICT (id) DO UPDATE SET email=EXCLUDED.email, status='active', deleted_at=NULL`,
			u.id, u.email, u.email)
		exec(ctx, log, pool,
			`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')
			 ON CONFLICT (org_id,user_id) DO NOTHING`, orgID, u.id)
	}

	// 2. a join token pinned to the gateway node name (same hash scheme the agent redeems).
	raw := mustRandToken()
	sum := sha256sum(raw)
	name := nodeName
	if _, err := sqlc.New(pool).CreateJoinToken(ctx, sqlc.CreateJoinTokenParams{
		OrgID: orgID, NodeName: &name, TokenHash: sum, ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		fatal(log, "create join token: "+err.Error())
	}

	// 3. an owner CLI bearer so the walk drives PUT config / map / rule / trigger without a browser.
	sealer := loadSealer(log, cfg)
	cred, err := cliauth.NewService(pool, sealer).MintForUser(ctx, ownerID)
	if err != nil {
		fatal(log, "mint bearer: "+err.Error())
	}

	fmt.Println("\n=== PHASE 1 DONE ===")
	fmt.Printf("users seeded: %s , %s\n", testUserEml, linkUserEml)
	fmt.Printf("JOIN_TOKEN=%s\n", raw)
	fmt.Printf("OWNER_BEARER=%s\n", cred.Token)
	fmt.Println("Next: put JOIN_TOKEN in .env, `docker compose up -d node-agent`, wait for enrollment, then -phase=2.")
}

func phase2(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, orgID uuid.UUID) {
	// find the enrolled gateway node by name.
	var nodeID uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT id FROM nodes WHERE org_id=$1 AND name=$2 AND status='active' ORDER BY created_at DESC LIMIT 1`,
		orgID, nodeName).Scan(&nodeID); err != nil {
		fatal(log, "no enrolled node named "+nodeName+" (enroll the agent first): "+err.Error())
	}

	// a device per user on that node (assigned_ip = the /32 the compiler emits as a src grant).
	for _, d := range []struct{ id, user, ip string }{{testDevID, testUserID, testDevIP}, {linkDevID, linkUserID, linkDevIP}} {
		exec(ctx, log, pool,
			`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,full_tunnel,status)
			 VALUES ($1,$2,$3,$4,$5,'linux',$6,$7,false,'active')
			 ON CONFLICT (id) DO UPDATE SET node_id=EXCLUDED.node_id, assigned_ip=EXCLUDED.assigned_ip,
			   status='active', deleted_at=NULL, revoked_at=NULL`,
			d.id, orgID, d.user, nodeID, "dev-"+d.user[len(d.user)-4:], mustRandKey(), d.ip)
	}

	// enforcing mode (the allow-list + deny tail get compiled onto the gateway forward chain).
	exec(ctx, log, pool, `UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, orgID)

	// a destination resource for the rule (src = the synced group → this dst). Select-or-insert
	// (resources has a case-insensitive unique index, so ON CONFLICT column-inference won't match).
	var resID uuid.UUID
	err := pool.QueryRow(ctx, `SELECT id FROM resources WHERE org_id=$1 AND name='walk-dst'`, orgID).Scan(&resID)
	if err == pgx.ErrNoRows {
		if e := pool.QueryRow(ctx,
			`INSERT INTO resources (org_id,name,cidr,protocol) VALUES ($1,'walk-dst',$2,'any') RETURNING id`,
			orgID, dstCIDR).Scan(&resID); e != nil {
			fatal(log, "create resource: "+e.Error())
		}
	} else if err != nil {
		fatal(log, "lookup resource: "+err.Error())
	}

	fmt.Println("\n=== PHASE 2 DONE ===")
	fmt.Printf("NODE_ID=%s\n", nodeID)
	fmt.Printf("devices: %s -> %s , %s -> %s\n", testUserEml, testDevIP, linkUserEml, linkDevIP)
	fmt.Printf("mode=enforcing\n")
	fmt.Printf("RESOURCE_ID=%s  (cidr %s)\n", resID, dstCIDR)
}

func loadSealer(log *slog.Logger, cfg config.Config) *crypto.Sealer {
	if _, err := os.Stat(filepath.Join(cfg.SecretsDir, "master.key")); err != nil {
		fatal(log, "no master key at "+cfg.SecretsDir+" (the API must have booted with this secrets volume): "+err.Error())
	}
	sec, err := secrets.LoadOrInit(cfg.SecretsDir)
	if err != nil {
		fatal(log, "secrets: "+err.Error())
	}
	sealer, err := crypto.NewSealer(sec.MasterKey)
	if err != nil {
		fatal(log, "sealer: "+err.Error())
	}
	return sealer
}

func exec(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, sql string, args ...any) {
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		fatal(log, "exec: "+err.Error())
	}
}

func mustRandToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func mustRandKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func sha256sum(raw string) []byte {
	// matches nodes.hashToken (sha256 of the raw token string)
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func fatal(log *slog.Logger, msg string) {
	log.Error("walk_bootstrap_failed", slog.String("error", msg))
	os.Exit(1)
}
