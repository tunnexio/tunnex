package db_test

import (
	"context"
	"crypto/sha256"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestAgentBootstrapTokenRevocationMigrationPostgres proves 0248 against real
// PostgreSQL: existing tokens stay pending, a token cannot be both used and
// revoked, and rolling back never makes a revoked token redeemable again.
func TestAgentBootstrapTokenRevocationMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminPool.Close()
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	name := "tnx_aisec1_bootstrap_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	branchURL := *u
	branchURL.Path = "/" + name
	dsn := branchURL.String()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.MigrateTo(dsn, 247); err != nil {
		t.Fatalf("migrate to 0247: %v", err)
	}
	org, node := uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'0248',$2,'10.96.0.0/24')`, org, "m0248-"+org.String()[:8])
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'m0248-gw',$3,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','gw.example:51820','active')`, node, org, "m0248-"+node.String())
	insert := func(label string) uuid.UUID {
		t.Helper()
		hash := sha256.Sum256([]byte(label + uuid.NewString()))
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO agent_bootstrap_tokens (org_id,gateway_node_id,agent_name,token_hash,expires_at) VALUES ($1,$2,$3,$4,now()+interval '1 hour') RETURNING id`, org, node, label, hash[:]).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	existing := insert("existing")

	if err := db.MigrateTo(dsn, 248); err != nil {
		t.Fatalf("migrate to 0248: %v", err)
	}
	var revokedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT revoked_at FROM agent_bootstrap_tokens WHERE id=$1`, existing).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt != nil {
		t.Fatal("0248 must leave existing tokens pending")
	}
	revoked := insert("revoked")
	exec(`UPDATE agent_bootstrap_tokens SET revoked_at=now() WHERE id=$1`, revoked)
	if _, err := pool.Exec(ctx, `UPDATE agent_bootstrap_tokens SET consumed_at=now() WHERE id=$1`, revoked); err == nil {
		t.Fatal("a revoked token must not also become used")
	}

	if err := db.MigrateTo(dsn, 247); err != nil {
		t.Fatalf("roll back 0248: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_bootstrap_tokens WHERE id=$1`, revoked).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("rolling back 0248 must not leave a revoked token redeemable")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_bootstrap_tokens WHERE id=$1`, existing).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatal("rolling back 0248 must keep tokens that were never revoked")
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='agent_bootstrap_tokens' AND column_name IN ('revoked_at','revoked_by')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 0 {
		t.Fatalf("0248 down left %d revocation column(s)", columns)
	}
	if err := db.MigrateTo(dsn, 248); err != nil {
		t.Fatalf("migrate to 0248 again: %v", err)
	}
}
