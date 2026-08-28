package db_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestK8sClusterScopeActivationMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0121 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s204_scope_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 120); err != nil {
		t.Fatalf("migrate prerequisite chain through 0120: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	orgID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0121',$2,'10.248.0.0/24')`, orgID, "s204-scope-"+orgID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, userID, "s204-"+userID.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(dsn, 121); err != nil {
		t.Fatalf("apply 0121: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_cluster_scope_settings WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy organization must remain missing/OFF: count=%d err=%v", count, err)
	}
	if err := db.MigrateTo(dsn, 120); err != nil {
		t.Fatalf("empty 0121 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 121); err != nil {
		t.Fatalf("0121 re-up: %v", err)
	}
	var nullable, evidenceFK string
	if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns WHERE table_schema='public' AND table_name='k8s_cluster_scope_initial_candidates' AND column_name='inventory_report_id'`).Scan(&nullable); err != nil || nullable != "NO" {
		t.Fatalf("0121 exact inventory evidence nullable=%q err=%v", nullable, err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='k8s_cluster_scope_initial_candidates_inventory_report_fkey' AND conrelid='k8s_cluster_scope_initial_candidates'::regclass`).Scan(&evidenceFK); err != nil {
		t.Fatal(err)
	}
	if evidenceFK != "FOREIGN KEY (inventory_report_id, org_id, cluster_id) REFERENCES k8s_service_inventory_reports(id, org_id, cluster_id) ON DELETE RESTRICT" {
		t.Fatalf("0121 exact inventory evidence FK=%q", evidenceFK)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_cluster_scope_settings(org_id,enabled,revision,actor_user_id,cause) VALUES($1,false,1,$2,'cross-tenant')`, orgID, userID); err == nil {
		t.Fatal("0121 must reject a globally valid user who is not a member of the organization")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'admin')`, orgID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_cluster_scope_settings(org_id,enabled,revision,actor_user_id,cause) VALUES($1,false,1,$2,'explicit off')`, orgID, userID); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0121_k8s_cluster_scope_activation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("0121 down must refuse explicit OFF state because actor provenance would be lost")
	}
}
