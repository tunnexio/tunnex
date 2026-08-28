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

func TestK8sServiceInventoryRetentionMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0123 PostgreSQL proof")
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
	name := "tnx_s204_retention_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 122); err != nil {
		t.Fatalf("migrate prerequisite chain through 0122: %v", err)
	}
	if err := db.MigrateTo(dsn, 123); err != nil {
		t.Fatalf("apply 0123: %v", err)
	}
	if err := db.MigrateTo(dsn, 122); err != nil {
		t.Fatalf("empty 0123 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 123); err != nil {
		t.Fatalf("0123 re-up: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var nullable string
	if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns WHERE table_name='k8s_cluster_scope_initial_candidates' AND column_name='inventory_report_id'`).Scan(&nullable); err != nil || nullable != "NO" {
		t.Fatalf("inventory evidence FK column nullable=%q err=%v", nullable, err)
	}
	if _, err := pool.Exec(ctx, `SELECT k8s_service_inventory_prune($1,$2,19)`, uuid.New(), uuid.New()); err == nil {
		t.Fatal("0123 accepted a caller-selected retention bound")
	}
	for _, signature := range []string{
		"k8s_service_inventory_retention_authorized(uuid)",
		"k8s_service_inventory_prune(uuid,uuid,integer)",
	} {
		var publicExecute bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_proc function
				CROSS JOIN LATERAL aclexplode(COALESCE(function.proacl,acldefault('f',function.proowner))) privilege
				WHERE function.oid=$1::regprocedure
				  AND privilege.grantee=0
				  AND privilege.privilege_type='EXECUTE'
			)`, signature).Scan(&publicExecute); err != nil {
			t.Fatal(err)
		}
		if publicExecute {
			t.Fatalf("PUBLIC can execute security-definer retention function %s", signature)
		}
	}
}
