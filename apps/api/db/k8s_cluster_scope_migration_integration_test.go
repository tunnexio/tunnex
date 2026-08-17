package db_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestK8sClusterScopeMigrationUpDownUp proves the additive P3 0086 migration
// against the consolidated 0079–0085 chain. The disposable database keeps the
// real order independent of whatever schema the local admin database has.
func TestK8sClusterScopeMigrationUpDownUp(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0086 up/down/up integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	name := fmt.Sprintf("tnx_cluster_scope_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") }()
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dsn := u.String()
	if err := db.MigrateTo(dsn, 85); err != nil {
		t.Fatalf("migrate consolidated prerequisite chain through 0085: %v", err)
	}
	if err := db.MigrateTo(dsn, 86); err != nil {
		t.Fatalf("apply 0086: %v", err)
	}
	if err := db.MigrateTo(dsn, 85); err != nil {
		t.Fatalf("empty 0086 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 86); err != nil {
		t.Fatalf("0086 re-up: %v", err)
	}
}
