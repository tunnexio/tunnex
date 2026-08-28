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

func TestK8sClusterProviderMetadataMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0124 PostgreSQL proof")
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
	name := "tnx_s204_provider_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 123); err != nil {
		t.Fatalf("migrate prerequisite chain through 0123: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	orgID, siteID, clusterID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0124',$2,'10.247.0.0/24')`, orgID, "s204-provider-"+orgID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'0124-site')`, siteID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range) VALUES($1,$2,$3,'legacy','100.125.0.0/24')`, clusterID, orgID, siteID); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(dsn, 124); err != nil {
		t.Fatalf("apply 0124: %v", err)
	}
	var provider, platform string
	if err := pool.QueryRow(ctx, `SELECT provider,platform FROM k8s_clusters WHERE id=$1`, clusterID).Scan(&provider, &platform); err != nil || provider != "unknown" || platform != "unknown" {
		t.Fatalf("legacy metadata inferred: provider=%q platform=%q err=%v", provider, platform, err)
	}
	if err := db.MigrateTo(dsn, 123); err != nil {
		t.Fatalf("empty/unknown 0124 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 124); err != nil {
		t.Fatalf("0124 re-up: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_clusters SET provider='aws',platform='eks' WHERE id=$1`, clusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_clusters SET provider='aws',platform='aks' WHERE id=$1`, clusterID); err == nil {
		t.Fatal("0124 must reject invalid provider/platform pairs")
	}
	down, err := os.ReadFile("migrations/0124_k8s_cluster_provider_metadata.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("0124 down must refuse non-unknown metadata")
	}
}
