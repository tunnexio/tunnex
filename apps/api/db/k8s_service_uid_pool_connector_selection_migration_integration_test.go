package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestK8sServiceUIDPoolConnectorSelectionMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0119 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s203a_uid_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("migrate prerequisite chain through 0118: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	orgID, siteID := uuid.New(), uuid.New()
	activeID, standbyID, legacyID := uuid.New(), uuid.New(), uuid.New()
	poolClusterID, legacyClusterID, connectorPoolID := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'S20.3a UID',$2,'10.247.0.0/24')`, orgID, "s203a-uid-"+orgID.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'S20.3a Site')`, siteID, orgID)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,status,wg_public_key,endpoint)
		VALUES($1,$2,'active',$3,$4,'active','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','198.51.100.10:51820')`, activeID, orgID, "s203a-active-"+activeID.String(), siteID)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,status,wg_public_key,endpoint)
		VALUES($1,$2,'standby',$3,$4,'active','BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','198.51.100.11:51820')`, standbyID, orgID, "s203a-standby-"+standbyID.String(), siteID)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,status,wg_public_key,endpoint)
		VALUES($1,$2,'legacy',$3,$4,'active','CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=','198.51.100.12:51820')`, legacyID, orgID, "s203a-legacy-"+legacyID.String(), siteID)
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,connector_node_id,name,vip_range)
		VALUES($1,$2,$3,$4,'pool-cluster','100.123.0.0/24')`, poolClusterID, orgID, siteID, activeID)
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,connector_node_id,name,vip_range)
		VALUES($1,$2,$3,$4,'legacy-cluster','100.124.0.0/24')`, legacyClusterID, orgID, siteID, legacyID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pools(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation)
		VALUES($1,$2,$3,$4,$5,$5,1)`, connectorPoolID, orgID, siteID, poolClusterID, activeID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id,admin_priority)
		VALUES($1,$2,$3,$4,10),($1,$2,$3,$5,1)`, connectorPoolID, orgID, siteID, activeID, standbyID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE k8s_clusters SET connector_node_id=NULL,connector_pool_id=$1 WHERE id=$2`, connectorPoolID, poolClusterID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	insertReplay := func(clusterID, connectorID uuid.UUID, identity string) error {
		_, err := pool.Exec(ctx, `INSERT INTO k8s_service_uid_observation_replay_states
			(org_id,site_id,cluster_id,connector_node_id,scope_identity)
			VALUES($1,$2,$3,$4,$5)`, orgID, siteID, clusterID, connectorID, identity)
		return err
	}
	deleteReplay := func(clusterID uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM k8s_service_uid_observation_replay_states WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID); err != nil {
			t.Fatal(err)
		}
	}
	expectRejected := func(name string, fn func() error) {
		t.Helper()
		if err := fn(); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	resetActive := func() {
		t.Helper()
		exec(`UPDATE nodes SET status='active',revoked_at=NULL,wg_public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',endpoint='198.51.100.10:51820' WHERE id=$1`, activeID)
	}

	if err := db.MigrateTo(dsn, 119); err != nil {
		t.Fatalf("apply 0119: %v", err)
	}
	if err := insertReplay(poolClusterID, activeID, "pool-active"); err != nil {
		t.Fatalf("eligible pool active connector: %v", err)
	}
	expectRejected("pool standby connector", func() error { return insertReplay(poolClusterID, standbyID, "pool-standby") })
	deleteReplay(poolClusterID)

	exec(`UPDATE nodes SET revoked_at=now() WHERE id=$1`, activeID)
	expectRejected("revoked active connector", func() error { return insertReplay(poolClusterID, activeID, "pool-revoked") })
	resetActive()
	exec(`UPDATE nodes SET wg_public_key='invalid' WHERE id=$1`, activeID)
	expectRejected("invalid-key active connector", func() error { return insertReplay(poolClusterID, activeID, "pool-invalid-key") })
	resetActive()
	exec(`UPDATE nodes SET endpoint='   ' WHERE id=$1`, activeID)
	expectRejected("empty-endpoint active connector", func() error { return insertReplay(poolClusterID, activeID, "pool-empty-endpoint") })
	resetActive()
	exec(`UPDATE nodes SET status='revoked' WHERE id=$1`, activeID)
	expectRejected("inactive active connector", func() error { return insertReplay(poolClusterID, activeID, "pool-inactive") })
	resetActive()

	if err := insertReplay(poolClusterID, activeID, "pool-progress"); err != nil {
		t.Fatalf("recreate eligible pool replay state: %v", err)
	}
	exec(`UPDATE nodes SET revoked_at=now() WHERE id=$1`, activeID)
	expectRejected("revoked connector replay progress", func() error {
		_, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states
			SET sequence=1,digest=$1 WHERE org_id=$2 AND cluster_id=$3 AND connector_node_id=$4`, strings.Repeat("a", 64), orgID, poolClusterID, activeID)
		return err
	})
	resetActive()
	exec(`UPDATE k8s_connector_pools SET active_node_id=$1,generation=2 WHERE id=$2`, standbyID, connectorPoolID)
	expectRejected("former active connector replay progress", func() error {
		_, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states
			SET sequence=1,digest=$1 WHERE org_id=$2 AND cluster_id=$3 AND connector_node_id=$4`, strings.Repeat("b", 64), orgID, poolClusterID, activeID)
		return err
	})
	deleteReplay(poolClusterID)
	if err := insertReplay(poolClusterID, standbyID, "pool-promoted-active"); err != nil {
		t.Fatalf("promoted exact pool active connector: %v", err)
	}
	deleteReplay(poolClusterID)
	exec(`UPDATE k8s_connector_pools SET active_node_id=$1,generation=3 WHERE id=$2`, activeID, connectorPoolID)

	if err := insertReplay(legacyClusterID, legacyID, "legacy-up"); err != nil {
		t.Fatalf("legacy selected connector must remain accepted: %v", err)
	}
	deleteReplay(poolClusterID)
	deleteReplay(legacyClusterID)
	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("0119 down: %v", err)
	}
	expectRejected("pool connector after 0119 down", func() error { return insertReplay(poolClusterID, activeID, "pool-down") })
	if err := insertReplay(legacyClusterID, legacyID, "legacy-down"); err != nil {
		t.Fatalf("0119 down must restore 0084 legacy behavior: %v", err)
	}
	deleteReplay(legacyClusterID)
	if err := db.MigrateTo(dsn, 119); err != nil {
		t.Fatalf("0119 re-up: %v", err)
	}
	if err := insertReplay(poolClusterID, activeID, "pool-re-up"); err != nil {
		t.Fatalf("0119 re-up must restore pool active behavior: %v", err)
	}
}
