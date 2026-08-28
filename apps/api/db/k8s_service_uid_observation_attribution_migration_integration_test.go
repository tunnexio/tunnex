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

func TestK8sServiceUIDObservationAttributionMigrationPostgres(t *testing.T) {
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
	t.Cleanup(admin.Close)
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s203a_attr_" + uuid.NewString()[:8]
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

	orgID, siteID, clusterID, connectorPoolID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	activeID, standbyID, replayID, standbyReplayID, ledgerID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0119',$2,'10.248.0.0/24')`, orgID, "s203a-attr-"+orgID.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'0119-site')`, siteID, orgID)
	for _, node := range []struct {
		id                  uuid.UUID
		name, key, endpoint string
	}{
		{activeID, "active", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "198.51.100.20:51820"},
		{standbyID, "standby", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "198.51.100.21:51820"},
	} {
		exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,status,wg_public_key,endpoint) VALUES($1,$2,$3,$4,$5,'active',$6,$7)`, node.id, orgID, node.name, "serial-"+node.id.String(), siteID, node.key, node.endpoint)
	}
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range) VALUES($1,$2,$3,'0119-cluster','100.125.0.0/24')`, clusterID, orgID, siteID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pools(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation) VALUES($1,$2,$3,$4,$5,$5,1)`, connectorPoolID, orgID, siteID, clusterID, activeID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id) VALUES($1,$2,$3,$4),($1,$2,$3,$5)`, connectorPoolID, orgID, siteID, activeID, standbyID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2`, connectorPoolID, clusterID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO k8s_service_uid_observation_replay_states(id,org_id,site_id,cluster_id,connector_node_id,scope_identity,sequence,digest) VALUES($1,$2,$3,$4,$5,'active-scope',1,$6)`, replayID, orgID, siteID, clusterID, activeID, strings.Repeat("a", 64))
	exec(`INSERT INTO k8s_service_uid_observation_ledgers(id,org_id,site_id,cluster_id,scope_identity) VALUES($1,$2,$3,$4,'cluster-ledger')`, ledgerID, orgID, siteID, clusterID)
	exec(`INSERT INTO k8s_service_uid_observation_current(ledger_id,org_id,namespace,service,uid,state,replay_sequence) VALUES($1,$2,'default','api','uid-v1','live',1)`, ledgerID, orgID)
	if err := db.MigrateTo(dsn, 119); err != nil {
		t.Fatalf("apply 0119: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_uid_observation_current_attributions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy current rows must remain unattributed: count=%d err=%v", count, err)
	}
	exec(`INSERT INTO k8s_service_uid_observation_current_attributions(ledger_id,org_id,namespace,service,replay_state_id,replay_sequence) VALUES($1,$2,'default','api',$3,1)`, ledgerID, orgID, replayID)
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_service_uid_observation_replay_states(id,org_id,site_id,cluster_id,connector_node_id,scope_identity,sequence,digest) VALUES($1,$2,$3,$4,$5,'standby-scope',1,$6)`, standbyReplayID, orgID, siteID, clusterID, standbyID, strings.Repeat("b", 64)); err == nil {
		t.Fatal("0117 must refuse a standby replay state")
	}
	down, err := os.ReadFile("migrations/0119_k8s_service_uid_observation_attribution.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("0119 down must refuse destructive loss while attribution exists")
	}
	exec(`UPDATE k8s_service_uid_observation_current SET uid='uid-v2' WHERE ledger_id=$1 AND namespace='default' AND service='api'`, ledgerID)
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_uid_observation_current_attributions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("mixed-version current write must invalidate attribution: count=%d err=%v", count, err)
	}
	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("0119 down after explicit de-attribution: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_uid_observation_current WHERE ledger_id=$1 AND uid='uid-v2'`, ledgerID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("0119 down must preserve current rows: count=%d err=%v", count, err)
	}
	if err := db.MigrateTo(dsn, 119); err != nil {
		t.Fatalf("0119 re-up: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_uid_observation_current_attributions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("0119 re-up must not invent attribution: count=%d err=%v", count, err)
	}
}
