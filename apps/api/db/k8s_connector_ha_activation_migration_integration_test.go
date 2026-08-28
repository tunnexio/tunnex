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

func TestK8sConnectorHAActivationMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0122 PostgreSQL proof")
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
	name := "tnx_s203b_ha_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 121); err != nil {
		t.Fatalf("migrate prerequisite chain through 0121: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	orgID, otherOrgID, userID := uuid.New(), uuid.New(), uuid.New()
	siteID, nodeID, clusterID, connectorPoolID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0122',$2,'10.249.0.0/24')`, orgID, "s203b-ha-"+orgID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0122-other',$2,'10.247.0.0/24')`, otherOrgID, "s203b-ha-other-"+otherOrgID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, userID, "s203b-ha-"+userID.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, otherOrgID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'0122-site')`, siteID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,org_id,site_id,name,cert_serial,status,wg_public_key,endpoint) VALUES($1,$2,$3,'0122-node',$4,'active','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','198.51.100.30:51820')`, nodeID, orgID, siteID, "s203b-ha-"+nodeID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range) VALUES($1,$2,$3,'0122-cluster','100.126.0.0/24')`, clusterID, orgID, siteID); err != nil {
		t.Fatal(err)
	}
	seedTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = seedTx.Exec(ctx, `INSERT INTO k8s_connector_pools(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation) VALUES($1,$2,$3,$4,$5,$5,1)`, connectorPoolID, orgID, siteID, clusterID, nodeID); err != nil {
		_ = seedTx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err = seedTx.Exec(ctx, `INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id) VALUES($1,$2,$3,$4)`, connectorPoolID, orgID, siteID, nodeID); err != nil {
		_ = seedTx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err = seedTx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2`, connectorPoolID, clusterID); err != nil {
		_ = seedTx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = seedTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(dsn, 122); err != nil {
		t.Fatalf("apply 0122: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_ha_settings WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy organization must remain missing/OFF: count=%d err=%v", count, err)
	}
	if err := db.MigrateTo(dsn, 121); err != nil {
		t.Fatalf("empty 0122 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 122); err != nil {
		t.Fatalf("0122 re-up: %v", err)
	}

	// The down preflight must wait for an in-flight writer, then observe its
	// committed row instead of dropping it after an earlier empty read.
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec(ctx, `INSERT INTO k8s_ha_settings(org_id,enabled,revision,actor_system,cause) VALUES($1,false,1,'migration-test','race proof')`, orgID); err != nil {
		_ = writer.Rollback(ctx)
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0122_k8s_connector_ha_activation.down.sql")
	if err != nil {
		_ = writer.Rollback(ctx)
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		_, downErr := pool.Exec(context.Background(), string(down))
		downResult <- downErr
	}()
	select {
	case downErr := <-downResult:
		_ = writer.Rollback(ctx)
		t.Fatalf("0122 down bypassed an in-flight writer before commit: %v", downErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err = writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case downErr := <-downResult:
		if downErr == nil {
			t.Fatal("0122 down must observe and refuse the row committed by the in-flight writer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("0122 down did not finish after the in-flight writer committed")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM k8s_ha_settings WHERE org_id=$1`, orgID); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO k8s_ha_settings(org_id,enabled,revision,actor_user_id,cause) VALUES($1,false,1,$2,'cross-org actor')`, orgID, userID); err == nil {
		t.Fatal("0122 settings must refuse an actor who belongs only to another organization")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,reason_code,actor_user_id,cause) VALUES($1,$2,$3,$4,'fenced_ha','bootstrap_pending',$5,1,'bootstrap_pending',$6,'cross-org actor')`, connectorPoolID, orgID, siteID, clusterID, nodeID, userID); err == nil {
		t.Fatal("0122 transition must refuse an actor who belongs only to another organization")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_ha_settings(org_id,enabled,revision,actor_user_id,cause) VALUES($1,false,1,$2,'explicit off')`, orgID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,achieved_authority_revision,reason_code,actor_user_id,cause,achieved_at) VALUES($1,$2,$3,$4,'fenced_ha','fenced_ha',$5,1,NULL,1,'fenced_ha_active',$6,'malformed fenced epoch',now())`, connectorPoolID, orgID, siteID, clusterID, nodeID, userID); err == nil {
		t.Fatal("0122 fenced HA transition must refuse a missing durable membership epoch")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,reason_code,actor_user_id,cause) VALUES($1,$2,$3,$4,'fenced_ha','bootstrap_pending',$5,1,'bootstrap_pending',$6,'bootstrap request')`, connectorPoolID, orgID, siteID, clusterID, nodeID, userID); err != nil {
		t.Fatal(err)
	}

	deliveryID := uuid.New()
	baseHash, payloadDigest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_base_authority_deliveries(id,org_id,site_id,node_id,authority_revision,wire_version,base_version,base_hash,payload_digest,payload,transition_revision,expires_at) VALUES($1,$2,$3,$4,1,1,7,$5,$6,'{}'::jsonb,1,now()+interval '5 minutes')`, deliveryID, orgID, siteID, nodeID, baseHash, payloadDigest); err != nil {
		t.Fatal(err)
	}
	insertACK := `INSERT INTO k8s_base_authority_ack_receipts(delivery_id,org_id,site_id,node_id,authority_revision,payload_digest,applied_base_version,applied_base_hash,agent_applied_at,receipt_time) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),now())`
	for _, mismatch := range []struct {
		name              string
		authorityRevision int
		digest            string
		baseVersion       int
		baseHash          string
	}{
		{"authority revision", 2, payloadDigest, 7, baseHash},
		{"payload digest", 1, strings.Repeat("d", 64), 7, baseHash},
		{"base version", 1, payloadDigest, 8, baseHash},
		{"base hash", 1, payloadDigest, 7, strings.Repeat("e", 64)},
	} {
		if _, err := pool.Exec(ctx, insertACK, deliveryID, orgID, siteID, nodeID, mismatch.authorityRevision, mismatch.digest, mismatch.baseVersion, mismatch.baseHash); err == nil {
			t.Fatalf("0122 ACK must refuse a mismatched %s", mismatch.name)
		}
	}
	if _, err := pool.Exec(ctx, insertACK, deliveryID, orgID, siteID, nodeID, 1, payloadDigest, 7, baseHash); err != nil {
		t.Fatalf("0122 exact ACK: %v", err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("0122 down must refuse exact HA state because provenance would be lost")
	}
}
