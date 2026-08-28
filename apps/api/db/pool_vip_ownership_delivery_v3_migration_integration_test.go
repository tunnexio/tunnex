package db_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestPoolVIPOwnershipDeliveryV3MigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0118 PostgreSQL proof")
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
	databaseName := "tnx_s203a_v3_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	testURL := *base
	testURL.Path = "/" + databaseName
	dsn := testURL.String()

	if err := db.MigrateTo(dsn, 117); err != nil {
		t.Fatalf("migrate prerequisite chain through 0117: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	assertPoolVIPOwnershipProvenanceCapabilityConstraintName(t, ctx, pool, "pool_vip_ownership_handoff_provenance_capabi_wire_version_check")

	orgID, siteID, clusterID, poolID, nodeID, stateID := seedPoolVIPOwnershipDeliveryV3Migration(t, ctx, pool)
	v1DeliveryID := insertPoolVIPOwnershipMigrationDelivery(t, ctx, pool, orgID, siteID, clusterID, poolID, nodeID, 1, nil)
	v2DeliveryID := insertPoolVIPOwnershipMigrationDelivery(t, ctx, pool, orgID, siteID, clusterID, poolID, nodeID, 2, nil)

	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("0118 up: %v", err)
	}
	assertPoolVIPOwnershipV3MigrationObjects(t, ctx, pool, true)
	var preserved int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE id=ANY($1) AND ownership_manifest='{}'::jsonb`, []uuid.UUID{v1DeliveryID, v2DeliveryID}).Scan(&preserved); err != nil || preserved != 2 {
		t.Fatalf("0118 must preserve v1/v2 rows with an empty manifest: count=%d err=%v", preserved, err)
	}

	manifest := `{"manifest":"v3"}`
	v3DeliveryID := insertPoolVIPOwnershipMigrationDelivery(t, ctx, pool, orgID, siteID, clusterID, poolID, nodeID, 3, &manifest)
	expectPoolVIPOwnershipAckRejected(t, ctx, pool, orgID, stateID, v1DeliveryID, 1, &manifest)
	expectPoolVIPOwnershipAckRejected(t, ctx, pool, orgID, stateID, v2DeliveryID, 2, &manifest)
	expectPoolVIPOwnershipAckRejected(t, ctx, pool, orgID, stateID, v3DeliveryID, 3, nil)

	insertPoolVIPOwnershipMigrationAck(t, ctx, pool, orgID, stateID, v2DeliveryID, 2, nil)
	insertPoolVIPOwnershipMigrationAck(t, ctx, pool, orgID, stateID, v3DeliveryID, 3, &manifest)
	// The documented operator precondition is to remove v3 provenance before
	// contraction. Exercise the reversible path after that cleanup; deliberately
	// attempting a refused golang-migrate down would mark the version dirty before
	// PostgreSQL executes the guard and would test repair tooling, not 0118.
	if _, err := pool.Exec(ctx, `DELETE FROM pool_vip_ownership_delivery_ack_receipts WHERE delivery_row_id=$1`, v3DeliveryID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM pool_vip_ownership_deliveries WHERE id=$1`, v3DeliveryID); err != nil {
		t.Fatal(err)
	}

	if err := db.MigrateTo(dsn, 117); err != nil {
		t.Fatalf("0118 down after v3 cleanup: %v", err)
	}
	assertPoolVIPOwnershipV3MigrationObjects(t, ctx, pool, false)
	assertPoolVIPOwnershipProvenanceCapabilityConstraintName(t, ctx, pool, "pool_vip_ownership_handoff_provenance_capabi_wire_version_check")
	if err := db.MigrateTo(dsn, 118); err != nil {
		t.Fatalf("0118 re-up: %v", err)
	}
	assertPoolVIPOwnershipV3MigrationObjects(t, ctx, pool, true)
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE id=ANY($1) AND ownership_manifest='{}'::jsonb`, []uuid.UUID{v1DeliveryID, v2DeliveryID}).Scan(&preserved); err != nil || preserved != 2 {
		t.Fatalf("0118 re-up must preserve v1/v2 rows: count=%d err=%v", preserved, err)
	}
}

func seedPoolVIPOwnershipDeliveryV3Migration(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	orgID, siteID, clusterID, poolID, nodeID, stateID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed 0118 fixture: %v", err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'S20.3a v3',$2,'10.246.0.0/24')`, orgID, "s203a-v3-"+orgID.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'S20.3a v3 site')`, siteID, orgID)
	exec(`INSERT INTO nodes(id,org_id,site_id,name,cert_serial,agent_version,status,wg_public_key,endpoint)
		VALUES($1,$2,$3,'v3 connector',$4,'test','active','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','198.51.100.20:51820')`, nodeID, orgID, siteID, "s203a-v3-"+nodeID.String())
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,connector_node_id,name,vip_range) VALUES($1,$2,$3,$4,'v3 cluster','100.125.0.0/24')`, clusterID, orgID, siteID, nodeID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pools(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation) VALUES($1,$2,$3,$4,$5,$5,1)`, poolID, orgID, siteID, clusterID, nodeID); err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id) VALUES($1,$2,$3,$4)`, poolID, orgID, siteID, nodeID)
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO pool_vip_ownership_delivery_states(id,org_id,site_id,cluster_id,pool_id,connector_node_id,scope_identity) VALUES($1,$2,$3,$4,$5,$6,'s20.3a-v3')`, stateID, orgID, siteID, clusterID, poolID, nodeID)
	return orgID, siteID, clusterID, poolID, nodeID, stateID
}

func insertPoolVIPOwnershipMigrationDelivery(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, siteID, clusterID, poolID, nodeID uuid.UUID, version int, manifest *string) uuid.UUID {
	t.Helper()
	deliveryID, operationID := uuid.New(), uuid.New()
	routes, routeDigest := `[]`, ""
	if version > 1 {
		routeDigest = strings.Repeat("b", 64)
	}
	var rowID uuid.UUID
	if version == 3 {
		if manifest == nil {
			t.Fatal("v3 delivery manifest is required")
		}
		if err := pool.QueryRow(ctx, `INSERT INTO pool_vip_ownership_deliveries
			(org_id,site_id,cluster_id,pool_id,connector_node_id,target_node_id,operation_id,wire_version,manifest_identity,role,promotion_generation,manifest_revision,lease_epoch,delivery_phase,delivery_id,delivery_nonce,owned_routes,expected_route_digest,expected_vip_map_digest,prior_lease_epoch,expires_at,ownership_manifest)
			VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8,'prepared_non_serving',$9,$9,$9,'prepare',$10,$11,$12::jsonb,$13,'',0,now()+interval '1 hour',$14::jsonb) RETURNING id`, orgID, siteID, clusterID, poolID, nodeID, operationID, version, strings.Repeat("a", 64), version, deliveryID, strings.Repeat("c", 64), routes, routeDigest, *manifest).Scan(&rowID); err != nil {
			t.Fatal(err)
		}
		return rowID
	}
	if err := pool.QueryRow(ctx, `INSERT INTO pool_vip_ownership_deliveries
		(org_id,site_id,cluster_id,pool_id,connector_node_id,target_node_id,operation_id,wire_version,manifest_identity,role,promotion_generation,manifest_revision,lease_epoch,delivery_phase,delivery_id,delivery_nonce,owned_routes,expected_route_digest,expected_vip_map_digest,prior_lease_epoch,expires_at)
		VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8,'prepared_non_serving',$9,$9,$9,'prepare',$10,$11,$12::jsonb,$13,'',0,now()+interval '1 hour') RETURNING id`, orgID, siteID, clusterID, poolID, nodeID, operationID, version, strings.Repeat("a", 64), version, deliveryID, strings.Repeat("c", 64), routes, routeDigest).Scan(&rowID); err != nil {
		t.Fatal(err)
	}
	return rowID
}

func expectPoolVIPOwnershipAckRejected(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, stateID, deliveryID uuid.UUID, version int, manifest *string) {
	t.Helper()
	if err := insertPoolVIPOwnershipMigrationAckRaw(ctx, pool, orgID, stateID, deliveryID, version, manifest); err == nil || !strings.Contains(err.Error(), "ownership acknowledgement manifest does not match delivery wire version") {
		t.Fatalf("wire v%d manifest mismatch must be rejected by the 0118 trigger: %v", version, err)
	}
}

func insertPoolVIPOwnershipMigrationAck(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, stateID, deliveryID uuid.UUID, version int, manifest *string) {
	t.Helper()
	if err := insertPoolVIPOwnershipMigrationAckRaw(ctx, pool, orgID, stateID, deliveryID, version, manifest); err != nil {
		t.Fatalf("insert valid wire v%d acknowledgement: %v", version, err)
	}
}

func insertPoolVIPOwnershipMigrationAckRaw(ctx context.Context, pool *pgxpool.Pool, orgID, stateID, deliveryID uuid.UUID, version int, manifest *string) error {
	manifestValue := any(nil)
	if manifest != nil {
		manifestValue = *manifest
	}
	if version == 1 {
		_, err := pool.Exec(ctx, `INSERT INTO pool_vip_ownership_delivery_ack_receipts
			(org_id,delivery_row_id,state_id,fingerprint,receipt_time,applied_manifest)
			VALUES($1,$2,$3,$4,now(),$5::jsonb)`, orgID, deliveryID, stateID, fmt.Sprintf("fingerprint-v%d", version), manifestValue)
		return err
	}
	_, err := pool.Exec(ctx, `INSERT INTO pool_vip_ownership_delivery_ack_receipts
		(org_id,delivery_row_id,state_id,fingerprint,receipt_time,applied_role,applied_manifest_identity,applied_promotion_generation,applied_manifest_revision,applied_lease_epoch,owned_route_digest,vip_map_digest,applied_manifest)
		VALUES($1,$2,$3,$4,now(),'prepared_non_serving',$5,$6,$6,$6,$7,'',$8::jsonb)`, orgID, deliveryID, stateID, fmt.Sprintf("fingerprint-v%d", version), strings.Repeat("a", 64), version, strings.Repeat("b", 64), manifestValue)
	return err
}

func assertPoolVIPOwnershipV3MigrationObjects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, wantV3 bool) {
	t.Helper()
	var deliveryConstraint, capabilityConstraint, provenanceCapabilityConstraint, provenanceScopeFunction string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='pool_vip_ownership_deliveries'::regclass AND conname='pool_vip_ownership_deliveries_wire_version_check'`).Scan(&deliveryConstraint); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='k8s_pool_ownership_v2_capabilities'::regclass AND conname='k8s_pool_ownership_v2_capabilities_wire_version_check'`).Scan(&capabilityConstraint); err != nil {
		t.Fatal(err)
	}
	provenanceConstraintName := "pool_vip_ownership_handoff_provenance_capabi_wire_version_check"
	if wantV3 {
		provenanceConstraintName = "pool_vip_handoff_provenance_caps_wire_version_check"
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='pool_vip_ownership_handoff_provenance_capabilities'::regclass AND conname=$1`, provenanceConstraintName).Scan(&provenanceCapabilityConstraint); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('pool_vip_ownership_handoff_provenance_require_child_scope()'::regprocedure)`).Scan(&provenanceScopeFunction); err != nil {
		t.Fatal(err)
	}
	provenanceScopeSQL := strings.ToLower(provenanceScopeFunction)
	provenanceScopeCompact := strings.Join(strings.Fields(provenanceScopeSQL), "")
	var manifestColumn, manifestTrigger bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='pool_vip_ownership_delivery_ack_receipts' AND column_name='applied_manifest')`).Scan(&manifestColumn); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='pool_vip_ownership_delivery_ack_receipts'::regclass AND tgname='pool_vip_ownership_ack_manifest_matches_wire_version_before_write' AND NOT tgisinternal)`).Scan(&manifestTrigger); err != nil {
		t.Fatal(err)
	}
	if wantV3 {
		if !strings.Contains(deliveryConstraint, "ANY (ARRAY[1, 2, 3])") || !strings.Contains(capabilityConstraint, "ANY (ARRAY[2, 3])") || !strings.Contains(provenanceCapabilityConstraint, "ANY (ARRAY[2, 3])") || !strings.Contains(provenanceScopeCompact, "d.wire_version=new.wire_version") || !strings.Contains(provenanceScopeCompact, "a.applied_manifest=d.ownership_manifest") || !manifestColumn || !manifestTrigger {
			t.Fatalf("0118 objects missing: delivery=%q capability=%q provenance_capability=%q provenance_scope=%q column=%v trigger=%v", deliveryConstraint, capabilityConstraint, provenanceCapabilityConstraint, provenanceScopeFunction, manifestColumn, manifestTrigger)
		}
		return
	}
	if !strings.Contains(deliveryConstraint, "ANY (ARRAY[1, 2])") || !strings.Contains(capabilityConstraint, "wire_version = 2") || !strings.Contains(provenanceCapabilityConstraint, "wire_version = 2") || !strings.Contains(provenanceScopeCompact, "d.wire_version=2") || strings.Contains(provenanceScopeCompact, "a.applied_manifest=d.ownership_manifest") || manifestColumn || manifestTrigger {
		t.Fatalf("0118 down did not restore v1/v2 objects: delivery=%q capability=%q provenance_capability=%q provenance_scope=%q column=%v trigger=%v", deliveryConstraint, capabilityConstraint, provenanceCapabilityConstraint, provenanceScopeFunction, manifestColumn, manifestTrigger)
	}
}

func assertPoolVIPOwnershipProvenanceCapabilityConstraintName(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want string) {
	t.Helper()
	var names []string
	rows, err := pool.Query(ctx, `SELECT conname FROM pg_constraint WHERE conrelid='pool_vip_ownership_handoff_provenance_capabilities'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%wire_version%' ORDER BY conname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != want {
		t.Fatalf("wire-version constraint names=%v, want [%s]", names, want)
	}
}
