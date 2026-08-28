package nodes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestPostgresK8sServiceInventoryStorePersistsAttributedSnapshotAndDuplicate(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run inventory PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	if err := db.MigrateTo(pool.Config().ConnString(), 123); err != nil {
		t.Fatalf("migrate through 0123: %v", err)
	}
	scope := K8sServiceUIDObservationScope{OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID, ClusterID: fixture.scope.ClusterID, ConnectorNodeID: fixture.active}
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states SET scope_identity=$1 WHERE org_id=$2 AND cluster_id=$3 AND connector_node_id=$4`, k8sServiceUIDObservationScopeIdentity(scope), scope.OrgID, scope.ClusterID, scope.ConnectorNodeID); err != nil {
		t.Fatal(err)
	}
	agent := K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: scope.ConnectorNodeID}
	now := time.Now().UTC()
	report := K8sServiceInventoryReport{Version: 1, Sequence: 2, ObservedAt: now, Services: []K8sServiceInventoryService{{Namespace: "default", Service: "api", UID: "uid-api-v2", Ports: []K8sServiceInventoryPort{{Name: "https", Protocol: "tcp", Port: 443}, {Name: "dns", Protocol: "udp", Port: 53}}}}}
	report.Digest = K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
	store := NewPostgresK8sServiceInventoryStore(pool)
	first, err := store.WriteK8sServiceInventory(ctx, agent, report, now)
	if err != nil || first.Duplicate {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	duplicate, err := NewPostgresK8sServiceInventoryStore(pool).WriteK8sServiceInventory(ctx, agent, report, now.Add(time.Second))
	if err != nil || !duplicate.Duplicate || duplicate.ReportID != first.ReportID {
		t.Fatalf("duplicate=%+v first=%+v err=%v", duplicate, first, err)
	}
	var generation, sequence int64
	var itemCount, portCount int
	if err := pool.QueryRow(ctx, `SELECT promotion_generation,replay_sequence,service_count FROM k8s_service_inventory_reports WHERE id=$1`, first.ReportID).Scan(&generation, &sequence, &itemCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_inventory_ports WHERE report_id=$1`, first.ReportID).Scan(&portCount); err != nil {
		t.Fatal(err)
	}
	if generation <= 0 || sequence != 2 || itemCount != 1 || portCount != 2 {
		t.Fatalf("generation=%d sequence=%d items=%d ports=%d", generation, sequence, itemCount, portCount)
	}
	standby := K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: fixture.standbyA}
	other := report
	other.Sequence = 3
	other.Digest = K8sServiceInventoryDigest(other.Sequence, other.ObservedAt, other.Services)
	if _, err := store.WriteK8sServiceInventory(ctx, standby, other, now); err == nil {
		t.Fatal("standby inventory reporter accepted")
	}
}

func TestPostgresK8sServiceInventoryStoreRetainsTwentyUnreferencedAndDurableEvidence(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run inventory retention PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	if err := db.MigrateTo(pool.Config().ConnString(), 123); err != nil {
		t.Fatalf("migrate through 0123: %v", err)
	}
	scope := K8sServiceUIDObservationScope{OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID, ClusterID: fixture.scope.ClusterID, ConnectorNodeID: fixture.active}
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states SET scope_identity=$1 WHERE org_id=$2 AND cluster_id=$3 AND connector_node_id=$4`, k8sServiceUIDObservationScopeIdentity(scope), scope.OrgID, scope.ClusterID, scope.ConnectorNodeID); err != nil {
		t.Fatal(err)
	}
	agent := K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: scope.ConnectorNodeID}
	store := NewPostgresK8sServiceInventoryStore(pool)
	baseTime := time.Now().UTC()
	makeReport := func(sequence uint64) K8sServiceInventoryReport {
		report := K8sServiceInventoryReport{Version: 1, Sequence: sequence, ObservedAt: baseTime, Services: []K8sServiceInventoryService{{Namespace: "default", Service: "api", UID: "uid-api-v2", Ports: []K8sServiceInventoryPort{{Name: "https", Protocol: "tcp", Port: 443}}}}}
		report.Digest = K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
		return report
	}
	first, err := store.WriteK8sServiceInventory(ctx, agent, makeReport(2), baseTime)
	if err != nil {
		t.Fatal(err)
	}

	actorID, ruleID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, actorID, "retention-"+actorID.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, scope.OrgID, actorID); err != nil {
		t.Fatal(err)
	}
	var childID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM k8s_services WHERE org_id=$1 AND cluster_id=$2 AND namespace='default' AND name='api' AND protocol='tcp' AND port_low=443`, scope.OrgID, scope.ClusterID).Scan(&childID); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_k8s_cluster_id) VALUES($1,$2,'cidr','10.20.0.0/24','k8s_cluster_scope',$3)`, ruleID, scope.OrgID, scope.ClusterID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_grants(rule_id,org_id,cluster_id,created_by_user_id,initial_candidate_count,active,revision) VALUES($1,$2,$3,$4,1,true,1)`, ruleID, scope.OrgID, scope.ClusterID, actorID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_initial_candidates(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,selected,inventory_report_id) VALUES($1,$2,$3,$4,'default','uid-api-v2','tcp',443,443,false,$5)`, ruleID, scope.OrgID, scope.ClusterID, childID, first.ReportID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	mismatched := makeReport(3)
	mismatched.Services[0].Ports[0].Port = 8443
	mismatched.Digest = K8sServiceInventoryDigest(mismatched.Sequence, mismatched.ObservedAt, mismatched.Services)
	mismatchedResult, err := store.WriteK8sServiceInventory(ctx, agent, mismatched, baseTime.Add(3*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	mismatchedRuleID := uuid.New()
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_k8s_cluster_id) VALUES($1,$2,'cidr','10.21.0.0/24','k8s_cluster_scope',$3)`, mismatchedRuleID, scope.OrgID, scope.ClusterID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_grants(rule_id,org_id,cluster_id,created_by_user_id,initial_candidate_count,active,revision) VALUES($1,$2,$3,$4,1,true,1)`, mismatchedRuleID, scope.OrgID, scope.ClusterID, actorID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_cluster_scope_initial_candidates(rule_id,org_id,cluster_id,service_child_id,namespace,service_uid,protocol,port_low,port_high,selected,inventory_report_id) VALUES($1,$2,$3,$4,'default','uid-api-v2','tcp',443,443,false,$5)`, mismatchedRuleID, scope.OrgID, scope.ClusterID, childID, mismatchedResult.ReportID); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("initial-candidate evidence accepted a report without the exact port")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var last K8sServiceInventoryWriteResult
	for sequence := uint64(4); sequence <= 23; sequence++ {
		last, err = store.WriteK8sServiceInventory(ctx, agent, makeReport(sequence), baseTime.Add(time.Duration(sequence)*time.Millisecond))
		if err != nil {
			t.Fatalf("sequence %d: %v", sequence, err)
		}
	}
	if last.PrunedSnapshots != 1 {
		t.Fatalf("last prune count=%d, want 1", last.PrunedSnapshots)
	}
	var total, unreferenced, evidence, currentSequence int
	var freshUntil time.Time
	if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM k8s_cluster_scope_initial_candidates candidate WHERE candidate.inventory_report_id=report.id)) FROM k8s_service_inventory_reports report WHERE org_id=$1 AND cluster_id=$2`, scope.OrgID, scope.ClusterID).Scan(&total, &unreferenced); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_inventory_reports WHERE id=$1`, first.ReportID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT replay_sequence,fresh_until FROM k8s_service_inventory_reports WHERE org_id=$1 AND cluster_id=$2 ORDER BY replay_sequence DESC LIMIT 1`, scope.OrgID, scope.ClusterID).Scan(&currentSequence, &freshUntil); err != nil {
		t.Fatal(err)
	}
	if total != 21 || unreferenced != 20 || evidence != 1 || currentSequence != 23 || !freshUntil.After(baseTime) {
		t.Fatalf("retention total=%d unreferenced=%d evidence=%d current=%d fresh_until=%v", total, unreferenced, evidence, currentSequence, freshUntil)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM k8s_service_inventory_reports WHERE id=$1`, last.ReportID); err == nil {
		t.Fatal("ordinary writer deleted an immutable current snapshot")
	}
	if _, err := pool.Exec(ctx, `TRUNCATE k8s_service_inventory_ports`); err == nil {
		t.Fatal("TRUNCATE bypassed immutable inventory history")
	}

	if _, err := pool.Exec(ctx, `CREATE FUNCTION test_refuse_inventory_retention() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced retention failure'; END; $$ LANGUAGE plpgsql; CREATE TRIGGER test_refuse_inventory_retention BEFORE INSERT ON k8s_service_inventory_retention_authorizations FOR EACH ROW EXECUTE FUNCTION test_refuse_inventory_retention()`); err != nil {
		t.Fatal(err)
	}
	_, err = store.WriteK8sServiceInventory(ctx, agent, makeReport(24), baseTime.Add(24*time.Millisecond))
	if !errors.Is(err, ErrK8sServiceInventoryRetention) {
		t.Fatalf("forced prune error=%v, want retention sentinel", err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER test_refuse_inventory_retention ON k8s_service_inventory_retention_authorizations; DROP FUNCTION test_refuse_inventory_retention()`); err != nil {
		t.Fatal(err)
	}
	var replaySequence, reportSequence int
	if err := pool.QueryRow(ctx, `SELECT sequence FROM k8s_service_uid_observation_replay_states WHERE org_id=$1 AND cluster_id=$2 AND connector_node_id=$3`, scope.OrgID, scope.ClusterID, scope.ConnectorNodeID).Scan(&replaySequence); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT max(replay_sequence) FROM k8s_service_inventory_reports WHERE org_id=$1 AND cluster_id=$2`, scope.OrgID, scope.ClusterID).Scan(&reportSequence); err != nil {
		t.Fatal(err)
	}
	if replaySequence != 23 || reportSequence != 23 {
		t.Fatalf("failed prune partially committed replay/report=%d/%d", replaySequence, reportSequence)
	}

	var oldestUnreferenced uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT report.id FROM k8s_service_inventory_reports report WHERE report.org_id=$1 AND report.cluster_id=$2 AND NOT EXISTS (SELECT 1 FROM k8s_cluster_scope_initial_candidates candidate WHERE candidate.inventory_report_id=report.id) ORDER BY report.received_at,report.id LIMIT 1`, scope.OrgID, scope.ClusterID).Scan(&oldestUnreferenced); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_connector_pools SET active_node_id=$1,generation=generation+1 WHERE id=$2`, fixture.standbyA, fixture.scope.PoolID); err != nil {
		t.Fatal(err)
	}
	standbyReport := makeReport(1)
	standbyWrite, err := store.WriteK8sServiceInventory(ctx, K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: fixture.standbyA}, standbyReport, baseTime.Add(25*time.Millisecond))
	if err != nil {
		t.Fatalf("new generation sequence reset inventory: %v", err)
	}
	if standbyWrite.PrunedSnapshots != 1 {
		t.Fatalf("new generation prune count=%d, want 1", standbyWrite.PrunedSnapshots)
	}
	var newReportCount, oldReportCount, unreferencedAfterHandoff int
	var newGeneration, newSequence int64
	if err := pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(promotion_generation),0),COALESCE(max(replay_sequence),0) FROM k8s_service_inventory_reports WHERE id=$1`, standbyWrite.ReportID).Scan(&newReportCount, &newGeneration, &newSequence); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_inventory_reports WHERE id=$1`, oldestUnreferenced).Scan(&oldReportCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_inventory_reports report WHERE report.org_id=$1 AND report.cluster_id=$2 AND NOT EXISTS (SELECT 1 FROM k8s_cluster_scope_initial_candidates candidate WHERE candidate.inventory_report_id=report.id)`, scope.OrgID, scope.ClusterID).Scan(&unreferencedAfterHandoff); err != nil {
		t.Fatal(err)
	}
	if newReportCount != 1 || newGeneration != 2 || newSequence != 1 || oldReportCount != 0 || unreferencedAfterHandoff != 20 {
		t.Fatalf("handoff retention new_count=%d generation=%d sequence=%d oldest_count=%d unreferenced=%d", newReportCount, newGeneration, newSequence, oldReportCount, unreferencedAfterHandoff)
	}

	if err := db.MigrateTo(pool.Config().ConnString(), 122); err != nil {
		t.Fatalf("retention-only 0123 down with evidence: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_cluster_scope_initial_candidates WHERE rule_id=$1 AND inventory_report_id=$2`, ruleID, first.ReportID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("0123 down lost exact evidence count=%d err=%v", evidence, err)
	}
	if err := db.MigrateTo(pool.Config().ConnString(), 123); err != nil {
		t.Fatalf("retention-only 0123 re-up with evidence: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_inventory_reports WHERE id=$1`, first.ReportID).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("0123 up/down/up lost referenced report count=%d err=%v", evidence, err)
	}
}
