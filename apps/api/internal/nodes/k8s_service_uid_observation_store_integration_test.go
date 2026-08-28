package nodes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresK8sServiceUIDObservationStoreAuthorityAndRestart(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run UID observation store PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	scope := K8sServiceUIDObservationScope{OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID, ClusterID: fixture.scope.ClusterID, ConnectorNodeID: fixture.active}
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states SET scope_identity=$1 WHERE org_id=$2 AND cluster_id=$3 AND connector_node_id=$4`, k8sServiceUIDObservationScopeIdentity(scope), scope.OrgID, scope.ClusterID, scope.ConnectorNodeID); err != nil {
		t.Fatal(err)
	}
	agent := K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: scope.ConnectorNodeID}
	report := testK8sServiceUIDObservationReport(2, K8sServiceUIDObservation{Namespace: "default", Service: "api", UID: "uid-api-v2", State: "live"})
	// 789ns is intentionally below PostgreSQL's microsecond precision. The
	// store must bind the validator to its durable canonical receipt, not let a
	// closure retain caller nanoseconds that disappear on restart.
	now := time.Date(2026, time.August, 28, 12, 0, 0, 789, time.UTC)
	update := func(store *PostgresK8sServiceUIDObservationStore, principal K8sServiceUIDObservationAgent, value K8sServiceUIDObservationReport) (K8sServiceUIDObservationValidation, error) {
		return store.UpdateK8sServiceUIDObservations(ctx, principal, value, now, func(resolved K8sServiceUIDObservationScope, state K8sServiceUIDObservationState, durableReceiptTime time.Time) (K8sServiceUIDObservationValidation, error) {
			if !durableReceiptTime.Equal(now.Truncate(time.Microsecond)) {
				t.Fatalf("validator receipt=%s want durable %s", durableReceiptTime, now.Truncate(time.Microsecond))
			}
			return ValidateK8sServiceUIDObservations(durableReceiptTime, principal, resolved, value, state)
		})
	}
	result, err := update(NewPostgresK8sServiceUIDObservationStore(pool), agent, report)
	if err != nil || result.Duplicate {
		t.Fatalf("selected active report: duplicate=%t err=%v", result.Duplicate, err)
	}
	if !result.ReceiptTime.Equal(now.Truncate(time.Microsecond)) {
		t.Fatalf("first durable receipt=%s want=%s", result.ReceiptTime, now.Truncate(time.Microsecond))
	}
	var reporter uuid.UUID
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT r.connector_node_id,a.replay_sequence FROM k8s_service_uid_observation_current_attributions a JOIN k8s_service_uid_observation_replay_states r ON r.id=a.replay_state_id AND r.org_id=a.org_id WHERE a.org_id=$1 AND a.namespace='default' AND a.service='api'`, scope.OrgID).Scan(&reporter, &revision); err != nil || reporter != fixture.active || revision != 2 {
		t.Fatalf("exact active attribution reporter=%s revision=%d err=%v", reporter, revision, err)
	}
	duplicate, err := update(NewPostgresK8sServiceUIDObservationStore(pool), agent, report)
	if err != nil || !duplicate.Duplicate || !duplicate.ReceiptTime.Equal(result.ReceiptTime) {
		t.Fatalf("restart exact retry: duplicate=%t receipt=%v want=%v err=%v", duplicate.Duplicate, duplicate.ReceiptTime, result.ReceiptTime, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_current SET uid=uid WHERE org_id=$1 AND namespace='default' AND service='api'`, scope.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := update(NewPostgresK8sServiceUIDObservationStore(pool), agent, report); err != nil {
		t.Fatalf("duplicate remains replay-safe after legacy invalidation: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_service_uid_observation_current_attributions WHERE org_id=$1`, scope.OrgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("old duplicate must not invent fresh attribution: count=%d err=%v", count, err)
	}
	standby := K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: fixture.standbyA}
	if _, err := update(NewPostgresK8sServiceUIDObservationStore(pool), standby, testK8sServiceUIDObservationReport(1, K8sServiceUIDObservation{Namespace: "default", Service: "api", UID: "standby", State: "live"})); err == nil {
		t.Fatal("standby reporter must be refused")
	}
}

func TestPostgresK8sServiceUIDObservationStoreSerializesAuthorityLoss(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run UID authority serialization proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	scope := K8sServiceUIDObservationScope{OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID, ClusterID: fixture.scope.ClusterID, ConnectorNodeID: fixture.active}
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states SET scope_identity=$1 WHERE org_id=$2 AND cluster_id=$3 AND connector_node_id=$4`, k8sServiceUIDObservationScopeIdentity(scope), scope.OrgID, scope.ClusterID, scope.ConnectorNodeID); err != nil {
		t.Fatal(err)
	}
	agent := K8sServiceUIDObservationAgent{OrgID: scope.OrgID, NodeID: scope.ConnectorNodeID}
	store := NewPostgresK8sServiceUIDObservationStore(pool)
	run := func(report K8sServiceUIDObservationReport) <-chan error {
		result := make(chan error, 1)
		go func() {
			receiptTime := time.Now().UTC()
			_, err := store.UpdateK8sServiceUIDObservations(ctx, agent, report, receiptTime, func(resolved K8sServiceUIDObservationScope, state K8sServiceUIDObservationState, durableReceiptTime time.Time) (K8sServiceUIDObservationValidation, error) {
				return ValidateK8sServiceUIDObservations(durableReceiptTime, agent, resolved, report, state)
			})
			result <- err
		}()
		return result
	}
	assertBlockedThenRefused := func(name string, mutate string, args ...any) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, mutate, args...); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		done := run(testK8sServiceUIDObservationReport(2, K8sServiceUIDObservation{Namespace: "default", Service: "api", UID: "uid-race", State: "live"}))
		select {
		case err := <-done:
			_ = tx.Rollback(ctx)
			t.Fatalf("%s report escaped uncommitted authority mutation: %v", name, err)
		case <-time.After(150 * time.Millisecond):
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s report must fail closed after authority loss: %v", name, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s report remained blocked after commit", name)
		}
	}
	assertBlockedThenRefused("demotion", `UPDATE k8s_connector_pools SET active_node_id=$1,generation=generation+1 WHERE id=$2`, fixture.standbyA, fixture.scope.PoolID)
	if _, err := pool.Exec(ctx, `UPDATE k8s_connector_pools SET active_node_id=$1,generation=generation+1 WHERE id=$2`, fixture.active, fixture.scope.PoolID); err != nil {
		t.Fatal(err)
	}
	assertBlockedThenRefused("revocation", `UPDATE nodes SET revoked_at=now() WHERE id=$1`, fixture.active)
}
