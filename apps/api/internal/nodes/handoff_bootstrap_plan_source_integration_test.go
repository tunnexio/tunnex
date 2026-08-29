package nodes

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestPostgresHandoffBootstrapPlanSourceAndIssue(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run handoff bootstrap PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)

	leaderConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leaderConn.Release)
	var pid int32
	var granted bool
	if err := leaderConn.QueryRow(ctx, `SELECT pg_backend_pid(),pg_try_advisory_lock($1)`, leader.SchedulerLockKey).Scan(&pid, &granted); err != nil || !granted {
		t.Fatalf("acquire exact scheduler lock: pid=%d granted=%t err=%v", pid, granted, err)
	}
	t.Cleanup(func() {
		_, _ = leaderConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, leader.SchedulerLockKey)
	})
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: leader.SchedulerLockKey}
	now := time.Now().UTC()
	source := NewPostgresHandoffBootstrapPlanSource(pool, HandoffBootstrapPlanSourceConfig{LeaseTTL: 5 * time.Minute})

	plan, found, err := source.LoadHandoffBootstrapPlanWithLeadership(ctx, now, fixture.scope, epoch, leaderConn)
	if err != nil || !found {
		t.Fatalf("load locked bootstrap plan: found=%t err=%v", found, err)
	}
	if plan.ActiveNodeID != fixture.active || len(plan.EligibleStandbyIDs) != 2 || len(plan.StandbyEnvelopes) != 2 || len(plan.ServiceUIDs) != 1 ||
		plan.ServiceUIDs[0].UID != "uid-api-v1" || plan.CurrentOwnerEnvelope.Manifest.Services[0].DNSName != "api.default.svc.cluster.k8s.example" ||
		plan.CurrentOwnerEnvelope.Manifest.Services[0].ServiceCIDR != "10.96.0.0/12" || !reflect.DeepEqual(plan.CurrentOwnerEnvelope.Manifest.Routes, []string{"10.44.0.0/16"}) ||
		plan.CurrentOwnerEnvelope.Manifest.WGPeers[0].PublicKey != fixture.edgeKey {
		t.Fatalf("locked topology/UID plan is incomplete: %+v", plan)
	}
	wantStandbys := map[uuid.UUID]bool{fixture.standbyA: true, fixture.standbyB: true}
	for _, id := range plan.EligibleStandbyIDs {
		delete(wantStandbys, id)
	}
	if len(wantStandbys) != 0 {
		t.Fatalf("standby enumeration omitted: %v", wantStandbys)
	}

	// The exact backend PID and advisory lock belong to leaderConn. Reusing the
	// epoch with another pooled session must fail before any source authority is
	// returned.
	otherConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer otherConn.Release()
	if _, _, err := source.LoadHandoffBootstrapPlanWithLeadership(ctx, now, fixture.scope, epoch, otherConn); !errors.Is(err, ErrPoolVIPOwnershipHandoffLeaderSession) {
		t.Fatalf("mismatched leader connection err=%v", err)
	}

	// A new source instance reconstructs byte-identical issue authority in the
	// same lease window; no process-local cursor participates.
	restartedPlan, found, err := NewPostgresHandoffBootstrapPlanSource(pool, HandoffBootstrapPlanSourceConfig{LeaseTTL: 5 * time.Minute}).LoadHandoffBootstrapPlanWithLeadership(ctx, now, fixture.scope, epoch, leaderConn)
	if err != nil || !found || !reflect.DeepEqual(restartedPlan, plan) {
		t.Fatalf("restart-stable plan: found=%t err=%v\nfirst=%+v\nrestart=%+v", found, err, plan, restartedPlan)
	}

	// Change the exact Kubernetes incarnation after planning. The issuer must
	// rebuild under the same transaction that writes and refuse the stale V3
	// envelope; UID evidence is bound into its deterministic owner/delivery IDs.
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_replay_states SET sequence=2,digest=$2 WHERE org_id=$1 AND cluster_id=$3 AND connector_node_id=$4`, fixture.scope.OrgID, strings.Repeat("b", 64), fixture.scope.ClusterID, fixture.active); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_service_uid_observation_current SET uid='uid-api-v2',replay_sequence=2 WHERE org_id=$1 AND namespace='default' AND service='api'`, fixture.scope.OrgID); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	if err := store.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, epoch, leaderConn, plan.CurrentOwnerEnvelope); !errors.Is(err, ErrHandoffBootstrapPlanRefused) {
		t.Fatalf("TOCTOU stale UID issue err=%v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1`, fixture.scope.OrgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale issue wrote rows=%d err=%v", count, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO k8s_service_uid_observation_current_attributions
		(ledger_id,org_id,namespace,service,replay_state_id,replay_sequence)
		SELECT c.ledger_id,c.org_id,c.namespace,c.service,r.id,c.replay_sequence
		FROM k8s_service_uid_observation_current c
		JOIN k8s_service_uid_observation_ledgers l ON l.id=c.ledger_id AND l.org_id=c.org_id
		JOIN k8s_service_uid_observation_replay_states r ON r.org_id=l.org_id AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id
		WHERE c.org_id=$1 AND c.namespace='default' AND c.service='api' AND r.connector_node_id=$2`, fixture.scope.OrgID, fixture.active); err != nil {
		t.Fatalf("reattribute refreshed selected-connector observation: %v", err)
	}

	current, found, err := source.LoadHandoffBootstrapPlanWithLeadership(ctx, now, fixture.scope, epoch, leaderConn)
	if err != nil || !found || current.ServiceUIDs[0].UID != "uid-api-v2" || current.CurrentOwnerEnvelope.DeliveryID == plan.CurrentOwnerEnvelope.DeliveryID {
		t.Fatalf("refreshed UID plan: found=%t err=%v plan=%+v", found, err, current)
	}
	envelopes := append([]PoolVIPOwnershipDeliveryEnvelopeV3{current.CurrentOwnerEnvelope}, current.StandbyEnvelopes...)
	for _, envelope := range envelopes {
		if err := store.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, epoch, leaderConn, envelope); err != nil {
			t.Fatalf("issue current %s: %v", envelope.TargetNodeID, err)
		}
	}
	// A restarted writer repeats the same durable artifacts without duplicating
	// rows or allocating new revisions.
	restartedStore := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	for _, envelope := range envelopes {
		if err := restartedStore.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, epoch, leaderConn, envelope); err != nil {
			t.Fatalf("restart issue %s: %v", envelope.TargetNodeID, err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pool_vip_ownership_deliveries WHERE org_id=$1`, fixture.scope.OrgID).Scan(&count); err != nil || count != 3 {
		t.Fatalf("restart-stable issue rows=%d err=%v", count, err)
	}
}

type handoffBootstrapIntegrationFixture struct {
	scope            k8s.HandoffPoolScope
	active, standbyA uuid.UUID
	standbyB         uuid.UUID
	edgeKey          string
}

func seedHandoffBootstrapIntegration(t *testing.T, ctx context.Context, pool *pgxpool.Pool) handoffBootstrapIntegrationFixture {
	t.Helper()
	if err := db.MigrateTo(pool.Config().ConnString(), 121); err != nil {
		t.Fatalf("migrate bootstrap fixture through 0119: %v", err)
	}
	fixture := handoffBootstrapIntegrationFixture{scope: k8s.HandoffPoolScope{OrgID: uuid.New(), SiteID: uuid.New(), ClusterID: uuid.New(), PoolID: uuid.New()},
		active: uuid.New(), standbyA: uuid.New(), standbyB: uuid.New(), edgeKey: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}
	edge := uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed bootstrap: %v\n%s", err, query)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'bootstrap',$2,'10.44.0.0/16')`, fixture.scope.OrgID, "bootstrap-"+fixture.scope.OrgID.String()[:8])
	exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'bootstrap-site')`, fixture.scope.SiteID, fixture.scope.OrgID)
	nodes := []struct {
		id            uuid.UUID
		key, endpoint string
	}{
		{fixture.active, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "10.0.0.1:51820"},
		{fixture.standbyA, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "10.0.0.2:51820"},
		{fixture.standbyB, "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "10.0.0.3:51820"},
		{edge, fixture.edgeKey, "10.0.0.4:51820"},
	}
	for _, node := range nodes {
		exec(`INSERT INTO nodes (id,org_id,site_id,name,cert_serial,agent_version,wg_public_key,endpoint) VALUES ($1,$2,$3,$4,$5,'test',$6,$7)`,
			node.id, fixture.scope.OrgID, fixture.scope.SiteID, "node-"+node.id.String()[:8], "serial-"+node.id.String(), node.key, node.endpoint)
	}
	exec(`INSERT INTO org_hub_set (org_id,configured,demoted,generation) VALUES ($1,$2,'{}',1)`, fixture.scope.OrgID, []uuid.UUID{edge})
	exec(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,service_cidr,dns_zone,dns_vip) VALUES ($1,$2,$3,'cluster','100.64.0.0/24','10.96.0.0/12','k8s.example','100.64.0.2')`,
		fixture.scope.ClusterID, fixture.scope.OrgID, fixture.scope.SiteID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pools (id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation) VALUES ($1,$2,$3,$4,$5,$5,1)`,
		fixture.scope.PoolID, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.active); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{fixture.active, fixture.standbyA, fixture.standbyB} {
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members (pool_id,org_id,site_id,node_id) VALUES ($1,$2,$3,$4)`, fixture.scope.PoolID, fixture.scope.OrgID, fixture.scope.SiteID, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2 AND org_id=$3`, fixture.scope.PoolID, fixture.scope.ClusterID, fixture.scope.OrgID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	serviceID, replayID, ledgerID := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES ($1,$2,$3,'api','default','tcp',443,443,'100.64.0.10')`, serviceID, fixture.scope.OrgID, fixture.scope.ClusterID)
	observationScope := K8sServiceUIDObservationScope{OrgID: fixture.scope.OrgID, SiteID: fixture.scope.SiteID, ClusterID: fixture.scope.ClusterID, ConnectorNodeID: fixture.active}
	exec(`INSERT INTO k8s_service_uid_observation_replay_states (id,org_id,site_id,cluster_id,connector_node_id,scope_identity,sequence,digest) VALUES ($1,$2,$3,$4,$5,$6,1,$7)`,
		replayID, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.active, k8sServiceUIDObservationScopeIdentity(observationScope), strings.Repeat("a", 64))
	exec(`INSERT INTO k8s_service_uid_observation_ledgers (id,org_id,site_id,cluster_id,scope_identity) VALUES ($1,$2,$3,$4,$5)`, ledgerID, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, k8sServiceUIDObservationClusterIdentity(observationScope))
	exec(`INSERT INTO k8s_service_uid_observation_current (ledger_id,org_id,namespace,service,uid,state,replay_sequence) VALUES ($1,$2,'default','api','uid-api-v1','live',1)`, ledgerID, fixture.scope.OrgID)
	exec(`INSERT INTO k8s_service_uid_observation_current_attributions (ledger_id,org_id,namespace,service,replay_state_id,replay_sequence) VALUES ($1,$2,'default','api',$3,1)`, ledgerID, fixture.scope.OrgID, replayID)
	return fixture
}
