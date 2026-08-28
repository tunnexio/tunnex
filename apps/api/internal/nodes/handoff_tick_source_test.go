package nodes

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestPostgresHandoffTickSource(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run PostgreSQL handoff tick-source tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := newHandoffTickTestDB(t, ctx, admin)
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)

	t.Run("scope isolation, multiple pools, deterministic new selection, and stale evidence", func(t *testing.T) {
		first := newProductionHandoffTickPool(t, ctx, p, now, "first", false)
		second := newProductionHandoffTickPool(t, ctx, p, now, "second", false)
		unbound := newProductionHandoffTickPool(t, ctx, p, now, "unbound", false)
		if _, err := p.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id = NULL WHERE id = $1`, unbound.cluster); err != nil {
			t.Fatal(err)
		}
		stale := newProductionHandoffTickPool(t, ctx, p, now, "stale", true)
		staleHeartbeat := newProductionHandoffTickPool(t, ctx, p, now, "stale-heartbeat", false)
		if _, err := p.Exec(ctx, `UPDATE nodes SET last_seen_at = $1 WHERE id = $2`, now.Add(-2*time.Minute), staleHeartbeat.candidate); err != nil {
			t.Fatal(err)
		}
		disabled := newProductionHandoffTickPool(t, ctx, p, now, "ha-disabled", false)
		if _, err := p.Exec(ctx, `UPDATE k8s_ha_settings SET enabled=false WHERE org_id=$1`, disabled.org); err != nil {
			t.Fatal(err)
		}
		pendingActivation := newProductionHandoffTickPool(t, ctx, p, now, "ha-pending", false)
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET actual_mode='bootstrap_pending',achieved_at=NULL,achieved_authority_revision=NULL WHERE pool_id=$1`, pendingActivation.pool); err != nil {
			t.Fatal(err)
		}
		epochMismatch := newProductionHandoffTickPool(t, ctx, p, now, "ha-epoch-mismatch", false)
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET membership_epoch=membership_epoch+1 WHERE pool_id=$1`, epochMismatch.pool); err != nil {
			t.Fatal(err)
		}
		noHealth := newHandoffTickPool(t, ctx, p, now, "ha-no-health", false)
		if _, err := p.Exec(ctx, `INSERT INTO k8s_ha_settings (org_id,enabled,actor_system,cause) VALUES ($1,true,'test','malformed no-health fixture')`, noHealth.org); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions
			(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,transition_revision,achieved_authority_revision,reason_code,actor_system,cause,achieved_at)
			VALUES ($1,$2,$3,$4,'fenced_ha','fenced_ha',$5,1,0,1,1,'fenced_ha_active','test','malformed no-health fixture',$6)`, noHealth.pool, noHealth.org, noHealth.site, noHealth.cluster, noHealth.active, now); err != nil {
			t.Fatal(err)
		}

		history := &handoffTickHistory{states: map[uuid.UUID]k8s.HandoffHealthState{
			first.pool:             readyForHandoff(first.candidate),
			second.pool:            readyForHandoff(second.candidate),
			stale.pool:             readyForHandoff(stale.candidate),
			staleHeartbeat.pool:    readyForHandoff(staleHeartbeat.candidate),
			disabled.pool:          readyForHandoff(disabled.candidate),
			pendingActivation.pool: readyForHandoff(pendingActivation.candidate),
			epochMismatch.pool:     readyForHandoff(epochMismatch.candidate),
			noHealth.pool:          readyForHandoff(noHealth.candidate),
		}}
		resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}
		source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, history, resolver, tickSourceConfig())

		requests, err := source.HandoffRequests(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(requests) != 2 {
			t.Fatalf("requests=%d, want two bound, healthy-evidence pools", len(requests))
		}
		got := map[uuid.UUID]k8s.HandoffCoordinatorRequest{}
		for _, request := range requests {
			got[request.Plan.Plan.Scope.PoolID] = request
			for nodeID, evidence := range request.Evidence {
				if evidence.OrgID != request.Plan.Plan.Scope.OrgID.String() || evidence.SiteID != request.Plan.Plan.Scope.SiteID.String() {
					t.Fatalf("cross-scope evidence for pool=%s node=%s: %+v", request.Plan.Plan.Scope.PoolID, nodeID, evidence)
				}
			}
		}
		for _, fixture := range []handoffTickPoolFixture{first, second} {
			request, ok := got[fixture.pool]
			if !ok {
				t.Fatalf("missing bound pool %s", fixture.pool)
			}
			if request.Plan.Plan.CandidateID != fixture.candidate {
				t.Fatalf("pool %s selected %s, want highest-priority healthy member %s", fixture.pool, request.Plan.Plan.CandidateID, fixture.candidate)
			}
			wantID := StableHandoffOperationID(request.Plan.Plan.Scope, fixture.active, fixture.candidate, 1, nil)
			if request.Plan.Plan.OperationID != wantID {
				t.Fatalf("pool %s operation ID=%s, want stable %s", fixture.pool, request.Plan.Plan.OperationID, wantID)
			}
		}
		if _, ok := got[unbound.pool]; ok {
			t.Fatal("legacy/unbound cluster must not enter handoff source")
		}
		if _, ok := got[stale.pool]; ok {
			t.Fatal("missing endpoint-view evidence must fail closed")
		}
		if _, ok := got[staleHeartbeat.pool]; ok {
			t.Fatal("stale candidate heartbeat must fail closed")
		}

		again, err := source.HandoffRequests(ctx, now)
		if err != nil || len(again) != len(requests) {
			t.Fatalf("second read err=%v requests=%d", err, len(again))
		}
		for i := range requests {
			if requests[i].Plan.Plan.OperationID != again[i].Plan.Plan.OperationID {
				t.Fatalf("operation order/identity changed: %s then %s", requests[i].Plan.Plan.OperationID, again[i].Plan.Plan.OperationID)
			}
		}
	})

	t.Run("max durable bigint generation refuses a fresh intent", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "max-generation", false)
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pools SET generation=$1 WHERE id=$2`, int64(math.MaxInt64), fixture.pool); err != nil {
			t.Fatal(err)
		}
		history := &handoffTickHistory{states: map[uuid.UUID]k8s.HandoffHealthState{fixture.pool: readyForHandoff(fixture.candidate)}}
		resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}
		requests, err := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, history, resolver, tickSourceConfig()).HandoffRequests(ctx, now)
		if err != nil || len(requests) != 0 || resolver.newCalls() != 0 {
			t.Fatalf("max durable generation created a fresh intent: requests=%+v err=%v new=%d", requests, err, resolver.newCalls())
		}
	})

	t.Run("restart resumes persisted operation despite membership change", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "resume", false)
		intent := HandoffTickIntent{OperationID: uuid.New(), Scope: k8s.HandoffPoolScope{OrgID: fixture.org, SiteID: fixture.site, PoolID: fixture.pool, ClusterID: fixture.cluster}, Existing: true,
			ExpectedActiveID: fixture.active, CandidateID: fixture.candidate, ExpectedGeneration: 1, TargetGeneration: 2}
		plan := testHandoffPlan(intent, now)
		insertTickOperation(t, ctx, p, plan)
		added := addHandoffTickMember(t, ctx, p, fixture, now, 99, false)
		if added == fixture.candidate {
			t.Fatal("fixture must add a distinct member")
		}
		resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{plan.Plan.OperationID: plan}}
		first := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, nil, resolver, tickSourceConfig())
		requests, err := first.HandoffRequests(ctx, now)
		if err != nil || len(requests) != 1 {
			t.Fatalf("first resume err=%v requests=%d", err, len(requests))
		}
		if request := requests[0]; request.Plan.Plan.OperationID != plan.Plan.OperationID || request.Plan.Plan.CandidateID != fixture.candidate || request.CurrentPhase != k8s.HandoffPrepareCandidate {
			t.Fatalf("resume changed durable intent: %+v", request.Plan.Plan)
		}
		second := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, nil, resolver, tickSourceConfig())
		again, err := second.HandoffRequests(ctx, now)
		if err != nil || len(again) != 1 || again[0].Plan.Plan.OperationID != plan.Plan.OperationID || again[0].CurrentPhase != k8s.HandoffPrepareCandidate {
			t.Fatalf("restart did not resume exact operation: err=%v requests=%+v", err, again)
		}
		if resolver.newCalls() != 0 || resolver.resumeCalls() != 2 {
			t.Fatalf("resume must not create replacement intent: new=%d resume=%d", resolver.newCalls(), resolver.resumeCalls())
		}
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_handoff_operations SET phase = 'failed', failure_reason = 'test complete' WHERE id = $1`, plan.Plan.OperationID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ownership drift refuses pre- and post-CAS resume before plan resolution", func(t *testing.T) {
		t.Run("before CAS", func(t *testing.T) {
			fixture := newProductionHandoffTickPool(t, ctx, p, now, "pre-cas-drift", false)
			plan := testHandoffPlan(newTickIntent(fixture), now)
			insertTickOperation(t, ctx, p, plan)
			if _, err := p.Exec(ctx, `UPDATE k8s_connector_pools SET active_node_id = $1, generation = 2 WHERE id = $2`, fixture.candidate, fixture.pool); err != nil {
				t.Fatal(err)
			}
			assertDriftRefused(t, ctx, p, now, plan, fixture)
		})

		t.Run("after CAS", func(t *testing.T) {
			fixture := newProductionHandoffTickPool(t, ctx, p, now, "post-cas-drift", false)
			plan := testHandoffPlan(newTickIntent(fixture), now)
			insertTickOperation(t, ctx, p, plan)
			advanceTickOperationPastCAS(t, ctx, p, plan)
			resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{plan.Plan.OperationID: plan}}
			requests, err := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, nil, resolver, tickSourceConfig()).HandoffRequests(ctx, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(requests) != 1 || requests[0].Plan.Plan.OperationID != plan.Plan.OperationID || resolver.resumeCalls() != 1 {
				t.Fatalf("matching post-CAS restart did not resume exactly once: requests=%+v resolver=%d", requests, resolver.resumeCalls())
			}
			if _, err := p.Exec(ctx, `UPDATE k8s_connector_pools SET active_node_id = $1, generation = 3 WHERE id = $2`, fixture.active, fixture.pool); err != nil {
				t.Fatal(err)
			}
			assertDriftRefused(t, ctx, p, now, plan, fixture)
		})
	})

	t.Run("concurrent readers are read-only and deterministic", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "concurrent", false)
		history := &handoffTickHistory{states: map[uuid.UUID]k8s.HandoffHealthState{fixture.pool: readyForHandoff(fixture.candidate)}}
		resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}
		source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, history, resolver, tickSourceConfig())
		start := make(chan struct{})
		errs := make(chan error, 8)
		ids := make(chan uuid.UUID, 8)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				requests, err := source.HandoffRequests(ctx, now)
				if err != nil || len(requests) != 1 {
					errs <- fmt.Errorf("err=%v requests=%d", err, len(requests))
					return
				}
				ids <- requests[0].Plan.Plan.OperationID
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		close(ids)
		for err := range errs {
			t.Fatal(err)
		}
		want := StableHandoffOperationID(k8s.HandoffPoolScope{OrgID: fixture.org, SiteID: fixture.site, PoolID: fixture.pool, ClusterID: fixture.cluster}, fixture.active, fixture.candidate, 1, nil)
		for id := range ids {
			if id != want {
				t.Fatalf("concurrent reader operation=%s, want %s", id, want)
			}
		}
	})
}

func tickSourceConfig() HandoffTickSourceConfig {
	return HandoffTickSourceConfig{ReportFreshness: time.Minute, MaxAckAge: time.Minute, ClockSkewMargin: time.Second}
}

func leaderBoundHandoffRequests(t *testing.T, ctx context.Context, p *pgxpool.Pool, source *PostgresHandoffTickSource, now time.Time) ([]k8s.HandoffCoordinatorRequest, error) {
	t.Helper()
	conn, err := p.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	const key int64 = 840000001
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("acquire test handoff leadership")
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key) }()
	var pid int32
	if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		return nil, err
	}
	return source.HandoffRequestsWithLeadership(ctx, now, k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: key}, conn)
}

type handoffTickPoolFixture struct {
	org, site, cluster, pool, active, candidate uuid.UUID
}

func newHandoffTickPool(t *testing.T, ctx context.Context, p *pgxpool.Pool, now time.Time, name string, endpointUnknown bool) handoffTickPoolFixture {
	t.Helper()
	org, site, cluster, active, candidate := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1, $2, $3, '10.110.0.0/24')`, org, name+" org", name+"-"+org.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO sites (id, org_id, name) VALUES ($1, $2, $3)`, site, org, name+" site"); err != nil {
		t.Fatal(err)
	}
	for i, node := range []uuid.UUID{active, candidate} {
		caps := []byte(`{"policy_hash":"policy","k8s_endpoints_unavailable":false}`)
		if endpointUnknown && node == candidate {
			caps = []byte(`{"policy_hash":"policy"}`)
		}
		seen := now.Add(-time.Second)
		if node == active {
			seen = now.Add(-2 * time.Minute)
		}
		if _, err := p.Exec(ctx, `INSERT INTO nodes (id, org_id, site_id, name, cert_serial, status, wg_public_key, endpoint, last_seen_at, policy_reported_at, capabilities) VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$8,$9,$10)`, node, org, site, fmt.Sprintf("%s-node-%d", name, i), fmt.Sprintf("%s-serial-%d", name, i), tickWGKey(i), fmt.Sprintf("198.51.100.%d:51820", i+10), seen, now.Add(-time.Second), caps); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(ctx, `INSERT INTO k8s_clusters (id, org_id, site_id, name, vip_range) VALUES ($1,$2,$3,$4,'100.80.0.0/16')`, cluster, org, site, name+" cluster"); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(p)
	created, err := q.CreateK8sConnectorPool(ctx, sqlc.CreateK8sConnectorPoolParams{ClusterID: cluster, OrgID: org, PreferredNodeID: active, ActiveNodeID: active})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: created.ID, OrgID: org, NodeID: candidate, AdminPriority: 10}); err != nil {
		t.Fatal(err)
	}
	if bound, err := q.BindK8sClusterConnectorPool(ctx, sqlc.BindK8sClusterConnectorPoolParams{OrgID: org, ClusterID: cluster, ConnectorPoolID: uuidParam(created.ID)}); err != nil || bound != 1 {
		t.Fatalf("bind pool=%d err=%v", bound, err)
	}
	return handoffTickPoolFixture{org: org, site: site, cluster: cluster, pool: created.ID, active: active, candidate: candidate}
}

// newProductionHandoffTickPool adds the explicit 0120 opt-in/activation rows
// required by the current scheduler source. The underlying helper remains
// usable by the historical 0083 health-history proof, where these tables do
// not exist yet.
func newProductionHandoffTickPool(t *testing.T, ctx context.Context, p *pgxpool.Pool, now time.Time, name string, endpointUnknown bool) handoffTickPoolFixture {
	t.Helper()
	fixture := newHandoffTickPool(t, ctx, p, now, name, endpointUnknown)
	if _, err := sqlc.New(p).CreateK8sConnectorPoolHealthState(ctx, sqlc.CreateK8sConnectorPoolHealthStateParams{
		OrgID: fixture.org, SiteID: fixture.site, ClusterID: fixture.cluster, PoolID: fixture.pool,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO k8s_ha_settings (org_id,enabled,actor_system,cause)
		VALUES ($1,true,'test','production scheduler fixture')`, fixture.org); err != nil {
		t.Fatal(err)
	}
	result, err := p.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions
		(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,transition_revision,achieved_authority_revision,reason_code,actor_system,cause,achieved_at)
		SELECT p.id,p.org_id,p.site_id,p.cluster_id,'fenced_ha','fenced_ha',p.active_node_id,p.generation,h.membership_epoch,1,1,'fenced_ha_active','test','production scheduler fixture',$2
		FROM k8s_connector_pools p
		JOIN k8s_connector_pool_health_states h ON h.pool_id=p.id AND h.org_id=p.org_id
		WHERE p.id=$1`, fixture.pool, now)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("activate production HA fixture rows=%d err=%v", result.RowsAffected(), err)
	}
	var enabled bool
	var requestedMode, actualMode string
	var poolGeneration, transitionGeneration, healthEpoch, transitionEpoch int64
	if err := p.QueryRow(ctx, `SELECT settings.enabled,transition.requested_mode,transition.actual_mode,pool.generation,transition.promotion_generation,health.membership_epoch,transition.membership_epoch
		FROM k8s_ha_settings settings
		JOIN k8s_connector_pool_ha_transitions transition ON transition.org_id=settings.org_id
		JOIN k8s_connector_pools pool ON pool.id=transition.pool_id AND pool.org_id=transition.org_id
		JOIN k8s_connector_pool_health_states health ON health.pool_id=pool.id AND health.org_id=pool.org_id
		WHERE transition.pool_id=$1`, fixture.pool).Scan(&enabled, &requestedMode, &actualMode, &poolGeneration, &transitionGeneration, &healthEpoch, &transitionEpoch); err != nil {
		t.Fatal(err)
	}
	if !enabled || requestedMode != "fenced_ha" || actualMode != "fenced_ha" || poolGeneration != transitionGeneration || healthEpoch != transitionEpoch {
		t.Fatalf("invalid production HA fixture enabled=%t requested=%s actual=%s generation=%d/%d epoch=%d/%d", enabled, requestedMode, actualMode, poolGeneration, transitionGeneration, healthEpoch, transitionEpoch)
	}
	return fixture
}

func syncProductionHandoffTickPoolEpoch(t *testing.T, ctx context.Context, p *pgxpool.Pool, fixture handoffTickPoolFixture) {
	t.Helper()
	result, err := p.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions transition
		SET active_node_id=pool.active_node_id,promotion_generation=pool.generation,membership_epoch=health.membership_epoch
		FROM k8s_connector_pools pool
		JOIN k8s_connector_pool_health_states health ON health.pool_id=pool.id AND health.org_id=pool.org_id
		WHERE transition.pool_id=pool.id AND transition.org_id=pool.org_id AND transition.pool_id=$1`, fixture.pool)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("sync production HA epoch rows=%d err=%v", result.RowsAffected(), err)
	}
}

func addHandoffTickMember(t *testing.T, ctx context.Context, p *pgxpool.Pool, fixture handoffTickPoolFixture, now time.Time, priority int32, endpointUnknown bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	caps := []byte(`{"policy_hash":"policy","k8s_endpoints_unavailable":false}`)
	if endpointUnknown {
		caps = []byte(`{"policy_hash":"policy"}`)
	}
	if _, err := p.Exec(ctx, `INSERT INTO nodes (id, org_id, site_id, name, cert_serial, status, wg_public_key, endpoint, last_seen_at, policy_reported_at, capabilities) VALUES ($1,$2,$3,$4,$5,'active',$6,'198.51.100.99:51820',$7,$7,$8)`, id, fixture.org, fixture.site, "extra-"+id.String()[:8], "extra-serial-"+id.String()[:8], tickWGKey(3), now.Add(-time.Second), caps); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlc.New(p).AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: fixture.pool, OrgID: fixture.org, NodeID: id, AdminPriority: priority}); err != nil {
		t.Fatal(err)
	}
	return id
}

func uuidParam(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func tickWGKey(i int) string {
	keys := []string{"/RLJQov+0n5q0hNM2/ZkqzUO/GFUcoziClpzUvI+5j4=", "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=", "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM=", "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo="}
	return keys[i%len(keys)]
}

func readyForHandoff(candidate uuid.UUID) k8s.HandoffHealthState {
	return k8s.HandoffHealthState{StaleTicks: 2, CandidateHealthyTicks: map[uuid.UUID]int{candidate: 2}}
}

func newTickIntent(fixture handoffTickPoolFixture) HandoffTickIntent {
	return HandoffTickIntent{OperationID: uuid.New(), Scope: k8s.HandoffPoolScope{OrgID: fixture.org, SiteID: fixture.site, PoolID: fixture.pool, ClusterID: fixture.cluster}, Existing: true,
		ExpectedActiveID: fixture.active, CandidateID: fixture.candidate, ExpectedGeneration: 1, TargetGeneration: 2}
}

func assertDriftRefused(t *testing.T, ctx context.Context, p *pgxpool.Pool, now time.Time, plan k8s.DurableHandoffPlan, fixture handoffTickPoolFixture) {
	t.Helper()
	resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{plan.Plan.OperationID: plan}}
	requests, err := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, nil, resolver, tickSourceConfig()).HandoffRequests(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		if request.Plan.Plan.Scope.PoolID == fixture.pool {
			t.Fatalf("ownership-drifted pool emitted coordinator request: %+v", request.Plan.Plan)
		}
	}
	if resolver.resumeCalls() != 0 {
		t.Fatalf("ownership drift reached plan resolver %d times", resolver.resumeCalls())
	}
}

type handoffTickPolicy struct{}

func (handoffTickPolicy) HandoffPolicyAcknowledgements(_ context.Context, _ uuid.UUID, _ uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]k8s.PolicyAcknowledgement, error) {
	out := make(map[uuid.UUID]k8s.PolicyAcknowledgement, len(ids))
	for _, id := range ids {
		out[id] = k8s.PolicyAcknowledgement{ExpectedKnown: true, ExpectedHash: "policy", HealthKnown: true}
	}
	return out, nil
}

type handoffTickHistory struct {
	states map[uuid.UUID]k8s.HandoffHealthState
}

func (h *handoffTickHistory) HandoffHealthState(_ context.Context, scope k8s.HandoffPoolScope) (k8s.HandoffHealthState, bool, error) {
	state, ok := h.states[scope.PoolID]
	return state, ok, nil
}

type handoffTickPlans struct {
	mu     sync.Mutex
	now    time.Time
	plans  map[uuid.UUID]k8s.DurableHandoffPlan
	new    int
	resume int
}

func (r *handoffTickPlans) ResolveHandoffPlan(_ context.Context, intent HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if intent.Existing {
		r.resume++
		plan, ok := r.plans[intent.OperationID]
		return plan, ok, nil
	}
	r.new++
	return testHandoffPlan(intent, r.now), true, nil
}

func (r *handoffTickPlans) ResolveHandoffPlanWithLeadership(ctx context.Context, intent HandoffTickIntent, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	if conn == nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return k8s.DurableHandoffPlan{}, false, fmt.Errorf("leader-bound test resolver received no exact session")
	}
	return r.ResolveHandoffPlan(ctx, intent)
}

func (r *handoffTickPlans) newCalls() int    { r.mu.Lock(); defer r.mu.Unlock(); return r.new }
func (r *handoffTickPlans) resumeCalls() int { r.mu.Lock(); defer r.mu.Unlock(); return r.resume }

func testHandoffPlan(intent HandoffTickIntent, now time.Time) k8s.DurableHandoffPlan {
	decision := intent.Decision
	if decision.Transition == "" {
		decision = k8s.Decision{Transition: k8s.Promoted, FromID: intent.ExpectedActiveID.String(), ToID: intent.CandidateID.String(), Pool: k8s.ConnectorPool{ActiveID: intent.CandidateID.String(), Generation: intent.TargetGeneration}}
	}
	old := tickArtifact(intent.Scope, intent.ExpectedActiveID, intent.ExpectedGeneration, 10, 1, k8s.Serving, "old-serving-"+intent.OperationID.String(), now.Add(time.Minute))
	prepared := tickArtifact(intent.Scope, intent.CandidateID, intent.TargetGeneration, 11, 2, k8s.PreparedNonServing, "candidate-prepared-"+intent.OperationID.String(), now.Add(5*time.Minute))
	withdrawal := tickArtifact(intent.Scope, intent.ExpectedActiveID, intent.TargetGeneration, 11, 2, k8s.PreparedNonServing, "old-withdrawal-"+intent.OperationID.String(), now.Add(5*time.Minute))
	serving := tickArtifact(intent.Scope, intent.CandidateID, intent.TargetGeneration, 12, 2, k8s.Serving, "new-serving-"+intent.OperationID.String(), now.Add(5*time.Minute))
	// Both serving artifacts prove the same P2 route/VIP snapshot. Revisions
	// and identities intentionally differ, but a CAS cannot bridge digest drift.
	serving.ExpectedRouteDigest, serving.ExpectedVIPMapDigest = old.ExpectedRouteDigest, old.ExpectedVIPMapDigest
	return k8s.DurableHandoffPlan{Plan: k8s.HandoffPlan{OperationID: intent.OperationID, Scope: intent.Scope, ExpectedActiveID: intent.ExpectedActiveID, CandidateID: intent.CandidateID,
		ExpectedGeneration: intent.ExpectedGeneration, TargetGeneration: intent.TargetGeneration, Decision: decision, OldServing: old, NewPrepared: prepared, OldWithdrawal: withdrawal, NewServing: serving}, OldLeaseIdentity: "old-lease-" + intent.OperationID.String(), TargetLeaseIdentity: "target-lease-" + intent.OperationID.String()}
}

func tickArtifact(scope k8s.HandoffPoolScope, connector uuid.UUID, generation, revision, epoch uint64, role k8s.OwnershipRole, identity string, expires time.Time) k8s.ArtifactPrerequisite {
	routeDigest, vipMapDigest := k8s.P2HandoffCanonicalEmptyRouteDigest, ""
	if role == k8s.Serving {
		routeDigest = fmt.Sprintf("%064x", revision)
		vipMapDigest = fmt.Sprintf("%064x", revision+100)
	}
	return k8s.ArtifactPrerequisite{Scope: k8s.OwnershipScope{OrgID: scope.OrgID, SiteID: scope.SiteID, PoolID: scope.PoolID, ClusterID: scope.ClusterID, ConnectorID: connector}, PromotionGeneration: generation, ManifestRevision: revision, ManifestIdentity: identity, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipMapDigest, IdentityValidated: true, Lease: k8s.CPOwnershipLease{Epoch: epoch, ExpiresAt: expires, CPIssuedValidated: true}, Role: role}
}

func insertTickOperation(t *testing.T, ctx context.Context, p *pgxpool.Pool, plan k8s.DurableHandoffPlan) {
	t.Helper()
	if _, err := p.Exec(ctx, `INSERT INTO k8s_connector_handoff_operations (id, org_id, site_id, pool_id, cluster_id, old_node_id, new_node_id, expected_generation, target_generation, old_serving_manifest_identity, candidate_prepared_manifest_identity, old_withdrawal_manifest_identity, new_serving_manifest_identity, old_serving_manifest_revision, candidate_prepared_manifest_revision, old_withdrawal_manifest_revision, new_serving_manifest_revision, old_serving_expected_route_digest, old_serving_expected_vip_map_digest, candidate_prepared_expected_route_digest, candidate_prepared_expected_vip_map_digest, old_withdrawal_expected_route_digest, old_withdrawal_expected_vip_map_digest, new_serving_expected_route_digest, new_serving_expected_vip_map_digest, old_lease_identity, target_lease_identity, old_lease_epoch, target_lease_epoch, old_lease_expires_at, target_lease_expires_at, decision_transition) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)`,
		plan.Plan.OperationID, plan.Plan.Scope.OrgID, plan.Plan.Scope.SiteID, plan.Plan.Scope.PoolID, plan.Plan.Scope.ClusterID, plan.Plan.ExpectedActiveID, plan.Plan.CandidateID, int64(plan.Plan.ExpectedGeneration), int64(plan.Plan.TargetGeneration), plan.Plan.OldServing.ManifestIdentity, plan.Plan.NewPrepared.ManifestIdentity, plan.Plan.OldWithdrawal.ManifestIdentity, plan.Plan.NewServing.ManifestIdentity, int64(plan.Plan.OldServing.ManifestRevision), int64(plan.Plan.NewPrepared.ManifestRevision), int64(plan.Plan.OldWithdrawal.ManifestRevision), int64(plan.Plan.NewServing.ManifestRevision), plan.Plan.OldServing.ExpectedRouteDigest, plan.Plan.OldServing.ExpectedVIPMapDigest, plan.Plan.NewPrepared.ExpectedRouteDigest, plan.Plan.NewPrepared.ExpectedVIPMapDigest, plan.Plan.OldWithdrawal.ExpectedRouteDigest, plan.Plan.OldWithdrawal.ExpectedVIPMapDigest, plan.Plan.NewServing.ExpectedRouteDigest, plan.Plan.NewServing.ExpectedVIPMapDigest, plan.OldLeaseIdentity, plan.TargetLeaseIdentity, int64(plan.Plan.OldServing.Lease.Epoch), int64(plan.Plan.NewPrepared.Lease.Epoch), plan.Plan.OldServing.Lease.ExpiresAt, plan.Plan.NewPrepared.Lease.ExpiresAt, string(plan.Plan.Decision.Transition)); err != nil {
		t.Fatal(err)
	}
}

func advanceTickOperationPastCAS(t *testing.T, ctx context.Context, p *pgxpool.Pool, plan k8s.DurableHandoffPlan) {
	t.Helper()
	if _, err := p.Exec(ctx, `UPDATE k8s_connector_handoff_operations SET phase = 'await_prepared_ack' WHERE id = $1`, plan.Plan.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE k8s_connector_handoff_operations SET phase = 'await_withdrawal', prepared_ack_received_at = $2 WHERE id = $1`, plan.Plan.OperationID, plan.Plan.OldServing.Lease.ExpiresAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE k8s_connector_handoff_operations SET phase = 'cas_active', withdrawal_ack_received_at = $2 WHERE id = $1`, plan.Plan.OperationID, plan.Plan.OldServing.Lease.ExpiresAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	var auditID uuid.UUID
	if err := p.QueryRow(ctx, `INSERT INTO audit_logs (org_id, actor_system, action) VALUES ($1, 'test', 'handoff') RETURNING id`, plan.Plan.Scope.OrgID).Scan(&auditID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE k8s_connector_pools SET active_node_id = $1, generation = $2 WHERE id = $3`, plan.Plan.CandidateID, int64(plan.Plan.TargetGeneration), plan.Plan.Scope.PoolID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE k8s_connector_handoff_operations SET phase = 'enable_serving', cas_receipt_at = $2, cas_audit_id = $3, cas_audit_applied = true WHERE id = $1`, plan.Plan.OperationID, plan.Plan.OldServing.Lease.ExpiresAt.Add(-time.Minute), auditID); err != nil {
		t.Fatal(err)
	}
}

func newHandoffTickTestDB(t *testing.T, ctx context.Context, admin string) *pgxpool.Pool {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	dbName := fmt.Sprintf("tnx_handoff_source_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		adminPool.Close()
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + dbName
	if err := db.MigrateTo(u.String(), 120); err != nil {
		t.Fatal(err)
	}
	p, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}
