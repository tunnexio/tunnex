package nodes

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestPostgresHandoffHealthHistory(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run PostgreSQL 0083 health-history tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := newHandoffHealthTestDB(t, ctx, admin)
	now := time.Date(2026, time.August, 14, 9, 0, 0, 0, time.UTC)

	t.Run("duplicate and restart are idempotent", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-duplicate", false)
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		first := observeHealth(t, ctx, history, f, now)
		if first.State.StaleTicks != 1 || first.State.CandidateHealthyTicks[f.candidate] != 1 {
			t.Fatalf("first observation=%+v", first.State)
		}
		duplicate := observeHealth(t, ctx, history, f, now)
		if !reflect.DeepEqual(duplicate.State, first.State) || duplicate.Decision.Transition != first.Decision.Transition {
			t.Fatalf("duplicate changed state/decision: first=%+v duplicate=%+v", first, duplicate)
		}
		restarted := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		again := observeHealth(t, ctx, restarted, f, now)
		if !reflect.DeepEqual(again.State, first.State) {
			t.Fatalf("restart duplicated observation: first=%+v again=%+v", first.State, again.State)
		}
	})

	t.Run("concurrent replicas apply one observation", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-race", false)
		start := make(chan struct{})
		results := make(chan HandoffHealthObservation, 2)
		errs := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				r, ok, err := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute).ObserveHandoffHealth(ctx, healthScope(f), now)
				if !ok && err == nil {
					err = errors.New("observation unavailable")
				}
				results <- r
				errs <- err
			}()
		}
		close(start)
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			if r := <-results; r.State.StaleTicks != 1 || r.State.CandidateHealthyTicks[f.candidate] != 1 {
				t.Fatalf("race result=%+v", r.State)
			}
		}
		assertHealthState(t, ctx, p, f, 1, 0, map[uuid.UUID]int{f.candidate: 1})
	})

	t.Run("out of order evidence fails closed", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-order", false)
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		observeHealth(t, ctx, history, f, now)
		if _, ok, err := history.ObserveHandoffHealth(ctx, healthScope(f), now.Add(-time.Second)); !errors.Is(err, ErrHandoffHealthObservationStale) || ok {
			t.Fatalf("older observation ok=%t err=%v", ok, err)
		}
		assertHealthState(t, ctx, p, f, 1, 0, map[uuid.UUID]int{f.candidate: 1})
	})

	t.Run("membership churn prunes evidence and rejoined member starts at zero", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-churn", false)
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		observeHealth(t, ctx, history, f, now)
		if _, err := p.Exec(ctx, `DELETE FROM k8s_connector_pool_members WHERE pool_id=$1 AND node_id=$2`, f.pool, f.candidate); err != nil {
			t.Fatal(err)
		}
		if got := healthTickCount(t, ctx, p, f.pool); got != 0 {
			t.Fatalf("departed candidate tick rows=%d", got)
		}
		if _, err := sqlc.New(p).AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: f.pool, OrgID: f.org, NodeID: f.candidate, AdminPriority: 10}); err != nil {
			t.Fatal(err)
		}
		// Even the same UUID rejoined to this pool gets only its first new
		// evidence tick; the membership FK cascade erased its old streak.
		o := observeHealth(t, ctx, history, f, now.Add(time.Second))
		if o.State.CandidateHealthyTicks[f.candidate] != 1 {
			t.Fatalf("rejoined member inherited streak: %+v", o.State.CandidateHealthyTicks)
		}
	})

	t.Run("cross-pool membership move invalidates both pool incarnations", func(t *testing.T) {
		oldPool := newHandoffTickPool(t, ctx, p, now, "health-move-old", false)
		newPool := newSiblingHandoffTickPool(t, ctx, p, oldPool, now, "health-move-new")
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		for tick := 0; tick < k8s.PromoteAfterStaleTicks; tick++ {
			at := now.Add(time.Duration(tick) * time.Second)
			observeHealth(t, ctx, history, oldPool, at)
			observeHealth(t, ctx, history, newPool, at)
		}
		q := sqlc.New(p)
		beforeOld, err := q.GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(oldPool)))
		if err != nil {
			t.Fatal(err)
		}
		beforeNew, err := q.GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(newPool)))
		if err != nil {
			t.Fatal(err)
		}
		if beforeOld.LastTransition != string(k8s.Promoted) || beforeNew.LastTransition != string(k8s.Promoted) {
			t.Fatalf("expected pending transitions before move: old=%+v new=%+v", beforeOld, beforeNew)
		}

		// Raw writers can move a non-owner membership row. Both old and new
		// pools must become new incarnations; the trigger locks their state rows
		// in pool-ID order before clearing either side.
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pool_members SET pool_id=$1 WHERE pool_id=$2 AND node_id=$3`, newPool.pool, oldPool.pool, oldPool.candidate); err != nil {
			t.Fatal(err)
		}
		afterOld, err := q.GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(oldPool)))
		if err != nil {
			t.Fatal(err)
		}
		afterNew, err := q.GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(newPool)))
		if err != nil {
			t.Fatal(err)
		}
		for label, beforeAfter := range map[string][2]sqlc.K8sConnectorPoolHealthState{
			"old": {beforeOld, afterOld},
			"new": {beforeNew, afterNew},
		} {
			before, after := beforeAfter[0], beforeAfter[1]
			if after.MembershipEpoch != before.MembershipEpoch+1 || after.StaleTicks != 0 || after.PreferredFreshTicks != 0 || after.LastTransition != string(k8s.NoChange) || after.LastObservationKey != nil {
				t.Fatalf("%s pool move did not invalidate state: before=%+v after=%+v", label, before, after)
			}
		}
		if got := healthTickCount(t, ctx, p, oldPool.pool); got != 0 {
			t.Fatalf("old pool retained %d candidate tick rows", got)
		}
		if got := healthTickCount(t, ctx, p, newPool.pool); got != 0 {
			t.Fatalf("new pool retained %d candidate tick rows", got)
		}
	})

	t.Run("no-op member and pool updates preserve durable hysteresis", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-noop", false)
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		first := observeHealth(t, ctx, history, f, now)
		q := sqlc.New(p)
		before, err := q.GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(f)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pool_members SET admin_priority=admin_priority WHERE pool_id=$1 AND node_id=$2`, f.pool, f.candidate); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pools SET preferred_node_id=preferred_node_id, active_node_id=active_node_id, generation=generation WHERE id=$1`, f.pool); err != nil {
			t.Fatal(err)
		}
		after, err := q.GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(f)))
		if err != nil {
			t.Fatal(err)
		}
		if after.MembershipEpoch != before.MembershipEpoch || after.StaleTicks != before.StaleTicks || after.PreferredFreshTicks != before.PreferredFreshTicks || after.LastTransition != before.LastTransition || after.LastObservationKey == nil || before.LastObservationKey == nil || *after.LastObservationKey != *before.LastObservationKey {
			t.Fatalf("no-op update reset durable state: before=%+v after=%+v", before, after)
		}
		duplicate := observeHealth(t, ctx, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), f, now)
		if !reflect.DeepEqual(duplicate.State, first.State) || duplicate.Decision.Transition != first.Decision.Transition {
			t.Fatalf("no-op update broke observation idempotency: first=%+v duplicate=%+v", first, duplicate)
		}
	})

	t.Run("org scope is exact", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-scope", false)
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		bad := healthScope(f)
		bad.OrgID = uuid.New()
		if _, ok, err := history.ObserveHandoffHealth(ctx, bad, now); err != nil || ok {
			t.Fatalf("cross-org observation ok=%t err=%v", ok, err)
		}
		if got := healthTickCount(t, ctx, p, f.pool); got != 0 {
			t.Fatalf("cross-org write created %d ticks", got)
		}
	})

	t.Run("failback needs five distinct CP evidence observations", func(t *testing.T) {
		f := newHandoffTickPool(t, ctx, p, now, "health-failback", false)
		// Make the non-preferred candidate active at generation two. Preferred is
		// fresh, so only persisted preferred freshness can reach FailedBack.
		if _, err := p.Exec(ctx, `UPDATE k8s_connector_pools SET active_node_id=$1, generation=2 WHERE id=$2`, f.candidate, f.pool); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(ctx, `UPDATE nodes SET last_seen_at=$1, policy_reported_at=$1 WHERE id IN ($2,$3)`, now.Add(-time.Second), f.active, f.candidate); err != nil {
			t.Fatal(err)
		}
		history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
		for i := 0; i < k8s.FailbackAfterFreshTicks; i++ {
			at := now.Add(time.Duration(i) * time.Second)
			if _, err := p.Exec(ctx, `UPDATE nodes SET policy_reported_at=$1 WHERE id=$2`, at, f.active); err != nil {
				t.Fatal(err)
			}
			o := observeHealth(t, ctx, history, f, at)
			if i < k8s.FailbackAfterFreshTicks-1 && o.Decision.Transition == k8s.FailedBack {
				t.Fatalf("early failback at tick %d", i+1)
			}
			if i == k8s.FailbackAfterFreshTicks-1 && o.Decision.Transition != k8s.FailedBack {
				t.Fatalf("final decision=%+v", o.Decision)
			}
		}
	})
}

func TestPostgresHandoffTickSourceUsesDurableHealthHistory(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run durable tick-source history proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := newHandoffHealthRuntimeTestDB(t, ctx, admin)
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	f := newProductionHandoffTickPool(t, ctx, p, now, "health-source", false)
	history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
	resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}
	source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, history, resolver, tickSourceConfig())
	for tick := 0; tick < k8s.PromoteAfterStaleTicks; tick++ {
		requests, err := leaderBoundHandoffRequests(t, ctx, p, source, now.Add(time.Duration(tick)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if tick < k8s.PromoteAfterStaleTicks-1 {
			if len(requests) != 0 {
				t.Fatalf("tick %d requests=%d, want no premature transition", tick+1, len(requests))
			}
			continue
		}
		if len(requests) != 1 || requests[0].ObservedHealthDecision == nil || requests[0].ObservedHealthDecision.Transition != k8s.Promoted {
			t.Fatalf("threshold request=%+v", requests)
		}
		if requests[0].Plan.Plan.CandidateID != f.candidate {
			t.Fatalf("candidate=%s, want %s", requests[0].Plan.Plan.CandidateID, f.candidate)
		}
	}
	// A restart before durable operation claim retains the threshold decision
	// with its stable operation ID; it does not begin a second three-tick run.
	restarted := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), resolver, tickSourceConfig())
	retry, err := leaderBoundHandoffRequests(t, ctx, p, restarted, now.Add(3*time.Second))
	if err != nil || len(retry) != 1 || retry[0].ObservedHealthDecision == nil || retry[0].ObservedHealthDecision.Transition != k8s.Promoted {
		t.Fatalf("restart lost durable threshold: requests=%+v err=%v", retry, err)
	}
	if retry[0].Plan.Plan.OperationID != StableHandoffOperationID(healthScope(f), f.active, f.candidate, 1, retry[0].ObservedMembershipEpoch) {
		t.Fatalf("restart changed operation identity: %s", retry[0].Plan.Plan.OperationID)
	}
	state, ok, err := history.HandoffHealthState(ctx, healthScope(f))
	if err != nil || !ok || state.StaleTicks != 0 {
		t.Fatalf("post-transition durable state=%+v ok=%t err=%v", state, ok, err)
	}
}

func TestPostgresHandoffTickSourceRefusesUnfencedObservationWrites(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run leader-bound source fencing proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := newHandoffHealthRuntimeTestDB(t, ctx, admin)
	now := time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)

	t.Run("mismatched connection", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "health-unfenced-mismatch", false)
		source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}, tickSourceConfig())
		leaderConn, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer leaderConn.Release()
		otherConn, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer otherConn.Release()
		const key int64 = 840000002
		var locked bool
		if err := leaderConn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil || !locked {
			t.Fatalf("lock leader err=%v locked=%t", err, locked)
		}
		defer func() { _, _ = leaderConn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key) }()
		var pid int32
		if err := leaderConn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			t.Fatal(err)
		}
		before := sourceMutationSnapshot(t, ctx, p, fixture)
		if _, err := source.HandoffRequestsWithLeadership(ctx, now, k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: key}, otherConn); !errors.Is(err, ErrHandoffHealthLeaderSessionUnavailable) {
			t.Fatalf("mismatched session err=%v, want leader-session refusal", err)
		}
		if after := sourceMutationSnapshot(t, ctx, p, fixture); after != before {
			t.Fatalf("mismatched session mutated source state: before=%+v after=%+v", before, after)
		}
	})

	t.Run("unbound call has no pool-writer fallback", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "health-unfenced-direct", false)
		source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}, tickSourceConfig())
		before := sourceMutationSnapshot(t, ctx, p, fixture)
		if _, err := source.HandoffRequests(ctx, now); !errors.Is(err, ErrHandoffHealthLeaderSessionUnavailable) {
			t.Fatalf("unbound source err=%v, want leader-session refusal", err)
		}
		if after := sourceMutationSnapshot(t, ctx, p, fixture); after != before {
			t.Fatalf("unbound source fell back to pool writer: before=%+v after=%+v", before, after)
		}
	})

	t.Run("released exact session before authorization", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "health-unfenced-release", false)
		source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}, tickSourceConfig())
		conn, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		const key int64 = 840000003
		var locked bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil || !locked {
			t.Fatalf("lock leader err=%v locked=%t", err, locked)
		}
		var pid int32
		if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", key); err != nil {
			t.Fatal(err)
		}
		before := sourceMutationSnapshot(t, ctx, p, fixture)
		if _, err := source.HandoffRequestsWithLeadership(ctx, now, k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: key}, conn); !errors.Is(err, ErrHandoffHealthLeaderSessionUnavailable) {
			t.Fatalf("released session err=%v, want leader-session refusal", err)
		}
		if after := sourceMutationSnapshot(t, ctx, p, fixture); after != before {
			t.Fatalf("released session mutated source state: before=%+v after=%+v", before, after)
		}
	})

	t.Run("exact session loss during observation rolls back", func(t *testing.T) {
		fixture := newProductionHandoffTickPool(t, ctx, p, now, "health-unfenced-during", false)
		conn, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		const key int64 = 840000004
		var locked bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil || !locked {
			t.Fatalf("lock leader err=%v locked=%t", err, locked)
		}
		var pid int32
		if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			t.Fatal(err)
		}
		policy := &unlockingHandoffPolicy{conn: conn, key: key}
		source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, NewPostgresHandoffHealthHistory(p, policy, time.Minute), &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}, tickSourceConfig())
		before := sourceMutationSnapshot(t, ctx, p, fixture)
		if _, err := source.HandoffRequestsWithLeadership(ctx, now, k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: key}, conn); !errors.Is(err, ErrHandoffHealthLeaderSessionUnavailable) {
			t.Fatalf("mid-observation session loss err=%v, want leader-session refusal", err)
		}
		if after := sourceMutationSnapshot(t, ctx, p, fixture); after != before {
			t.Fatalf("mid-observation session loss mutated source state: before=%+v after=%+v", before, after)
		}
	})
}

type unlockingHandoffPolicy struct {
	conn *pgxpool.Conn
	key  int64
	once sync.Once
}

func (p *unlockingHandoffPolicy) HandoffPolicyAcknowledgements(ctx context.Context, orgID, siteID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]k8s.PolicyAcknowledgement, error) {
	var unlockErr error
	p.once.Do(func() {
		_, unlockErr = p.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", p.key)
	})
	if unlockErr != nil {
		return nil, unlockErr
	}
	return handoffTickPolicy{}.HandoffPolicyAcknowledgements(ctx, orgID, siteID, ids)
}

type handoffSourceMutationSnapshot struct {
	active             uuid.UUID
	generation         int64
	health, ticks, ops int
}

func sourceMutationSnapshot(t *testing.T, ctx context.Context, p *pgxpool.Pool, fixture handoffTickPoolFixture) handoffSourceMutationSnapshot {
	t.Helper()
	var out handoffSourceMutationSnapshot
	if err := p.QueryRow(ctx, `SELECT active_node_id, generation FROM k8s_connector_pools WHERE id=$1`, fixture.pool).Scan(&out.active, &out.generation); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM k8s_connector_pool_health_states WHERE pool_id=$1`, fixture.pool).Scan(&out.health); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM k8s_connector_pool_health_candidate_ticks WHERE pool_id=$1`, fixture.pool).Scan(&out.ticks); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM k8s_connector_handoff_operations WHERE pool_id=$1`, fixture.pool).Scan(&out.ops); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPostgresHandoffTickSourceMembershipChurnInvalidatesPendingTransition(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run durable membership-incarnation proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := newHandoffHealthRuntimeTestDB(t, ctx, admin)
	now := time.Date(2026, time.August, 14, 11, 0, 0, 0, time.UTC)
	f := newProductionHandoffTickPool(t, ctx, p, now, "health-pending-churn", false)
	history := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
	resolver := &handoffTickPlans{now: now, plans: map[uuid.UUID]k8s.DurableHandoffPlan{}}
	source := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, history, resolver, tickSourceConfig())

	// Reach the three-tick promotion edge without calling a coordinator: no
	// 0082 operation exists, so the state-row retained transition is the only
	// thing that could accidentally resurrect after membership churn.
	for tick := 0; tick < k8s.PromoteAfterStaleTicks; tick++ {
		requests, err := leaderBoundHandoffRequests(t, ctx, p, source, now.Add(time.Duration(tick)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if tick < k8s.PromoteAfterStaleTicks-1 && len(requests) != 0 {
			t.Fatalf("pre-threshold tick %d emitted %+v", tick+1, requests)
		}
		if tick == k8s.PromoteAfterStaleTicks-1 && (len(requests) != 1 || requests[0].ObservedHealthDecision == nil || requests[0].ObservedHealthDecision.Transition != k8s.Promoted) {
			t.Fatalf("threshold did not create pending transition: %+v", requests)
		}
	}
	before, err := sqlc.New(p).GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(f)))
	if err != nil {
		t.Fatal(err)
	}
	if before.LastTransition != string(k8s.Promoted) {
		t.Fatalf("expected pending promotion, state=%+v", before)
	}

	if _, err := p.Exec(ctx, `DELETE FROM k8s_connector_pool_members WHERE pool_id=$1 AND node_id=$2`, f.pool, f.candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlc.New(p).AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: f.pool, OrgID: f.org, NodeID: f.candidate, AdminPriority: 10}); err != nil {
		t.Fatal(err)
	}
	// Production discovery binds a fenced transition to an exact membership
	// epoch. Model the separate revalidation/activation step before proving a
	// fresh health threshold for the new pool incarnation.
	syncProductionHandoffTickPoolEpoch(t, ctx, p, f)
	after, err := sqlc.New(p).GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(f)))
	if err != nil {
		t.Fatal(err)
	}
	if after.MembershipEpoch != before.MembershipEpoch+2 || after.LastTransition != string(k8s.NoChange) || after.LastObservationKey != nil || after.StaleTicks != 0 || after.PreferredFreshTicks != 0 {
		t.Fatalf("membership churn did not durably invalidate pending transition: before=%+v after=%+v", before, after)
	}
	if got := healthTickCount(t, ctx, p, f.pool); got != 0 {
		t.Fatalf("membership churn retained %d candidate tick rows", got)
	}

	// Restart between leave/rejoin has no in-memory reset to rely on. The
	// rejoined same UUID needs a full new threshold before a request appears.
	restarted := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), resolver, tickSourceConfig())
	for tick := 0; tick < k8s.PromoteAfterStaleTicks; tick++ {
		requests, err := leaderBoundHandoffRequests(t, ctx, p, restarted, now.Add(time.Duration(k8s.PromoteAfterStaleTicks+tick)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if tick < k8s.PromoteAfterStaleTicks-1 && len(requests) != 0 {
			t.Fatalf("rejoined pre-threshold tick %d resurrected %+v", tick+1, requests)
		}
		if tick == k8s.PromoteAfterStaleTicks-1 && (len(requests) != 1 || requests[0].ObservedHealthDecision == nil || requests[0].ObservedHealthDecision.Transition != k8s.Promoted) {
			t.Fatalf("rejoined full threshold missing transition: %+v", requests)
		}
	}
}

func healthScope(f handoffTickPoolFixture) k8s.HandoffPoolScope {
	return k8s.HandoffPoolScope{OrgID: f.org, SiteID: f.site, ClusterID: f.cluster, PoolID: f.pool}
}
func observeHealth(t *testing.T, ctx context.Context, h *PostgresHandoffHealthHistory, f handoffTickPoolFixture, at time.Time) HandoffHealthObservation {
	t.Helper()
	out, ok, err := h.ObserveHandoffHealth(ctx, healthScope(f), at)
	if err != nil || !ok {
		t.Fatalf("observe health ok=%t err=%v", ok, err)
	}
	return out
}
func healthTickCount(t *testing.T, ctx context.Context, p *pgxpool.Pool, pool uuid.UUID) int {
	t.Helper()
	var n int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM k8s_connector_pool_health_candidate_ticks WHERE pool_id=$1`, pool).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func assertHealthState(t *testing.T, ctx context.Context, p *pgxpool.Pool, f handoffTickPoolFixture, stale, preferred int, want map[uuid.UUID]int) {
	t.Helper()
	h := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
	got, ok, err := h.HandoffHealthState(ctx, healthScope(f))
	if err != nil || !ok {
		t.Fatalf("read health state ok=%t err=%v", ok, err)
	}
	if got.StaleTicks != stale || got.PreferredFresh != preferred || fmt.Sprint(got.CandidateHealthyTicks) != fmt.Sprint(want) {
		t.Fatalf("state=%+v want stale=%d preferred=%d candidates=%v", got, stale, preferred, want)
	}
}

func TestK8sConnectorPoolHealthHistoryMigrationUpDownUp(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run 0083 migration proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	name := fmt.Sprintf("tnx_health_migration_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") }()
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), 83); err != nil {
		t.Fatalf("up 0083: %v", err)
	}
	p, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Exec(ctx, `SELECT 1 FROM k8s_connector_pool_health_states`); err != nil {
		t.Fatalf("0083 table unavailable: %v", err)
	}
	if err := db.MigrateTo(u.String(), 82); err != nil {
		t.Fatalf("down 0083 empty: %v", err)
	}
	if err := db.MigrateTo(u.String(), 83); err != nil {
		t.Fatalf("re-up 0083: %v", err)
	}
	f := newHandoffTickPool(t, ctx, p, time.Now().UTC(), "health-rollback", false)
	observeHealth(t, ctx, NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute), f, time.Now().UTC())
	if err := db.MigrateTo(u.String(), 82); err == nil {
		t.Fatal("rollback with health history must refuse")
	}
}

func newSiblingHandoffTickPool(t *testing.T, ctx context.Context, p *pgxpool.Pool, sibling handoffTickPoolFixture, now time.Time, name string) handoffTickPoolFixture {
	t.Helper()
	cluster, active, candidate := uuid.New(), uuid.New(), uuid.New()
	for i, node := range []uuid.UUID{active, candidate} {
		seen := now.Add(-time.Second)
		if node == active {
			seen = now.Add(-2 * time.Minute)
		}
		if _, err := p.Exec(ctx, `INSERT INTO nodes (id, org_id, site_id, name, cert_serial, status, wg_public_key, endpoint, last_seen_at, policy_reported_at, capabilities) VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$8,$9,$10)`, node, sibling.org, sibling.site, fmt.Sprintf("%s-node-%d", name, i), fmt.Sprintf("%s-serial-%d", name, i), tickWGKey(i+2), fmt.Sprintf("198.51.100.%d:51820", i+22), seen, now.Add(-time.Second), []byte(`{"policy_hash":"policy","k8s_endpoints_unavailable":false}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(ctx, `INSERT INTO k8s_clusters (id, org_id, site_id, name, vip_range) VALUES ($1,$2,$3,$4,'100.81.0.0/16')`, cluster, sibling.org, sibling.site, name+" cluster"); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(p)
	created, err := q.CreateK8sConnectorPool(ctx, sqlc.CreateK8sConnectorPoolParams{ClusterID: cluster, OrgID: sibling.org, PreferredNodeID: active, ActiveNodeID: active})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: created.ID, OrgID: sibling.org, NodeID: candidate, AdminPriority: 10}); err != nil {
		t.Fatal(err)
	}
	if bound, err := q.BindK8sClusterConnectorPool(ctx, sqlc.BindK8sClusterConnectorPoolParams{OrgID: sibling.org, ClusterID: cluster, ConnectorPoolID: uuidParam(created.ID)}); err != nil || bound != 1 {
		t.Fatalf("bind sibling pool=%d err=%v", bound, err)
	}
	return handoffTickPoolFixture{org: sibling.org, site: sibling.site, cluster: cluster, pool: created.ID, active: active, candidate: candidate}
}

func newHandoffHealthTestDB(t *testing.T, ctx context.Context, admin string) *pgxpool.Pool {
	return newHandoffHealthTestDBAt(t, ctx, admin, 83, "history")
}

func newHandoffHealthRuntimeTestDB(t *testing.T, ctx context.Context, admin string) *pgxpool.Pool {
	return newHandoffHealthTestDBAt(t, ctx, admin, 122, "runtime")
}

func newHandoffHealthTestDBAt(t *testing.T, ctx context.Context, admin string, version uint, suffix string) *pgxpool.Pool {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("tnx_handoff_health_%s_%d", suffix, time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		adminPool.Close()
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), version); err != nil {
		t.Fatalf("migrate through %04d: %v", version, err)
	}
	p, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

var _ = sqlc.K8sConnectorPoolHealthState{}
var _ = sync.Once{}
