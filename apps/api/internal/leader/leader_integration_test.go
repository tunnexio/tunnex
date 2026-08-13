package leader

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool connects to the live test DB. Leader election is a DATABASE property — Postgres is what
// guarantees single-holder — so testing it against a fake would test nothing that matters.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TUNNEX_TEST_DATABASE_URL not set")
	}
	// MaxConns must exceed the number of simulated replicas: each leader holds one connection for the whole
	// of its leadership, which is the mechanism working as designed.
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

// TestExactlyOneLeaderOfN — the ruling's pin. N replicas campaign; EXACTLY ONE leads.
//
// This is the safety property, and it is the one that must never be merely "usually true": two leaders
// ticking means a double failover promotion or two concurrent CRL rebuilds. The assertion is exact-one, not
// at-most-one and not at-least-one.
func TestExactlyOneLeaderOfN(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const replicas = 4
	electors := make([]*Elector, replicas)
	var wg sync.WaitGroup
	for i := range electors {
		electors[i] = &Elector{}
		wg.Add(1)
		go func(e *Elector) { defer wg.Done(); e.Run(ctx, pool, quiet()) }(electors[i])
	}

	count := func() int {
		n := 0
		for _, e := range electors {
			if e.IsLeader() {
				n++
			}
		}
		return n
	}
	if !waitFor(t, 10*time.Second, func() bool { return count() == 1 }) {
		t.Fatalf("want exactly 1 leader of %d, got %d", replicas, count())
	}
	// Hold the invariant over time — a race that resolves to two leaders a second later is still two leaders.
	for i := 0; i < 10; i++ {
		if n := count(); n != 1 {
			t.Fatalf("leadership must be exactly 1 at all times, saw %d", n)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	wg.Wait()
	if n := count(); n != 0 {
		t.Fatalf("after shutdown no replica may still claim leadership, got %d", n)
	}
}

// TestFollowerTakesOverWhenLeaderStops — the liveness half, and the direction the mechanism is allowed to
// fail in. A follower must take over after the leader goes away; the gap is bounded by RetryInterval.
func TestFollowerTakesOverWhenLeaderStops(t *testing.T) {
	pool := testPool(t)

	leaderCtx, stopLeader := context.WithCancel(context.Background())
	followerCtx, stopFollower := context.WithCancel(context.Background())
	defer stopFollower()

	first, second := &Elector{}, &Elector{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); first.Run(leaderCtx, pool, quiet()) }()
	if !waitFor(t, 10*time.Second, first.IsLeader) {
		t.Fatal("the first elector never acquired leadership")
	}

	wg.Add(1)
	go func() { defer wg.Done(); second.Run(followerCtx, pool, quiet()) }()
	// The follower must NOT lead while the leader holds — the safety direction, asserted before liveness.
	time.Sleep(500 * time.Millisecond)
	if second.IsLeader() {
		t.Fatal("two leaders: the follower acquired leadership while the leader still held it")
	}

	stopLeader() // graceful stop → explicit unlock → the follower should win promptly
	if !waitFor(t, 3*RetryInterval, second.IsLeader) {
		t.Fatalf("the follower did not take over within %s of the leader stopping", 3*RetryInterval)
	}
	if first.IsLeader() {
		t.Fatal("the stopped leader still claims leadership")
	}

	stopFollower()
	wg.Wait()
}

// TestLeadershipDropsWhenConnectionDies — leadership must not survive its own connection. This is what makes
// a SIGKILLed or partitioned leader safe: Postgres frees the lock when the session ends, and this replica
// stops claiming leadership rather than ticking on with a lock it no longer holds.
//
// The session is killed SERVER-SIDE with pg_terminate_backend, which is a truer simulation than closing the
// pool client-side: it is what actually happens when a leader is SIGKILLed, its host dies, or the network
// drops — Postgres notices the session is gone and releases its locks, with no cooperation from our code.
func TestLeadershipDropsWhenConnectionDies(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := &Elector{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); e.Run(ctx, pool, quiet()) }()
	if !waitFor(t, 10*time.Second, e.IsLeader) {
		t.Fatal("never acquired leadership")
	}

	// Terminate whichever backend holds the advisory lock — the leader's session, identified through
	// Postgres itself rather than by bookkeeping we could get wrong.
	var killed bool
	err := pool.QueryRow(context.Background(), `
		SELECT pg_terminate_backend(l.pid)
		  FROM pg_locks l
		 WHERE l.locktype = 'advisory'
		   AND ((l.classid::bigint << 32) | l.objid::bigint) = $1
		   AND l.granted
		 LIMIT 1`, SchedulerLockKey).Scan(&killed)
	if err != nil || !killed {
		t.Fatalf("could not terminate the leader's backend (err=%v killed=%v)", err, killed)
	}

	if !waitFor(t, 3*RetryInterval, func() bool { return !e.IsLeader() }) {
		t.Fatal("leadership survived the death of its own session — a replica that cannot reach the DB " +
			"must stop claiming leadership, or two replicas can tick at once")
	}
	cancel()
	wg.Wait()
}

// TestLeadershipIsConfirmedAgainstPGLOCKS — the finding that generalised (review #4).
//
// EVERY OTHER TEST IN THIS FILE ASSERTS THE IN-PROCESS BOOLEAN, which is the thing under test. None consults
// pg_locks, and none runs a gated tick. So a stale true, a lock stranded on a pooled connection, and an uncancelled
// in-flight tick all pass — and TestLeadershipDropsWhenConnectionDies goes further: it PASSES if the flag clears
// within 3*RetryInterval, which certifies the very stale-true window that permitted two replicas to write
// contradictory hub-set generations.
//
// This asserts the boolean AGAINST THE DATABASE, which is the only external truth available:
//
//   - a leader's ConfirmLeader must be true AND pg_locks must show its lock;
//   - a follower's ConfirmLeader must be false even though it is a healthy process;
//   - after the leader stops, its lock must be GONE from pg_locks — not merely its flag cleared. That is the
//     stranded-lock defect: conn.Release() does not free a session-scoped lock, so a cleared flag proved nothing.
func TestLeadershipIsConfirmedAgainstPGLOCKS(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	locksHeld := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1
			  AND ((classid::bigint << 32) | (objid::bigint & 4294967295)) = $1`,
			SchedulerLockKey).Scan(&n); err != nil {
			t.Fatalf("pg_locks: %v", err)
		}
		return n
	}

	if n := locksHeld(); n != 0 {
		t.Fatalf("precondition: the scheduler lock must be free before this test, found %d holders", n)
	}

	lead := &Elector{}
	leadCtx, stopLead := context.WithCancel(ctx)
	go lead.Run(leadCtx, pool, nil)

	deadline := time.Now().Add(15 * time.Second)
	for !lead.IsLeader() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !lead.IsLeader() {
		t.Fatal("never acquired leadership")
	}

	// THE DATABASE agrees, not just our flag.
	if n := locksHeld(); n != 1 {
		t.Errorf("exactly one advisory lock must be held for the scheduler key, pg_locks says %d", n)
	}
	if !lead.ConfirmLeader(context.Background(), pool) {
		t.Error("the leader's ConfirmLeader must agree with pg_locks — a boolean that cannot be checked against " +
			"the database is the defect this test exists for")
	}

	// A FOLLOWER is a healthy process that must not confirm.
	follow := &Elector{}
	followCtx, stopFollow := context.WithCancel(ctx)
	go follow.Run(followCtx, pool, nil)
	time.Sleep(2 * time.Second)
	if follow.ConfirmLeader(context.Background(), pool) {
		t.Error("a follower must never confirm leadership, however healthy it is")
	}
	stopFollow()

	// THE STRANDED-LOCK CHECK. After the leader stops, its lock must be GONE from the database — not merely its
	// flag cleared. conn.Release() does not free a session-scoped advisory lock, so before the explicit unlock on
	// every exit path, this is exactly what leaked: flag false, lock still held, fleet leaderless.
	stopLead()
	gone := time.Now().Add(15 * time.Second)
	for locksHeld() != 0 && time.Now().Before(gone) {
		time.Sleep(100 * time.Millisecond)
	}
	if n := locksHeld(); n != 0 {
		t.Errorf("after the leader stops, the advisory lock must be RELEASED IN POSTGRES, pg_locks still shows %d "+
			"holder(s). A cleared in-process flag proves nothing: releasing the connection to the pool leaves the "+
			"session — and its lock — intact, which strands leadership until the connection is recycled", n)
	}
}
