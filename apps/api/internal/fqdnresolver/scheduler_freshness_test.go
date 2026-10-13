package fqdnresolver

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// This store models the genuine SQL cutoff/eligibility, not a changed TTL or clock.
type freshnessStore struct {
	mu           sync.Mutex
	clock        func() time.Time
	start        time.Time
	cutoff       map[string]time.Time
	work         []Work
	published    []Generation
	publishTimes []time.Time
	headroom     time.Duration
}

func (f *freshnessStore) Due(ctx context.Context, now time.Time, limit int) ([]Work, error) {
	return f.selectWork(now, limit, 0), nil
}
func (f *freshnessStore) DueForRefresh(ctx context.Context, now time.Time, limit int, headroom time.Duration) ([]Work, error) {
	f.headroom = headroom
	return f.selectWork(now, limit, headroom), nil
}
func (f *freshnessStore) selectWork(now time.Time, limit int, headroom time.Duration) []Work {
	var result []Work
	for _, w := range f.work {
		cutoff := f.cutoff[w.Hostname]
		ttl := cutoff.Sub(f.start)
		if !now.Before(f.start.Add(ttl*8/10)) || headroom > 0 && !cutoff.After(now.Add(headroom)) {
			result = append(result, w)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return f.cutoff[result[i].Hostname].Before(f.cutoff[result[j].Hostname]) })
	if len(result) > limit {
		return result[:limit]
	}
	return result
}
func (f *freshnessStore) Publish(_ context.Context, w Work, g Generation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, g)
	f.publishTimes = append(f.publishTimes, f.clock())
	return nil
}
func (f *freshnessStore) Withdraw(context.Context, Work, WithdrawalCause, time.Time) error {
	return nil
}

// Hold each wave until every worker has captured its start time. A synchronized
// clock then charges bounded lookup time without relying on goroutine order.
type schedulerTestClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *schedulerTestClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *schedulerTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type schedulerTestLookup struct {
	name    string
	started time.Time
	release chan struct{}
}

func stagedSchedulerResolver(t *testing.T, clock *schedulerTestClock) (Resolver, <-chan schedulerTestLookup) {
	t.Helper()
	entered := make(chan schedulerTestLookup, 4)
	return resolverFunc(func(ctx context.Context, _ Context, name string) ([]Response, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
			t.Error("original 5s lookup deadline changed")
		}
		lookup := schedulerTestLookup{name: name, started: clock.now(), release: make(chan struct{})}
		entered <- lookup
		select {
		case <-lookup.release:
			return []Response{answer(a(name, "10.2.3.4", 30*time.Second))}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}), entered
}
func awaitSchedulerLookup(t *testing.T, entered <-chan schedulerTestLookup) schedulerTestLookup {
	t.Helper()
	select {
	case lookup := <-entered:
		return lookup
	case <-time.After(5 * time.Second):
		t.Fatal("queued lookup did not start")
		return schedulerTestLookup{}
	}
}
func TestSchedulerRefreshHeadroomPreservesPriorCutoffWithBoundedQueue(t *testing.T) {
	start := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	clock := &schedulerTestClock{at: start.Add(15 * time.Second)}
	ws := []Work{work("later.internal"), work("first.internal"), work("middle.internal")}
	for i := range ws {
		ws[i].OrgID = ws[0].OrgID
	}
	store := &freshnessStore{clock: clock.now, start: start, work: ws, cutoff: map[string]time.Time{"later.internal": start.Add(33 * time.Second), "first.internal": start.Add(30 * time.Second), "middle.internal": start.Add(32 * time.Second)}}
	resolver, entered := stagedSchedulerResolver(t, clock)
	scheduler := NewScheduler(store, resolver, SchedulerConfig{Batch: 3})
	scheduler.now = clock.now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { scheduler.Tick(ctx); close(done) }()
	first, second := awaitSchedulerLookup(t, entered), awaitSchedulerLookup(t, entered)
	starts := map[string]time.Time{first.name: first.started, second.name: second.started}
	if _, ok := starts["first.internal"]; !ok {
		t.Fatal("earliest expiry was not in first gateway wave")
	}
	if _, ok := starts["middle.internal"]; !ok {
		t.Fatal("later expiry bypassed queued priority")
	}
	clock.advance(4900 * time.Millisecond)
	close(first.release)
	close(second.release)
	last := awaitSchedulerLookup(t, entered)
	if last.name != "later.internal" {
		t.Fatal("expiry ordering lost")
	}
	starts[last.name] = last.started
	clock.advance(4900 * time.Millisecond)
	close(last.release)
	<-done
	if len(store.published) != 3 {
		t.Fatalf("refresh not admitted before original cutoff: publications=%d", len(store.published))
	}
	for i, g := range store.published {
		if !store.publishTimes[i].Before(store.cutoff[g.Hostname]) {
			t.Fatal("old generation expired before replacement")
		}
		if !g.ResolvedAt.Equal(starts[g.Hostname]) || g.TTL != jitteredTTL(g.Hostname, 30*time.Second) {
			t.Fatal("TTL or original lookup timestamp changed")
		}
	}
	if store.headroom != 30*time.Second {
		t.Fatalf("headroom must retain conservative poll15 + three original5s slots: %s", store.headroom)
	}
}

func TestRefreshHeadroomCapsBatchAndArithmeticWithoutChangingTimeout(t *testing.T) {
	if refreshHeadroom(15*time.Second, 5*time.Second, 32) != 175*time.Second {
		t.Fatal("default bounded budget")
	}
	if refreshHeadroom(15*time.Second, 5*time.Second, 1000) != 175*time.Second {
		t.Fatal("batch capacity bound")
	}
	for _, pair := range [][2]time.Duration{{time.Duration(1<<63 - 1), time.Second}, {time.Second, time.Duration(1<<63 - 1)}} {
		if got := refreshHeadroom(pair[0], pair[1], 32); got != MaxTTL {
			t.Fatalf("overflow/headroom bound %s", got)
		}
	}
}
func TestSchedulerRefreshHeadroomCanceledParentDoesNotStartQueuedLookup(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &freshnessStore{clock: func() time.Time { return now }, start: now, work: []Work{work("orders.internal")}, cutoff: map[string]time.Time{"orders.internal": now.Add(30 * time.Second)}}
	called := false
	resolver := resolverFunc(func(context.Context, Context, string) ([]Response, error) { called = true; return nil, nil })
	NewScheduler(store, resolver, SchedulerConfig{}).Tick(ctx)
	if called || len(store.published) > 0 {
		t.Fatal("canceled parent started or published queued work")
	}
}
func TestRefreshHeadroomRejectsInvalidStoreLookaheadBeforeSQL(t *testing.T) {
	for _, bad := range []time.Duration{-1, MaxTTL + 1} {
		if _, err := NewPostgresStore(nil).DueForRefresh(context.Background(), time.Now(), 32, bad); err == nil {
			t.Fatal("invalid headroom accepted")
		}
	}
}
