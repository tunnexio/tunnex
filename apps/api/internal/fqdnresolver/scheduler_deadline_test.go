package fqdnresolver

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"sync"
	"testing"
	"time"
)

type deadlineStore struct {
	*memoryStore
	at    time.Time
	calls int
	err   error
}

func (s *deadlineStore) NextRefreshAt(context.Context) (time.Time, error) {
	s.calls++
	return s.at, s.err
}
func TestSchedulerDeadlineWakeHonorsThirtySecondTTL(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	st := &deadlineStore{memoryStore: &memoryStore{}, at: now.Add(24 * time.Second)}
	s := NewScheduler(st, nil, SchedulerConfig{})
	s.now = func() time.Time { return now.Add(15 * time.Second) }
	if d := s.nextWake(context.Background()); d != 9*time.Second {
		t.Fatalf("wake=%v must wake24s beforeexpiry30s", d)
	}
	st.at = now.Add(14 * time.Second)
	if d := s.nextWake(context.Background()); d != schedulerWakeFloor {
		t.Fatalf("pastdue=%v", d)
	}
	st.at = now.Add(time.Hour)
	if d := s.nextWake(context.Background()); d != 15*time.Second {
		t.Fatalf("heartbeat=%v", d)
	}
}

type boundedResolver struct {
	mu               sync.Mutex
	active, max      int
	gateways, mapMax map[string]int
	entered          chan string
	release          chan struct{}
}

func (r *boundedResolver) Lookup(context.Context, Context, string) ([]Response, error) {
	panic("scoped only")
}
func (r *boundedResolver) LookupWork(ctx context.Context, w Work) ([]Response, error) {
	r.mu.Lock()
	r.active++
	if r.active > r.max {
		r.max = r.active
	}
	r.gateways[w.Context.GatewayID]++
	if r.gateways[w.Context.GatewayID] > r.mapMax[w.Context.GatewayID] {
		r.mapMax[w.Context.GatewayID] = r.gateways[w.Context.GatewayID]
	}
	r.mu.Unlock()
	r.entered <- w.Context.GatewayID
	select {
	case <-ctx.Done():
	case <-r.release:
	}
	r.mu.Lock()
	r.active--
	r.gateways[w.Context.GatewayID]--
	r.mu.Unlock()
	return []Response{answer(a(w.Hostname, "10.2.3.4", time.Minute))}, nil
}
func TestSchedulerBoundsFourGlobalTwoPerGatewayAndCancelsQueued(t *testing.T) {
	st := &memoryStore{}
	org := uuid.New()
	for i := 0; i < 12; i++ {
		w := work("orders.internal")
		w.OrgID = org
		w.Context.GatewayID = []string{"g1", "g2", "g3"}[i/4]
		st.work = append(st.work, w)
	}
	r := &boundedResolver{gateways: map[string]int{}, mapMax: map[string]int{}, entered: make(chan string, 32), release: make(chan struct{})}
	s := NewScheduler(st, r, SchedulerConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Tick(ctx); close(done) }()
	for i := 0; i < 4; i++ {
		select {
		case <-r.entered:
		case <-time.After(time.Second):
			t.Fatal("four slots did not start")
		}
	}
	select {
	case <-r.entered:
		t.Fatal("fifth started")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not drain")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max != 4 {
		t.Fatalf("global=%d", r.max)
	}
	for g, n := range r.mapMax {
		if n > 2 {
			t.Fatalf("gateway%s=%d", g, n)
		}
	}
	if len(r.entered) != 0 {
		t.Fatal("queued aftercancel")
	}
}

type clockAdvancingStore struct {
	*memoryStore
	now *time.Time
}

func (s *clockAdvancingStore) Due(ctx context.Context, at time.Time, n int) ([]Work, error) {
	*s.now = at.Add(7 * time.Second)
	return s.memoryStore.Due(ctx, at, n)
}
func TestSchedulerUsesFreshWorkClockAfterDueRead(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	st := &clockAdvancingStore{memoryStore: &memoryStore{work: []Work{work("orders.internal")}}, now: &now}
	r := &fixtureResolver{responses: []Response{answer(a("orders.internal", "10.2.3.4", time.Minute))}}
	s := NewScheduler(st, r, SchedulerConfig{})
	s.now = func() time.Time { return now }
	s.Tick(context.Background())
	if len(st.published) != 1 || !st.published[0].ResolvedAt.Equal(now) {
		t.Fatalf("staleclock: %+v", st.published)
	}
}

func TestSchedulerFollowerAndCanceledWakeNeverReadsDeadlines(t *testing.T) {
	st := &deadlineStore{memoryStore: &memoryStore{}}
	s := NewScheduler(st, nil, SchedulerConfig{MayTick: func() bool { return false }})
	if d := s.nextWake(context.Background()); d != 15*time.Second || st.calls != 0 {
		t.Fatalf("follower read deadline: %v %d", d, st.calls)
	}
	s.mayTick = func() bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d := s.nextWake(ctx); d != 15*time.Second || st.calls != 0 {
		t.Fatalf("canceled read deadline: %v %d", d, st.calls)
	}
}

type causalClockStore struct {
	active Generation
	w      Work
	clock  *time.Time
	gap    time.Duration
}

func (s *causalClockStore) NextRefreshAt(context.Context) (time.Time, error) {
	return s.active.RefreshAt, nil
}
func (s *causalClockStore) Due(_ context.Context, now time.Time, _ int) ([]Work, error) {
	if s.active.TTL == 0 || !now.Before(s.active.RefreshAt) {
		return []Work{s.w}, nil
	}
	return nil, nil
}
func (s *causalClockStore) Publish(_ context.Context, _ Work, g Generation) error {
	if s.active.TTL > 0 {
		expiry := s.active.ResolvedAt.Add(s.active.TTL)
		if s.clock.After(expiry) {
			s.gap = s.clock.Sub(expiry)
		}
	}
	s.active = g
	return nil
}
func (s *causalClockStore) Withdraw(context.Context, Work, WithdrawalCause, time.Time) error {
	return nil
}

type causalClockResolver struct {
	clock *time.Time
	calls int
	err   error
}

func (r *causalClockResolver) Lookup(_ context.Context, _ Context, h string) ([]Response, error) {
	r.calls++
	if r.calls > 1 {
		*r.clock = r.clock.Add(5 * time.Second)
	}
	return []Response{answer(a(h, "10.81.0.10", 30*time.Second))}, nil
}
func TestSchedulerRealLifecycleDeadlineWakeRenewsBeforeHardExpiry(t *testing.T) {
	start := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	clock := start
	st := &causalClockStore{clock: &clock, w: work("fqdn-tcp.classic.gcp.s2s-qa.tunnex.app")}
	r := &causalClockResolver{clock: &clock}
	s := NewScheduler(st, r, SchedulerConfig{})
	s.now = func() time.Time { return clock }
	s.Tick(context.Background())
	if st.active.TTL != 30*time.Second || !st.active.RefreshAt.Equal(start.Add(24*time.Second)) {
		t.Fatalf("real lifecycle TTL/refresh changed: %+v", st.active)
	}
	clock = clock.Add(s.nextWake(context.Background()))
	s.Tick(context.Background())
	if r.calls != 1 {
		t.Fatal("heartbeat forced early refresh")
	}
	wake := s.nextWake(context.Background())
	if wake != 9*time.Second {
		t.Fatalf("next deadline wake=%v", wake)
	}
	clock = clock.Add(wake)
	s.Tick(context.Background())
	if clock.Sub(start) != 29*time.Second || st.gap != 0 || !st.active.ResolvedAt.Equal(start.Add(24*time.Second)) {
		t.Fatalf("renewal clock=%v gap=%v active=%+v", clock.Sub(start), st.gap, st.active)
	}
}

func TestSchedulerExplicitHeartbeatRetainedWithoutUsableDeadline(t *testing.T) {
	for _, store := range []Store{&memoryStore{}, &deadlineStore{memoryStore: &memoryStore{}}, &deadlineStore{memoryStore: &memoryStore{}, err: errors.New("deadline read failed")}} {
		s := NewScheduler(store, nil, SchedulerConfig{Interval: time.Minute})
		if d := s.nextWake(context.Background()); d != time.Minute {
			t.Fatalf("explicit heartbeat changed: %v", d)
		}
	}
}
