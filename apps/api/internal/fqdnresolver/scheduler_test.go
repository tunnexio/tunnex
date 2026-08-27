package fqdnresolver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memoryStore struct {
	mu        sync.Mutex
	work      []Work
	dueCalls  int
	published []Generation
	withdrawn []WithdrawalCause
	entered   chan struct{}
	block     <-chan struct{}
}

func (s *memoryStore) Due(_ context.Context, _ time.Time, limit int) ([]Work, error) {
	s.mu.Lock()
	s.dueCalls++
	entered, block := s.entered, s.block
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.work) > limit {
		return append([]Work(nil), s.work[:limit]...), nil
	}
	return append([]Work(nil), s.work...), nil
}
func (s *memoryStore) Publish(_ context.Context, _ Work, g Generation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.published = append(s.published, g)
	return nil
}
func (s *memoryStore) Withdraw(_ context.Context, _ Work, c WithdrawalCause, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.withdrawn = append(s.withdrawn, c)
	return nil
}

func work(name string) Work {
	return Work{OrgID: uuid.New(), ResourceID: uuid.New(), Hostname: name, Context: selected}
}

func TestSchedulerUsesOnlySelectedContextAndPublishesBoundedWork(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{work: []Work{work("orders.internal")}}
	resolver := &fixtureResolver{responses: []Response{answer(a("orders.internal", "10.2.3.4", time.Minute))}}
	s := NewScheduler(store, resolver, SchedulerConfig{Batch: 1})
	s.now = func() time.Time { return now }
	s.Tick(context.Background())
	if resolver.got != selected {
		t.Fatalf("lookup context = %#v, want server-selected %#v", resolver.got, selected)
	}
	if len(store.published) != 1 || !store.published[0].RefreshAt.Equal(now.Add(store.published[0].TTL*RefreshAt/100)) {
		t.Fatalf("publication = %#v", store.published)
	}
}

func TestSchedulerWithdrawsEveryResolverFailureAndNeverPublishesLastGood(t *testing.T) {
	cases := []struct {
		name     string
		resolver *fixtureResolver
		want     WithdrawalCause
	}{
		{"timeout", &fixtureResolver{err: errors.New("down")}, WithdrawalTimeout},
		{"nxdomain", &fixtureResolver{responses: []Response{{Status: StatusNXDOMAIN}}}, WithdrawalNXDOMAIN},
		{"servfail", &fixtureResolver{responses: []Response{{Status: StatusSERVFAIL}}}, WithdrawalSERVFAIL},
		{"unusable", &fixtureResolver{responses: []Response{answer(a("db.internal", "127.0.0.1", time.Minute))}}, WithdrawalInvalidAnswer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{work: []Work{work("db.internal")}}
			s := NewScheduler(store, tc.resolver, SchedulerConfig{})
			s.Tick(context.Background())
			if len(store.published) != 0 || len(store.withdrawn) != 1 || store.withdrawn[0] != tc.want {
				t.Fatalf("published=%d withdrawals=%v", len(store.published), store.withdrawn)
			}
		})
	}
}

func TestSchedulerBoundsEachSweepAndCoalescesConcurrentTicks(t *testing.T) {
	release := make(chan struct{})
	store := &memoryStore{work: []Work{work("one.internal"), work("two.internal")}, entered: make(chan struct{}, 1), block: release}
	resolver := &fixtureResolver{responses: []Response{answer(a("one.internal", "10.2.3.4", time.Minute))}}
	s := NewScheduler(store, resolver, SchedulerConfig{Batch: 1})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.Tick(context.Background()) }()
	<-store.entered
	// This call overlaps the blocked Due call, so it must be coalesced rather
	// than starting a second writer. The database CAS handles separate processes.
	s.Tick(context.Background())
	close(release)
	wg.Wait()
	if len(store.published) != 1 {
		t.Fatalf("concurrent ticks exceeded one bounded sweep: %d", len(store.published))
	}
}

func TestSchedulerHasNoFallbackWhenTransportIsAbsent(t *testing.T) {
	store := &memoryStore{work: []Work{work("orders.internal")}}
	NewScheduler(store, nil, SchedulerConfig{}).Tick(context.Background())
	if store.dueCalls != 0 || len(store.published) != 0 || len(store.withdrawn) != 0 {
		t.Fatalf("nil transport must do no DNS work: %#v", store)
	}
}
