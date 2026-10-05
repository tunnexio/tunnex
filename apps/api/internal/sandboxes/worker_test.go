package sandboxes

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"testing"
)

type workerStore struct {
	batches [][]uuid.UUID
	after   []uuid.UUID
	work    []uuid.UUID
	failure error
	onWork  func()
}

func (s *workerStore) PendingCleanupAfter(_ context.Context, limit int, after uuid.UUID) ([]uuid.UUID, error) {
	if limit != 100 {
		panic("unbounded batch")
	}
	s.after = append(s.after, after)
	if len(s.batches) == 0 {
		return nil, nil
	}
	ids := s.batches[0]
	s.batches = s.batches[1:]
	return ids, nil
}
func (s *workerStore) ReconcileCleanup(_ context.Context, id uuid.UUID, _ sandboxruntime.Provider, _ CleanupNetwork) error {
	s.work = append(s.work, id)
	if s.onWork != nil {
		s.onWork()
	}
	return s.failure
}
func TestCleanupWorkerDormantAndFairRetry(t *testing.T) {
	s := &workerStore{}
	w := NewCleanupWorker(s, nil, nil)
	for range 100 {
		w.Wake()
	}
	if err := w.Run(context.Background(), nil); err != ErrDisabled || len(s.after) != 0 {
		t.Fatal("dormant worker performed work", err)
	}
	ids := make([]uuid.UUID, 100)
	for i := range ids {
		ids[i] = uuid.New()
	}
	last := uuid.New()
	s = &workerStore{batches: [][]uuid.UUID{ids, {last}}, failure: ErrConflict}
	w = NewCleanupWorker(s, &cleanupProvider{}, cleanupNetworkFunc(func(context.Context, Sandbox) (Withdrawal, error) { return Withdrawal{}, nil }))
	reports := 0
	report := func(uuid.UUID, error) { reports++ }
	w.batch(context.Background(), report)
	w.batch(context.Background(), report)
	if len(s.work) != 101 || reports != 101 || s.after[1] != ids[99] || w.cursor != uuid.Nil {
		t.Fatal("failed early items starved later work")
	}
}
func TestCleanupWorkerCancellationAndStartupScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &workerStore{batches: [][]uuid.UUID{{uuid.New(), uuid.New()}}, onWork: cancel}
	w := NewCleanupWorker(s, &cleanupProvider{}, cleanupNetworkFunc(func(context.Context, Sandbox) (Withdrawal, error) { return Withdrawal{}, nil }))
	if err := w.Run(ctx, nil); !errors.Is(err, context.Canceled) || len(s.work) != 1 {
		t.Fatal("startup/cancellation failed", err)
	}
}
