package sandboxes

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"time"
)

type cleanupStore interface {
	PendingCleanupAfter(context.Context, int, uuid.UUID) ([]uuid.UUID, error)
	ReconcileCleanup(context.Context, uuid.UUID, sandboxruntime.Provider, CleanupNetwork) error
}

// CleanupWorker is serial and bounded. Nil qualified adapters keep it dormant;
// construction and Wake do not confer provisioning availability.
type CleanupWorker struct {
	store    cleanupStore
	provider sandboxruntime.Provider
	network  CleanupNetwork
	wake     chan struct{}
	cursor   uuid.UUID
}

func NewCleanupWorker(store cleanupStore, provider sandboxruntime.Provider, network CleanupNetwork) *CleanupWorker {
	return &CleanupWorker{store: store, provider: provider, network: network, wake: make(chan struct{}, 1)}
}
func (w *CleanupWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *CleanupWorker) Run(ctx context.Context, report func(uuid.UUID, error)) error {
	if w.store == nil || w.provider == nil || w.network == nil {
		return ErrDisabled
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		w.batch(ctx, report)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.wake:
		case <-ticker.C:
		}
	}
}
func (w *CleanupWorker) batch(ctx context.Context, report func(uuid.UUID, error)) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ids, err := w.store.PendingCleanupAfter(listCtx, 100, w.cursor)
	cancel()
	if err != nil {
		if report != nil {
			report(uuid.Nil, err)
		}
		return
	}
	if len(ids) == 0 {
		w.cursor = uuid.Nil
		return
	}
	// Advance despite a failed item so early failures cannot starve later IDs.
	// The durable per-sandbox lease fences other replicas.
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		workCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = w.store.ReconcileCleanup(workCtx, id, w.provider, w.network)
		cancel()
		w.cursor = id
		if err != nil && report != nil {
			report(id, err)
		}
	}
	if len(ids) < 100 {
		w.cursor = uuid.Nil
	}
}
