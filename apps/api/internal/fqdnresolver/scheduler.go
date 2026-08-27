package fqdnresolver

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Scheduler owns retries and refresh timing. Resolver is intentionally the only
// transport it accepts: there is no optional net.DefaultResolver path.
type Scheduler struct {
	store             Store
	resolver          Resolver
	now               func() time.Time
	interval, timeout time.Duration
	batch             int
	mayTick           func() bool
	mu                sync.Mutex
	running           bool
}

type SchedulerConfig struct {
	Interval time.Duration
	Timeout  time.Duration
	Batch    int
	MayTick  func() bool
}

func NewScheduler(store Store, resolver Resolver, cfg SchedulerConfig) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 32
	}
	return &Scheduler{store: store, resolver: resolver, now: time.Now, interval: cfg.Interval, timeout: cfg.Timeout, batch: cfg.Batch, mayTick: cfg.MayTick}
}

// Start performs a bounded startup sweep and then bounded periodic/reconnect
// sweeps. A busy scheduler coalesces a signal rather than starting concurrent
// writers; database CAS remains the cross-process protection.
func (s *Scheduler) Start(ctx context.Context, reconnect <-chan struct{}) {
	s.Tick(ctx)
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Tick(ctx)
			case _, ok := <-reconnect:
				// A closed reconnect source is a completed notification stream, not
				// a request for an unbounded busy-loop of resolver writes.
				if !ok {
					reconnect = nil
					continue
				}
				s.Tick(ctx)
			}
		}
	}()
}

func (s *Scheduler) Tick(ctx context.Context) {
	if s.store == nil || s.resolver == nil {
		return
	}
	if s.mayTick != nil && !s.mayTick() {
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	now := s.now()
	work, err := s.store.Due(ctx, now, s.batch)
	if err != nil {
		return
	}
	for _, w := range work {
		s.refresh(ctx, now, w)
	}
}

func (s *Scheduler) refresh(parent context.Context, now time.Time, w Work) {
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	// A fresh lifecycle never reads or republishes last-good state. The store
	// retains it only in closed historical rows for diagnostics.
	var l Lifecycle
	resolver := s.resolver
	if scoped, ok := s.resolver.(WorkResolver); ok {
		resolver = resolverFunc(func(ctx context.Context, _ Context, _ string) ([]Response, error) {
			return scoped.LookupWork(ctx, w)
		})
	}
	snapshot := l.Refresh(ctx, now, resolver, w.Context, w.Hostname)
	if snapshot.Active != nil {
		_ = s.store.Publish(parent, w, *snapshot.Active)
		return
	}
	if snapshot.Withdrawal != nil {
		// The persisted failure vocabulary is exactly the D4 decision set. Bad
		// wire answers and an absent transport are resolver failures too, but do
		// not get to extend that durable/public contract.
		cause := d4Cause(snapshot.Withdrawal.Cause)
		if err := s.store.Withdraw(parent, w, cause, now); err != nil && !errors.Is(err, ErrSuperseded) {
			return
		}
	}
}

type resolverFunc func(context.Context, Context, string) ([]Response, error)

func (f resolverFunc) Lookup(ctx context.Context, selected Context, hostname string) ([]Response, error) {
	return f(ctx, selected, hostname)
}

func d4Cause(c WithdrawalCause) WithdrawalCause {
	if approvedWithdrawalCause(c) {
		return c
	}
	return WithdrawalSERVFAIL
}
