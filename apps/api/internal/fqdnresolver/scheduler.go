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
// refreshDeadlineStore is optional so existing storage implementations retain
// their heartbeat behavior. It never dispatches work before Store.Due admits it.
type refreshDeadlineStore interface {
	NextRefreshAt(context.Context) (time.Time, error)
}

const schedulerWakeFloor = 250 * time.Millisecond

func (s *Scheduler) nextWake(ctx context.Context) time.Duration {
	delay := s.interval
	if ctx.Err() != nil || (s.mayTick != nil && !s.mayTick()) {
		return delay
	}
	if store, ok := s.store.(refreshDeadlineStore); ok {
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		at, err := store.NextRefreshAt(readCtx)
		cancel()
		if err == nil && !at.IsZero() {
			until := at.Sub(s.now())
			if until < delay {
				delay = until
			}
		}
	}
	if delay < schedulerWakeFloor {
		delay = schedulerWakeFloor
	}
	return delay
}

func (s *Scheduler) Start(ctx context.Context, reconnect <-chan struct{}) {
	s.Tick(ctx)
	go func() {
		timer := time.NewTimer(s.nextWake(ctx))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.Tick(ctx)
				timer.Reset(s.nextWake(ctx))
			case _, ok := <-reconnect:
				// A closed reconnect source is a completed notification stream, not
				// a request for an unbounded busy-loop of resolver writes.
				if !ok {
					reconnect = nil
					continue
				}
				s.Tick(ctx)
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.nextWake(ctx))
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
	// A selected gateway has at most two DNS RPCs in flight, and the entire
	// sweep has at most four. Work retains the store's deadline priority.
	type gatewayKey struct{ org, gateway string }
	key := func(w Work) gatewayKey { return gatewayKey{w.OrgID.String(), w.Context.GatewayID} }
	active := map[gatewayKey]int{}
	done := make(chan gatewayKey, 4)
	pending := append([]Work(nil), work...)
	running := 0
	for len(pending) > 0 || running > 0 {
		if ctx.Err() != nil {
			pending = nil
		}
		for running < 4 && len(pending) > 0 {
			if ctx.Err() != nil || (s.mayTick != nil && !s.mayTick()) {
				pending = nil
				break
			}
			index := -1
			for i, w := range pending {
				if active[key(w)] < 2 {
					index = i
					break
				}
			}
			if index < 0 {
				break
			}
			w := pending[index]
			pending = append(pending[:index], pending[index+1:]...)
			k := key(w)
			active[k]++
			running++
			go func() { defer func() { done <- k }(); s.refresh(ctx, s.now(), w) }()
		}
		if running == 0 {
			break
		}
		k := <-done
		active[k]--
		running--
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
