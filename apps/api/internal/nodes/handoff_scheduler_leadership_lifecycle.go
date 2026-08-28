package nodes

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

// HandoffSchedulerLeaderProbe is the lifecycle precondition for running an
// already-constructed scheduler loop. It is deliberately distinct from the
// scheduler's per-call leader-session fence: this controller bounds process
// lifetime, while the fenced coordinator remains the authorization for every
// P2 delivery and durable mutation.
type HandoffSchedulerLeaderProbe interface {
	ConfirmHandoffSchedulerLeader(context.Context) bool
}

// HandoffSchedulerLifecycleActivation is the minimal lifecycle ownership
// boundary. Production composition passes *HandoffSchedulerActivation; the
// interface also lets integration tests prove leader lifecycle behavior with an
// inert loop, without pretending to implement P2 delivery or attestation.
type HandoffSchedulerLifecycleActivation interface {
	Status() HandoffSchedulerFeatureStatus
	Start(context.Context) HandoffSchedulerFeatureStatus
	Stop(context.Context) error
	Running() bool
}

// PostgresHandoffSchedulerLeaderProbe binds this lifecycle to the existing
// dedicated-session leader election. ConfirmLeader asks PostgreSQL about the
// exact lock holder; a process-local leader bit is never enough to start work.
type PostgresHandoffSchedulerLeaderProbe struct {
	Elector *leader.Elector
	Pool    *pgxpool.Pool
}

func (p PostgresHandoffSchedulerLeaderProbe) ConfirmHandoffSchedulerLeader(ctx context.Context) bool {
	return p.Elector != nil && p.Pool != nil && p.Elector.ConfirmLeader(ctx, p.Pool)
}

// HandoffSchedulerLeadershipTiming is intentionally validated, not repaired.
// It bounds how long a locally running scheduler can outlive a lost leader
// observation. The scheduler itself independently fences each source read and
// mutation on the exact advisory-lock session, closing the interval between
// lifecycle probes.
type HandoffSchedulerLeadershipTiming struct {
	ProbeInterval time.Duration
	StopTimeout   time.Duration
}

const (
	minHandoffSchedulerLeaderProbeInterval = 100 * time.Millisecond
	maxHandoffSchedulerLeaderProbeInterval = 10 * time.Second
	minHandoffSchedulerStopTimeout         = 100 * time.Millisecond
	maxHandoffSchedulerStopTimeout         = 30 * time.Second
)

func (t HandoffSchedulerLeadershipTiming) valid() bool {
	return t.ProbeInterval >= minHandoffSchedulerLeaderProbeInterval &&
		t.ProbeInterval <= maxHandoffSchedulerLeaderProbeInterval &&
		t.StopTimeout >= minHandoffSchedulerStopTimeout &&
		t.StopTimeout <= maxHandoffSchedulerStopTimeout
}

// HandoffSchedulerLeaderLifecycleConfig is a composition-root-only contract.
// Enabled defaults false at the future call site. It does not read env, start
// leader election, or provide a partial P2 dependency; the activation passed
// here must already be ready from real durable CP/P2 dependencies.
type HandoffSchedulerLeaderLifecycleConfig struct {
	Enabled    bool
	Activation HandoffSchedulerLifecycleActivation
	Leader     HandoffSchedulerLeaderProbe
	Timing     HandoffSchedulerLeadershipTiming
}

// handoffSchedulerLeadershipClock keeps lifecycle tests deterministic without
// making production depend on a ticker goroutine.
type handoffSchedulerLeadershipClock interface {
	After(time.Duration) <-chan time.Time
}

type realHandoffSchedulerLeadershipClock struct{}

func (realHandoffSchedulerLeadershipClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

// HandoffSchedulerLeaderLifecycle starts at most one local scheduler loop,
// and only for confirmed advisory-lock leadership. On leadership loss it
// cancels and waits for the loop before it will ever start it again. It is not
// registered by main in this slice.
type HandoffSchedulerLeaderLifecycle struct {
	mu         sync.Mutex
	status     HandoffSchedulerFeatureStatus
	activation HandoffSchedulerLifecycleActivation
	leader     HandoffSchedulerLeaderProbe
	timing     HandoffSchedulerLeadershipTiming
	clock      handoffSchedulerLeadershipClock
	cancel     context.CancelFunc
	done       chan struct{}
}

func NewHandoffSchedulerLeaderLifecycle(config HandoffSchedulerLeaderLifecycleConfig) *HandoffSchedulerLeaderLifecycle {
	lifecycle := &HandoffSchedulerLeaderLifecycle{clock: realHandoffSchedulerLeadershipClock{}}
	if !config.Enabled {
		lifecycle.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerDisabled}
		return lifecycle
	}
	if !handoffActivationDependencyPresent(config.Activation) {
		lifecycle.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
		return lifecycle
	}
	if status := config.Activation.Status(); status.State != HandoffSchedulerReady {
		lifecycle.status = status
		return lifecycle
	}
	if !handoffActivationDependencyPresent(config.Leader) {
		lifecycle.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerLeaderElectorMissing}}
		return lifecycle
	}
	if !config.Timing.valid() {
		lifecycle.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerTimingInvalid}}
		return lifecycle
	}
	lifecycle.activation = config.Activation
	lifecycle.leader = config.Leader
	lifecycle.timing = config.Timing
	lifecycle.status = HandoffSchedulerFeatureStatus{State: HandoffSchedulerReady}
	return lifecycle
}

func (l *HandoffSchedulerLeaderLifecycle) Status() HandoffSchedulerFeatureStatus {
	if l == nil {
		return HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status.copy()
}

// Start is idempotent. Disabled/blocked lifecycles create no goroutine and do
// not ask the leader probe (and therefore cannot cause DB/P2 work indirectly).
func (l *HandoffSchedulerLeaderLifecycle) Start(parent context.Context) HandoffSchedulerFeatureStatus {
	if l == nil || parent == nil {
		return HandoffSchedulerFeatureStatus{State: HandoffSchedulerBlocked, Reasons: []HandoffSchedulerBlockReason{HandoffSchedulerConstructionFailed}}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status.State != HandoffSchedulerReady || l.done != nil || parent.Err() != nil {
		return l.status.copy()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	l.cancel, l.done = cancel, done
	go func() {
		defer close(done)
		defer func() {
			l.mu.Lock()
			if l.done == done {
				l.cancel, l.done = nil, nil
			}
			l.mu.Unlock()
		}()
		l.run(ctx)
	}()
	return l.status.copy()
}

func (l *HandoffSchedulerLeaderLifecycle) run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			l.stopScheduler()
			return
		}
		if l.leader.ConfirmHandoffSchedulerLeader(ctx) {
			if !l.activation.Running() {
				l.activation.Start(ctx)
			}
		} else if l.activation.Running() {
			l.stopScheduler()
		}

		select {
		case <-ctx.Done():
			l.stopScheduler()
			return
		case <-l.clock.After(l.timing.ProbeInterval):
		}
	}
}

// stopScheduler waits only for the explicit bound. A timed-out stop remains
// safe: activation will not start a second loop while the first has not exited.
func (l *HandoffSchedulerLeaderLifecycle) stopScheduler() {
	if l.activation == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.timing.StopTimeout)
	defer cancel()
	_ = l.activation.Stop(ctx)
}

// Stop is safe before Start and waits for the lifecycle and its child scheduler
// loop to exit. It is intended for the API shutdown path once this remains a
// composition-root opt-in.
func (l *HandoffSchedulerLeaderLifecycle) Stop(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	cancel, done := l.cancel, l.done
	l.mu.Unlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
