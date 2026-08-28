package k8s

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

// HandoffTickSource is the CP-only read seam for this adapter. It supplies
// current node evidence and already-validated P2 handoff prerequisites; it is
// not an HTTP/report/agent transport and does not make any state change.
type HandoffTickSource interface {
	HandoffRequests(context.Context, time.Time) ([]HandoffCoordinatorRequest, error)
}

// HandoffLeaderBoundTickSource is required by PostgreSQL-backed sources that
// persist CP-owned observation history while deriving a fresh handoff intent.
// The exact lock-holding connection is passed through so the source can bind
// its own write transaction to the same advisory-lock session. Pure/read-only
// test sources may implement only HandoffTickSource.
type HandoffLeaderBoundTickSource interface {
	HandoffRequestsWithLeadership(context.Context, time.Time, HandoffLeadershipEpoch, *pgxpool.Conn) ([]HandoffCoordinatorRequest, error)
}

// HandoffTickRunner is implemented by HandoffCoordinator. It is an interface
// solely to make scheduler timing/fencing deterministic in tests.
type HandoffTickRunner interface {
	Tick(context.Context, HandoffCoordinatorRequest) (HandoffCoordinatorResult, error)
}

// HandoffLeadershipEpoch identifies the exact PostgreSQL backend session that
// held scheduler leadership. It is CP-only provenance, never agent input. A
// fenced coordinator carries the session itself through durable mutations,
// whose SQL checks this backend PID in the statement that writes state.
type HandoffLeadershipEpoch struct {
	BackendPID int32
	LockKey    int64
}

func (e HandoffLeadershipEpoch) valid() bool { return e.BackendPID > 0 && e.LockKey != 0 }

// HandoffFencedTickRunner is mandatory for scheduler execution. It receives
// the authoritative session epoch so external delivery is provenance-bound and
// the coordinator can make phase/CAS writes fail closed if that session lost
// its advisory lock after scheduler confirmation.
type HandoffFencedTickRunner interface {
	TickWithLeadership(context.Context, HandoffCoordinatorRequest, HandoffLeadershipEpoch, *pgxpool.Conn) (HandoffCoordinatorResult, error)
}

// HandoffLeaderFence must return an epoch from authoritative ownership, never
// a stale process-local boolean. A false or errored confirmation means no
// read-derived decision, transport delivery, or CAS may run this tick.
type HandoffLeaderFence interface {
	AcquireEpoch(context.Context) (HandoffLeadershipEpoch, bool)
	WithEpoch(context.Context, HandoffLeadershipEpoch, func(*pgxpool.Conn) error) (bool, error)
}

// LeaderHandoffFence adapts the existing dedicated-session PostgreSQL leader
// elector. WithEpoch rechecks pg_locks on the exact lock-holding session and
// serializes the bounded callback with that session's ping/unlock, so a stale
// leader bit cannot authorize an HA handoff write.
type LeaderHandoffFence struct {
	Elector *leader.Elector
	Pool    *pgxpool.Pool
}

func (f LeaderHandoffFence) AcquireEpoch(ctx context.Context) (HandoffLeadershipEpoch, bool) {
	if f.Elector == nil || f.Pool == nil {
		return HandoffLeadershipEpoch{}, false
	}
	pid, held := f.Elector.ConfirmLeaderEpoch(ctx, f.Pool)
	if !held {
		return HandoffLeadershipEpoch{}, false
	}
	return HandoffLeadershipEpoch{BackendPID: pid, LockKey: leader.SchedulerLockKey}, true
}

func (f LeaderHandoffFence) WithEpoch(ctx context.Context, epoch HandoffLeadershipEpoch, fn func(*pgxpool.Conn) error) (bool, error) {
	if f.Elector == nil || !epoch.valid() {
		return false, nil
	}
	return f.Elector.WithLeaderSession(ctx, epoch.BackendPID, fn)
}

// HandoffSchedulerClock is injected so cadence/backoff and cancellation tests
// never sleep. The production clock is intentionally tiny and has no hidden
// goroutine or ticker state.
type HandoffSchedulerClock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realHandoffSchedulerClock struct{}

func (realHandoffSchedulerClock) Now() time.Time { return time.Now().UTC() }
func (realHandoffSchedulerClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

type HandoffSchedulerConfig struct {
	Cadence         time.Duration
	MaxBackoff      time.Duration
	PerTickTimeout  time.Duration
	SerialBatchSize int
}

const (
	defaultHandoffCadence     = 5 * time.Second
	defaultHandoffBackoff     = time.Minute
	defaultHandoffTickTimeout = 4 * time.Second
	defaultHandoffSerialBatch = 32
)

func (c HandoffSchedulerConfig) normalized() HandoffSchedulerConfig {
	if c.Cadence <= 0 {
		c.Cadence = defaultHandoffCadence
	}
	if c.MaxBackoff < c.Cadence {
		c.MaxBackoff = defaultHandoffBackoff
		if c.MaxBackoff < c.Cadence {
			c.MaxBackoff = c.Cadence
		}
	}
	if c.PerTickTimeout <= 0 {
		c.PerTickTimeout = defaultHandoffTickTimeout
	}
	if c.SerialBatchSize <= 0 {
		c.SerialBatchSize = defaultHandoffSerialBatch
	}
	return c
}

// HandoffScheduler is an explicit local run-loop adapter. It is NOT wired into
// main, has no transport implementation, and starts no work until Run is
// called. The durable coordinator/DB CAS remains the final fencing layer.
type HandoffScheduler struct {
	source HandoffTickSource
	runner HandoffTickRunner
	fence  HandoffLeaderFence
	clock  HandoffSchedulerClock
	config HandoffSchedulerConfig

	mu       sync.Mutex
	inFlight map[handoffScheduleKey]bool
}

type handoffScheduleKey struct{ org, site, pool uuid.UUID }

type HandoffSchedulerResult struct {
	Follower         bool
	SourceError      error
	RunnerError      error
	Attempted        int
	SkippedEvidence  int
	SkippedDuplicate int
}

// ErrHandoffSchedulerCallbackPanicked is deliberately content-free: an
// injected source or coordinator panic must fail closed and back off without
// exposing implementation or untrusted data through scheduler diagnostics.
var ErrHandoffSchedulerCallbackPanicked = errors.New("handoff scheduler callback panicked")

func NewHandoffScheduler(source HandoffTickSource, runner HandoffTickRunner, fence HandoffLeaderFence, config HandoffSchedulerConfig) *HandoffScheduler {
	return &HandoffScheduler{
		source:   source,
		runner:   runner,
		fence:    fence,
		clock:    realHandoffSchedulerClock{},
		config:   config.normalized(),
		inFlight: map[handoffScheduleKey]bool{},
	}
}

// Tick performs one bounded local reconciliation pass. Leadership is confirmed
// before the source read. Each runner call then executes under the exact
// lock-holding session after that session rechecks its own advisory lock. The
// runner carries that session into durable SQL predicates, so a
// confirmed-then-lost advisory session cannot advance a phase or CAS a pool.
func (s *HandoffScheduler) Tick(ctx context.Context) HandoffSchedulerResult {
	if s == nil || s.source == nil || s.runner == nil || s.fence == nil {
		return HandoffSchedulerResult{Follower: true}
	}
	epoch, leading := s.fence.AcquireEpoch(ctx)
	if !leading || !epoch.valid() {
		return HandoffSchedulerResult{Follower: true}
	}
	fencedRunner, ok := s.runner.(HandoffFencedTickRunner)
	if !ok {
		return HandoffSchedulerResult{RunnerError: ErrHandoffLeadershipUnavailable}
	}
	now := s.clock.Now()
	readCtx, cancel := context.WithTimeout(ctx, s.config.PerTickTimeout)
	var reqs []HandoffCoordinatorRequest
	var sourceErr error
	// The durable PostgreSQL source may atomically advance CP-owned health
	// history while deriving requests. Keep that work inside the exact
	// leader-session callback too: a loss between AcquireEpoch and the source
	// call must perform neither a source read nor an observation write.
	held, fenceErr := s.fence.WithEpoch(readCtx, epoch, func(conn *pgxpool.Conn) error {
		return recoverHandoffSchedulerCallback(func() error {
			if bound, ok := s.source.(HandoffLeaderBoundTickSource); ok {
				reqs, sourceErr = bound.HandoffRequestsWithLeadership(readCtx, now, epoch, conn)
			} else {
				reqs, sourceErr = s.source.HandoffRequests(readCtx, now)
			}
			return sourceErr
		})
	})
	cancel()
	if !held {
		return HandoffSchedulerResult{Follower: true}
	}
	if sourceErr != nil {
		return HandoffSchedulerResult{SourceError: sourceErr}
	}
	if fenceErr != nil {
		return HandoffSchedulerResult{SourceError: fenceErr}
	}
	result := HandoffSchedulerResult{}
	if len(reqs) > s.config.SerialBatchSize {
		reqs = reqs[:s.config.SerialBatchSize]
	}
	for _, req := range reqs {
		if ctx.Err() != nil {
			result.RunnerError = ctx.Err()
			return result
		}
		req.Now = now // the scheduler's CP clock is authoritative for this tick.
		if !schedulerCandidateHealthy(req) {
			result.SkippedEvidence++
			continue
		}
		key := handoffScheduleKey{org: req.Plan.Plan.Scope.OrgID, site: req.Plan.Plan.Scope.SiteID, pool: req.Plan.Plan.Scope.PoolID}
		if !s.claim(key) {
			result.SkippedDuplicate++
			continue
		}
		func() {
			defer s.release(key)
			callCtx, cancel := context.WithTimeout(ctx, s.config.PerTickTimeout)
			defer cancel()
			held, fenceErr := s.fence.WithEpoch(callCtx, epoch, func(conn *pgxpool.Conn) error {
				return recoverHandoffSchedulerCallback(func() error {
					_, err := fencedRunner.TickWithLeadership(callCtx, req, epoch, conn)
					return err
				})
			})
			if !held {
				result.Follower = true
				return
			}
			if fenceErr != nil && result.RunnerError == nil {
				result.RunnerError = fenceErr
			}
			result.Attempted++
		}()
		if result.Follower {
			return result
		}
		if result.RunnerError != nil {
			return result
		}
	}
	return result
}

// Run waits one cadence before the first pass (boot must not manufacture a
// health tick), doubles only after a source/runner error, and exits promptly
// when ctx is cancelled. Followers retain normal cadence; leadership loss is
// a safe no-write condition, not an error backoff storm.
func (s *HandoffScheduler) Run(ctx context.Context) {
	if s == nil {
		return
	}
	delay := s.config.Cadence
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(delay):
		}
		result := s.Tick(ctx)
		if result.SourceError != nil || result.RunnerError != nil {
			delay *= 2
			if delay > s.config.MaxBackoff {
				delay = s.config.MaxBackoff
			}
		} else {
			delay = s.config.Cadence
		}
	}
}

func (s *HandoffScheduler) claim(key handoffScheduleKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight[key] {
		return false
	}
	s.inFlight[key] = true
	return true
}

func (s *HandoffScheduler) release(key handoffScheduleKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, key)
}

func recoverHandoffSchedulerCallback(fn func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrHandoffSchedulerCallbackPanicked
		}
	}()
	return fn()
}

// schedulerCandidateHealthy is the adapter's explicit fail-closed boundary.
// An absent/old-agent/malformed candidate report cannot cause preparation,
// withdrawal, CAS, or serving delivery. A stale active report is still valid
// input to the pure model as an unhealthy active; only the target must be
// currently dual-signal healthy before this scheduler touches a handoff.
func schedulerCandidateHealthy(req HandoffCoordinatorRequest) bool {
	p := req.Plan.Plan
	evidence, ok := req.Evidence[p.CandidateID]
	if !ok {
		return false
	}
	_, health := AdaptConnectorEvidence(req.Now, req.ReportFreshness, p.Scope.OrgID.String(), p.Scope.SiteID.String(), evidence)
	return health.Healthy()
}
