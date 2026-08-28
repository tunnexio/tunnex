package k8s

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandoffSchedulerDuplicateTickIsSuppressed(t *testing.T) {
	req := schedulerRequest(t, false)
	runner := &schedulerRunner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s := newRequestScheduler(req, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{Cadence: time.Second})
	done := make(chan struct{})
	go func() {
		s.Tick(context.Background())
		close(done)
	}()
	<-runner.entered
	duplicate := s.Tick(context.Background())
	if duplicate.Attempted != 0 || duplicate.SkippedDuplicate != 1 || runner.count() != 1 {
		t.Fatalf("duplicate tick=%+v calls=%d", duplicate, runner.count())
	}
	close(runner.release)
	<-done
}

func TestHandoffSchedulerLeaderFenceAllowsOneConcurrentScheduler(t *testing.T) {
	req := schedulerRequest(t, false)
	shared := &oneWinnerFence{}
	runner := &schedulerRunner{}
	left := newRequestScheduler(req, runner, shared, HandoffSchedulerConfig{})
	right := newRequestScheduler(req, runner, shared, HandoffSchedulerConfig{})
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan HandoffSchedulerResult, 2)
	for _, s := range []*HandoffScheduler{left, right} {
		wg.Add(1)
		go func(s *HandoffScheduler) {
			defer wg.Done()
			<-start
			results <- s.Tick(context.Background())
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	attempted, followers := 0, 0
	for r := range results {
		attempted += r.Attempted
		if r.Follower {
			followers++
		}
	}
	if attempted != 1 || followers != 1 || runner.count() != 1 {
		t.Fatalf("leader fence must permit one scheduler: attempted=%d followers=%d calls=%d", attempted, followers, runner.count())
	}
}

func TestHandoffSchedulerRestartPreservesExactOperationRequest(t *testing.T) {
	req := schedulerRequest(t, false)
	runner := &schedulerRunner{}
	first := newRequestScheduler(req, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{})
	second := newRequestScheduler(req, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{})
	if r := first.Tick(context.Background()); r.Attempted != 1 || r.RunnerError != nil {
		t.Fatalf("first tick=%+v", r)
	}
	if r := second.Tick(context.Background()); r.Attempted != 1 || r.RunnerError != nil {
		t.Fatalf("restart tick=%+v", r)
	}
	ids := runner.operationIDs()
	if len(ids) != 2 || ids[0] != req.Plan.Plan.OperationID || ids[1] != req.Plan.Plan.OperationID {
		t.Fatalf("restart changed durable operation identity: %v", ids)
	}
}

func TestHandoffSchedulerFailsClosedOnMissingOrStaleCandidateEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*HandoffCoordinatorRequest){
		"missing": func(r *HandoffCoordinatorRequest) {
			delete(r.Evidence, r.Plan.Plan.CandidateID)
		},
		"stale": func(r *HandoffCoordinatorRequest) {
			e := r.Evidence[r.Plan.Plan.CandidateID]
			e.LastSeenAt = r.Now.Add(-2 * r.ReportFreshness)
			r.Evidence[r.Plan.Plan.CandidateID] = e
		},
		"old agent endpoint view": func(r *HandoffCoordinatorRequest) {
			e := r.Evidence[r.Plan.Plan.CandidateID]
			e.K8sEndpointViewKnown = false
			r.Evidence[r.Plan.Plan.CandidateID] = e
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := schedulerRequest(t, false)
			mutate(&req)
			runner := &schedulerRunner{}
			r := newRequestScheduler(req, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{}).Tick(context.Background())
			if r.Attempted != 0 || r.SkippedEvidence != 1 || runner.count() != 0 {
				t.Fatalf("stale/missing evidence ran coordinator: result=%+v calls=%d", r, runner.count())
			}
		})
	}
}

func TestHandoffSchedulerPassesStaleActiveEvidenceToCoordinator(t *testing.T) {
	req := schedulerRequest(t, true)
	runner := &schedulerRunner{}
	r := newRequestScheduler(req, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{}).Tick(context.Background())
	if r.Attempted != 1 || r.SkippedEvidence != 0 || runner.count() != 1 {
		t.Fatalf("stale active must reach pure-model coordinator: result=%+v calls=%d", r, runner.count())
	}
	epochs := runner.leadershipEpochs()
	if len(epochs) != 1 || epochs[0] != (HandoffLeadershipEpoch{BackendPID: 1, LockKey: 1}) {
		t.Fatalf("runner did not receive the fence epoch: %v", epochs)
	}
}

func TestHandoffSchedulerLeadershipLossAfterSourceReadRunsNothing(t *testing.T) {
	req := schedulerRequest(t, false)
	fence := &lossAfterSourceFence{epoch: HandoffLeadershipEpoch{BackendPID: 42, LockKey: 99}}
	source := &schedulerSource{requests: []HandoffCoordinatorRequest{req}, after: fence.lose}
	runner := &schedulerRunner{}
	s := NewHandoffScheduler(source, runner, fence, HandoffSchedulerConfig{})
	s.clock = staticSchedulerClock{now: req.Now}
	result := s.Tick(context.Background())
	if !result.Follower || result.Attempted != 0 || runner.count() != 0 {
		t.Fatalf("leadership loss after source read must not enter runner: result=%+v calls=%d", result, runner.count())
	}
}

func TestHandoffSchedulerLeadershipLossBeforeSourceReadRunsNothing(t *testing.T) {
	req := schedulerRequest(t, false)
	source := &schedulerSource{requests: []HandoffCoordinatorRequest{req}}
	runner := &schedulerRunner{}
	s := NewHandoffScheduler(source, runner, sourceRefusingFence{}, HandoffSchedulerConfig{})
	s.clock = staticSchedulerClock{now: req.Now}
	result := s.Tick(context.Background())
	if !result.Follower || result.Attempted != 0 || source.count() != 0 || runner.count() != 0 {
		t.Fatalf("loss before fenced source read must do no source/runner work: result=%+v source=%d runner=%d", result, source.count(), runner.count())
	}
}

func TestHandoffSchedulerSourcePanicFailsClosed(t *testing.T) {
	req := schedulerRequest(t, false)
	runner := &schedulerRunner{}
	s := NewHandoffScheduler(panickingSchedulerSource{}, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{})
	s.clock = staticSchedulerClock{now: req.Now}
	result := s.Tick(context.Background())
	if !errors.Is(result.SourceError, ErrHandoffSchedulerCallbackPanicked) || result.Attempted != 0 || runner.count() != 0 {
		t.Fatalf("source panic must become a fail-closed source error: result=%+v runner=%d", result, runner.count())
	}
}

func TestHandoffSchedulerRunnerPanicFailsClosed(t *testing.T) {
	req := schedulerRequest(t, false)
	runner := panickingSchedulerRunner{}
	s := newRequestScheduler(req, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{})
	result := s.Tick(context.Background())
	if !errors.Is(result.RunnerError, ErrHandoffSchedulerCallbackPanicked) || result.Attempted != 1 {
		t.Fatalf("runner panic must become a fail-closed runner error: result=%+v", result)
	}
}

func TestHandoffSchedulerNormalizesBackoffBound(t *testing.T) {
	s := NewHandoffScheduler(nil, nil, nil, HandoffSchedulerConfig{Cadence: 2 * time.Minute, MaxBackoff: time.Second})
	if s.config.MaxBackoff != 2*time.Minute {
		t.Fatalf("max backoff %s is below cadence", s.config.MaxBackoff)
	}
}

func TestHandoffSchedulerRunBacksOffAndCancelsGracefully(t *testing.T) {
	clock := newManualSchedulerClock(time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC))
	source := &schedulerSource{err: errors.New("CP read unavailable")}
	s := NewHandoffScheduler(source, &schedulerRunner{}, schedulerFence{leader: true}, HandoffSchedulerConfig{Cadence: time.Second, MaxBackoff: 4 * time.Second})
	s.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	if d := <-clock.delays; d != time.Second {
		t.Fatalf("first cadence=%s", d)
	}
	clock.tick()
	if d := <-clock.delays; d != 2*time.Second {
		t.Fatalf("error backoff=%s", d)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestHandoffSchedulerCancellationReachesRunner(t *testing.T) {
	clock := newManualSchedulerClock(time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC))
	runner := &schedulerRunner{entered: make(chan struct{}, 1), waitContext: true}
	s := NewHandoffScheduler(&schedulerSource{requests: []HandoffCoordinatorRequest{schedulerRequest(t, false)}}, runner, schedulerFence{leader: true}, HandoffSchedulerConfig{Cadence: time.Second, PerTickTimeout: time.Minute})
	s.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	<-clock.delays
	clock.tick()
	<-runner.entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop the in-flight tick")
	}
}

func TestHandoffSchedulerCancellationReachesSource(t *testing.T) {
	clock := newManualSchedulerClock(time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC))
	source := &waitingSchedulerSource{entered: make(chan struct{}, 1)}
	s := NewHandoffScheduler(source, &schedulerRunner{}, schedulerFence{leader: true}, HandoffSchedulerConfig{Cadence: time.Second, PerTickTimeout: time.Minute})
	s.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	<-clock.delays
	clock.tick()
	<-source.entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop the in-flight CP read")
	}
}

func schedulerRequest(t *testing.T, activeStale bool) HandoffCoordinatorRequest {
	t.Helper()
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	org, site, pool, cluster, old, candidate := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	scope := HandoffPoolScope{OrgID: org, SiteID: site, PoolID: pool, ClusterID: cluster}
	plan := HandoffPlan{OperationID: uuid.New(), Scope: scope, ExpectedActiveID: old, CandidateID: candidate, ExpectedGeneration: 1, TargetGeneration: 2,
		Decision:      Decision{Transition: Promoted, FromID: old.String(), ToID: candidate.String(), Pool: ConnectorPool{ActiveID: candidate.String(), Generation: 2}},
		OldServing:    coordinatorArtifact(scope, old, 1, 1, 1, Serving, "old", now.Add(time.Minute)),
		NewPrepared:   coordinatorArtifact(scope, candidate, 2, 2, 2, PreparedNonServing, "prepared", now.Add(2*time.Minute)),
		OldWithdrawal: coordinatorArtifact(scope, old, 2, 2, 2, PreparedNonServing, "withdraw", now.Add(2*time.Minute)),
		NewServing:    coordinatorArtifact(scope, candidate, 2, 3, 2, Serving, "serve", now.Add(2*time.Minute)),
	}
	seen := now
	if activeStale {
		seen = now.Add(-2 * time.Minute)
	}
	return HandoffCoordinatorRequest{Plan: DurableHandoffPlan{Plan: plan, OldLeaseIdentity: "old", TargetLeaseIdentity: "target"}, Now: now, ReportFreshness: time.Minute, MaxAckAge: time.Minute, ClockSkewMargin: time.Second,
		Evidence: map[uuid.UUID]ConnectorEvidence{old: coordinatorEvidence(old, org, site, seen, now), candidate: coordinatorEvidence(candidate, org, site, now, now)}}
}

func newRequestScheduler(req HandoffCoordinatorRequest, runner HandoffTickRunner, fence HandoffLeaderFence, config HandoffSchedulerConfig) *HandoffScheduler {
	s := NewHandoffScheduler(&schedulerSource{requests: []HandoffCoordinatorRequest{req}}, runner, fence, config)
	s.clock = staticSchedulerClock{now: req.Now}
	return s
}

type schedulerSource struct {
	requests []HandoffCoordinatorRequest
	err      error
	after    func()
	mu       sync.Mutex
	calls    int
}

type panickingSchedulerSource struct{}

func (panickingSchedulerSource) HandoffRequests(context.Context, time.Time) ([]HandoffCoordinatorRequest, error) {
	panic("source panic")
}

type waitingSchedulerSource struct{ entered chan struct{} }

func (s *waitingSchedulerSource) HandoffRequests(ctx context.Context, _ time.Time) ([]HandoffCoordinatorRequest, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *schedulerSource) HandoffRequests(_ context.Context, _ time.Time) ([]HandoffCoordinatorRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.after != nil {
		s.after()
	}
	return s.requests, s.err
}

func (s *schedulerSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type schedulerRunner struct {
	mu          sync.Mutex
	calls       []HandoffCoordinatorRequest
	epochs      []HandoffLeadershipEpoch
	entered     chan struct{}
	release     chan struct{}
	waitContext bool
}

type panickingSchedulerRunner struct{}

func (panickingSchedulerRunner) Tick(context.Context, HandoffCoordinatorRequest) (HandoffCoordinatorResult, error) {
	panic("runner panic")
}

func (panickingSchedulerRunner) TickWithLeadership(context.Context, HandoffCoordinatorRequest, HandoffLeadershipEpoch, *pgxpool.Conn) (HandoffCoordinatorResult, error) {
	panic("runner panic")
}

func (r *schedulerRunner) TickWithLeadership(ctx context.Context, req HandoffCoordinatorRequest, epoch HandoffLeadershipEpoch, _ *pgxpool.Conn) (HandoffCoordinatorResult, error) {
	r.mu.Lock()
	r.epochs = append(r.epochs, epoch)
	r.mu.Unlock()
	return r.Tick(ctx, req)
}

func (r *schedulerRunner) Tick(ctx context.Context, req HandoffCoordinatorRequest) (HandoffCoordinatorResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, req)
	r.mu.Unlock()
	if r.entered != nil {
		select {
		case r.entered <- struct{}{}:
		default:
		}
	}
	if r.waitContext {
		<-ctx.Done()
		return HandoffCoordinatorResult{}, ctx.Err()
	}
	if r.release != nil {
		<-r.release
	}
	return HandoffCoordinatorResult{OperationID: req.Plan.Plan.OperationID}, nil
}

func (r *schedulerRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *schedulerRunner) operationIDs() []uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uuid.UUID, len(r.calls))
	for i := range r.calls {
		out[i] = r.calls[i].Plan.Plan.OperationID
	}
	return out
}

func (r *schedulerRunner) leadershipEpochs() []HandoffLeadershipEpoch {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]HandoffLeadershipEpoch(nil), r.epochs...)
}

type schedulerFence struct{ leader bool }

func (f schedulerFence) AcquireEpoch(context.Context) (HandoffLeadershipEpoch, bool) {
	return HandoffLeadershipEpoch{BackendPID: 1, LockKey: 1}, f.leader
}
func (f schedulerFence) WithEpoch(_ context.Context, epoch HandoffLeadershipEpoch, fn func(*pgxpool.Conn) error) (bool, error) {
	if !f.leader || epoch != (HandoffLeadershipEpoch{BackendPID: 1, LockKey: 1}) {
		return false, nil
	}
	return true, fn(nil)
}

type oneWinnerFence struct {
	mu   sync.Mutex
	used bool
}

func (f *oneWinnerFence) AcquireEpoch(context.Context) (HandoffLeadershipEpoch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used {
		return HandoffLeadershipEpoch{}, false
	}
	f.used = true
	return HandoffLeadershipEpoch{BackendPID: 1, LockKey: 1}, true
}
func (f *oneWinnerFence) WithEpoch(_ context.Context, epoch HandoffLeadershipEpoch, fn func(*pgxpool.Conn) error) (bool, error) {
	if epoch != (HandoffLeadershipEpoch{BackendPID: 1, LockKey: 1}) {
		return false, nil
	}
	return true, fn(nil)
}

type lossAfterSourceFence struct {
	mu    sync.Mutex
	epoch HandoffLeadershipEpoch
	lost  bool
}

func (f *lossAfterSourceFence) AcquireEpoch(context.Context) (HandoffLeadershipEpoch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epoch, !f.lost
}

func (f *lossAfterSourceFence) WithEpoch(_ context.Context, epoch HandoffLeadershipEpoch, fn func(*pgxpool.Conn) error) (bool, error) {
	f.mu.Lock()
	if f.lost || epoch != f.epoch {
		f.mu.Unlock()
		return false, nil
	}
	f.mu.Unlock()
	return true, fn(nil)
}

func (f *lossAfterSourceFence) lose() {
	f.mu.Lock()
	f.lost = true
	f.mu.Unlock()
}

// sourceRefusingFence models a leader session that disappears after the cheap
// epoch read but before the callback begins. The source must not be touched.
type sourceRefusingFence struct{}

func (sourceRefusingFence) AcquireEpoch(context.Context) (HandoffLeadershipEpoch, bool) {
	return HandoffLeadershipEpoch{BackendPID: 1, LockKey: 1}, true
}
func (sourceRefusingFence) WithEpoch(context.Context, HandoffLeadershipEpoch, func(*pgxpool.Conn) error) (bool, error) {
	return false, nil
}

type manualSchedulerClock struct {
	now    time.Time
	ticks  chan time.Time
	delays chan time.Duration
}

func newManualSchedulerClock(now time.Time) *manualSchedulerClock {
	return &manualSchedulerClock{now: now, ticks: make(chan time.Time), delays: make(chan time.Duration, 4)}
}

func (c *manualSchedulerClock) Now() time.Time { return c.now }

func (c *manualSchedulerClock) After(d time.Duration) <-chan time.Time {
	c.delays <- d
	return c.ticks
}

func (c *manualSchedulerClock) tick() { c.ticks <- c.now }

type staticSchedulerClock struct{ now time.Time }

func (c staticSchedulerClock) Now() time.Time { return c.now }

func (staticSchedulerClock) After(time.Duration) <-chan time.Time { return nil }
