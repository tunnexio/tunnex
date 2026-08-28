package nodes

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandoffSchedulerLeaderLifecycleDisabledDoesNoWork(t *testing.T) {
	probe := &lifecycleProbe{}
	lifecycle := NewHandoffSchedulerLeaderLifecycle(HandoffSchedulerLeaderLifecycleConfig{Enabled: false, Leader: probe})
	if status := lifecycle.Status(); status.State != HandoffSchedulerDisabled {
		t.Fatalf("disabled status=%+v", status)
	}
	if status := lifecycle.Start(context.Background()); status.State != HandoffSchedulerDisabled {
		t.Fatalf("disabled start=%+v", status)
	}
	if probe.calls.Load() != 0 {
		t.Fatalf("disabled lifecycle confirmed leadership %d times", probe.calls.Load())
	}
	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffSchedulerLeaderLifecycleBlocksIncompleteOrUnsafeComposition(t *testing.T) {
	activation := readyLifecycleActivation(t)
	var typedNilActivation *HandoffSchedulerActivation
	for name, config := range map[string]HandoffSchedulerLeaderLifecycleConfig{
		"missing activation":   {Enabled: true, Leader: &lifecycleProbe{}, Timing: validLifecycleTiming()},
		"typed nil activation": {Enabled: true, Activation: typedNilActivation, Leader: &lifecycleProbe{}, Timing: validLifecycleTiming()},
		"blocked activation": {
			Enabled:    true,
			Activation: NewHandoffSchedulerActivation(HandoffSchedulerActivationConfig{Enabled: true}),
			Leader:     &lifecycleProbe{},
			Timing:     validLifecycleTiming(),
		},
		"missing leader": {Enabled: true, Activation: activation, Timing: validLifecycleTiming()},
		"unsafe probe interval": {
			Enabled: true, Activation: activation, Leader: &lifecycleProbe{},
			Timing: HandoffSchedulerLeadershipTiming{ProbeInterval: minHandoffSchedulerLeaderProbeInterval - time.Millisecond, StopTimeout: time.Second},
		},
		"unsafe stop timeout": {
			Enabled: true, Activation: activation, Leader: &lifecycleProbe{},
			Timing: HandoffSchedulerLeadershipTiming{ProbeInterval: time.Second, StopTimeout: maxHandoffSchedulerStopTimeout + time.Millisecond},
		},
	} {
		t.Run(name, func(t *testing.T) {
			lifecycle := NewHandoffSchedulerLeaderLifecycle(config)
			if status := lifecycle.Status(); status.State != HandoffSchedulerBlocked {
				t.Fatalf("blocked status=%+v", status)
			}
			if status := lifecycle.Start(context.Background()); status.State != HandoffSchedulerBlocked {
				t.Fatalf("blocked start=%+v", status)
			}
		})
	}
}

func TestHandoffSchedulerLeaderLifecycleStartsOnlyForLeaderAndRestartsAfterHandover(t *testing.T) {
	loop := newRestartableLifecycleLoop()
	activation := lifecycleActivation(loop)
	probe := &lifecycleProbe{}
	clock := newLifecycleClock()
	lifecycle := NewHandoffSchedulerLeaderLifecycle(HandoffSchedulerLeaderLifecycleConfig{
		Enabled: true, Activation: activation, Leader: probe, Timing: validLifecycleTiming(),
	})
	lifecycle.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if status := lifecycle.Start(ctx); status.State != HandoffSchedulerReady {
		t.Fatalf("start status=%+v", status)
	}
	probe.waitCalls(t, 1)
	if loop.starts.Load() != 0 {
		t.Fatalf("follower started scheduler loop %d times", loop.starts.Load())
	}

	probe.leading.Store(true)
	clock.pulse(t)
	loop.waitStarts(t, 1)
	if loop.exits.Load() != 0 {
		t.Fatalf("leader loop exited unexpectedly: %d", loop.exits.Load())
	}

	// Leadership loss cancels and joins the prior loop before a later confirmed
	// leader can start it again. There is never a pair of local scheduler loops.
	probe.leading.Store(false)
	clock.pulse(t)
	loop.waitExits(t, 1)
	if activation.running() {
		t.Fatal("leadership loss left scheduler loop running")
	}

	probe.leading.Store(true)
	clock.pulse(t)
	loop.waitStarts(t, 2)
	if loop.maxRunning.Load() != 1 {
		t.Fatalf("leadership handover overlapped scheduler loops: max=%d", loop.maxRunning.Load())
	}

	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	loop.waitExits(t, 2)
	if activation.running() {
		t.Fatal("shutdown left scheduler loop running")
	}
}

func TestHandoffSchedulerLeaderLifecycleStartIsIdempotentAndParentCancellationStops(t *testing.T) {
	loop := newRestartableLifecycleLoop()
	activation := lifecycleActivation(loop)
	probe := &lifecycleProbe{}
	probe.leading.Store(true)
	clock := newLifecycleClock()
	lifecycle := NewHandoffSchedulerLeaderLifecycle(HandoffSchedulerLeaderLifecycleConfig{
		Enabled: true, Activation: activation, Leader: probe, Timing: validLifecycleTiming(),
	})
	lifecycle.clock = clock
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status := lifecycle.Start(ctx); status.State != HandoffSchedulerReady {
				t.Errorf("start status=%+v", status)
			}
		}()
	}
	wg.Wait()
	loop.waitStarts(t, 1)
	cancel()
	loop.waitExits(t, 1)
	if err := lifecycle.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresHandoffSchedulerLeaderProbeFailsClosedWithoutDependencies(t *testing.T) {
	if (PostgresHandoffSchedulerLeaderProbe{}).ConfirmHandoffSchedulerLeader(context.Background()) {
		t.Fatal("nil PostgreSQL leader dependencies confirmed leadership")
	}
}

func validLifecycleTiming() HandoffSchedulerLeadershipTiming {
	return HandoffSchedulerLeadershipTiming{ProbeInterval: time.Second, StopTimeout: time.Second}
}

func readyLifecycleActivation(t *testing.T) *HandoffSchedulerActivation {
	t.Helper()
	return lifecycleActivation(newRestartableLifecycleLoop())
}

func lifecycleActivation(loop handoffSchedulerLoop) *HandoffSchedulerActivation {
	config, _, _ := activationConfig()
	return newHandoffSchedulerActivation(config, activationFactory(loop))
}

type lifecycleProbe struct {
	leading atomic.Bool
	calls   atomic.Int32
	wake    chan struct{}
}

func (p *lifecycleProbe) ConfirmHandoffSchedulerLeader(context.Context) bool {
	p.calls.Add(1)
	if p.wake != nil {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
	return p.leading.Load()
}

func (p *lifecycleProbe) waitCalls(t *testing.T, want int32) {
	t.Helper()
	deadline := time.After(time.Second)
	for p.calls.Load() < want {
		select {
		case <-deadline:
			t.Fatalf("leader confirmations=%d, want at least %d", p.calls.Load(), want)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

type lifecycleClock struct{ ticks chan time.Time }

func newLifecycleClock() *lifecycleClock                       { return &lifecycleClock{ticks: make(chan time.Time, 8)} }
func (c *lifecycleClock) After(time.Duration) <-chan time.Time { return c.ticks }
func (c *lifecycleClock) pulse(t *testing.T) {
	t.Helper()
	select {
	case c.ticks <- time.Now():
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not wait for next probe")
	}
}

type restartableLifecycleLoop struct {
	starts     atomic.Int32
	exits      atomic.Int32
	running    atomic.Int32
	maxRunning atomic.Int32
	wake       chan struct{}
}

func newRestartableLifecycleLoop() *restartableLifecycleLoop {
	return &restartableLifecycleLoop{wake: make(chan struct{}, 16)}
}

func (l *restartableLifecycleLoop) Run(ctx context.Context) {
	starts := l.starts.Add(1)
	running := l.running.Add(1)
	for {
		max := l.maxRunning.Load()
		if running <= max || l.maxRunning.CompareAndSwap(max, running) {
			break
		}
	}
	select {
	case l.wake <- struct{}{}:
	default:
	}
	<-ctx.Done()
	l.running.Add(-1)
	l.exits.Add(1)
	select {
	case l.wake <- struct{}{}:
	default:
	}
	_ = starts
}

func (l *restartableLifecycleLoop) waitStarts(t *testing.T, want int32) {
	t.Helper()
	l.wait(t, want, &l.starts, "starts")
}

func (l *restartableLifecycleLoop) waitExits(t *testing.T, want int32) {
	t.Helper()
	l.wait(t, want, &l.exits, "exits")
}

func (l *restartableLifecycleLoop) wait(t *testing.T, want int32, got *atomic.Int32, what string) {
	t.Helper()
	deadline := time.After(time.Second)
	for got.Load() < want {
		select {
		case <-l.wake:
		case <-deadline:
			t.Fatalf("loop %s=%d, want at least %d", what, got.Load(), want)
		}
	}
}

var _ HandoffSchedulerLeaderProbe = (*lifecycleProbe)(nil)
var _ handoffSchedulerLeadershipClock = (*lifecycleClock)(nil)
var _ handoffSchedulerLoop = (*restartableLifecycleLoop)(nil)
