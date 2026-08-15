package cli

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAgentRuntimeConcurrentChecksNeverRegressAppliedRevision is an F04
// acceptance red. Two overlapping checks may finish out of order; the local
// reconciler must not let the older apply overwrite the newer applied revision.
func TestAgentRuntimeConcurrentChecksNeverRegressAppliedRevision(t *testing.T) {
	source := &concurrentRuntimeSource{}
	applier := &serialRuntimeApplier{}
	runtime, err := NewAgentRuntime(source, applier, "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	done := make(chan struct{})
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = runtime.CheckOnce(ctx)
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("concurrent CheckOnce calls did not complete under timeout")
	}
	if got := applier.maxActive.Load(); got > 1 {
		t.Fatalf("privileged Apply ran concurrently: max active=%d", got)
	}
	if got := runtime.AppliedRevision(); got != 3 {
		t.Fatalf("concurrent checks regressed applied revision: got %d, want 3", got)
	}
}

// TestAgentRuntimeCancellationReleasesSingleFlight proves a canceled poll
// cannot strand the mutex and block the next reconciliation forever.
func TestAgentRuntimeCancellationReleasesSingleFlight(t *testing.T) {
	source := &cancelBlockingRuntimeSource{started: make(chan struct{})}
	runtime, err := NewAgentRuntime(source, &fakeAgentApplier{}, "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	go func() {
		_, _ = runtime.CheckOnce(canceled)
		close(firstDone)
	}()
	<-source.started
	cancel()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("canceled poll did not release CheckOnce")
	}

	secondDone := make(chan struct{})
	go func() {
		_, _ = runtime.CheckOnce(context.Background())
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("a canceled poll stranded the single-flight mutex")
	}
	if got := runtime.AppliedRevision(); got != 1 {
		t.Fatalf("cancellation path regressed or failed to establish revision: got %d, want 1", got)
	}
}

type cancelBlockingRuntimeSource struct {
	started chan struct{}
	polled  atomic.Int32
}

func (s *cancelBlockingRuntimeSource) Poll(ctx context.Context, _ int64, _ string) (ManagedAgentConfig, error) {
	if s.polled.Add(1) == 1 {
		close(s.started)
		<-ctx.Done()
		return ManagedAgentConfig{}, ctx.Err()
	}
	return validAgentConfig(1), nil
}

func (*cancelBlockingRuntimeSource) Report(context.Context, AgentRuntimeReport) error { return nil }

type concurrentRuntimeSource struct{ polls atomic.Int32 }

func (s *concurrentRuntimeSource) Poll(context.Context, int64, string) (ManagedAgentConfig, error) {
	if s.polls.Add(1) == 1 {
		return validAgentConfig(2), nil
	}
	return validAgentConfig(3), nil
}

func (*concurrentRuntimeSource) Report(context.Context, AgentRuntimeReport) error { return nil }

type serialRuntimeApplier struct {
	active    atomic.Int32
	maxActive atomic.Int32
}

func (a *serialRuntimeApplier) Apply(ctx context.Context, _ ManagedAgentConfig) error {
	active := a.active.Add(1)
	for {
		max := a.maxActive.Load()
		if active <= max || a.maxActive.CompareAndSwap(max, active) {
			break
		}
	}
	defer a.active.Add(-1)
	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*serialRuntimeApplier) Disable(context.Context) error { return nil }
