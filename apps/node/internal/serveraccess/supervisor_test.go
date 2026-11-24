package serveraccess

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestModeFromEnvIsTriStateAndFailsClosed(t *testing.T) {
	for value, want := range map[string]Mode{"": ModeFollow, "  ": ModeFollow, "true": ModeOn, " true ": ModeOn, "false": ModeOff, "TRUE": ModeOff, "1": ModeOff, "yes": ModeOff, "automatic": ModeOff} {
		if got := ModeFromEnv(value); got != want {
			t.Errorf("ModeFromEnv(%q) = %v, want %v", value, got, want)
		}
	}
}

type fakeRuntime struct {
	mu      sync.Mutex
	starts  int
	running int
}

func (f *fakeRuntime) start(ctx context.Context) func() {
	f.mu.Lock()
	f.starts++
	f.running++
	f.mu.Unlock()
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		f.running--
		f.mu.Unlock()
		close(done)
	}()
	return func() { <-done }
}

func (f *fakeRuntime) state() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.running
}

func TestFollowStartsAndStopsWithControlPlane(t *testing.T) {
	answers := make(chan struct {
		on  bool
		err error
	})
	poll := func(ctx context.Context) (bool, error) {
		select {
		case a := <-answers:
			return a.on, a.err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	rt := &fakeRuntime{}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		follow(ctx, time.Millisecond, poll, rt.start, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(finished)
	}()
	send := func(on bool, err error) {
		answers <- struct {
			on  bool
			err error
		}{on, err}
	}
	expect := func(starts, running int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if s, r := rt.state(); s == starts && r == running {
				return
			}
			time.Sleep(time.Millisecond)
		}
		s, r := rt.state()
		t.Fatalf("starts=%d running=%d, want %d/%d", s, r, starts, running)
	}
	send(false, nil)
	expect(0, 0)
	send(true, nil)
	expect(1, 1)
	send(true, nil) // steady state: no second runtime
	expect(1, 1)
	send(false, errors.New("control plane unreachable")) // keep current state
	expect(1, 1)
	send(false, nil) // capability turned off: runtime cancelled
	expect(1, 0)
	send(true, nil) // turned on again without restart
	expect(2, 1)
	cancel()
	<-finished
	expect(2, 0)
}
