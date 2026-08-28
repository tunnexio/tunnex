package ovpnserver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestProcAliveReflectsReapedProcess is the review-#2 red: it exercises the REAL procAlive (not the
// injected fake) against a REAL reaped process — the zombie case that survived the original test. A
// short-lived child, reaped like realSpawn does (a Wait goroutine), must NOT be reported alive; without
// the reaper its PID would still answer kill(pid,0) and self-heal would never respawn (green-while-broken).
func TestProcAliveReflectsReapedProcess(t *testing.T) {
	// A live process IS alive.
	long := exec.Command("sleep", "30")
	if err := long.Start(); err != nil {
		t.Skipf("cannot spawn a test process: %v", err)
	}
	go func() { _ = long.Wait() }()
	defer func() { _ = long.Process.Kill() }()
	if !procAlive(long.Process) {
		t.Fatal("a running process must be reported alive")
	}

	// An EXITED + REAPED process must NOT be alive (the zombie must not pass kill(pid,0)).
	short := exec.Command("sh", "-c", "exit 0")
	if err := short.Start(); err != nil {
		t.Skipf("cannot spawn a test process: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = short.Wait(); close(done) }() // reap it, exactly like realSpawn
	<-done
	if procAlive(short.Process) {
		t.Fatal("review #2: a reaped/exited process must NOT be reported alive — a zombie masquerading as alive is why self-heal silently never fired")
	}
}

// TestSupervisorSpawnsIfNotAliveElseNoop (4d) locks the self-heal core: spawn when no process / a
// dead process; leave a live one untouched. Deterministic — spawn + isAlive injected.
func TestSupervisorSpawnsIfNotAliveElseNoop(t *testing.T) {
	spawns := 0
	alive := false
	sup := &Supervisor{
		spawn:          func(string) (*os.Process, error) { spawns++; return &os.Process{}, nil },
		isAlive:        func(*os.Process) bool { return alive },
		signal:         func(*os.Process, os.Signal) error { alive = false; return nil },
		restartTimeout: time.Second,
	}
	ctx := context.Background()

	// no process yet → spawn.
	if _, err := sup.Ensure(ctx, "server.conf", "digest-a"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if spawns != 1 {
		t.Fatalf("first ensure must spawn; spawns=%d", spawns)
	}
	// process alive → NO respawn.
	alive = true
	_, _ = sup.Ensure(ctx, "server.conf", "digest-a")
	if spawns != 1 {
		t.Fatalf("a live process must not be respawned; spawns=%d", spawns)
	}
	// process died → respawn (self-heal).
	alive = false
	_, _ = sup.Ensure(ctx, "server.conf", "digest-a")
	if spawns != 2 {
		t.Fatalf("a dead process must be respawned; spawns=%d", spawns)
	}
}

func TestSupervisorControlledRestartOnArtifactChange(t *testing.T) {
	spawns, signals := 0, 0
	alive := false
	sup := &Supervisor{
		spawn:          func(string) (*os.Process, error) { spawns++; alive = true; return &os.Process{}, nil },
		isAlive:        func(*os.Process) bool { return alive },
		signal:         func(*os.Process, os.Signal) error { signals++; alive = false; return nil },
		restartTimeout: time.Second,
	}
	if _, err := sup.Ensure(context.Background(), "server.conf", "digest-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := sup.Ensure(context.Background(), "server.conf", "digest-a"); err != nil {
		t.Fatal(err)
	}
	if spawns != 1 || signals != 0 {
		t.Fatalf("same digest must retain live process: spawns=%d signals=%d", spawns, signals)
	}
	state, err := sup.Ensure(context.Background(), "server.conf", "digest-b")
	if err != nil {
		t.Fatal(err)
	}
	if spawns != 2 || signals != 1 || !state.Serving || state.AppliedDigest != "digest-b" {
		t.Fatalf("changed artifact must restart exactly once: state=%+v spawns=%d signals=%d", state, spawns, signals)
	}
}

func TestSupervisorReadinessFailureWithdrawsChild(t *testing.T) {
	spawns, signals := 0, 0
	alive := false
	sup := &Supervisor{
		spawn:          func(string) (*os.Process, error) { spawns++; alive = true; return &os.Process{}, nil },
		isAlive:        func(*os.Process) bool { return alive },
		signal:         func(*os.Process, os.Signal) error { signals++; alive = false; return nil },
		restartTimeout: time.Second,
		ready:          func(context.Context, *os.Process) error { return errors.New("config rejected") },
	}
	if _, err := sup.Ensure(context.Background(), "server.conf", "digest-a"); err == nil {
		t.Fatal("child without readiness must be refused")
	}
	state, err := sup.Readback()
	if err != nil {
		t.Fatal(err)
	}
	if spawns != 1 || signals != 1 || alive || state.Serving {
		t.Fatalf("unready child was not withdrawn: spawns=%d signals=%d alive=%v state=%+v", spawns, signals, alive, state)
	}
}

func TestSupervisorCancellationNeverSpawns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spawns := 0
	sup := &Supervisor{
		spawn:          func(string) (*os.Process, error) { spawns++; return &os.Process{}, nil },
		isAlive:        func(*os.Process) bool { return false },
		restartTimeout: time.Second,
	}
	if _, err := sup.Ensure(ctx, "server.conf", "digest-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ensure err=%v", err)
	}
	if spawns != 0 {
		t.Fatalf("cancelled ensure spawned %d children", spawns)
	}
}
