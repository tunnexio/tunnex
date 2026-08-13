package ovpnserver

import (
	"context"
	"os"
	"os/exec"
	"testing"
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
		spawn:   func(string) (*os.Process, error) { spawns++; return &os.Process{}, nil },
		isAlive: func(*os.Process) bool { return alive },
	}
	ctx := context.Background()

	// no process yet → spawn.
	if err := sup.Ensure(ctx, "server.conf"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if spawns != 1 {
		t.Fatalf("first ensure must spawn; spawns=%d", spawns)
	}
	// process alive → NO respawn.
	alive = true
	_ = sup.Ensure(ctx, "server.conf")
	if spawns != 1 {
		t.Fatalf("a live process must not be respawned; spawns=%d", spawns)
	}
	// process died → respawn (self-heal).
	alive = false
	_ = sup.Ensure(ctx, "server.conf")
	if spawns != 2 {
		t.Fatalf("a dead process must be respawned; spawns=%d", spawns)
	}
}
