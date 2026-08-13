package ovpnserver

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// Supervisor is the real process control for the OpenVPN server (the ovpnserver.Manager's ensureProc
// seam in production). It spawns `openvpn --config <conf>` if the process is NOT alive and leaves a
// live one untouched — so the next Reconcile tick respawns a crashed process (self-heal, the wg0
// analog). It is only ever CALLED once the Manager's preconditions pass (binary + certs present), so
// it is structurally unable to crash-loop. spawn + isAlive are injectable for deterministic tests.
type Supervisor struct {
	mu      sync.Mutex
	proc    *os.Process
	spawn   func(confPath string) (*os.Process, error)
	isAlive func(p *os.Process) bool
}

// NewSupervisor wires the real spawn (exec openvpn) + liveness (signal 0) implementations.
func NewSupervisor() *Supervisor {
	return &Supervisor{spawn: realSpawn, isAlive: procAlive}
}

// Ensure is the ovpnserver.Manager ensureProc seam: start the process if it isn't alive, else no-op.
func (s *Supervisor) Ensure(_ context.Context, confPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc != nil && s.isAlive(s.proc) {
		return nil // still running — leave it
	}
	p, err := s.spawn(confPath)
	if err != nil {
		return err
	}
	s.proc = p
	return nil
}

// Stop terminates the managed process on agent shutdown (graceful; the tun goes down, and the agent
// publishes egress.SetOVPNTun("") so the Slice-3 sweep removes the tun's egress rules).
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc != nil {
		_ = s.proc.Signal(syscall.SIGTERM)
		s.proc = nil
	}
}

func realSpawn(confPath string) (*os.Process, error) {
	cmd := exec.Command("openvpn", "--config", confPath)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// REAP the child on exit (review #2). Without Wait() a crashed/killed openvpn became a ZOMBIE whose
	// PID still answered kill(pid,0), so procAlive reported it ALIVE and the self-heal NEVER respawned it
	// while Reconcile reported serving=true/HealthOK — green-while-broken, the exact class the health
	// surface exists to prevent, worse than a crash because self-heal silently never fired. The reaping
	// goroutine Wait()s: it reaps the zombie AND marks the os.Process done, so procAlive's Signal then
	// returns ErrProcessDone → false → Ensure respawns.
	go func() { _ = cmd.Wait() }()
	return cmd.Process, nil
}

// procAlive reports whether the process is still running. It relies on the realSpawn reaper: once the
// child exits and the reaping Wait() marks the os.Process done, Signal returns ErrProcessDone (never
// nil), so a reaped/zombie process is correctly NOT alive — Ensure then respawns (review #2).
func procAlive(p *os.Process) bool {
	if p == nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
