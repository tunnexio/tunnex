package ovpnserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type ProcessState struct {
	Serving       bool
	AppliedDigest string
	DesiredDigest string
}

type ProcessController interface {
	Ensure(context.Context, string, string) (ProcessState, error)
	Readback() (ProcessState, error)
	Stop() error
}

type noopProcessController struct{}

func (noopProcessController) Ensure(_ context.Context, _ string, digest string) (ProcessState, error) {
	return ProcessState{Serving: true, AppliedDigest: digest}, nil
}
func (noopProcessController) Readback() (ProcessState, error) { return ProcessState{}, nil }
func (noopProcessController) Stop() error                     { return nil }

// Supervisor is the real process control for the OpenVPN server. It spawns
// `openvpn --config <conf>` when absent and retains a live process only while
// its loaded artifact digest is exact. A changed digest gets a bounded
// terminate/kill/restart, and disable/refusal paths use the same bounded stop.
type Supervisor struct {
	mu             sync.Mutex
	proc           *os.Process
	spawn          func(confPath string) (*os.Process, error)
	isAlive        func(p *os.Process) bool
	signal         func(*os.Process, os.Signal) error
	appliedDigest  string
	restartTimeout time.Duration
	ready          func(context.Context, *os.Process) error
}

// NewSupervisor wires the real spawn (exec openvpn) + liveness (signal 0) implementations.
func NewSupervisor() *Supervisor {
	return &Supervisor{spawn: realSpawn, isAlive: procAlive, signal: func(p *os.Process, sig os.Signal) error { return p.Signal(sig) }, restartTimeout: 5 * time.Second, ready: waitForOpenVPNReady}
}

// Ensure starts an absent process, keeps an exact one, or controlled-restarts a
// process that loaded a different artifact digest.
func (s *Supervisor) Ensure(ctx context.Context, confPath, digest string) (ProcessState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ProcessState{}, err
	}
	if s.proc != nil && s.isAlive(s.proc) {
		if s.appliedDigest == digest {
			return ProcessState{Serving: true, AppliedDigest: digest}, nil
		}
		if err := s.stopLocked(); err != nil {
			return ProcessState{}, err
		}
		if err := ctx.Err(); err != nil {
			return ProcessState{}, err
		}
	}
	p, err := s.spawn(confPath)
	if err != nil {
		s.proc, s.appliedDigest = nil, ""
		return ProcessState{}, err
	}
	s.proc = p
	if s.ready != nil {
		readyCtx, cancel := context.WithTimeout(ctx, s.restartTimeout)
		err = s.ready(readyCtx, p)
		cancel()
		if err != nil {
			stopErr := s.stopLocked()
			if stopErr != nil {
				return ProcessState{}, fmt.Errorf("OpenVPN readiness failed (%v) and process withdrawal failed: %w", err, stopErr)
			}
			return ProcessState{}, fmt.Errorf("OpenVPN readiness failed: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		_ = s.stopLocked()
		return ProcessState{}, err
	}
	s.appliedDigest = digest
	return ProcessState{Serving: true, AppliedDigest: digest}, nil
}

func (s *Supervisor) Readback() (ProcessState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil || !s.isAlive(s.proc) {
		return ProcessState{}, nil
	}
	return ProcessState{Serving: true, AppliedDigest: s.appliedDigest}, nil
}

func (s *Supervisor) stopLocked() error {
	if s.proc == nil {
		return nil
	}
	signal := s.signal
	if signal == nil {
		signal = func(p *os.Process, sig os.Signal) error { return p.Signal(sig) }
	}
	if err := signal(s.proc, syscall.SIGTERM); err != nil && s.isAlive(s.proc) {
		return fmt.Errorf("stop OpenVPN for controlled restart: %w", err)
	}
	deadline := time.Now().Add(s.restartTimeout)
	for s.isAlive(s.proc) && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if s.isAlive(s.proc) {
		if err := signal(s.proc, syscall.SIGKILL); err != nil && s.isAlive(s.proc) {
			return fmt.Errorf("kill OpenVPN after restart timeout: %w", err)
		}
		killDeadline := time.Now().Add(time.Second)
		for s.isAlive(s.proc) && time.Now().Before(killDeadline) {
			time.Sleep(25 * time.Millisecond)
		}
		if s.isAlive(s.proc) {
			return fmt.Errorf("OpenVPN did not stop for controlled restart")
		}
	}
	s.proc, s.appliedDigest = nil, ""
	return nil
}

// Stop terminates the managed process on agent shutdown (graceful; the tun goes down, and the agent
// publishes egress.SetOVPNTun("") so the Slice-3 sweep removes the tun's egress rules).
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked()
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

func waitForOpenVPNReady(ctx context.Context, process *os.Process) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !procAlive(process) {
			return fmt.Errorf("process exited before tunnel readiness")
		}
		if _, err := net.InterfaceByName(TunName); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
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
