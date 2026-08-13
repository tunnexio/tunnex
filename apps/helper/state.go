package helper

import (
	"errors"
	"os"
	"sync"
	"time"
)

// DeadManDefault is the conservative window after which an un-heartbeated tunnel
// auto-releases its kill-switch. This BOUNDS the fail-closed model: a helper that
// is alive but whose owning app has crashed/wedged (no heartbeats) can't strand the
// host forever — after this window the block is released. The app heartbeats every
// ~10s, so this is many missed beats. See PLAN "S6.3 KILL-SWITCH DESIGN" (bounded).
// Used when the owner IPC connection is STILL OPEN but heartbeats stopped — we can't
// tell a wedged app from a briefly-slow one, so stay conservative (S6.8).
const DeadManDefault = 90 * time.Second

// DeadManOrphan is the SHORTER window used when the owner IPC connection was
// DEFINITIVELY LOST (the socket closed — OnPeerLost), as opposed to merely missing
// heartbeats on a still-open connection. A closed socket means the app is truly gone
// (crash / force-quit), so the conservative full window is unnecessary — but we keep a
// brief grace so a transient owner hiccup doesn't drop the kill-switch (releasing it
// too eagerly would fail OPEN — a moment of cleartext). This cuts the force-quit/crash
// blackhole from ~90s to ~5s while STILL failing closed in the interim. A CLEAN quit
// (Cmd-Q / tray Quit) uses graceful Down and recovers in ~0s, never reaching here (S6.8).
const DeadManOrphan = 5 * time.Second

// TunnelState is the helper's view of the data plane.
type TunnelState string

const (
	StateDown   TunnelState = "down"   // no tunnel; normal routing
	StateUp     TunnelState = "up"     // tunnel active
	StateFailed TunnelState = "failed" // tunnel lost + FAIL-CLOSED kill-switch installed
)

// Backend is the platform tunnel implementation (wireguard-go on macOS,
// wireguard-nt on Windows). The core dispatches through it; the platform files
// provide it.
//
// KILL-SWITCH INVARIANT (see PLAN "S6.3 KILL-SWITCH DESIGN"): fail-closed must
// require NO LIVE CODE to act, because the helper can be `kill -9`'d (no handlers
// run). So the kill-switch is KERNEL-RESIDENT STATE (pf anchor on macOS, WFP
// filters on Windows) that Up ARRANGES and that PERSISTS however the process
// exits. Death itself enforces no-cleartext.
//
//   - Up(cfg)      bring the tunnel up AND arrange the persistent kill-switch
//     (block all egress except via the tunnel / to the WG endpoint). The block
//     outlives the process; only Down removes it.
//     ORDERING INVARIANT (leak-safety): Up MUST arm the kill-switch backstop
//     BEFORE it moves any routes onto the tunnel. So if Up is interrupted at any
//     point after arming, traffic is BLOCKED (fail-closed), never leaked out the
//     cleartext default route during a half-built setup. Graceful Down is the
//     inverse — restore normal routing, then drop the backstop LAST — so a
//     teardown transient is at worst a brief DROP, never a leak. (This is a
//     contract on each platform Backend's Up/Down; the Supervisor guarantees the
//     state-level fail-closed, the ordering guarantees the setup/teardown windows.)
//   - Down()       graceful: remove the interface AND remove the kill-switch —
//     restore normal routing (the user clicked Disconnect and wants cleartext back).
//   - FailClosed() alive-process FAST PATH (app died / a mid-up error): tear the
//     interface and ASSERT the kill-switch is present. It does NOT "install" the
//     guarantee — Up already did; this is convenience for when code is still
//     running. On `kill -9` this never runs, and the pre-arranged block is what
//     holds the line.
type Backend interface {
	Up(cfg *TunnelConfig) error
	Down() error
	FailClosed() error
	Stats() (TunnelStatus, error)
	// CleanStale releases any kill-switch state left over from a PRIOR process that
	// exited without a graceful Down (a crash / kill -9). The helper calls it ONCE
	// at startup, BEFORE serving, so a KeepAlive-restarted helper self-heals a block
	// that would otherwise strand the host. Must be safe to call when nothing is
	// stale (idempotent no-op).
	CleanStale() error
	// SetAllowedIPs (S8.5) LIVE-updates the tunnel peer's AllowedIPs to allowedIPs (the full desired
	// set) — a wireguard-go uapi update (no handshake reset) + an OS-route full-sweep. It NEVER touches
	// the kill-switch, the device identity, or the peer's keys/endpoint. Called only while a tunnel is up.
	SetAllowedIPs(peerPubKey string, allowedIPs []string) error
	// SetGatewayPeer (WF-A) LIVE-swaps the gateway peer to newPubKey@newEndpoint, preserving the current
	// peer's allowed_ips (routing) and the device identity (own key/address/kill-switch). A peer SWAP, not
	// an endpoint edit — WG keys a peer by pubkey. Split-tunnel only in v1 (full-tunnel refused upstream).
	// Called only while a split tunnel is up.
	SetGatewayPeer(newPubKey, newEndpoint string) error
}

// Supervisor owns the tunnel lifecycle and enforces the FAIL-CLOSED invariant: any
// unexpected loss of the tunnel — a backend error mid-bring-up, or the IPC channel
// to the app dropping while up (helper death is handled by the OS keeping the
// interface down; app death is handled here) — transitions to a kill-switched
// Failed state, never to a silent Down that would leak. It is safe for concurrent
// use.
type Supervisor struct {
	mu      sync.Mutex
	be      Backend
	state   TunnelState
	lastCfg *TunnelConfig
	// Dead-man: lastBeat is refreshed on Up + every heartbeat (Status while up); if
	// the tunnel is up/failed and no beat lands within the effective window,
	// CheckDeadMan releases the kill-switch. now/deadMan/deadManOrphan are injectable
	// for tests. deadManOrphan is the SHORTER window applied once the owner connection
	// was definitively lost (orphaned); deadMan is the conservative heartbeat-silence one.
	lastBeat      time.Time
	deadMan       time.Duration
	deadManOrphan time.Duration
	// orphaned is set when OnPeerLost fired (the owner IPC socket closed) — a definitive
	// owner death, distinct from a still-open connection that merely stopped beating. It
	// selects deadManOrphan in CheckDeadMan. Cleared by a fresh Up / Down / release.
	orphaned bool
	// now MUST stay time.Now (a MONOTONIC source). now()-lastBeat is then monotonic,
	// and Go's monotonic clock PAUSES during system sleep/suspend on macOS + Windows +
	// Linux — so a tunnel healthy at sleep is NOT spuriously released on resume before
	// the app's first post-resume heartbeat (review #9). Do NOT swap this for a
	// wall-clock source, which would count sleep time and fail the tunnel open.
	now func() time.Time
	// onCrashSweep (S8.5 Slice 1) fires when the dead-man RELEASES the kill-switch — the "session is
	// definitively gone" conclusion after the grace window. It is the crash/owner-loss resolver sweep,
	// carefully NOT the S8.4 release-rider that was reduced-out: it is called OUTSIDE s.mu (no FS-under-
	// lock — the RR2 lesson), from the dead-man path ONLY (not graceful Down, which the client already
	// sweeps via set_resolvers([])), and is set ONCE before the dead-man goroutine starts (no SetOnRelease
	// race). nil = no sweep. The dormant-machinery law's scheduled compliance: it lands in S8.5 (where the
	// resolver install path goes live) BEFORE any resolver file can exist, and is walk-proven.
	onCrashSweep func()
}

// SetOnCrashSweep registers the dead-man-release resolver sweep. MUST be called once at startup BEFORE the
// dead-man loop goroutine starts (the happens-before makes the field read race-free). Fired OUTSIDE s.mu.
func (s *Supervisor) SetOnCrashSweep(fn func()) { s.onCrashSweep = fn }

func NewSupervisor(be Backend) *Supervisor {
	dm := DeadManDefault
	// TUNNEX_DEADMAN shortens the window for smoke tests (e.g. "15s") so a forgotten
	// tunnel auto-releases fast. Never lengthen it silently past the default.
	if v := os.Getenv("TUNNEX_DEADMAN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			dm = d
		}
	}
	orphan := DeadManOrphan
	if v := os.Getenv("TUNNEX_DEADMAN_ORPHAN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			orphan = d
		}
	}
	// The orphan (definitive-death) window must never EXCEED the conservative one — if an
	// operator shortened deadMan below it, clamp so the "we know the owner is gone" path is
	// never SLOWER than the "maybe just slow" path.
	if orphan > dm {
		orphan = dm
	}
	return &Supervisor{be: be, state: StateDown, deadMan: dm, deadManOrphan: orphan, now: time.Now}
}

// TickInterval is how often the dead-man loop should poll: a fraction of the SHORTER of
// the two windows, so the orphan window is honored with fine granularity rather than
// only firing on the next coarse tick. (min(deadMan, deadManOrphan)/3.) FLOORED at 100ms
// so a pathologically small env override (e.g. TUNNEX_DEADMAN=2ns) can't yield 0 — a
// zero/negative interval panics time.NewTicker and would crash the helper at startup.
func (s *Supervisor) TickInterval() time.Duration {
	w := s.deadMan
	if s.deadManOrphan < w {
		w = s.deadManOrphan
	}
	if t := w / 3; t > 100*time.Millisecond {
		return t
	}
	return 100 * time.Millisecond
}

// SelfHeal releases any kill-switch state stranded by a prior crashed process. The
// helper calls it ONCE at startup, before serving. Idempotent.
func (s *Supervisor) SelfHeal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StateDown
	return s.be.CleanStale()
}

// beat refreshes the dead-man deadline. Caller holds s.mu.
func (s *Supervisor) beat() { s.lastBeat = s.now() }

// CheckDeadMan releases the kill-switch if the tunnel is up/failed but no heartbeat
// has landed within the dead-man window (owner crashed/wedged). Returns whether it
// fired. A background loop calls it periodically; tests call it directly.
func (s *Supervisor) CheckDeadMan() bool {
	s.mu.Lock()
	if s.state != StateUp && s.state != StateFailed {
		s.mu.Unlock()
		return false
	}
	// Definitive owner death (socket closed) releases on the SHORT window; a still-open
	// connection that merely stopped beating gets the conservative full window.
	window := s.deadMan
	if s.orphaned {
		window = s.deadManOrphan
	}
	if s.now().Sub(s.lastBeat) <= window {
		s.mu.Unlock()
		return false
	}
	// Bounded fail-closed: past the window with no owner → release so an unrecovered
	// crash can't strand the host. Down restores routing + drops the block.
	_ = s.be.Down()
	s.state = StateDown
	s.lastCfg = nil
	s.orphaned = false
	sweep := s.onCrashSweep
	// Release the lock BEFORE the resolver sweep's filesystem work — a wedged /etc/resolver must NOT
	// stall the whole Supervisor state machine (the S8.4 RR2 lesson: FS never under s.mu). The grace is
	// inherited (we only reach here past the window); the micro-window between unlock and sweep is
	// self-healing (a reconnecting client re-installs on its next Up). Down does NOT sweep here — the
	// client already sweeps on graceful teardown via set_resolvers([]).
	s.mu.Unlock()
	if sweep != nil {
		sweep()
	}
	return true
}

func (s *Supervisor) State() TunnelState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Up validates then brings the tunnel up. On ANY backend failure it fails closed
// (kill-switch) rather than leaving traffic on the cleartext default route.
func (s *Supervisor) Up(cfg *TunnelConfig) error {
	if err := cfg.Validate(); err != nil {
		return err // nothing touched yet — plain Down, no kill-switch needed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateUp {
		return &ProtocolError{Code: "already_up", Msg: "a tunnel is already up"}
	}
	if err := s.be.Up(cfg); err != nil {
		// A PRE-ARM rejection (the backend refused/failed BEFORE arming anything, so NOTHING is
		// blocking — full_tunnel_requires_dns, or wfp_arm_failed when the Windows WFP arm's
		// transaction aborted) is a CLEAN rejection, NOT a fail-closed: leave the state Down and
		// surface the code as-is. Otherwise the UI would falsely show "failed / kill-switch
		// active" for a request that blocked nothing (a false fail-closed while traffic flows
		// cleartext). Any OTHER error may have half-built an ARMED tunnel → fail closed.
		var pe *ProtocolError
		if errors.As(err, &pe) && (pe.Code == "full_tunnel_requires_dns" || pe.Code == "wfp_arm_failed") {
			return err
		}
		// Partial bring-up may have created an interface/routes: fail closed so a
		// half-configured tunnel can't leak.
		_ = s.be.FailClosed()
		s.state = StateFailed
		// CRITICAL: beat NOW. Without this, lastBeat is stale (zero / a prior session)
		// and the dead-man fires on its very next tick — releasing the kill-switch
		// ~immediately (fail-OPEN) while the UI still shows "failed/blocked". The block
		// must hold for the full dead-man window before auto-release.
		s.orphaned = false // the owner is present (it made this Up call + got the error)
		s.beat()
		return &ProtocolError{Code: "tunnel_up_failed", Msg: err.Error()}
	}
	s.state = StateUp
	s.lastCfg = cfg
	s.orphaned = false // fresh owner-driven bring-up clears any prior orphan flag
	s.beat()           // start the dead-man clock
	return nil
}

// Down is the GRACEFUL, user-initiated teardown: restore normal routing.
// Idempotent — calling it while already down is a no-op success.
func (s *Supervisor) Down() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateDown {
		return nil
	}
	err := s.be.Down()
	s.state = StateDown
	s.lastCfg = nil
	s.orphaned = false
	if err != nil {
		return &ProtocolError{Code: "tunnel_down_failed", Msg: err.Error()}
	}
	return nil
}

// UpdateAllowedIPs LIVE-applies the desired peer AllowedIPs (S8.5 routed-subnets push). It reads the
// active peer under the lock then applies OUTSIDE it (bounded route syscalls must not hold s.mu — the
// crash-sweep RR2 lesson). NOT tunnel-owning: it changes routing, never the kill-switch / state / owner.
//   - tunnel not up → not_up (a down tunnel has no peer to route through).
//   - FULL-TUNNEL → NO-OP: 0.0.0.0/0 already subsumes every range, and the kill-switch (full-tunnel only)
//     must never be perturbed. So the verb is split-tunnel-only by structure.
func (s *Supervisor) UpdateAllowedIPs(allowedIPs []string) error {
	s.mu.Lock()
	if s.state != StateUp || s.lastCfg == nil {
		s.mu.Unlock()
		return &ProtocolError{Code: "not_up", Msg: "no tunnel is up"}
	}
	full := s.lastCfg.FullTunnel
	peer := s.lastCfg.PeerPublicKey
	s.mu.Unlock()
	if full {
		return nil // full-tunnel: routes subsumed by 0.0.0.0/0; kill-switch never touched
	}
	return s.be.SetAllowedIPs(peer, allowedIPs)
}

// UpdateGatewayPeer LIVE-re-homes the tunnel onto a new active-hub peer (WF-A). Like UpdateAllowedIPs it
// reads state under the lock then applies the (bounded) backend swap OUTSIDE it, and is NOT tunnel-owning:
// it changes the peer, never the state / owner connection.
//   - tunnel not up → not_up (nothing to re-home).
//   - full-vs-split policy lives in the BACKEND (it owns the kill-switch): the darwin backend re-points the
//     pf carve-out + WG host-route for a FULL tunnel (D-WFA-4) when the CP carve-out is present, and refuses
//     (rehome_full_tunnel_unsupported) when it is absent — the Windows backend refuses full-tunnel outright
//     (its WFP carve-out is deferred). Split-tunnel re-home is a bare peer swap on every backend.
func (s *Supervisor) UpdateGatewayPeer(newPubKey, newEndpoint string) error {
	s.mu.Lock()
	if s.state != StateUp || s.lastCfg == nil {
		s.mu.Unlock()
		return &ProtocolError{Code: "not_up", Msg: "no tunnel is up"}
	}
	// Preserve the exact session identity so a concurrent Down→Up cannot have
	// its fresh config overwritten after the bounded backend call below.
	cfg := s.lastCfg
	s.mu.Unlock()
	if err := s.be.SetGatewayPeer(newPubKey, newEndpoint); err != nil {
		return err
	}

	// UpdateAllowedIPs obtains its WireGuard target from lastCfg. A successful
	// re-home must advance this session's peer too; otherwise a later routed-range
	// update can add an OS route while applying AllowedIPs to the removed peer.
	s.mu.Lock()
	if s.state == StateUp && s.lastCfg == cfg {
		cfg.PeerPublicKey = newPubKey
		cfg.Endpoint = newEndpoint
	}
	s.mu.Unlock()
	return nil
}

// OnPeerLost is invoked when the IPC channel to the owning app drops — either the tunnel
// is up (crash/kill) or it already failed closed on a partial bring-up. It FAILS CLOSED:
// the user's protected traffic must not silently revert to cleartext just because the UI
// went away. A no-op when already cleanly down.
//
// `definitive` distinguishes HOW the connection ended (ipc.go classifies it):
//   - true  — the owner socket was CLOSED (EOF/reset): the app process is GONE. Select the
//     SHORT orphan window so a force-quit/crash un-strands the host in ~5s.
//   - false — the owner connection merely hit its READ-DEADLINE timeout: the app may be
//     wedged but is STILL CONNECTED. Keep the CONSERVATIVE full window — we must NOT
//     release a possibly-still-wanted tunnel to cleartext early (fail-open). This is the
//     case the 30s liveness timeout produces for a slow-but-alive app.
func (s *Supervisor) OnPeerLost(definitive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateUp && s.state != StateFailed {
		return
	}
	if s.state == StateUp {
		_ = s.be.FailClosed()
		s.state = StateFailed
	}
	if definitive {
		s.orphaned = true // owner process gone → CheckDeadMan uses the SHORT window
	}
	s.beat()        // count the window from the loss, not the last heartbeat
	s.lastCfg = nil // drop the private-key reference, like the graceful Down path
}

// Status returns live stats. In Failed state it reports "failed" without touching
// the backend (the interface is already gone).
func (s *Supervisor) Status() (TunnelStatus, error) {
	s.mu.Lock()
	state := s.state
	if state == StateUp {
		s.beat() // a status call from the app IS the heartbeat — refresh the dead-man
	}
	s.mu.Unlock()
	if state != StateUp {
		return TunnelStatus{State: string(state)}, nil
	}
	st, err := s.be.Stats()
	if err != nil {
		// Preserve the backend's status fields on a transient stats-read error.
		st.State = string(StateUp)
		return st, &ProtocolError{Code: "stats_failed", Msg: err.Error()}
	}
	st.State = string(StateUp)
	return st, nil
}
