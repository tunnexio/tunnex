package helper

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// MaxMessageBytes caps a single framed message so a hostile/confused caller can't
// make the root helper allocate unboundedly. WireGuard configs are tiny; 64 KiB
// is generous.
const MaxMessageBytes = 64 * 1024

// Framing: a 4-byte big-endian length prefix followed by that many JSON bytes.
// Simple, language-neutral (the Electron main side speaks the same framing in TS).

// WriteMessage frames and writes v as length-prefixed JSON.
func WriteMessage(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > MaxMessageBytes {
		return errors.New("message exceeds MaxMessageBytes")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadMessage reads one length-prefixed JSON message into v, rejecting oversize
// frames before allocating the body.
func ReadMessage(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMessageBytes {
		return errors.New("incoming message exceeds MaxMessageBytes")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// PeerResolver resolves the on-disk executable path of the process on the other
// end of conn. It is PLATFORM-SPECIFIC (macOS: audit token → pid → path; Windows:
// GetNamedPipeClientProcessId → image path) and injected into the Server so the
// dispatch logic stays pure + testable. A resolver that cannot determine the peer
// MUST return an error — the Server then refuses the caller (fail closed).
type PeerResolver func(conn net.Conn) (exePath string, err error)

// Default connection bounds. The read deadline doubles as the app-LIVENESS
// timeout: the app holds ONE control connection open and must send a request (a
// status heartbeat suffices, and the UI wants live stats anyway) within this
// window; silence past it means the app crashed/hung → the owner connection is
// dropped → fail closed. It also defeats slow-loris against the root process.
const (
	defaultReadTimeout  = 30 * time.Second
	defaultWriteTimeout = 10 * time.Second
	defaultMaxConns     = 16
)

// Server runs the helper's request loop for one listener. It authenticates each
// connection's caller BEFORE any dispatch, enforces the mode of its ACTUAL
// verifier, and — critically — FAILS CLOSED only when the connection that OWNS the
// live tunnel goes away (crash/hang/close-without-down). A benign second
// connection (e.g. a status poll) closing never tears down a tunnel another
// connection owns.
type Server struct {
	sup     *Supervisor
	verify  CallerVerifier
	resolve PeerResolver

	readTimeout  time.Duration
	writeTimeout time.Duration
	sem          chan struct{} // caps concurrent connections against a local flood

	// posture reads local device posture facts (S7.5.3) — the platform collector
	// by default, injectable so dispatch tests never exec fdesetup/powershell.
	posture func() PostureStatus

	// resolvers reconciles domain-scoped resolver files (S8.4) — the platform
	// implementation by default (macOS /etc/resolver; unsupported elsewhere until
	// S8.4b), injectable so dispatch tests never write to the real /etc/resolver.
	resolvers func([]ResolverForward) error

	// setAllowedIPs live-updates the tunnel peer's AllowedIPs (S8.5) — Supervisor.UpdateAllowedIPs by
	// default, injectable so dispatch tests never touch a real wg device.
	setAllowedIPs func([]string) error

	// setGatewayPeer live-swaps the gateway peer (WF-A re-homing) — Supervisor.UpdateGatewayPeer by
	// default, injectable so dispatch tests never touch a real wg device.
	setGatewayPeer func(newPubKey, newEndpoint string) error

	mu    sync.Mutex
	owner net.Conn // the connection that brought the current tunnel up (nil if down)
}

// NewServer wires the dispatch dependencies. The enforced auth mode is the mode of
// the verifier itself (path_check now; code_signing at S6.5b) — there is no
// separate knob to drift out of sync with the real check.
func NewServer(sup *Supervisor, verify CallerVerifier, resolve PeerResolver) *Server {
	return &Server{
		sup:            sup,
		verify:         verify,
		resolve:        resolve,
		readTimeout:    defaultReadTimeout,
		writeTimeout:   defaultWriteTimeout,
		sem:            make(chan struct{}, defaultMaxConns),
		posture:        collectPosture,
		resolvers:      setResolvers,
		setAllowedIPs:  sup.UpdateAllowedIPs,
		setGatewayPeer: sup.UpdateGatewayPeer,
	}
}

// Serve accepts connections until the listener closes. Each is handled in its own
// goroutine, bounded by the connection semaphore (excess connections are refused,
// not queued, so a local flood can't exhaust the root process).
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case s.sem <- struct{}{}:
			go func() {
				defer func() { <-s.sem }()
				s.handle(conn)
			}()
		default:
			_ = conn.Close() // at capacity — refuse
		}
	}
}

// handle authenticates then serves one connection. A recover() makes a single bad
// connection unable to crash the root helper. On loop exit it fails the tunnel
// closed IFF this connection OWNED a live tunnel.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	// definitive records HOW this connection ended, for the owner-loss path: a CLOSED
	// socket (EOF/reset — the app process is gone) is definitive → short orphan window;
	// a READ-DEADLINE timeout (a wedged-but-still-connected app) is NOT → conservative
	// full window (no early fail-open). Default true: anything but an explicit read
	// timeout (close, write error, panic) is treated as a real loss of the owner.
	definitive := true
	// recover first (runs last, catching panics from the loop), then owner cleanup.
	defer func() { s.onClose(conn, definitive) }()
	defer func() { _ = recover() }()

	exe, err := s.resolve(conn)
	if err != nil {
		// Surface the resolver's SPECIFIC code (peer_no_handle / peer_pid_unresolved /
		// peer_open_failed / peer_path_unresolved) instead of masking every failure as a
		// generic "peer_unresolved" — the specific code is what makes a caller-auth
		// failure diagnosable in the field.
		code, msg := "peer_unresolved", "could not identify the caller"
		var pe *ProtocolError
		if errors.As(err, &pe) {
			code, msg = pe.Code, pe.Msg
		}
		_ = WriteMessage(conn, errorResponse(code, msg))
		return
	}
	if err := s.verify.Verify(exe); err != nil {
		// Log the rejected caller's exe path so an install can self-correct its
		// trusted dirs (dev) and so untrusted-caller attempts are auditable.
		log.Printf("caller_untrusted: caller exe %q not inside any trusted install dir", exe)
		_ = WriteMessage(conn, errorResponse(codeOf(err), "caller not trusted"))
		return
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		var req Request
		if err := ReadMessage(conn, &req); err != nil {
			// A read-deadline timeout means the app is silent but the socket is STILL
			// OPEN (possibly just wedged) — NOT a definitive death. Any other read error
			// (EOF/reset) is the owner socket closing = the process is gone.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				definitive = false
			}
			return // deferred onClose fails closed if this conn owned the tunnel
		}
		resp := s.dispatch(&req)
		switch req.Verb {
		case VerbTunnelUp:
			// Own the connection if the up left the kill-switch ARMED — StateUp on
			// success, OR StateFailed on a partial bring-up that fail-closed. Either way
			// THIS connection's loss must drive teardown (else a force-quit after a failed
			// connect would wait the full window with no orphan signal — review #3).
			if st := s.sup.State(); st == StateUp || st == StateFailed {
				s.setOwner(conn)
			}
		case VerbTunnelDown:
			if resp.OK {
				s.clearOwner(conn)
			}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		if err := WriteMessage(conn, resp); err != nil {
			return
		}
	}
}

func (s *Server) setOwner(conn net.Conn) {
	s.mu.Lock()
	s.owner = conn
	s.mu.Unlock()
}

func (s *Server) clearOwner(conn net.Conn) {
	s.mu.Lock()
	if s.owner == conn {
		s.owner = nil
	}
	s.mu.Unlock()
}

// onClose fails the tunnel closed only if the closing connection is the owner —
// app death (crash/hang/close-without-down) must not silently drop protection, but
// a non-owner connection closing must not disturb a live tunnel.
func (s *Server) onClose(conn net.Conn, definitive bool) {
	s.mu.Lock()
	isOwner := s.owner == conn
	if isOwner {
		s.owner = nil
	}
	s.mu.Unlock()
	if isOwner {
		// definitive=true (socket closed → process gone) selects the short orphan window;
		// false (read-deadline timeout → wedged-but-connected) keeps the full window.
		// NO resolver sweep on owner-loss (S8.4 round-3 reduce-by-removal): the crash/owner-loss resolver
		// sweep is DEFERRED to S8.4b/S8.5, where the client resolver path goes live and the sweep is
		// exercisable + walk-provable. Until S8.5 the client installs NO resolver files (dns_forwards is
		// empty), so there is no crash residue to sweep; startup CleanStaleResolvers covers the only
		// residue path that could exist (a future downgrade/mixed-version edge). See docs/S8.4-decisions.md.
		s.sup.OnPeerLost(definitive) // no-op unless a tunnel is up/failed
	}
}

// dispatch validates the envelope, enforces auth mode (of the actual verifier), and
// runs the verb. It never panics on bad input — every failure is a typed Response
// with a stable code.
func (s *Server) dispatch(req *Request) *Response {
	if err := ValidateRequest(req); err != nil {
		return errorResponse(codeOf(err), err.Error())
	}
	if _, err := Negotiate(req.AuthMode, s.verify.Mode()); err != nil {
		return errorResponse(codeOf(err), err.Error())
	}
	switch req.Verb {
	case VerbTunnelUp:
		if err := s.sup.Up(req.Config); err != nil {
			return errorResponse(codeOf(err), err.Error())
		}
		st, _ := s.sup.Status()
		return okResponse(&st)
	case VerbTunnelDown:
		if err := s.sup.Down(); err != nil {
			return errorResponse(codeOf(err), err.Error())
		}
		return okResponse(nil)
	case VerbStatus:
		st, err := s.sup.Status()
		if err != nil {
			return errorResponse(codeOf(err), err.Error())
		}
		return okResponse(&st)
	case VerbPostureStatus:
		// Read-only, never fails: an unreadable fact comes back nil (reported
		// absent upstream, never guessed) rather than an error — the caller has
		// nothing to retry and absence is a first-class honest answer.
		p := s.posture()
		return &Response{Version: ProtocolVersion, OK: true, Posture: &p}
	case VerbSetResolvers:
		// State-changing but NOT tunnel-owning: reconciling resolver files never
		// affects who owns the live tunnel (unlike tunnel_up). A failure returns a
		// typed code; the app fail-STATIC (keeps the tunnel up, names just don't
		// resolve cross-site) — DNS forwarding is never load-bearing for the tunnel.
		if err := s.resolvers(req.Resolvers); err != nil {
			return errorResponse(codeOf(err), err.Error())
		}
		return okResponse(nil)
	case VerbSetAllowedIPs:
		// State-changing but NOT tunnel-owning (same class as set_resolvers): a live AllowedIPs
		// update changes routing, never tunnel state / the owner connection / the kill-switch. A
		// failure returns a typed code; the client fail-STATIC (keeps the tunnel + its last routes,
		// the new route just doesn't push). Full-tunnel is a no-op (Supervisor.UpdateAllowedIPs).
		if err := s.setAllowedIPs(req.AllowedIPs); err != nil {
			return errorResponse(codeOf(err), err.Error())
		}
		return okResponse(nil)
	case VerbSetGatewayPeer:
		// State-changing but NOT tunnel-owning (same class as set_allowed_ips): a peer swap re-homes the
		// tunnel, never touching tunnel state / the owner connection / the kill-switch. A failure returns a
		// typed code; the client fail-STATIC (keeps its current peer, the re-home just doesn't apply). Full-
		// tunnel is refused upstream (Supervisor.UpdateGatewayPeer) — its carve-out is a separate slice.
		if err := s.setGatewayPeer(req.GatewayPeer.PeerPublicKey, req.GatewayPeer.Endpoint); err != nil {
			return errorResponse(codeOf(err), err.Error())
		}
		return okResponse(nil)
	default:
		return errorResponse("unknown_verb", "unknown verb")
	}
}

func okResponse(st *TunnelStatus) *Response {
	return &Response{Version: ProtocolVersion, OK: true, Status: st}
}

func errorResponse(code, msg string) *Response {
	return &Response{Version: ProtocolVersion, OK: false, Code: code, Error: msg}
}

// codeOf extracts a ProtocolError's stable code, defaulting to "internal".
func codeOf(err error) string {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "internal"
}

// Do is a minimal request/response client round-trip over conn — used by tests and
// callers that speak Go (the Electron main side speaks the same framing in TS).
func Do(conn net.Conn, req *Request) (*Response, error) {
	if err := WriteMessage(conn, req); err != nil {
		return nil, err
	}
	var resp Response
	if err := ReadMessage(conn, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
