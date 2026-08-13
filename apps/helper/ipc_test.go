package helper

import (
	"net"
	"testing"
	"time"
)

// trustedResolver reports a caller path inside /app; PathCheckVerifier{InstallDir:"/app"}
// accepts it. untrustedResolver reports one outside.
func trustedResolver(net.Conn) (string, error)   { return "/app/tunnex", nil }
func untrustedResolver(net.Conn) (string, error) { return "/evil/mal", nil }

func newServer(t *testing.T, be Backend, resolve PeerResolver) (*Server, *Supervisor) {
	t.Helper()
	sup := NewSupervisor(be)
	return NewServer(sup, PathCheckVerifier{InstallDirs: []string{"/app"}}, resolve), sup
}

func req(verb Verb, cfg *TunnelConfig) *Request {
	return &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: verb, Config: cfg}
}

func TestIPCRoundTrip(t *testing.T) {
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	// up
	resp, err := Do(c1, req(VerbTunnelUp, goodConfig()))
	if err != nil || !resp.OK || resp.Status == nil || resp.Status.State != "up" {
		t.Fatalf("up: err=%v resp=%+v", err, resp)
	}
	// status
	resp, err = Do(c1, req(VerbStatus, nil))
	if err != nil || !resp.OK || resp.Status.State != "up" {
		t.Fatalf("status: err=%v resp=%+v", err, resp)
	}
	// down → graceful (restores routing, not a kill-switch)
	resp, err = Do(c1, req(VerbTunnelDown, nil))
	if err != nil || !resp.OK {
		t.Fatalf("down: err=%v resp=%+v", err, resp)
	}
	if sup.State() != StateDown {
		t.Fatalf("want down, got %s", sup.State())
	}
}

// TestIPCSetResolversRoutesAndLeavesTunnelUntouched: set_resolvers reaches the
// resolver reconciler with the desired set and NEVER changes tunnel state or
// ownership (the S8.4 kill-switch/revocation-untouched probe).
func TestIPCSetResolversRoutesAndLeavesTunnelUntouched(t *testing.T) {
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	var got []ResolverForward
	called := 0
	srv.resolvers = func(r []ResolverForward) error { called++; got = r; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	// Bring the tunnel up so we can prove set_resolvers doesn't disturb it.
	if resp, err := Do(c1, req(VerbTunnelUp, goodConfig())); err != nil || !resp.OK {
		t.Fatalf("up: err=%v resp=%+v", err, resp)
	}
	want := []ResolverForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetResolvers, Resolvers: want})
	if err != nil || !resp.OK {
		t.Fatalf("set_resolvers: err=%v resp=%+v", err, resp)
	}
	if called != 1 || len(got) != 1 || got[0] != want[0] {
		t.Fatalf("reconciler not called with the desired set: called=%d got=%+v", called, got)
	}
	if sup.State() != StateUp {
		t.Fatalf("set_resolvers disturbed the tunnel: state=%s", sup.State())
	}
}

// TestIPCSetResolversErrorIsTypedTunnelUntouched: a reconcile failure returns the
// typed code and leaves the tunnel UP — fail-static, DNS forwarding is never
// load-bearing for the tunnel.
func TestIPCSetResolversErrorIsTypedTunnelUntouched(t *testing.T) {
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	srv.resolvers = func([]ResolverForward) error { return &ProtocolError{Code: "resolver_write_failed", Msg: "boom"} }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()
	if resp, err := Do(c1, req(VerbTunnelUp, goodConfig())); err != nil || !resp.OK {
		t.Fatalf("up: err=%v resp=%+v", err, resp)
	}
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetResolvers, Resolvers: []ResolverForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}})
	if err != nil {
		t.Fatalf("io: %v", err)
	}
	if resp.OK || resp.Code != "resolver_write_failed" {
		t.Fatalf("want typed failure, got %+v", resp)
	}
	if sup.State() != StateUp {
		t.Fatalf("failed set_resolvers disturbed the tunnel: state=%s", sup.State())
	}
}

// TestIPCResolversRejectedOnOtherVerbs: a resolvers payload smuggled onto a non-
// set_resolvers verb is rejected by the envelope validator (no resolver write on
// tunnel_down).
func TestIPCResolversRejectedOnOtherVerbs(t *testing.T) {
	srv, _ := newServer(t, &fakeBackend{}, trustedResolver)
	called := 0
	srv.resolvers = func([]ResolverForward) error { called++; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbTunnelDown, Resolvers: []ResolverForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}})
	if err != nil {
		t.Fatalf("io: %v", err)
	}
	if resp.OK || resp.Code != "unexpected_resolvers" {
		t.Fatalf("want unexpected_resolvers, got %+v", resp)
	}
	if called != 0 {
		t.Fatalf("reconciler ran for a non-set_resolvers verb")
	}
}

// TestIPCSetAllowedIPsRoutesAndTunnelUntouched (S8.5 Slice 2a) — set_allowed_ips reaches the live-apply
// with the desired set and NEVER changes tunnel state or ownership (the kill-switch-untouched probe).
func TestIPCSetAllowedIPsRoutesAndTunnelUntouched(t *testing.T) {
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	var got []string
	called := 0
	srv.setAllowedIPs = func(a []string) error { called++; got = a; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	if resp, err := Do(c1, req(VerbTunnelUp, goodConfig())); err != nil || !resp.OK {
		t.Fatalf("up: err=%v resp=%+v", err, resp)
	}
	want := []string{"10.0.0.0/16", "192.168.1.0/24"}
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetAllowedIPs, AllowedIPs: want})
	if err != nil || !resp.OK {
		t.Fatalf("set_allowed_ips: err=%v resp=%+v", err, resp)
	}
	if called != 1 || len(got) != 2 {
		t.Fatalf("live-apply not routed with the desired set: called=%d got=%v", called, got)
	}
	if sup.State() != StateUp {
		t.Fatalf("set_allowed_ips disturbed the tunnel: state=%s", sup.State())
	}
}

// TestIPCAllowedIPsRejectedOnOtherVerbs (S8.5 Slice 2a) — an allowed_ips payload smuggled onto a non-
// set_allowed_ips verb is rejected by the envelope validator (no routing change on tunnel_down).
func TestIPCAllowedIPsRejectedOnOtherVerbs(t *testing.T) {
	srv, _ := newServer(t, &fakeBackend{}, trustedResolver)
	called := 0
	srv.setAllowedIPs = func([]string) error { called++; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbTunnelDown, AllowedIPs: []string{"10.0.0.0/16"}})
	if err != nil {
		t.Fatalf("io: %v", err)
	}
	if resp.OK || resp.Code != "unexpected_allowed_ips" {
		t.Fatalf("want unexpected_allowed_ips, got %+v", resp)
	}
	if called != 0 {
		t.Fatalf("must not apply for a non-set_allowed_ips verb")
	}
}

// TestIPCSetGatewayPeerRoutesAndTunnelUntouched (WF-A) — set_gateway_peer reaches the swap with the new
// peer + endpoint and NEVER changes tunnel state or ownership (the kill-switch-untouched probe).
func TestIPCSetGatewayPeerRoutesAndTunnelUntouched(t *testing.T) {
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	var gotKey, gotEP string
	called := 0
	srv.setGatewayPeer = func(k, ep string) error { called++; gotKey, gotEP = k, ep; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	cfg := goodConfig()
	cfg.FullTunnel = false
	cfg.AllowedIPs = []string{"10.99.0.0/24"}
	if resp, err := Do(c1, req(VerbTunnelUp, cfg)); err != nil || !resp.OK {
		t.Fatalf("up: err=%v resp=%+v", err, resp)
	}
	const newKey = "bBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetGatewayPeer, GatewayPeer: &GatewayPeer{PeerPublicKey: newKey, Endpoint: "gw-b.example:51820"}})
	if err != nil || !resp.OK {
		t.Fatalf("set_gateway_peer: err=%v resp=%+v", err, resp)
	}
	if called != 1 || gotKey != newKey || gotEP != "gw-b.example:51820" {
		t.Fatalf("swap not routed: called=%d key=%q ep=%q", called, gotKey, gotEP)
	}
	if sup.State() != StateUp {
		t.Fatalf("set_gateway_peer disturbed the tunnel: state=%s", sup.State())
	}
}

// TestIPCGatewayPeerRejectedOnOtherVerbs (WF-A) — a gateway_peer smuggled onto a non-set_gateway_peer verb
// is rejected by the envelope validator (no peer swap on tunnel_down).
func TestIPCGatewayPeerRejectedOnOtherVerbs(t *testing.T) {
	srv, _ := newServer(t, &fakeBackend{}, trustedResolver)
	called := 0
	srv.setGatewayPeer = func(string, string) error { called++; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()
	resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbTunnelDown, GatewayPeer: &GatewayPeer{PeerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "gw-b.example:51820"}})
	if err != nil {
		t.Fatalf("io: %v", err)
	}
	if resp.OK || resp.Code != "unexpected_gateway_peer" {
		t.Fatalf("want unexpected_gateway_peer, got %+v", resp)
	}
	if called != 0 {
		t.Fatalf("must not swap for a non-set_gateway_peer verb")
	}
}

// TestIPCGatewayPeerRequiredAndValidated (WF-A) — set_gateway_peer with no peer is rejected
// (gateway_peer_required); a bad key / unsafe endpoint is rejected as strictly as a tunnel_up peer.
func TestIPCGatewayPeerRequiredAndValidated(t *testing.T) {
	srv, _ := newServer(t, &fakeBackend{}, trustedResolver)
	called := 0
	srv.setGatewayPeer = func(string, string) error { called++; return nil }
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	// missing gateway_peer
	if resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetGatewayPeer}); err != nil {
		t.Fatalf("io: %v", err)
	} else if resp.OK || resp.Code != "gateway_peer_required" {
		t.Fatalf("want gateway_peer_required, got %+v", resp)
	}
	// bad key
	if resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetGatewayPeer, GatewayPeer: &GatewayPeer{PeerPublicKey: "not-base64", Endpoint: "gw-b.example:51820"}}); err != nil {
		t.Fatalf("io: %v", err)
	} else if resp.OK || resp.Code != "bad_peer_key" {
		t.Fatalf("want bad_peer_key, got %+v", resp)
	}
	// unsafe endpoint (loopback host barred by validEndpoint)
	if resp, err := Do(c1, &Request{Version: ProtocolVersion, AuthMode: AuthModePathCheck, Verb: VerbSetGatewayPeer, GatewayPeer: &GatewayPeer{PeerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "127.0.0.1:51820"}}); err != nil {
		t.Fatalf("io: %v", err)
	} else if resp.OK || resp.Code != "bad_endpoint" {
		t.Fatalf("want bad_endpoint, got %+v", resp)
	}
	if called != 0 {
		t.Fatalf("no swap must reach the backend on a rejected envelope: called=%d", called)
	}
}

func TestIPCUntrustedCallerRejected(t *testing.T) {
	srv, _ := newServer(t, &fakeBackend{}, untrustedResolver)
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	// The server proactively writes a rejection before reading anything, so we READ.
	var resp Response
	if err := ReadMessage(c1, &resp); err != nil {
		t.Fatalf("read rejection: %v", err)
	}
	if resp.OK || resp.Code != "caller_untrusted" {
		t.Fatalf("want caller_untrusted rejection, got %+v", resp)
	}
}

func TestIPCBadConfigRejectedNoTunnel(t *testing.T) {
	be := &fakeBackend{}
	srv, sup := newServer(t, be, trustedResolver)
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	defer c1.Close()

	bad := goodConfig()
	bad.PrivateKey = "AAAA" // too short
	resp, err := Do(c1, req(VerbTunnelUp, bad))
	if err != nil || resp.OK || resp.Code != "bad_private_key" {
		t.Fatalf("want bad_private_key, got err=%v resp=%+v", err, resp)
	}
	// Nothing touched the backend; still down.
	if be.up != 0 || sup.State() != StateDown {
		t.Fatalf("bad config must not reach the backend: up=%d state=%s", be.up, sup.State())
	}
}

func TestIPCNonOwnerCloseKeepsTunnel(t *testing.T) {
	// Connection A owns the tunnel; a benign connection B closing must NOT tear it
	// down (the owner-tracking fix — any-close-fails-closed was the reported bug).
	srv, sup := newServer(t, &fakeBackend{}, trustedResolver)
	ca1, ca2 := net.Pipe()
	go srv.handle(ca2)
	defer ca1.Close()
	if resp, err := Do(ca1, req(VerbTunnelUp, goodConfig())); err != nil || !resp.OK {
		t.Fatalf("A up: %v %+v", err, resp)
	}

	cb1, cb2 := net.Pipe()
	go srv.handle(cb2)
	if resp, err := Do(cb1, req(VerbStatus, nil)); err != nil || !resp.OK {
		t.Fatalf("B status: %v %+v", err, resp)
	}
	cb1.Close()                        // non-owner closes
	time.Sleep(100 * time.Millisecond) // let B's onClose run

	// A's tunnel must still be up; prove it over A's own still-open connection.
	resp, err := Do(ca1, req(VerbStatus, nil))
	if err != nil || !resp.OK || resp.Status.State != "up" {
		t.Fatalf("owner tunnel must survive a non-owner close: err=%v resp=%+v state=%s", err, resp, sup.State())
	}
}

func TestIPCPeerLossFailsClosed(t *testing.T) {
	be := &fakeBackend{fc: make(chan struct{}, 1)}
	srv, sup := newServer(t, be, trustedResolver)
	c1, c2 := net.Pipe()
	go srv.handle(c2)

	if resp, err := Do(c1, req(VerbTunnelUp, goodConfig())); err != nil || !resp.OK {
		t.Fatalf("up: %v %+v", err, resp)
	}
	// App dies: drop the controlling connection while the tunnel is up.
	c1.Close()

	select {
	case <-be.fc:
		// FailClosed fired.
	case <-time.After(2 * time.Second):
		t.Fatal("peer loss did not fail closed within 2s")
	}
	if sup.State() != StateFailed {
		t.Fatalf("want failed after peer loss, got %s", sup.State())
	}
}

// orphanedForTest reads the orphan flag under the lock (race-safe). The lock also
// serializes against an in-flight OnPeerLost, so a caller that first waits on the fc
// signal is guaranteed to observe the flag OnPeerLost set after FailClosed.
func (s *Supervisor) orphanedForTest() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.orphaned
}

// TestIPCClosedSocketIsDefinitive: a CLOSED owner socket (app process gone) must mark
// the supervisor orphaned → the SHORT dead-man window (review #1's definitive path).
func TestIPCClosedSocketIsDefinitive(t *testing.T) {
	be := &fakeBackend{fc: make(chan struct{}, 1)}
	srv, sup := newServer(t, be, trustedResolver)
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	if resp, err := Do(c1, req(VerbTunnelUp, fullConfig())); err != nil || !resp.OK {
		t.Fatalf("up: %v %+v", err, resp)
	}
	c1.Close() // socket closes → EOF on the server read → definitive
	select {
	case <-be.fc:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not fail closed within 2s")
	}
	if !sup.orphanedForTest() {
		t.Fatal("a closed owner socket must mark orphaned (short window)")
	}
}

// TestIPCReadTimeoutIsNotDefinitive: a wedged-but-connected owner trips the read
// deadline WITHOUT closing the socket — it must fail closed but NOT be orphaned, so it
// keeps the conservative full window (the fail-open the review flagged as #1).
func TestIPCReadTimeoutIsNotDefinitive(t *testing.T) {
	be := &fakeBackend{fc: make(chan struct{}, 1)}
	srv, sup := newServer(t, be, trustedResolver)
	srv.readTimeout = 50 * time.Millisecond // wedge trips fast for the test
	c1, c2 := net.Pipe()
	defer c1.Close()
	go srv.handle(c2)
	if resp, err := Do(c1, req(VerbTunnelUp, fullConfig())); err != nil || !resp.OK {
		t.Fatalf("up: %v %+v", err, resp)
	}
	// Do NOT send anything more + do NOT close: the server's next read times out.
	select {
	case <-be.fc:
	case <-time.After(2 * time.Second):
		t.Fatal("read timeout did not fail closed within 2s")
	}
	if sup.State() != StateFailed {
		t.Fatalf("timeout must fail closed, got %s", sup.State())
	}
	if sup.orphanedForTest() {
		t.Fatal("a read-timeout (socket still open) must NOT be orphaned — keep the full window")
	}
}

// TestIPCFailedUpOwnsConnection: a bring-up that FAILS still arms the kill-switch, so the
// attempting connection must be OWNED — a later force-quit (socket close) then gets the
// short orphan window instead of blackholing for the full window (review #3).
func TestIPCFailedUpOwnsConnection(t *testing.T) {
	be := &fakeBackend{upErr: &ProtocolError{Code: "x", Msg: "endpoint down"}}
	srv, sup := newServer(t, be, trustedResolver)
	c1, c2 := net.Pipe()
	go srv.handle(c2)
	// Up FAILS → StateFailed, kill-switch armed, but the response is not OK.
	if resp, err := Do(c1, req(VerbTunnelUp, fullConfig())); err != nil || resp.OK {
		t.Fatalf("expected a failed up: err=%v resp=%+v", err, resp)
	}
	if sup.State() != StateFailed {
		t.Fatalf("failed up must be StateFailed, got %s", sup.State())
	}
	c1.Close() // force-quit after a failed connect → definitive close
	deadline := time.Now().Add(2 * time.Second)
	for !sup.orphanedForTest() {
		if time.Now().After(deadline) {
			t.Fatal("closing a failed-up owner must mark orphaned (short window), not wait the full one")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
