package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

type fakeBackend struct {
	mu        sync.Mutex
	peers     []Peer
	routes    []string
	srcHint   string
	stats     []PeerStat
	statsErr  error
	applyN    int
	configErr error
}

func (f *fakeBackend) setConfigErr(e error) { f.mu.Lock(); f.configErr = e; f.mu.Unlock() }
func (f *fakeBackend) Configure(context.Context, InterfaceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.configErr
}
func (f *fakeBackend) applyCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.applyN }
func (f *fakeBackend) appliedRoutes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.routes...)
}
func (f *fakeBackend) ApplyRoutes(_ context.Context, cidrs []string, srcHint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = append([]string(nil), cidrs...)
	f.srcHint = srcHint
	return nil
}
func (f *fakeBackend) appliedSrcHint() string { f.mu.Lock(); defer f.mu.Unlock(); return f.srcHint }
func (f *fakeBackend) setStat(s PeerStat) {
	f.mu.Lock()
	f.stats = []PeerStat{s}
	f.statsErr = nil
	f.mu.Unlock()
}
func (f *fakeBackend) setStatsErr(e error) { f.mu.Lock(); f.statsErr = e; f.mu.Unlock() }
func (f *fakeBackend) Stats(context.Context) ([]PeerStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	return append([]PeerStat(nil), f.stats...), nil
}

func (f *fakeBackend) Close(context.Context) error { return nil } // WF-C Layer 1: no-op fake teardown
func (f *fakeBackend) Peers(context.Context) ([]Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// R2 fixture-fidelity: the kernel/`wg show dump` read path CANNOT know SiteLink, so the fake must not
	// either — strip it on read (a test double must not be more capable than the real substrate).
	out := make([]Peer, len(f.peers))
	for i, p := range f.peers {
		p.SiteLink = false
		out[i] = p
	}
	return out, nil
}
func (f *fakeBackend) ApplyPeers(_ context.Context, p []Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = append([]Peer(nil), p...)
	f.applyN++
	return nil
}

// roam simulates the real device OBSERVING a peer's endpoint change (a client's
// NAT source port rebinding) — what Peers() would then report back.
func (f *fakeBackend) roam(pubKey, endpoint string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.peers {
		if f.peers[i].PublicKey == pubKey {
			f.peers[i].Endpoint = endpoint
		}
	}
}
func (f *fakeBackend) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.peers)
}

// appliedPeers returns the peers as APPLIED (with AllowedIPs intact — unlike Peers() which strips SiteLink
// to mimic the kernel read). For asserting the agent applies the CP's AllowedIPs verbatim.
func (f *fakeBackend) appliedPeers() []Peer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Peer(nil), f.peers...)
}

type fakeClient struct {
	mu       sync.Mutex
	desired  DesiredState
	fetchErr error
	watch    chan struct{}
}

func (c *fakeClient) set(ds DesiredState) { c.mu.Lock(); c.desired = ds; c.mu.Unlock() }
func (c *fakeClient) setErr(e error)      { c.mu.Lock(); c.fetchErr = e; c.mu.Unlock() }
func (c *fakeClient) FetchDesired(context.Context) (DesiredState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.desired, c.fetchErr
}
func (c *fakeClient) Watch(ctx context.Context, _ uint64) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.watch:
		return nil
	}
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var p1 = Peer{PublicKey: "k1", AllowedIPs: []string{"10.0.0.1/32"}}
var p2 = Peer{PublicKey: "k2", AllowedIPs: []string{"10.0.0.2/32"}}

// TestReconcileIgnoresRoamedEndpoint is the WS1 regression for the POC-surfaced
// bug: a roaming client's observed endpoint changes every reconcile, and the old
// dirty-check (canon included the endpoint) re-fired ApplyPeers each time — whose
// empty-[Interface] syncconf then wiped the interface key + port. After the fix,
// only stable identity (pubkey + allowed-ips) drives convergence, so consecutive
// reconciles over a roaming peer are byte-stable no-ops.
func TestReconcileIgnoresRoamedEndpoint(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	ctx := context.Background()
	// A control-plane desired peer carries NO endpoint (clients roam).
	desired := []Peer{{PublicKey: "k1", AllowedIPs: []string{"10.99.0.2/32"}}}

	// Cycle 1 applies.
	if changed, _ := r.Reconcile(ctx, desired); !changed || b.applyCount() != 1 {
		t.Fatalf("cycle 1 should apply once, applyN=%d", b.applyCount())
	}
	// The device now REPORTS the peer with a roamed NAT endpoint.
	b.roam("k1", "203.0.113.9:41000")
	// Cycle 2: only the roamed endpoint differs → MUST be a no-op (no re-apply).
	if changed, _ := r.Reconcile(ctx, desired); changed || b.applyCount() != 1 {
		t.Fatalf("roamed endpoint must NOT re-apply (would wipe key+port): changed=%v applyN=%d", changed, b.applyCount())
	}
	// Cycle 3: endpoint roams again → still a stable no-op.
	b.roam("k1", "203.0.113.9:55555")
	if changed, _ := r.Reconcile(ctx, desired); changed || b.applyCount() != 1 {
		t.Fatalf("further roam must stay a no-op: applyN=%d", b.applyCount())
	}
}

// TestRunOnceProgramsAndPrunesSiteRoutes — S8.2 Slice-2 agent red: the reconcile loop programs the
// kernel routes carried in Policy.Routes (explicit intent, NEVER inferred from peer AllowedIPs), and a
// subsequent fetch carrying fewer routes shrinks the delivered set — the full-sweep contract (a site
// unbind drops its route). A nil Policy (mesh) clears routes.
func TestRunOnceProgramsAndPrunesSiteRoutes(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	ctx := context.Background()
	c := &fakeClient{watch: make(chan struct{})}

	c.set(DesiredState{Policy: &nodepolicy.Compiled{
		Version: 5, Mode: nodepolicy.ModeEnforcing,
		Routes: []nodepolicy.Route{{DstCIDR: "10.2.0.0/24"}, {DstCIDR: "10.3.0.0/24"}},
	}})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if got := b.appliedRoutes(); len(got) != 2 {
		t.Fatalf("both site routes must be programmed, got %v", got)
	}
	// A site unbind: the next fetch drops 10.3.0.0/24 → the desired set shrinks → prune.
	c.set(DesiredState{Policy: &nodepolicy.Compiled{
		Version: 5, Mode: nodepolicy.ModeEnforcing, Routes: []nodepolicy.Route{{DstCIDR: "10.2.0.0/24"}},
	}})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce 2: %v", err)
	}
	if got := b.appliedRoutes(); len(got) != 1 || got[0] != "10.2.0.0/24" {
		t.Fatalf("the dropped route must be pruned (full-sweep), got %v", got)
	}
	// nil Policy (mesh) → routes cleared.
	c.set(DesiredState{})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce 3: %v", err)
	}
	if got := b.appliedRoutes(); len(got) != 0 {
		t.Fatalf("nil policy must clear routes, got %v", got)
	}
}

// TestRunOnceDerivesSrcHintAndUnreachableSignal — S8.2c D2/D3: the src-derivation is enumerated ONCE per
// tick in the reconcile loop (review #6 — not re-enumerated inside the backend). Proves runOnce (a) threads
// the host addr inside an approved local subnet to the backend as the route srcHint (D2), and (b) flips the
// siteSubnetUnreachable sink when a local subnet is advertised but no host addr is inside it (D3), and clears
// it once a match exists — INDEPENDENT of link state. hostAddrsFn is the injected seam (no real interfaces).
func TestRunOnceDerivesSrcHintAndUnreachableSignal(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	var sink atomic.Bool
	r.SetSiteSubnetUnreachableSink(&sink)
	ctx := context.Background()
	c := &fakeClient{watch: make(chan struct{})}

	// Host is ON the advertised subnet → src-hint threaded, NOT unreachable.
	r.hostAddrsFn = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("172.31.24.206")}
	}
	c.set(DesiredState{Policy: &nodepolicy.Compiled{
		Version: 5, Mode: nodepolicy.ModeEnforcing,
		Routes: []nodepolicy.Route{{DstCIDR: "10.2.0.0/24"}}, LocalSubnets: []string{"172.31.0.0/16"},
	}})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if got := b.appliedSrcHint(); got != "172.31.24.206" {
		t.Fatalf("D2: reconcile must thread the local-subnet host addr as srcHint, got %q", got)
	}
	if sink.Load() {
		t.Fatal("D3: host IS on the advertised subnet → must NOT be unreachable")
	}

	// Same advertisement, host NO LONGER on it (bridge-trapped) → no src-hint, sink flips ON.
	r.hostAddrsFn = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.99.0.1")} }
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce 2: %v", err)
	}
	if got := b.appliedSrcHint(); got != "" {
		t.Fatalf("D2: no host addr in the advertised subnet → empty srcHint (never a guess), got %q", got)
	}
	if !sink.Load() {
		t.Fatal("D3: advertised subnet + no host addr inside → UNREACHABLE (the reassuring-green trap)")
	}

	// A match returns → sink clears (recovers without a restart).
	r.hostAddrsFn = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.31.24.206")} }
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce 3: %v", err)
	}
	if sink.Load() {
		t.Fatal("D3: a recovered match must CLEAR the unreachable signal")
	}

	// re-review #5: the common non-site node (no LocalSubnets) must NOT pay the host-addr enumeration
	// syscall — siteRouteSrc discards the addrs on an empty advertisement, so runOnce skips the call.
	called := false
	r.hostAddrsFn = func() []netip.Addr { called = true; return nil }
	c.set(DesiredState{Policy: &nodepolicy.Compiled{Version: 5, Mode: nodepolicy.ModeEnforcing, Routes: []nodepolicy.Route{{DstCIDR: "10.2.0.0/24"}}}})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce 4: %v", err)
	}
	if called {
		t.Fatal("#5: no LocalSubnets → host-addr enumeration must be SKIPPED (no needless syscall per tick)")
	}
	if sink.Load() {
		t.Fatal("no advertised subnet → NOT unreachable")
	}
}

// TestSiteLinkEndpointChangeIsDirty — S8.2 B4 + R2: the ACTUAL peer set comes from the kernel (wg dump)
// and NEVER carries SiteLink; only the DESIRED (CP) side does. A converged site-link peer must be a
// steady-state no-op (the R2 perpetual-dirty regression would fail here); a hub endpoint change must be
// dirty (re-dial); a device peer's roamed endpoint stays ignored.
func TestSiteLinkEndpointChangeIsDirty(t *testing.T) {
	actualHub := Peer{PublicKey: "hub", AllowedIPs: []string{"10.2.0.0/24"}, Endpoint: "old:51820"} // kernel shape: SiteLink=false
	desiredSame := Peer{PublicKey: "hub", AllowedIPs: []string{"10.2.0.0/24"}, Endpoint: "old:51820", SiteLink: true}
	if !peersEqual([]Peer{actualHub}, []Peer{desiredSame}) {
		t.Fatal("R2: a converged site-link peer (actual has no SiteLink) must be a steady-state NO-OP, not perpetually dirty")
	}
	desiredNew := desiredSame
	desiredNew.Endpoint = "new:51820"
	if peersEqual([]Peer{actualHub}, []Peer{desiredNew}) {
		t.Fatal("B4: a site-link peer endpoint change MUST be dirty (spoke re-dials the hub)")
	}
	actualDev := Peer{PublicKey: "dev", AllowedIPs: []string{"10.99.0.5/32"}, Endpoint: "1.2.3.4:5"}
	desiredDev := Peer{PublicKey: "dev", AllowedIPs: []string{"10.99.0.5/32"}, Endpoint: "6.7.8.9:10"} // device: SiteLink=false
	if !peersEqual([]Peer{actualDev}, []Peer{desiredDev}) {
		t.Fatal("a device peer's roamed endpoint must be IGNORED (no re-apply every reconcile)")
	}
}

// TestSiteLinkNatSpokePeerConverges — review #1: a HUB's view of a NAT'd spoke has desired Endpoint=""
// (the spoke dials the hub, never vice versa). Once the spoke handshakes — now GUARANTEED by the CK
// keepalive — the kernel learns its roamed src endpoint. The B4 endpoint compare must be BLIND when the
// desired endpoint is empty, or the hub churns `wg syncconf` forever (perpetual-dirty). The spoke→hub
// direction (desired endpoint PRESENT) still compares, so a moved hub re-dials.
func TestSiteLinkNatSpokePeerConverges(t *testing.T) {
	// Hub's spoke peer: desired Endpoint="" (NAT'd spoke); actual = kernel-learned roamed src.
	desiredSpoke := Peer{PublicKey: "spoke", AllowedIPs: []string{"10.2.0.0/24"}, SiteLink: true, PersistentKeepalive: 25}
	actualSpoke := Peer{PublicKey: "spoke", AllowedIPs: []string{"10.2.0.0/24"}, Endpoint: "203.0.113.7:41000", PersistentKeepalive: 25} // learned; SiteLink stripped on read
	if !peersEqual([]Peer{actualSpoke}, []Peer{desiredSpoke}) {
		t.Fatal("#1: a hub's NAT'd-spoke peer (desired endpoint empty) must CONVERGE despite a learned roamed endpoint — no perpetual churn")
	}
	// Spoke→hub direction unaffected: a MOVED hub (desired endpoint present + changed) is still dirty (B4).
	desiredHub := Peer{PublicKey: "hub", AllowedIPs: []string{"10.1.0.0/24"}, Endpoint: "new:51820", SiteLink: true, PersistentKeepalive: 25}
	actualHub := Peer{PublicKey: "hub", AllowedIPs: []string{"10.1.0.0/24"}, Endpoint: "old:51820", PersistentKeepalive: 25}
	if peersEqual([]Peer{actualHub}, []Peer{desiredHub}) {
		t.Fatal("B4: a moved hub (desired endpoint present) must stay DIRTY so the spoke re-dials")
	}
}

// TestSiteLinkKeepaliveSignificance — S8.3 CK: keepalive is CP intent on site-link peers, and the kernel
// DOES report it (wg dump), so it must be COMPARED for SiteLink peers (a peer that gained keepalive is
// dirty → re-syncs) yet CONVERGE once applied (no churn — the R2 discipline). A device peer's keepalive is
// never compared. (The buildSyncConf/parseWGDump round-trip is asserted in the linux-tagged routes test.)
func TestSiteLinkKeepaliveSignificance(t *testing.T) {
	// First application: actual (kernel) has no keepalive yet; desired site-link peer wants 25 → DIRTY.
	actualNoKA := Peer{PublicKey: "hub", AllowedIPs: []string{"10.2.0.0/24"}, Endpoint: "h:51820"}
	desiredKA := Peer{PublicKey: "hub", AllowedIPs: []string{"10.2.0.0/24"}, Endpoint: "h:51820", SiteLink: true, PersistentKeepalive: 25}
	if peersEqual([]Peer{actualNoKA}, []Peer{desiredKA}) {
		t.Fatal("CK: a site-link peer that lacks the desired keepalive must be DIRTY (re-sync applies it)")
	}
	// Converged: the kernel now reports keepalive=25 (round-tripped) → steady-state NO-OP.
	actualKA := actualNoKA
	actualKA.PersistentKeepalive = 25 // kernel read carries it; SiteLink stays false (fixture-fidelity)
	if !peersEqual([]Peer{actualKA}, []Peer{desiredKA}) {
		t.Fatal("CK: once keepalive is applied and the kernel reports it, the peer must CONVERGE (no churn)")
	}
	// A device peer's keepalive is never CP-managed → not compared (SiteLink=false).
	devA := Peer{PublicKey: "dev", AllowedIPs: []string{"10.99.0.5/32"}}
	devD := Peer{PublicKey: "dev", AllowedIPs: []string{"10.99.0.5/32"}, PersistentKeepalive: 25}
	if !peersEqual([]Peer{devA}, []Peer{devD}) {
		t.Fatal("a device peer's keepalive must be ignored (SiteLink=false → not compared)")
	}
}

// TestSiteLinkStaleComputation — S8.2 H5 + F2 three-state: cold-start/no-reading → stale; a fresh
// handshake → clears; a TRANSIENT Stats error after a good reading → keep-last (flap-free); an error
// PERSISTING past the window → stale; device peers never drive it.
func TestSiteLinkStaleComputation(t *testing.T) {
	var sink atomic.Bool
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	r.SetSiteLinkStaleSink(&sink)
	ctx := context.Background()
	site := []Peer{{PublicKey: "hub", SiteLink: true}}

	// (1) Cold start: no good reading yet + a site link with no handshake → stale (over-report once).
	r.updateSiteLinkStale(ctx, site)
	if !sink.Load() {
		t.Fatal("cold start with no handshake must be stale")
	}
	// (2) A fresh handshake → not stale (records lastStatsOK).
	b.setStat(PeerStat{PublicKey: "hub", LastHandshake: time.Now().Unix()})
	r.updateSiteLinkStale(ctx, site)
	if sink.Load() {
		t.Fatal("a fresh handshake must clear")
	}
	// (3) TRANSIENT Stats error right after a good reading → KEEP last value (F2 flap-free): stays clear.
	b.setStatsErr(errors.New("wg dump blip"))
	r.updateSiteLinkStale(ctx, site)
	if sink.Load() {
		t.Fatal("F2: a transient Stats error within the window must KEEP the last value (no flap)")
	}
	// (4) Error PERSISTING past the staleness window → stale.
	r.lastStatsOK = time.Now().Add(-2 * siteLinkStaleWindow)
	r.updateSiteLinkStale(ctx, site)
	if !sink.Load() {
		t.Fatal("F2: a Stats error persisting past the window must go stale")
	}
	// (5) Device peers only → never stale.
	b.setStat(PeerStat{PublicKey: "x"}) // clears the error
	r.updateSiteLinkStale(ctx, []Peer{{PublicKey: "dev", SiteLink: false}})
	if sink.Load() {
		t.Fatal("device peers must not drive site-link staleness")
	}
}

// TestPeersEqualMultiset — F4/R2: a duplicate-pubkey desired set must NOT mask an unpruned actual peer
// (the map-keyed compare dropped multiset semantics; the sorted-multiset compare catches it).
func TestPeersEqualMultiset(t *testing.T) {
	x := Peer{PublicKey: "X", AllowedIPs: []string{"10.0.0.1/32"}}
	y := Peer{PublicKey: "Y", AllowedIPs: []string{"10.0.0.2/32"}}
	if peersEqual([]Peer{x, y}, []Peer{x, x}) {
		t.Fatal("F4: a duplicate-pubkey desired must not mask an unpruned actual peer Y (multiset)")
	}
}

func TestReconcileAppliesAndIdempotent(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	ctx := context.Background()

	if changed, _ := r.Reconcile(ctx, []Peer{p1}); !changed || b.count() != 1 {
		t.Fatal("first reconcile should apply p1")
	}
	if changed, _ := r.Reconcile(ctx, []Peer{p1}); changed {
		t.Fatal("identical desired must be a no-op (idempotent)")
	}
	// Revocation: empty desired removes the peer.
	if changed, _ := r.Reconcile(ctx, []Peer{}); !changed || b.count() != 0 {
		t.Fatal("empty desired should remove peers")
	}
}

func TestRunOnceDataPlaneIndependence(t *testing.T) {
	b := &fakeBackend{peers: []Peer{p1}}
	r := New(b, "priv", "pub", discard())
	c := &fakeClient{watch: make(chan struct{})}
	c.setErr(errors.New("control plane down"))

	// Control-plane fetch fails -> backend is NOT flushed.
	if _, err := r.runOnce(context.Background(), c); err == nil {
		t.Fatal("expected fetch error")
	}
	if b.count() != 1 {
		t.Fatal("data-plane independence violated: peers flushed on control-plane outage")
	}
	// Recovery -> full resync applies the current desired state.
	c.setErr(nil)
	c.set(DesiredState{Peers: []Peer{p1, p2}})
	if _, err := r.runOnce(context.Background(), c); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if b.count() != 2 {
		t.Fatal("resync did not converge after recovery")
	}
}

func TestRunPushConvergesQuickly(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	c := &fakeClient{watch: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Long interval so only the PUSH path can converge within the window.
	go r.Run(ctx, c, time.Hour, 10*time.Millisecond)

	c.set(DesiredState{Peers: []Peer{p1}})
	start := time.Now()
	c.watch <- struct{}{} // push signal

	waitFor(t, 5*time.Second, func() bool { return b.count() == 1 })
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("push convergence took %v (> 5s)", elapsed)
	}
}

func TestRunIntervalSafetyNet(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	// watch never fires -> only the interval (safety net) can converge.
	c := &fakeClient{watch: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.Run(ctx, c, 20*time.Millisecond, 10*time.Millisecond)

	c.set(DesiredState{Peers: []Peer{p1}})
	waitFor(t, 3*time.Second, func() bool { return b.count() == 1 })
}

// TestDirtyDeviceConvergence proves watch-item (c) at the reconcile layer: a
// device carrying a STALE peer plus a still-correct peer converges to exactly
// the desired set (stale removed, correct kept, new added) and a repeat run is a
// no-op — no re-apply, so unchanged peers never flap.
func TestDirtyDeviceConvergence(t *testing.T) {
	stale := Peer{PublicKey: "gone", AllowedIPs: []string{"10.0.0.9/32"}}
	// Device is dirty: it has a stale peer and the still-correct p1.
	b := &fakeBackend{peers: []Peer{stale, p1}}
	r := New(b, "priv", "pub", discard())
	c := &fakeClient{watch: make(chan struct{})}
	c.set(DesiredState{Peers: []Peer{p1, p2}}) // p1 kept, p2 added, stale dropped

	if _, err := r.runOnce(context.Background(), c); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if !peersEqual(b.peers, []Peer{p1, p2}) {
		t.Fatalf("did not converge to desired set: %+v", b.peers)
	}
	appliesAfterFirst := b.applyCount()

	// Second run against identical desired state must not re-apply (no flap).
	if changed, err := r.runOnce(context.Background(), c); err != nil || changed {
		t.Fatalf("second run should be a no-op: changed=%v err=%v", changed, err)
	}
	if b.applyCount() != appliesAfterFirst {
		t.Fatal("idempotence violated: re-applied an unchanged peer set")
	}
}

// TestHealthyReflectsBackendFailure proves watch-item (d): a backend that cannot
// configure the device (e.g. NET_ADMIN missing, port bound) leaves the agent
// NOT-ready with a diagnosable error — never a silent success. Recovery flips it
// back to ready.
func TestHealthyReflectsBackendFailure(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	c := &fakeClient{watch: make(chan struct{})}
	c.set(DesiredState{Peers: []Peer{p1}})

	if r.Healthy() {
		t.Fatal("should not be healthy before any successful reconcile")
	}
	b.setConfigErr(errors.New("operation not permitted (NET_ADMIN?)"))
	if _, err := r.runOnce(context.Background(), c); err == nil {
		t.Fatal("expected a backend configure error")
	}
	if r.Healthy() {
		t.Fatal("backend failure must leave the agent NOT healthy (not-ready)")
	}
	// Recovery.
	b.setConfigErr(nil)
	if _, err := r.runOnce(context.Background(), c); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !r.Healthy() {
		t.Fatal("healthy should flip true after a fully successful reconcile")
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// TestReconcileAppliesDesiredVerbatimNoLocalPromotion (S8.6 Slice 5 — the absence-proof) — the agent
// applies the CP's peers VERBATIM: a spoke's primary carries the subnets, the standby is keepalive-only
// (EMPTY AllowedIPs), and there is NO agent code path that moves the subnets onto the standby. A spoke
// cannot locally promote a standby (observe-never-vote / CP-single-authority) — the empty-AllowedIPs
// standby stays inert until a NEW CP artifact rewrites it. This is the dead-code assertion inverted:
// failover redirection is impossible spoke-side by the absence of any local-election path.
func TestReconcileAppliesDesiredVerbatimNoLocalPromotion(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	ctx := context.Background()
	desired := []Peer{
		{PublicKey: "primary", AllowedIPs: []string{"172.31.0.0/16"}, Endpoint: "p:51820", SiteLink: true, PersistentKeepalive: 25},
		{PublicKey: "standby", AllowedIPs: []string{}, Endpoint: "s:51820", SiteLink: true, PersistentKeepalive: 25},
	}
	if _, err := r.Reconcile(ctx, desired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var gp, gs *Peer
	for i, p := range b.appliedPeers() {
		if p.PublicKey == "primary" {
			gp = &b.appliedPeers()[i]
		}
		if p.PublicKey == "standby" {
			gs = &b.appliedPeers()[i]
		}
	}
	if gp == nil || len(gp.AllowedIPs) != 1 || gp.AllowedIPs[0] != "172.31.0.0/16" {
		t.Fatalf("primary must keep its subnets verbatim (no local mutation), got %+v", gp)
	}
	if gs == nil || len(gs.AllowedIPs) != 0 {
		t.Fatalf("standby must stay keepalive-only EMPTY — NO local path moves subnets onto it, got %+v", gs)
	}
}

// TestReconcileFailStaticKeepsStandby (S8.6 Slice 5 — case (b), CP-outage fail-static with a standby
// present) — a CP that goes unreachable does NOT perturb the applied peers: the agent keeps its last-known
// config (fail-static, proven since S3.1), and a standby peer in that config doesn't change the behavior.
// The spoke keeps routing to the primary; it does NOT locally fail over to the standby (no CP → no
// re-election, per-spoke — the named residue joining "CP-down = no failover").
func TestReconcileFailStaticKeepsStandby(t *testing.T) {
	b := &fakeBackend{}
	r := New(b, "priv", "pub", discard())
	c := &fakeClient{watch: make(chan struct{})}
	ctx := context.Background()
	c.set(DesiredState{Peers: []Peer{
		{PublicKey: "primary", AllowedIPs: []string{"172.31.0.0/16"}, Endpoint: "p:51820", SiteLink: true, PersistentKeepalive: 25},
		{PublicKey: "standby", AllowedIPs: []string{}, Endpoint: "s:51820", SiteLink: true, PersistentKeepalive: 25},
	}})
	if _, err := r.runOnce(ctx, c); err != nil {
		t.Fatalf("runOnce (fetch ok): %v", err)
	}
	before := b.appliedPeers()
	// CP unreachable → FetchDesired errors. Fail-static: the agent keeps last-applied, does NOT wipe/redirect.
	c.setErr(errors.New("cp unreachable"))
	if _, err := r.runOnce(ctx, c); err == nil {
		t.Fatal("a fetch error must surface (fail-static, not silent)")
	}
	after := b.appliedPeers()
	if len(after) != len(before) {
		t.Fatalf("fail-static: a CP outage must NOT change the applied peers (a standby present is unperturbed), got %d want %d", len(after), len(before))
	}
	// The primary still carries the subnets; nothing locally moved them to the standby.
	for _, p := range after {
		if p.PublicKey == "standby" && len(p.AllowedIPs) != 0 {
			t.Fatalf("under a CP outage the standby must stay empty — NO local failover, got %+v", p)
		}
	}
}

// TestOVPNPushRoutesUnion is the WF-OVPN-11 red: the OVPN push route-set is Routes ∪ LocalSubnets — the
// same reachable set a WG client assembles from routed-ranges (one truth, two delivery mechanisms). It
// pins the parity half (LocalSubnets ARE pushed, so an OVPN client reaches the LAN behind its own gateway)
// and the zero-config golden (no local subnets → identical to remote-Routes-only; nil policy → nothing).
func TestOVPNPushRoutesUnion(t *testing.T) {
	// Routes (remote sites) ∪ LocalSubnets (this gateway's own LAN) — both present.
	p := &nodepolicy.Compiled{
		Routes:       []nodepolicy.Route{{DstCIDR: "10.0.0.0/16"}},
		LocalSubnets: []string{"172.31.0.0/16"},
	}
	got := OVPNPushRoutes(p)
	has := func(c string) bool {
		for _, r := range got {
			if r == c {
				return true
			}
		}
		return false
	}
	if !has("10.0.0.0/16") {
		t.Fatalf("remote Route must be pushed; got %v", got)
	}
	if !has("172.31.0.0/16") {
		t.Fatalf("WF-OVPN-11: this gateway's LocalSubnet must be pushed (reach the LAN behind your own gateway); got %v", got)
	}

	// Zero-config golden: a gateway with NO local subnets pushes exactly its remote Routes — identical to
	// pre-fold (no behavior change where there is no local LAN to advertise).
	remoteOnly := OVPNPushRoutes(&nodepolicy.Compiled{Routes: []nodepolicy.Route{{DstCIDR: "10.0.0.0/16"}}})
	if len(remoteOnly) != 1 || remoteOnly[0] != "10.0.0.0/16" {
		t.Fatalf("no-local-subnet gateway must push only its remote Routes (zero-config golden); got %v", remoteOnly)
	}

	// nil policy → nil (no push lines).
	if OVPNPushRoutes(nil) != nil {
		t.Fatalf("nil policy must push nothing; got %v", OVPNPushRoutes(nil))
	}

	// Parity assertion (the cheaply-expressible half): the pushed set is EXACTLY Routes ∪ LocalSubnets,
	// which by construction equals the org's approved site subnets a WG client receives via routed-ranges
	// (sites.ListRoutedRanges) for the same gateway. The cross-mechanism wire equality is walk-proven (WG
	// reached 172.31.x; OVPN reaches it once this ships).
	if len(got) != len(p.Routes)+len(p.LocalSubnets) {
		t.Fatalf("pushed set must be exactly Routes ∪ LocalSubnets (no drops, no dupes) when no K8s VIPs; got %v", got)
	}
}

// TestOVPNPushRoutesK8s — S10.3 fork-1 (WF-OVPN-11's K8s twin): an OVPN client must reach the exposed
// Services of the cluster this gateway fronts, else OpenVPN inherits the client gap the moment WireGuard's is
// closed. The push includes each exposed Service VIP /32 AND the reserved DNS VIP /32 (the SAME artifact data
// the DNAT + DNS answer use). Zero-config: a non-cluster gateway pushes nothing K8s.
func TestOVPNPushRoutesK8s(t *testing.T) {
	p := &nodepolicy.Compiled{
		VIPMappings: []nodepolicy.VIPMapping{{VIP: "100.64.0.5", DNSName: "api.prod.svc.prod.k8s.acme.com"}},
		K8sDNSZones: []nodepolicy.K8sDNSZone{{ListenVIP: "100.64.0.2", Zone: "prod.k8s.acme.com"}},
	}
	got := OVPNPushRoutes(p)
	has := func(c string) bool {
		for _, r := range got {
			if r == c {
				return true
			}
		}
		return false
	}
	if !has("100.64.0.5/32") {
		t.Fatalf("the exposed Service VIP must be pushed as a /32 route; got %v", got)
	}
	if !has("100.64.0.2/32") {
		t.Fatalf("the reserved DNS VIP must be pushed as a /32 route (so the client reaches the resolver); got %v", got)
	}
	// Zero-config golden: a non-cluster gateway (no VIP map, no DNS zones) pushes NOTHING K8s.
	if OVPNPushRoutes(&nodepolicy.Compiled{Routes: []nodepolicy.Route{{DstCIDR: "10.0.0.0/16"}}})[0] != "10.0.0.0/16" {
		t.Fatal("a non-cluster gateway's push must be byte-identical to pre-fork")
	}
	if len(OVPNPushRoutes(&nodepolicy.Compiled{Routes: []nodepolicy.Route{{DstCIDR: "10.0.0.0/16"}}})) != 1 {
		t.Fatal("a non-cluster gateway pushes only its site routes, no K8s /32s")
	}
}
