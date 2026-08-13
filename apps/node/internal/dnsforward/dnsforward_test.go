package dnsforward

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeListener is an injectable udpListener for the F1 bind-reconcile red — no real sockets. ReadFrom
// blocks until Close (so serveConn's reader exits cleanly when its listener is cancelled).
type fakeListener struct {
	closed atomic.Bool
	done   chan struct{}
}

func newFakeListener() *fakeListener { return &fakeListener{done: make(chan struct{})} }
func (l *fakeListener) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	<-l.done
	return 0, netip.AddrPort{}, errors.New("closed")
}
func (l *fakeListener) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	return len(b), nil
}
func (l *fakeListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
	}
	return nil
}

// TestServeBindReconcileLifecycle (F1) — the forwarder binds when wg0 APPEARS after start (not at boot,
// where wg0 doesn't exist yet), re-binds after an address flap, and closes listeners when the interface
// goes. Drives reconcileBinds directly across interface states with injected seams.
func TestServeBindReconcileLifecycle(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { return nil, nil })
	var mu sync.Mutex
	var addrs []netip.Addr
	setAddrs := func(a ...netip.Addr) { mu.Lock(); addrs = a; mu.Unlock() }
	ifaceUp := false // false = wg0 not found (InterfaceByName errors); true = wg0 present (addrs may be empty)
	src := func(string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if !ifaceUp {
			return nil, errWGIfaceNotFound // wg0 absent (boot / removed) → close (the F1 topology + RR1 guard)
		}
		return append([]netip.Addr(nil), addrs...), nil // present: a SUCCESSFUL read (possibly empty)
	}
	opened := map[netip.Addr]*fakeListener{}
	var olMu sync.Mutex
	lst := func(a netip.Addr) (udpListener, error) {
		l := newFakeListener()
		olMu.Lock()
		opened[a] = l
		olMu.Unlock()
		return l, nil
	}
	waitClosed := func(a netip.Addr) {
		for i := 0; i < 200; i++ {
			olMu.Lock()
			l := opened[a]
			olMu.Unlock()
			if l != nil && l.closed.Load() {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("listener for %v never closed", a)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	live := map[netip.Addr]context.CancelFunc{}
	a1 := netip.MustParseAddr("10.99.0.2")
	a2 := netip.MustParseAddr("10.99.0.7")

	// 1) wg0 absent at boot → NO bind (the F1 bug was a bind-once here that died forever).
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if len(live) != 0 {
		t.Fatal("must not bind before wg0 exists")
	}
	// 2) wg0 appears → bind a1.
	mu.Lock()
	ifaceUp = true
	mu.Unlock()
	setAddrs(a1)
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if _, ok := live[a1]; !ok {
		t.Fatal("must bind once wg0 appears (the F1 fix)")
	}
	// 3) flap a1 → a2: a1 closes, a2 binds.
	setAddrs(a2)
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if _, ok := live[a1]; ok {
		t.Fatal("stale a1 listener must close on flap")
	}
	if _, ok := live[a2]; !ok {
		t.Fatal("must re-bind to a2 after flap")
	}
	waitClosed(a1)
	// 4) addresses removed (wg0 up but addressless — a SUCCESSFUL empty read) → all listeners close.
	// (A transient InterfaceByName ERROR is the separate R6 case and must NOT close — see that red.)
	setAddrs()
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if len(live) != 0 {
		t.Fatal("a successful empty address read closes every listener")
	}
	waitClosed(a2)
}

// TestReconcileBindsTrichotomy (S8.4 RR1) — error is NOT one thing. A TRANSIENT error (interface exists,
// addrs unreadable) KEEPS the listeners; interface-NOT-FOUND (wg0 gone) CLOSES them (the open-resolver
// guard); a successful EMPTY read CLOSES them. Collapsing not-found into "keep" leaks a :53 listener on a
// departed wg0 address (the RR1 regression); collapsing transient into "close" blips DNS on a glitch (R6).
func TestReconcileBindsTrichotomy(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { return nil, nil })
	a1 := netip.MustParseAddr("10.99.0.2")
	mode := "ok"
	src := func(string) ([]netip.Addr, error) {
		switch mode {
		case "transient":
			return nil, errors.New("transient Addrs read glitch") // iface exists, addrs unreadable → KEEP
		case "notfound":
			return nil, errWGIfaceNotFound // wg0 removed → CLOSE (security)
		case "empty":
			return nil, nil // successful read, no addresses → CLOSE
		default:
			return []netip.Addr{a1}, nil
		}
	}
	lst := func(netip.Addr) (udpListener, error) { return newFakeListener(), nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// (2) transient error keeps the listener.
	live := map[netip.Addr]context.CancelFunc{}
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if _, ok := live[a1]; !ok {
		t.Fatal("a1 must bind")
	}
	mode = "transient"
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if _, ok := live[a1]; !ok {
		t.Fatal("a transient error must KEEP the listener (availability half)")
	}
	// (1) interface not-found CLOSES the listener (the open-resolver guard — RR1 leak scenario).
	mode = "notfound"
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if len(live) != 0 {
		t.Fatal("wg0 gone (not-found) must CLOSE the listener, not leak it on the departed address")
	}
	// (3) successful empty read CLOSES.
	mode = "ok"
	f.reconcileBinds(ctx, src, lst, "wg0", live) // re-bind
	if _, ok := live[a1]; !ok {
		t.Fatal("a1 must re-bind")
	}
	mode = "empty"
	f.reconcileBinds(ctx, src, lst, "wg0", live)
	if len(live) != 0 {
		t.Fatal("a successful empty address read must close the listeners")
	}
}

// TestBucketEvictionBounded (F7) — idle rate-limit buckets are swept so a source-address flood can't grow
// the map without bound (OOM → tunnel-down). 1000 idle sources collapse to ~1 after a sweep pass.
func TestBucketEvictionBounded(t *testing.T) {
	base := time.Unix(0, 0)
	cur := base
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { return []byte{0}, nil })
	f.now = func() time.Time { return cur }
	f.SetTable([]Entry{{Domain: "corp.local", ResolverIP: "10.0.0.53"}})
	q := mkQuery("nas.corp.local.")
	for i := 0; i < 1000; i++ {
		f.handle(q, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 5}))
	}
	f.mu.Lock()
	before := len(f.buckets)
	f.mu.Unlock()
	if before < 900 {
		t.Fatalf("expected ~1000 buckets before eviction, got %d", before)
	}
	// Advance past the idle TTL + a sweep interval; the next query triggers the sweep.
	cur = base.Add(bucketIdleTTL + bucketSweepEvery + time.Second)
	f.handle(q, netip.MustParseAddr("10.200.200.200"))
	f.mu.Lock()
	after := len(f.buckets)
	f.mu.Unlock()
	if after > 1 {
		t.Fatalf("idle buckets must be evicted; map still holds %d", after)
	}
}

func mkQuery(name string) []byte {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		panic(err)
	}
	return out
}

func rcodeOf(t *testing.T, resp []byte) dnsmessage.RCode {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("unparseable response: %v", err)
	}
	return h.RCode
}

// TestMatchLongestSuffix — a QNAME resolves to the LONGEST covering zone; unrelated names don't match.
func TestMatchLongestSuffix(t *testing.T) {
	tbl := buildTable([]Entry{
		{Domain: "corp.local", ResolverIP: "10.0.0.53"},
		{Domain: "a.corp.local", ResolverIP: "10.1.0.53"},
	}, nil)
	if r, ok := tbl.match("nas.corp.local"); !ok || r != netip.MustParseAddr("10.0.0.53") {
		t.Fatalf("nas.corp.local → corp.local resolver; got %v ok=%v", r, ok)
	}
	if r, ok := tbl.match("db.a.corp.local"); !ok || r != netip.MustParseAddr("10.1.0.53") {
		t.Fatalf("db.a.corp.local → the more specific a.corp.local resolver; got %v ok=%v", r, ok)
	}
	if _, ok := tbl.match("example.com"); ok {
		t.Fatal("an out-of-zone name must NOT match (split-horizon)")
	}
	// A near-miss must not false-match by bare suffix ("evilcorp.local" is not within "corp.local").
	if _, ok := tbl.match("evilcorp.local"); ok {
		t.Fatal("a label-boundary near-miss must NOT match")
	}
}

// TestSingleLabelZoneCompiles (F3) — a single-label zone ("internal") is legitimate and must compile +
// match, matching what the control plane accepts (no normalizer drift between layers).
func TestSingleLabelZoneCompiles(t *testing.T) {
	tbl := buildTable([]Entry{{Domain: "internal", ResolverIP: "10.0.0.53"}}, nil)
	if len(tbl.rules) != 1 {
		t.Fatalf("single-label zone must compile, got %d", len(tbl.rules))
	}
	if _, ok := tbl.match("host.internal"); !ok {
		t.Fatal("host.internal must resolve via the single-label zone")
	}
}

// TestBuildTableSkipDegraded — a malformed entry (bad IP / empty / empty-label domain) is SKIPPED; the
// valid ones survive (D2: one typo never blanks every zone).
func TestBuildTableSkipDegraded(t *testing.T) {
	tbl := buildTable([]Entry{
		{Domain: "corp.local", ResolverIP: "10.0.0.53"}, // good
		{Domain: "bad.local", ResolverIP: "not-an-ip"},  // bad IP → skip
		{Domain: "a..b", ResolverIP: "10.0.0.9"},        // empty label → skip
		{Domain: "", ResolverIP: "10.0.0.9"},            // empty domain → skip
	}, nil)
	if len(tbl.rules) != 1 {
		t.Fatalf("only the one valid entry must survive, got %d: %+v", len(tbl.rules), tbl.rules)
	}
	if _, ok := tbl.match("nas.corp.local"); !ok {
		t.Fatal("the surviving good entry must still resolve")
	}
}

// TestHandleServfailFailStatic — a matched domain whose resolver is unreachable → SERVFAIL (never a
// timeout, never a tunnel effect); the last-good table stays in force.
func TestHandleServfailFailStatic(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { return nil, errors.New("i/o timeout") })
	f.SetTable([]Entry{{Domain: "corp.local", ResolverIP: "10.0.0.53"}})
	resp := f.handle(mkQuery("nas.corp.local."), netip.MustParseAddr("10.99.0.5"))
	if resp == nil || rcodeOf(t, resp) != dnsmessage.RCodeServerFailure {
		t.Fatalf("unreachable resolver → SERVFAIL; got %v", resp)
	}
}

// TestHandleRefusedOutOfScope — an unmatched domain is REFUSED (scoped forwarder; the client's own resolver
// handles everything else — split-horizon).
func TestHandleRefusedOutOfScope(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) {
		t.Fatal("must NOT forward an out-of-scope query")
		return nil, nil
	})
	f.SetTable([]Entry{{Domain: "corp.local", ResolverIP: "10.0.0.53"}})
	resp := f.handle(mkQuery("www.example.com."), netip.MustParseAddr("10.99.0.5"))
	if resp == nil || rcodeOf(t, resp) != dnsmessage.RCodeRefused {
		t.Fatalf("out-of-scope → REFUSED; got %v", resp)
	}
}

// TestHandleForwardsMatched — a matched query is relayed and the upstream response returned verbatim.
func TestHandleForwardsMatched(t *testing.T) {
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	var got netip.Addr
	f := New(nil, func(r netip.Addr, _ []byte) ([]byte, error) { got = r; return want, nil })
	f.SetTable([]Entry{{Domain: "corp.local", ResolverIP: "10.0.0.53"}})
	resp := f.handle(mkQuery("nas.corp.local."), netip.MustParseAddr("10.99.0.5"))
	if string(resp) != string(want) || got != netip.MustParseAddr("10.0.0.53") {
		t.Fatalf("matched query must relay to the declared resolver + return its bytes; got resp=%v resolver=%v", resp, got)
	}
}

// TestRateLimit — a single source over its burst is dropped (nil, no reply). D2 hygiene.
func TestRateLimit(t *testing.T) {
	now := time.Unix(0, 0)
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { return []byte{0}, nil })
	f.now = func() time.Time { return now } // frozen clock → no refill
	f.SetTable([]Entry{{Domain: "corp.local", ResolverIP: "10.0.0.53"}})
	src := netip.MustParseAddr("10.99.0.5")
	q := mkQuery("nas.corp.local.")
	served := 0
	for i := 0; i < dnsRateBurst+10; i++ {
		if f.handle(q, src) != nil {
			served++
		}
	}
	if served != dnsRateBurst {
		t.Fatalf("a frozen-clock source may spend exactly its burst (%d), then drop; served %d", dnsRateBurst, served)
	}
}

// TestWgBindScopeNeverWildcard — the bind set is derived from a NAMED interface's addresses ONLY, never a
// wildcard/public bind (D2). Using loopback (a real iface everywhere): its addrs are 127.0.0.1 / ::1, and
// 0.0.0.0 can never appear — proving the forwarder can't become an open resolver.
func TestWgBindScopeNeverWildcard(t *testing.T) {
	addrs, err := wgBindAddrs("lo")
	if err != nil {
		t.Skipf("no loopback iface named 'lo' on this host: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("loopback must yield at least one bind address")
	}
	for _, a := range addrs {
		if a.IsUnspecified() {
			t.Fatalf("bind set must NEVER contain a wildcard/unspecified address (open-resolver risk); got %v", a)
		}
		if !a.IsLoopback() {
			t.Fatalf("binds must come from the named iface only; got non-loopback %v from 'lo'", a)
		}
	}
}

// TestWgBindAddrsAbsenceIsEnumerated (FF1) — a genuinely-absent interface is determined from a SUCCESSFUL
// enumeration (not inferred from a call failure) and returns errWGIfaceNotFound, so reconcileBinds closes;
// a transient enumeration failure would surface as a plain error (keep). No real host has an interface named
// this, so net.Interfaces() succeeds and simply doesn't contain it → the terminal not-found signal.
func TestWgBindAddrsAbsenceIsEnumerated(t *testing.T) {
	_, err := wgBindAddrs("tnx-nope-xyz0")
	if !errors.Is(err, errWGIfaceNotFound) {
		t.Fatalf("an enumerated-but-absent interface must return errWGIfaceNotFound, got %v", err)
	}
}

// aRecordOf extracts the single A-record address from a response, or fails.
func aRecordOf(t *testing.T, resp []byte) netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatalf("unparseable response: %v", err)
	}
	if _, err := p.Question(); err != nil {
		t.Fatalf("question: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	ah, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("no answer record: %v", err)
	}
	if ah.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want A", ah.Type)
	}
	r, err := p.AResource()
	if err != nil {
		t.Fatalf("A resource: %v", err)
	}
	return netip.AddrFrom4(r.A)
}

// TestK8sDirectAnswer — S10.3 A1, THE capability red (the one that would have caught the dead-while-green
// gap: the CP carried DNSName+VIP + the agent mirrored the struct, but NO agent code answered). An agent
// given a K8s VIP map answers an exposed FQDN's A query with its VIP; an in-zone-but-unexposed name is
// authoritative NXDOMAIN; an empty/stale map answers NOTHING for cluster names (fail-closed); the ONLY
// address ever returned is an exposed Service's own VIP.
func TestK8sDirectAnswer(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) {
		t.Fatal("a cluster-zone query must NEVER relay upstream")
		return nil, nil
	})
	f.SetK8sAnswers(
		[]K8sEntry{{FQDN: "api.prod.svc.prod.k8s.acme.com", VIP: "100.64.0.5"}},
		[]string{"prod.k8s.acme.com"},
	)

	// Exposed FQDN → its VIP (A answer, NOERROR).
	resp := f.handle(mkQuery("api.prod.svc.prod.k8s.acme.com."), netip.MustParseAddr("100.64.0.9"))
	if resp == nil || rcodeOf(t, resp) != dnsmessage.RCodeSuccess {
		t.Fatalf("exposed FQDN must NOERROR, got %v", resp)
	}
	if got := aRecordOf(t, resp); got.String() != "100.64.0.5" {
		t.Fatalf("exposed FQDN must answer its VIP 100.64.0.5, got %s", got)
	}

	// In-zone but UNEXPOSED → authoritative NXDOMAIN (the name we own the zone for does not exist).
	resp = f.handle(mkQuery("web.prod.svc.prod.k8s.acme.com."), netip.MustParseAddr("100.64.0.9"))
	if resp == nil || rcodeOf(t, resp) != dnsmessage.RCodeNameError {
		t.Fatalf("in-zone unexposed name must NXDOMAIN, got %v (rcode %v)", resp, rcodeOf(t, resp))
	}

	// Out of every owned zone → falls through to the S8.4 table (empty here) → REFUSED, never a K8s answer.
	resp = f.handle(mkQuery("host.corp.local."), netip.MustParseAddr("100.64.0.9"))
	if resp == nil || rcodeOf(t, resp) != dnsmessage.RCodeRefused {
		t.Fatalf("out-of-zone name must fall through to REFUSED, got rcode %v", rcodeOf(t, resp))
	}

	// Empty/stale map → answers NOTHING for a former cluster name (fail-closed: no fabricated address).
	f.SetK8sAnswers(nil, nil)
	resp = f.handle(mkQuery("api.prod.svc.prod.k8s.acme.com."), netip.MustParseAddr("100.64.0.9"))
	if resp == nil || rcodeOf(t, resp) != dnsmessage.RCodeRefused {
		t.Fatalf("an emptied map must answer no cluster name (fall through to REFUSED), got rcode %v", rcodeOf(t, resp))
	}
}
