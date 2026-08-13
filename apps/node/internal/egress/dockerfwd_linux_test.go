//go:build linux

package egress

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeNft models the DOCKER-USER + FORWARD chains for the WF-4 reconcile. It tracks the
// agent's comment-marked accept rules (daddr -> handle) so idempotence + full-sweep are testable.
type fakeNft struct {
	chainAbsent bool              // list chain DOCKER-USER errors (bare-metal / non-Docker host)
	forwardDrop bool              // `list chain ip filter FORWARD` reports policy drop
	insertErr   bool              // inserts fail (can't place the accept → forwardBlocked path)
	listErr     bool              // the `-a list` enumeration errors (transient nft busy/lock)
	rules       map[string]string // daddr (as nft PRINTS it) -> handle (the agent's tunnex-marked rules)
	orient      map[string]string // key -> nft-rendered iif/oif prefix (drift-detection, S8.6b)
	nextHandle  int
	inserts     []string   // daddr order of inserts (assert scoping)
	insertArgs  [][]string // full arg vector per insert (assert iif/oif ORIENTATION — WF-4-local)
	deletes     []string   // handles deleted
}

func newFakeNft() *fakeNft {
	return &fakeNft{rules: map[string]string{}, orient: map[string]string{}, nextHandle: 10}
}

// fakeFirstIface extracts the first interface NAME from insert-arg orientation tokens (skipping a `!=`),
// so the fake keys a rule by dir:iface:addr the way per-interface rules coexist under real nft.
func fakeFirstIface(orient []string) string {
	for i, t := range orient {
		if t == "iifname" || t == "oifname" {
			if i+1 < len(orient) {
				n := orient[i+1]
				if n == "!=" && i+2 < len(orient) {
					n = orient[i+2]
				}
				return n
			}
		}
	}
	return ""
}

// renderOrient turns insert-arg orientation tokens (before "ip") into the nft-printed form, quoting the
// interface names so the reconcile's regex + orientSig read them back the way real nft would.
func renderOrient(toks []string) string {
	var parts []string
	for _, t := range toks {
		if t == "iifname" || t == "oifname" || t == "!=" {
			parts = append(parts, t)
		} else {
			parts = append(parts, `"`+t+`"`)
		}
	}
	return strings.Join(parts, " ")
}

func (f *fakeNft) run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	switch {
	case cmd == "list chain ip filter DOCKER-USER":
		if f.chainAbsent {
			return "", errors.New("No such file or directory")
		}
		return "table ip filter { chain DOCKER-USER { } }", nil
	case cmd == "list chain ip filter FORWARD":
		if f.forwardDrop {
			return "chain FORWARD { type filter hook forward priority filter; policy drop; }", nil
		}
		return "chain FORWARD { type filter hook forward priority filter; policy accept; }", nil
	case cmd == "-a list chain ip filter DOCKER-USER":
		if f.listErr {
			return "", errors.New("nft busy: resource temporarily unavailable")
		}
		var b strings.Builder
		b.WriteString("table ip filter {\n  chain DOCKER-USER {\n")
		for key, h := range f.rules { // key = "dir:iface:addr" (per-interface, S9.1) — models real nft (handle-unique)
			parts := strings.SplitN(key, ":", 3)
			dir, addr := "daddr", parts[2]
			if parts[0] == "s" {
				dir = "saddr"
			}
			fmt.Fprintf(&b, "    %s ip %s %s counter accept comment \"%s\" # handle %s\n", f.orient[key], dir, addr, dockerUserComment, h)
		}
		b.WriteString("  }\n}\n")
		return b.String(), nil
	case len(args) >= 4 && args[0] == "insert" && args[1] == "rule":
		if f.insertErr {
			return "", errors.New("insert denied")
		}
		dir, addr := "", ""
		var orient []string                // the match tokens BEFORE "ip <dir>addr" (the iif/oif clause)
		for i := 5; i+1 < len(args); i++ { // args[0..4] = insert rule ip filter DOCKER-USER
			if args[i] == "ip" {
				break
			}
			orient = append(orient, args[i])
		}
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "daddr" {
				dir, addr = "d", args[i+1]
			} else if args[i] == "saddr" {
				dir, addr = "s", args[i+1]
			}
		}
		addr = strings.TrimSuffix(addr, "/32") // model nft: a host addr is stored/printed BARE
		// Key by dir:iface:addr so multiple rules at the SAME addr with DIFFERENT interfaces (the S9.1
		// per-interface pool class) coexist — real nft keys by handle; this models that faithfully.
		key := dir + ":" + fakeFirstIface(orient) + ":" + addr
		f.nextHandle++
		f.rules[key] = fmt.Sprint(f.nextHandle)
		f.orient[key] = renderOrient(orient)
		f.inserts = append(f.inserts, key)
		f.insertArgs = append(f.insertArgs, append([]string(nil), args...))
		return "", nil
	case len(args) >= 2 && args[0] == "delete" && args[1] == "rule":
		handle := args[len(args)-1]
		for daddr, h := range f.rules {
			if h == handle {
				delete(f.rules, daddr)
				delete(f.orient, daddr)
			}
		}
		f.deletes = append(f.deletes, handle)
		return "", nil
	}
	return "", nil
}

func mgrWithNft(f *fakeNft) *Manager {
	m := New("wg0")
	m.nftRun = f.run
	return m
}

func TestPoolCIDRForForwardFallsBackToLiveWGSubnet(t *testing.T) {
	if got := poolCIDRForForward("", "10.99.0.1/24"); got != "10.99.0.1/24" {
		t.Fatalf("empty policy pool must use live wg subnet, got %q", got)
	}
	if got := poolCIDRForForward("   ", "10.99.0.1/24"); got != "10.99.0.1/24" {
		t.Fatalf("whitespace policy pool must use live wg subnet, got %q", got)
	}
	if got := poolCIDRForForward("10.99.0.0/24", "10.99.0.1/24"); got != "10.99.0.0/24" {
		t.Fatalf("configured policy pool must remain authoritative, got %q", got)
	}
}

// TestDockerForwardScopedInsert — WF-4 D-WF4-b: on a Docker host, the agent inserts a Routes-SCOPED
// accept into DOCKER-USER (one per v4 route, comment-marked), never a blanket accept.
func TestDockerForwardScopedInsert(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24", "172.31.0.0/16"}, nil, "")
	// TWO Route-scoped accepts per route: forward (d:) + return (s:) — the return path is why the re-walk
	// forward-ping passed but the reply dropped.
	for _, k := range []string{"d:wg0:10.0.0.0/24", "s:wg0:10.0.0.0/24", "d:wg0:172.31.0.0/16", "s:wg0:172.31.0.0/16"} {
		if f.rules[k] == "" {
			t.Fatalf("missing scoped accept %s; got %v", k, f.rules)
		}
	}
	if len(f.rules) != 4 {
		t.Fatalf("expected 4 rules (fwd+ret per route), got %v", f.rules)
	}
}

// TestDockerForwardIdempotent — D-WF4-a: a second reconcile with the same routes inserts NOTHING
// (list → insert-only-missing), so a per-tick loop doesn't churn.
func TestDockerForwardIdempotent(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	routes := []string{"10.0.0.0/24"}
	m.reconcileDockerForward(context.Background(), routes, nil, "")
	n := len(f.inserts)
	m.reconcileDockerForward(context.Background(), routes, nil, "")
	if len(f.inserts) != n {
		t.Fatalf("second reconcile must insert nothing (idempotent); inserts went %d -> %d", n, len(f.inserts))
	}
}

// TestDockerForwardFullSweep — D-WF4-b: a route withdrawn removes its comment-marked DOCKER-USER
// rule (by handle), never leaving a stale foreign-chain accept.
func TestDockerForwardFullSweep(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24", "172.31.0.0/16"}, nil, "")
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, "") // 172.31 withdrawn
	for _, k := range []string{"d:wg0:172.31.0.0/16", "s:wg0:172.31.0.0/16"} {
		if _, still := f.rules[k]; still {
			t.Fatalf("a withdrawn route's rule %s must be swept, still present: %v", k, f.rules)
		}
	}
	for _, k := range []string{"d:wg0:10.0.0.0/24", "s:wg0:10.0.0.0/24"} {
		if _, kept := f.rules[k]; !kept {
			t.Fatalf("the surviving route's rule %s must stay, got %v", k, f.rules)
		}
	}
	if len(f.deletes) != 2 { // both directions of the withdrawn route
		t.Fatalf("exactly the stale route's two rules must be deleted, deletes=%v", f.deletes)
	}
}

// TestDockerForwardHostRouteIdempotent — re-review #1: a /32 route must NOT thrash. nft prints a host
// daddr BARE (no /32), so keying on Masked() "x/32" would never match the listed "x" → perpetual
// insert+delete. canonDaddr keys both sides bare, so a second reconcile inserts nothing.
func TestDockerForwardHostRouteIdempotent(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	routes := []string{"10.0.0.5/32"}
	m.reconcileDockerForward(context.Background(), routes, nil, "")
	n := len(f.inserts)
	if n != 2 { // fwd + ret for the one /32
		t.Fatalf("first reconcile inserts the /32 fwd+ret accepts, got %d", n)
	}
	m.reconcileDockerForward(context.Background(), routes, nil, "")
	if len(f.inserts) != n || len(f.deletes) != 0 {
		t.Fatalf("a /32 route must be idempotent (no churn); inserts %d→%d, deletes %d", n, len(f.inserts), len(f.deletes))
	}
}

// TestDockerForwardListErrorSkips — re-review #2: a transient `-a list` failure must NOT blind-insert
// (which duplicates accepts the sweep can't reap). On a list error the reconcile skips add/sweep.
func TestDockerForwardListErrorSkips(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, "") // places one
	before := len(f.inserts)
	f.listErr = true
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, "") // list fails → must NOT re-insert
	if len(f.inserts) != before {
		t.Fatalf("a transient list error must skip inserts (no duplicates); inserts %d→%d", before, len(f.inserts))
	}
}

// TestDockerForwardBareMetalNoOp — D-WF4-c: no DOCKER-USER chain (bare metal / non-Docker) → no-op,
// no error, forwardBlocked stays false (forwarding rides the host's own FORWARD).
func TestDockerForwardBareMetalNoOp(t *testing.T) {
	f := newFakeNft()
	f.chainAbsent = true
	m := mgrWithNft(f)
	if blocked := m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, ""); blocked {
		t.Fatal("bare-metal (no DOCKER-USER) must not report forwardBlocked")
	}
	if len(f.inserts) != 0 {
		t.Fatalf("bare-metal must not touch any foreign chain, inserts=%v", f.inserts)
	}
	if m.ForwardBlocked() {
		t.Fatal("ForwardBlocked() must be false on a non-Docker host")
	}
}

// TestDockerForwardBlockedSignal — D-WF4-d: Docker host + FORWARD policy-drop + routes to carry +
// the accept CAN'T be placed → forwardBlocked TRUE (surfaced as site_subnet_unreachable, never green).
func TestDockerForwardBlockedSignal(t *testing.T) {
	f := newFakeNft()
	f.forwardDrop = true
	f.insertErr = true
	m := mgrWithNft(f)
	if blocked := m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, ""); !blocked {
		t.Fatal("Docker FORWARD-drop + unplaceable accept + routes present → must report forwardBlocked")
	}
	if !m.ForwardBlocked() {
		t.Fatal("ForwardBlocked() must be true when the forward is Docker-blocked")
	}
	// Recovery: inserts succeed → not blocked.
	f.insertErr = false
	if blocked := m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, ""); blocked {
		t.Fatal("once the accept is placed, forwardBlocked must clear")
	}
}

// hasArgSeq reports whether args contains seq as a contiguous subsequence.
func hasArgSeq(args, seq []string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		ok := true
		for j := range seq {
			if args[i+j] != seq[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// findInsertWith returns the first recorded insert arg-vector whose (dirTok, addr) pair matches.
func findInsertWith(f *fakeNft, dirTok, addr string) []string {
	for _, a := range f.insertArgs {
		for i := 0; i+1 < len(a); i++ {
			if a[i] == dirTok && a[i+1] == addr {
				return a
			}
		}
	}
	return nil
}

// TestDockerForwardLocalSubnetMirrored — WF-4-LOCAL (S8.5), the walk fixture as a red: a split-tunnel device
// reaching the LAN BEHIND its own gateway is forwarded wg0→eth0; Docker's FORWARD DROP swallowed it even
// though the ZT chain accepted it (wire-proven). The fix opens a DOCKER-USER accept for the gateway's OWN
// advertised subnets too — but in the MIRRORED orientation vs a remote route. A remote route is a behind-LAN
// host initiating OUT to the site-link (iif!=wg0 → oif=wg0, daddr); a local subnet is a DEVICE initiating IN
// to the local LAN (iif=wg0 → oif!=wg0, daddr) — the mirror. A wrong (route) orientation would leave the
// device→own-LAN forward dropped exactly as before the fix. BOTH faces asserted: (a) Docker's structural drop
// opened in the RIGHT direction; (b) the ZT enforcement chain (`ip tunnex`) is NEVER touched here — this lifts
// only Docker's isolation, so the grant still adjudicates.
func TestDockerForwardLocalSubnetMirrored(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	// a REMOTE route 10.0.0.0/24 (site-to-site) + this gateway's OWN advertised subnet 172.31.0.0/16.
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, []string{"172.31.0.0/16"}, "")

	// Both get fwd (d:) + ret (s:) accepts — 4 rules, disjoint addrs, no key collision across orientations.
	for _, k := range []string{"d:wg0:10.0.0.0/24", "s:wg0:10.0.0.0/24", "d:wg0:172.31.0.0/16", "s:wg0:172.31.0.0/16"} {
		if f.rules[k] == "" {
			t.Fatalf("missing accept %s; got %v", k, f.rules)
		}
	}

	// ORIENTATION. Route FORWARD (daddr=route) is RELAXED (S8.6b): oif=wg0, NO iif predicate — one rule covers
	// eth0→wg0 (route) AND wg0→wg0 (hub transit). A re-added iif predicate would re-break transit.
	if fwd := findInsertWith(f, "daddr", "10.0.0.0/24"); !hasArgSeq(fwd, []string{"oifname", "wg0", "ip", "daddr"}) || hasArgSeq(fwd, []string{"iifname"}) {
		t.Fatalf("route forward must be RELAXED oif=wg0 (no iif predicate), got %v", fwd)
	}
	// LOCAL-SUBNET FORWARD (daddr=localsubnet) = tunnel-client→own-LAN. S9.1: keyed `iifname <tif> daddr`,
	// the `oifname != wg0` NEGATION DROPPED (founder-ruled) — a packet to the gateway's own LAN can't egress a
	// tunnel (routing + disjointness), so the negation added nothing. Here (single iface) tif=wg0.
	if fwd := findInsertWith(f, "daddr", "172.31.0.0/16"); !hasArgSeq(fwd, []string{"iifname", "wg0", "ip", "daddr"}) || hasArgSeq(fwd, []string{"oifname"}) {
		t.Fatalf("local-subnet forward must be iif=<tif> daddr (no oifname negation), got %v", fwd)
	}
	// LOCAL-SUBNET RETURN (saddr=localsubnet) = own-LAN→tunnel-client: keyed `oifname <tif> saddr`, no iif negation.
	if ret := findInsertWith(f, "saddr", "172.31.0.0/16"); !hasArgSeq(ret, []string{"oifname", "wg0", "ip", "saddr"}) || hasArgSeq(ret, []string{"iifname"}) {
		t.Fatalf("local-subnet return must be oif=<tif> saddr (no iifname negation), got %v", ret)
	}

	// SECOND FACE: this reconcile touches ONLY DOCKER-USER (Docker's structural drop), NEVER the `ip tunnex`
	// ZT enforcement chain — the grant still adjudicates. No insert may target the tunnex table.
	for _, a := range f.insertArgs {
		if hasArgSeq(a, []string{"ip", "tunnex"}) {
			t.Fatalf("reconcileDockerForward must not touch the ZT enforcement chain, got %v", a)
		}
	}
}

// TestDockerForwardTransitionConverges — S8.6b D-transit-2 (sweep-hygiene, the fork's transition engine): a
// pre-fold agent left OLD orientation-predicated route rules (iif!=wg0 oif=wg0 daddr=route) under the SAME
// "d:route"/"s:route" keys the relaxed form uses. Key-only idempotence would SKIP them (key present) and strand
// the stale rules → transit broken forever. Drift-detection must REPLACE them in ONE pass: old handle deleted,
// relaxed form inserted, no orphan window. Then it must stay idempotent (no re-churn once converged).
func TestDockerForwardTransitionConverges(t *testing.T) {
	f := newFakeNft()
	// seed the OLD orientation-predicated route rules a pre-S8.6b agent placed, under the same keys.
	f.rules["d:wg0:10.0.0.0/24"], f.orient["d:wg0:10.0.0.0/24"] = "77", `iifname != "wg0" oifname "wg0"`
	f.rules["s:wg0:10.0.0.0/24"], f.orient["s:wg0:10.0.0.0/24"] = "78", `iifname "wg0" oifname != "wg0"`
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, "")

	// converged to the RELAXED form under the same key.
	if fwd := findInsertWith(f, "daddr", "10.0.0.0/24"); !hasArgSeq(fwd, []string{"oifname", "wg0", "ip", "daddr"}) || hasArgSeq(fwd, []string{"iifname"}) {
		t.Fatalf("transition: route forward must converge to the RELAXED form, got %v", fwd)
	}
	// the 2 stale-orientation rules deleted in this ONE pass (no orphan).
	if len(f.deletes) != 2 {
		t.Fatalf("transition: exactly the 2 old rules must be swept in one pass, deletes=%v", f.deletes)
	}
	for _, h := range []string{"77", "78"} {
		gone := false
		for _, d := range f.deletes {
			if d == h {
				gone = true
			}
		}
		if !gone {
			t.Fatalf("transition: old handle %s must be swept, deletes=%v", h, f.deletes)
		}
	}
	// idempotence re-verified against the RELAXED render — a second pass churns nothing.
	insN, delN := len(f.inserts), len(f.deletes)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, nil, "")
	if len(f.inserts) != insN || len(f.deletes) != delN {
		t.Fatalf("transition: post-convergence must be idempotent, inserts %d→%d deletes %d→%d", insN, len(f.inserts), delN, len(f.deletes))
	}
}

// TestDockerForwardSpokeIsolation — S8.6b spoke-isolation (carries the fork's weight): the relaxed route accept
// opens Docker's drop for daddr/saddr ∈ Routes∪LocalSubnets ONLY. A device→device-pool packet (daddr = the WG
// pool, NEVER a Route) is UNTOUCHED — no accept references a pool address, so relaxing the route rule's iif/oif
// opened nothing that matters. The S8.2 D1 spoke-isolation sibling, at the DOCKER-USER tier.
func TestDockerForwardSpokeIsolation(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	// a remote route + a local subnet; the WG device pool 10.99.0.0/24 is NEITHER.
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, []string{"172.31.0.0/16"}, "")
	allowed := map[string]bool{"10.0.0.0/24": true, "172.31.0.0/16": true}
	for key := range f.rules {
		parts := strings.SplitN(key, ":", 3) // dir:iface:addr
		addr := parts[2]
		if strings.HasPrefix(addr, "10.99.") {
			t.Fatalf("spoke-isolation: NO accept may reference the device pool, got %s", key)
		}
		if !allowed[addr] {
			t.Fatalf("spoke-isolation: accept references %s, not a Route/LocalSubnet", addr)
		}
	}
}

// TestDockerForwardFailoverSymmetry — S8.6b failover-symmetry: the accept derives from Routes; a promoted
// standby carries the SAME Routes in its artifact → it renders the SAME DOCKER-USER set. Two managers, same
// Routes → identical rule sets + orientations (the hub-symmetry red's packaging-tier sibling).
func TestDockerForwardFailoverSymmetry(t *testing.T) {
	routes := []string{"10.0.0.0/24", "172.31.9.0/24"}
	fa, fb := newFakeNft(), newFakeNft()
	mgrWithNft(fa).reconcileDockerForward(context.Background(), routes, nil, "")
	mgrWithNft(fb).reconcileDockerForward(context.Background(), routes, nil, "")
	if len(fa.rules) != len(fb.rules) || len(fa.rules) == 0 {
		t.Fatalf("failover-symmetry: rule counts differ/empty, primary=%d standby=%d", len(fa.rules), len(fb.rules))
	}
	for key := range fa.rules {
		if _, ok := fb.rules[key]; !ok {
			t.Fatalf("failover-symmetry: standby missing key %s", key)
		}
		if fa.orient[key] != fb.orient[key] {
			t.Fatalf("failover-symmetry: orientation differs for %s: %q vs %q", key, fa.orient[key], fb.orient[key])
		}
	}
}

// TestDockerForwardOpensDockerNotEnforcement — S8.6b D-transit-3 (ZT-boundary, unit face): the reconcile
// touches ONLY Docker's chain (ip filter DOCKER-USER) — it lifts the STRUCTURAL drop, never the policy. The
// enforcement face (enforcing-no-grant drops at the tunnex chain, with-grant flows — A3's counter-0 inverting)
// is the LIVE A3 re-proof; this pins the boundary at unit level.
func TestDockerForwardOpensDockerNotEnforcement(t *testing.T) {
	f := newFakeNft()
	var cmds [][]string
	m := New("wg0")
	m.nftRun = func(ctx context.Context, args ...string) (string, error) {
		cmds = append(cmds, append([]string(nil), args...))
		return f.run(ctx, args...)
	}
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, []string{"172.31.0.0/16"}, "")
	for _, c := range cmds {
		if hasArgSeq(c, []string{"ip", "tunnex"}) {
			t.Fatalf("ZT-boundary: reconcileDockerForward must never touch ip tunnex, got %v", c)
		}
		if (c[0] == "insert" || c[0] == "delete") && !hasArgSeq(c, []string{"ip", "filter", "DOCKER-USER"}) {
			t.Fatalf("ZT-boundary: a rule op must be scoped to DOCKER-USER, got %v", c)
		}
	}
}

// TestDockerForwardPoolClassRelaxed — A3b v6, fork-ruled (ii): the org device pool gets RELAXED accepts —
// forward oif=wg0 daddr=pool (LAN→device replies AND wg0→wg0 device↔device), return iif=wg0 saddr=pool
// (device-sourced any direction, incl. wg0→wg0 hub transit). NO iif/oif exclusions: Docker's match tier
// never structurally drops what the ip tunnex chain adjudicates (D-transit-3 uniform; the amended D-A3b-1
// condition — darkness lives at the CHAIN, per-grant, not here).
func TestDockerForwardPoolClassRelaxed(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, []string{"172.31.0.0/16"}, "10.99.0.0/24")

	for _, k := range []string{"d:wg0:10.99.0.0/24", "s:wg0:10.99.0.0/24"} {
		if f.rules[k] == "" {
			t.Fatalf("missing pool accept %s; got %v", k, f.rules)
		}
	}
	// RELAXED: forward = oif=wg0 only; return = iif=wg0 only — a re-added exclusion predicate would
	// silently re-break device↔device / hub transit at the Docker tier.
	if fwd := findInsertWith(f, "daddr", "10.99.0.0/24"); !hasArgSeq(fwd, []string{"oifname", "wg0", "ip", "daddr"}) || hasArgSeq(fwd, []string{"iifname"}) {
		t.Fatalf("pool forward must be RELAXED oif=wg0 (no iif predicate), got %v", fwd)
	}
	if ret := findInsertWith(f, "saddr", "10.99.0.0/24"); !hasArgSeq(ret, []string{"iifname", "wg0", "ip", "saddr"}) || hasArgSeq(ret, []string{"oifname"}) {
		t.Fatalf("pool return must be RELAXED iif=wg0 (no oif predicate), got %v", ret)
	}
}

// TestDockerForwardKeySpaceCensus — the A3b census red (D-A3b-3 founder condition): the engine's key space
// enumerates EXACTLY the classes the paper names — routes, local subnets, pool — two keys (d:/s:) each,
// nothing else. A class silently added here without its paper entry is the drift this red exists to catch.
func TestDockerForwardKeySpaceCensus(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.0.0.0/24"}, []string{"172.31.0.0/16"}, "10.99.0.0/24")

	want := map[string]bool{
		"d:wg0:10.0.0.0/24": true, "s:wg0:10.0.0.0/24": true, // route class (S8.2c WF-4, relaxed S8.6b)
		"d:wg0:172.31.0.0/16": true, "s:wg0:172.31.0.0/16": true, // local-subnet class (S8.5 WF-4-local)
		"d:wg0:10.99.0.0/24": true, "s:wg0:10.99.0.0/24": true, // pool class (A3b v6)
	}
	if len(f.rules) != len(want) {
		t.Fatalf("key-space census: want exactly %d keys (route+local+pool × d/s), got %v", len(want), f.rules)
	}
	for k := range want {
		if f.rules[k] == "" {
			t.Fatalf("key-space census: missing %s; got %v", k, f.rules)
		}
	}
}

// TestDockerForwardPoolCollisionGuard — a pool CIDR colliding with an already-claimed route/local addr
// must NOT overwrite it (the same disjoint-by-construction guard localSubnets carries): first claim wins,
// the collision surfaces via the validator CP-side, never via a silently re-oriented accept.
func TestDockerForwardPoolCollisionGuard(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.reconcileDockerForward(context.Background(), []string{"10.99.0.0/24"}, nil, "10.99.0.0/24")

	// the ROUTE claimed the addr; the pool must not have re-oriented it (route fwd = daddr with oif=wg0 —
	// identical here — but the RETURN differs: route ret iif=wg0 saddr; pool would be the same relaxed form,
	// so assert exactly 2 rules exist (no duplicate insert churn).
	if len(f.rules) != 2 {
		t.Fatalf("collision guard: route claim must win, exactly 2 rules, got %v", f.rules)
	}
	if len(f.inserts) != 2 {
		t.Fatalf("collision guard: no duplicate inserts on collision, got %v", f.inserts)
	}
}

// TestDockerPoolPerInterfaceIdempotent (S9.1 Slice 3, D-S9.3-DOCKER (a), guard-red i): with TWO
// tunnel interfaces present (wg0 + the co-terminated OVPN tun), the pool class emits a per-interface
// accept pair for EACH, and a second reconcile tick inserts NOTHING — the widened dir:iface:addr key
// space is idempotent (no thrash against Docker, the reason the drift engine exists).
func TestDockerPoolPerInterfaceIdempotent(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.SetOVPNTun("tunnex-ovpn")
	pool := "10.99.0.0/24"
	m.reconcileDockerForward(context.Background(), nil, nil, pool)
	for _, k := range []string{
		"d:wg0:10.99.0.0/24", "s:wg0:10.99.0.0/24",
		"d:tunnex-ovpn:10.99.0.0/24", "s:tunnex-ovpn:10.99.0.0/24",
	} {
		if f.rules[k] == "" {
			t.Fatalf("missing per-interface pool rule %s; got %v", k, f.rules)
		}
	}
	n := len(f.inserts)
	m.reconcileDockerForward(context.Background(), nil, nil, pool) // second tick
	if len(f.inserts) != n {
		t.Fatalf("second reconcile with two tunnel interfaces must insert nothing (no thrash); %d -> %d", n, len(f.inserts))
	}
}

// TestDockerPoolSweepsDepartedTun (S9.1 Slice 3, guard-red ii): when the OVPN server is removed (the
// tun departs from tunnelIfaces()), the tun's pool rules are FULL-SWEPT — no orphans — while wg0's
// pool rules survive. The per-interface key is what lets the sweep target exactly the departed iface.
func TestDockerPoolSweepsDepartedTun(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.SetOVPNTun("tunnex-ovpn")
	pool := "10.99.0.0/24"
	m.reconcileDockerForward(context.Background(), nil, nil, pool) // wg0 + tun rules
	m.SetOVPNTun("")                                               // OVPN server removed → tun departs
	m.reconcileDockerForward(context.Background(), nil, nil, pool)
	for _, k := range []string{"d:tunnex-ovpn:10.99.0.0/24", "s:tunnex-ovpn:10.99.0.0/24"} {
		if _, still := f.rules[k]; still {
			t.Fatalf("a departed tunnel's pool rule %s must be swept (no orphan), got %v", k, f.rules)
		}
	}
	for _, k := range []string{"d:wg0:10.99.0.0/24", "s:wg0:10.99.0.0/24"} {
		if f.rules[k] == "" {
			t.Fatalf("wg0's pool rule %s must survive the tun departure, got %v", k, f.rules)
		}
	}
}

// TestDockerPoolZeroConfigByteIdentical (S9.1 Slice 3, guard-red iii): a WireGuard-only deployment
// (no OVPN tun) emits EXACTLY the two legacy pool rules, wg0-oriented, byte-identical to pre-OVPN —
// the internal dir:iface:addr key is invisible to nft, so the rendered DOCKER-USER rule is unchanged.
func TestDockerPoolZeroConfigByteIdentical(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f) // no SetOVPNTun
	m.reconcileDockerForward(context.Background(), nil, nil, "10.99.0.0/24")
	if len(f.rules) != 2 {
		t.Fatalf("WireGuard-only must emit exactly the 2 legacy pool rules, got %v", f.rules)
	}
	if f.rules["d:wg0:10.99.0.0/24"] == "" || f.rules["s:wg0:10.99.0.0/24"] == "" {
		t.Fatalf("zero-config pool rules missing; got %v", f.rules)
	}
	if o := f.orient["d:wg0:10.99.0.0/24"]; o != `oifname "wg0"` {
		t.Fatalf("zero-config pool forward orient must be bare `oifname \"wg0\"`, got %q", o)
	}
	if o := f.orient["s:wg0:10.99.0.0/24"]; o != `iifname "wg0"` {
		t.Fatalf("zero-config pool return orient must be bare `iifname \"wg0\"`, got %q", o)
	}
}

// TestDockerLocalSubnetPerInterface_PrimaryUseCase (S9.1 Slice 3, localSubnets fold): the PRIMARY
// OpenVPN use case — a client dials in and reaches the LAN behind its own gateway. With the OVPN tun
// co-terminated, the local-subnet class emits a tun-ingress accept per interface so Docker doesn't
// structurally drop tunnel-client→own-LAN. The `oifname != wg0` NEGATION is dropped (founder-ruled):
// a packet to the gateway's OWN LAN cannot egress a tunnel — routing sends it out the LAN interface,
// and the subnet-disjointness validator guarantees NO site subnet overlaps a local subnet. The fake
// cannot observe kernel egress, so that guarantee is CITED + pinned here, not packet-tested.
func TestDockerLocalSubnetPerInterface_PrimaryUseCase(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.SetOVPNTun("tunnex-ovpn")
	m.reconcileDockerForward(context.Background(), nil, []string{"172.31.0.0/16"}, "")
	// per-interface: forward + return for BOTH wg0 and the OVPN tun (the OVPN path was structurally dropped before).
	for _, k := range []string{
		"d:wg0:172.31.0.0/16", "s:wg0:172.31.0.0/16",
		"d:tunnex-ovpn:172.31.0.0/16", "s:tunnex-ovpn:172.31.0.0/16",
	} {
		if f.rules[k] == "" {
			t.Fatalf("missing per-interface local-subnet rule %s (OVPN client→own-LAN would drop); got %v", k, f.rules)
		}
	}
	// ANTI-SPOOF at the DOCKER-USER tier: every local-subnet forward is TUNNEL-INGRESS keyed
	// (`iifname <tif>`), never a non-tunnel ingress and never a `!=` negation — an eth0 spoofer's
	// packet (iifname=eth0 ∉ {wg0,tunnex-ovpn}) matches no local-subnet accept. (The ip tunnex chain
	// is the real boundary — TestOVPNTunJoinsTunnelSet_MeshAntiSpoof; this confirms the coverage tier
	// added no hole.)
	if o := f.orient["d:tunnex-ovpn:172.31.0.0/16"]; o != `iifname "tunnex-ovpn"` {
		t.Fatalf("OVPN local-subnet forward must be `iifname \"tunnex-ovpn\"` (ingress-keyed, no negation), got %q", o)
	}
	for k, o := range f.orient {
		if strings.HasSuffix(k, "172.31.0.0/16") && strings.Contains(o, "!=") {
			t.Fatalf("local-subnet accept %s must not carry a `!=` negation (anti-spoof: ingress-keyed), got %q", k, o)
		}
	}
}

// TestDockerLocalSubnetZeroConfigByteIdentical (S9.1 Slice 3): WireGuard-only emits exactly the two
// local-subnet rules, tunnel-ingress keyed (the negation drop is the only intended shape change; a
// WG-only deployment sees one pair, wg0-oriented).
func TestDockerLocalSubnetZeroConfigByteIdentical(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f) // no SetOVPNTun
	m.reconcileDockerForward(context.Background(), nil, []string{"172.31.0.0/16"}, "")
	if len(f.rules) != 2 {
		t.Fatalf("WG-only must emit exactly 2 local-subnet rules, got %v", f.rules)
	}
	if o := f.orient["d:wg0:172.31.0.0/16"]; o != `iifname "wg0"` {
		t.Fatalf("zero-config local-subnet forward must be bare `iifname \"wg0\"`, got %q", o)
	}
	if o := f.orient["s:wg0:172.31.0.0/16"]; o != `oifname "wg0"` {
		t.Fatalf("zero-config local-subnet return must be bare `oifname \"wg0\"`, got %q", o)
	}
}

// TestDockerLocalSubnetSweepsDepartedTun (S9.1 Slice 3): the sweep covers the local-subnet class too —
// a departed OVPN tun's local-subnet rules leave, wg0's survive.
func TestDockerLocalSubnetSweepsDepartedTun(t *testing.T) {
	f := newFakeNft()
	m := mgrWithNft(f)
	m.SetOVPNTun("tunnex-ovpn")
	m.reconcileDockerForward(context.Background(), nil, []string{"172.31.0.0/16"}, "")
	m.SetOVPNTun("")
	m.reconcileDockerForward(context.Background(), nil, []string{"172.31.0.0/16"}, "")
	for _, k := range []string{"d:tunnex-ovpn:172.31.0.0/16", "s:tunnex-ovpn:172.31.0.0/16"} {
		if _, still := f.rules[k]; still {
			t.Fatalf("departed tun's local-subnet rule %s must be swept, got %v", k, f.rules)
		}
	}
	for _, k := range []string{"d:wg0:172.31.0.0/16", "s:wg0:172.31.0.0/16"} {
		if f.rules[k] == "" {
			t.Fatalf("wg0's local-subnet rule %s must survive, got %v", k, f.rules)
		}
	}
}
