//go:build linux

package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// TestKeepaliveSyncConfRoundTrip — S8.3 CK: buildSyncConf EMITS PersistentKeepalive for a site-link peer,
// and parseWGDump READS it back off the last dump field (so the actual side carries it → peersEqual
// converges instead of churning). An "off"/absent keepalive parses to 0.
func TestKeepaliveSyncConfRoundTrip(t *testing.T) {
	p := Peer{PublicKey: "hub", AllowedIPs: []string{"10.2.0.0/24"}, Endpoint: "h:51820", SiteLink: true, PersistentKeepalive: 25}
	conf := buildSyncConf("priv", 51820, []Peer{p})
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Fatalf("buildSyncConf must emit the keepalive, got:\n%s", conf)
	}
	got := parseWGDump("if\tpub\n" + "hub\t(none)\th:51820\t10.2.0.0/24\t0\t0\t0\t25\n")
	if len(got) != 1 || got[0].PersistentKeepalive != 25 {
		t.Fatalf("parseWGDump must read keepalive from the last field, got %+v", got)
	}
	off := parseWGDump("if\tpub\n" + "dev\t(none)\t1.2.3.4:5\t10.99.0.5/32\t0\t0\t0\toff\n")
	if len(off) != 1 || off[0].PersistentKeepalive != 0 {
		t.Fatalf("an 'off' keepalive must parse to 0, got %+v", off)
	}
}

// TestApplyRoutesV4EnumErrorSurfaces — S8.2 F3 (terminal): a -4 route-enumeration error ALWAYS surfaces
// (full-sweep), INCLUDING when there are no desired routes — the just-UNBOUND gateway, where the prune is
// owed. A -6 error is tolerated (v6-disabled host).
func TestApplyRoutesV4EnumErrorSurfaces(t *testing.T) {
	ctx := context.Background()
	fail := func(family string) func(context.Context, string, ...string) (string, error) {
		return func(_ context.Context, _ string, args ...string) (string, error) {
			if len(args) >= 2 && args[0] == family && args[1] == "route" { // the `ip <fam> route show` call
				return "", errors.New("route show failed")
			}
			return "", nil
		}
	}
	// Unbound gateway (cidrs empty) + a -4 show failure → MUST surface (the sweep is owed).
	b4 := &wgctrlBackend{iface: "wg0", runFn: fail("-4")}
	if err := b4.ApplyRoutes(ctx, nil, ""); err == nil {
		t.Fatal("F3: a -4 enum error must surface even with no desired routes (unbound gateway owes the prune)")
	}
	// A -6 show failure → tolerated.
	b6 := &wgctrlBackend{iface: "wg0", runFn: fail("-6")}
	if err := b6.ApplyRoutes(ctx, nil, ""); err != nil {
		t.Fatalf("a -6 enum error must be tolerated: %v", err)
	}
}

// TestApplyRoutesSrcHint — S8.2c D2 (backend seam): ApplyRoutes applies the reconcile-derived srcHint
// VERBATIM to each route, and re-applies it every call (survives reconcile — there is no persisted state to
// clobber). An empty srcHint programs the route WITHOUT a src (the no-site / D3 edges, which reconcile
// resolves to ""). The DERIVATION (which host addr, the no-match refusal) lives in TestSiteRouteSrc — the
// backend never guesses a src, it only threads the one it's handed.
func TestApplyRoutesSrcHint(t *testing.T) {
	ctx := context.Background()
	var gotArgs [][]string
	rec := func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "route" && args[1] == "replace" {
			gotArgs = append(gotArgs, append([]string(nil), args...))
		}
		return "", nil // route show returns empty (no prune)
	}
	b := &wgctrlBackend{iface: "wg0", runFn: rec}

	// srcHint set → applied to the route.
	gotArgs = nil
	if err := b.ApplyRoutes(ctx, []string{"10.0.0.0/24"}, "172.31.24.206"); err != nil {
		t.Fatal(err)
	}
	if len(gotArgs) != 1 || !hasPair(gotArgs[0], "src", "172.31.24.206") {
		t.Fatalf("D2: a non-empty srcHint must be applied as src; got %v", gotArgs)
	}
	// survives reconcile: a second call re-applies the same src.
	gotArgs = nil
	_ = b.ApplyRoutes(ctx, []string{"10.0.0.0/24"}, "172.31.24.206")
	if len(gotArgs) != 1 || !hasPair(gotArgs[0], "src", "172.31.24.206") {
		t.Fatalf("D2: the src-hint must SURVIVE reconcile (re-applied every tick); got %v", gotArgs)
	}
	// empty srcHint → no src (reconcile hands "" for the no-site + no-match edges).
	gotArgs = nil
	_ = b.ApplyRoutes(ctx, []string{"10.0.0.0/24"}, "")
	if len(gotArgs) != 1 || hasArg(gotArgs[0], "src") {
		t.Fatalf("empty srcHint → route programs WITHOUT a src; got %v", gotArgs)
	}
}

func TestApplyRoutesReconcilesDevicePoolReturnRuleAheadOfCNI(t *testing.T) {
	ctx := context.Background()
	var calls [][]string
	rec := func(_ context.Context, _ string, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		if strings.Join(args, " ") == "-4 rule show pref 100" {
			return "100: from all to 10.88.0.0/24 lookup main\n", nil
		}
		return "", nil
	}
	b := &wgctrlBackend{
		iface:             "wg0",
		runFn:             rec,
		interfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
	}
	if err := b.ApplyRoutes(ctx, []string{"10.99.0.0/24", "172.16.0.0/16"}, ""); err != nil {
		t.Fatal(err)
	}
	wantAdd := []string{"-4", "rule", "add", "pref", "100", "to", "10.99.0.0/24", "lookup", "main"}
	wantDel := []string{"-4", "rule", "del", "pref", "100", "to", "10.88.0.0/24", "lookup", "main"}
	if !hasCall(calls, wantAdd) {
		t.Fatalf("device-pool return rule not installed before provider CNI rules; calls=%v", calls)
	}
	if !hasCall(calls, wantDel) {
		t.Fatalf("departed Tunnex return rule not pruned; calls=%v", calls)
	}
	for _, c := range calls {
		if strings.Join(c, " ") == "-4 rule add pref 100 to 172.16.0.0/16 lookup main" {
			t.Fatalf("ordinary site route must not gain a priority rule; calls=%v", calls)
		}
	}
}

func TestReturnRulesIgnoresForeignPriorityShapes(t *testing.T) {
	got := returnRules("100: from all fwmark 0x80 lookup main\n100: from all to 10.99.0.7 lookup main\n")
	want := netip.MustParsePrefix("10.99.0.7/32")
	if len(got) != 1 || !got[want] {
		t.Fatalf("returnRules = %v, want only %s", got, want)
	}
}

func hasCall(calls [][]string, want []string) bool {
	for _, got := range calls {
		if strings.Join(got, "\x00") == strings.Join(want, "\x00") {
			return true
		}
	}
	return false
}

// TestSiteRouteSrc — S8.2c D2/D3, the PURE derivation shared by the backend (src-hint) and reconcile (the
// unreachable signal). Picks the host address inside an approved local subnet (never the overlay). Returns
// (_, false, false) for the no-site edge and (_, false, true) — the D3 signal — when a subnet is advertised
// but NO host address is inside it (bridge-trapped / misconfig, INDEPENDENT of link state → catches the
// reassuring-green shape).
func TestSiteRouteSrc(t *testing.T) {
	siteHost := netip.MustParseAddr("172.31.24.206") // inside the local site subnet
	overlay := netip.MustParseAddr("10.99.0.1")      // wg0 overlay — must NOT be chosen
	both := []netip.Addr{overlay, siteHost}

	// match → the local-subnet host addr, never the overlay.
	if src, ok, had := siteRouteSrc([]string{"172.31.0.0/16"}, both); !ok || !had || src != siteHost {
		t.Fatalf("D2: must pick the local-subnet host addr (not the overlay); got src=%v ok=%v had=%v", src, ok, had)
	}
	// advertised subnet + no host addr inside → D3 signal (had && !ok).
	if src, ok, had := siteRouteSrc([]string{"172.31.0.0/16"}, []netip.Addr{overlay}); ok || !had || src.IsValid() {
		t.Fatalf("D3: advertised subnet + no host addr inside → (invalid, false, true); got src=%v ok=%v had=%v", src, ok, had)
	}
	// no advertised subnet → not a signal (nothing to be unreachable).
	if _, ok, had := siteRouteSrc(nil, both); ok || had {
		t.Fatalf("no advertised subnet → (false, false); got ok=%v had=%v", ok, had)
	}
}

func hasArg(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}
func hasPair(args []string, k, v string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == k && args[i+1] == v {
			return true
		}
	}
	return false
}

// TestParseRouteDstNormalizesHost — S8.2 review #3: `ip route show` prints a host route as a BARE address
// (no /32), so a desired "10.1.0.5/32" and the enumerated "10.1.0.5" MUST canonicalize equal — otherwise
// a /32 site route churns install→delete every reconcile tick and blackholes.
func TestParseRouteDstNormalizesHost(t *testing.T) {
	want, ok1 := parseRouteDst("10.1.0.5/32")
	got, ok2 := parseRouteDst("10.1.0.5") // the bare form `ip route show` prints
	if !ok1 || !ok2 || got != want {
		t.Fatalf("a bare host must canonicalize to its /32 (no churn): %v vs %v", got, want)
	}
	// A v6 host normalizes to /128 too (the dual-family prune, review #4).
	w6, _ := parseRouteDst("2001:db8::1/128")
	g6, ok := parseRouteDst("2001:db8::1")
	if !ok || g6 != w6 {
		t.Fatalf("a bare v6 host must canonicalize to /128: %v vs %v", g6, w6)
	}
}

// TestRoutesToPruneCanonicalCompare — the pure prune decision compares canonical prefixes, so a desired
// /32 (enumerated bare) is NOT pruned while a genuinely stale route IS. Stability is the proof (#3).
func TestRoutesToPruneCanonicalCompare(t *testing.T) {
	desired := map[netip.Prefix]bool{}
	p, _ := parseRouteDst("10.1.0.5/32")
	desired[p] = true
	q, _ := parseRouteDst("10.2.0.0/24")
	desired[q] = true
	// As `ip route show` prints: the /32 as a bare host, the /24 as-is, plus a stale route we own.
	del := routesToPrune([]string{"10.1.0.5", "10.2.0.0/24", "10.9.0.0/24"}, desired)
	if len(del) != 1 || del[0].String() != "10.9.0.0/24" {
		t.Fatalf("only the stale route must prune (the /32 must NOT churn): %v", del)
	}
}

// TestBackendCloseDeletesInterface — WF-C Layer 1: Close is the symmetric destroy for the interface
// Configure creates. When the interface EXISTS, Close issues `ip link del <iface>` (so a graceful
// docker stop tears the data plane down, not a zombie hub). IDEMPOTENT: when it's already ABSENT
// (`ip link show` errors), Close is a no-op success — no `ip link del`, no error.
func TestBackendCloseDeletesInterface(t *testing.T) {
	ctx := context.Background()

	// EXISTS: `ip link show` succeeds → Close must issue `ip link del wg0`.
	var calls [][]string
	present := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		return "", nil // show + del both succeed
	}}
	if err := present.Close(ctx); err != nil {
		t.Fatalf("Close on a present interface must succeed, got %v", err)
	}
	sawDel := false
	for _, c := range calls {
		if len(c) >= 4 && c[0] == "ip" && c[1] == "link" && c[2] == "del" && c[3] == "wg0" {
			sawDel = true
		}
	}
	if !sawDel {
		t.Fatalf("Close must delete the interface (ip link del wg0), calls=%v", calls)
	}

	// ABSENT: `ip link show` errors → Close is a no-op success, NEVER an `ip link del`.
	absent := &wgctrlBackend{iface: "wg0", runFn: func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) >= 2 && args[0] == "link" && args[1] == "show" {
			return "", errors.New("Cannot find device \"wg0\"")
		}
		t.Fatalf("Close on an absent interface must NOT issue further commands, got args=%v", args)
		return "", nil
	}}
	if err := absent.Close(ctx); err != nil {
		t.Fatalf("Close on an absent interface must be idempotent (no error), got %v", err)
	}
}
