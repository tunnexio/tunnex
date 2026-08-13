//go:build darwin

package helper

import (
	"reflect"
	"strings"
	"testing"
)

// TestRouteTargets pins the RC2 split-default mapping: a full-tunnel default is
// installed as the WG-standard half-route PAIR (more specific than the physical
// default, so it takes precedence WITHOUT destroying it), while any non-default
// destination passes through unchanged. This is what makes teardown/crash recover
// the physical default automatically instead of stranding the host.
func TestRouteTargets(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"0.0.0.0/0", []string{"0.0.0.0/1", "128.0.0.0/1"}},
		{"::/0", []string{"::/1", "8000::/1"}},
		{"10.99.0.0/24", []string{"10.99.0.0/24"}}, // split-tunnel route untouched
		{"10.99.0.1/32", []string{"10.99.0.1/32"}},
	}
	for _, c := range cases {
		if got := routeTargets(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("routeTargets(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestBuildPFRulesUsesPassQuickNotSetSkip guards the kill-switch data-plane fix:
// `set skip on <iface>` is SILENTLY IGNORED inside a pf anchor (set options are
// main-ruleset-only), which left every packet routed onto the tunnel falling through
// `block drop out all` — the tunnel handshook but carried no data. The rules MUST use
// `pass quick on <iface>` (honored in an anchor) so loopback + the tunnel interface
// bypass the block. This pins that regression without a live pf.
func TestBuildPFRulesUsesPassQuickNotSetSkip(t *testing.T) {
	rules := buildPFRules("40.65.63.141:51820", "utun4", "")

	// `set skip` must NEVER appear — pf drops it in an anchor, silently disarming the bypass.
	if strings.Contains(rules, "set skip") {
		t.Errorf("buildPFRules must not use `set skip` (ignored inside a pf anchor):\n%s", rules)
	}
	// Loopback + the tunnel interface must be passed quick ABOVE the block.
	wants := []string{
		"pass quick on lo0 all",
		"pass quick on utun4 all",
		"block drop out all",
		"pass out proto udp to 40.65.63.141 port 51820", // WG endpoint (handshake + data)
	}
	for _, w := range wants {
		if !strings.Contains(rules, w) {
			t.Errorf("buildPFRules missing %q\n---\n%s", w, rules)
		}
	}
	// The quick passes must come BEFORE `block drop out all` (quick = first-match-wins).
	if i, j := strings.Index(rules, "pass quick on utun4"), strings.Index(rules, "block drop out all"); i < 0 || i > j {
		t.Errorf("`pass quick on utun4` must precede `block drop out all`:\n%s", rules)
	}

	// Before the tunnel exists (ifname ""), only loopback is passed — no tunnel iface,
	// so the initial arm blocks everything except the endpoint (fail-closed).
	initial := buildPFRules("40.65.63.141:51820", "", "")
	if strings.Contains(initial, "pass quick on utun") {
		t.Errorf("no tunnel-iface pass should be emitted before the tunnel exists:\n%s", initial)
	}
	if !strings.Contains(initial, "pass quick on lo0 all") {
		t.Errorf("loopback must always be passed:\n%s", initial)
	}
	// D-WFA-4: with NO CP endpoint (the default / split-tunnel), the ruleset must carry NO tcp carve-out —
	// the kill-switch is unchanged from before this slice (proves the carve-out is opt-in, widens nothing
	// when absent).
	if strings.Contains(rules, "proto tcp") {
		t.Errorf("no CP carve-out must appear when cpEndpoint is empty:\n%s", rules)
	}
}

// TestBuildPFRulesCPCarveOut (WF-A / D-WFA-4) — THE kill-switch invariant with the carve-out present:
// block-all + EXACTLY the named exceptions, plus ONE new named exception (the CP endpoint, tcp, its exact
// port). Proves the carve-out is scoped to the CP endpoint EXACTLY and nothing broader — the block-all
// invariant re-verified minus exactly one named line.
func TestBuildPFRulesCPCarveOut(t *testing.T) {
	rules := buildPFRules("40.65.63.141:51820", "utun4", "203.0.113.9:443")

	// The FULL exception set — and NOTHING else broad. block-all present; each pass is a NAMED, scoped line.
	wantExact := []string{
		"pass quick on lo0 all",
		"pass quick on utun4 all",
		"block drop out all",
		"pass out proto udp to 40.65.63.141 port 51820", // WG endpoint
		"pass out proto tcp to 203.0.113.9 port 443",    // D-WFA-4 CP carve-out — scoped to the CP IP:port EXACTLY
		"pass out proto udp from any port 68 to any port 67",
		"pass out proto udp from any port 546 to any port 547",
		"pass out inet6 proto icmp6 all",
	}
	for _, w := range wantExact {
		if !strings.Contains(rules, w) {
			t.Errorf("carve-out ruleset missing %q\n---\n%s", w, rules)
		}
	}
	// The carve-out must come BELOW block-all (block-all is the default; the passes are exceptions). Only
	// the `quick` passes short-circuit above it — the tcp CP pass is a plain (non-quick) pass evaluated
	// after the block, exactly like the WG endpoint pass.
	if strings.Contains(rules, "pass quick") && strings.Index(rules, "proto tcp to 203.0.113.9") < strings.Index(rules, "block drop out all") {
		t.Errorf("the CP carve-out must be a plain pass (below block-all), not a quick short-circuit:\n%s", rules)
	}
	// SCOPED EXACTLY: the CP pass names a single host:port, never a broad `to any` — the one thing that
	// would turn a named carve-out into a hole.
	if strings.Contains(rules, "pass out proto tcp to any") {
		t.Errorf("the CP carve-out must NOT be a broad `to any` — scoped to the CP endpoint exactly:\n%s", rules)
	}
}

// TestPhysGatewayForPerFamily (WF-A-FT-1) — the re-home pin selects the stored physical gateway by the new
// endpoint's family: v6 host → the v6 gateway, else v4 (the fold-#2 per-family guard).
func TestPhysGatewayForPerFamily(t *testing.T) {
	if g := physGatewayFor("15.135.130.96", "192.168.1.1", "fe80::1"); g != "192.168.1.1" {
		t.Fatalf("v4 endpoint must select the v4 gateway, got %q", g)
	}
	if g := physGatewayFor("2001:db8::2", "192.168.1.1", "fe80::1"); g != "fe80::1" {
		t.Fatalf("v6 endpoint must select the v6 gateway, got %q", g)
	}
}

// TestPinHostRouteViaUsesGivenGateway (WF-A-FT-1) — the re-home pin routes the new WG endpoint via the
// EXPLICIT (stored physical) gateway. Because gw is a PARAMETER, this path structurally CANNOT re-derive the
// tunnel next-hop via gatewayFor — the stuck-on-connecting loop the walk found is impossible here.
func TestPinHostRouteViaUsesGivenGateway(t *testing.T) {
	var got []string
	b := &darwinBackend{routeRun: func(args ...string) error { got = append(got, strings.Join(args, " ")); return nil }}
	fam, err := b.pinHostRouteVia("15.135.130.96", "192.168.1.1")
	if err != nil || fam != "-inet" {
		t.Fatalf("pin: fam=%q err=%v", fam, err)
	}
	var add string
	for _, c := range got {
		if strings.Contains(c, "add") {
			add = c
		}
	}
	// the ADD must be a HOST route for the endpoint, next-hop = the STORED gateway (not a tunnel next-hop).
	if !strings.Contains(add, "add -inet -host 15.135.130.96 192.168.1.1") {
		t.Fatalf("re-home pin must be `add -inet -host <endpoint> <stored-gw>`, got %q", add)
	}
}

// TestPinHostRouteViaEmptyGatewaySkips (WF-A-FT-1) — no stored gateway (on-link / not captured) → nothing is
// pinned, fam="" (never a bogus route). Guards the on-link edge + a full tunnel that captured no default.
func TestPinHostRouteViaEmptyGatewaySkips(t *testing.T) {
	called := 0
	b := &darwinBackend{routeRun: func(args ...string) error { called++; return nil }}
	fam, err := b.pinHostRouteVia("15.135.130.96", "")
	if err != nil || fam != "" || called != 0 {
		t.Fatalf("empty gw must pin nothing: fam=%q called=%d err=%v", fam, called, err)
	}
}

func TestAssignAddressesUsesFamilySpecificIfconfigSyntax(t *testing.T) {
	var got [][]string
	b := &darwinBackend{ifconfigRun: func(args ...string) error {
		got = append(got, append([]string(nil), args...))
		return nil
	}}
	if err := b.assignAddresses("utun6", []string{
		"10.99.0.2/32",
		"fd7a:1b2c:3d4e:33e7::a63:2/128",
	}, ""); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"utun6", "inet", "10.99.0.2", "10.99.0.2", "up"},
		{"utun6", "inet6", "fd7a:1b2c:3d4e:33e7::a63:2", "prefixlen", "128", "up"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ifconfig args = %#v, want %#v", got, want)
	}
}

func TestAssignAddressesFallsBackToLegacyAddress(t *testing.T) {
	var got []string
	b := &darwinBackend{ifconfigRun: func(args ...string) error { got = args; return nil }}
	if err := b.assignAddresses("utun6", nil, "10.99.0.2/32"); err != nil {
		t.Fatal(err)
	}
	want := []string{"utun6", "inet", "10.99.0.2", "10.99.0.2", "up"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ifconfig args = %#v, want %#v", got, want)
	}
}
