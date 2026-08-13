//go:build linux

package egress

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// The tunnex ruleset must: masquerade tunnel→egress (any non-tunnel oif), forward
// spoke↔spoke + spoke↔egress under a DROP policy (so the ct-state return guard is real
// and the egress side can't initiate into spokes). With no live wg0 in this pure
// renderer test, IPv6 has no NAT66 rule; a real IPv6 address enables it. This pins
// the generated rules without a live kernel.
func TestRuleset(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(nil) // received nil = legacy mesh (cold-start with no policy is now deny-all, finding #2)
	rs := m.ruleset("10.99.0.1/24")

	wants := []string{
		"table ip tunnex",
		"flush table ip tunnex",                                  // atomic replace (idempotent reconcile / self-heal)
		"type nat hook postrouting priority srcnat - 1",          // Tunnex owns pool SNAT before a CNI's conventional srcnat hook
		`ip saddr 10.99.0.1/24 oifname != "wg0" masquerade`,      // SOURCE-scoped NAT, any non-tunnel iface
		"type filter hook forward priority filter; policy drop;", // DROP policy → guards are real
		"ct state established,related accept",
		`iifname != "wg0" oifname != "wg0" counter accept comment "tunnex_native_forward_passthrough"`,
		`iifname "wg0" oifname "wg0" counter accept`,    // device-to-device (spoke↔spoke); counter=flow-log seam (S7.2)
		`iifname "wg0" oifname != "wg0" counter accept`, // full-tunnel egress out
		"table ip6 tunnex", // IPv6: forward DROP; NAT appears with a v6 wg0 address
	}
	for _, w := range wants {
		if !strings.Contains(rs, w) {
			t.Errorf("ruleset missing %q\n---\n%s", w, rs)
		}
	}
	// No masquerade uses iifname (unreliable in postrouting) — scope is ip saddr only.
	if strings.Contains(rs, "iifname \"wg0\" oifname != \"wg0\" masquerade") {
		t.Error("masquerade must be source-scoped (ip saddr), not iifname (unreliable in postrouting)")
	}
	// Without a live wg0 IPv6 address, the v6 table must not emit NAT66.
	v6 := rs[strings.Index(rs, "table ip6 tunnex"):]
	if strings.Contains(v6, "masquerade") {
		t.Errorf("ip6 table must not masquerade (would risk a v6 leak):\n%s", v6)
	}
	// Before wg0 is up (no subnet), the postrouting chain has NO masquerade rule.
	if strings.Contains(New("wg0").ruleset(""), "masquerade") {
		t.Error("no masquerade should be emitted when the pool subnet is unknown")
	}
}

// A host-network Kubernetes connector shares its network namespace with the CNI.
// CNIs conventionally register postrouting NAT at `srcnat`; nft does not define the
// order of equal-priority base chains, and the first NAT binding wins. Tunnex must
// therefore own its tightly scoped device-pool SNAT one priority earlier so the
// VIP->pod DNAT has a deterministic reverse-NAT return path. This is generic across
// EKS, AKS, GKE and on-prem CNIs; native non-pool traffic does not match the rule.
func TestRulesetSNATPrecedesConventionalCNIHook(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(nil)
	rs := m.ruleset("10.99.0.1/24")
	if got := strings.Count(rs, "type nat hook postrouting priority srcnat - 1; policy accept;"); got != 2 {
		t.Fatalf("both v4 and v6 Tunnex postrouting hooks must precede conventional CNI srcnat, got %d:\n%s", got, rs)
	}
	if strings.Contains(rs, "type nat hook postrouting priority srcnat; policy accept;") {
		t.Fatalf("equal-priority CNI/Tunnex NAT ordering must never be reintroduced:\n%s", rs)
	}
	if !strings.Contains(rs, `ip saddr 10.99.0.1/24 oifname != "wg0" masquerade`) {
		t.Fatalf("the early hook must remain source- and interface-scoped, got:\n%s", rs)
	}
}

func TestRulesetNativeForwardPassthroughKeepsTunnelBoundary(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(nil)
	rs := m.ruleset("10.99.0.1/24")
	native := `iifname != "wg0" oifname != "wg0" counter accept comment "tunnex_native_forward_passthrough"`
	if !strings.Contains(rs, native) {
		t.Fatalf("native CNI traffic must bypass the Tunnex forwarding policy; got:\n%s", rs)
	}
	forward := "type filter hook forward priority filter; policy drop;"
	if strings.Index(rs, native) < strings.Index(rs, forward) {
		t.Fatalf("native passthrough must live in the default-deny forward chain; got:\n%s", rs)
	}

	// Co-terminated OVPN is also a Tunnex tunnel. A packet touching either
	// tunnel must remain policy-gated rather than matching native passthrough.
	m.SetOVPNTun("tunnex-ovpn")
	withOVPN := m.ruleset("10.99.0.1/24")
	if !strings.Contains(withOVPN, `iifname != { "wg0", "tunnex-ovpn" } oifname != { "wg0", "tunnex-ovpn" } counter accept comment "tunnex_native_forward_passthrough"`) {
		t.Fatalf("native passthrough must exclude every tunnel interface; got:\n%s", withOVPN)
	}
}

func TestRulesetNativeForwardPassthroughExcludesExposedVIP(t *testing.T) {
	m := New("wg0")
	m.localIPs = func() map[netip.Addr]struct{} { return nil }
	m.SetEndpointSource(&fakeSource{m: map[string]fakeEntry{
		"prod/api": {ok: true, targets: []k8sTarget{{ip: "10.42.0.14", port: 8080}}},
	}})
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 7, Mode: nodepolicy.ModeEnforcing,
		VIPMappings: []nodepolicy.VIPMapping{{VIP: "100.64.0.5", Namespace: "prod", Service: "api", Protocol: "tcp", PortLow: 80, PortHigh: 80}},
	})
	m.ResolveK8sVIPs(context.Background())
	rs := m.ruleset("10.99.0.1/24")
	want := `iifname != "wg0" oifname != "wg0" ct original ip daddr != 100.64.0.5 counter accept comment "tunnex_native_forward_passthrough"`
	if !strings.Contains(rs, want) {
		t.Fatalf("native bypass must reserve every resolved synthetic VIP for grant enforcement; got:\n%s", rs)
	}
}

func TestIfaceValidationRejectsInjection(t *testing.T) {
	if ifaceRE.MatchString(`wg0" ; drop table ip tunnex ; #`) {
		t.Fatal("iface regex must reject an injection payload")
	}
	if !ifaceRE.MatchString("wg0") {
		t.Fatal("iface regex must accept a normal name")
	}
}
