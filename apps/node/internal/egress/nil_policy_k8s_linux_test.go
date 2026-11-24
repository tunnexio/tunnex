//go:build linux

package egress

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// K8N-5 item 3. In Kubernetes mode an absent policy never opens the tunnel: only an explicit Mesh=true
// artifact does. The emergency withdraw returns to the cold-start state (deny-all) in every mode.

const nilPolicySubnet = "10.99.0.1/24"

// forwardChain returns the rule lines of `chain forward { ... }` of the given family's table, hook line
// excluded.
func forwardChain(t *testing.T, ruleset, family string) []string {
	t.Helper()
	v4, v6, ok := strings.Cut(ruleset, "add table ip6 tunnex")
	if !ok {
		t.Fatalf("ruleset has no ip6 table:\n%s", ruleset)
	}
	table := v4
	if family == "ip6" {
		table = v6
	}
	_, body, ok := strings.Cut(table, "  chain forward {\n")
	if !ok {
		t.Fatalf("%s table has no forward chain:\n%s", family, table)
	}
	body, _, ok = strings.Cut(body, "  }\n")
	if !ok {
		t.Fatalf("%s forward chain is not closed:\n%s", family, table)
	}
	var rules []string
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "type filter hook forward") {
			rules = append(rules, line)
		}
	}
	return rules
}

// assertDenyAll requires exactly the cold-start forward chain in both families: conntrack return path,
// invalid drop, the native passthrough (both interfaces outside the tunnel set) and the counted drop.
// No rule may accept a packet that enters or leaves the tunnel.
func assertDenyAll(t *testing.T, ruleset string) {
	t.Helper()
	for _, family := range []string{"ip", "ip6"} {
		want := []string{
			"ct state established,related accept",
			`ct state invalid counter drop comment "tunnex_ct_invalid_drop"`,
		}
		want = append(want, `iifname != "wg0" oifname != "wg0" counter accept comment "tunnex_native_forward_passthrough"`)
		if family == "ip" {
			want = append(want, `iifname "wg0" oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu`)
		}
		want = append(want, `counter comment "tunnex_default_drop"`)
		got := forwardChain(t, ruleset, family)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%s forward chain:\n%s\nwant deny-all:\n%s", family, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

func assertLegacyMesh(t *testing.T, ruleset string) {
	t.Helper()
	for _, rule := range []string{
		`iifname "wg0" oifname "wg0" counter accept`,
		`iifname "wg0" oifname != "wg0" counter accept`,
	} {
		for _, family := range []string{"ip", "ip6"} {
			if !strings.Contains(strings.Join(forwardChain(t, ruleset, family), "\n"), rule) {
				t.Fatalf("%s forward chain lacks the mesh accept %q:\n%s", family, rule, ruleset)
			}
		}
	}
	if strings.Contains(ruleset, "tunnex_default_drop") {
		t.Fatalf("the mesh renders no default-drop counter:\n%s", ruleset)
	}
}

func TestKubernetesNilPolicyIsDenyAllNotMesh(t *testing.T) {
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetPolicy(nil) // what the control plane serves an off org's gateway that has nothing to serve
	assertDenyAll(t, m.rulesetWith(nilPolicySubnet, m.policy.Load()))
	v4, v6 := m.forwardRules(nil, true)
	if v4 != dropCounter || v6 != dropCounter {
		t.Fatalf("forwardRules(nil) in Kubernetes mode = %q / %q, want the cold-start drop", v4, v6)
	}
}

func TestVMNilPolicyStaysTheLegacyMesh(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(nil)
	assertLegacyMesh(t, m.rulesetWith(nilPolicySubnet, m.policy.Load()))
}

// The documented Zero Trust off behaviour of an in-cluster gateway (K8N-3, "Open mesh") is an explicit
// artifact, and it is unchanged.
func TestKubernetesExplicitMeshArtifactStaysOpen(t *testing.T) {
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeOff, Mesh: true})
	assertLegacyMesh(t, m.rulesetWith(nilPolicySubnet, m.policy.Load()))
}

// emergencyReadyManager has an enforcing policy in force and fakes the two readbacks the emergency path
// makes (no wg0, an empty table), so it runs without a kernel.
func emergencyReadyManager(t *testing.T, kubernetes bool) *Manager {
	t.Helper()
	m := New("wg0")
	m.SetKubernetesMode(kubernetes)
	m.runIPOutput = func(context.Context, ...string) (string, error) {
		return "", errors.New(`ip -o -4 addr show dev wg0: exit status 1: Device "wg0" does not exist`)
	}
	m.nftRun = func(context.Context, ...string) (string, error) { return "table ip tunnex {}", nil }
	m.SetPolicy(&nodepolicy.Compiled{Version: 1, Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{
		{SrcIP: "10.99.0.2", DstCIDR: "10.70.0.9/32", Protocol: "tcp", PortLow: 80, PortHigh: 80},
	}})
	if rs := m.rulesetWith(nilPolicySubnet, m.policy.Load()); !strings.Contains(rs, "10.70.0.9") {
		t.Fatalf("the grant is not in force before the withdraw:\n%s", rs)
	}
	return m
}

// The emergency withdraw, then what the next egress pass renders: Reconcile loads the stored policy once
// and renders rulesetWith(subnet, that policy). Before the fix this was the mesh, in both modes.
func TestEmergencyWithdrawThenEgressPassIsDenyAllInEveryMode(t *testing.T) {
	for _, kubernetes := range []bool{true, false} {
		m := emergencyReadyManager(t, kubernetes)
		if err := m.EmergencyWithdrawK8s(t.Context(), nil); err != nil {
			t.Fatalf("kubernetes=%v: emergency withdraw: %v", kubernetes, err)
		}
		if m.policy.Load() != nil || m.policyReceived.Load() {
			t.Fatalf("kubernetes=%v: the emergency withdraw did not return to the cold-start state", kubernetes)
		}
		assertDenyAll(t, m.rulesetWith(nilPolicySubnet, m.policy.Load()))

		// The next delivery leaves the withdrawn state, exactly as after a start.
		m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeOff, Mesh: true})
		assertLegacyMesh(t, m.rulesetWith(nilPolicySubnet, m.policy.Load()))
	}
}

// SetPolicy(nil) used to clear an unsupported-version refusal. The withdraw is not a supported artifact.
func TestEmergencyWithdrawKeepsAnUnsupportedVersionRefusal(t *testing.T) {
	m := emergencyReadyManager(t, true)
	m.SetPolicy(&nodepolicy.Compiled{Version: nodepolicy.MaxSupportedVersion + 1, Mode: nodepolicy.ModeOff, Mesh: true})
	refused := m.RefusedVersion()
	if refused == 0 {
		t.Fatal("the too-new artifact was not refused")
	}
	if err := m.EmergencyWithdrawK8s(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if m.RefusedVersion() != refused {
		t.Fatalf("the emergency withdraw cleared the refusal: %d, want %d", m.RefusedVersion(), refused)
	}
	assertDenyAll(t, m.rulesetWith(nilPolicySubnet, m.policy.Load()))
}
