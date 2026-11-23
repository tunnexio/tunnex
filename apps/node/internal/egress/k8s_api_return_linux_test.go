//go:build linux

package egress

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// K8N-3, "Return path for the API server". The inputs are the GKE walk: the gateway's own tunnel address
// is 100.65.0.2, the device (10.99.0.2) belongs to another gateway, 100.65.0.4:443 is mapped to
// default/kubernetes whose only endpoint is the managed control plane (10.70.0.3, not a node), and
// 100.65.0.3:80 is an ordinary Service.
const (
	apiReturnTunnel  = "100.65.0.2/32"
	apiReturnDevice  = "10.99.0.2"
	apiReturnAPIVIP  = "100.65.0.4"
	apiReturnSvcVIP  = "100.65.0.3"
	apiReturnAPIRule = `ct original ip daddr 100.65.0.4 oifname != "wg0" masquerade comment "tunnex_k8s_api_return"`
	apiReturnPool    = `ip saddr 100.65.0.2/32 oifname != "wg0" masquerade`
)

func apiReturnPolicy(apiAccess bool) *nodepolicy.Compiled {
	p := &nodepolicy.Compiled{
		Version: 7, Mode: nodepolicy.ModeEnforcing,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: apiReturnDevice, DstCIDR: apiReturnSvcVIP + "/32", Protocol: "tcp", PortLow: 80, PortHigh: 80},
		},
		VIPMappings: []nodepolicy.VIPMapping{
			{VIP: apiReturnSvcVIP, Namespace: "prod", Service: "web", Protocol: "tcp", PortLow: 80, PortHigh: 80},
		},
	}
	if apiAccess {
		p.Allow = append(p.Allow, nodepolicy.AllowEntry{SrcIP: apiReturnDevice, DstCIDR: apiReturnAPIVIP + "/32", Protocol: "tcp", PortLow: 443, PortHigh: 443})
		p.VIPMappings = append(p.VIPMappings, nodepolicy.VIPMapping{VIP: apiReturnAPIVIP, Namespace: "default", Service: "kubernetes", Protocol: "tcp", PortLow: 443, PortHigh: 443})
	}
	return p
}

func apiReturnEndpoints() *fakeSource {
	return &fakeSource{m: map[string]fakeEntry{
		"default/kubernetes": {ok: true, targets: []k8sTarget{{ip: "10.70.0.3", port: 443}}},
		"prod/web":           {ok: true, targets: []k8sTarget{{ip: "10.70.0.9", port: 80}}},
	}}
}

// apiReturnManager resolves the mapping the way the egress pass does. Kubernetes mode is switched on only
// after resolving, so no host/CNI check runs here; it adds the ownership marker chain to the rendering.
func apiReturnManager(t *testing.T, policy *nodepolicy.Compiled, source endpointSource) *Manager {
	t.Helper()
	m := New("wg0")
	m.localIPs = func() map[netip.Addr]struct{} { return nil }
	m.SetEndpointSource(source)
	m.SetPolicy(policy)
	m.ResolveK8sVIPs(context.Background())
	m.SetKubernetesMode(true)
	return m
}

// natChain returns the rule lines of `table ip tunnex { chain postrouting { ... } }`, hook line excluded.
func natChain(t *testing.T, ruleset string) []string {
	t.Helper()
	v4, _, ok := strings.Cut(ruleset, "add table ip6 tunnex")
	if !ok {
		t.Fatalf("ruleset has no ip6 table to delimit the ip table:\n%s", ruleset)
	}
	_, body, ok := strings.Cut(v4, "  chain postrouting {\n")
	if !ok {
		t.Fatalf("ip table has no postrouting chain:\n%s", v4)
	}
	body, _, ok = strings.Cut(body, "  }\n")
	if !ok {
		t.Fatalf("postrouting chain is not closed:\n%s", v4)
	}
	var rules []string
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "type nat hook postrouting") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

func assertNATChain(t *testing.T, ruleset string, want ...string) {
	t.Helper()
	got := natChain(t, ruleset)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ip tunnex postrouting:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// (a) The rule is rendered for the address mapped to default/kubernetes, after the device-pool rule, and
// for nothing else: the Service next to it keeps the device's source.
func TestK8sAPIReturnRuleIsRenderedForTheAPIMappingOnly(t *testing.T) {
	m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
	rs := m.ruleset(apiReturnTunnel)
	assertNATChain(t, rs, apiReturnPool, apiReturnAPIRule)
	if !strings.HasSuffix(apiReturnAPIRule, `comment "`+k8snetprep.APIReturnRuleComment+`"`) {
		t.Fatalf("the rendered marker and the marker the ownership check accepts have diverged: %q", k8snetprep.APIReturnRuleComment)
	}
	// Both addresses are forwarded; only one of them is translated.
	for _, want := range []string{"ip daddr 100.65.0.4 tcp dport 443 dnat to 10.70.0.3:443", "ip daddr 100.65.0.3 tcp dport 80 dnat to 10.70.0.9:80"} {
		if !strings.Contains(rs, want) {
			t.Fatalf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	if n := strings.Count(rs, k8snetprep.APIReturnRuleComment); n != 1 {
		t.Fatalf("want one API return rule in the whole ruleset (never in ip6, never for a Service), got %d:\n%s", n, rs)
	}

	// With OpenVPN co-terminated the exclusion is the whole tunnel set, as in the device-pool rule.
	m.SetOVPNTun("tun0")
	assertNATChain(t, m.ruleset(apiReturnTunnel),
		`ip saddr 100.65.0.2/32 oifname != { "wg0", "tun0" } masquerade`,
		`ct original ip daddr 100.65.0.4 oifname != { "wg0", "tun0" } masquerade comment "tunnex_k8s_api_return"`)

	// Before the tunnel address is known there is no device-pool rule; the return rule does not depend on it.
	m.SetOVPNTun("")
	assertNATChain(t, m.ruleset(""), apiReturnAPIRule)
}

// (d) No address mapped to default/kubernetes, no rule. Each case is a way the mapping goes away while the
// gateway keeps running; the next rendering is the one a gateway that never had the mapping produces.
func TestK8sAPIReturnRuleDisappearsWithTheMapping(t *testing.T) {
	never := apiReturnManager(t, apiReturnPolicy(false), apiReturnEndpoints()).ruleset(apiReturnTunnel)
	assertNATChain(t, never, apiReturnPool)

	t.Run("API access turned off", func(t *testing.T) {
		m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
		assertNATChain(t, m.ruleset(apiReturnTunnel), apiReturnPool, apiReturnAPIRule)
		m.SetPolicy(apiReturnPolicy(false))
		m.ResolveK8sVIPs(context.Background())
		if got := m.ruleset(apiReturnTunnel); got != never {
			t.Fatalf("after API access is turned off the ruleset must be the one without it:\n%s\nwant:\n%s", got, never)
		}
	})
	t.Run("every mapping removed", func(t *testing.T) {
		m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
		m.SetPolicy(&nodepolicy.Compiled{Version: 7, Mode: nodepolicy.ModeEnforcing})
		m.ResolveK8sVIPs(context.Background())
		assertNATChain(t, m.ruleset(apiReturnTunnel), apiReturnPool)
	})
	for name, source := range map[string]*fakeSource{
		"no ready endpoint": {m: map[string]fakeEntry{
			"default/kubernetes": {ok: true},
			"prod/web":           {ok: true, targets: []k8sTarget{{ip: "10.70.0.9", port: 80}}},
		}},
		"endpoints not observed": {m: map[string]fakeEntry{
			"prod/web": {ok: true, targets: []k8sTarget{{ip: "10.70.0.9", port: 80}}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
			m.SetEndpointSource(source)
			m.ResolveK8sVIPs(context.Background())
			rs := m.ruleset(apiReturnTunnel)
			assertNATChain(t, rs, apiReturnPool)
			// The rewrite went with it: the rule never outlives the forwarding it serves.
			if strings.Contains(rs, "ip daddr "+apiReturnAPIVIP+" ") {
				t.Fatalf("the API address is still rewritten:\n%s", rs)
			}
		})
	}
	t.Run("gateway on the control-plane node", func(t *testing.T) {
		m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
		m.localIPs = func() map[netip.Addr]struct{} { return map[netip.Addr]struct{}{netip.MustParseAddr("10.70.0.3"): {}} }
		m.ResolveK8sVIPs(context.Background())
		assertNATChain(t, m.ruleset(apiReturnTunnel), apiReturnPool)
		if m.K8sAPIEndpointState() != ReasonEndpointsOnGatewayNode {
			t.Fatalf("state=%q", m.K8sAPIEndpointState())
		}
	})
}

// The renderer re-validates what it interpolates: only a canonical IPv4 address flagged as the API's
// reaches root ruleset text, once.
func TestK8sAPIReturnRuleRendersOnlyValidatedIPv4(t *testing.T) {
	m := New("wg0")
	if got := m.k8sAPIReturnRules([]string{"wg0"}); got != "" {
		t.Fatalf("nothing is resolved, yet a rule was rendered: %q", got)
	}
	resolved := []resolvedVIP{
		{vip: "100.65.0.9", apiServer: true},
		{vip: "100.65.0.4", apiServer: true},
		{vip: "100.65.0.4", apiServer: true},
		{vip: "100.65.0.3"},
		{vip: "fd00::4", apiServer: true},
		{vip: "100.65.0.0/24", apiServer: true},
		{vip: `100.65.0.5 accept comment "x`, apiServer: true},
	}
	m.resolvedVIPs.Store(&resolved)
	want := "    " + apiReturnAPIRule + "\n" + `    ct original ip daddr 100.65.0.9 oifname != "wg0" masquerade comment "tunnex_k8s_api_return"` + "\n"
	if got := m.k8sAPIReturnRules([]string{"wg0"}); got != want {
		t.Fatalf("rendered:\n%s\nwant:\n%s", got, want)
	}
}

// The ownership check's fixture (k8snetprep/testdata/k8n3-api-return.nft-ruleset.json) is what a real
// kernel listed after loading this renderer's output. This pins the two together: if the NAT chain is
// rendered differently, that capture no longer describes what the gateway loads, and the check must be
// proved against the new shape (TestK8sAPIReturnPathKernel regenerates both files).
func TestK8sAPIReturnRenderingIsTheOneTheOwnershipCheckWasProvedOn(t *testing.T) {
	captured, err := os.ReadFile("../k8snetprep/testdata/k8n3-api-return.rendered.nft")
	if err != nil {
		t.Fatal(err)
	}
	m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
	got, want := natChain(t, m.ruleset(apiReturnTunnel)), natChain(t, string(captured))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ip tunnex postrouting is rendered as:\n%s\nthe ownership check was proved on a kernel that loaded:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The syntax probe of TestRenderedRulesetIsValidNft, for the return rule in both interface forms.
func TestK8sAPIReturnRulesetIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	m := apiReturnManager(t, apiReturnPolicy(true), apiReturnEndpoints())
	for _, tun := range []string{"", "tun0"} {
		m.SetOVPNTun(tun)
		rs := m.ruleset(apiReturnTunnel)
		if !strings.Contains(rs, k8snetprep.APIReturnRuleComment) {
			t.Fatalf("probe would not exercise the return rule:\n%s", rs)
		}
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(rs)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "cache initialization") {
				t.Skipf("nft cannot init netlink here (needs NET_ADMIN):\n%s", out)
			}
			t.Fatalf("nft rejected the rendered ruleset (%v):\n%s\n--- RULESET ---\n%s", err, out, rs)
		}
	}
}
