//go:build linux

package egress

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// K8N-7: an in-cluster gateway's node is closed to the tunnel by an input chain in both families. These
// pin the chain the renderer writes, which k8snetprep's validateTunnexInput reads back.

const wantInputChainV4 = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
`

const wantInputChainV4AIVPN = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 8083 counter accept comment "tunnex_input_ai_vpn"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
`

const wantInputChainV4MCPGateway = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 8084 counter accept comment "tunnex_input_mcp_gateway"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
`

const wantInputChainV4AIVPNAndMCPGateway = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 8083 counter accept comment "tunnex_input_ai_vpn"
    iifname "wg0" fib daddr . iif type local tcp dport 8084 counter accept comment "tunnex_input_mcp_gateway"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
`

const wantInputChainOpenVPN = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname { "wg0", "tun0" } ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname { "wg0", "tun0" } counter drop comment "tunnex_input_tunnel_drop"
  }
`

// inputChains returns the `chain input` block of `table ip tunnex` and of `table ip6 tunnex`.
func inputChains(t *testing.T, ruleset string) (v4, v6 string) {
	t.Helper()
	split := strings.SplitN(ruleset, "table ip6 tunnex {", 2)
	if len(split) != 2 {
		t.Fatalf("no ip6 table:\n%s", ruleset)
	}
	block := func(table string) string {
		start := strings.Index(table, "  chain input {\n")
		if start < 0 {
			return ""
		}
		end := strings.Index(table[start:], "\n  }\n")
		if end < 0 {
			t.Fatalf("unterminated input chain:\n%s", table)
		}
		return table[start : start+end+len("\n  }\n")]
	}
	if strings.Count(split[0], "chain input {") > 1 || strings.Count(split[1], "chain input {") > 1 {
		t.Fatalf("more than one input chain per family:\n%s", ruleset)
	}
	return block(split[0]), block(split[1])
}

func inputTestManager(k8s bool) *Manager {
	m := New("wg0")
	m.SetKubernetesMode(k8s)
	return m
}

func TestKubernetesRulesetHasTheInputChainInBothFamilies(t *testing.T) {
	m := inputTestManager(true)
	m.SetPolicy(&nodepolicy.Compiled{Version: 15, Mode: nodepolicy.ModeEnforcing})
	v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", m.policy.Load()))
	if v4 != wantInputChainV4 {
		t.Fatalf("ip tunnex input:\n%s\nwant:\n%s", v4, wantInputChainV4)
	}
	if v6 != wantInputChainV4 {
		t.Fatalf("ip6 tunnex input (the same rules; no AI VPN):\n%s\nwant:\n%s", v6, wantInputChainV4)
	}
}

func TestKubernetesInputChainAcceptsTheAIVPNListenerOnlyWhenConfiguredAndOnlyInIPv4(t *testing.T) {
	m := inputTestManager(true)
	m.SetAIVPNListener(true)
	v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", nil))
	if v4 != wantInputChainV4AIVPN {
		t.Fatalf("ip tunnex input with AI VPN:\n%s\nwant:\n%s", v4, wantInputChainV4AIVPN)
	}
	if v6 != wantInputChainV4 {
		t.Fatalf("ip6 tunnex input must not carry the IPv4-only AI VPN listener:\n%s", v6)
	}
	m.SetAIVPNListener(false)
	if v4, _ := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4 {
		t.Fatalf("the AI VPN accept outlived its listener:\n%s", v4)
	}
	// The port is the listener's.
	if aivpn.HTTPPort != strconv.Itoa(k8snetprep.InputAIVPNPort) {
		t.Fatalf("aivpn.HTTPPort=%s, the input chain accepts %d", aivpn.HTTPPort, k8snetprep.InputAIVPNPort)
	}
}

// AI-SEC-2: the MCP gateway listener (TCP 8084 on the tunnel address) is accepted only when configured,
// only in IPv4, after the AI VPN listener.
func TestKubernetesInputChainAcceptsTheMCPGatewayListenerOnlyWhenConfiguredAndOnlyInIPv4(t *testing.T) {
	m := inputTestManager(true)
	m.SetMCPGatewayListener(true)
	v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", nil))
	if v4 != wantInputChainV4MCPGateway {
		t.Fatalf("ip tunnex input with the MCP gateway:\n%s\nwant:\n%s", v4, wantInputChainV4MCPGateway)
	}
	if v6 != wantInputChainV4 {
		t.Fatalf("ip6 tunnex input must not carry the IPv4-only MCP gateway listener:\n%s", v6)
	}
	m.SetAIVPNListener(true)
	if v4, _ := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4AIVPNAndMCPGateway {
		t.Fatalf("ip tunnex input with both listeners:\n%s\nwant:\n%s", v4, wantInputChainV4AIVPNAndMCPGateway)
	}
	m.SetAIVPNListener(false)
	m.SetMCPGatewayListener(false)
	if v4, _ := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4 {
		t.Fatalf("the MCP gateway accept outlived its listener:\n%s", v4)
	}
	// The port is the listener's.
	if mcpwire.ListenerPort != k8snetprep.InputMCPGatewayPort {
		t.Fatalf("mcpwire.ListenerPort=%d, the input chain accepts %d", mcpwire.ListenerPort, k8snetprep.InputMCPGatewayPort)
	}
}

func TestKubernetesInputChainWithOpenVPNClosesBothTunnelsAndKeepsListenersOnWireGuard(t *testing.T) {
	m := inputTestManager(true)
	m.SetOVPNTun("tun0")
	v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", nil))
	if v4 != wantInputChainOpenVPN || v6 != wantInputChainOpenVPN {
		t.Fatalf("with OpenVPN:\n%s\n%s\nwant:\n%s", v4, v6, wantInputChainOpenVPN)
	}
}

// The input chain does not follow the policy: no state opens the node, and none closes DNS.
func TestKubernetesInputChainIsTheSameInEveryPolicyState(t *testing.T) {
	enforcing := &nodepolicy.Compiled{Version: 15, Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{
		// A grant whose destination covers the gateway node's own address (a range rule) does not open it.
		{SrcIP: "10.99.0.2", DstCIDR: "10.70.0.0/24", Protocol: "tcp", PortLow: 10250, PortHigh: 10250},
	}}
	for name, setup := range map[string]func(*Manager){
		"cold start":      func(*Manager) {},
		"nil":             func(m *Manager) { m.SetPolicy(nil) },
		"refused version": func(m *Manager) { m.SetPolicy(nil); m.refusedVersion.Store(99) },
		"enforcing":       func(m *Manager) { m.SetPolicy(enforcing) },
		"mesh":            func(m *Manager) { m.SetPolicy(&nodepolicy.Compiled{Version: 15, Mesh: true}) },
		"emergency":       func(m *Manager) { m.SetPolicy(enforcing); m.withdrawPolicy() },
	} {
		t.Run(name, func(t *testing.T) {
			m := inputTestManager(true)
			setup(m)
			v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", m.policy.Load()))
			if v4 != wantInputChainV4 || v6 != wantInputChainV4 {
				t.Fatalf("%s:\n%s\n%s", name, v4, v6)
			}
		})
	}
}

// VM and site gateways are out of scope (founder ruling): administrators may reach them over the VPN.
func TestVMRulesetHasNoInputChain(t *testing.T) {
	for name, pol := range map[string]*nodepolicy.Compiled{
		"nil":       nil,
		"mesh":      {Version: 15, Mesh: true},
		"enforcing": {Version: 15, Mode: nodepolicy.ModeEnforcing},
	} {
		m := inputTestManager(false)
		m.SetAIVPNListener(true)
		m.SetOVPNTun("tun0")
		m.SetPolicy(pol)
		rs := m.rulesetWith("10.99.0.0/24", pol)
		if strings.Contains(rs, "input") || strings.Contains(rs, "fib ") {
			t.Fatalf("%s: a VM gateway rendered an input chain:\n%s", name, rs)
		}
		// Byte for byte what Kubernetes mode renders minus the posture marker and the input chain.
		k := inputTestManager(true)
		k.SetAIVPNListener(true)
		k.SetOVPNTun("tun0")
		k.SetPolicy(pol)
		if pol == nil {
			continue // nil is deny-all in Kubernetes mode (K8N-5 item 3), the legacy mesh on a VM
		}
		k8s := k.rulesetWith("10.99.0.0/24", pol)
		v4, v6 := inputChains(t, k8s)
		marker := "  chain tunnex_posture_owner {\n    counter comment \"tunnex_host_posture_v1\"\n  }\n"
		stripped := strings.Replace(strings.Replace(strings.Replace(k8s, v4, "", 1), v6, "", 1), marker, "", 2)
		if stripped != rs {
			t.Fatalf("%s: the VM ruleset differs from Kubernetes mode beyond the marker and the input chain:\nVM:\n%s\nK8s stripped:\n%s", name, rs, stripped)
		}
	}
}

func TestKubernetesInputChainIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	for _, tun := range []string{"", "tun0"} {
		m := inputTestManager(true)
		m.SetAIVPNListener(true)
		m.SetMCPGatewayListener(true)
		m.SetAIInternalListener([]netip.Addr{netip.MustParseAddr("10.123.0.1"), netip.MustParseAddr("192.168.10.5")}, 9443)
		m.SetOVPNTun(tun)
		rs := m.rulesetWith("10.99.0.0/24", nil)
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(rs)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "cache initialization") {
				t.Skipf("nft cannot init netlink here (needs NET_ADMIN):\n%s", out)
			}
			t.Fatalf("nft rejected the rendered ruleset (%v):\n%s\n--- RULESET ---\n%s", err, out, rs)
		}
		stopped, err := hostPostureStoppedRuleset(m.tunnelIfaces())
		if err != nil {
			t.Fatal(err)
		}
		// The stop runs over the running table; check them as one transaction.
		cmd = exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(rs + stopped)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft rejected the stop over the running table (%v):\n%s", err, out)
		}
	}
}

// The ownership surface's kernel readback of the tunnel set also requires the input drop to name it.
func TestKubernetesTunnelReadbackRequiresTheInputDrop(t *testing.T) {
	for name, tc := range map[string]struct {
		k8s     bool
		tun     string
		listing func(*Manager) string
		err     string
	}{
		"the running table": {k8s: true, listing: func(m *Manager) string { return m.rulesetWith("10.99.0.0/24", nil) }},
		"with OpenVPN":      {k8s: true, tun: "tun0", listing: func(m *Manager) string { return m.rulesetWith("10.99.0.0/24", nil) }},
		"a table without the input chain (v0.1.44)": {k8s: true, err: "tunnel input drop is absent or ambiguous", listing: func(m *Manager) string {
			v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", nil))
			return strings.Replace(strings.Replace(m.rulesetWith("10.99.0.0/24", nil), v4, "", 1), v6, "", 1)
		}},
		"an input drop that leaves tun0 open": {k8s: true, tun: "tun0", err: `tunnel input drop interfaces=[wg0] want=[tun0 wg0]`, listing: func(m *Manager) string {
			return strings.Replace(m.rulesetWith("10.99.0.0/24", nil), `iifname { "wg0", "tun0" } counter drop comment "tunnex_input_tunnel_drop"`, `iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"`, 2)
		}},
		"two input drops": {k8s: true, err: "tunnel input drop is absent or ambiguous", listing: func(m *Manager) string {
			return strings.Replace(m.rulesetWith("10.99.0.0/24", nil), "    iifname \"wg0\" counter drop comment \"tunnex_input_tunnel_drop\"\n", "    iifname \"wg0\" counter drop comment \"tunnex_input_tunnel_drop\"\n    iifname \"wg0\" counter drop comment \"tunnex_input_tunnel_drop\"\n", 1)
		}},
		"an input drop with another statement": {k8s: true, err: "tunnel input drop semantics are invalid", listing: func(m *Manager) string {
			return strings.Replace(m.rulesetWith("10.99.0.0/24", nil), `iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"`, `iifname "wg0" tcp dport 22 counter drop comment "tunnex_input_tunnel_drop"`, 2)
		}},
		"a VM gateway needs none": {k8s: false, listing: func(m *Manager) string { return m.rulesetWith("10.99.0.0/24", nil) }},
	} {
		t.Run(name, func(t *testing.T) {
			m := inputTestManager(tc.k8s)
			m.SetOVPNTun(tc.tun)
			listing := tc.listing(m)
			m.nftRun = func(_ context.Context, args ...string) (string, error) {
				family := args[len(args)-2]
				parts := strings.SplitN(listing, "table ip6 tunnex {", 2)
				if family == "ip6" {
					return "table ip6 tunnex {" + parts[1], nil
				}
				return parts[0], nil
			}
			_, err := m.ReadAppliedOVPNTunnel(t.Context())
			if tc.err == "" && err != nil {
				t.Fatalf("readback refused: %v", err)
			}
			if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("readback error %v, want %q", err, tc.err)
			}
		})
	}
}

// The ownership check's fixtures (k8snetprep/testdata/k8n7-input*.nft-ruleset.json) are what a real
// kernel listed after loading this renderer's output. This pins the two together: if the input chain is
// rendered differently, the captures no longer describe what the gateway loads, and the check must be
// proved against the new shape (TestGatewayInputChainKernel regenerates them).
func TestInputChainRenderingIsTheOneTheOwnershipCheckWasProvedOn(t *testing.T) {
	captured, err := os.ReadFile("../k8snetprep/testdata/k8n7-input.rendered.nft")
	if err != nil {
		t.Fatal(err)
	}
	wantV4, wantV6 := inputChains(t, string(captured))
	m := inputTestManager(true)
	gotV4, gotV6 := inputChains(t, m.rulesetWith("100.65.0.2/32", nil))
	if gotV4 != wantV4 || gotV6 != wantV6 {
		t.Fatalf("the input chains are rendered as:\n%s%s\nthe ownership check was proved on a kernel that loaded:\n%s%s", gotV4, gotV6, wantV4, wantV6)
	}
}

const wantInputChainV4AIInternalOne = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" ip daddr 10.123.0.1 tcp dport 9443 counter accept comment "tunnex_input_ai_internal"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
`

const wantInputChainV4AllListeners = `  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 8083 counter accept comment "tunnex_input_ai_vpn"
    iifname "wg0" fib daddr . iif type local tcp dport 8084 counter accept comment "tunnex_input_mcp_gateway"
    iifname "wg0" ip daddr { 10.123.0.1, 192.168.10.5 } tcp dport 9443 counter accept comment "tunnex_input_ai_internal"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
`

// AI-KEYS-1: the internal AI endpoint accept exists only while an endpoint is configured, only in IPv4,
// last before the drop, on exactly its addresses and port. Without one the chain is byte for byte the
// chain before AI-KEYS-1 (the goldens above are unchanged).
func TestKubernetesInputChainAcceptsTheInternalAIEndpointOnlyWhileConfigured(t *testing.T) {
	m := inputTestManager(true)
	if v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4 || v6 != wantInputChainV4 {
		t.Fatalf("no endpoint changed the chain:\n%s\n%s", v4, v6)
	}
	if !m.SetAIInternalListener([]netip.Addr{netip.MustParseAddr("10.123.0.1")}, 9443) {
		t.Fatal("enabling did not report a change")
	}
	if m.SetAIInternalListener([]netip.Addr{netip.MustParseAddr("10.123.0.1")}, 9443) {
		t.Fatal("the same endpoint reported a change")
	}
	v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", nil))
	if v4 != wantInputChainV4AIInternalOne {
		t.Fatalf("ip tunnex input with the internal AI endpoint:\n%s\nwant:\n%s", v4, wantInputChainV4AIInternalOne)
	}
	if v6 != wantInputChainV4 {
		t.Fatalf("ip6 tunnex input must not carry the IPv4-only endpoint:\n%s", v6)
	}
	m.SetAIVPNListener(true)
	m.SetMCPGatewayListener(true)
	// Addresses render sorted, whatever order they are configured in.
	m.SetAIInternalListener([]netip.Addr{netip.MustParseAddr("192.168.10.5"), netip.MustParseAddr("10.123.0.1")}, 9443)
	if v4, _ := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4AllListeners {
		t.Fatalf("all listeners:\n%s\nwant:\n%s", v4, wantInputChainV4AllListeners)
	}
	m.SetAIVPNListener(false)
	m.SetMCPGatewayListener(false)
	if !m.SetAIInternalListener(nil, 0) {
		t.Fatal("disabling did not report a change")
	}
	if v4, _ := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4 {
		t.Fatalf("the endpoint accept outlived the endpoint:\n%s", v4)
	}
	for name, tc := range map[string]struct {
		addrs []string
		port  int
	}{
		"no address":        {nil, 9443},
		"three addresses":   {[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 9443},
		"duplicate":         {[]string{"10.0.0.1", "10.0.0.1"}, 9443},
		"public address":    {[]string{"203.0.113.7"}, 9443},
		"IPv6 address":      {[]string{"fd00::1"}, 9443},
		"privileged port":   {[]string{"10.0.0.1"}, 443},
		"the AI VPN port":   {[]string{"10.0.0.1"}, 8083},
		"the MCP port":      {[]string{"10.0.0.1"}, 8084},
		"port out of range": {[]string{"10.0.0.1"}, 70000},
	} {
		var addrs []netip.Addr
		for _, a := range tc.addrs {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		m.SetAIInternalListener(addrs, tc.port)
		if v4, _ := inputChains(t, m.rulesetWith("10.99.0.0/24", nil)); v4 != wantInputChainV4 {
			t.Fatalf("%s rendered an accept:\n%s", name, v4)
		}
	}
	// A VM gateway never renders an input chain for it.
	vm := inputTestManager(false)
	vm.SetAIInternalListener([]netip.Addr{netip.MustParseAddr("10.123.0.1")}, 9443)
	if rs := vm.rulesetWith("10.99.0.0/24", &nodepolicy.Compiled{Version: 15, Mode: nodepolicy.ModeEnforcing}); strings.Contains(rs, "input") || strings.Contains(rs, "9443") {
		t.Fatalf("a VM gateway rendered the endpoint accept:\n%s", rs)
	}
}
