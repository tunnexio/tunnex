//go:build linux

package k8snetprep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// K8N-7. The input hook of an in-cluster gateway closes the node to the tunnel. validateTunnexInput
// runs inside validateHookCoverage on every pass over the kernel's own listing, and at startup its
// refusal stops the process. It must accept the running chain and the stopped chain, each in its exact
// shape, accept a table that has no input chain yet, and refuse everything else.

// The kernel's JSON for each statement (nft 1.1.6, as listed by `nft -j -a list ruleset`).
func nftIifname(right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": right}}
}

func nftNameSet(names ...string) map[string]any {
	members := make([]any, len(names))
	for i, name := range names {
		members[i] = name
	}
	return map[string]any{"set": members}
}

var (
	nftReplyDirection = map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"ct": map[string]any{"key": "direction"}}, "right": "reply"}}
	nftEstablished    = map[string]any{"match": map[string]any{"op": "in", "left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": []any{"established", "related"}}}
	nftLocalOnIif     = map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"fib": map[string]any{"result": "type", "flags": []any{"daddr", "iif"}}}, "right": "local"}}
	nftCounter        = map[string]any{"counter": map[string]any{"packets": float64(0), "bytes": float64(0)}}
	nftAccept         = map[string]any{"accept": nil}
	nftDrop           = map[string]any{"drop": nil}
)

func nftDport(proto string, port int) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": proto, "field": "dport"}}, "right": float64(port)}}
}

func inputRule(family, comment string, expr ...map[string]any) nftRuleView {
	return nftRuleView{Family: family, Table: "tunnex", Chain: "input", Comment: comment, Expr: expr}
}

func inputReply(family string, tunnels any) nftRuleView {
	return inputRule(family, InputReplyRuleComment, nftIifname(tunnels), nftReplyDirection, nftEstablished, nftCounter, nftAccept)
}

func inputListener(family, comment, proto string, port int) nftRuleView {
	return inputRule(family, comment, nftIifname("wg0"), nftLocalOnIif, nftDport(proto, port), nftCounter, nftAccept)
}

func inputDrop(family string, tunnels any) nftRuleView {
	return inputRule(family, InputTunnelDropRuleComment, nftIifname(tunnels), nftCounter, nftDrop)
}

// runningInput is the chain the egress renderer writes, rule for rule.
func runningInput(family string, aiVPN bool, tunnels any) []nftRuleView {
	rules := []nftRuleView{
		inputReply(family, tunnels),
		inputListener(family, InputDNSRuleComment, "udp", InputDNSPort),
		inputListener(family, InputDNSRuleComment, "tcp", InputDNSPort),
	}
	if aiVPN {
		rules = append(rules, inputListener(family, InputAIVPNRuleComment, "tcp", InputAIVPNPort))
	}
	return append(rules, inputDrop(family, tunnels))
}

func stoppedInput(family string, tunnels any) []nftRuleView {
	return []nftRuleView{inputRule(family, StoppedTunnelDropRuleComment, nftIifname(tunnels), nftCounter, nftDrop)}
}

func inputChain(family string) nftChainView {
	return nftChainView{Family: family, Table: "tunnex", Name: "input", Type: "filter", Hook: "input", Priority: 0, Policy: "accept"}
}

var inputChainHandle uint64 = 8100

// tunnexInputKernel is tunnexNATKernel (the AWS worker, the marker, the device-pool rule) plus, per
// family, the given input chain and its rules, in order.
func tunnexInputKernel(t *testing.T, chains map[nftChainView][]nftRuleView) *awsTestKernel {
	t.Helper()
	f := tunnexNATKernel(t, devicePoolRule())
	for chain, rules := range chains {
		inputChainHandle++
		chain.Handle = inputChainHandle
		f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", chain))
		for _, rule := range rules {
			f.addRule(rule, false)
		}
	}
	return f
}

func TestTunnexInputAcceptsTheRunningAndTheStoppedChain(t *testing.T) {
	for name, tc := range map[string]struct {
		chains  map[nftChainView][]nftRuleView
		tunnels []string
	}{
		"no input chain (the manager's table, a v0.1.44 leftover)": {},
		"running, both families": {chains: map[nftChainView][]nftRuleView{
			inputChain("ip"): runningInput("ip", false, "wg0"), inputChain("ip6"): runningInput("ip6", false, "wg0")}},
		"running with the AI VPN listener in IPv4": {chains: map[nftChainView][]nftRuleView{
			inputChain("ip"): runningInput("ip", true, "wg0"), inputChain("ip6"): runningInput("ip6", false, "wg0")}},
		"running with OpenVPN: the reply and the drop name the set": {
			tunnels: []string{"wg0", "tun0"},
			chains: map[nftChainView][]nftRuleView{
				inputChain("ip"): runningInput("ip", false, nftNameSet("wg0", "tun0")), inputChain("ip6"): runningInput("ip6", false, nftNameSet("wg0", "tun0"))}},
		"stopped, both families": {chains: map[nftChainView][]nftRuleView{
			inputChain("ip"): stoppedInput("ip", "wg0"), inputChain("ip6"): stoppedInput("ip6", "wg0")}},
		"stopped with OpenVPN": {
			tunnels: []string{"wg0", "tun0"},
			chains:  map[nftChainView][]nftRuleView{inputChain("ip"): stoppedInput("ip", nftNameSet("tun0", "wg0"))}},
	} {
		t.Run(name, func(t *testing.T) {
			f := tunnexInputKernel(t, tc.chains)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			if tc.tunnels != nil {
				r.UseTunnelInterfaces(func() []string { return tc.tunnels })
			}
			if _, err := r.Reconcile(t.Context(), testTunnel); err != nil {
				t.Fatalf("an exact gateway input chain was refused: %v", err)
			}
		})
	}
}

func TestTunnexInputRefusesEveryNearMiss(t *testing.T) {
	const (
		notChain     = "Tunnex input hook is not the exact registered chain"
		notRules     = "Tunnex input chain does not hold exactly the registered rules"
		notListener  = "Tunnex input listener is not the exact registered accept"
		notReply     = "Tunnex input reply accept is not limited to replies"
		notState     = "Tunnex input reply accept is not limited to established and related"
		replyShape   = "Tunnex input reply accept is not exact"
		dropShape    = "Tunnex input tunnel drop is not exact"
		leavesOpen   = "Tunnex input rule leaves a tunnel interface open"
		notIngress   = "Tunnex input rule is not limited to tunnel ingress"
		differ       = "Tunnex input reply and drop name different tunnels"
		unknownHook  = "unknown Tunnex hook"
		notHook      = "Tunnex input chain is not the registered input hook"
		invalidNames = "Tunnex input interface set is invalid"
	)
	running := func() []nftRuleView { return runningInput("ip", false, "wg0") }
	with := func(i int, rule nftRuleView) []nftRuleView { rules := running(); rules[i] = rule; return rules }
	chain := func(mutate func(*nftChainView)) nftChainView { c := inputChain("ip"); mutate(&c); return c }
	cases := map[string]struct {
		chains  map[nftChainView][]nftRuleView
		tunnels []string
		reason  string
	}{
		"policy drop":    {chains: map[nftChainView][]nftRuleView{chain(func(c *nftChainView) { c.Policy = "drop" }): running()}, reason: notChain},
		"priority -10":   {chains: map[nftChainView][]nftRuleView{chain(func(c *nftChainView) { c.Priority = -10 }): running()}, reason: notChain},
		"type nat":       {chains: map[nftChainView][]nftRuleView{chain(func(c *nftChainView) { c.Type = "nat" }): running()}, reason: notChain},
		"another name":   {chains: map[nftChainView][]nftRuleView{chain(func(c *nftChainView) { c.Name = "input2" }): nil}, reason: notChain},
		"an output hook": {chains: map[nftChainView][]nftRuleView{chain(func(c *nftChainView) { c.Name = "output"; c.Hook = "output" }): nil}, reason: unknownHook},
		"a regular chain named input": {chains: map[nftChainView][]nftRuleView{
			{Family: "ip", Table: "tunnex", Name: "input"}: nil}, reason: notHook},
		"a second input-hook chain beside the registered one": {chains: map[nftChainView][]nftRuleView{
			inputChain("ip"): running(), chain(func(c *nftChainView) { c.Name = "input_extra" }): nil}, reason: notChain},
		"empty":                 {chains: map[nftChainView][]nftRuleView{inputChain("ip"): nil}, reason: notRules},
		"the drop missing":      {chains: map[nftChainView][]nftRuleView{inputChain("ip"): running()[:3]}, reason: notRules},
		"the reply missing":     {chains: map[nftChainView][]nftRuleView{inputChain("ip"): running()[1:]}, reason: notRules},
		"an extra accept first": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): append([]nftRuleView{inputListener("ip", InputDNSRuleComment, "tcp", 10250)}, running()...)}, reason: notRules},
		"rules out of order": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): {
			inputListener("ip", InputDNSRuleComment, "udp", 53), inputReply("ip", "wg0"), inputListener("ip", InputDNSRuleComment, "tcp", 53), inputDrop("ip", "wg0")}}, reason: notRules},
		"the AI VPN listener in IPv6": {chains: map[nftChainView][]nftRuleView{inputChain("ip6"): runningInput("ip6", true, "wg0")}, reason: notRules},
		"the AI VPN listener twice": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): append(running()[:3],
			inputListener("ip", InputAIVPNRuleComment, "tcp", InputAIVPNPort), inputListener("ip", InputAIVPNRuleComment, "tcp", InputAIVPNPort), inputDrop("ip", "wg0"))}, reason: notRules},
		"the stopped drop beside running rules": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): append(running()[:4], stoppedInput("ip", "wg0")...)}, reason: notRules},
		"the stopped drop twice":                {chains: map[nftChainView][]nftRuleView{inputChain("ip"): append(stoppedInput("ip", "wg0"), stoppedInput("ip", "wg0")...)}, reason: notRules},
		"an unknown comment":                    {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(3, inputRule("ip", "tunnex_other", nftIifname("wg0"), nftCounter, nftDrop))}, reason: notRules},
		"DNS on another port (kubelet)":         {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(2, inputListener("ip", InputDNSRuleComment, "tcp", 10250))}, reason: notListener},
		"DNS over the wrong protocol":           {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(1, inputListener("ip", InputDNSRuleComment, "tcp", 53))}, reason: notListener},
		"the AI VPN listener on another port": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): append(running()[:3],
			inputListener("ip", InputAIVPNRuleComment, "tcp", 10250), inputDrop("ip", "wg0"))}, reason: notListener},
		"a listener without the local-on-wg0 match": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(1,
			inputRule("ip", InputDNSRuleComment, nftIifname("wg0"), nftDport("udp", 53), nftCounter, nftAccept))}, reason: notListener},
		"a listener on any local address": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(1,
			inputRule("ip", InputDNSRuleComment, nftIifname("wg0"), map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"fib": map[string]any{"result": "type", "flags": []any{"daddr"}}}, "right": "local"}}, nftDport("udp", 53), nftCounter, nftAccept))}, reason: notListener},
		"a listener on another interface": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(1,
			inputRule("ip", InputDNSRuleComment, nftIifname("eth0"), nftLocalOnIif, nftDport("udp", 53), nftCounter, nftAccept))}, reason: notListener},
		"a listener on the tunnel set, not wg0": {tunnels: []string{"wg0", "tun0"}, chains: map[nftChainView][]nftRuleView{inputChain("ip"): {
			inputReply("ip", nftNameSet("wg0", "tun0")),
			inputRule("ip", InputDNSRuleComment, nftIifname(nftNameSet("wg0", "tun0")), nftLocalOnIif, nftDport("udp", 53), nftCounter, nftAccept),
			inputListener("ip", InputDNSRuleComment, "tcp", 53), inputDrop("ip", nftNameSet("wg0", "tun0"))}}, reason: notListener},
		"a listener that drops instead": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(1,
			inputRule("ip", InputDNSRuleComment, nftIifname("wg0"), nftLocalOnIif, nftDport("udp", 53), nftCounter, nftDrop))}, reason: notListener},
		"a reply accept without ct direction reply": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(0,
			inputRule("ip", InputReplyRuleComment, nftIifname("wg0"), nftEstablished, nftCounter, nftAccept))}, reason: replyShape},
		"a reply accept in the original direction": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(0,
			inputRule("ip", InputReplyRuleComment, nftIifname("wg0"), map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"ct": map[string]any{"key": "direction"}}, "right": "original"}}, nftEstablished, nftCounter, nftAccept))}, reason: notReply},
		"a reply accept of new connections": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(0,
			inputRule("ip", InputReplyRuleComment, nftIifname("wg0"), nftReplyDirection, map[string]any{"match": map[string]any{"op": "in", "left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": []any{"established", "related", "new"}}}, nftCounter, nftAccept))}, reason: notState},
		"a reply accept on any interface": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(0,
			inputRule("ip", InputReplyRuleComment, map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": "eth0"}}, nftReplyDirection, nftEstablished, nftCounter, nftAccept))}, reason: notIngress},
		"a drop that does not cover wg0":  {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(3, inputDrop("ip", "eth0"))}, reason: leavesOpen},
		"a drop that leaves tun0 open":    {tunnels: []string{"wg0", "tun0"}, chains: map[nftChainView][]nftRuleView{inputChain("ip"): runningInput("ip", false, "wg0")}, reason: leavesOpen},
		"a stopped drop that leaves tun0": {tunnels: []string{"wg0", "tun0"}, chains: map[nftChainView][]nftRuleView{inputChain("ip"): stoppedInput("ip", "wg0")}, reason: leavesOpen},
		"a drop that accepts":             {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(3, inputRule("ip", InputTunnelDropRuleComment, nftIifname("wg0"), nftCounter, nftAccept))}, reason: dropShape},
		"a drop limited to one port": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(3,
			inputRule("ip", InputTunnelDropRuleComment, nftIifname("wg0"), nftDport("tcp", 22), nftCounter, nftDrop))}, reason: dropShape},
		"reply and drop name different tunnels": {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(3, inputDrop("ip", nftNameSet("wg0", "tun9")))}, reason: differ},
		"an invalid interface name":             {chains: map[nftChainView][]nftRuleView{inputChain("ip"): with(3, inputDrop("ip", nftNameSet("wg0", "a b")))}, reason: invalidNames},
		"the IPv6 chain alone is wrong": {chains: map[nftChainView][]nftRuleView{
			inputChain("ip"): running(), inputChain("ip6"): runningInput("ip6", false, "wg0")[1:]}, reason: notRules},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := tunnexInputKernel(t, tc.chains)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			if tc.tunnels != nil {
				r.UseTunnelInterfaces(func() []string { return tc.tunnels })
			}
			_, err := r.Reconcile(t.Context(), testTunnel)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("a near-miss was not refused as %q: %v", tc.reason, err)
			}
		})
	}
}

// The restart: a new process (a fresh Reconciler) reads a kernel that already holds the gateway's input
// chain, running and then stopped. The listings are `nft -j -a list ruleset` from a kernel that loaded
// the egress manager's own rendering, saved by TestGatewayInputChainKernel in the egress package.
func TestTunnexInputRestartOverAKernelThatHoldsTheChain(t *testing.T) {
	for _, name := range []string{"k8n7-input", "k8n7-input-openvpn", "k8n7-input-stopped"} {
		t.Run(name, func(t *testing.T) {
			listing, err := os.ReadFile(filepath.Join("testdata", name+".nft-ruleset.json"))
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := parseCNISnapshot(string(listing))
			if err != nil {
				t.Fatal(err)
			}
			// Not vacuous: both families hold the input chain on the input hook.
			for _, family := range []string{"ip", "ip6"} {
				chain, ok := snapshot.chains[nftKey(family, "tunnex", "input")]
				if !ok || chain.Hook != "input" || len(snapshot.rules[nftKey(family, "tunnex", "input")]) == 0 {
					t.Fatalf("fixture has no %s input chain: %+v", family, chain)
				}
			}
			f := &awsTestKernel{version: "iptables-nft-save v1.8.8 (nf_tables)", next: 10000}
			if err := json.Unmarshal(listing, &f.doc); err != nil {
				t.Fatal(err)
			}
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			if strings.Contains(name, "openvpn") {
				r.UseTunnelInterfaces(func() []string { return []string{"wg0", "tun0"} })
			}
			for pass := 1; pass <= 2; pass++ {
				status, err := r.Reconcile(t.Context(), "100.65.0.2/32")
				if err != nil {
					t.Fatalf("pass %d after restart refused the table this gateway renders: %v", pass, err)
				}
				if status.Host.State != StateReady {
					t.Fatalf("pass %d after restart is not ready: %+v", pass, status)
				}
			}
			if len(f.mutations) != 0 {
				t.Fatalf("the check changed the kernel: %v", f.mutations)
			}
			// The same listing with OpenVPN live but not in the chain leaves tun0 open: refused.
			if !strings.Contains(name, "openvpn") {
				r = awsTestReconciler(t, f, ScopeIPMasqAndAWS)
				r.UseTunnelInterfaces(func() []string { return []string{"wg0", "tun0"} })
				if _, err := r.Reconcile(t.Context(), "100.65.0.2/32"); err == nil || !strings.Contains(err.Error(), "Tunnex input rule leaves a tunnel interface open") {
					t.Fatalf("a chain that leaves tun0 open was accepted: %v", err)
				}
			}
		})
	}
}
