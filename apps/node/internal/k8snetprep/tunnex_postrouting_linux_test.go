//go:build linux

package k8snetprep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// K8N-3, "Return path for the API server". validateTunnexPostrouting runs on every pass of the gateway
// over the kernel's own listing, and at startup its refusal stops the process. It must accept the
// device-pool rule and the API return rule, each in its exact shape, and nothing else.

const (
	testTunnel = "10.99.0.0/24"
	testAPIVIP = "100.65.0.4"
)

// nftOriginalDst is the kernel's JSON for `ct original ip daddr <right>` (nft 1.1.6).
func nftOriginalDst(right any) map[string]any {
	return nftCT("ip daddr", "original", "==", right)
}

func nftCT(key, dir, op string, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": op, "left": map[string]any{"ct": map[string]any{"key": key, "dir": dir}}, "right": right}}
}

func nftIfaceSet(names ...string) map[string]any {
	members := make([]any, len(names))
	for i, name := range names {
		members[i] = name
	}
	return map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": map[string]any{"set": members}}}
}

func nftPrefix(addr string, bits int) map[string]any {
	return map[string]any{"prefix": map[string]any{"addr": addr, "len": float64(bits)}}
}

var nftMasquerade = map[string]any{"masquerade": nil}

func tunnexNATRule(comment string, expr ...map[string]any) nftRuleView {
	return nftRuleView{Family: "ip", Table: "tunnex", Chain: "postrouting", Comment: comment, Expr: expr}
}

func devicePoolRule() nftRuleView {
	return tunnexNATRule("", nftAddr("saddr", testTunnel), nftIface("!=", "wg0"), nftMasquerade)
}

func apiReturnRule(address string) nftRuleView {
	return tunnexNATRule(APIReturnRuleComment, nftOriginalDst(address), nftIface("!=", "wg0"), nftMasquerade)
}

// tunnexNATKernel is the AWS worker fixture plus the gateway's own table: the ownership marker and the
// given rules in `ip tunnex postrouting`, in order.
func tunnexNATKernel(t *testing.T, rules ...nftRuleView) *awsTestKernel {
	t.Helper()
	f := newAWSTestKernel(t)
	f.doc.NFTables = append(f.doc.NFTables,
		rawEntry("chain", nftChainView{Family: "ip", Table: "tunnex", Name: "postrouting", Handle: 8000, Type: "nat", Hook: "postrouting", Priority: 99, Policy: "accept"}),
		rawEntry("chain", nftChainView{Family: "ip", Table: "tunnex", Name: "tunnex_posture_owner", Handle: 8001}))
	f.addRule(nftRuleView{Family: "ip", Table: "tunnex", Chain: "tunnex_posture_owner", Comment: "tunnex_host_posture_v1", Expr: []map[string]any{{"counter": map[string]any{"packets": float64(0), "bytes": float64(0)}}}}, false)
	for _, rule := range rules {
		f.addRule(rule, false)
	}
	return f
}

func TestTunnexPostroutingAcceptsOnlyTheDevicePoolRuleAndTheAPIReturnRule(t *testing.T) {
	for name, rules := range map[string][]nftRuleView{
		"no rule yet":                                 nil,
		"the device-pool rule alone":                  {devicePoolRule()},
		"device-pool rule and API return":             {devicePoolRule(), apiReturnRule(testAPIVIP)},
		"API return before the tunnel has an address": {apiReturnRule(testAPIVIP)},
		"two API addresses":                           {devicePoolRule(), apiReturnRule(testAPIVIP), apiReturnRule("100.65.0.9")},
		"OpenVPN co-terminated: the exclusion is a set that holds wg0": {
			tunnexNATRule("", nftAddr("saddr", testTunnel), nftIfaceSet("wg0", "tun0"), nftMasquerade),
			tunnexNATRule(APIReturnRuleComment, nftOriginalDst(testAPIVIP), nftIfaceSet("wg0", "tun0"), nftMasquerade),
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := tunnexNATKernel(t, rules...)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			if _, err := r.Reconcile(t.Context(), testTunnel); err != nil {
				t.Fatalf("an exact gateway table was refused: %v", err)
			}
		})
	}
}

func TestTunnexPostroutingRefusesEveryNearMissOfTheAPIReturnRule(t *testing.T) {
	const (
		notMasquerade = "Tunnex API return rule is not the exact registered masquerade"
		notOneAddress = "Tunnex API return rule does not match one original IPv4 destination"
		noExclusion   = "Tunnex source-NAT lacks exact tunnel egress exclusion"
		couldBind     = "Tunnex NAT could bind traffic returning to WireGuard"
		unknown       = "unknown Tunnex source-NAT rule"
		// What the first attempt met: its unmarked rule was read as a device-pool rule for the wrong range.
		wrongPool = "Tunnex source-NAT CIDR differs from current tunnel"
	)
	exclusion := nftIface("!=", "wg0")
	marked := func(expr ...map[string]any) nftRuleView { return tunnexNATRule(APIReturnRuleComment, expr...) }
	for name, tt := range map[string]struct {
		rule nftRuleView
		want string
	}{
		// Wrong statement.
		"snat instead of masquerade":   {marked(nftOriginalDst(testAPIVIP), exclusion, map[string]any{"snat": map[string]any{"addr": "10.70.0.6"}}), notMasquerade},
		"masquerade with flags":        {marked(nftOriginalDst(testAPIVIP), exclusion, map[string]any{"masquerade": map[string]any{"flags": []any{"random"}}}), notMasquerade},
		"masquerade to a port range":   {marked(nftOriginalDst(testAPIVIP), exclusion, map[string]any{"masquerade": map[string]any{"port": float64(1024)}}), notMasquerade},
		"accept instead of masquerade": {marked(nftOriginalDst(testAPIVIP), exclusion, map[string]any{"accept": nil}), notMasquerade},
		"return instead of masquerade": {marked(nftOriginalDst(testAPIVIP), exclusion, map[string]any{"return": nil}), notMasquerade},
		"an extra statement":           {marked(nftOriginalDst(testAPIVIP), nftAddr("saddr", "10.0.0.0/8"), exclusion, nftMasquerade), notMasquerade},
		"an extra log statement":       {marked(nftOriginalDst(testAPIVIP), exclusion, map[string]any{"log": nil}, nftMasquerade), notMasquerade},
		// Not the flow's original destination.
		"ip saddr instead of the original destination": {marked(nftAddr("saddr", testAPIVIP+"/32"), exclusion, nftMasquerade), notOneAddress},
		"ip saddr as nft prints one address":           {marked(map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": testAPIVIP}}, exclusion, nftMasquerade), notOneAddress},
		"ip daddr, the destination after the rewrite":  {marked(map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "daddr"}}, "right": testAPIVIP}}, exclusion, nftMasquerade), notOneAddress},
		"ct original ip saddr":                         {marked(nftCT("ip saddr", "original", "==", testAPIVIP), exclusion, nftMasquerade), notOneAddress},
		"ct reply ip daddr":                            {marked(nftCT("ip daddr", "reply", "==", testAPIVIP), exclusion, nftMasquerade), notOneAddress},
		"ct original daddr without the family":         {marked(nftCT("daddr", "original", "==", testAPIVIP), exclusion, nftMasquerade), notOneAddress},
		"every original destination but one":           {marked(nftCT("ip daddr", "original", "!=", testAPIVIP), exclusion, nftMasquerade), notOneAddress},
		// Not one IPv4 address.
		"a prefix":                  {marked(nftOriginalDst(nftPrefix("100.65.0.0", 24)), exclusion, nftMasquerade), notOneAddress},
		"a /32 written as a prefix": {marked(nftOriginalDst(nftPrefix(testAPIVIP, 32)), exclusion, nftMasquerade), notOneAddress},
		"a set of addresses":        {marked(nftOriginalDst(map[string]any{"set": []any{testAPIVIP, "100.65.0.9"}}), exclusion, nftMasquerade), notOneAddress},
		"a range":                   {marked(nftOriginalDst(map[string]any{"range": []any{testAPIVIP, "100.65.0.9"}}), exclusion, nftMasquerade), notOneAddress},
		"an IPv6 address":           {marked(nftOriginalDst("fd00::4"), exclusion, nftMasquerade), notOneAddress},
		"an IPv4-mapped address":    {marked(nftOriginalDst("::ffff:100.65.0.4"), exclusion, nftMasquerade), notOneAddress},
		"a non-canonical address":   {marked(nftOriginalDst("100.065.000.004"), exclusion, nftMasquerade), notOneAddress},
		"an address with a zone":    {marked(nftOriginalDst("100.65.0.4%eth0"), exclusion, nftMasquerade), notOneAddress},
		"a number, not an address":  {marked(nftOriginalDst(float64(443)), exclusion, nftMasquerade), notOneAddress},
		// The tunnel exclusion: this is what keeps the invariant.
		"no interface exclusion at all":         {marked(nftOriginalDst(testAPIVIP), nftMasquerade), notMasquerade},
		"the exclusion names another interface": {marked(nftOriginalDst(testAPIVIP), nftIface("!=", "eth0"), nftMasquerade), couldBind},
		"the exclusion set does not hold wg0":   {marked(nftOriginalDst(testAPIVIP), nftIfaceSet("tun0", "eth0"), nftMasquerade), couldBind},
		"oifname equal instead of not equal":    {marked(nftOriginalDst(testAPIVIP), nftIface("==", "wg0"), nftMasquerade), noExclusion},
		"iifname instead of oifname":            {marked(nftOriginalDst(testAPIVIP), map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": "wg0"}}, nftMasquerade), noExclusion},
		"the exclusion before the address":      {marked(exclusion, nftOriginalDst(testAPIVIP), nftMasquerade), notOneAddress},
		// The marker identifies the rule; it is required and it is exact.
		"the exact shape without the marker":        {tunnexNATRule("", nftOriginalDst(testAPIVIP), exclusion, nftMasquerade), wrongPool},
		"the exact shape under another comment":     {tunnexNATRule("tunnex_k8s_api_return_v2", nftOriginalDst(testAPIVIP), exclusion, nftMasquerade), unknown},
		"the exact shape under a foreign comment":   {tunnexNATRule("kubernetes", nftOriginalDst(testAPIVIP), exclusion, nftMasquerade), unknown},
		"the marker on the device-pool shape":       {marked(nftAddr("saddr", testTunnel), exclusion, nftMasquerade), notOneAddress},
		"the marker on an unconditional masquerade": {marked(nftMasquerade), notMasquerade},
		// Any other rule is still refused, also next to a valid return rule.
		"the site-LAN masquerade":              {tunnexNATRule("tunnex_site_lan_masquerade", nftAddr("saddr", "10.70.0.0/24"), exclusion, nftMasquerade), unknown},
		"a device-pool rule for another range": {tunnexNATRule("", nftAddr("saddr", "10.98.0.0/24"), exclusion, nftMasquerade), wrongPool},
		"an unconditional masquerade":          {tunnexNATRule("", nftMasquerade), unknown},
		"a commented device-pool rule":         {tunnexNATRule("note", nftAddr("saddr", testTunnel), exclusion, nftMasquerade), unknown},
	} {
		t.Run(name, func(t *testing.T) {
			// Alone after the device-pool rule, and again after a valid return rule: a good rule
			// earlier in the chain must not let a bad one through.
			for _, before := range [][]nftRuleView{{devicePoolRule()}, {devicePoolRule(), apiReturnRule("100.65.0.9")}} {
				f := tunnexNATKernel(t, append(before, tt.rule)...)
				r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
				_, err := r.Reconcile(t.Context(), testTunnel)
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("after %d valid rule(s): err=%v, want refusal %q", len(before), err, tt.want)
				}
				if len(f.mutations) != 0 {
					t.Fatalf("a refused table was mutated: %v", f.mutations)
				}
			}
		})
	}
}

func TestTunnexPostroutingRefusesADuplicateAPIReturnRuleAndAMissingOwnershipMarker(t *testing.T) {
	f := tunnexNATKernel(t, devicePoolRule(), apiReturnRule(testAPIVIP), apiReturnRule(testAPIVIP))
	if _, err := awsTestReconciler(t, f, ScopeIPMasqAndAWS).Reconcile(t.Context(), testTunnel); err == nil || !strings.Contains(err.Error(), "Tunnex API return rule is duplicated") {
		t.Fatalf("duplicate return rule: %v", err)
	}

	// The return rule does not stand in for the table's ownership marker.
	f = newAWSTestKernel(t)
	f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", nftChainView{Family: "ip", Table: "tunnex", Name: "postrouting", Handle: 8000, Type: "nat", Hook: "postrouting", Priority: 99, Policy: "accept"}))
	f.addRule(apiReturnRule(testAPIVIP), false)
	if _, err := awsTestReconciler(t, f, ScopeIPMasqAndAWS).Reconcile(t.Context(), testTunnel); err == nil || !strings.Contains(err.Error(), "posture ownership marker") {
		t.Fatalf("table without its ownership marker: %v", err)
	}
}

// The restart that crash-looped the first attempt, at the function that refused: a NEW process (a fresh
// Reconciler, no memory of any mapping) reads a kernel that already holds the return rule. The listings
// are not hand-written: they are `nft -j -a list ruleset` from a kernel (nft 1.1.6) that had loaded the
// egress manager's own rendering, saved by TestK8sAPIReturnPathKernel in the egress package next to that
// rendering (*.rendered.nft). The inputs are the GKE walk: the gateway's tunnel address is 100.65.0.2,
// 100.65.0.4:443 is the cluster's API.
func TestTunnexPostroutingRestartOverAKernelThatHoldsTheAPIReturnRule(t *testing.T) {
	for _, name := range []string{"k8n3-api-return", "k8n3-api-return-openvpn"} {
		t.Run(name, func(t *testing.T) {
			listing, err := os.ReadFile(filepath.Join("testdata", name+".nft-ruleset.json"))
			if err != nil {
				t.Fatal(err)
			}
			restart := func() (*awsTestKernel, *Reconciler) {
				f := &awsTestKernel{version: "iptables-nft-save v1.8.8 (nf_tables)", next: 10000}
				if err := json.Unmarshal(listing, &f.doc); err != nil {
					t.Fatal(err)
				}
				return f, awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			}

			// Not vacuous: the kernel listing does hold the rule, once, under its marker.
			snapshot, err := parseCNISnapshot(string(listing))
			if err != nil {
				t.Fatal(err)
			}
			held := 0
			for _, rule := range snapshot.rules[nftKey("ip", "tunnex", "postrouting")] {
				if rule.Comment == APIReturnRuleComment {
					held++
				}
			}
			if held != 1 || len(snapshot.rules[nftKey("ip", "tunnex", "postrouting")]) != 2 {
				t.Fatalf("fixture does not hold exactly the device-pool rule and one return rule: %+v", snapshot.rules[nftKey("ip", "tunnex", "postrouting")])
			}

			f, r := restart()
			for pass := 1; pass <= 2; pass++ {
				status, err := r.Reconcile(t.Context(), "100.65.0.2/32")
				if err != nil {
					t.Fatalf("pass %d after restart refused the table this gateway renders: %v", pass, err)
				}
				if status.Host.State != StateReady || len(status.Adapters) == 0 || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
					t.Fatalf("pass %d after restart is not ready: %+v", pass, status)
				}
			}
			if len(f.mutations) != 0 {
				t.Fatalf("the check changed the kernel: %v", f.mutations)
			}
			if _, err := r.Withdraw(t.Context()); err != nil {
				t.Fatalf("withdrawal over the same kernel: %v", err)
			}

			// The same kernel still fails the check when the tunnel range is not the one in its
			// device-pool rule: accepting the return rule did not loosen the rule beside it.
			_, r = restart()
			if _, err := r.Reconcile(t.Context(), "100.65.0.9/32"); err == nil || !strings.Contains(err.Error(), "Tunnex source-NAT CIDR differs from current tunnel") {
				t.Fatalf("a different tunnel range was accepted: %v", err)
			}
		})
	}
}
