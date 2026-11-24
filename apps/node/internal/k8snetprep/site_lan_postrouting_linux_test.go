//go:build linux

package k8snetprep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// K8N-5 item 4. SSI-8's site-LAN masquerade is rendered into `ip tunnex postrouting` on an in-cluster
// gateway whose site chose `lan_egress = gateway_address`. validateTunnexPostrouting must accept it in
// its one exact shape, with its marker and the tunnel exclusion, and still refuse everything else.

// nftSaddrAddress is the kernel's JSON for `ip saddr <one address>`: nft lists a /32 as a bare string.
func nftSaddrAddress(address string) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": address}}
}

func siteLANRule(source map[string]any) nftRuleView {
	return tunnexNATRule(SiteLANMasqueradeRuleComment, source, nftIface("!=", "wg0"), nftMasquerade)
}

func TestTunnexPostroutingAcceptsTheSiteLANMasquerade(t *testing.T) {
	for name, rules := range map[string][]nftRuleView{
		"one remote site range": {devicePoolRule(), siteLANRule(nftAddr("saddr", "10.50.0.0/24"))},
		"a /32 as nft lists it": {devicePoolRule(), siteLANRule(nftSaddrAddress("100.65.0.7"))},
		// The client-graph /32 of a device on another gateway lies in the device pool, which is also
		// this gateway's range. The renderer emits it under the marker; refusing it would crash-loop.
		"a device of another gateway, inside the tunnel range": {devicePoolRule(), siteLANRule(nftSaddrAddress("10.99.0.7"))},
		"next to the API return rule": {
			devicePoolRule(),
			siteLANRule(nftAddr("saddr", "10.50.0.0/24")),
			siteLANRule(nftAddr("saddr", "172.16.4.0/22")),
			apiReturnRule(testAPIVIP),
		},
		"before the tunnel has an address": {siteLANRule(nftAddr("saddr", "10.50.0.0/24"))},
		"OpenVPN co-terminated: the exclusion is a set that holds wg0": {
			tunnexNATRule("", nftAddr("saddr", testTunnel), nftIfaceSet("wg0", "tun0"), nftMasquerade),
			tunnexNATRule(SiteLANMasqueradeRuleComment, nftAddr("saddr", "10.50.0.0/24"), nftIfaceSet("wg0", "tun0"), nftMasquerade),
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

func TestTunnexPostroutingRefusesEveryNearMissOfTheSiteLANMasquerade(t *testing.T) {
	const (
		notMasquerade = "Tunnex site-LAN masquerade is not the exact registered masquerade"
		notOneSource  = "Tunnex site-LAN masquerade does not match one IPv4 source range"
		everySource   = "Tunnex site-LAN masquerade matches every source"
		noExclusion   = "Tunnex source-NAT lacks exact tunnel egress exclusion"
		couldBind     = "Tunnex NAT could bind traffic returning to WireGuard"
		unknown       = "unknown Tunnex source-NAT rule"
		wrongPool     = "Tunnex source-NAT CIDR differs from current tunnel"
		apiShape      = "Tunnex API return rule does not match one original IPv4 destination"
	)
	site := nftAddr("saddr", "10.50.0.0/24")
	exclusion := nftIface("!=", "wg0")
	marked := func(expr ...map[string]any) nftRuleView {
		return tunnexNATRule(SiteLANMasqueradeRuleComment, expr...)
	}
	saddr := func(op string, right any) map[string]any {
		return map[string]any{"match": map[string]any{"op": op, "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": right}}
	}
	for name, tt := range map[string]struct {
		rule nftRuleView
		want string
	}{
		// Wrong statement.
		"snat instead of masquerade":   {marked(site, exclusion, map[string]any{"snat": map[string]any{"addr": "10.70.0.6"}}), notMasquerade},
		"masquerade with flags":        {marked(site, exclusion, map[string]any{"masquerade": map[string]any{"flags": []any{"random"}}}), notMasquerade},
		"masquerade to a port range":   {marked(site, exclusion, map[string]any{"masquerade": map[string]any{"port": float64(1024)}}), notMasquerade},
		"accept instead of masquerade": {marked(site, exclusion, map[string]any{"accept": nil}), notMasquerade},
		"return instead of masquerade": {marked(site, exclusion, map[string]any{"return": nil}), notMasquerade},
		"an extra statement":           {marked(site, nftAddr("daddr", "10.70.0.0/24"), exclusion, nftMasquerade), notMasquerade},
		"an extra log statement":       {marked(site, exclusion, map[string]any{"log": nil}, nftMasquerade), notMasquerade},
		// Not one IPv4 source range.
		"ip daddr instead of ip saddr":   {marked(nftAddr("daddr", "10.50.0.0/24"), exclusion, nftMasquerade), notOneSource},
		"ct original ip saddr":           {marked(nftCT("ip saddr", "original", "==", "10.50.0.5"), exclusion, nftMasquerade), notOneSource},
		"the original destination":       {marked(nftOriginalDst("10.50.0.5"), exclusion, nftMasquerade), notOneSource},
		"every source but one range":     {marked(saddr("!=", nftPrefix("10.50.0.0", 24)), exclusion, nftMasquerade), notOneSource},
		"a set of ranges":                {marked(saddr("==", map[string]any{"set": []any{nftPrefix("10.50.0.0", 24), nftPrefix("10.51.0.0", 24)}}), exclusion, nftMasquerade), notOneSource},
		"a range of addresses":           {marked(saddr("==", map[string]any{"range": []any{"10.50.0.1", "10.50.0.9"}}), exclusion, nftMasquerade), notOneSource},
		"host bits set":                  {marked(saddr("==", nftPrefix("10.50.0.5", 24)), exclusion, nftMasquerade), notOneSource},
		"a non-canonical address":        {marked(nftSaddrAddress("10.050.000.005"), exclusion, nftMasquerade), notOneSource},
		"an IPv6 address":                {marked(nftSaddrAddress("fd00::5"), exclusion, nftMasquerade), notOneSource},
		"a number, not an address":       {marked(saddr("==", float64(5)), exclusion, nftMasquerade), notOneSource},
		"every source, 0.0.0.0/0":        {marked(nftAddr("saddr", "0.0.0.0/0"), exclusion, nftMasquerade), everySource},
		"no source match at all":         {marked(exclusion, nftMasquerade), notMasquerade},
		"the exclusion before the range": {marked(exclusion, site, nftMasquerade), notOneSource},
		// The tunnel exclusion: this is what keeps the invariant.
		"no interface exclusion":                {marked(site, nftMasquerade), notMasquerade},
		"the exclusion names another interface": {marked(site, nftIface("!=", "eth0"), nftMasquerade), couldBind},
		"the exclusion set does not hold wg0":   {marked(site, nftIfaceSet("tun0", "eth0"), nftMasquerade), couldBind},
		"oifname equal instead of not equal":    {marked(site, nftIface("==", "wg0"), nftMasquerade), noExclusion},
		"iifname instead of oifname":            {marked(site, map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": "wg0"}}, nftMasquerade), noExclusion},
		// The marker identifies the rule; it is required and it is exact.
		"the exact shape without the marker":        {tunnexNATRule("", site, exclusion, nftMasquerade), wrongPool},
		"the exact shape under another comment":     {tunnexNATRule("tunnex_site_lan_masquerade_v2", site, exclusion, nftMasquerade), unknown},
		"the exact shape under the API marker":      {tunnexNATRule(APIReturnRuleComment, site, exclusion, nftMasquerade), apiShape},
		"the marker on the API return shape":        {marked(nftOriginalDst(testAPIVIP), exclusion, nftMasquerade), notOneSource},
		"the marker on an unconditional masquerade": {marked(nftMasquerade), notMasquerade},
		// The IPsec desktop exemption is not taught (K8N-5 item 4, (b)): it is still refused.
		"the IPsec desktop exemption": {tunnexNATRule("tunnex_ipsec_desktop_no_snat", nftAddr("saddr", "10.99.0.2/32"), nftAddr("daddr", "10.60.0.0/24"), map[string]any{"return": nil}), unknown},
	} {
		t.Run(name, func(t *testing.T) {
			// After the device-pool rule, and again after valid site-LAN and API return rules: a good
			// rule earlier in the chain must not let a bad one through.
			for _, before := range [][]nftRuleView{
				{devicePoolRule()},
				{devicePoolRule(), siteLANRule(nftAddr("saddr", "10.51.0.0/24")), apiReturnRule("100.65.0.9")},
			} {
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

func TestTunnexPostroutingRefusesADuplicateSiteLANMasquerade(t *testing.T) {
	// The same range twice, also in its two nft spellings of a /32.
	for name, rules := range map[string][]nftRuleView{
		"a range twice": {siteLANRule(nftAddr("saddr", "10.50.0.0/24")), siteLANRule(nftAddr("saddr", "10.50.0.0/24"))},
		"a /32 twice":   {siteLANRule(nftSaddrAddress("10.50.0.5")), siteLANRule(nftAddr("saddr", "10.50.0.5/32"))},
	} {
		t.Run(name, func(t *testing.T) {
			f := tunnexNATKernel(t, append([]nftRuleView{devicePoolRule()}, rules...)...)
			if _, err := awsTestReconciler(t, f, ScopeIPMasqAndAWS).Reconcile(t.Context(), testTunnel); err == nil || !strings.Contains(err.Error(), "Tunnex site-LAN masquerade is duplicated") {
				t.Fatalf("duplicate site-LAN rule: %v", err)
			}
		})
	}
}

// The evidence for not teaching the IPsec desktop exemption (K8N-5 item 4, (b)): IPsec on a gateway
// needs its guard table, `inet tunnex_ipsec`, whose postrouting hooks the host-network proof already
// refuses, whatever `ip tunnex postrouting` holds. Hook shapes are those of ipsec/guard_render.go.
func TestTheIPsecGuardHooksAreRefusedOnAnInClusterGateway(t *testing.T) {
	for _, hook := range []nftChainView{
		{Family: "inet", Table: "tunnex_ipsec", Name: "postrouting_guard", Handle: 9100, Type: "filter", Hook: "postrouting", Priority: 90, Policy: "accept"},
		{Family: "inet", Table: "tunnex_ipsec", Name: "postnat_guard", Handle: 9101, Type: "filter", Hook: "postrouting", Priority: 300, Policy: "accept"},
	} {
		t.Run(hook.Name, func(t *testing.T) {
			f := tunnexNATKernel(t, devicePoolRule())
			f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", hook))
			_, err := awsTestReconciler(t, f, ScopeIPMasqAndAWS).Reconcile(t.Context(), testTunnel)
			if err == nil || !strings.Contains(err.Error(), "unknown IPv4 postrouting hook coverage") {
				t.Fatalf("the IPsec guard's %s hook was not refused: %v", hook.Name, err)
			}
		})
	}
}

// The restart that crash-looped, at the function that refused: a new process (a fresh Reconciler, no
// memory of the artifact) reads a kernel that already holds the site-LAN rule. The listing is `nft -j -a
// list ruleset` from a kernel that loaded the egress manager's own rendering, saved by
// TestSiteLANMasqueradeKernel in the egress package next to that rendering (*.rendered.nft).
func TestTunnexPostroutingRestartOverAKernelThatHoldsTheSiteLANMasquerade(t *testing.T) {
	listing, err := os.ReadFile(filepath.Join("testdata", "k8n5-site-lan.nft-ruleset.json"))
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

	// Not vacuous: the listing holds the device-pool rule and the site-LAN rule, once, under its marker.
	snapshot, err := parseCNISnapshot(string(listing))
	if err != nil {
		t.Fatal(err)
	}
	chain := snapshot.rules[nftKey("ip", "tunnex", "postrouting")]
	held := 0
	for _, rule := range chain {
		if rule.Comment == SiteLANMasqueradeRuleComment {
			held++
		}
	}
	if held != 1 || len(chain) != 2 {
		t.Fatalf("fixture does not hold exactly the device-pool rule and one site-LAN rule: %+v", chain)
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

	// Accepting the site-LAN rule did not loosen the device-pool rule beside it.
	_, r = restart()
	if _, err := r.Reconcile(t.Context(), "100.65.0.9/32"); err == nil || !strings.Contains(err.Error(), "Tunnex source-NAT CIDR differs from current tunnel") {
		t.Fatalf("a different tunnel range was accepted: %v", err)
	}
}
