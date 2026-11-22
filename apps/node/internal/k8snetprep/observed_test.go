package k8snetprep

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func observedFixture(t *testing.T, listing []byte) (map[string]bool, map[string][][]map[string]any) {
	t.Helper()
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		t.Fatal(err)
	}
	chains, rules := map[string]bool{}, map[string][][]map[string]any{}
	for _, entry := range doc.NFTables {
		if raw, ok := entry["chain"]; ok {
			var chain struct{ Name string }
			if err := json.Unmarshal(raw, &chain); err != nil {
				t.Fatal(err)
			}
			chains[chain.Name] = true
		}
		if raw, ok := entry["rule"]; ok {
			var rule struct {
				Chain string
				Expr  []map[string]any
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				t.Fatal(err)
			}
			var expr []map[string]any
			for _, item := range rule.Expr {
				if _, counter := item["counter"]; !counter {
					expr = append(expr, item)
				}
			}
			rules[rule.Chain] = append(rules[rule.Chain], expr)
		}
	}
	return chains, rules
}

func observedRules(t *testing.T, chains map[string][]string) (map[string]bool, map[string][][]map[string]any) {
	t.Helper()
	names, rules := map[string]bool{}, map[string][][]map[string]any{}
	for name, lines := range chains {
		names[name] = true
		for _, line := range lines {
			var expr []map[string]any
			if err := json.Unmarshal([]byte(line), &expr); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			rules[name] = append(rules[name], expr)
		}
	}
	return names, rules
}

const (
	xtComment     = `{"xt":{"type":"match","name":"comment"}}`
	xtAddrtype    = `{"xt":{"type":"match","name":"addrtype"}}`
	xtMasquerade  = `{"xt":{"type":"target","name":"MASQUERADE"}}`
	xtMark        = `{"xt":{"type":"target","name":"MARK"}}`
	kubeUnmarked  = `{"match":{"op":"!=","left":{"&":[{"meta":{"key":"mark"}},16384]},"right":16384}}`
	returnVerdict = `{"return":null}`
)

func daddr(op, addr string, bits int) string {
	b, _ := json.Marshal(map[string]any{"match": map[string]any{"op": op, "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "daddr"}}, "right": map[string]any{"prefix": map[string]any{"addr": addr, "len": bits}}}})
	return string(b)
}

func saddr(op, addr string, bits int) string {
	return strings.Replace(daddr(op, addr, bits), `"daddr"`, `"saddr"`, 1)
}

// The rules a real one-node k3s cluster (Flannel, kube-proxy, portmap) puts in
// ip nat: nothing there can rewrite traffic bound for a 100.64/10 tunnel.
func TestObservedProvesK3sFlannelCannotRewriteTunnelTraffic(t *testing.T) {
	listing, err := os.ReadFile("testdata/k3s-flannel-nat.json")
	if err != nil {
		t.Fatal(err)
	}
	chains, rules := observedFixture(t, listing)
	if len(rules["FLANNEL-POSTRTG"]) == 0 || len(rules["KUBE-POSTROUTING"]) == 0 {
		t.Fatal("fixture lost the chains under test")
	}
	if err := proveNoTunnelSourceNAT(chains, rules, "POSTROUTING", netip.MustParsePrefix("100.96.0.0/24"), nil); err != nil {
		t.Fatalf("k3s Flannel rules were refused: %v", err)
	}
}

// Flannel masquerades anything it sends to the pod network. A tunnel range
// that overlaps the pod network would be rewritten, so it must be refused.
func TestObservedRefusesTunnelRangeInsideFlannelPodNetwork(t *testing.T) {
	listing, err := os.ReadFile("testdata/k3s-flannel-nat.json")
	if err != nil {
		t.Fatal(err)
	}
	chains, rules := observedFixture(t, listing)
	err = proveNoTunnelSourceNAT(chains, rules, "POSTROUTING", netip.MustParsePrefix("10.42.7.0/24"), nil)
	if err == nil || !strings.Contains(err.Error(), "FLANNEL-POSTRTG") {
		t.Fatalf("overlapping tunnel range was accepted: %v", err)
	}
}

func gkeRules(t *testing.T) (map[string]bool, map[string][][]map[string]any) {
	return observedRules(t, map[string][]string{
		"POSTROUTING": {
			`[` + xtComment + `,{"jump":{"target":"KUBE-POSTROUTING"}}]`,
			`[` + xtComment + `,` + xtAddrtype + `,{"jump":{"target":"IP-MASQ"}}]`,
		},
		"KUBE-POSTROUTING": {
			`[` + kubeUnmarked + `,` + returnVerdict + `]`,
			`[` + xtMark + `]`,
			`[` + xtComment + `,` + xtMasquerade + `]`,
		},
		"IP-MASQ": {
			`[` + daddr("==", "169.254.0.0", 16) + `,` + xtComment + `,` + returnVerdict + `]`,
			`[` + daddr("==", "10.0.0.0", 8) + `,` + xtComment + `,` + returnVerdict + `]`,
			`[` + daddr("==", "100.64.0.0", 10) + `,` + xtComment + `,` + returnVerdict + `]`,
			`[` + xtComment + `,` + xtMasquerade + `]`,
		},
	})
}

// GKE Standard: IP-MASQ masquerades everything except a list of destination
// ranges. A tunnel range inside one of them is returned before the masquerade.
func TestObservedProvesGKEExcludedRange(t *testing.T) {
	chains, rules := gkeRules(t)
	for _, tunnel := range []string{"100.96.0.0/24", "10.200.0.0/16"} {
		if err := proveNoTunnelSourceNAT(chains, rules, "POSTROUTING", netip.MustParsePrefix(tunnel), nil); err != nil {
			t.Fatalf("%s: %v", tunnel, err)
		}
	}
}

func TestObservedRefusesGKERangeThatWouldBeMasqueraded(t *testing.T) {
	chains, rules := gkeRules(t)
	// Not in the exclusion list, and one that is only partly covered by it.
	for _, tunnel := range []string{"172.20.0.0/24", "100.0.0.0/8"} {
		err := proveNoTunnelSourceNAT(chains, rules, "POSTROUTING", netip.MustParsePrefix(tunnel), nil)
		if err == nil || !strings.Contains(err.Error(), "IP-MASQ") {
			t.Fatalf("%s was accepted: %v", tunnel, err)
		}
	}
}

func TestObservedRefusesWhatItCannotRead(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.96.0.0/24")
	for name, chains := range map[string]map[string][]string{
		"unguarded masquerade":      {"POSTROUTING": {`[{"masquerade":null}]`}},
		"masquerade behind a set":   {"POSTROUTING": {`[{"xt":{"type":"match","name":"set"}},` + xtMasquerade + `]`}},
		"unknown extension target":  {"POSTROUTING": {`[{"xt":{"type":"target","name":"NETMAP"}}]`}},
		"untyped extension target":  {"POSTROUTING": {`[{"xt":null}]`}},
		"untyped extension match":   {"POSTROUTING": {`[{"xt":null},{"return":null}]`, `[{"masquerade":null}]`}},
		"target before the end":     {"POSTROUTING": {`[` + xtMasquerade + `,{"return":null}]`}},
		"jump to a missing chain":   {"POSTROUTING": {`[{"jump":{"target":"GONE"}}]`}},
		"loop":                      {"POSTROUTING": {`[{"jump":{"target":"A"}}]`}, "A": {`[{"jump":{"target":"POSTROUTING"}}]`}},
		"unknown statement":         {"POSTROUTING": {`[{"redirect":null}]`}},
		"source inside the tunnel":  {"POSTROUTING": {`[` + saddr("==", "100.96.0.0", 24) + `,{"masquerade":null}]`}},
		"conditional return first":  {"POSTROUTING": {`[` + xtAddrtype + `,` + returnVerdict + `]`, `[{"masquerade":null}]`}},
		"other mark is not a guard": {"POSTROUTING": {`[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},1]},"right":1}},{"masquerade":null}]`}},
	} {
		names, rules := observedRules(t, chains)
		if err := proveNoTunnelSourceNAT(names, rules, "POSTROUTING", tunnel, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestObservedAcceptsWhatCannotReachTunnelTraffic(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.96.0.0/24")
	for name, chains := range map[string]map[string][]string{
		"no rules":                 {"POSTROUTING": nil},
		"pod-sourced masquerade":   {"POSTROUTING": {`[` + saddr("==", "10.244.0.0", 16) + `,{"masquerade":null}]`}},
		"other destination only":   {"POSTROUTING": {`[` + daddr("==", "10.244.0.0", 16) + `,{"masquerade":null}]`}},
		"excluded by negation":     {"POSTROUTING": {`[` + daddr("!=", "100.64.0.0", 10) + `,{"masquerade":null}]`}},
		"certain accept first":     {"POSTROUTING": {`[` + daddr("==", "100.64.0.0", 10) + `,{"accept":null}]`, `[{"masquerade":null}]`}},
		"accepted inside a jump":   {"POSTROUTING": {`[{"jump":{"target":"A"}}]`, `[{"masquerade":null}]`}, "A": {`[{"accept":null}]`}},
		"registered chain skipped": {"POSTROUTING": {`[{"jump":{"target":"IP-MASQ-AGENT"}}]`}, "IP-MASQ-AGENT": {`[{"masquerade":null}]`}},
	} {
		names, rules := observedRules(t, chains)
		if err := proveNoTunnelSourceNAT(names, rules, "POSTROUTING", tunnel, map[string]bool{"IP-MASQ-AGENT": true}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
