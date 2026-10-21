package ipsec

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func pendingNATFixture() []any {
	return []any{
		map[string]any{"table": map[string]any{"family": "ip", "name": "tunnex", "handle": 5}},
		map[string]any{"chain": map[string]any{"family": "ip", "table": "tunnex", "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 99, "policy": "accept", "handle": 6}},
		map[string]any{"rule": map[string]any{"family": "ip", "table": "tunnex", "chain": "postrouting", "handle": 7, "expr": []any{
			guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.0/24"))),
			guardMatch("!=", guardMeta("oifname"), "wg0"), map[string]any{"masquerade": nil},
		}}},
	}
}
func pendingNATExemption(source, destination string) any {
	return map[string]any{"rule": map[string]any{"family": "ip", "table": "tunnex", "chain": "postrouting", "comment": "tunnex_ipsec_desktop_no_snat", "expr": []any{
		guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix(source))),
		guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(netip.MustParsePrefix(destination))), guardCounter(), guardVerdict("return"),
	}}}
}
func pendingNATJSON(rows []any) []byte {
	raw, _ := json.Marshal(map[string]any{"nftables": rows})
	return raw
}
func pendingNATRule(row any) map[string]any { return row.(map[string]any)["rule"].(map[string]any) }
func TestDesktopNATExemptionPendingCanonicalOnly(t *testing.T) {
	source, destination := netip.MustParsePrefix("10.99.0.7/32"), netip.MustParsePrefix("10.182.10.246/32")
	for name, rows := range map[string][]any{
		"empty exemption list": pendingNATFixture(),
		"other source":         append(pendingNATFixture()[:2], pendingNATExemption("10.99.0.8/32", "10.182.10.246/32"), pendingNATFixture()[2]),
		"other destination":    append(pendingNATFixture()[:2], pendingNATExemption("10.99.0.7/32", "10.182.20.166/32"), pendingNATFixture()[2]),
	} {
		t.Run(name, func(t *testing.T) {
			raw := pendingNATJSON(rows)
			if !desktopNATExemptionPending(raw, source, destination, "wg0") || desktopNATExempt(raw, source, destination) {
				t.Fatal("canonical absence must be pending, never positive exemption proof")
			}
		})
	}
	rows := append(pendingNATFixture()[:2], pendingNATExemption(source.String(), destination.String()), pendingNATFixture()[2])
	raw := pendingNATJSON(rows)
	if desktopNATExemptionPending(raw, source, destination, "wg0") || !desktopNATExempt(raw, source, destination) {
		t.Fatal("present exact exemption must use the unchanged positive proof")
	}
	// nft represents host operands as strings instead of prefix objects.
	row := pendingNATExemption("10.99.0.8/32", "10.182.20.166/32")
	expr := pendingNATRule(row)["expr"].([]any)
	expr[0] = guardMatch("==", guardPayload("ip", "saddr"), "10.99.0.8")
	expr[1] = guardMatch("==", guardPayload("ip", "daddr"), "10.182.20.166")
	rows = append(pendingNATFixture()[:2], row, pendingNATFixture()[2])
	if !desktopNATExemptionPending(pendingNATJSON(rows), source, destination, "wg0") {
		t.Fatal("canonical nft host normalization refused")
	}
}

func TestDesktopNATExemptionPendingRefusesAmbiguousRecipe(t *testing.T) {
	source, destination := netip.MustParsePrefix("10.99.0.7/32"), netip.MustParsePrefix("10.182.10.246/32")
	type mutate func([]any) []any
	cases := map[string]mutate{
		"missing table":       func(r []any) []any { return r[1:] },
		"duplicate table":     func(r []any) []any { return append(r, r[0]) },
		"missing chain":       func(r []any) []any { return []any{r[0], r[2]} },
		"duplicate chain":     func(r []any) []any { return append(r, r[1]) },
		"missing terminal":    func(r []any) []any { return r[:2] },
		"duplicate terminal":  func(r []any) []any { return append(r, r[2]) },
		"rule after terminal": func(r []any) []any { return append(r, pendingNATExemption("10.99.0.8/32", "10.182.20.166/32")) },
		"unknown row": func(r []any) []any {
			return append(r, map[string]any{"flowtable": map[string]any{"family": "ip", "table": "tunnex"}})
		},
		"malformed row":  func(r []any) []any { return append(r, map[string]any{"rule": nil}) },
		"multiple kinds": func(r []any) []any { r[0].(map[string]any)["chain"] = r[1]; return r },
	}
	for name, change := range map[string]struct {
		key   string
		value any
	}{
		"wrong priority": {"prio", 100}, "missing policy": {"policy", nil}, "drop policy": {"policy", "drop"},
		"wrong chain type": {"type", "filter"}, "wrong hook": {"hook", "prerouting"}, "foreign chain table": {"table", "foreign"},
		"foreign chain family": {"family", "ip6"}, "unknown chain field": {"flags", []any{"offload"}},
	} {
		change := change
		cases[name] = func(r []any) []any {
			r[1].(map[string]any)["chain"].(map[string]any)[change.key] = change.value
			return r
		}
	}
	for name, change := range map[string]struct {
		key   string
		value any
	}{
		"terminal comment": {"comment", "unexpected"}, "unknown rule field": {"userdata", "unknown"},
		"foreign rule table": {"table", "foreign"}, "foreign rule family": {"family", "ip6"}, "invalid handle": {"handle", -1},
	} {
		change := change
		cases[name] = func(r []any) []any { pendingNATRule(r[2])[change.key] = change.value; return r }
	}
	for name, expression := range map[string][]any{
		"broad masquerade":         {map[string]any{"masquerade": nil}},
		"zero pool":                {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("0.0.0.0/0"))), guardMatch("!=", guardMeta("oifname"), "wg0"), guardVerdict("masquerade")},
		"wrong pool":               {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.98.0.0/24"))), guardMatch("!=", guardMeta("oifname"), "wg0"), guardVerdict("masquerade")},
		"unmasked pool":            {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.1/24"))), guardMatch("!=", guardMeta("oifname"), "wg0"), guardVerdict("masquerade")},
		"wrong interface":          {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.0/24"))), guardMatch("!=", guardMeta("oifname"), "wg1"), guardVerdict("masquerade")},
		"wrong interface operator": {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.0/24"))), guardMatch("==", guardMeta("oifname"), "wg0"), guardVerdict("masquerade")},
		"anonymous interface set":  {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.0/24"))), guardMatch("!=", guardMeta("oifname"), map[string]any{"set": []any{"wg0", "tun0"}}), guardVerdict("masquerade")},
		"masquerade options":       {guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.0/24"))), guardMatch("!=", guardMeta("oifname"), "wg0"), map[string]any{"masquerade": map[string]any{"flags": "random"}}},
	} {
		expression := expression
		cases[name] = func(r []any) []any { pendingNATRule(r[2])["expr"] = expression; return r }
	}
	for name, change := range map[string]func(map[string]any){
		"unknown preceding comment": func(r map[string]any) { r["comment"] = "foreign" },
		"broad preceding source": func(r map[string]any) {
			r["expr"].([]any)[0] = guardMatch("==", guardPayload("ip", "saddr"), guardPrefixJSON(netip.MustParsePrefix("10.99.0.0/24")))
		},
		"preceding source outside pool": func(r map[string]any) {
			r["expr"].([]any)[0] = guardMatch("==", guardPayload("ip", "saddr"), "10.98.0.7")
		},
		"broad preceding destination": func(r map[string]any) {
			r["expr"].([]any)[1] = guardMatch("==", guardPayload("ip", "daddr"), guardPrefixJSON(netip.MustParsePrefix("0.0.0.0/0")))
		},
		"counter missing": func(r map[string]any) { e := r["expr"].([]any); r["expr"] = append(e[:2], e[3]) },
		"counter malformed": func(r map[string]any) {
			r["expr"].([]any)[2] = map[string]any{"counter": map[string]any{"packets": "0", "bytes": 0}}
		},
		"jump instead of return": func(r map[string]any) {
			r["expr"].([]any)[3] = map[string]any{"jump": map[string]any{"target": "other"}}
		},
		"return options": func(r map[string]any) { r["expr"].([]any)[3] = map[string]any{"return": map[string]any{}} },
		"unknown match field": func(r map[string]any) {
			r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["unknown"] = true
		},
	} {
		change := change
		cases[name] = func(r []any) []any {
			e := pendingNATExemption("10.99.0.8/32", "10.182.20.166/32")
			change(pendingNATRule(e))
			return append(r[:2], e, r[2])
		}
	}
	cases["duplicate preceding tuple"] = func(r []any) []any {
		e := pendingNATExemption("10.99.0.8/32", "10.182.20.166/32")
		return append(r[:2], e, e, r[2])
	}
	cases["overlapping prior tuples"] = func(r []any) []any {
		return append(r[:2], pendingNATExemption("10.99.0.8/32", "10.182.0.0/16"), pendingNATExemption("10.99.0.8/32", "10.182.20.166/32"), r[2])
	}
	cases["second postrouting hook"] = func(r []any) []any {
		return append(r, map[string]any{"chain": map[string]any{"family": "ip", "table": "tunnex", "name": "other", "type": "nat", "hook": "postrouting", "prio": 98, "policy": "accept"}})
	}
	cases["covering requested tuple"] = func(r []any) []any { return append(r[:2], pendingNATExemption(source.String(), "10.182.0.0/16"), r[2]) }
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if desktopNATExemptionPending(pendingNATJSON(mutate(pendingNATFixture())), source, destination, "wg0") {
				t.Fatal("ambiguous recipe accepted as retryable pending")
			}
		})
	}
	for _, raw := range []string{"", "not-json", `{"nftables":[],"nftables":[]}`, `{"nftables":null}`, strings.Replace(string(pendingNATJSON(pendingNATFixture())), `"prio":99`, `"prio":99,"prio":99`, 1)} {
		if desktopNATExemptionPending([]byte(raw), source, destination, "wg0") {
			t.Fatal("malformed/read-error snapshot accepted")
		}
	}
}

func TestDesktopNATExemptionPendingCapturedNativeShape(t *testing.T) {
	// Complete native nft 1.1.6 table captured 2026-10-21, SHA
	// 127af26982212a1d0d736caa73c554b5ce36bd04c3ab95854154d85af5613f9a.
	// This is parser evidence only; it grants no native forwarding authority.
	raw := []byte(`{"nftables":[{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}},{"table":{"family":"ip","name":"tunnex","handle":14}},{"chain":{"family":"ip","table":"tunnex","name":"postrouting","handle":1,"type":"nat","hook":"postrouting","prio":99,"policy":"accept"}},{"chain":{"family":"ip","table":"tunnex","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},{"rule":{"family":"ip","table":"tunnex","chain":"postrouting","handle":10480,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.99.0.0","len":24}}}},{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"wg0"}},{"masquerade":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10481,"expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10482,"comment":"tunnex_ct_invalid_drop","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"counter":{"packets":0,"bytes":0}},{"drop":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10483,"comment":"tunnex_native_forward_passthrough","expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"wg0"}},{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"wg0"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10484,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wg0"}},{"match":{"op":"in","left":{"payload":{"protocol":"tcp","field":"flags"}},"right":"syn"}},{"mangle":{"key":{"tcp option":{"name":"maxseg","field":"size"}},"value":{"rt":{"key":"mtu"}}}}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10485,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.181.10.0","len":24}}}},{"match":{"op":"==","left":{"ct":{"key":"ip daddr","dir":"original"}},"right":{"prefix":{"addr":"10.182.10.0","len":24}}}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"match":{"op":"==","left":{"ct":{"key":"proto-dst","dir":"original"}},"right":443}},{"counter":{"packets":0,"bytes":0}},{"log":{"prefix":"tnx:01a15cb7-fc4b-7083-8fd7-5e773fbbbd65 ","group":100}},{"accept":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10486,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.181.10.0","len":24}}}},{"match":{"op":"==","left":{"ct":{"key":"ip daddr","dir":"original"}},"right":"10.182.10.20"}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"match":{"op":"==","left":{"ct":{"key":"proto-dst","dir":"original"}},"right":80}},{"counter":{"packets":0,"bytes":0}},{"log":{"prefix":"tnx:01a15cb7-fc09-7461-89b4-c7ac94942a09 ","group":100}},{"accept":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10487,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.181.10.0","len":24}}}},{"match":{"op":"==","left":{"ct":{"key":"ip daddr","dir":"original"}},"right":{"prefix":{"addr":"10.182.20.0","len":24}}}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"match":{"op":"==","left":{"ct":{"key":"proto-dst","dir":"original"}},"right":443}},{"counter":{"packets":0,"bytes":0}},{"log":{"prefix":"tnx:01a15cb7-fc8f-7e05-a03a-643e32d52bd7 ","group":100}},{"accept":null}]}},{"rule":{"family":"ip","table":"tunnex","chain":"forward","handle":10488,"comment":"tunnex_default_drop","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},{"log":{"prefix":"tnx:deny ","group":100}},{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}]}`)
	source, destination := netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("10.182.10.246/32")
	if !desktopNATExemptionPending(raw, source, destination, "wg0") || desktopNATExempt(raw, source, destination) {
		t.Fatal("complete captured canonical absence must be pending, not positive proof")
	}
}
func TestDesktopNATExemptionPendingRejectsInvalidInputs(t *testing.T) {
	raw := pendingNATJSON(pendingNATFixture())
	source, destination := netip.MustParsePrefix("10.99.0.7/32"), netip.MustParsePrefix("10.182.10.246/32")
	for _, source := range []netip.Prefix{{}, netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("::1/128")} {
		if desktopNATExemptionPending(raw, source, destination, "wg0") {
			t.Fatal("invalid requested source classified pending")
		}
	}
	for _, destination := range []netip.Prefix{{}, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.182.10.1/24"), source} {
		if desktopNATExemptionPending(raw, source, destination, "wg0") {
			t.Fatal("invalid requested destination classified pending")
		}
	}
	for _, iface := range []string{"", "wg bad", "abcdefghijklmnop"} {
		if desktopNATExemptionPending(raw, source, destination, iface) {
			t.Fatal("invalid interface classified pending")
		}
	}
}
