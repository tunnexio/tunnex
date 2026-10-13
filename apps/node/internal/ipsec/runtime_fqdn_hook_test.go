package ipsec

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestRuntimeHookCensusProductionFQDNMark(t *testing.T) {
	raw, err := os.ReadFile("testdata/fqdn-native-v3-observed.json")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		NFT []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &root) != nil {
		t.Fatal("fixture")
	}
	var mark json.RawMessage
	for _, r := range root.NFT {
		var rule struct {
			Expr []map[string]json.RawMessage `json:"expr"`
		}
		json.Unmarshal(r["rule"], &rule)
		for _, e := range rule.Expr {
			if b := e["mangle"]; len(b) > 0 {
				var m struct {
					Key map[string]any `json:"key"`
				}
				json.Unmarshal(b, &m)
				if _, ok := m.Key["ct"]; ok {
					mark = b
				}
			}
		}
	}
	if len(mark) == 0 {
		t.Fatal("missing actual mark")
	}
	for _, family := range []string{"ip", "ip6"} {
		rows := map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"family": family, "name": "tunnex"}}, map[string]any{"chain": map[string]any{"family": family, "table": "tunnex", "name": "forward", "hook": "forward", "type": "filter", "prio": 0, "policy": "drop"}}, map[string]any{"rule": map[string]any{"family": family, "table": "tunnex", "chain": "forward", "expr": []any{map[string]any{"mangle": mark}, map[string]any{"accept": nil}}}}}}
		b, _ := json.Marshal(rows)
		if !runtimeHookCensus(b, []netip.Prefix{netip.MustParsePrefix("10.81.0.0/24")}) {
			t.Fatalf("production %s FQDN mark must remain hook qualified", family)
		}
		for _, bad := range []string{
			strings.ReplaceAll(string(b), `"chain":"forward"`, `"chain":"postrouting"`),
			strings.ReplaceAll(string(b), `"family":"`+family+`"`, `"family":"inet"`),
			strings.ReplaceAll(string(b), `"key":{"ct":{"key":"mark"}}`, `"key":{"meta":{"key":"mark"}}`),
			strings.ReplaceAll(string(b), `4060086271`, `4060086270`),
			strings.ReplaceAll(string(b), `16777216`, `33554432`),
			strings.ReplaceAll(string(b), `16777216`, `16777216.0000000001`),
			strings.ReplaceAll(string(b), `4060086271`, `4060086271.0000000001`),
			strings.ReplaceAll(string(b), `"key":"mark"`, `"key":"mark","key":"mark"`),
		} {
			if runtimeHookCensus([]byte(bad), []netip.Prefix{netip.MustParsePrefix("10.81.0.0/24")}) {
				t.Fatal("wrong scope/mark admitted")
			}
		}
	}
}
func TestRuntimeFQDNConntrackMarkClosed(t *testing.T) {
	good := `{"key":{"ct":{"key":"mark"}},"value":{"|":[{"&":[{"ct":{"key":"mark"}},4060086271]},16777216]}}`
	if !runtimeFQDNConntrackMark([]byte(good)) {
		t.Fatal("canonical refused")
	}
	for _, bad := range []string{
		strings.ReplaceAll(good, "4060086271", "4060086271.000000001"),
		strings.ReplaceAll(good, "16777216", "16777216.0000000001"),
		strings.ReplaceAll(good, `"key":"mark"`, `"key":"mark","key":"mark"`),
		`{"key":{"meta":{"key":"mark"}},"value":{"|":[{"&":[{"ct":{"key":"mark"}},4060086271]},16777216]}}`,
		`{"key":{"ct":{"key":"mark"}},"value":{"|":[{"&":[{"ct":{"key":"mark"}},4060086270]},16777216]}}`,
		`{"key":{"ct":{"key":"mark"}},"value":{"|":[{"&":[{"ct":{"key":"mark"}},4060086271]},33554432]}}`,
		`{"key":{"ct":{"key":"mark"}},"value":{"|":[{"&":[{"ct":{"key":"mark"}},4060086271]},16777216]},"extra":true}`,
	} {
		if runtimeFQDNConntrackMark([]byte(bad)) {
			t.Fatal("unknown mark admitted")
		}
	}
}
