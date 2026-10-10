package ipsec

import (
	"encoding/json"
	"testing"
)

func TestGuardCTHostPrefixExactNormalization(t *testing.T) {
	for _, key := range []string{"ip saddr", "ip daddr"} {
		for _, scenario := range []string{"exact", "reply", "ipv6", "wrongkey", "extra", "wrongprefix", "malformed"} {
			ct := map[string]any{"key": key, "dir": "original"}
			addr := "10.20.0.1"
			bits := json.Number("32")
			switch scenario {
			case "reply":
				ct["dir"] = "reply"
			case "ipv6":
				ct["key"] = "ip6 saddr"
			case "wrongkey":
				ct["key"] = "proto-dst"
			case "extra":
				ct["family"] = "ip"
			case "wrongprefix":
				bits = json.Number("24")
			case "malformed":
				addr = "not-an-ip"
			}
			m := map[string]any{"right": map[string]any{"prefix": map[string]any{"addr": addr, "len": bits}}}
			normalizeGuardHostPrefix(m, map[string]any{"ct": ct})
			_, scalar := m["right"].(string)
			if scalar != (scenario == "exact") {
				t.Fatal(key, scenario, m)
			}
		}
	}
}

func TestGuardCTDifferentHostStillRefuses(t *testing.T) {
	left := map[string]any{"ct": map[string]any{"key": "ip daddr", "dir": "original"}}
	a := map[string]any{"right": map[string]any{"prefix": map[string]any{"addr": "10.20.0.1", "len": json.Number("32")}}}
	b := map[string]any{"right": "10.20.0.2"}
	normalizeGuardHostPrefix(a, left)
	normalizeGuardHostPrefix(b, left)
	if a["right"] == b["right"] {
		t.Fatal("different host adopted")
	}
}
