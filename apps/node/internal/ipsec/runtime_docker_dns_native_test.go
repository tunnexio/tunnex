package ipsec

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDockerDNSActualOpaqueProtocolMatch(t *testing.T) {
	raw, err := os.ReadFile("testdata/docker-dns-native/nft.json")
	if err != nil {
		t.Fatal(err)
	}
	listing, err := os.ReadFile("testdata/docker-dns-native/iptables-save.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeDockerDNSCensus(raw, listing, nil) {
		t.Fatal("actual independently attested Docker DNS topology refused")
	}
	for _, mutation := range []string{"protocol_mismatch", "extra_opaque", "unknown_match", "wrong_target", "extra_match_field"} {
		t.Run(mutation, func(t *testing.T) {
			var doc map[string]any
			if json.Unmarshal(raw, &doc) != nil {
				t.Fatal("fixture")
			}
			for _, row := range doc["nftables"].([]any) {
				rule, ok := row.(map[string]any)["rule"].(map[string]any)
				if !ok || rule["chain"] != "DOCKER_OUTPUT" {
					continue
				}
				expr := rule["expr"].([]any)
				switch mutation {
				case "protocol_mismatch":
					expr[0].(map[string]any)["match"].(map[string]any)["right"] = "udp"
				case "extra_opaque":
					expr = append(expr, map[string]any{"xt": map[string]any{"type": "match", "name": "tcp"}})
				case "unknown_match":
					expr[2].(map[string]any)["xt"].(map[string]any)["name"] = "conntrack"
				case "wrong_target":
					expr[4].(map[string]any)["xt"].(map[string]any)["name"] = "SNAT"
				case "extra_match_field":
					expr[2].(map[string]any)["xt"].(map[string]any)["revision"] = 1
				}
				rule["expr"] = expr
				break
			}
			changed, _ := json.Marshal(doc)
			if runtimeDockerDNSCensus(changed, listing, nil) {
				t.Fatal("unsupported opaque semantics accepted")
			}
		})
	}
}
