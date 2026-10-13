package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestFQDNAdditiveWireCausal(t *testing.T) {
	m := runtimeMaterialFixture()
	raw, _ := json.Marshal(m)
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["policy"].(map[string]any)["fqdn_policy_version"] = 1
	doc["policy"].(map[string]any)["fqdn_grants"] = []any{map[string]any{"source": "10.10.0.8/32", "destination": "10.20.0.9/32", "protocol": "tcp", "port_low": 8081, "port_high": 8081, "rule_id": uuid.NewString(), "fqdn_managed": true, "resource_id": uuid.NewString(), "name": "private.example.test", "generation": strings.Repeat("a", 64), "resolver_config_id": uuid.NewString(), "resolver_config_version": int64(5), "selected_site_id": m.Manifest.SiteID.String(), "selected_gateway_id": m.Manifest.NodeID.String(), "resolver_profile_id": uuid.NewString(), "resolver_match_suffix": "example.test", "connection_id": m.Manifest.ConnectionID.String(), "configuration_revision": m.Manifest.ConfigurationRevision}}
	raw, _ = json.Marshal(doc)
	var received RuntimeMaterial
	if json.Unmarshal(raw, &received) != nil {
		t.Fatal("wire decode")
	}
	_, grants, err := runtimeMaterialEntry(received, received.Manifest.OrgID, received.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 1 || !grants[0].FQDNManaged {
		t.Fatalf("additive FQDN wire not supported: grants=%d error=%v", len(grants), err)
	}
	if len(received.Policy.Grants) != 0 {
		t.Fatal("hidden ordinary IP grant")
	}
}
