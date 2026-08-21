package mcptoolpolicy

import "testing"

func TestInventoryRulesBindEndpointServerToolAndSchema(t *testing.T) {
	snapshot := []byte(`{"servers":[{"endpoint":"https://mcp.example/rpc","server_name":"billing","tools":[{"name":"read","input_schema_hash":"sha256:a"}]}]}`)
	available := inventoryRules(snapshot)
	if !available[ruleKey(Rule{Endpoint: "https://mcp.example/rpc", ServerName: "billing", ToolName: "read", InputSchemaHash: "sha256:a"})] {
		t.Fatal("exact observed tool was not available")
	}
	if available[ruleKey(Rule{Endpoint: "https://mcp.example/rpc", ServerName: "billing", ToolName: "read", InputSchemaHash: "sha256:b"})] {
		t.Fatal("changed schema hash was accepted")
	}
}

func TestCanonicalRulesRejectMissingStableIdentity(t *testing.T) {
	if got := canonicalRules([]Rule{{Endpoint: "https://mcp.example/rpc", ToolName: "read", InputSchemaHash: "hash"}}); got != nil {
		t.Fatalf("rules = %#v, want rejection", got)
	}
}
