package cli

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeMCPInventoryAcceptsLegacyAndCurrentSnapshots(t *testing.T) {
	for _, version := range []string{"2024-11-05", "2025-11-25"} {
		got, err := NormalizeMCPInventory(MCPInventorySnapshot{Endpoint: "https://mcp.example/rpc", ServerName: "inventory", ProtocolVersion: version, Transport: "streamable_http", ObservedAt: time.Now(), Tools: []MCPToolInventory{{Name: "list", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
		if err != nil || got.Tools[0].InputSchemaHash == "" {
			t.Fatalf("%s: %#v, %v", version, got, err)
		}
	}
}

func TestNormalizeMCPInventoryRejectsCredentialBearingEndpoint(t *testing.T) {
	_, err := NormalizeMCPInventory(MCPInventorySnapshot{Endpoint: "https://token@example.test/rpc", ServerName: "inventory", ProtocolVersion: "2025-11-25", Transport: "streamable_http", ObservedAt: time.Now()})
	if err == nil {
		t.Fatal("credential-bearing endpoint accepted")
	}
}

func TestNormalizeObservedSnapshotAcceptsMCPWireFieldNames(t *testing.T) {
	got, err := normalizeObservedSnapshot(map[string]interface{}{
		"endpoint": "https://mcp.example/rpc", "server_name": "inventory", "protocol_version": "2025-11-25", "latency_millis": int64(1),
		"tools":     []interface{}{map[string]interface{}{"name": "list", "inputSchema": map[string]interface{}{"type": "object"}, "outputSchema": map[string]interface{}{"type": "object"}}},
		"resources": []interface{}{map[string]interface{}{"uri": "mcp://inventory/status", "name": "status", "mimeType": "application/json"}},
		"prompts":   []interface{}{map[string]interface{}{"name": "summarize"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Tools[0].InputSchemaHash == "" || got.Tools[0].OutputSchemaHash == "" || got.Resources[0].MIMEType != "application/json" {
		t.Fatalf("wire fields were not retained: %#v", got)
	}
}
