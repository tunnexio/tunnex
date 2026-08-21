package cli

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeMCPInventoryAcceptsLegacyAndCurrentSnapshots(t *testing.T) {
	for _, version := range []string{"2024-11-05", "2025-11-25"} {
		got, err := NormalizeMCPInventory(MCPInventorySnapshot{Endpoint: "https://mcp.example/rpc", ServerName: "inventory", ProtocolVersion: version, Transport: "streamable_http", ObservedAt: time.Now(), Tools: []MCPToolInventory{{Name: "list", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
		if err != nil || got.Tools[0].InputSchemaHash == "" { t.Fatalf("%s: %#v, %v", version, got, err) }
	}
}

func TestNormalizeMCPInventoryRejectsCredentialBearingEndpoint(t *testing.T) {
	_, err := NormalizeMCPInventory(MCPInventorySnapshot{Endpoint: "https://token@example.test/rpc", ServerName: "inventory", ProtocolVersion: "2025-11-25", Transport: "streamable_http", ObservedAt: time.Now()})
	if err == nil { t.Fatal("credential-bearing endpoint accepted") }
}
