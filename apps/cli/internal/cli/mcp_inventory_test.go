package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestObserveMCPOAuthDiscoveryUsesResourceMetadataChallenge(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/metadata"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"resource": server.URL + "/mcp", "authorization_servers": []string{"https://issuer.example"}, "scopes_supported": []string{"tools:read"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	discovery := ObserveMCPOAuthDiscovery(t.Context(), []string{server.URL + "/mcp"})
	servers := discovery["servers"].([]interface{})
	got := servers[0].(map[string]interface{})
	if got["status"] != "protected" || got["protected_resource"] != server.URL+"/mcp" {
		t.Fatalf("discovery=%#v", got)
	}
}

func TestObserveMCPOAuthDiscoveryUsesWellKnownFallback(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/mcp":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"resource": server.URL + "/mcp", "authorization_servers": []string{"https://issuer.example"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	discovery := ObserveMCPOAuthDiscovery(t.Context(), []string{server.URL + "/mcp"})
	got := discovery["servers"].([]interface{})[0].(map[string]interface{})
	if got["status"] != "protected" {
		t.Fatalf("discovery=%#v", got)
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
