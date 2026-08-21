package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestMCPToolProxyBodyIsAuthoritativeAndDeniedRequestNeverReachesUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer leased-token" {
			t.Fatalf("authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxy, err := MCPToolProxy(upstream.URL, func(context.Context) (MCPProxyPolicy, error) {
		return MCPProxyPolicy{Version: 1, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ToolName: "safe"}}}, nil
	}, func(context.Context) (string, error) { return "leased-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous","arguments":{}}}`))
	request.Header.Set("MCP-Protocol-Version", MCPProtocol20260728)
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "safe")
	request.Header.Set("Authorization", "Bearer forged-client-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls = %d", calls.Load())
	}
}

func TestMCPToolProxyForwardsOnlyAnAllowedTool(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	proxy, err := MCPToolProxy(upstream.URL, func(context.Context) (MCPProxyPolicy, error) {
		return MCPProxyPolicy{Version: 4, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ToolName: "safe"}}}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	response, err := http.Post(server.URL, "application/json", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d", calls.Load())
	}
}
