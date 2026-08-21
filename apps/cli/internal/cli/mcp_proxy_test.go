package cli

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestMCPToolProxyRejectsArgumentsBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	max := 4
	proxy, err := MCPToolProxy(upstream.URL, func(context.Context) (MCPProxyPolicy, error) {
		return MCPProxyPolicy{Version: 1, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ToolName: "safe", Arguments: &MCPArgumentConstraints{
			Required: []string{"mode"}, Properties: map[string]MCPArgumentConstraint{"mode": {Type: "string", Enum: []json.RawMessage{json.RawMessage(`"read"`)}, MaxLength: &max}},
		}}}}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	response, err := http.Post(server.URL, "application/json", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{"mode":"write"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls = %d", calls.Load())
	}
}

func TestMCPToolProxyRateLimitPreventsSecondUpstreamCall(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	proxy, err := MCPToolProxy(upstream.URL, func(context.Context) (MCPProxyPolicy, error) {
		return MCPProxyPolicy{Version: 7, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ToolName: "safe", RateLimitPerMinute: 1}}}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{}}}`
	for i, want := range []int{http.StatusNoContent, http.StatusTooManyRequests} {
		response, err := http.Post(server.URL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("call %d status = %d, want %d", i, response.StatusCode, want)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d", calls.Load())
	}
}

func TestMCPToolProxyConsumesStepUpBeforeUpstream(t *testing.T) {
	var calls, approvals atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	proxy, err := MCPToolProxy(upstream.URL, func(context.Context) (MCPProxyPolicy, error) {
		return MCPProxyPolicy{Version: 8, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ServerName: "example", ToolName: "safe", InputSchemaHash: "schema", StepUpRequired: true}}}, nil
	}, nil, func(_ context.Context, policy MCPProxyPolicy, rule MCPProxyRule, request MCPToolRequest) (bool, error) {
		approvals.Add(1)
		if policy.Version != 8 || rule.ServerName != "example" || len(MCPApprovalDigest(request)) != 64 {
			t.Fatal("step-up identity was not bound")
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	response, err := http.Post(server.URL, "application/json", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{"mode":"read"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || calls.Load() != 1 || approvals.Load() != 1 {
		t.Fatalf("status=%d calls=%d approvals=%d", response.StatusCode, calls.Load(), approvals.Load())
	}
}
