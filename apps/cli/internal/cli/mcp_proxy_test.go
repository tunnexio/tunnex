package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

func TestMCPToolProxyPermitsOnlyFixedControlMethodsWithoutAToolRule(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxy, err := MCPToolProxy(upstream.URL, func(context.Context) (MCPProxyPolicy, error) {
		return MCPProxyPolicy{}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	for _, method := range []string{"initialize", "notifications/initialized", "tools/list", "ping"} {
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`
		response, err := http.Post(server.URL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s status = %d", method, response.StatusCode)
		}
	}
	response, err := http.Post(server.URL, "application/json", bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unnamed non-control status = %d", response.StatusCode)
	}
	if calls.Load() != 4 {
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

// ── AI-SEC-2: with a gateway URL the loopback proxy is a pure forwarder ───────────

const mcpTestListen = "127.0.0.1:17100"

// gatewayModeProxy builds the handler the runtime serves, with legacy sources that record any use.
func gatewayModeProxy(t *testing.T, gatewayURL func() string) (http.Handler, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var policyCalls, leaseCalls atomic.Int64
	handler, err := managedMCPProxyHandler(mcpTestListen,
		func(context.Context) string { return gatewayURL() },
		func(context.Context) (string, error) { return "http://192.0.2.1:9/legacy-must-not-be-used", nil },
		func(context.Context) (MCPProxyPolicy, error) { policyCalls.Add(1); return MCPProxyPolicy{}, nil },
		func(context.Context) (string, error) { leaseCalls.Add(1); return "leased-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	return handler, &policyCalls, &leaseCalls
}

func localMCPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	request.Host = mcpTestListen
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestMCPGatewayForwarderForwardsUnchangedWithoutLocalPolicyOrLease(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"never_allowed_locally","arguments":{"q":"x"}}}`
	var seen atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		got, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/mcp" || string(got) != body {
			t.Errorf("gateway got %s %s %q", r.Method, r.URL.Path, got)
		}
		for name, want := range map[string]string{
			"Mcp-Session-Id": "session-1", "MCP-Protocol-Version": MCPProtocol20251125,
			"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
		} {
			if r.Header.Get(name) != want {
				t.Errorf("header %s = %q, want %q", name, r.Header.Get(name), want)
			}
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Tunnex-Vpn-Ip", "X-Tunnex-Vpn-Key", "X-Forwarded-For"} {
			if r.Header.Get(name) != "" {
				t.Errorf("caller header %s reached the gateway: %q", name, r.Header.Get(name))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "session-1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32103,"message":"MCP tool requires step-up approval","data":{"request_id":"r1"}},"id":7}`))
	}))
	defer gateway.Close()
	handler, policyCalls, leaseCalls := gatewayModeProxy(t, func() string { return gateway.URL + "/mcp" })

	request := localMCPRequest(body)
	request.Header.Set("Mcp-Session-Id", "session-1")
	request.Header.Set("MCP-Protocol-Version", MCPProtocol20251125)
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Authorization", "Bearer caller-token")
	request.Header.Set("Proxy-Authorization", "Basic abc")
	request.Header.Set("Cookie", "a=b")
	request.Header.Set("X-Tunnex-VPN-IP", "10.99.0.99")
	request.Header.Set("X-Tunnex-VPN-Key", "forged")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if seen.Load() != 1 {
		t.Fatalf("gateway calls = %d, want 1", seen.Load())
	}
	// The gateway's answer comes back as it was sent: status, headers and body.
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Mcp-Session-Id") != "session-1" ||
		recorder.Body.String() != `{"jsonrpc":"2.0","error":{"code":-32103,"message":"MCP tool requires step-up approval","data":{"request_id":"r1"}},"id":7}` {
		t.Fatalf("response changed on the way back: %d %v %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if policyCalls.Load() != 0 || leaseCalls.Load() != 0 {
		t.Fatalf("forwarder used local policy (%d) or leased a token (%d)", policyCalls.Load(), leaseCalls.Load())
	}
}

// The loopback forwarder serves MCP, never a web page: whatever content type the gateway (or anything
// answering at its address) sends, the local client receives JSON or an event stream, with sniffing off.
func TestMCPGatewayForwarderAnswersOnlyJSONOrEventStream(t *testing.T) {
	for _, tc := range []struct{ upstream, want string }{
		{"text/html; charset=utf-8", "application/json"},
		{"", "application/json"},
		{"application/json; charset=utf-8", "application/json"},
		{"text/event-stream", "text/event-stream"},
		{"Text/Event-Stream; charset=utf-8", "text/event-stream"},
	} {
		gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.upstream != "" {
				w.Header().Set("Content-Type", tc.upstream)
			} else {
				w.Header()["Content-Type"] = nil
			}
			w.Header().Set("Mcp-Session-Id", "session-2")
			_, _ = w.Write([]byte(`<script>alert(1)</script>`))
		}))
		handler, _, _ := gatewayModeProxy(t, func() string { return gateway.URL + "/mcp" })
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, localMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		gateway.Close()
		if got := recorder.Header().Values("Content-Type"); len(got) != 1 || got[0] != tc.want {
			t.Errorf("upstream %q: Content-Type = %q, want exactly %q", tc.upstream, got, tc.want)
		}
		if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("upstream %q: nosniff missing", tc.upstream)
		}
		if recorder.Header().Get("Mcp-Session-Id") != "session-2" {
			t.Errorf("upstream %q: MCP session header was dropped", tc.upstream)
		}
	}
}

func TestMCPGatewayForwarderKeepsLoopbackGuardAndBodyLimit(t *testing.T) {
	var seen atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { seen.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer gateway.Close()
	handler, _, _ := gatewayModeProxy(t, func() string { return gateway.URL + "/mcp" })
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	cases := []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"local JSON", func(*http.Request) {}, http.StatusNoContent},
		{"rebinding host", func(r *http.Request) { r.Host = "attacker.example:17100" }, http.StatusForbidden},
		{"browser origin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, http.StatusForbidden},
		{"form content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusForbidden},
		{"GET", func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		{"over 1 MiB", func(r *http.Request) {
			r.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), maxMCPRequestBody+1)))
		}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := seen.Load()
			request := localMCPRequest(body)
			tc.edit(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
			if forwarded := seen.Load() == before+1; forwarded != (tc.want == http.StatusNoContent) {
				t.Fatalf("forwarded = %v for a request that must answer %d", forwarded, tc.want)
			}
		})
	}
}

func TestMCPGatewayForwarderFailsWithUpstreamUnavailable(t *testing.T) {
	const want = `{"jsonrpc":"2.0","error":{"code":-32020,"message":"MCP upstream is unavailable"},"id":null}`
	if mcpGatewayDialTimeout != 5*time.Second {
		t.Fatalf("the gateway must be reached within 5 s, dial timeout is %s", mcpGatewayDialTimeout)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	refusedURL := closed.URL + "/mcp"
	closed.Close()

	release := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer silent.Close()
	defer close(release)

	// An address that accepts no connection: the dial itself must give up at the dial timeout.
	blackhole := newMCPGatewayForwarder(func(context.Context) string { return "http://192.0.2.1:8084/mcp" })
	blackhole.dialTimeout = 150 * time.Millisecond
	blackhole.dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	slow := newMCPGatewayForwarder(func(context.Context) string { return silent.URL + "/mcp" })
	slow.headerTimeout = 150 * time.Millisecond

	cases := map[string]http.Handler{
		"connection refused":       newMCPGatewayForwarder(func(context.Context) string { return refusedURL }),
		"gateway never accepts":    blackhole,
		"gateway never answers":    slow,
		"gateway URL is not a URL": newMCPGatewayForwarder(func(context.Context) string { return "://nope" }),
		"gateway URL is not http":  newMCPGatewayForwarder(func(context.Context) string { return "file:///etc/passwd" }),
		"gateway URL has userinfo": newMCPGatewayForwarder(func(context.Context) string { return "http://u:p@10.99.0.1:8084/mcp" }),
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, localMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			if recorder.Code != http.StatusBadGateway || recorder.Body.String() != want {
				t.Fatalf("got %d %s", recorder.Code, recorder.Body.String())
			}
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("failure took %s", elapsed)
			}
		})
	}
}

func TestMCPProxyUsesLegacyLocalPathWithoutGatewayURL(t *testing.T) {
	var upstreamCalls, policyCalls, leaseCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer leased-token" {
			t.Errorf("legacy path must attach the leased token, got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	gatewayURL := ""
	handler, err := managedMCPProxyHandler(mcpTestListen,
		func(context.Context) string { return gatewayURL },
		func(context.Context) (string, error) { return upstream.URL, nil },
		func(context.Context) (MCPProxyPolicy, error) {
			policyCalls.Add(1)
			return MCPProxyPolicy{Version: 1, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ToolName: "safe"}}}, nil
		},
		func(context.Context) (string, error) { leaseCalls.Add(1); return "leased-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	call := func(tool string) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, localMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":{}}}`))
		return recorder.Code
	}
	if got := call("safe"); got != http.StatusNoContent || upstreamCalls.Load() != 1 || policyCalls.Load() != 1 || leaseCalls.Load() != 1 {
		t.Fatalf("legacy allow: status %d upstream %d policy %d lease %d", got, upstreamCalls.Load(), policyCalls.Load(), leaseCalls.Load())
	}
	if got := call("dangerous"); got != http.StatusForbidden || upstreamCalls.Load() != 1 {
		t.Fatalf("legacy path must still deny locally: status %d upstream %d", got, upstreamCalls.Load())
	}

	// The gateway URL arrives with a later poll: the same listener switches to forwarding, and back.
	var gatewayCalls atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { gatewayCalls.Add(1); w.WriteHeader(http.StatusAccepted) }))
	defer gateway.Close()
	gatewayURL = gateway.URL + "/mcp"
	if got := call("dangerous"); got != http.StatusAccepted || gatewayCalls.Load() != 1 || upstreamCalls.Load() != 1 || policyCalls.Load() != 2 || leaseCalls.Load() != 1 {
		t.Fatalf("gateway mode: status %d gateway %d upstream %d policy %d lease %d", got, gatewayCalls.Load(), upstreamCalls.Load(), policyCalls.Load(), leaseCalls.Load())
	}
	gatewayURL = ""
	if got := call("safe"); got != http.StatusNoContent || upstreamCalls.Load() != 2 {
		t.Fatalf("back on the legacy path: status %d upstream %d", got, upstreamCalls.Load())
	}
}
