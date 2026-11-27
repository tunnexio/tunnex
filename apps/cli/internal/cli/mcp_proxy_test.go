package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// ── AI-UX-1: several MCP servers behind one loopback address ───────────────────────

func localMCPRequestAt(path, body string) *http.Request {
	request := localMCPRequest(body)
	request.URL.Path = path
	return request
}

// /<server name> goes to the gateway's /mcp/<server name>. The bare address, and the /mcp path clients
// were given before servers had names, go to the gateway's /mcp, which is the agent's first server.
func TestMCPGatewayForwarderRoutesByServerName(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"refund","arguments":{"order":"o1"}}}`
	var mu sync.Mutex
	var seen []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		if string(got) != body || r.Header.Get("Mcp-Session-Id") != "session-1" || r.Header.Get("Authorization") != "" {
			t.Errorf("gateway got body %q headers %v", got, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{"path":"`+r.URL.Path+`"}}`)
	}))
	defer gateway.Close()
	handler, policyCalls, leaseCalls := gatewayModeProxyWithServers(t, func() string { return gateway.URL + "/mcp" },
		[]MCPProxyServer{{Name: "orders-db", Default: true}, {Name: "billing"}})
	for _, tc := range []struct{ local, gateway string }{
		{"/", "/mcp"},
		{"", "/mcp"},
		{"/mcp", "/mcp"},
		{"/orders-db", "/mcp/orders-db"},
		{"/billing", "/mcp/billing"},
	} {
		request := localMCPRequestAt(tc.local, body)
		request.URL.RawQuery = "server=billing"
		request.Header.Set("Mcp-Session-Id", "session-1")
		request.Header.Set("Authorization", "Bearer caller-token")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Body.String() != `{"jsonrpc":"2.0","id":7,"result":{"path":"`+tc.gateway+`"}}` {
			t.Fatalf("%q: %d %s", tc.local, recorder.Code, recorder.Body.String())
		}
		mu.Lock()
		last := seen[len(seen)-1]
		mu.Unlock()
		// The caller's query never travels: the path alone names the server.
		if last != "POST "+tc.gateway {
			t.Fatalf("%q reached the gateway as %q, want POST %s", tc.local, last, tc.gateway)
		}
	}
	if policyCalls.Load() != 0 || leaseCalls.Load() != 0 {
		t.Fatalf("forwarder used local policy (%d) or leased a token (%d)", policyCalls.Load(), leaseCalls.Load())
	}
}

// A name that is not one of the agent's servers answers 404 with a plain JSON-RPC error. Nothing is
// forwarded, to the gateway or anywhere else.
func TestMCPGatewayForwarderRefusesAnUnknownServerName(t *testing.T) {
	var forwarded atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer gateway.Close()
	handler, policyCalls, leaseCalls := gatewayModeProxyWithServers(t, func() string { return gateway.URL + "/mcp" },
		[]MCPProxyServer{{Name: "orders-db", Default: true}, {Name: "billing"}, {Name: "Not_A_Name"}, {Name: "a/b"}, {Name: "mcp"}, {Name: ""}})
	const want = `{"jsonrpc":"2.0","error":{"code":-32600,"message":"No MCP server with this name is connected to this agent"},"id":null}`
	for _, path := range []string{"/unknown", "/Orders-DB", "/orders-db/", "/orders-db/admin", "/mcp/orders-db", "/mcp/", "//billing", "/billing%2Fadmin",
		"/Not_A_Name", "/a/b", "/..", "/../mcp", "/.", "/%6dcp"} {
		request := localMCPRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		// What the server hands the handler: the decoded path, and the raw one when it was escaped.
		request.URL.Path, request.URL.RawPath = path, ""
		if unescaped, err := url.PathUnescape(path); err != nil {
			t.Fatal(err)
		} else if unescaped != path {
			request.URL.Path, request.URL.RawPath = unescaped, path
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound || recorder.Body.String() != want || recorder.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body.String())
		}
		var reply map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &reply); err != nil {
			t.Fatalf("%s: the refusal is not JSON: %v", path, err)
		}
	}
	if forwarded.Load() != 0 || policyCalls.Load() != 0 || leaseCalls.Load() != 0 {
		t.Fatalf("an unknown server was acted on: gateway %d policy %d lease %d", forwarded.Load(), policyCalls.Load(), leaseCalls.Load())
	}
}

// A control plane that predates several servers sends no server list. The proxy then forwards every path
// to the gateway URL as it is, exactly as before.
func TestMCPGatewayForwarderWithoutAServerListForwardsAsBefore(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gateway.Close()
	for name, handler := range map[string]http.Handler{
		"no source": func() http.Handler {
			h, _, _ := gatewayModeProxy(t, func() string { return gateway.URL + "/mcp" })
			return h
		}(),
		"an empty list": func() http.Handler {
			h, _, _ := gatewayModeProxyWithServers(t, func() string { return gateway.URL + "/mcp" }, nil)
			return h
		}(),
	} {
		for _, path := range []string{"/", "/mcp", "/anything", "/v1/mcp"} {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, localMCPRequestAt(path, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("%s %s: %d %s", name, path, recorder.Code, recorder.Body.String())
			}
		}
	}
	if strings.Join(seen, " ") != strings.TrimSpace(strings.Repeat("/mcp ", 8)) {
		t.Fatalf("gateway paths: %v", seen)
	}
}

// The legacy local path (no gateway URL) stays single-server: it ignores the path and the server list.
func TestMCPLegacyLocalPathIgnoresServerNames(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	handler, err := managedMCPServersProxyHandler(mcpTestListen,
		func(context.Context) string { return "" },
		func(context.Context) []MCPProxyServer {
			return []MCPProxyServer{{Name: "orders-db", Default: true}, {Name: "billing"}}
		},
		func(context.Context) (string, error) { return upstream.URL, nil },
		func(context.Context) (MCPProxyPolicy, error) {
			return MCPProxyPolicy{Version: 1, Rules: []MCPProxyRule{{Endpoint: upstream.URL, ToolName: "safe"}}}, nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/billing", "/unknown"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, localMCPRequestAt(path, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{}}}`))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, localMCPRequestAt("/billing", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous","arguments":{}}}`))
	if recorder.Code != http.StatusForbidden || upstreamCalls.Load() != 3 {
		t.Fatalf("legacy deny: %d, upstream calls %d", recorder.Code, upstreamCalls.Load())
	}
}

// A held "Ask first" call keeps the gateway silent for up to 45 seconds, so the proxy waits 60 for the
// gateway's answer. Reaching the gateway is still bounded at five.
func TestMCPGatewayForwarderWaitsLongEnoughForAHeldCall(t *testing.T) {
	if mcpGatewayHeaderTimeout != 60*time.Second || mcpGatewayDialTimeout != 5*time.Second {
		t.Fatalf("header timeout %s, dial timeout %s", mcpGatewayHeaderTimeout, mcpGatewayDialTimeout)
	}
	if got := newMCPGatewayForwarder(func(context.Context) string { return "" }).roundTripper().ResponseHeaderTimeout; got != 60*time.Second {
		t.Fatalf("the transport gives the gateway %s", got)
	}
}
