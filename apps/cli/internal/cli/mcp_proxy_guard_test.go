package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The loopback listener is reachable by every local process and by any web
// page open on the agent host. Only a same-host, non-browser JSON request may
// reach the tool gate.
func TestMCPLoopbackGuardRefusesBrowserAndRebindingRequests(t *testing.T) {
	reached := 0
	guard := mcpLoopbackGuard("127.0.0.1:17100", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	cases := []struct {
		name        string
		host        string
		origin      string
		contentType string
		want        int
	}{
		{"loopback address", "127.0.0.1:17100", "", "application/json", http.StatusNoContent},
		{"localhost name", "localhost:17100", "", "application/json; charset=utf-8", http.StatusNoContent},
		{"rebinding host", "attacker.example:17100", "", "application/json", http.StatusForbidden},
		{"wrong port", "127.0.0.1:8080", "", "application/json", http.StatusForbidden},
		{"browser origin", "127.0.0.1:17100", "https://attacker.example", "application/json", http.StatusForbidden},
		{"null origin", "127.0.0.1:17100", "null", "application/json", http.StatusForbidden},
		{"simple cross-site form post", "127.0.0.1:17100", "", "text/plain", http.StatusForbidden},
		{"missing content type", "127.0.0.1:17100", "", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := reached
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
			request.Host = tc.host
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			recorder := httptest.NewRecorder()
			guard.ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
			if allowed := tc.want == http.StatusNoContent; allowed != (reached == before+1) {
				t.Fatalf("handler reached = %v, want %v", reached == before+1, allowed)
			}
		})
	}
}

// AI-UX-1: the proxy now serves a path per MCP server. The guard and the 1 MiB limit stand in front of
// every one of them, known or not, and a refused request reaches neither the gateway nor the local path.
func TestMCPLoopbackGuardIsEnforcedOnEveryServerPath(t *testing.T) {
	var forwarded atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gateway.Close()
	handler, policyCalls, leaseCalls := gatewayModeProxyWithServers(t, func() string { return gateway.URL + "/mcp" },
		[]MCPProxyServer{{Name: "orders-db", Default: true}, {Name: "billing"}})
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	refusals := []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"rebinding host", func(r *http.Request) { r.Host = "attacker.example:17100" }, http.StatusForbidden},
		{"wrong port", func(r *http.Request) { r.Host = "127.0.0.1:8080" }, http.StatusForbidden},
		{"browser origin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, http.StatusForbidden},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden},
		{"simple cross-site form post", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusForbidden},
		{"missing content type", func(r *http.Request) { r.Header.Del("Content-Type") }, http.StatusForbidden},
		{"GET", func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
	}
	for _, path := range []string{"/", "/mcp", "/orders-db", "/billing", "/unknown", "/billing/admin"} {
		for _, tc := range refusals {
			t.Run(path+" "+tc.name, func(t *testing.T) {
				before := forwarded.Load()
				request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
				request.Host = mcpTestListen
				request.Header.Set("Content-Type", "application/json")
				tc.edit(request)
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				if recorder.Code != tc.want {
					t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
				}
				if forwarded.Load() != before {
					t.Fatal("a refused request was forwarded")
				}
			})
		}
	}
	// The body limit on a named server path.
	for _, path := range []string{"/", "/billing"} {
		before := forwarded.Load()
		request := httptest.NewRequest(http.MethodPost, path, io.NopCloser(strings.NewReader(strings.Repeat("a", maxMCPRequestBody+1))))
		request.Host = mcpTestListen
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || forwarded.Load() != before {
			t.Fatalf("%s: over 1 MiB answered %d, forwarded %v", path, recorder.Code, forwarded.Load() != before)
		}
	}
	if policyCalls.Load() != 0 || leaseCalls.Load() != 0 {
		t.Fatalf("local policy (%d) or lease (%d) used in gateway mode", policyCalls.Load(), leaseCalls.Load())
	}
}

// gatewayModeProxyWithServers is gatewayModeProxy with the server list of the runtime configuration.
func gatewayModeProxyWithServers(t *testing.T, gatewayURL func() string, servers []MCPProxyServer) (http.Handler, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var policyCalls, leaseCalls atomic.Int64
	handler, err := managedMCPServersProxyHandler(mcpTestListen,
		func(context.Context) string { return gatewayURL() },
		func(context.Context) []MCPProxyServer { return servers },
		func(context.Context) (string, error) { return "http://192.0.2.1:9/legacy-must-not-be-used", nil },
		func(context.Context) (MCPProxyPolicy, error) { policyCalls.Add(1); return MCPProxyPolicy{}, nil },
		func(context.Context) (string, error) { leaseCalls.Add(1); return "leased-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	return handler, &policyCalls, &leaseCalls
}
