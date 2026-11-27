package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

const mcpTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type mcpRoundTrip func(*http.Request) (*http.Response, error)

func (f mcpRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mcpTestClient(rt mcpRoundTrip) *Client {
	return &Client{base: "https://control.test:8443", http: &http.Client{Transport: rt}}
}

func mcpReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

// The decision is asked on the node channel with exactly one of each evidence header, set by the gateway.
func TestMCPDecideSendsTheGatewaysEvidenceAndReturnsTheDecision(t *testing.T) {
	c := mcpTestClient(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.String() != "https://control.test:8443"+mcpwire.PathDecide {
			t.Fatalf("%s %s", r.Method, r.URL)
		}
		if ips, keys := r.Header.Values(mcpwire.HeaderVPNIP), r.Header.Values(mcpwire.HeaderVPNKey); len(ips) != 1 || ips[0] != "10.99.0.7" || len(keys) != 1 || keys[0] != mcpTestKey {
			t.Fatalf("evidence headers: %v %v", ips, keys)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("headers: %v", r.Header)
		}
		var got mcpwire.DecideRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Method != "tools/call" || got.ToolName != "run_sql" || string(got.Arguments) != `{"q":"select 1"}` || got.ProtocolVersion != "2025-11-25" {
			t.Fatalf("request: %+v", got)
		}
		return mcpReply(200, `{"decision":"allow","upstream":"http://172.30.0.10:9000/mcp","authorization":"token","call_id":"call-1"}`), nil
	})
	got, err := c.MCPDecide(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.DecideRequest{Method: "tools/call", ToolName: "run_sql", Arguments: json.RawMessage(`{"q":"select 1"}`), ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != mcpwire.DecisionAllow || got.Upstream != "http://172.30.0.10:9000/mcp" || got.Authorization != "token" || got.CallID != "call-1" {
		t.Fatalf("decision: %+v", got)
	}
}

// Only a well-formed answer is a decision. Anything else is an error, which the gateway treats as a denial;
// an allow is accepted only with HTTP 200, and the answer's body never appears in the error.
func TestMCPDecideAcceptsOnlyAWellFormedDecision(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		body     string
		decision string
		invalid  bool
	}{
		"deny":                          {200, `{"decision":"deny","error":{"http_status":403,"code":-32100,"message":"MCP tool is denied by policy"}}`, mcpwire.DecisionDeny, false},
		"deny sent with its own status": {403, `{"decision":"deny","error":{"http_status":403,"code":-32100,"message":"MCP tool is denied by policy"}}`, mcpwire.DecisionDeny, false},
		"allow without an upstream":     {200, `{"decision":"allow","authorization":"secret-token"}`, "", true},
		"allow with an error":           {200, `{"decision":"allow","upstream":"http://x/","error":{"http_status":403,"code":-32100,"message":"m"}}`, "", true},
		"deny that names an upstream":   {200, `{"decision":"deny","upstream":"http://x/","error":{"http_status":403,"code":-32100,"message":"m"}}`, "", true},
		"unknown decision":              {200, `{"decision":"maybe","upstream":"http://x/"}`, "", true},
		"empty object":                  {200, `{}`, "", true},
		"not JSON":                      {200, `secret-token`, "", true},
		"allow with a failure status":   {500, `{"decision":"allow","upstream":"http://x/","authorization":"secret-token"}`, "", false},
		"server error":                  {502, `secret-token`, "", false},
		"not found (older control)":     {404, `not found`, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			c := mcpTestClient(func(*http.Request) (*http.Response, error) { return mcpReply(tc.status, tc.body), nil })
			got, err := c.MCPDecide(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.DecideRequest{Method: "tools/list"})
			if tc.decision != "" {
				if err != nil || got.Decision != tc.decision || got.Error == nil {
					t.Fatalf("decision=%+v err=%v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted: %+v", got)
			}
			if got.Decision != "" || got.Upstream != "" || got.Authorization != "" {
				t.Fatalf("a refused answer leaked into the result: %+v", got)
			}
			if tc.invalid && !errors.Is(err, mcpwire.ErrInvalidDecision) {
				t.Fatalf("err=%v, want ErrInvalidDecision", err)
			}
			if strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("the error carries the answer's body: %v", err)
			}
		})
	}
}

func TestMCPDecideNeverFollowsARedirect(t *testing.T) {
	calls := 0
	c := mcpTestClient(func(r *http.Request) (*http.Response, error) {
		calls++
		res := mcpReply(307, "")
		res.Header.Set("Location", "https://elsewhere.test/agent/mcp/decide")
		return res, nil
	})
	if _, err := c.MCPDecide(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.DecideRequest{Method: "tools/list"}); err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d: the evidence and the request followed a redirect", err, calls)
	}
}

func TestMCPResultTargetsAndInventoryUseTheirPaths(t *testing.T) {
	var seen []string
	c := mcpTestClient(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(body))
		switch r.URL.Path {
		case mcpwire.PathTargets:
			return mcpReply(200, `{"targets":[{"device_id":"d1","vpn_ip":"10.99.0.7","endpoint":"http://172.30.0.10:9000/mcp","authorization":"t"}]}`), nil
		case mcpwire.PathResult:
			if r.Header.Get(mcpwire.HeaderVPNIP) != "10.99.0.7" || r.Header.Get(mcpwire.HeaderVPNKey) != mcpTestKey {
				t.Fatalf("result evidence: %v", r.Header)
			}
		}
		return mcpReply(204, ""), nil
	})
	if err := c.MCPResult(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.ResultRequest{CallID: "call-1", Status: mcpwire.ResultOK, UpstreamHTTPStatus: 200}); err != nil {
		t.Fatal(err)
	}
	targets, err := c.MCPTargets(t.Context())
	if err != nil || len(targets) != 1 || targets[0].DeviceID != "d1" || targets[0].Authorization != "t" {
		t.Fatalf("targets=%+v err=%v", targets, err)
	}
	if err := c.MCPInventory(t.Context(), mcpwire.InventoryReport{DeviceID: "d1", Endpoint: "http://172.30.0.10:9000/mcp", Status: "healthy", Tools: []mcpwire.ObservedTool{{Name: "run_sql", InputSchema: json.RawMessage(`{"type":"object"}`)}}}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`POST /agent/mcp/result {"call_id":"call-1","status":"ok","upstream_http_status":200}`,
		`GET /agent/mcp/targets `,
		`POST /agent/mcp/inventory {"device_id":"d1","endpoint":"http://172.30.0.10:9000/mcp","status":"healthy","tools":[{"name":"run_sql","input_schema":{"type":"object"}}]}`,
	}
	if len(seen) != len(want) {
		t.Fatalf("calls: %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("call %d:\n%s\nwant:\n%s", i, seen[i], want[i])
		}
	}
	failing := mcpTestClient(func(*http.Request) (*http.Response, error) { return mcpReply(500, "boom"), nil })
	if failing.MCPResult(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.ResultRequest{CallID: "c"}) == nil || failing.MCPInventory(t.Context(), mcpwire.InventoryReport{}) == nil {
		t.Fatal("a failed report was treated as delivered")
	}
	if _, err := failing.MCPTargets(t.Context()); err == nil {
		t.Fatal("a failed targets fetch returned targets")
	}
}

// The capability is reported beside the AI one, and only as the runtime reports it.
func TestReportInfoCarriesTheMCPGatewayCapability(t *testing.T) {
	for _, tc := range []PolicyStatus{{}, {MCPGatewayReady: true, MCPGatewayAddress: "10.99.0.1"}} {
		var payload map[string]any
		c := mcpTestClient(func(r *http.Request) (*http.Response, error) {
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return mcpReply(204, ""), nil
		})
		if err := c.ReportInfo(t.Context(), "pub", "198.51.100.1:51820", true, false, tc); err != nil {
			t.Fatal(err)
		}
		ready, okReady := payload[mcpwire.CapabilityGatewayReady].(bool)
		address, okAddress := payload[mcpwire.CapabilityGatewayAddress].(string)
		if !okReady || !okAddress || ready != tc.MCPGatewayReady || address != tc.MCPGatewayAddress {
			t.Fatalf("payload ready=%v address=%v, want %v %q", payload[mcpwire.CapabilityGatewayReady], payload[mcpwire.CapabilityGatewayAddress], tc.MCPGatewayReady, tc.MCPGatewayAddress)
		}
	}
}

// AI-UX-1: the wait for a held call is asked with the agent's evidence, and only a 200 with a readable
// body is an answer. A control plane that predates the route (404), a redirect or an error is no answer.
func TestMCPWaitSendsEvidenceAndAcceptsOnlyA200(t *testing.T) {
	c := mcpTestClient(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != mcpwire.PathWait || string(body) != `{"request_id":"req-42"}` {
			t.Fatalf("wait request: %s %s %s", r.Method, r.URL.Path, body)
		}
		if got := r.Header.Values(mcpwire.HeaderVPNIP); len(got) != 1 || got[0] != "10.99.0.7" {
			t.Fatalf("vpn ip header: %v", got)
		}
		if got := r.Header.Values(mcpwire.HeaderVPNKey); len(got) != 1 || got[0] != mcpTestKey {
			t.Fatalf("vpn key header: %v", got)
		}
		return mcpReply(200, `{"state":"approved"}`), nil
	})
	got, err := c.MCPWait(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.WaitRequest{RequestID: "req-42"})
	if err != nil || got.State != mcpwire.WaitApproved {
		t.Fatalf("wait: %+v %v", got, err)
	}
	for name, reply := range map[string]*http.Response{
		"an older control plane": mcpReply(404, `{"state":"approved"}`),
		"a server error":         mcpReply(500, `{"state":"approved"}`),
		"a redirect":             {StatusCode: 307, Header: http.Header{"Location": {"https://elsewhere.test/"}}, Body: io.NopCloser(strings.NewReader(""))},
		"not JSON":               mcpReply(200, `approved`),
	} {
		calls := 0
		failing := mcpTestClient(func(*http.Request) (*http.Response, error) { calls++; return reply, nil })
		if got, err := failing.MCPWait(t.Context(), "10.99.0.7", mcpTestKey, mcpwire.WaitRequest{RequestID: "req-42"}); err == nil || got.State != "" || calls != 1 {
			t.Fatalf("%s: %+v err=%v calls=%d", name, got, err, calls)
		}
	}
}
