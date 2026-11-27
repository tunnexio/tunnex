package mcpgw

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

const (
	peer        = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	gatewayHost = "10.99.0.1"
	agentIP     = "10.99.0.7"
	leasedToken = "lease-0123456789-secret"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeControl is the control plane's side of the mcpwire contract.
type fakeControl struct {
	mu        sync.Mutex
	decide    func(vpnIP, vpnKey string, request mcpwire.DecideRequest) (mcpwire.DecideResponse, error)
	decisions []mcpwire.DecideRequest
	evidence  [][2]string
	results   chan mcpwire.ResultRequest
	targets   []mcpwire.Target
	targetErr error
	reports   []mcpwire.InventoryReport
}

func newFakeControl(decide func(vpnIP, vpnKey string, request mcpwire.DecideRequest) (mcpwire.DecideResponse, error)) *fakeControl {
	return &fakeControl{decide: decide, results: make(chan mcpwire.ResultRequest, 16)}
}

func (c *fakeControl) MCPDecide(_ context.Context, vpnIP, vpnKey string, request mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
	c.mu.Lock()
	c.decisions = append(c.decisions, request)
	c.evidence = append(c.evidence, [2]string{vpnIP, vpnKey})
	c.mu.Unlock()
	return c.decide(vpnIP, vpnKey, request)
}

func (c *fakeControl) MCPResult(_ context.Context, _, _ string, result mcpwire.ResultRequest) error {
	c.results <- result
	return nil
}

func (c *fakeControl) MCPTargets(context.Context) ([]mcpwire.Target, error) {
	return c.targets, c.targetErr
}

func (c *fakeControl) MCPInventory(_ context.Context, report mcpwire.InventoryReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, report)
	return nil
}

func (c *fakeControl) decideCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.decisions)
}

func (c *fakeControl) result(t *testing.T) mcpwire.ResultRequest {
	t.Helper()
	select {
	case result := <-c.results:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("no result was reported")
		return mcpwire.ResultRequest{}
	}
}

func (c *fakeControl) noResult(t *testing.T) {
	t.Helper()
	select {
	case result := <-c.results:
		t.Fatalf("a result was reported for a call that was not forwarded: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
}

func allow(upstream string) func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
	return func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
		return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: upstream, Authorization: leasedToken, CallID: "call-1"}, nil
	}
}

func testRelay(control Control) *relay {
	h := Handler(gatewayHost, control, NewUpstreamTransport(), func(context.Context) (string, error) { return peer + "\t" + agentIP + "/32", nil }, quiet).(*relay)
	return h
}

func mcpRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://"+gatewayHost+":8084"+Path, strings.NewReader(body))
	r.RemoteAddr = agentIP + ":40000"
	r.Header.Set("Content-Type", "application/json")
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

type rpcReply struct {
	JSONRPC string `json:"jsonrpc"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
	ID json.RawMessage `json:"id"`
}

// requireError checks the refusal shape {"jsonrpc":"2.0","error":{...},"id":null}.
func requireError(t *testing.T, w *httptest.ResponseRecorder, status, code int, message string) rpcReply {
	t.Helper()
	var reply rpcReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatalf("status %d, body is not a JSON-RPC error: %q", w.Code, w.Body.String())
	}
	if w.Code != status || reply.JSONRPC != "2.0" || reply.Error == nil || reply.Error.Code != code || reply.Error.Message != message || string(reply.ID) != "null" {
		t.Fatalf("status=%d body=%s, want status=%d code=%d message=%q id=null", w.Code, w.Body.String(), status, code, message)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type %q", w.Header().Get("Content-Type"))
	}
	return reply
}

const callBody = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_sql","arguments":{"q":"select 1"}}}`

// The caller is the peer that owns the connection's tunnel source address. Whatever identity the caller
// claims in headers is neither believed nor passed on, to the control plane or to the MCP server.
func TestIdentityComesFromTunnelEvidenceOnly(t *testing.T) {
	forged := []string{"Authorization", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Real-Ip", "X-Api-Key",
		"X-Tunnex-User", "X-Tunnex-Device", mcpwire.HeaderVPNIP, mcpwire.HeaderVPNKey}
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		for _, name := range forged {
			if name != "Authorization" && r.Header.Get(name) != "" {
				t.Errorf("caller header reached the MCP server: %s", name)
			}
		}
		if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+leasedToken {
			t.Errorf("the MCP server did not get exactly the decision's credential: %v", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{"content":[]}}`)
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL + "/mcp"))
	h := testRelay(control)

	r := mcpRequest(callBody)
	for _, name := range forged {
		r.Header.Set(name, "forged-10.99.0.99")
	}
	w := serve(h, r)
	if w.Code != 200 || upstreamCalls != 1 {
		t.Fatalf("status=%d upstream calls=%d body=%s", w.Code, upstreamCalls, w.Body)
	}
	if len(control.evidence) != 1 || control.evidence[0] != [2]string{agentIP, peer} {
		t.Fatalf("the decision was asked for %v, want the observed peer", control.evidence)
	}
	if got := control.decisions[0]; got.Method != "tools/call" || got.ToolName != "run_sql" || string(got.Arguments) != `{"q":"select 1"}` {
		t.Fatalf("decision request: %+v", got)
	}
	control.result(t)

	// A source that owns no tunnel address is nobody, whatever it claims.
	for _, source := range []string{"203.0.113.9:40000", "10.99.0.8:40000", "malformed"} {
		r := mcpRequest(callBody)
		r.RemoteAddr = source
		r.Header.Set(mcpwire.HeaderVPNIP, agentIP)
		r.Header.Set(mcpwire.HeaderVPNKey, peer)
		requireError(t, serve(h, r), 401, codeInvalidRequest, "MCP caller is not a VPN device")
	}
	if control.decideCalls() != 1 || upstreamCalls != 1 {
		t.Fatalf("an unidentified caller reached the control plane or the server: decisions=%d upstream=%d", control.decideCalls(), upstreamCalls)
	}
}

// The peer table is read for every request: a peer removed since the last call is refused.
func TestRevokedPeerIsRefusedOnTheNextRequest(t *testing.T) {
	readback := peer + "\t" + agentIP + "/32"
	control := newFakeControl(func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
		return mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeDenied, Message: mcpwire.MessageDenied}}, nil
	})
	h := Handler(gatewayHost, control, NewUpstreamTransport(), func(context.Context) (string, error) {
		if readback == "" {
			return "", errors.New("readback failed")
		}
		return readback, nil
	}, quiet)
	requireError(t, serve(h, mcpRequest(callBody)), 403, mcpwire.CodeDenied, mcpwire.MessageDenied)
	readback = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t10.99.0.8/32"
	requireError(t, serve(h, mcpRequest(callBody)), 401, codeInvalidRequest, "MCP caller is not a VPN device")
	readback = ""
	requireError(t, serve(h, mcpRequest(callBody)), 503, codeTransport, "VPN identity is unavailable")
	if control.decideCalls() != 1 {
		t.Fatalf("decisions=%d", control.decideCalls())
	}
}

// Nothing reaches the MCP server without an allow: a deny returns the decision's own error, and no
// decision at all (the control plane unreachable, or an answer that is not consistent) is a denial too.
func TestNothingIsForwardedWithoutAnAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request was forwarded without an allow")
	}))
	defer upstream.Close()
	for name, tc := range map[string]struct {
		decision mcpwire.DecideResponse
		err      error
		status   int
		code     int
		message  string
		data     string
	}{
		"denied by policy": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeDenied, Message: mcpwire.MessageDenied}},
			status: 403, code: mcpwire.CodeDenied, message: mcpwire.MessageDenied},
		"arguments": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeArgumentsDenied, Message: mcpwire.MessageArgumentsDenied}},
			status: 403, code: mcpwire.CodeArgumentsDenied, message: mcpwire.MessageArgumentsDenied},
		"rate limit": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 429, Code: mcpwire.CodeRateLimited, Message: mcpwire.MessageRateLimited}},
			status: 429, code: mcpwire.CodeRateLimited, message: mcpwire.MessageRateLimited},
		"step-up, with the request to approve": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeStepUpRequired, Message: mcpwire.MessageStepUpRequired, Data: &mcpwire.ErrorData{RequestID: "req-42"}}},
			status: 403, code: mcpwire.CodeStepUpRequired, message: mcpwire.MessageStepUpRequired, data: `{"request_id":"req-42"}`},
		"a deny with a status that is not an error": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 200, Code: mcpwire.CodeDenied, Message: mcpwire.MessageDenied}},
			status: 403, code: mcpwire.CodeDenied, message: mcpwire.MessageDenied},
		"control plane unreachable": {err: errors.New("dial tcp: connection refused"),
			status: 503, code: codeTransport, message: messageDecisionUnavailable},
		"an allow that also carries an error": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: upstream.URL, Authorization: leasedToken, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeDenied, Message: "m"}},
			status: 503, code: codeTransport, message: messageDecisionUnavailable},
		"an allow without an upstream": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Authorization: leasedToken},
			status: 503, code: codeTransport, message: messageDecisionUnavailable},
		"a deny that names an upstream": {decision: mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Upstream: upstream.URL, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeDenied, Message: "m"}},
			status: 503, code: codeTransport, message: messageDecisionUnavailable},
		"an empty answer": {status: 503, code: codeTransport, message: messageDecisionUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			control := newFakeControl(func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
				return tc.decision, tc.err
			})
			w := serve(testRelay(control), mcpRequest(callBody))
			reply := requireError(t, w, tc.status, tc.code, tc.message)
			if tc.data != "" && string(reply.Error.Data) != tc.data {
				t.Fatalf("error data = %s, want %s", reply.Error.Data, tc.data)
			}
			if strings.Contains(w.Body.String(), leasedToken) || strings.Contains(w.Body.String(), "connection refused") {
				t.Fatalf("the refusal leaks: %s", w.Body)
			}
			control.noResult(t)
		})
	}
}

// The call goes to the upstream the decision names, with the credential the decision carries, and the
// MCP session headers pass through both ways. The credential never comes back to the caller.
func TestForwardsOnlyToTheDecisionsUpstreamWithItsCredential(t *testing.T) {
	var got *http.Request
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "session-from-server")
		w.Header().Set("MCP-Protocol-Version", "2025-11-25")
		// A server may answer with headers the agent must not get.
		w.Header().Set("Set-Cookie", "upstream=1")
		w.Header().Set("Www-Authenticate", `Bearer resource_metadata="https://auth.example/"`)
		w.Header().Set("X-Echo-Authorization", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"1"}]}}`)
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL + "/servers/db/mcp"))
	r := mcpRequest(callBody)
	r.Header.Set("Authorization", "Bearer agent-own-token")
	r.Header.Set("Mcp-Session-Id", "session-from-agent")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := serve(testRelay(control), r)

	if w.Code != 200 || w.Body.String() != `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"1"}]}}` {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if got == nil || got.URL.Path != "/servers/db/mcp" || got.Method != http.MethodPost || gotBody != callBody {
		t.Fatalf("upstream request: %+v body=%q", got, gotBody)
	}
	if auth := got.Header.Values("Authorization"); len(auth) != 1 || auth[0] != "Bearer "+leasedToken {
		t.Fatalf("upstream Authorization = %v", auth)
	}
	if got.Header.Get("Mcp-Session-Id") != "session-from-agent" || got.Header.Get("Mcp-Protocol-Version") != "2025-11-25" || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("MCP headers to the server: %v", got.Header)
	}
	if w.Header().Get("Mcp-Session-Id") != "session-from-server" || w.Header().Get("Mcp-Protocol-Version") != "2025-11-25" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("MCP headers to the agent: %v", w.Header())
	}
	for name, values := range w.Header() {
		for _, value := range values {
			if strings.Contains(value, leasedToken) || name == "Set-Cookie" || name == "Www-Authenticate" {
				t.Fatalf("the agent received %s: %s", name, value)
			}
		}
	}
	if strings.Contains(w.Body.String(), leasedToken) {
		t.Fatal("the credential came back in the body")
	}
	if control.decisions[0].ProtocolVersion != "2025-11-25" {
		t.Fatalf("protocol version told to the control plane: %q", control.decisions[0].ProtocolVersion)
	}
	if result := control.result(t); result != (mcpwire.ResultRequest{CallID: "call-1", Status: mcpwire.ResultOK, UpstreamHTTPStatus: 200}) {
		t.Fatalf("result: %+v", result)
	}
}

func TestDecisionCredentialFormsAndAbsence(t *testing.T) {
	for name, tc := range map[string]struct{ credential, want string }{
		"a bare token":         {"abc", "Bearer abc"},
		"a full header value":  {"Bearer abc", "Bearer abc"},
		"another letter case":  {"bearer abc", "bearer abc"},
		"no credential at all": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			var auth []string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth = r.Header.Values("Authorization")
				w.WriteHeader(http.StatusAccepted)
			}))
			defer upstream.Close()
			control := newFakeControl(func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
				return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: upstream.URL, Authorization: tc.credential}, nil
			})
			r := mcpRequest(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
			r.Header.Set("Authorization", "Bearer agent-own-token")
			if w := serve(testRelay(control), r); w.Code != http.StatusAccepted {
				t.Fatalf("status %d", w.Code)
			}
			if strings.Join(auth, ",") != tc.want {
				t.Fatalf("Authorization = %v, want %q", auth, tc.want)
			}
			control.noResult(t) // no call id, nothing to close
		})
	}
}

// An upstream that does not connect or does not answer with headers inside the budget fails as
// "MCP upstream is unavailable", and the budget is five seconds.
func TestUnavailableUpstreamFailsWithinTheBudget(t *testing.T) {
	if UpstreamTimeout != 5*time.Second {
		t.Fatalf("UpstreamTimeout = %s, the decision is five seconds", UpstreamTimeout)
	}
	if tr := NewUpstreamTransport(); tr.Proxy != nil || tr.ResponseHeaderTimeout != UpstreamTimeout || tr.TLSHandshakeTimeout != UpstreamTimeout {
		t.Fatalf("upstream transport: proxy set=%v header=%s tls=%s", tr.Proxy != nil, tr.ResponseHeaderTimeout, tr.TLSHandshakeTimeout)
	}
	release := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer silent.Close()
	defer close(release)
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := "http://" + closed.Addr().String() + "/mcp"
	_ = closed.Close()

	for name, upstream := range map[string]string{"no response headers": silent.URL, "connection refused": refused,
		"not a URL the gateway forwards to": "ftp://172.30.0.10/mcp", "credentials in the URL": "http://user:pass@127.0.0.1:9/mcp"} {
		t.Run(name, func(t *testing.T) {
			control := newFakeControl(allow(upstream))
			h := testRelay(control)
			h.headerTimeout = 150 * time.Millisecond
			start := time.Now()
			w := serve(h, mcpRequest(callBody))
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("took %s with a %s budget", elapsed, h.headerTimeout)
			}
			requireError(t, w, http.StatusBadGateway, mcpwire.CodeUpstreamUnavailable, mcpwire.MessageUpstreamUnavailable)
			if strings.Contains(w.Body.String(), leasedToken) {
				t.Fatal("the credential leaked into the failure")
			}
			if result := control.result(t); result.CallID != "call-1" || result.Status != mcpwire.ResultUpstreamUnavailable {
				t.Fatalf("result: %+v", result)
			}
		})
	}
}

// A redirect is not followed: the credential would leave for a server the decision did not name.
func TestUpstreamRedirectIsNotFollowed(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the call followed a redirect")
	}))
	defer elsewhere.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL))
	w := serve(testRelay(control), mcpRequest(callBody))
	requireError(t, w, http.StatusBadGateway, mcpwire.CodeUpstreamUnavailable, mcpwire.MessageUpstreamUnavailable)
	if w.Header().Get("Location") != "" {
		t.Fatal("the redirect target was passed to the agent")
	}
	if result := control.result(t); result.Status != mcpwire.ResultError || result.UpstreamHTTPStatus != http.StatusTemporaryRedirect {
		t.Fatalf("result: %+v", result)
	}
}

// A server's own failure is the agent's to see, and is recorded as an error.
func TestUpstreamErrorStatusPassesThroughAndIsRecorded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Session not found"}}`)
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL))
	w := serve(testRelay(control), mcpRequest(callBody))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Session not found") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if result := control.result(t); result.Status != mcpwire.ResultError || result.UpstreamHTTPStatus != http.StatusNotFound {
		t.Fatalf("result: %+v", result)
	}
}

// A streamed answer reaches the agent as it is produced.
func TestStreamedAnswerIsRelayedAsItArrives(t *testing.T) {
	second := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
		w.(http.Flusher).Flush()
		<-second
		_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n\n")
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL))
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = agentIP + ":40000"
		r.Host = gatewayHost + ":8084"
		testRelay(control).ServeHTTP(w, r)
	}))
	front.Start()
	defer front.Close()
	response, err := http.Post(front.URL+Path, "application/json", strings.NewReader(callBody))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, 256)
	n, err := response.Body.Read(first)
	if err != nil || !strings.Contains(string(first[:n]), "notifications/progress") {
		t.Fatalf("the first event did not arrive before the stream ended: %q %v", first[:n], err)
	}
	close(second)
	rest, _ := io.ReadAll(response.Body)
	if response.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(string(rest), `"result":{}`) {
		t.Fatalf("content type %q rest %q", response.Header.Get("Content-Type"), rest)
	}
	control.result(t)
}

const listedTools = `{"tools":[` +
	`{"name":"read_orders","description":"Read orders","inputSchema":{"type":"object"}},` +
	`{"name":"run_sql","description":"Run SQL","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}},` +
	`{"name":"refund","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}`

func listedNames(t *testing.T, message string) (names []string, cursor string) {
	t.Helper()
	var reply struct {
		ID     int `json:"id"`
		Result struct {
			Tools []struct {
				Name        string          `json:"name"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(message), &reply); err != nil || reply.ID != 3 {
		t.Fatalf("not the list response: %q (%v)", message, err)
	}
	for _, tool := range reply.Result.Tools {
		if len(tool.InputSchema) == 0 {
			t.Fatalf("tool %s lost its definition", tool.Name)
		}
		names = append(names, tool.Name)
	}
	return names, reply.Result.NextCursor
}

// tools/list returns only the tools the decision says are callable, for a plain JSON answer and for an
// event-stream answer alike.
func TestToolsListIsFilteredToCallableTools(t *testing.T) {
	const listBody = `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`
	for name, tc := range map[string]struct {
		contentType string
		body        string
		callable    []string
		want        string
	}{
		"json":                            {"application/json", `{"jsonrpc":"2.0","id":3,"result":` + listedTools + `}`, []string{"read_orders", "refund", "not_on_server"}, "read_orders,refund"},
		"json with a charset":             {"application/json; charset=utf-8", `{"jsonrpc":"2.0","id":3,"result":` + listedTools + `}`, []string{"run_sql"}, "run_sql"},
		"nothing callable":                {"application/json", `{"jsonrpc":"2.0","id":3,"result":` + listedTools + `}`, nil, ""},
		"event stream":                    {"text/event-stream", "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":" + listedTools + "}\n\n", []string{"run_sql"}, "run_sql"},
		"event stream, no space":          {"text/event-stream", "data:{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":" + listedTools + "}\n\n", []string{"refund"}, "refund"},
		"event stream after notification": {"text/event-stream; charset=utf-8", "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"tools\":[{\"name\":\"refund\"}]}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":" + listedTools + "}\n\n", []string{"read_orders"}, "read_orders"},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Mcp-Session-Id", "s1")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			control := newFakeControl(func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
				return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: upstream.URL, CallableTools: tc.callable, CallID: "call-1"}, nil
			})
			w := serve(testRelay(control), mcpRequest(listBody))
			if w.Code != 200 || w.Header().Get("Mcp-Session-Id") != "s1" {
				t.Fatalf("status=%d headers=%v body=%s", w.Code, w.Header(), w.Body)
			}
			message := w.Body.String()
			if strings.HasPrefix(tc.contentType, "text/event-stream") {
				if w.Header().Get("Content-Type") != "text/event-stream" || !strings.HasPrefix(message, "event: message\ndata: ") || !strings.HasSuffix(message, "\n\n") {
					t.Fatalf("event-stream answer: %q %q", w.Header().Get("Content-Type"), message)
				}
				message = strings.TrimSuffix(strings.TrimPrefix(message, "event: message\ndata: "), "\n\n")
				if strings.Contains(message, "\n") || strings.Contains(message, "notifications/message") {
					t.Fatalf("more than the list response was passed on: %q", message)
				}
			} else if w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("content type %q", w.Header().Get("Content-Type"))
			}
			names, cursor := listedNames(t, message)
			if strings.Join(names, ",") != tc.want || cursor != "page-2" {
				t.Fatalf("tools=%v cursor=%q, want %q", names, cursor, tc.want)
			}
			for _, hidden := range []string{"read_orders", "run_sql", "refund"} {
				if !strings.Contains(","+tc.want+",", ","+hidden+",") && strings.Contains(w.Body.String(), hidden) {
					t.Fatalf("a tool that is not callable is visible: %s in %s", hidden, w.Body)
				}
			}
			if result := control.result(t); result.Status != mcpwire.ResultOK {
				t.Fatalf("result: %+v", result)
			}
		})
	}
}

// A list answer the gateway cannot filter with certainty is not passed on at all.
func TestToolsListThatCannotBeFilteredIsNotPassedOn(t *testing.T) {
	const listBody = `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`
	for name, tc := range map[string]struct {
		status      int
		contentType string
		body        string
		wantStatus  int
	}{
		"not JSON":                  {200, "application/json", `tools: run_sql, refund`, 502},
		"an array":                  {200, "application/json", `[{"jsonrpc":"2.0","id":3,"result":` + listedTools + `}]`, 502},
		"a repeated tools key":      {200, "application/json", `{"jsonrpc":"2.0","id":3,"result":{"tools":[],"tools":[{"name":"refund"}]}}`, 502},
		"a repeated result key":     {200, "application/json", `{"jsonrpc":"2.0","id":3,"result":{"tools":[]},"result":` + listedTools + `}`, 502},
		"tools in another case":     {200, "application/json", `{"jsonrpc":"2.0","id":3,"result":{"Tools":[{"name":"refund"}]}}`, 502},
		"tools that is not a list":  {200, "application/json", `{"jsonrpc":"2.0","id":3,"result":{"tools":{"refund":{"name":"refund"}}}}`, 502},
		"an event stream of noise":  {200, "text/event-stream", "event: message\ndata: refund run_sql\n\n", 502},
		"a stream with no response": {200, "text/event-stream", ": refund keep-alive\n\n", 502},
		"an empty answer":           {200, "application/json", ``, 502},
		"the server's own failure":  {500, "text/plain", `tools: run_sql, refund`, 500},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			control := newFakeControl(func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
				return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: upstream.URL, CallableTools: []string{"read_orders"}, CallID: "call-1"}, nil
			})
			w := serve(testRelay(control), mcpRequest(listBody))
			requireError(t, w, tc.wantStatus, mcpwire.CodeUpstreamUnavailable, mcpwire.MessageUpstreamUnavailable)
			if strings.Contains(w.Body.String(), "refund") || strings.Contains(w.Body.String(), "run_sql") {
				t.Fatalf("an unfiltered tool name was passed on: %s", w.Body)
			}
			if result := control.result(t); result.Status != mcpwire.ResultError {
				t.Fatalf("result: %+v", result)
			}
		})
	}
}

// A JSON-RPC error answer to tools/list holds no tool list and passes through.
func TestToolsListErrorAnswerPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid cursor"}}`)
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL))
	w := serve(testRelay(control), mcpRequest(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"x"}}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Invalid cursor") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
}

// What the listener refuses before it asks for any decision.
func TestRequestsRefusedBeforeAnyDecision(t *testing.T) {
	control := newFakeControl(func(string, string, mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
		t.Error("a refused request reached the control plane")
		return mcpwire.DecideResponse{}, errors.New("unexpected")
	})
	h := testRelay(control)
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sql","arguments":{"q":"` + strings.Repeat("a", mcpwire.MaxRequestBytes) + `"}}}`
	for name, tc := range map[string]struct {
		request func() *http.Request
		status  int
		code    int
	}{
		"GET": {func() *http.Request {
			r := mcpRequest("")
			r.Method = http.MethodGet
			return r
		}, 405, codeInvalidRequest},
		"DELETE": {func() *http.Request {
			r := mcpRequest("")
			r.Method = http.MethodDelete
			return r
		}, 405, codeInvalidRequest},
		"another host": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Host = "mcp.example.test:8084"
			return r
		}, 421, codeInvalidRequest},
		"another path": {func() *http.Request {
			r := mcpRequest(callBody)
			r.URL.Path = "/mcp/admin"
			return r
		}, 404, codeInvalidRequest},
		"a query": {func() *http.Request {
			r := mcpRequest(callBody)
			r.URL.RawQuery = "upstream=http://evil.test/"
			return r
		}, 404, codeInvalidRequest},
		"a form content type": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Header.Set("Content-Type", "text/plain")
			return r
		}, 403, codeInvalidRequest},
		"a browser origin": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Header.Set("Origin", "https://evil.test")
			return r
		}, 403, codeInvalidRequest},
		"a body over 1 MiB":             {func() *http.Request { return mcpRequest(big) }, 413, codeInvalidRequest},
		"an empty body":                 {func() *http.Request { return mcpRequest("") }, 400, codeInvalidRequest},
		"a batch":                       {func() *http.Request { return mcpRequest("[" + callBody + "]") }, 400, codeInvalidRequest},
		"two requests":                  {func() *http.Request { return mcpRequest(callBody + callBody) }, 400, codeInvalidRequest},
		"not JSON-RPC 2.0":              {func() *http.Request { return mcpRequest(`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`) }, 400, codeInvalidRequest},
		"no method":                     {func() *http.Request { return mcpRequest(`{"jsonrpc":"2.0","id":1}`) }, 400, codeInvalidRequest},
		"a method that is not a string": {func() *http.Request { return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":["tools/list"]}`) }, 400, codeInvalidRequest},
		"a repeated method": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"a repeated tool name": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_orders","name":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"a repeated params": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_orders"},"params":{"name":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"a repeated key written with an escape": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"a repeated argument, deep": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sql","arguments":{"filter":{"table":"orders","table":"users"}}}}`)
		}, 400, codeInvalidRequest},
		"method in another letter case": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"only a capitalised method": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"arguments in another letter case": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sql","Arguments":{"q":"drop table"}}}`)
		}, 400, codeInvalidRequest},
		"tool name in another letter case": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_orders","NAME":"run_sql"}}`)
		}, 400, codeInvalidRequest},
		"two arguments that differ by case": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sql","arguments":{"q":"select 1","Q":"drop table"}}}`)
		}, 400, codeInvalidRequest},
		"a tool call without a name": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`)
		}, 400, codeInvalidRequest},
		"a tool name that is not a string": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["run_sql"]}}`)
		}, 400, codeInvalidRequest},
		"arguments that are not an object": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sql","arguments":"q=1"}}`)
		}, 400, codeInvalidRequest},
		"params that are not an object": {func() *http.Request {
			return mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["run_sql"]}`)
		}, 400, codeInvalidRequest},
		"invalid UTF-8": {func() *http.Request {
			return mcpRequest("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"run\xff_sql\"}}")
		}, 400, codeInvalidRequest},
		"a method header for another method": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Header.Set("Mcp-Method", "tools/list")
			return r
		}, 400, codeTransport},
		"a name header for another tool": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Header.Set("Mcp-Name", "read_orders")
			return r
		}, 400, codeTransport},
		"a malformed protocol version": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Header.Set("MCP-Protocol-Version", "latest\r\nX: y")
			return r
		}, 400, codeTransport},
		"2026-07-28 without its mirrors": {func() *http.Request {
			r := mcpRequest(callBody)
			r.Header.Set("MCP-Protocol-Version", protocol20260728)
			return r
		}, 400, codeTransport},
	} {
		t.Run(name, func(t *testing.T) {
			w := serve(h, tc.request())
			var reply rpcReply
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != tc.status || reply.Error == nil || reply.Error.Code != tc.code || string(reply.ID) != "null" {
				t.Fatalf("status=%d body=%s, want status=%d code=%d", w.Code, w.Body, tc.status, tc.code)
			}
		})
	}
	if control.decideCalls() != 0 {
		t.Fatalf("decisions=%d", control.decideCalls())
	}
}

// The mirrored headers of the 2026-07-28 revision are an integrity check on the body, which stays
// authoritative; a consistent request is decided on the body's values.
func TestModernMirroredHeadersAreCheckedAgainstTheBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mcp-Method") != "tools/call" || r.Header.Get("Mcp-Name") != "=?base64?cnVuX3NxbA==?=" || r.Header.Get("Mcp-Protocol-Version") != protocol20260728 {
			t.Errorf("mirrors not passed to the server: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{}}`)
	}))
	defer upstream.Close()
	control := newFakeControl(allow(upstream.URL))
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_sql","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	r := mcpRequest(body)
	r.Header.Set("MCP-Protocol-Version", protocol20260728)
	r.Header.Set("Mcp-Method", "tools/call")
	r.Header.Set("Mcp-Name", "=?base64?cnVuX3NxbA==?=")
	if w := serve(testRelay(control), r); w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if got := control.decisions[0]; got.ToolName != "run_sql" || got.ProtocolVersion != protocol20260728 {
		t.Fatalf("decision request: %+v", got)
	}
}

// Every method is decided by the control plane, including the ones that open a session.
func TestEveryMethodAsksForADecision(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()
	control := newFakeControl(func(_, _ string, request mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
		if request.Method == "resources/read" {
			return mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: 403, Code: mcpwire.CodeDenied, Message: mcpwire.MessageDenied}}, nil
		}
		return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: upstream.URL}, nil
	})
	h := testRelay(control)
	if w := serve(h, mcpRequest(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)); w.Code != 200 {
		t.Fatalf("initialize: %d %s", w.Code, w.Body)
	}
	if w := serve(h, mcpRequest(`{"jsonrpc":"2.0","id":"a","method":"ping"}`)); w.Code != 200 {
		t.Fatalf("ping: %d %s", w.Code, w.Body)
	}
	requireError(t, serve(h, mcpRequest(`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`)), 403, mcpwire.CodeDenied, mcpwire.MessageDenied)
	if got := control.decisions; len(got) != 3 || got[0].Method != "initialize" || got[0].ProtocolVersion != "2025-06-18" || got[1].Method != "ping" || got[2].Method != "resources/read" || got[2].ToolName != "" {
		t.Fatalf("decisions: %+v", got)
	}
}

func TestBusyListenerRefusesInsteadOfQueueing(t *testing.T) {
	control := newFakeControl(allow("http://127.0.0.1:9/"))
	h := testRelay(control)
	for i := 0; i < cap(h.slots); i++ {
		h.slots <- struct{}{}
	}
	requireError(t, serve(h, mcpRequest(callBody)), http.StatusTooManyRequests, codeTransport, "MCP gateway is busy")
	if control.decideCalls() != 0 {
		t.Fatal("a refused request reached the control plane")
	}
}
