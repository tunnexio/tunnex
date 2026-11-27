package mcpgw

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// fakeMCP is a streamable-HTTP MCP server as the discovery client meets it.
type fakeMCP struct {
	mu sync.Mutex
	// accepts is the newest protocol version the server speaks; a newer offer gets HTTP 400.
	accepts string
	// negotiated overrides the version the server answers initialize with.
	negotiated string
	sse        bool
	requireKey string
	pages      map[string]string // cursor -> result JSON
	requests   []fakeMCPRequest
	server     *httptest.Server
}

type fakeMCPRequest struct {
	method        string // HTTP method
	rpc           string
	offered       string
	accept        string
	session       string
	protocol      string
	authorization string
}

func newFakeMCP(t *testing.T, configure func(*fakeMCP)) *fakeMCP {
	t.Helper()
	f := &fakeMCP{accepts: "2025-11-25", pages: map[string]string{"": `{"tools":[]}`}}
	if configure != nil {
		configure(f)
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeMCP) serve(w http.ResponseWriter, r *http.Request) {
	var message struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
			Cursor          string `json:"cursor"`
		} `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &message)
	f.mu.Lock()
	f.requests = append(f.requests, fakeMCPRequest{method: r.Method, rpc: message.Method, offered: message.Params.ProtocolVersion,
		accept: r.Header.Get("Accept"), session: r.Header.Get("Mcp-Session-Id"), protocol: r.Header.Get("Mcp-Protocol-Version"), authorization: r.Header.Get("Authorization")})
	f.mu.Unlock()
	if f.requireKey != "" && r.Header.Get("Authorization") != "Bearer "+f.requireKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	reply := func(result string) {
		payload := `{"jsonrpc":"2.0","id":` + string(message.ID) + `,"result":` + result + `}`
		if f.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\nevent: message\ndata: "+payload+"\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, payload)
	}
	switch message.Method {
	case "initialize":
		if message.Params.ProtocolVersion > f.accepts {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		version := message.Params.ProtocolVersion
		if f.negotiated != "" {
			version = f.negotiated
		}
		w.Header().Set("Mcp-Session-Id", "session-1")
		reply(`{"protocolVersion":"` + version + `","capabilities":{"tools":{}},"serverInfo":{"name":"orders-db","version":"3"}}`)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		page, ok := f.pages[message.Params.Cursor]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reply(page)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeMCP) seen() []fakeMCPRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMCPRequest(nil), f.requests...)
}

func (f *fakeMCP) count(rpc string) int {
	n := 0
	for _, request := range f.seen() {
		if request.rpc == rpc {
			n++
		}
	}
	return n
}

func testDiscoverer(control Control) *discoverer {
	return &discoverer{control: control, upstream: NewUpstreamTransport(), logger: quiet}
}

const twoTools = `{"tools":[` +
	`{"name":"run_sql","description":"Run a query","inputSchema":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]},"annotations":{"readOnlyHint":false}},` +
	`{"name":"refund","inputSchema":{"type":"object"}}]}`

// The gateway runs initialize, notifications/initialized and tools/list itself and reports the raw
// definitions. It offers the newest protocol version first and falls back, sends the streamable-HTTP
// Accept header, keeps the server's session and ends it.
func TestDiscoveryObservesRawToolDefinitionsWithVersionFallback(t *testing.T) {
	for _, sse := range []bool{false, true} {
		server := newFakeMCP(t, func(f *fakeMCP) {
			f.accepts, f.sse = "2025-06-18", sse
			f.pages = map[string]string{"": twoTools}
		})
		report := testDiscoverer(newFakeControl(nil)).observe(t.Context(), server.server.URL+"/mcp", "")
		if report.Status != statusHealthy || report.ServerName != "orders-db" || report.ProtocolVersion != "2025-06-18" || report.Endpoint != server.server.URL+"/mcp" {
			t.Fatalf("sse=%v report: %+v", sse, report)
		}
		if len(report.Tools) != 2 || report.Tools[0].Name != "run_sql" || report.Tools[0].Description != "Run a query" ||
			string(report.Tools[0].InputSchema) != `{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}` ||
			report.Tools[1].Name != "refund" || report.Tools[1].Description != "" || string(report.Tools[1].InputSchema) != `{"type":"object"}` {
			t.Fatalf("sse=%v tools: %+v", sse, report.Tools)
		}
		var order []string
		for _, request := range server.seen() {
			order = append(order, request.method+" "+request.rpc+" "+request.offered)
			if request.accept != "application/json, text/event-stream" {
				t.Fatalf("Accept = %q", request.accept)
			}
			if request.authorization != "" {
				t.Fatalf("a credential was sent to a server that has none: %q", request.authorization)
			}
			switch request.rpc {
			case "initialize":
				if request.session != "" || request.protocol != "" {
					t.Fatalf("initialize carried a session or a version header: %+v", request)
				}
			default:
				if request.session != "session-1" || request.protocol != "2025-06-18" {
					t.Fatalf("%s %s did not carry the session and the negotiated version: %+v", request.method, request.rpc, request)
				}
			}
		}
		want := "POST initialize 2025-11-25|POST initialize 2025-06-18|POST notifications/initialized |POST tools/list |DELETE  "
		if strings.Join(order, "|") != want {
			t.Fatalf("sse=%v requests:\n%s\nwant:\n%s", sse, strings.Join(order, "|"), want)
		}
	}
}

// The inventory the gateway posts is raw: it carries no hash for the control plane to trust.
func TestInventoryReportCarriesNoHash(t *testing.T) {
	server := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": twoTools} })
	report := testDiscoverer(newFakeControl(nil)).observe(t.Context(), server.server.URL, "")
	report.DeviceID = "device-1"
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "hash") || strings.Contains(string(encoded), "digest") {
		t.Fatalf("the report carries a hash: %s", encoded)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &fields)
	var tools []map[string]json.RawMessage
	_ = json.Unmarshal(fields["tools"], &tools)
	for _, tool := range tools {
		for key := range tool {
			if key != "name" && key != "description" && key != "input_schema" {
				t.Fatalf("unexpected tool field %q in %s", key, encoded)
			}
		}
	}
}

func TestDiscoveryFollowsToolListPages(t *testing.T) {
	server := newFakeMCP(t, func(f *fakeMCP) {
		f.pages = map[string]string{
			"":   `{"tools":[{"name":"a","inputSchema":{"type":"object"}}],"nextCursor":"p2"}`,
			"p2": `{"tools":[{"name":"b","inputSchema":{"type":"object"}}],"nextCursor":"p3"}`,
			"p3": `{"tools":[{"name":"c","inputSchema":{"type":"object"}}]}`,
		}
	})
	report := testDiscoverer(newFakeControl(nil)).observe(t.Context(), server.server.URL, "")
	if report.Status != statusHealthy || len(report.Tools) != 3 || report.Tools[2].Name != "c" {
		t.Fatalf("report: %+v", report)
	}
	// A page that fails is not a shorter list: the server is reported unavailable with no tools.
	broken := newFakeMCP(t, func(f *fakeMCP) {
		f.pages = map[string]string{"": `{"tools":[{"name":"a","inputSchema":{"type":"object"}}],"nextCursor":"gone"}`}
	})
	report = testDiscoverer(newFakeControl(nil)).observe(t.Context(), broken.server.URL, "")
	if report.Status != statusUnavailable || len(report.Tools) != 0 {
		t.Fatalf("a partial list was reported as the inventory: %+v", report)
	}
}

func TestDiscoveryStatuses(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	unreachable := "http://" + closed.Addr().String() + "/mcp"
	_ = closed.Close()
	locked := newFakeMCP(t, func(f *fakeMCP) { f.requireKey = "right-key" })
	future := newFakeMCP(t, func(f *fakeMCP) { f.negotiated = "2031-01-01" })
	nameless := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": `{"tools":[{"description":"no name"}]}`} })
	notAList := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": `{"tools":"run_sql"}`} })
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, locked.server.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for name, tc := range map[string]struct{ endpoint, authorization, want string }{
		"unreachable":                      {unreachable, "", statusUnavailable},
		"refuses the credential":           {locked.server.URL, "wrong-key", statusUnauthorized},
		"needs a credential":               {locked.server.URL, "", statusUnauthorized},
		"accepts the credential":           {locked.server.URL, "right-key", statusHealthy},
		"a version the gateway cannot use": {future.server.URL, "", statusInvalid},
		"a tool without a name":            {nameless.server.URL, "", statusInvalid},
		"tools that are not a list":        {notAList.server.URL, "", statusInvalid},
		"a redirect is not followed":       {redirect.URL, "right-key", statusUnavailable},
		"not an http URL":                  {"file:///etc/passwd", "", statusInvalid},
		"credentials in the URL":           {"http://user:pass@127.0.0.1:9/mcp", "", statusInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			report := testDiscoverer(newFakeControl(nil)).observe(t.Context(), tc.endpoint, tc.authorization)
			if report.Status != tc.want || report.Tools == nil || (tc.want != statusHealthy && len(report.Tools) != 0) {
				t.Fatalf("report: %+v, want status %s", report, tc.want)
			}
			if encoded, _ := json.Marshal(report); strings.Contains(string(encoded), "right-key") || strings.Contains(string(encoded), "wrong-key") {
				t.Fatalf("the report carries the credential: %s", encoded)
			}
		})
	}
	// The redirect was not followed: the locked server never saw the credential arrive that way.
	if got := locked.count("initialize"); got != 3 {
		t.Fatalf("the locked server was asked %d times, want once per direct case", got)
	}
}

// One pass: agents that share an endpoint and carry no credential share one observation; an agent with
// its own credential is observed on its own, with only that credential. Every agent gets its report.
func TestDiscoveryPassSharesAnObservationPerEndpointWithoutACredential(t *testing.T) {
	open := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": twoTools} })
	perAgent := newFakeMCP(t, func(f *fakeMCP) {
		f.pages = map[string]string{"": `{"tools":[{"name":"mine","inputSchema":{"type":"object"}}]}`}
	})
	control := newFakeControl(nil)
	control.targets = []mcpwire.Target{
		{DeviceID: "agent-a", VPNIP: "10.99.0.7", Endpoint: open.server.URL},
		{DeviceID: "agent-b", VPNIP: "10.99.0.8", Endpoint: open.server.URL},
		{DeviceID: "agent-c", VPNIP: "10.99.0.9", Endpoint: perAgent.server.URL, Authorization: "token-c"},
		{DeviceID: "agent-d", VPNIP: "10.99.0.10", Endpoint: perAgent.server.URL, Authorization: "Bearer token-d"},
		{DeviceID: "", Endpoint: open.server.URL},
		{DeviceID: "agent-e", Endpoint: ""},
	}
	testDiscoverer(control).pass(t.Context())

	if got := open.count("initialize"); got != 1 {
		t.Fatalf("the shared endpoint was observed %d times for two agents", got)
	}
	if got := perAgent.count("initialize"); got != 2 {
		t.Fatalf("the per-agent endpoint was observed %d times for two agents", got)
	}
	credentials := map[string]bool{}
	for _, request := range perAgent.seen() {
		credentials[request.authorization] = true
	}
	if len(credentials) != 2 || !credentials["Bearer token-c"] || !credentials["Bearer token-d"] {
		t.Fatalf("credentials used: %v", credentials)
	}
	var devices []string
	for _, report := range control.reports {
		devices = append(devices, report.DeviceID+"="+report.Status+":"+report.Tools[0].Name)
		if encoded, _ := json.Marshal(report); strings.Contains(string(encoded), "token-") {
			t.Fatalf("a report carries a credential: %s", encoded)
		}
	}
	sort.Strings(devices)
	if strings.Join(devices, " ") != "agent-a=healthy:run_sql agent-b=healthy:run_sql agent-c=healthy:mine agent-d=healthy:mine" {
		t.Fatalf("reports: %v", devices)
	}
}

func TestDiscoveryPassWithoutTargetsDoesNothing(t *testing.T) {
	control := newFakeControl(nil)
	control.targetErr = context.DeadlineExceeded
	testDiscoverer(control).pass(t.Context())
	control.targetErr = nil
	testDiscoverer(control).pass(t.Context())
	if len(control.reports) != 0 {
		t.Fatalf("reports without targets: %+v", control.reports)
	}
}

// ── AI-UX-1: connection previews and several servers per agent ───────────────────

// A preview target (an address an administrator is about to connect) carries a preview id and no device.
// The gateway reads its tool list once and reports it under that preview id, beside the per-agent reports.
func TestDiscoveryPassObservesAPreviewTargetAndReportsItByPreviewID(t *testing.T) {
	assigned := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": twoTools} })
	previewed := newFakeMCP(t, func(f *fakeMCP) {
		f.pages = map[string]string{"": `{"tools":[{"name":"refund","description":"Refund an order","inputSchema":{"type":"object","properties":{"order":{"type":"string"}}}}]}`}
	})
	protected := newFakeMCP(t, func(f *fakeMCP) {
		f.requireKey = "preview-token"
		f.pages = map[string]string{"": `{"tools":[{"name":"private","inputSchema":{"type":"object"}}]}`}
	})
	control := newFakeControl(nil)
	control.targets = []mcpwire.Target{
		{DeviceID: "agent-a", VPNIP: "10.99.0.7", Endpoint: assigned.server.URL},
		{PreviewID: "preview-1", Endpoint: previewed.server.URL},
		{PreviewID: "preview-2", Endpoint: protected.server.URL, Authorization: "preview-token"},
		{PreviewID: "preview-3", Endpoint: "http://127.0.0.1:1/mcp"},
		{PreviewID: "preview-4", Endpoint: ""},
	}
	testDiscoverer(control).pass(t.Context())

	if got := previewed.count("initialize"); got != 1 {
		t.Fatalf("the preview endpoint was observed %d times", got)
	}
	if previewed.count("tools/call") != 0 {
		t.Fatal("a preview called a tool")
	}
	var got []string
	for _, report := range control.reports {
		encoded, _ := json.Marshal(report)
		if strings.Contains(string(encoded), "preview-token") {
			t.Fatalf("a report carries a credential: %s", encoded)
		}
		if (report.PreviewID == "") == (report.DeviceID == "") {
			t.Fatalf("a report names both or neither of an agent and a preview: %s", encoded)
		}
		line := "device:" + report.DeviceID
		if report.PreviewID != "" {
			line = "preview:" + report.PreviewID
		}
		line += "=" + report.Status
		for _, tool := range report.Tools {
			line += ":" + tool.Name
		}
		got = append(got, line)
		if report.PreviewID == "preview-1" {
			if report.Endpoint != previewed.server.URL || report.ServerName != "orders-db" || report.Tools[0].Description != "Refund an order" ||
				string(report.Tools[0].InputSchema) != `{"type":"object","properties":{"order":{"type":"string"}}}` {
				t.Fatalf("preview report: %s", encoded)
			}
		}
	}
	sort.Strings(got)
	want := "device:agent-a=healthy:run_sql:refund preview:preview-1=healthy:refund preview:preview-2=healthy:private preview:preview-3=unavailable"
	if strings.Join(got, " ") != want {
		t.Fatalf("reports:\n got %v\nwant %s", got, want)
	}
}

// A preview of an address that agents on this gateway already use shares that one observation, and a
// target that names both an agent and a preview is an agent's.
func TestDiscoveryPassSharesAnObservationBetweenAPreviewAndAnAgent(t *testing.T) {
	server := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": twoTools} })
	control := newFakeControl(nil)
	control.targets = []mcpwire.Target{
		{DeviceID: "agent-a", Endpoint: server.server.URL},
		{PreviewID: "preview-1", Endpoint: server.server.URL},
		{DeviceID: "agent-b", PreviewID: "preview-9", Endpoint: server.server.URL},
	}
	testDiscoverer(control).pass(t.Context())
	if got := server.count("initialize"); got != 1 {
		t.Fatalf("the endpoint was observed %d times", got)
	}
	var got []string
	for _, report := range control.reports {
		got = append(got, report.DeviceID+"/"+report.PreviewID+"="+report.Status)
	}
	sort.Strings(got)
	if strings.Join(got, " ") != "/preview-1=healthy agent-a/=healthy agent-b/=healthy" {
		t.Fatalf("reports: %v", got)
	}
}

// An agent with several MCP servers appears once per server. Each endpoint is observed and reported for
// that agent under its own endpoint, with its own credential where it has one.
func TestDiscoveryPassReportsEveryEndpointOfOneAgent(t *testing.T) {
	orders := newFakeMCP(t, func(f *fakeMCP) { f.pages = map[string]string{"": twoTools} })
	billing := newFakeMCP(t, func(f *fakeMCP) {
		f.requireKey = "billing-token"
		f.pages = map[string]string{"": `{"tools":[{"name":"invoice","inputSchema":{"type":"object"}}]}`}
	})
	down := "http://127.0.0.1:1/mcp"
	control := newFakeControl(nil)
	control.targets = []mcpwire.Target{
		{DeviceID: "agent-a", VPNIP: "10.99.0.7", Endpoint: orders.server.URL},
		{DeviceID: "agent-a", VPNIP: "10.99.0.7", Endpoint: billing.server.URL, Authorization: "billing-token"},
		{DeviceID: "agent-a", VPNIP: "10.99.0.7", Endpoint: down},
		{DeviceID: "agent-b", VPNIP: "10.99.0.8", Endpoint: orders.server.URL},
		// The same server listed twice for one agent is reported once.
		{DeviceID: "agent-a", VPNIP: "10.99.0.7", Endpoint: orders.server.URL},
	}
	testDiscoverer(control).pass(t.Context())
	if orders.count("initialize") != 1 || billing.count("initialize") != 1 {
		t.Fatalf("observations: orders %d billing %d", orders.count("initialize"), billing.count("initialize"))
	}
	for _, request := range orders.seen() {
		if request.authorization != "" {
			t.Fatalf("another server's credential reached the open server: %q", request.authorization)
		}
	}
	names := map[string]string{orders.server.URL: "orders", billing.server.URL: "billing", down: "down"}
	var got []string
	for _, report := range control.reports {
		line := report.DeviceID + "@" + names[report.Endpoint] + "=" + report.Status
		for _, tool := range report.Tools {
			line += ":" + tool.Name
		}
		got = append(got, line)
	}
	sort.Strings(got)
	want := "agent-a@billing=healthy:invoice agent-a@down=unavailable agent-a@orders=healthy:run_sql:refund agent-b@orders=healthy:run_sql:refund"
	if strings.Join(got, " ") != want {
		t.Fatalf("reports:\n got %v\nwant %s", got, want)
	}
}
