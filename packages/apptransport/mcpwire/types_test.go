package mcpwire

import (
	"encoding/json"
	"strings"
	"testing"
)

// The control plane and the gateway are separate modules that both import this package, so the JSON below is
// the one description of the wire. If a field name changes here, both sides change with it or neither does.
func TestDecideRequestWireShape(t *testing.T) {
	req := DecideRequest{Method: "tools/call", ToolName: "refund_order", Arguments: json.RawMessage(`{"order_id":3,"amount_cents":2500}`), ProtocolVersion: "2025-11-25"}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"method":"tools/call","tool_name":"refund_order","arguments":{"order_id":3,"amount_cents":2500},"protocol_version":"2025-11-25"}`
	if string(b) != want {
		t.Fatalf("request wire = %s\nwant           %s", b, want)
	}
	b, err = json.Marshal(DecideRequest{Method: "tools/list"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"method":"tools/list"}` {
		t.Fatalf("a request with no tool must omit the tool fields: %s", b)
	}
}

func TestDecideResponseWireShape(t *testing.T) {
	allow := DecideResponse{Decision: DecisionAllow, Upstream: "http://172.30.0.10:9000/mcp", Authorization: "Bearer t", CallableTools: []string{"list_customers"}, CallID: "01a21b38-dc70-7d21-9c08-2772c26b7a3c"}
	b, err := json.Marshal(allow)
	if err != nil {
		t.Fatal(err)
	}
	const wantAllow = `{"decision":"allow","upstream":"http://172.30.0.10:9000/mcp","authorization":"Bearer t","callable_tools":["list_customers"],"call_id":"01a21b38-dc70-7d21-9c08-2772c26b7a3c"}`
	if string(b) != wantAllow {
		t.Fatalf("allow wire = %s\nwant         %s", b, wantAllow)
	}
	deny := DecideResponse{Decision: DecisionDeny, Error: &Error{HTTPStatus: 403, Code: CodeStepUpRequired, Message: MessageStepUpRequired, Data: &ErrorData{RequestID: "22a21cf4-fc02-441a-aef0-0f6472b59ca0"}}}
	b, err = json.Marshal(deny)
	if err != nil {
		t.Fatal(err)
	}
	const wantDeny = `{"decision":"deny","error":{"http_status":403,"code":-32103,"message":"MCP tool requires step-up approval","data":{"request_id":"22a21cf4-fc02-441a-aef0-0f6472b59ca0"}}}`
	if string(b) != wantDeny {
		t.Fatalf("deny wire = %s\nwant        %s", b, wantDeny)
	}
}

// A deny must never carry what an allow carries: no upstream to call and no credential to call it with.
func TestDenyCarriesNoUpstreamOrCredential(t *testing.T) {
	if (DecideResponse{Decision: DecisionDeny, Error: &Error{HTTPStatus: 403, Code: CodeDenied, Message: MessageDenied}}).Valid() != nil {
		t.Fatal("a plain deny must be valid")
	}
	for name, r := range map[string]DecideResponse{
		"deny with upstream":      {Decision: DecisionDeny, Upstream: "http://x/mcp", Error: &Error{HTTPStatus: 403, Code: CodeDenied, Message: MessageDenied}},
		"deny with authorization": {Decision: DecisionDeny, Authorization: "Bearer t", Error: &Error{HTTPStatus: 403, Code: CodeDenied, Message: MessageDenied}},
		"deny without error":      {Decision: DecisionDeny},
		"allow without upstream":  {Decision: DecisionAllow},
		"allow with error":        {Decision: DecisionAllow, Upstream: "http://x/mcp", Error: &Error{HTTPStatus: 403, Code: CodeDenied, Message: MessageDenied}},
		"unknown decision":        {Decision: "maybe", Upstream: "http://x/mcp"},
	} {
		if r.Valid() == nil {
			t.Fatalf("%s must be rejected by the gateway before it forwards anything", name)
		}
	}
	if (DecideResponse{Decision: DecisionAllow, Upstream: "http://x/mcp"}).Valid() != nil {
		t.Fatal("an allow with an upstream must be valid")
	}
}

// The JSON-RPC codes and messages are the ones the agent-host proxy has always returned, so an agent client
// sees the same refusal whether the local proxy or the gateway produced it.
func TestErrorCodesMatchTheExistingProxy(t *testing.T) {
	for code, msg := range map[int]string{
		-32100: "MCP tool is denied by policy",
		-32101: "MCP tool arguments are denied by policy",
		-32102: "MCP tool rate limit exceeded",
		-32103: "MCP tool requires step-up approval",
	} {
		if Messages[code] != msg {
			t.Fatalf("code %d message = %q, want %q", code, Messages[code], msg)
		}
	}
	if CodeUpstreamUnavailable != -32020 || MessageUpstreamUnavailable != "MCP upstream is unavailable" {
		t.Fatal("the upstream-unavailable code or message changed")
	}
}

// AI-UX-1 additions are additive: a gateway or control plane that predates them sends and reads the same
// JSON as before, and the new fields appear only when set.
func TestMultiServerAndHoldFieldsAreOptionalOnTheWire(t *testing.T) {
	b, err := json.Marshal(DecideRequest{Method: "tools/call", ToolName: "refund_order", Server: "billing"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"method":"tools/call","tool_name":"refund_order","server":"billing"}` {
		t.Fatalf("request wire with a server = %s", b)
	}
	var old DecideRequest
	if err := json.Unmarshal([]byte(`{"method":"tools/list"}`), &old); err != nil || old.Server != "" {
		t.Fatalf("a request from a gateway that names no server must mean the first server (server=%q, err=%v)", old.Server, err)
	}
	held := DecideResponse{Decision: DecisionDeny, HoldSeconds: 45, Error: &Error{HTTPStatus: 403, Code: CodeStepUpRequired, Message: MessageStepUpRequired, Data: &ErrorData{RequestID: "22a21cf4-fc02-441a-aef0-0f6472b59ca0"}}}
	if b, err = json.Marshal(held); err != nil {
		t.Fatal(err)
	}
	const wantHeld = `{"decision":"deny","error":{"http_status":403,"code":-32103,"message":"MCP tool requires step-up approval","data":{"request_id":"22a21cf4-fc02-441a-aef0-0f6472b59ca0"}},"hold_seconds":45}`
	if string(b) != wantHeld {
		t.Fatalf("held deny wire = %s\nwant             %s", b, wantHeld)
	}
	if held.Valid() != nil {
		t.Fatal("a held step-up refusal is still a valid deny")
	}
	if b, err = json.Marshal(WaitRequest{RequestID: "22a21cf4-fc02-441a-aef0-0f6472b59ca0"}); err != nil || string(b) != `{"request_id":"22a21cf4-fc02-441a-aef0-0f6472b59ca0"}` {
		t.Fatalf("wait request wire = %s (err=%v)", b, err)
	}
	if b, err = json.Marshal(WaitResponse{State: WaitApproved}); err != nil || string(b) != `{"state":"approved"}` {
		t.Fatalf("wait response wire = %s (err=%v)", b, err)
	}
	if b, err = json.Marshal(Target{DeviceID: "d", VPNIP: "10.99.0.2", Endpoint: "http://x/mcp"}); err != nil || string(b) != `{"device_id":"d","vpn_ip":"10.99.0.2","endpoint":"http://x/mcp"}` {
		t.Fatalf("an agent target must not change on the wire: %s (err=%v)", b, err)
	}
	if b, err = json.Marshal(InventoryReport{DeviceID: "d", Endpoint: "http://x/mcp", Status: "healthy", Tools: []ObservedTool{}}); err != nil || string(b) != `{"device_id":"d","endpoint":"http://x/mcp","status":"healthy","tools":[]}` {
		t.Fatalf("an agent inventory report must not change on the wire: %s (err=%v)", b, err)
	}
}

// Only a step-up refusal that names its request can be held, never for longer than the bound.
func TestOnlyANamedStepUpRefusalIsHoldable(t *testing.T) {
	stepUp := func(seconds int, requestID string) DecideResponse {
		r := DecideResponse{Decision: DecisionDeny, HoldSeconds: seconds, Error: &Error{HTTPStatus: 403, Code: CodeStepUpRequired, Message: MessageStepUpRequired}}
		if requestID != "" {
			r.Error.Data = &ErrorData{RequestID: requestID}
		}
		return r
	}
	if s, ok := stepUp(45, "r").Holdable(); !ok || s != 45 {
		t.Fatalf("a step-up refusal with a request and a hold must be holdable for 45s, got %d %v", s, ok)
	}
	if s, ok := stepUp(600, "r").Holdable(); !ok || s != MaxHoldSeconds {
		t.Fatalf("a hold is capped at %ds, got %d %v", MaxHoldSeconds, s, ok)
	}
	for name, r := range map[string]DecideResponse{
		"no hold":              stepUp(0, "r"),
		"no request":           stepUp(45, ""),
		"a policy deny":        {Decision: DecisionDeny, HoldSeconds: 45, Error: &Error{HTTPStatus: 403, Code: CodeDenied, Message: MessageDenied, Data: &ErrorData{RequestID: "r"}}},
		"an allow":             {Decision: DecisionAllow, Upstream: "http://x/mcp", HoldSeconds: 45},
		"a deny with no error": {Decision: DecisionDeny, HoldSeconds: 45},
	} {
		if _, ok := r.Holdable(); ok {
			t.Fatalf("%s must not be held", name)
		}
	}
}

func TestServerNamesAndListenerPaths(t *testing.T) {
	for _, name := range []string{"acme", "acme-mcp-2", "0billing", strings.Repeat("a", 63)} {
		if !ValidServerName(name) {
			t.Fatalf("%q must be a valid server name", name)
		}
	}
	for _, name := range []string{"", "mcp", "-acme", "Acme", "acme_mcp", "acme/tools", "acme mcp", "..", strings.Repeat("a", 64)} {
		if ValidServerName(name) {
			t.Fatalf("%q must not be a valid server name", name)
		}
	}
	for path, want := range map[string]string{"/mcp": "", "/mcp/acme": "acme", "/mcp/acme-mcp-2": "acme-mcp-2"} {
		if got, ok := ServerFromPath(path); !ok || got != want {
			t.Fatalf("ServerFromPath(%q) = %q %v, want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{"", "/", "/mcp/", "/mcp/mcp", "/mcp/acme/extra", "/mcp/../x", "/mcpx", "/acme", "/mcp/Acme"} {
		if _, ok := ServerFromPath(path); ok {
			t.Fatalf("ServerFromPath(%q) must be refused", path)
		}
	}
}
