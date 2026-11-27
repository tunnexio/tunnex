package mcpwire

import (
	"encoding/json"
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
