package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpdecision"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpfixture"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

func TestMCPGatewayRoutesRequireNodeCertificate(t *testing.T) {
	for method, routes := range map[string][]string{"POST": {mcpwire.PathDecide, mcpwire.PathResult, mcpwire.PathInventory}, "GET": {mcpwire.PathTargets}} {
		for _, route := range routes {
			a := &AgentChannel{}
			r := httptest.NewRequest(method, "https://control"+route, strings.NewReader(`{}`))
			for _, h := range []string{"Authorization", mcpwire.HeaderVPNIP, mcpwire.HeaderVPNKey, "X-Forwarded-For"} {
				r.Header.Set(h, "forged")
			}
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s %s without a certificate = %d", method, route, w.Code)
			}
		}
	}
}

type mcpChannelHarness struct {
	*mcpfixture.Fixture
	t        *testing.T
	handler  http.Handler
	policy   *mcptoolpolicy.Service
	approval *mcptoolapproval.Service
	decision *mcpdecision.Service
	pushed   int
}

func newMCPChannelHarness(t *testing.T) *mcpChannelHarness {
	t.Helper()
	f := mcpfixture.New(t)
	h := &mcpChannelHarness{Fixture: f, t: t, policy: mcptoolpolicy.New(f.Pool), approval: mcptoolapproval.New(f.Pool)}
	h.decision = mcpdecision.New(f.Pool, h.policy, h.approval, nil, nil, nil)
	f.Exec(`UPDATE nodes SET cert_serial=$2 WHERE id=$1`, f.Node, hex.EncodeToString(big.NewInt(0x6d6370).Bytes()))
	f.Exec(`UPDATE nodes SET cert_serial=$2 WHERE id=$1`, f.OtherNode, hex.EncodeToString(big.NewInt(0x6d6371).Bytes()))
	svc := nodes.NewService(f.Pool, nil, nil)
	svc.SetPushOrg(func(context.Context, uuid.UUID) { h.pushed++ })
	channel := NewAgentChannel(svc, nil, nil, nil)
	channel.SetMCPDecision(h.decision)
	h.handler = channel.Handler()
	return h
}

// do sends a request as the fixture gateway (or the other one), with the given evidence headers.
func (h *mcpChannelHarness) do(serial int64, method, path, body string, headers http.Header) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, "https://control"+path, strings.NewReader(body)).WithContext(h.Ctx)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(serial)}}}
	for name, values := range headers {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

func (h *mcpChannelHarness) evidence(ip, key string) http.Header {
	return http.Header{mcpwire.HeaderVPNIP: {ip}, mcpwire.HeaderVPNKey: {key}}
}

func (h *mcpChannelHarness) decide(headers http.Header, body string) (int, mcpwire.DecideResponse) {
	h.t.Helper()
	w := h.do(0x6d6370, "POST", mcpwire.PathDecide, body, headers)
	var out mcpwire.DecideResponse
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Valid() != nil {
			h.t.Fatalf("decide body is not a valid decision: %s", w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			h.t.Fatal("a decision is cacheable")
		}
	}
	return w.Code, out
}

func TestMCPGatewayChannelDecidesFromTunnelEvidenceOnly(t *testing.T) {
	h := newMCPChannelHarness(t)
	const initialize = `{"method":"initialize"}`
	agent := h.evidence(h.AgentIP, h.AgentKey)

	// Forged, missing or duplicated evidence headers are refused before anything is decided.
	for name, headers := range map[string]http.Header{
		"no evidence":           {},
		"address only":          {mcpwire.HeaderVPNIP: {h.AgentIP}},
		"key only":              {mcpwire.HeaderVPNKey: {h.AgentKey}},
		"duplicated address":    {mcpwire.HeaderVPNIP: {h.HumanIP, h.AgentIP}, mcpwire.HeaderVPNKey: {h.AgentKey}},
		"duplicated key":        {mcpwire.HeaderVPNIP: {h.AgentIP}, mcpwire.HeaderVPNKey: {h.AgentKey, h.AgentKey}},
		"lower-case duplicates": {"x-tunnex-vpn-ip": {h.AgentIP}, mcpwire.HeaderVPNIP: {h.AgentIP}, mcpwire.HeaderVPNKey: {h.AgentKey}},
		"empty values":          {mcpwire.HeaderVPNIP: {""}, mcpwire.HeaderVPNKey: {""}},
	} {
		if code, _ := h.decide(headers, initialize); code != 403 {
			t.Errorf("%s: status %d, want 403", name, code)
		}
	}
	// Evidence that does not name an active agent on this gateway is a denial, whatever else is sent.
	for name, headers := range map[string]http.Header{
		"human device":             h.evidence(h.HumanIP, h.HumanKey),
		"agent address, other key": h.evidence(h.AgentIP, h.HumanKey),
		"joined addresses":         h.evidence(h.HumanIP+", "+h.AgentIP, h.AgentKey),
		"device id header":         {mcpwire.HeaderVPNIP: {h.HumanIP}, mcpwire.HeaderVPNKey: {h.HumanKey}, "X-Tunnex-Device-Id": {h.Agent.String()}, "X-Forwarded-For": {h.AgentIP}},
	} {
		code, got := h.decide(headers, initialize)
		if code != 200 || got.Decision != mcpwire.DecisionDeny || got.Upstream != "" {
			t.Errorf("%s: %d %+v, want a denial", name, code, got)
		}
	}
	// The body cannot name a device or an organization either.
	if code, got := h.decide(h.evidence(h.HumanIP, h.HumanKey), `{"method":"initialize","device_id":"`+h.Agent.String()+`","org_id":"`+h.Org.String()+`"}`); code != 200 || got.Decision != mcpwire.DecisionDeny {
		t.Fatalf("identity from the body: %d %+v", code, got)
	}
	// The agent on another gateway's certificate is not this gateway's agent.
	if w := h.do(0x6d6371, "POST", mcpwire.PathDecide, initialize, agent); w.Code != 200 || !strings.Contains(w.Body.String(), `"deny"`) {
		t.Fatalf("other gateway: %d %s", w.Code, w.Body.String())
	}
	if code, got := h.decide(agent, initialize); code != 200 || got.Decision != mcpwire.DecisionAllow || got.Upstream != mcpfixture.Endpoint {
		t.Fatalf("agent initialize: %d %+v", code, got)
	}
	if code, _ := h.decide(agent, `{`); code != 400 {
		t.Fatalf("malformed body status %d", code)
	}
	if code, _ := h.decide(agent, `{"method":"tools/call","arguments":"`+strings.Repeat("a", mcpDecideBodyLimit)+`"}`); code != 400 {
		t.Fatalf("oversized body status %d", code)
	}

	// Targets, inventory, a decision and its result, end to end over the channel.
	w := h.do(0x6d6370, "GET", mcpwire.PathTargets, "", nil)
	var targets mcpwire.TargetsResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &targets) != nil || len(targets.Targets) != 1 || targets.Targets[0].DeviceID != h.Agent.String() || targets.Targets[0].Endpoint != mcpfixture.Endpoint {
		t.Fatalf("targets: %d %s", w.Code, w.Body.String())
	}
	if w := h.do(0x6d6371, "GET", mcpwire.PathTargets, "", nil); w.Code != 200 || strings.Contains(w.Body.String(), h.Agent.String()) {
		t.Fatalf("other gateway targets: %d %s", w.Code, w.Body.String())
	}
	const schema = `{"type":"object","properties":{"limit":{"type":"integer"}}}`
	// A hash the reporter supplies is ignored: the stored one is computed here.
	report := `{"device_id":"` + h.Agent.String() + `","endpoint":"` + mcpfixture.Endpoint + `","status":"healthy","server_name":"billing","tools":[{"name":"list_customers","description":"List","input_schema":` + schema + `,"tool_definition_hash":"` + strings.Repeat("0", 64) + `","input_schema_hash":"forged"}]}`
	if w := h.do(0x6d6371, "POST", mcpwire.PathInventory, report, nil); w.Code != 404 {
		t.Fatalf("inventory from another gateway: %d", w.Code)
	}
	if w := h.do(0x6d6370, "POST", mcpwire.PathInventory, report, nil); w.Code != 204 {
		t.Fatalf("inventory: %d %s", w.Code, w.Body.String())
	}
	want, _ := mcptoolpolicy.DefinitionHash("list_customers", "List", json.RawMessage(schema))
	schemaHash, _ := mcptoolpolicy.InputSchemaHash(json.RawMessage(schema))
	inventory, err := h.policy.LoadInventory(h.Ctx, h.Org, h.Agent)
	if err != nil || inventory.Source != mcptoolpolicy.SourceGateway || inventory.Servers[0].Tools[0].ToolDefinitionHash != want || inventory.Servers[0].Tools[0].InputSchemaHash != schemaHash {
		t.Fatalf("stored inventory = %+v, %v", inventory, err)
	}
	if _, err := h.policy.Replace(h.Ctx, h.Org, h.Agent, h.Owner, []mcptoolpolicy.Rule{{Endpoint: mcpfixture.Endpoint, ServerName: "billing", ToolName: "list_customers", InputSchemaHash: schemaHash}}); err != nil {
		t.Fatal(err)
	}
	code, allowed := h.decide(agent, `{"method":"tools/call","tool_name":"list_customers","arguments":{"limit":3}}`)
	if code != 200 || allowed.Decision != mcpwire.DecisionAllow || allowed.CallID == "" {
		t.Fatalf("tool call: %d %+v", code, allowed)
	}
	if _, denied := h.decide(agent, `{"method":"tools/call","tool_name":"list_customers","arguments":{"limit":"3"}}`); denied.Decision != mcpwire.DecisionDeny || denied.Error.Code != mcpwire.CodeArgumentsDenied || denied.Error.Message != mcpwire.MessageArgumentsDenied {
		t.Fatalf("schema denial: %+v", denied.Error)
	}
	result := `{"call_id":"` + allowed.CallID + `","status":"ok","upstream_http_status":200}`
	if w := h.do(0x6d6371, "POST", mcpwire.PathResult, result, nil); w.Code != 404 {
		t.Fatalf("result from another gateway: %d", w.Code)
	}
	if w := h.do(0x6d6370, "POST", mcpwire.PathResult, result, nil); w.Code != 204 {
		t.Fatalf("result: %d", w.Code)
	}
	if w := h.do(0x6d6370, "POST", mcpwire.PathResult, `{"call_id":"x","status":"ok"}`, nil); w.Code != 400 {
		t.Fatalf("malformed result: %d", w.Code)
	}

	// The public API reads the same records.
	server := apiServer{mcpToolPolicy: h.policy, mcpToolApproval: h.approval, mcpDecision: h.decision, system: sqlc.New(h.Pool), agentRuntime: agentruntime.New(h.Pool, nil)}
	owner := authctx.WithPrincipal(h.Ctx, &authctx.Principal{UserID: h.Owner, EmailVerified: true, Roles: map[uuid.UUID]string{h.Org: rbac.RoleOwner}})
	member := authctx.WithPrincipal(h.Ctx, &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{h.Org: rbac.RoleMember}})
	limit := 1
	page, err := server.ListAgentMCPToolActivity(owner, api.ListAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.ListAgentMCPToolActivityParams{Limit: &limit}})
	first, ok := page.(api.ListAgentMCPToolActivity200JSONResponse)
	if err != nil || !ok || len(first.Items) != 1 || first.NextCursor == nil || first.Items[0].Decision != api.MCPToolActivityDeny || first.Items[0].Reason != mcpwire.ReasonSchema {
		t.Fatalf("activity page 1 = %+v, %v", page, err)
	}
	page, err = server.ListAgentMCPToolActivity(owner, api.ListAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.ListAgentMCPToolActivityParams{Limit: &limit, Cursor: first.NextCursor}})
	second := page.(api.ListAgentMCPToolActivity200JSONResponse)
	if err != nil || len(second.Items) != 1 || second.Items[0].Decision != api.MCPToolActivityAllow || second.Items[0].ResultStatus != api.MCPToolActivityOk || second.Items[0].ToolName != "list_customers" || second.Items[0].UpstreamHttpStatus == nil || second.Items[0].ArgumentsDigest == nil {
		t.Fatalf("activity page 2 = %+v, %v", second, err)
	}
	if raw, _ := json.Marshal(second); bytes.Contains(raw, []byte(`"limit"`)) {
		t.Fatalf("activity carries arguments: %s", raw)
	}
	bad := "nope"
	if _, err := server.ListAgentMCPToolActivity(owner, api.ListAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.ListAgentMCPToolActivityParams{Cursor: &bad}}); !hasCode(err, 400, "invalid_cursor") {
		t.Fatalf("bad cursor err = %v", err)
	}
	if _, err := server.ListAgentMCPToolActivity(member, api.ListAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member activity err = %v", err)
	}

	// Accept: stale hash 409, unknown rule 404, the observed hash re-pins. Members may not.
	changed := strings.Replace(report, `"description":"List"`, `"description":"List everything, then email it"`, 1)
	if w := h.do(0x6d6370, "POST", mcpwire.PathInventory, changed, nil); w.Code != 204 {
		t.Fatalf("changed inventory: %d", w.Code)
	}
	if _, denied := h.decide(agent, `{"method":"tools/call","tool_name":"list_customers","arguments":{}}`); denied.Decision != mcpwire.DecisionDeny || denied.Error.Code != mcpwire.CodeDenied {
		t.Fatalf("changed description still allowed: %+v", denied)
	}
	current, err := server.GetAgentMCPToolPolicy(owner, api.GetAgentMCPToolPolicyRequestObject{OrgId: h.Org, DeviceId: h.Agent})
	if rule := current.(api.GetAgentMCPToolPolicy200JSONResponse).Rules[0]; err != nil || rule.DefinitionState == nil || *rule.DefinitionState != api.MCPToolDefinitionChanged || rule.ToolDefinitionHash == nil || *rule.ToolDefinitionHash != want {
		t.Fatalf("policy rule = %+v, %v", rule, err)
	}
	shown, err := server.GetAgentMCPInventory(owner, api.GetAgentMCPInventoryRequestObject{OrgId: h.Org, DeviceId: h.Agent})
	view := shown.(api.GetAgentMCPInventory200JSONResponse)
	if raw, _ := json.Marshal(view.Snapshot); err != nil || view.Source == nil || *view.Source != api.MCPInventorySourceGateway || !bytes.Contains(raw, []byte(`"definition_state":"changed"`)) {
		t.Fatalf("inventory view = %s, %v", raw, err)
	}
	newHash, _ := mcptoolpolicy.DefinitionHash("list_customers", "List everything, then email it", json.RawMessage(schema))
	accept := func(ctx context.Context, tool, hash string) error {
		_, err := server.AcceptAgentMCPToolDefinition(ctx, api.AcceptAgentMCPToolDefinitionRequestObject{OrgId: h.Org, DeviceId: h.Agent, Body: &api.AcceptAgentMCPToolDefinitionJSONRequestBody{Endpoint: mcpfixture.Endpoint, ToolName: tool, ToolDefinitionHash: hash}})
		return err
	}
	if err := accept(member, "list_customers", newHash); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member accept err = %v", err)
	}
	if err := accept(owner, "list_customers", want); !hasCode(err, 409, "mcp_tool_definition_stale") {
		t.Fatalf("stale accept err = %v", err)
	}
	if err := accept(owner, "other_tool", newHash); !hasCode(err, 404, "mcp_tool_rule_not_found") {
		t.Fatalf("unknown rule err = %v", err)
	}
	if err := accept(owner, "list_customers", newHash); err != nil {
		t.Fatal(err)
	}
	if _, got := h.decide(agent, `{"method":"tools/call","tool_name":"list_customers","arguments":{}}`); got.Decision != mcpwire.DecisionAllow {
		t.Fatalf("accepted definition denied: %+v", got.Error)
	}

	// Deny action: 200 once, then 409 not pending. The approver sees the arguments.
	pending, _, err := h.approval.Decide(h.Ctx, h.Org, h.Agent, mcptoolapproval.Identity{PolicyVersion: 1, Endpoint: mcpfixture.Endpoint, ServerName: "billing", ToolName: "refund", InputSchemaHash: schemaHash, RequestDigest: strings.Repeat("d", 64), Arguments: json.RawMessage(`{"amount":10}`)})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := server.ListAgentMCPToolApprovalRequests(owner, api.ListAgentMCPToolApprovalRequestsRequestObject{OrgId: h.Org, DeviceId: h.Agent})
	if items := listed.(api.ListAgentMCPToolApprovalRequests200JSONResponse); err != nil || len(items) != 1 || items[0].Arguments == nil || (*items[0].Arguments)["amount"] != float64(10) {
		t.Fatalf("listed approvals = %+v, %v", listed, err)
	}
	deny := api.DenyAgentMCPToolApprovalRequestRequestObject{OrgId: h.Org, DeviceId: h.Agent, RequestId: pending.ID}
	if _, err := server.DenyAgentMCPToolApprovalRequest(member, deny); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member deny err = %v", err)
	}
	denied, err := server.DenyAgentMCPToolApprovalRequest(owner, deny)
	if got, ok := denied.(api.DenyAgentMCPToolApprovalRequest200JSONResponse); err != nil || !ok || got.State != "denied" || got.DeniedByUserId == nil || *got.DeniedByUserId != h.Owner || got.DeniedAt == nil {
		t.Fatalf("deny = %+v, %v", denied, err)
	}
	if _, err := server.DenyAgentMCPToolApprovalRequest(owner, deny); !hasCode(err, 409, "mcp_tool_approval_not_pending") {
		t.Fatalf("deny twice err = %v", err)
	}
	if _, err := server.ApproveAgentMCPToolApprovalRequest(owner, api.ApproveAgentMCPToolApprovalRequestRequestObject{OrgId: h.Org, DeviceId: h.Agent, RequestId: pending.ID}); !hasCode(err, 409, "mcp_tool_approval_not_pending") {
		t.Fatalf("approve denied err = %v", err)
	}
}

func TestNodeReportStoresMCPGatewayCapabilityAndPushesOnChange(t *testing.T) {
	h := newMCPChannelHarness(t)
	const pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	steps := []struct {
		fields  string
		ready   bool
		address string
		pushes  int
	}{
		{`,"mcp_gateway_ready":true,"mcp_gateway_address":"10.123.0.1"`, true, "10.123.0.1", 1},
		{`,"mcp_gateway_ready":true,"mcp_gateway_address":"10.123.0.1"`, true, "10.123.0.1", 1}, // unchanged: no push
		{``, false, "", 2}, // an older gateway (or a stopped listener) clears it
		{`,"mcp_gateway_ready":true,"mcp_gateway_address":"http://10.123.0.1"`, false, "", 2},
		{`,"mcp_gateway_ready":true,"mcp_gateway_address":"8.8.8.8"`, false, "", 2},
		{`,"mcp_gateway_ready":false,"mcp_gateway_address":"10.123.0.1"`, false, "", 2},
	}
	for i, step := range steps {
		if w := h.do(0x6d6370, "POST", "/agent/report", `{"public_key":"`+pk+`"`+step.fields+`}`, nil); w.Code != 204 {
			t.Fatalf("step %d report: %d %s", i, w.Code, w.Body.String())
		}
		var raw []byte
		if err := h.Pool.QueryRow(h.Ctx, `SELECT capabilities FROM nodes WHERE id=$1`, h.Node).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		caps := nodes.Capabilities(raw)
		if caps.MCPGatewayReady != step.ready || caps.MCPGatewayAddress != step.address {
			t.Fatalf("step %d stored %s", i, raw)
		}
		if h.pushed != step.pushes {
			t.Fatalf("step %d policy pushes = %d, want %d", i, h.pushed, step.pushes)
		}
	}
	if h.Count(`SELECT count(*) FROM nodes WHERE id=$1 AND capabilities ? 'mcp_gateway_ready'`, h.OtherNode) != 0 {
		t.Fatal("another gateway's capabilities changed")
	}
}
