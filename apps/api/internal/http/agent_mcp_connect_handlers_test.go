package http

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpdecision"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpfixture"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpoauth"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

type mcpAdminHarness struct {
	*mcpfixture.Fixture
	s        apiServer
	owner    context.Context
	member   context.Context
	decision *mcpdecision.Service
}

func newMCPAdminHarness(t *testing.T) *mcpAdminHarness {
	t.Helper()
	f := mcpfixture.New(t)
	q := sqlc.New(f.Pool)
	sealer, err := crypto.NewSealer(make([]byte, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	policy, approval := mcptoolpolicy.New(f.Pool), mcptoolapproval.New(f.Pool)
	decision := mcpdecision.New(f.Pool, policy, approval, nil, nil, nil)
	runtime := agentruntime.New(f.Pool, func(context.Context, uuid.UUID) (agentruntime.OptInState, error) {
		return agentruntime.OptInEnabled, nil
	})
	f.Exec(`UPDATE users SET status='active' WHERE id=$1`, f.Owner)
	with := func(role string) context.Context {
		return authctx.WithPrincipal(f.Ctx, &authctx.Principal{UserID: f.Owner, EmailVerified: true, Roles: map[uuid.UUID]string{f.Org: role}})
	}
	return &mcpAdminHarness{Fixture: f, decision: decision, owner: with(rbac.RoleOwner), member: with(rbac.RoleMember),
		s: apiServer{system: q, agentRuntime: runtime, mcpToolPolicy: policy, mcpToolApproval: approval, mcpDecision: decision, mcpOAuth: mcpoauth.New(q, sealer, nil, "https://control.example"), agentTemplates: NewAgentTemplatePort(f.Pool, nil)}}
}

// adminCalls is every administrator operation that needs MCP to be on.
func (h *mcpAdminHarness) adminCalls() map[string]func(context.Context) error {
	org, agent, group, profile := h.Org, h.Agent, h.Group, h.Profile
	endpoint := mcpfixture.Endpoint
	return map[string]func(context.Context) error{
		"StartMCPConnectionPreview": func(ctx context.Context) error {
			_, err := h.s.StartMCPConnectionPreview(ctx, api.StartMCPConnectionPreviewRequestObject{OrgId: org, Body: &api.StartMCPConnectionPreviewRequest{Endpoint: endpoint, ViaDeviceId: &agent}})
			return err
		},
		"GetMCPConnectionPreview": func(ctx context.Context) error {
			_, err := h.s.GetMCPConnectionPreview(ctx, api.GetMCPConnectionPreviewRequestObject{OrgId: org, PreviewId: uuid.New()})
			return err
		},
		"ConnectMCPServer": func(ctx context.Context) error {
			_, err := h.s.ConnectMCPServer(ctx, api.ConnectMCPServerRequestObject{OrgId: org, Body: &api.ConnectMCPServerRequest{Target: api.MCPConnectionTarget{DeviceId: &agent}, Name: "Gate", Endpoint: "http://10.123.0.70:9000/mcp", Tools: []api.MCPToolSettingInput{}}})
			return err
		},
		"GetAgentGroupMCPToolPolicy": func(ctx context.Context) error {
			_, err := h.s.GetAgentGroupMCPToolPolicy(ctx, api.GetAgentGroupMCPToolPolicyRequestObject{OrgId: org, GroupId: group, ProfileId: profile})
			return err
		},
		"ReplaceAgentGroupMCPToolPolicy": func(ctx context.Context) error {
			_, err := h.s.ReplaceAgentGroupMCPToolPolicy(ctx, api.ReplaceAgentGroupMCPToolPolicyRequestObject{OrgId: org, GroupId: group, ProfileId: profile, Body: &api.ReplaceAgentGroupMCPToolPolicyRequest{Tools: []api.MCPToolSettingInput{}}})
			return err
		},
		"RemoveAgentMCPToolPolicyOverride": func(ctx context.Context) error {
			_, err := h.s.RemoveAgentMCPToolPolicyOverride(ctx, api.RemoveAgentMCPToolPolicyOverrideRequestObject{OrgId: org, DeviceId: agent, Params: api.RemoveAgentMCPToolPolicyOverrideParams{Endpoint: endpoint}})
			return err
		},
		"ListOrganizationMCPToolApprovalRequests": func(ctx context.Context) error {
			_, err := h.s.ListOrganizationMCPToolApprovalRequests(ctx, api.ListOrganizationMCPToolApprovalRequestsRequestObject{OrgId: org})
			return err
		},
		"ExportAgentMCPToolActivity": func(ctx context.Context) error {
			_, err := h.s.ExportAgentMCPToolActivity(ctx, api.ExportAgentMCPToolActivityRequestObject{OrgId: org, DeviceId: agent})
			return err
		},
		"GetAgentMCPToolPolicy": func(ctx context.Context) error {
			_, err := h.s.GetAgentMCPToolPolicy(ctx, api.GetAgentMCPToolPolicyRequestObject{OrgId: org, DeviceId: agent})
			return err
		},
		"ReplaceAgentMCPToolPolicy": func(ctx context.Context) error {
			_, err := h.s.ReplaceAgentMCPToolPolicy(ctx, api.ReplaceAgentMCPToolPolicyRequestObject{OrgId: org, DeviceId: agent, Body: &api.ReplaceAgentMCPToolPolicyJSONRequestBody{}})
			return err
		},
		"ListAgentMCPToolApprovalRequests": func(ctx context.Context) error {
			_, err := h.s.ListAgentMCPToolApprovalRequests(ctx, api.ListAgentMCPToolApprovalRequestsRequestObject{OrgId: org, DeviceId: agent})
			return err
		},
		"ApproveAgentMCPToolApprovalRequest": func(ctx context.Context) error {
			_, err := h.s.ApproveAgentMCPToolApprovalRequest(ctx, api.ApproveAgentMCPToolApprovalRequestRequestObject{OrgId: org, DeviceId: agent, RequestId: uuid.New()})
			return err
		},
		"DenyAgentMCPToolApprovalRequest": func(ctx context.Context) error {
			_, err := h.s.DenyAgentMCPToolApprovalRequest(ctx, api.DenyAgentMCPToolApprovalRequestRequestObject{OrgId: org, DeviceId: agent, RequestId: uuid.New()})
			return err
		},
		"AcceptAgentMCPToolDefinition": func(ctx context.Context) error {
			_, err := h.s.AcceptAgentMCPToolDefinition(ctx, api.AcceptAgentMCPToolDefinitionRequestObject{OrgId: org, DeviceId: agent, Body: &api.AcceptAgentMCPToolDefinitionJSONRequestBody{Endpoint: endpoint, ToolName: "refund", ToolDefinitionHash: strings.Repeat("a", 64)}})
			return err
		},
		"ListAgentMCPToolActivity": func(ctx context.Context) error {
			_, err := h.s.ListAgentMCPToolActivity(ctx, api.ListAgentMCPToolActivityRequestObject{OrgId: org, DeviceId: agent})
			return err
		},
		"ListAgentMCPOAuthConnections": func(ctx context.Context) error {
			_, err := h.s.ListAgentMCPOAuthConnections(ctx, api.ListAgentMCPOAuthConnectionsRequestObject{OrgId: org, DeviceId: agent})
			return err
		},
		"StartAgentMCPOAuthConnection": func(ctx context.Context) error {
			_, err := h.s.StartAgentMCPOAuthConnection(ctx, api.StartAgentMCPOAuthConnectionRequestObject{OrgId: org, DeviceId: agent, Body: &api.StartAgentMCPOAuthConnectionJSONRequestBody{}})
			return err
		},
		"DisconnectAgentMCPOAuthConnection": func(ctx context.Context) error {
			_, err := h.s.DisconnectAgentMCPOAuthConnection(ctx, api.DisconnectAgentMCPOAuthConnectionRequestObject{OrgId: org, DeviceId: agent, ConnectionId: uuid.New()})
			return err
		},
		"GetAgentMCPInventory": func(ctx context.Context) error {
			_, err := h.s.GetAgentMCPInventory(ctx, api.GetAgentMCPInventoryRequestObject{OrgId: org, DeviceId: agent})
			return err
		},
	}
}

func TestMCPSwitchOffRefusesAdminHandlersAndTheCountIsZero(t *testing.T) {
	h := newMCPAdminHarness(t)
	// A request is waiting while MCP is still on.
	if _, _, err := h.s.mcpToolApproval.Decide(h.Ctx, h.Org, h.Agent, mcptoolapproval.Identity{PolicyVersion: 1, Endpoint: mcpfixture.Endpoint, ServerName: "billing", ToolName: "refund", InputSchemaHash: "x", RequestDigest: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		got, err := h.s.CountOrganizationMCPToolApprovalRequests(h.owner, api.CountOrganizationMCPToolApprovalRequestsRequestObject{OrgId: h.Org})
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		return got.(api.CountOrganizationMCPToolApprovalRequests200JSONResponse).Body.Pending
	}
	if n := count(); n != 1 {
		t.Fatalf("pending with MCP on = %d, want 1", n)
	}
	// With MCP on, none of them answers opt_in_required (they answer whatever the operation itself says).
	for name, call := range h.adminCalls() {
		if err := call(h.owner); hasCode(err, 403, "opt_in_required") {
			t.Errorf("%s: refused with MCP on", name)
		}
	}

	before := h.Count(`SELECT count(*) FROM audit_logs WHERE org_id=$1`, h.Org)
	for state, off := range map[string]string{
		"switched off":   `UPDATE organization_mcp_settings SET enabled=false WHERE org_id=$1`,
		"never switched": `DELETE FROM organization_mcp_settings WHERE org_id=$1`,
	} {
		h.Exec(off, h.Org)
		for name, call := range h.adminCalls() {
			if err := call(h.owner); !hasCode(err, 403, "opt_in_required") {
				t.Errorf("%s (%s): err = %v, want 403 opt_in_required", name, state, err)
			}
			// Permission still comes first: someone who may not do it learns nothing about the switch.
			if err := call(h.member); hasCode(err, 403, "opt_in_required") {
				t.Errorf("%s (%s): a member was told about the switch", name, state)
			}
		}
		// The sidebar count is not an error: nothing is waiting.
		if n := count(); n != 0 {
			t.Fatalf("pending with MCP %s = %d, want 0", state, n)
		}
		// The read model that says "no MCP server" stays readable.
		if _, err := h.s.GetAgentEffectiveMCPProfile(h.owner, api.GetAgentEffectiveMCPProfileRequestObject{OrgId: h.Org, DeviceId: h.Agent}); err != nil {
			t.Fatalf("effective profile with MCP %s: %v", state, err)
		}
	}
	if after := h.Count(`SELECT count(*) FROM audit_logs WHERE org_id=$1`, h.Org); after != before {
		t.Fatalf("a refused operation wrote %d audit rows", after-before)
	}
	// The older assign path is refused inside its transaction too.
	if _, err := h.s.agentTemplates.SetGroupMCPProfile(h.Ctx, h.Org, h.Group, h.Profile, h.Owner); err == nil {
		t.Fatal("a profile was assigned with MCP off")
	}
}

func TestConnectMCPServerThroughTheHandlers(t *testing.T) {
	h := newMCPAdminHarness(t)
	h.Exec(`UPDATE nodes SET capabilities='{"mcp_gateway_ready":true,"mcp_gateway_address":"10.123.0.1"}'::jsonb, policy_reported_at=now() WHERE org_id=$1`, h.Org)
	const endpoint = "http://10.123.0.80:9000/mcp"

	// Member: no. Owner: a waiting preview, which the gateway finds among its targets and answers.
	body := &api.StartMCPConnectionPreviewRequest{Endpoint: endpoint, ViaDeviceId: &h.Agent}
	if _, err := h.s.StartMCPConnectionPreview(h.member, api.StartMCPConnectionPreviewRequestObject{OrgId: h.Org, Body: body}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member preview: %v", err)
	}
	if _, err := h.s.StartMCPConnectionPreview(h.owner, api.StartMCPConnectionPreviewRequestObject{OrgId: h.Org, Body: &api.StartMCPConnectionPreviewRequest{Endpoint: endpoint}}); !hasCode(err, 400, "invalid_mcp_connection_preview") {
		t.Fatalf("preview with no target: %v", err)
	}
	started, err := h.s.StartMCPConnectionPreview(h.owner, api.StartMCPConnectionPreviewRequestObject{OrgId: h.Org, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	preview := started.(api.StartMCPConnectionPreview201JSONResponse).Body
	if preview.State != api.MCPConnectionPreviewWaiting || len(preview.Tools) != 0 {
		t.Fatalf("started preview = %+v", preview)
	}
	targets, err := h.decision.Targets(h.Ctx, h.Org, h.Node)
	if err != nil {
		t.Fatal(err)
	}
	var asked *mcpwire.Target
	for i := range targets {
		if targets[i].PreviewID == preview.PreviewId.String() {
			asked = &targets[i]
		}
	}
	if asked == nil || asked.DeviceID != "" || asked.VPNIP != "" || asked.Authorization != "" || asked.Endpoint != endpoint {
		t.Fatalf("preview target = %+v in %+v", asked, targets)
	}
	if other, _ := h.decision.Targets(h.Ctx, h.Org, h.OtherNode); len(other) != 0 {
		t.Fatalf("another gateway was asked to read the preview: %+v", other)
	}
	report := mcpwire.InventoryReport{PreviewID: asked.PreviewID, Endpoint: endpoint, Status: "healthy", ServerName: "Ledger", Tools: []mcpwire.ObservedTool{
		{Name: "=read", Description: "Read the ledger", InputSchema: json.RawMessage(`{"type":"object","properties":{}}`)},
		{Name: "post", Description: "Post an entry", InputSchema: json.RawMessage(`{"type":"object","properties":{"amount":{"type":"number"}}}`)},
	}}
	if err := h.decision.Inventory(h.Ctx, h.Org, h.OtherNode, report); err == nil {
		t.Fatal("a gateway that was not asked completed the preview")
	}
	if err := h.decision.Inventory(h.Ctx, h.Org, h.Node, report); err != nil {
		t.Fatal(err)
	}
	if targets, _ := h.decision.Targets(h.Ctx, h.Org, h.Node); len(targets) != 1 {
		t.Fatalf("an answered preview is still a target: %+v", targets)
	}
	read, err := h.s.GetMCPConnectionPreview(h.owner, api.GetMCPConnectionPreviewRequestObject{OrgId: h.Org, PreviewId: preview.PreviewId})
	if err != nil {
		t.Fatal(err)
	}
	ready := read.(api.GetMCPConnectionPreview200JSONResponse).Body
	if ready.State != api.MCPConnectionPreviewReady || len(ready.Tools) != 2 || ready.ServerName == nil || *ready.ServerName != "Ledger" || ready.SuggestedServerName == nil || *ready.SuggestedServerName != "ledger" || ready.Tools[1].InputSchema == nil {
		t.Fatalf("ready preview = %+v", ready)
	}
	if _, err := h.s.GetMCPConnectionPreview(h.owner, api.GetMCPConnectionPreviewRequestObject{OrgId: h.Org, PreviewId: uuid.New()}); !hasCode(err, 404, "mcp_connection_preview_not_found") {
		t.Fatalf("unknown preview: %v", err)
	}
	hash := map[string]string{}
	for _, tool := range ready.Tools {
		hash[tool.Name] = tool.ToolDefinitionHash
	}

	// Connect: refused whole when a tool changed since it was shown, then everything in one step.
	ask, off, reads, changes := api.MCPToolModeAsk, api.MCPToolModeOff, api.MCPToolEffectReads, api.MCPToolEffectChanges
	stale := strings.Repeat("0", 64)
	readHash, postHash := hash["=read"], hash["post"]
	request := func(postPin *string) *api.ConnectMCPServerRequest {
		return &api.ConnectMCPServerRequest{Target: api.MCPConnectionTarget{DeviceId: &h.Agent}, Name: "Ledger", Endpoint: endpoint, PreviewId: &preview.PreviewId, Tools: []api.MCPToolSettingInput{
			{ToolName: "=read", Mode: api.MCPToolModeAllow, Effect: &reads, ToolDefinitionHash: &readHash},
			{ToolName: "post", Mode: ask, Effect: &changes, ToolDefinitionHash: postPin},
			{ToolName: "unused", Mode: off},
		}}
	}
	if _, err := h.s.ConnectMCPServer(h.owner, api.ConnectMCPServerRequestObject{OrgId: h.Org, Body: request(&stale)}); !hasCode(err, 409, "mcp_tool_definition_stale") {
		t.Fatalf("stale connect: %v", err)
	}
	if n := h.Count(`SELECT count(*) FROM agent_mcp_profiles WHERE org_id=$1`, h.Org); n != 1 {
		t.Fatal("a refused connection left a profile behind")
	}
	taken := "billing"
	clash := request(&postHash)
	clash.ServerName = &taken
	if _, err := h.s.ConnectMCPServer(h.owner, api.ConnectMCPServerRequestObject{OrgId: h.Org, Body: clash}); !hasCode(err, 409, "mcp_server_name_taken") {
		t.Fatalf("server name in use: %v", err)
	}
	if _, err := h.s.ConnectMCPServer(h.member, api.ConnectMCPServerRequestObject{OrgId: h.Org, Body: request(&postHash)}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member connect: %v", err)
	}
	done, err := h.s.ConnectMCPServer(h.owner, api.ConnectMCPServerRequestObject{OrgId: h.Org, Body: request(&postHash)})
	if err != nil {
		t.Fatal(err)
	}
	connection := done.(api.ConnectMCPServer201JSONResponse).Body
	if !connection.GroupCreated || connection.Group.Name != "agent" || connection.Group.MemberCount != 1 || connection.Profile.ServerName == nil || *connection.Profile.ServerName != "ledger" ||
		connection.Assignment.State != "active" || connection.ToolPolicy.Version != 1 || len(connection.ToolPolicy.Tools) != 2 {
		t.Fatalf("connection = %+v", connection)
	}

	// The agent now has two servers; the first is still the one it had.
	effective, err := h.s.GetAgentEffectiveMCPProfile(h.owner, api.GetAgentEffectiveMCPProfileRequestObject{OrgId: h.Org, DeviceId: h.Agent})
	if err != nil {
		t.Fatal(err)
	}
	profile := effective.(api.GetAgentEffectiveMCPProfile200JSONResponse)
	if !profile.Assigned || *profile.Endpoint != mcpfixture.Endpoint || profile.Servers == nil || len(*profile.Servers) != 2 {
		t.Fatalf("effective profile = %+v", profile)
	}
	first, second := (*profile.Servers)[0], (*profile.Servers)[1]
	if !first.Default || first.ServerName != "billing" || first.LocalUrl != "http://127.0.0.1:17100/billing" || second.Default || second.ServerName != "ledger" || second.LocalUrl != "http://127.0.0.1:17100/ledger" ||
		second.PolicySource != api.MCPToolPolicySourceGroup || second.GroupId != connection.Group.Id {
		t.Fatalf("servers = %+v", *profile.Servers)
	}

	// The gateway observes the new server for the agent; a call to the Ask first tool waits in the inbox.
	if err := h.decision.Inventory(h.Ctx, h.Org, h.Node, mcpwire.InventoryReport{DeviceID: h.Agent.String(), Endpoint: endpoint, Status: "healthy", ServerName: "Ledger", Tools: report.Tools}); err != nil {
		t.Fatal(err)
	}
	evidence := mcpdecision.Evidence{OrgID: h.Org, NodeID: h.Node, VPNIP: h.AgentIP, VPNKey: h.AgentKey}
	held := h.decision.Decide(h.Ctx, evidence, mcpwire.DecideRequest{Method: "tools/call", Server: "ledger", ToolName: "post", Arguments: json.RawMessage(`{"amount":12}`)})
	if held.Error == nil || held.Error.Code != mcpwire.CodeStepUpRequired {
		t.Fatalf("ask-first call = %+v", held)
	}
	if got := h.decision.Decide(h.Ctx, evidence, mcpwire.DecideRequest{Method: "tools/call", Server: "ledger", ToolName: "=read"}); got.Decision != mcpwire.DecisionAllow || got.Upstream != endpoint {
		t.Fatalf("allowed call = %+v %+v", got, got.Error)
	}
	listed, err := h.s.ListOrganizationMCPToolApprovalRequests(h.owner, api.ListOrganizationMCPToolApprovalRequestsRequestObject{OrgId: h.Org})
	if err != nil {
		t.Fatal(err)
	}
	inbox := listed.(api.ListOrganizationMCPToolApprovalRequests200JSONResponse).Body
	if len(inbox.Items) != 1 || inbox.NextCursor != nil {
		t.Fatalf("inbox = %+v", inbox)
	}
	item := inbox.Items[0]
	if item.AgentName != "agent" || item.OwnerEmail == nil || item.McpServerName == nil || *item.McpServerName != "ledger" || item.Request.DeviceId != h.Agent || item.Request.ToolName != "post" ||
		item.Request.PolicySource == nil || *item.Request.PolicySource != api.MCPToolPolicySourceGroup || item.Request.PolicyGroupId == nil || *item.Request.PolicyGroupId != connection.Group.Id ||
		item.Request.Arguments == nil || (*item.Request.Arguments)["amount"] == nil || !item.Request.ExpiresAt.After(time.Now()) {
		t.Fatalf("inbox item = %+v", item)
	}
	if _, err := h.s.ListOrganizationMCPToolApprovalRequests(h.member, api.ListOrganizationMCPToolApprovalRequestsRequestObject{OrgId: h.Org}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member inbox: %v", err)
	}
	// Approve and deny stay the per-agent operations, with the device of the request.
	if _, err := h.s.ApproveAgentMCPToolApprovalRequest(h.owner, api.ApproveAgentMCPToolApprovalRequestRequestObject{OrgId: h.Org, DeviceId: item.Request.DeviceId, RequestId: item.Request.Id}); err != nil {
		t.Fatal(err)
	}
	if got := h.decision.Decide(h.Ctx, evidence, mcpwire.DecideRequest{Method: "tools/call", Server: "ledger", ToolName: "post", Arguments: json.RawMessage(`{"amount":12}`)}); got.Decision != mcpwire.DecisionAllow {
		t.Fatalf("approved call = %+v", got.Error)
	}

	// Group policy: read, save, and the per-agent override that takes one server away from it.
	got, err := h.s.GetAgentGroupMCPToolPolicy(h.owner, api.GetAgentGroupMCPToolPolicyRequestObject{OrgId: h.Org, GroupId: connection.Group.Id, ProfileId: connection.Profile.Id})
	if err != nil {
		t.Fatal(err)
	}
	shown := got.(api.GetAgentGroupMCPToolPolicy200JSONResponse).Body
	modes := map[string]api.MCPToolSetting{}
	for _, tool := range shown.Tools {
		modes[tool.ToolName] = tool
	}
	if shown.Version != 1 || modes["=read"].Mode != api.MCPToolModeAllow || modes["post"].Mode != ask || modes["post"].Effect == nil || *modes["post"].Effect != changes || !modes["post"].Observed ||
		modes["post"].DefinitionState == nil || *modes["post"].DefinitionState != api.MCPToolSettingDefinitionCurrent || *shown.OverridingAgentCount != 0 {
		t.Fatalf("group policy = %+v", shown)
	}
	if _, err := h.s.GetAgentGroupMCPToolPolicy(h.owner, api.GetAgentGroupMCPToolPolicyRequestObject{OrgId: h.Org, GroupId: h.Group, ProfileId: connection.Profile.Id}); !hasCode(err, 404, "mcp_server_not_found") {
		t.Fatalf("a server of another group: %v", err)
	}
	saved, err := h.s.ReplaceAgentGroupMCPToolPolicy(h.owner, api.ReplaceAgentGroupMCPToolPolicyRequestObject{OrgId: h.Org, GroupId: connection.Group.Id, ProfileId: connection.Profile.Id, Body: &api.ReplaceAgentGroupMCPToolPolicyRequest{Tools: []api.MCPToolSettingInput{{ToolName: "post", Mode: off}}}})
	if err != nil || saved.(api.ReplaceAgentGroupMCPToolPolicy200JSONResponse).Body.Version != 2 {
		t.Fatalf("save group policy: %+v, %v", saved, err)
	}
	if got := h.decision.Decide(h.Ctx, evidence, mcpwire.DecideRequest{Method: "tools/call", Server: "ledger", ToolName: "=read"}); got.Decision != mcpwire.DecisionDeny {
		t.Fatal("a tool left out of the saved policy is still allowed")
	}
	if _, err := h.s.ReplaceAgentGroupMCPToolPolicy(h.owner, api.ReplaceAgentGroupMCPToolPolicyRequestObject{OrgId: h.Org, GroupId: connection.Group.Id, ProfileId: connection.Profile.Id, Body: &api.ReplaceAgentGroupMCPToolPolicyRequest{Tools: []api.MCPToolSettingInput{{ToolName: "ghost", Mode: ask}}}}); !hasCode(err, 400, "unobserved_mcp_tool") {
		t.Fatalf("allowing a tool the server does not offer: %v", err)
	}
	if _, err := h.s.RemoveAgentMCPToolPolicyOverride(h.owner, api.RemoveAgentMCPToolPolicyOverrideRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.RemoveAgentMCPToolPolicyOverrideParams{Endpoint: endpoint}}); !hasCode(err, 404, "mcp_tool_policy_override_not_found") {
		t.Fatalf("removing an override that is not there: %v", err)
	}
	if _, err := h.s.ReplaceAgentMCPToolPolicy(h.owner, api.ReplaceAgentMCPToolPolicyRequestObject{OrgId: h.Org, DeviceId: h.Agent, Body: &api.ReplaceAgentMCPToolPolicyJSONRequestBody{Rules: []api.MCPToolPolicyRule{{Endpoint: endpoint, ServerName: "Ledger", ToolName: "=read", InputSchemaHash: *modes["=read"].InputSchemaHash}}}}); err != nil {
		t.Fatal(err)
	}
	own, err := h.s.GetAgentMCPToolPolicy(h.owner, api.GetAgentMCPToolPolicyRequestObject{OrgId: h.Org, DeviceId: h.Agent})
	if err != nil || own.(api.GetAgentMCPToolPolicy200JSONResponse).OverrideEndpoints == nil || len(*own.(api.GetAgentMCPToolPolicy200JSONResponse).OverrideEndpoints) != 1 {
		t.Fatalf("agent policy = %+v, %v", own, err)
	}
	removed, err := h.s.RemoveAgentMCPToolPolicyOverride(h.owner, api.RemoveAgentMCPToolPolicyOverrideRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.RemoveAgentMCPToolPolicyOverrideParams{Endpoint: endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	if after := removed.(api.RemoveAgentMCPToolPolicyOverride200JSONResponse).Body; len(after.Rules) != 0 || len(*after.OverrideEndpoints) != 0 || after.Version != 2 {
		t.Fatalf("after removing the override = %+v", after)
	}

	// Activity: filters on the list, the approver on the row, and the CSV.
	server := "ledger"
	approvedOnly := true
	page, err := h.s.ListAgentMCPToolActivity(h.owner, api.ListAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.ListAgentMCPToolActivityParams{Server: &server, Approved: &approvedOnly}})
	if err != nil {
		t.Fatal(err)
	}
	rows := page.(api.ListAgentMCPToolActivity200JSONResponse).Items
	if len(rows) != 1 || rows[0].ToolName != "post" || rows[0].ApprovedByUserId == nil || *rows[0].ApprovedByUserId != h.Owner || rows[0].ApprovedByEmail == nil || rows[0].ApprovedAt == nil ||
		rows[0].PolicySource == nil || *rows[0].PolicySource != api.MCPToolPolicySourceGroup {
		t.Fatalf("approved activity = %+v", rows)
	}
	bad := "Not A Name"
	if _, err := h.s.ListAgentMCPToolActivity(h.owner, api.ListAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.ListAgentMCPToolActivityParams{Server: &bad}}); !hasCode(err, 400, "invalid_request") {
		t.Fatalf("malformed server filter: %v", err)
	}
	exported, err := h.s.ExportAgentMCPToolActivity(h.owner, api.ExportAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent, Params: api.ExportAgentMCPToolActivityParams{Server: &server}})
	if err != nil {
		t.Fatal(err)
	}
	file := exported.(api.ExportAgentMCPToolActivity200TextcsvResponse)
	raw, _ := io.ReadAll(file.Body)
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil || len(records) != 5 || records[0][0] != "time" || len(records[0]) != len(mcpActivityCSVHeader) || file.ContentLength != int64(len(raw)) || !strings.Contains(file.Headers.ContentDisposition, "mcp-activity.csv") {
		t.Fatalf("csv = %d records, %v\n%s", len(records), err, raw)
	}
	text := string(raw)
	if strings.Contains(text, `"amount"`) || strings.Contains(text, ",=read,") || !strings.Contains(text, ",'=read,") || !strings.Contains(text, "@example.com") {
		t.Fatalf("csv content:\n%s", text)
	}
	if n := h.Count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='agent.mcp_tool_activity.exported' AND actor_user_id=$2`, h.Org, h.Owner); n != 1 {
		t.Fatal("the export was not recorded")
	}
	if _, err := h.s.ExportAgentMCPToolActivity(h.member, api.ExportAgentMCPToolActivityRequestObject{OrgId: h.Org, DeviceId: h.Agent}); err == nil {
		t.Fatal("a member exported an agent's activity")
	}
}
