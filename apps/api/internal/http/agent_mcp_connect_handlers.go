package http

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpdecision"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// AI-UX-1: connecting an MCP server in one step, tool policy on an agent group, the organization's
// approvals inbox and the activity export.

// requireMCPOn gates every operation in this file: MCP must be on for the organization (its own switch;
// no row means off). It is one small function so it can be replaced by the shared gate.
func (s apiServer) requireMCPOn(ctx context.Context, orgID uuid.UUID) error {
	if s.system == nil {
		return mcpConnectionUnavailable()
	}
	setting, err := s.system.GetOrganizationMCPSetting(ctx, orgID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return mcpConnectionUnavailable()
	}
	if err != nil || !setting.Enabled {
		return apierr.Forbidden("opt_in_required", "Turn on MCP for this organization first.")
	}
	return nil
}

func mcpConnectionUnavailable() error {
	return apierr.New(http.StatusServiceUnavailable, "mcp_connection_unavailable", "Connecting MCP servers is temporarily unavailable")
}

func (s apiServer) StartMCPConnectionPreview(ctx context.Context, req api.StartMCPConnectionPreviewRequestObject) (api.StartMCPConnectionPreviewResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_mcp_connection_preview", "An MCP server address and one agent or agent group are required")
	}
	preview, err := s.mcpToolPolicy.StartPreview(ctx, req.OrgId, actorID(ctx), req.Body.Endpoint, req.Body.ViaDeviceId, req.Body.ViaGroupId)
	switch {
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return nil, apierr.BadRequest("invalid_mcp_connection_preview", "Enter an http or https address with no sign-in details in it, and choose one agent or one agent group")
	case errors.Is(err, mcptoolpolicy.ErrNotFound):
		return nil, apierr.NotFound("mcp_connection_target_not_found", "That agent or agent group was not found")
	case errors.Is(err, mcptoolpolicy.ErrTooManyPreviews):
		return nil, apierr.New(http.StatusTooManyRequests, "mcp_connection_preview_busy", "Too many tool lists are being read right now. Try again in a minute.")
	case err != nil:
		return nil, mcpConnectionUnavailable()
	}
	return api.StartMCPConnectionPreview201JSONResponse{Body: toAPIMCPConnectionPreview(preview), Headers: api.StartMCPConnectionPreview201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetMCPConnectionPreview(ctx context.Context, req api.GetMCPConnectionPreviewRequestObject) (api.GetMCPConnectionPreviewResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	preview, err := s.mcpToolPolicy.GetPreview(ctx, req.OrgId, req.PreviewId)
	switch {
	case errors.Is(err, mcptoolpolicy.ErrNotFound), errors.Is(err, mcptoolpolicy.ErrInvalid):
		return nil, apierr.NotFound("mcp_connection_preview_not_found", "This tool list is no longer available. Read it again.")
	case err != nil:
		return nil, mcpConnectionUnavailable()
	}
	return api.GetMCPConnectionPreview200JSONResponse{Body: toAPIMCPConnectionPreview(preview), Headers: api.GetMCPConnectionPreview200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func toAPIMCPConnectionPreview(p mcptoolpolicy.Preview) api.MCPConnectionPreview {
	out := api.MCPConnectionPreview{PreviewId: p.ID, State: api.MCPConnectionPreviewState(p.State), Endpoint: p.Endpoint, ExpiresAt: p.ExpiresAt, Tools: make([]api.MCPConnectionPreviewTool, 0, len(p.Tools))}
	if p.FailureReason != "" {
		reason := p.FailureReason
		out.FailureReason = &reason
	}
	if p.State != mcptoolpolicy.PreviewReady {
		return out
	}
	if p.ServerName != "" {
		name := p.ServerName
		out.ServerName = &name
	}
	if p.SuggestedServerName != "" {
		name := p.SuggestedServerName
		out.SuggestedServerName = &name
	}
	for _, tool := range p.Tools {
		item := api.MCPConnectionPreviewTool{Name: tool.Name, ToolDefinitionHash: tool.ToolDefinitionHash}
		if tool.Description != "" {
			description := tool.Description
			item.Description = &description
		}
		if tool.InputSchemaHash != "" {
			hash := tool.InputSchemaHash
			item.InputSchemaHash = &hash
		}
		var schema map[string]interface{}
		if json.Unmarshal(tool.InputSchema, &schema) == nil && schema != nil {
			item.InputSchema = &schema
		}
		out.Tools = append(out.Tools, item)
	}
	return out
}

func mcpToolSettings(in []api.MCPToolSettingInput) []mcptoolpolicy.ToolSetting {
	out := make([]mcptoolpolicy.ToolSetting, 0, len(in))
	for _, tool := range in {
		setting := mcptoolpolicy.ToolSetting{ToolName: tool.ToolName, Mode: string(tool.Mode), RateLimitPerMinute: tool.RateLimitPerMinute}
		if tool.Effect != nil {
			setting.Effect = string(*tool.Effect)
		}
		if tool.ToolDefinitionHash != nil {
			setting.ToolDefinitionHash = *tool.ToolDefinitionHash
		}
		if tool.ArgumentConstraints != nil {
			setting.ArgumentConstraints, _ = json.Marshal(tool.ArgumentConstraints)
		}
		out = append(out, setting)
	}
	return out
}

// mcpToolPolicyError maps what saving a group tool policy (alone or as part of a connection) can refuse.
func mcpToolPolicyError(err error) error {
	switch {
	case errors.Is(err, mcptoolpolicy.ErrDefinitionStale):
		return apierr.Conflict("mcp_tool_definition_stale", "A tool changed since it was shown. Read the tool list again and review it.")
	case errors.Is(err, mcptoolpolicy.ErrUnobservedTool):
		return apierr.BadRequest("unobserved_mcp_tool", "Only a tool the server offers now can be set to Allow or Ask first")
	case errors.Is(err, mcptoolpolicy.ErrNoToolList):
		return apierr.Conflict("mcp_tool_list_unavailable", "The tool list of this server has not been read recently. Read it again, then save.")
	case errors.Is(err, mcptoolpolicy.ErrServerNotFound):
		return apierr.NotFound("mcp_server_not_found", "That MCP server is not connected to this agent group")
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return apierr.BadRequest("invalid_mcp_tool_policy", "The tool settings are not acceptable")
	}
	return nil
}

func (s apiServer) ConnectMCPServer(ctx context.Context, req api.ConnectMCPServerRequestObject) (api.ConnectMCPServerResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_mcp_connection", "A name, an address and one agent or agent group are required")
	}
	in := mcptoolpolicy.ConnectInput{OrgID: req.OrgId, ActorID: actorID(ctx), DeviceID: req.Body.Target.DeviceId, GroupID: req.Body.Target.GroupId,
		Name: req.Body.Name, Endpoint: req.Body.Endpoint, PreviewID: req.Body.PreviewId, Tools: mcpToolSettings(req.Body.Tools)}
	if req.Body.ServerName != nil {
		in.ServerName = *req.Body.ServerName
	}
	if in.ServerName == mcpwire.ReservedServerName {
		return nil, apierr.BadRequest("invalid_mcp_connection", "The server name \"mcp\" is reserved. Choose another.")
	}
	connection, err := s.mcpToolPolicy.Connect(ctx, in)
	if mapped := mcpToolPolicyError(err); mapped != nil && !errors.Is(err, mcptoolpolicy.ErrInvalid) {
		return nil, mapped
	}
	switch {
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return nil, apierr.BadRequest("invalid_mcp_connection", "Check the name, the address (http or https, with no sign-in details in it), the server name and the tool settings")
	case errors.Is(err, mcptoolpolicy.ErrTargetNotFound):
		return nil, apierr.NotFound("mcp_connection_target_not_found", "That agent or agent group was not found")
	case errors.Is(err, mcptoolpolicy.ErrMCPOff):
		return nil, apierr.Forbidden("opt_in_required", "Turn on MCP for this organization first.")
	case errors.Is(err, mcptoolpolicy.ErrServerNameTaken):
		return nil, apierr.Conflict("mcp_server_name_taken", "Another MCP server already uses that server name")
	case errors.Is(err, mcptoolpolicy.ErrProfileConflict):
		return nil, apierr.Conflict("mcp_profile_conflict", "An MCP server with that name already exists. Choose another name.")
	case err != nil:
		return nil, mcpConnectionUnavailable()
	}
	// The agents of the group now have a server: their gateways and runtimes are told at once.
	if s.devices != nil {
		s.devices.PushOrgNodes(ctx, req.OrgId)
	}
	g := connection.Group
	return api.ConnectMCPServer201JSONResponse{Body: api.MCPConnection{
		Profile:      toAPIAgentMCPProfile(connection.Profile),
		Group:        api.AgentGroup{Id: g.ID, OrgId: g.OrgID, Name: g.Name, Description: g.Description, MemberCount: connection.MemberCount, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt},
		GroupCreated: connection.GroupCreated,
		Assignment: api.AgentMCPProfileAssignment{Id: connection.Assignment.ID, OrgId: req.OrgId, ProfileId: connection.Profile.ID, ProfileName: connection.Profile.Name, GroupId: g.ID, GroupName: g.Name,
			State: api.AgentMCPProfileAssignmentState(connection.Assignment.State), AssignedAt: connection.Assignment.AssignedAt},
		ToolPolicy: toAPIGroupMCPToolPolicy(connection.Policy),
	}, Headers: api.ConnectMCPServer201ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) GetAgentGroupMCPToolPolicy(ctx context.Context, req api.GetAgentGroupMCPToolPolicyRequestObject) (api.GetAgentGroupMCPToolPolicyResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	policy, err := s.mcpToolPolicy.GetGroup(ctx, req.OrgId, req.GroupId, req.ProfileId)
	if mapped := mcpToolPolicyError(err); mapped != nil {
		return nil, mapped
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.GetAgentGroupMCPToolPolicy200JSONResponse{Body: toAPIGroupMCPToolPolicy(policy), Headers: api.GetAgentGroupMCPToolPolicy200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ReplaceAgentGroupMCPToolPolicy(ctx context.Context, req api.ReplaceAgentGroupMCPToolPolicyRequestObject) (api.ReplaceAgentGroupMCPToolPolicyResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_mcp_tool_policy", "The tool settings are required")
	}
	policy, err := s.mcpToolPolicy.ReplaceGroup(ctx, req.OrgId, req.GroupId, req.ProfileId, actorID(ctx), mcpToolSettings(req.Body.Tools))
	if mapped := mcpToolPolicyError(err); mapped != nil {
		return nil, mapped
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.ReplaceAgentGroupMCPToolPolicy200JSONResponse{Body: toAPIGroupMCPToolPolicy(policy), Headers: api.ReplaceAgentGroupMCPToolPolicy200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func toAPIGroupMCPToolPolicy(p mcptoolpolicy.GroupPolicy) api.AgentGroupMCPToolPolicy {
	overriding := p.OverridingAgents
	out := api.AgentGroupMCPToolPolicy{GroupId: p.GroupID, ProfileId: p.ProfileID, ServerName: p.ServerName, Endpoint: p.Endpoint, Version: p.Version,
		InventoryObservedAt: p.InventoryObservedAt, CreatedAt: p.CreatedAt, OverridingAgentCount: &overriding, Tools: make([]api.MCPToolSetting, 0, len(p.Tools))}
	text := func(value string) *string {
		if value == "" {
			return nil
		}
		return &value
	}
	for _, tool := range p.Tools {
		item := api.MCPToolSetting{ToolName: tool.ToolName, Mode: api.MCPToolMode(tool.Mode), Observed: tool.Observed, Description: text(tool.Description),
			InputSchemaHash: text(tool.InputSchemaHash), ToolDefinitionHash: text(tool.ToolDefinitionHash), RateLimitPerMinute: tool.RateLimitPerMinute}
		if tool.Effect != "" {
			effect := api.MCPToolEffect(tool.Effect)
			item.Effect = &effect
		}
		if tool.DefinitionState != "" {
			state := api.MCPToolSettingDefinitionState(tool.DefinitionState)
			item.DefinitionState = &state
		}
		if len(tool.ArgumentConstraints) > 0 {
			var constraints api.MCPArgumentConstraints
			if json.Unmarshal(tool.ArgumentConstraints, &constraints) == nil {
				item.ArgumentConstraints = &constraints
			}
		}
		out.Tools = append(out.Tools, item)
	}
	return out
}

func (s apiServer) RemoveAgentMCPToolPolicyOverride(ctx context.Context, req api.RemoveAgentMCPToolPolicyOverrideRequestObject) (api.RemoveAgentMCPToolPolicyOverrideResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if s.mcpToolPolicy == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	policy, err := s.mcpToolPolicy.RemoveOverride(ctx, req.OrgId, req.DeviceId, actorID(ctx), req.Params.Endpoint)
	switch {
	case errors.Is(err, mcptoolpolicy.ErrOverrideNotFound), errors.Is(err, mcptoolpolicy.ErrNotFound):
		return nil, apierr.NotFound("mcp_tool_policy_override_not_found", "This agent has no tool policy of its own for that MCP server")
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return nil, apierr.BadRequest("invalid_mcp_tool_policy", "The MCP server address is required")
	case err != nil:
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.RemoveAgentMCPToolPolicyOverride200JSONResponse{Body: toAPIMCPToolPolicy(policy), Headers: api.RemoveAgentMCPToolPolicyOverride200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) ListOrganizationMCPToolApprovalRequests(ctx context.Context, req api.ListOrganizationMCPToolApprovalRequestsRequestObject) (api.ListOrganizationMCPToolApprovalRequestsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if s.mcpToolApproval == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	limit, cursor := 50, ""
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	onlyPending := req.Params.State == nil || *req.Params.State == api.MCPToolApprovalInboxPending
	items, next, err := s.mcpToolApproval.ListOrganization(ctx, req.OrgId, onlyPending, limit, cursor)
	if errors.Is(err, mcptoolapproval.ErrCursor) {
		return nil, apierr.BadRequest("invalid_cursor", "The cursor is not one this list returned")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	page := api.MCPToolApprovalInboxPage{Items: make([]api.MCPToolApprovalInboxItem, 0, len(items))}
	// The profile's server name for the address each call went to, while that server is still assigned.
	names := map[uuid.UUID]map[string]string{}
	for _, item := range items {
		out := api.MCPToolApprovalInboxItem{Request: toAPIMCPToolApproval(item.Request), AgentName: item.AgentName, OwnerEmail: item.OwnerEmail}
		byEndpoint, cached := names[item.Request.DeviceID]
		if !cached && s.system != nil {
			byEndpoint = map[string]string{}
			if servers, err := mcptoolpolicy.AssignedServers(ctx, s.system, req.OrgId, item.Request.DeviceID); err == nil {
				for _, server := range servers {
					byEndpoint[server.Endpoint] = server.ServerName
				}
			}
			names[item.Request.DeviceID] = byEndpoint
		}
		if name, ok := byEndpoint[item.Request.Endpoint]; ok {
			out.McpServerName = &name
		}
		page.Items = append(page.Items, out)
	}
	if next != "" {
		page.NextCursor = &next
	}
	return api.ListOrganizationMCPToolApprovalRequests200JSONResponse{Body: page, Headers: api.ListOrganizationMCPToolApprovalRequests200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) CountOrganizationMCPToolApprovalRequests(ctx context.Context, req api.CountOrganizationMCPToolApprovalRequestsRequestObject) (api.CountOrganizationMCPToolApprovalRequestsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	// The sidebar asks this for every organization: with MCP off there is simply nothing waiting.
	if s.requireMCPOn(ctx, req.OrgId) != nil {
		return api.CountOrganizationMCPToolApprovalRequests200JSONResponse{Body: api.MCPToolApprovalCount{Pending: 0}, Headers: api.CountOrganizationMCPToolApprovalRequests200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
	}
	if s.mcpToolApproval == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	pending, err := s.mcpToolApproval.CountPending(ctx, req.OrgId)
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	return api.CountOrganizationMCPToolApprovalRequests200JSONResponse{Body: api.MCPToolApprovalCount{Pending: pending}, Headers: api.CountOrganizationMCPToolApprovalRequests200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// mcpActivityFilter reads the filters the activity list and its export share.
func mcpActivityFilter(decision *api.MCPToolActivityDecisionFilter, approved *bool, from, to *time.Time, server *string) (mcpdecision.ActivityFilter, error) {
	filter := mcpdecision.ActivityFilter{ApprovedOnly: approved != nil && *approved, From: from, To: to}
	if decision != nil {
		filter.Decision = string(*decision)
	}
	if server != nil {
		if !mcpwire.ValidServerName(*server) {
			return filter, apierr.BadRequest("invalid_request", "That is not a server name")
		}
		filter.Server = *server
	}
	if from != nil && to != nil && !from.Before(*to) {
		return filter, apierr.BadRequest("invalid_request", "The start of the period must be before its end")
	}
	return filter, nil
}

// ExportAgentMCPToolActivity is authorized like the activity list it exports.
func (s apiServer) ExportAgentMCPToolActivity(ctx context.Context, req api.ExportAgentMCPToolActivityRequestObject) (api.ExportAgentMCPToolActivityResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if err := s.requireMCPOn(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if s.mcpDecision == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_activity_unavailable", "MCP tool activity is temporarily unavailable")
	}
	filter, err := mcpActivityFilter(req.Params.Decision, req.Params.Approved, req.Params.From, req.Params.To, req.Params.Server)
	if err != nil {
		return nil, err
	}
	rows, _, err := s.mcpDecision.ExportActivity(ctx, req.OrgId, req.DeviceId, actorID(ctx), filter)
	if errors.Is(err, mcpdecision.ErrInvalid) {
		return nil, apierr.BadRequest("invalid_request", "The filters are not acceptable")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_activity_unavailable", "MCP tool activity is temporarily unavailable")
	}
	body := mcpActivityCSV(rows)
	return api.ExportAgentMCPToolActivity200TextcsvResponse{Body: bytes.NewReader(body), ContentLength: int64(len(body)),
		Headers: api.ExportAgentMCPToolActivity200ResponseHeaders{ContentDisposition: `attachment; filename="mcp-activity.csv"`, XRequestId: reqID(ctx)}}, nil
}

var mcpActivityCSVHeader = []string{"time", "tool", "server", "method", "result", "reason", "outcome", "server_response_status", "decided_by", "policy_version", "approved_by", "approved_at", "approval_request_id", "arguments_digest", "address"}

// mcpActivityCSV renders activity rows as one CSV file with a header row. Arguments are never in it, only
// their digest. Text an MCP server or an agent chose (tool and server names) is written so a spreadsheet
// shows it instead of running it as a formula.
func mcpActivityCSV(rows []mcpdecision.ActivityRow) []byte {
	var buffer bytes.Buffer
	w := csv.NewWriter(&buffer)
	_ = w.Write(mcpActivityCSVHeader)
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	for _, row := range rows {
		record := []string{row.OccurredAt.UTC().Format(time.RFC3339), csvText(row.ToolName), csvText(row.ServerName), csvText(row.Method), row.Decision, row.Reason, row.ResultStatus, "", text(row.PolicySource), "", "", "", "", text(row.ArgumentsDigest), csvText(row.Endpoint)}
		if row.UpstreamHttpStatus != nil {
			record[7] = strconv.Itoa(int(*row.UpstreamHttpStatus))
		}
		if row.PolicyVersion != nil {
			record[9] = strconv.FormatInt(*row.PolicyVersion, 10)
		}
		if row.ApprovalRequestID.Valid {
			record[10], record[12] = csvText(text(row.ApprovedByEmail)), uuid.UUID(row.ApprovalRequestID.Bytes).String()
			if row.ApprovedAt.Valid {
				record[11] = row.ApprovedAt.Time.UTC().Format(time.RFC3339)
			}
		}
		_ = w.Write(record)
	}
	w.Flush()
	return buffer.Bytes()
}

func csvText(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}
