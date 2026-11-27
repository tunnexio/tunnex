package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpdecision"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AcceptAgentMCPToolDefinition re-pins one rule to the tool definition the gateway observes now. The caller
// names the hash it reviewed, so a tool that changed again in the meantime is not accepted unseen.
func (s apiServer) AcceptAgentMCPToolDefinition(ctx context.Context, req api.AcceptAgentMCPToolDefinitionRequestObject) (api.AcceptAgentMCPToolDefinitionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	if req.Body == nil || s.mcpToolPolicy == nil {
		return nil, apierr.BadRequest("invalid_mcp_tool_definition", "endpoint, tool name and definition hash are required")
	}
	p, err := s.mcpToolPolicy.AcceptDefinition(ctx, req.OrgId, req.DeviceId, actorID(ctx), req.Body.Endpoint, req.Body.ToolName, req.Body.ToolDefinitionHash)
	switch {
	case errors.Is(err, mcptoolpolicy.ErrRuleNotFound), errors.Is(err, mcptoolpolicy.ErrNotFound):
		return nil, apierr.NotFound("mcp_tool_rule_not_found", "No rule of this agent's MCP tool policy names that tool")
	case errors.Is(err, mcptoolpolicy.ErrDefinitionStale):
		return nil, apierr.Conflict("mcp_tool_definition_stale", "The tool definition changed again; review the current one")
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return nil, apierr.BadRequest("invalid_mcp_tool_definition", "endpoint, tool name and definition hash are required")
	case err != nil:
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_policy_unavailable", "MCP tool policy is temporarily unavailable")
	}
	return api.AcceptAgentMCPToolDefinition200JSONResponse(toAPIMCPToolPolicy(p)), nil
}

// ListAgentMCPToolActivity pages what an agent did through MCP, newest first.
func (s apiServer) ListAgentMCPToolActivity(ctx context.Context, req api.ListAgentMCPToolActivityRequestObject) (api.ListAgentMCPToolActivityResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.mcpDecision == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_activity_unavailable", "MCP tool activity is temporarily unavailable")
	}
	limit, cursor := 50, ""
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	rows, next, err := s.mcpDecision.ListActivity(ctx, req.OrgId, req.DeviceId, limit, cursor)
	if errors.Is(err, mcpdecision.ErrCursor) {
		return nil, apierr.BadRequest("invalid_cursor", "The cursor is not one this list returned")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_activity_unavailable", "MCP tool activity is temporarily unavailable")
	}
	page := api.AgentMCPToolActivityPage{Items: make([]api.AgentMCPToolActivity, 0, len(rows))}
	for _, row := range rows {
		page.Items = append(page.Items, toAPIMCPToolActivity(row))
	}
	if next != "" {
		page.NextCursor = &next
	}
	return api.ListAgentMCPToolActivity200JSONResponse(page), nil
}

func toAPIMCPToolActivity(row sqlc.AgentMcpToolActivity) api.AgentMCPToolActivity {
	out := api.AgentMCPToolActivity{
		Id: row.ID, DeviceId: row.DeviceID, Endpoint: row.Endpoint, ServerName: row.ServerName, Method: row.Method, ToolName: row.ToolName,
		ArgumentsDigest: row.ArgumentsDigest, Decision: api.AgentMCPToolActivityDecision(row.Decision), Reason: row.Reason, PolicyVersion: row.PolicyVersion,
		ResultStatus: api.AgentMCPToolActivityResultStatus(row.ResultStatus), OccurredAt: row.OccurredAt,
	}
	if row.NodeID.Valid {
		id := uuid.UUID(row.NodeID.Bytes)
		out.NodeId = &id
	}
	if row.ApprovalRequestID.Valid {
		id := uuid.UUID(row.ApprovalRequestID.Bytes)
		out.ApprovalRequestId = &id
	}
	if row.UpstreamHttpStatus != nil {
		status := int(*row.UpstreamHttpStatus)
		out.UpstreamHttpStatus = &status
	}
	if row.CompletedAt.Valid {
		at := row.CompletedAt.Time
		out.CompletedAt = &at
	}
	return out
}
