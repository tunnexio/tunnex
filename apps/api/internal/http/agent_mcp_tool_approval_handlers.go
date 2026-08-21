package http

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) PermitRuntimeMCPToolApproval(ctx context.Context, req api.PermitRuntimeMCPToolApprovalRequestObject) (api.PermitRuntimeMCPToolApprovalResponseObject, error) {
	id, ok := agentruntime.IdentityFromContext(ctx)
	if !ok || req.Body == nil || s.mcpToolApproval == nil {
		return nil, runtimeUnauthorized()
	}
	b := req.Body
	r, allowed, err := s.mcpToolApproval.Permit(ctx, id.OrgID, id.DeviceID, mcptoolapproval.Identity{PolicyVersion: b.PolicyVersion, Endpoint: b.Endpoint, ServerName: b.ServerName, ToolName: b.ToolName, InputSchemaHash: b.InputSchemaHash, RequestDigest: b.RequestDigest})
	if errors.Is(err, mcptoolapproval.ErrInvalid) {
		return nil, apierr.BadRequest("invalid_mcp_tool_approval", "MCP tool approval request is invalid")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	return api.PermitRuntimeMCPToolApproval200JSONResponse(api.RuntimeMCPToolApprovalPermit{RequestId: r.ID, State: api.RuntimeMCPToolApprovalPermitState(r.State), Allowed: allowed}), nil
}

func (s apiServer) ListAgentMCPToolApprovalRequests(ctx context.Context, req api.ListAgentMCPToolApprovalRequestsRequestObject) (api.ListAgentMCPToolApprovalRequestsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	if s.mcpToolApproval == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	items, err := s.mcpToolApproval.List(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	out := make([]api.AgentMCPToolApprovalRequest, 0, len(items))
	for _, item := range items {
		out = append(out, toAPIMCPToolApproval(item))
	}
	return api.ListAgentMCPToolApprovalRequests200JSONResponse(out), nil
}

func (s apiServer) ApproveAgentMCPToolApprovalRequest(ctx context.Context, req api.ApproveAgentMCPToolApprovalRequestRequestObject) (api.ApproveAgentMCPToolApprovalRequestResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	if s.mcpToolApproval == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	r, err := s.mcpToolApproval.Approve(ctx, req.OrgId, req.DeviceId, req.RequestId, actorID(ctx))
	if errors.Is(err, mcptoolapproval.ErrConflict) {
		return nil, apierr.Conflict("mcp_tool_approval_not_pending", "MCP tool approval is not pending")
	}
	if err != nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "mcp_tool_approval_unavailable", "MCP tool approval is temporarily unavailable")
	}
	return api.ApproveAgentMCPToolApprovalRequest200JSONResponse(toAPIMCPToolApproval(r)), nil
}

func toAPIMCPToolApproval(r mcptoolapproval.Request) api.AgentMCPToolApprovalRequest {
	out := api.AgentMCPToolApprovalRequest{Id: r.ID, DeviceId: r.DeviceID, PolicyVersion: r.PolicyVersion, Endpoint: r.Endpoint, ServerName: r.ServerName, ToolName: r.ToolName, InputSchemaHash: r.InputSchemaHash, State: api.AgentMCPToolApprovalRequestState(r.State), RequestedAt: r.RequestedAt, ExpiresAt: r.ExpiresAt}
	if r.ApprovedAt.After(time.Unix(0, 0)) {
		out.ApprovedAt = &r.ApprovedAt
	}
	if r.ApprovedByUserID != uuid.Nil {
		v := r.ApprovedByUserID
		out.ApprovedByUserId = &v
	}
	return out
}
