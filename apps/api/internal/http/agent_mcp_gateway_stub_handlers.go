package http

import (
	"context"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-SEC-2 contract stubs. The operations below are in the OpenAPI contract so the gateway, runtime and web
// work packages can build against generated types, but their behaviour lands with the control-plane decision
// package. Until then each one authorizes the caller exactly as the finished handler will and then answers
// 501 `mcp_gateway_not_implemented`, so nothing can mistake a stub for a decision.
func mcpGatewayNotImplemented() *apierr.Error {
	return apierr.New(http.StatusNotImplemented, "mcp_gateway_not_implemented", "This MCP operation is not available yet.")
}

func (s apiServer) AcceptAgentMCPToolDefinition(ctx context.Context, req api.AcceptAgentMCPToolDefinitionRequestObject) (api.AcceptAgentMCPToolDefinitionResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	return nil, mcpGatewayNotImplemented()
}

func (s apiServer) ListAgentMCPToolActivity(ctx context.Context, req api.ListAgentMCPToolActivityRequestObject) (api.ListAgentMCPToolActivityResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	return nil, mcpGatewayNotImplemented()
}

func (s apiServer) DenyAgentMCPToolApprovalRequest(ctx context.Context, req api.DenyAgentMCPToolApprovalRequestRequestObject) (api.DenyAgentMCPToolApprovalRequestResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	return nil, mcpGatewayNotImplemented()
}
