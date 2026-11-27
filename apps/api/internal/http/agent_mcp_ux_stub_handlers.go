package http

import (
	"context"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-UX-1 stubs for connecting an MCP server, group tool policy, the approvals inbox and the activity
// export (see aiux1_stub.go). Replaced by the package that owns the MCP control plane.

func (s apiServer) StartMCPConnectionPreview(ctx context.Context, req api.StartMCPConnectionPreviewRequestObject) (api.StartMCPConnectionPreviewResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) GetMCPConnectionPreview(ctx context.Context, req api.GetMCPConnectionPreviewRequestObject) (api.GetMCPConnectionPreviewResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) ConnectMCPServer(ctx context.Context, req api.ConnectMCPServerRequestObject) (api.ConnectMCPServerResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) GetAgentGroupMCPToolPolicy(ctx context.Context, req api.GetAgentGroupMCPToolPolicyRequestObject) (api.GetAgentGroupMCPToolPolicyResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) ReplaceAgentGroupMCPToolPolicy(ctx context.Context, req api.ReplaceAgentGroupMCPToolPolicyRequestObject) (api.ReplaceAgentGroupMCPToolPolicyResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) RemoveAgentMCPToolPolicyOverride(ctx context.Context, req api.RemoveAgentMCPToolPolicyOverrideRequestObject) (api.RemoveAgentMCPToolPolicyOverrideResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolPolicyManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) ListOrganizationMCPToolApprovalRequests(ctx context.Context, req api.ListOrganizationMCPToolApprovalRequestsRequestObject) (api.ListOrganizationMCPToolApprovalRequestsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) CountOrganizationMCPToolApprovalRequests(ctx context.Context, req api.CountOrganizationMCPToolApprovalRequestsRequestObject) (api.CountOrganizationMCPToolApprovalRequestsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentMCPToolApprovalApprove); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

// ExportAgentMCPToolActivity is authorized like the activity list it exports.
func (s apiServer) ExportAgentMCPToolActivity(ctx context.Context, req api.ExportAgentMCPToolActivityRequestObject) (api.ExportAgentMCPToolActivityResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}
