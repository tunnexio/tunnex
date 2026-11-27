package http

import (
	"context"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-UX-1 stubs for the switches and the install status (see aiux1_stub.go). Replaced by the package that
// owns agent_handlers.go and the feature gates.

func (s apiServer) GetOrganizationMCPSetting(ctx context.Context, req api.GetOrganizationMCPSettingRequestObject) (api.GetOrganizationMCPSettingResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) SetOrganizationMCPEnabled(ctx context.Context, req api.SetOrganizationMCPEnabledRequestObject) (api.SetOrganizationMCPEnabledResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMCPManage); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) ListAgentFeatures(ctx context.Context, req api.ListAgentFeaturesRequestObject) (api.ListAgentFeaturesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) GetAgentBootstrapTokenStatus(ctx context.Context, req api.GetAgentBootstrapTokenStatusRequestObject) (api.GetAgentBootstrapTokenStatusResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentEnroll); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}
