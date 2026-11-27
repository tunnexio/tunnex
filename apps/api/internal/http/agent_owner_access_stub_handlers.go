package http

import (
	"context"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-UX-1 stubs for the agent Access tab (see aiux1_stub.go). Replaced by the package that owns
// agent_access_handlers.go.

// GetAgentAccessSummary is authorized like the access diagnostic beside it.
func (s apiServer) GetAgentAccessSummary(ctx context.Context, req api.GetAgentAccessSummaryRequestObject) (api.GetAgentAccessSummaryResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) PreviewAgentOwnerAccess(ctx context.Context, req api.PreviewAgentOwnerAccessRequestObject) (api.PreviewAgentOwnerAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentGrantAccess); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}

func (s apiServer) CreateAgentRulesFromOwnerAccess(ctx context.Context, req api.CreateAgentRulesFromOwnerAccessRequestObject) (api.CreateAgentRulesFromOwnerAccessResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentGrantAccess); err != nil {
		return nil, err
	}
	return nil, agentUXNotImplemented()
}
