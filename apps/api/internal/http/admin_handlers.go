package http

import (
	"context"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// The deployment-administration handlers (S12.11). Both are gated by requireCPAdmin — the capability
// question, asked BESIDE RoleIn — and neither calls authorize(), because the caller is typically a member
// of none of the organizations they are acting on.

// AdminSetOrgRole PUT /api/v1/admin/organizations/{orgId}/members/{userId}/role.
//
// The cross-tenant grant: any user, any organization, any role. Refuses to demote the org's last owner and
// audits into the TARGET org's feed.
func (s apiServer) AdminSetOrgRole(ctx context.Context, req api.AdminSetOrgRoleRequestObject) (api.AdminSetOrgRoleResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.orgs.GrantOrgRole(ctx, p.UserID, p.Email, req.OrgId, req.UserId, string(req.Body.Role)); err != nil {
		return nil, err
	}
	return api.AdminSetOrgRole204Response{
		Headers: api.AdminSetOrgRole204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// AdminSetCpAdmin PUT /api/v1/admin/users/{userId}/cp-admin — grant or revoke the capability itself.
// Refuses any change that would leave the deployment with zero holders.
func (s apiServer) AdminSetCpAdmin(ctx context.Context, req api.AdminSetCpAdminRequestObject) (api.AdminSetCpAdminResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.orgs.SetCPAdmin(ctx, p.UserID, req.UserId, req.Body.Granted); err != nil {
		return nil, err
	}
	return api.AdminSetCpAdmin204Response{
		Headers: api.AdminSetCpAdmin204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}
