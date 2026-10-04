package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type appAdminSessionsHTTPPort interface {
	ApplicationSessions(context.Context, uuid.UUID, uuid.UUID, int32, int32) ([]appaccess.AdminAppSession, error)
	RevokeApplicationSession(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) error
}

func (s apiServer) ListAppAccessApplicationSessions(ctx context.Context, req api.ListAppAccessApplicationSessionsRequestObject) (api.ListAppAccessApplicationSessionsResponseObject, error) {
	ctx, _, err := s.appAccessPermissionContext(ctx, req.OrgId, rbac.PermAppAccessSessionManage, false)
	if err != nil {
		return nil, err
	}
	p, ok := s.appAccess.(appAdminSessionsHTTPPort)
	if !ok {
		return nil, apierr.New(503, "app_access_unavailable", "App Access service unavailable")
	}
	limit, offset, err := appSessionPagination(req.Params.Limit, req.Params.Offset)
	if err != nil {
		return nil, err
	}
	rows, err := p.ApplicationSessions(ctx, req.OrgId, req.AppId, limit, offset)
	if err != nil {
		return nil, err
	}
	out := api.AppAccessApplicationSessions{Items: []api.AppAccessApplicationSession{}, Limit: int(limit), Offset: int(offset)}
	for _, r := range rows {
		out.Items = append(out.Items, api.AppAccessApplicationSession{Id: r.ID, AppId: r.AppID, UserId: r.UserID, InstallationGeneration: r.InstallationGeneration, AppLabel: r.Label, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt})
	}
	return api.ListAppAccessApplicationSessions200JSONResponse(out), nil
}
func (s apiServer) RevokeAppAccessApplicationSession(ctx context.Context, req api.RevokeAppAccessApplicationSessionRequestObject) (api.RevokeAppAccessApplicationSessionResponseObject, error) {
	ctx, actor, err := s.appAccessPermissionContext(ctx, req.OrgId, rbac.PermAppAccessSessionManage, true)
	if err != nil {
		return nil, err
	}
	p, ok := s.appAccess.(appAdminSessionsHTTPPort)
	if !ok {
		return nil, apierr.New(503, "app_access_unavailable", "App Access service unavailable")
	}
	if err := p.RevokeApplicationSession(ctx, req.OrgId, req.AppId, actor, req.SessionId); err != nil {
		return nil, err
	}
	return api.RevokeAppAccessApplicationSession204Response{}, nil
}
