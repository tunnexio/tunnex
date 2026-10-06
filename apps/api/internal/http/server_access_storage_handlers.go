package http

import (
	"context"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetServerAccessRecordingStorage(ctx context.Context, req api.GetServerAccessRecordingStorageRequestObject) (api.GetServerAccessRecordingStorageResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	_ = p
	out, e := s.serverAccess.GetRecordingStorage(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	return api.GetServerAccessRecordingStorage200JSONResponse(out), nil
}

func (s apiServer) UpdateServerAccessRecordingStorage(ctx context.Context, req api.UpdateServerAccessRecordingStorageRequestObject) (api.UpdateServerAccessRecordingStorageResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	out, e := s.serverAccess.ConfigureRecordingStorage(ctx, req.OrgId, p.UserID, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.UpdateServerAccessRecordingStorage200JSONResponse(out), nil
}

func (s apiServer) TestServerAccessRecordingStorage(ctx context.Context, req api.TestServerAccessRecordingStorageRequestObject) (api.TestServerAccessRecordingStorageResponseObject, error) {
	ctx, p, e := s.terminalContext(ctx, req.OrgId, rbac.PermServerAccessManage)
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "Request body required")
	}
	e = s.serverAccess.TestRecordingStorage(ctx, req.OrgId, p.UserID, *req.Body)
	if e != nil {
		return nil, e
	}
	return api.TestServerAccessRecordingStorage200JSONResponse{Ok: true}, nil
}
