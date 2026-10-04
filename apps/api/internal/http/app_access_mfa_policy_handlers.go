package http

import (
	"context"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
)

type appAccessMFAPolicyPort interface {
	UpdateMFAPolicy(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool, int64) (appaccess.Application, error)
}

func (s apiServer) UpdateAppAccessMFAPolicy(ctx context.Context, req api.UpdateAppAccessMFAPolicyRequestObject) (api.UpdateAppAccessMFAPolicyResponseObject, error) {
	ctx, actor, err := s.appAccessContext(ctx, req.OrgId, true)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	if req.Body.ExpectedVersion < 1 {
		return nil, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	svc, ok := s.appAccess.(appAccessMFAPolicyPort)
	if !ok || svc == nil {
		return nil, apierr.New(503, "app_access_unavailable", "App Access service is unavailable")
	}
	out, err := svc.UpdateMFAPolicy(ctx, req.OrgId, actor, req.AppId, req.Body.RequireMfa, req.Body.ExpectedVersion)
	if err != nil {
		return nil, err
	}
	return api.UpdateAppAccessMFAPolicy200JSONResponse{Body: appAccessApplication(out), Headers: api.UpdateAppAccessMFAPolicy200ResponseHeaders{CacheControl: "no-store"}}, nil
}
