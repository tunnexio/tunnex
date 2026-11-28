package http

import (
	"context"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-KEYS-1: the internal AI endpoint is a gateway setting. Reads need
// ai_workload:view, so a workload manager can see the URL to give an
// application; writes need ai_gateway:manage.

func (s apiServer) internalEndpointContext(ctx context.Context, org uuid.UUID, write bool) (context.Context, uuid.UUID, error) {
	perm := rbac.PermAIWorkloadView
	if write {
		perm = rbac.PermAIGatewayManage
	}
	ctx, err := authorize(ctx, org, perm)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	actor := uuid.Nil
	if write {
		if actor, err = aiManagementActor(ctx); err != nil {
			return ctx, actor, err
		}
	}
	if s.aiInternal == nil {
		return ctx, actor, apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
	}
	return ctx, actor, nil
}

func (s apiServer) ListAIInternalEndpoints(ctx context.Context, r api.ListAIInternalEndpointsRequestObject) (api.ListAIInternalEndpointsResponseObject, error) {
	ctx, _, err := s.internalEndpointContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	items, err := s.aiInternal.List(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	return api.ListAIInternalEndpoints200JSONResponse{Body: api.AIInternalEndpointList{Items: items}, Headers: api.ListAIInternalEndpoints200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) PutAIInternalEndpoint(ctx context.Context, r api.PutAIInternalEndpointRequestObject) (api.PutAIInternalEndpointResponseObject, error) {
	ctx, actor, err := s.internalEndpointContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	out, err := s.aiInternal.Put(ctx, r.OrgId, actor, r.NodeId, *r.Body)
	if err != nil {
		return nil, err
	}
	return api.PutAIInternalEndpoint200JSONResponse{Body: out, Headers: api.PutAIInternalEndpoint200ResponseHeaders{CacheControl: "no-store"}}, nil
}

func (s apiServer) DeleteAIInternalEndpoint(ctx context.Context, r api.DeleteAIInternalEndpointRequestObject) (api.DeleteAIInternalEndpointResponseObject, error) {
	ctx, actor, err := s.internalEndpointContext(ctx, r.OrgId, true)
	if err != nil {
		return nil, err
	}
	if err = s.aiInternal.Delete(ctx, r.OrgId, actor, r.NodeId); err != nil {
		return nil, err
	}
	return api.DeleteAIInternalEndpoint204Response{}, nil
}

// GetAIInternalEndpointCA returns the public CA certificate. Creating it on
// first use is safe for a reader: it holds no secret the reader can see.
func (s apiServer) GetAIInternalEndpointCA(ctx context.Context, r api.GetAIInternalEndpointCARequestObject) (api.GetAIInternalEndpointCAResponseObject, error) {
	ctx, _, err := s.internalEndpointContext(ctx, r.OrgId, false)
	if err != nil {
		return nil, err
	}
	out, err := s.aiInternal.CA(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetAIInternalEndpointCA200JSONResponse{Body: out, Headers: api.GetAIInternalEndpointCA200ResponseHeaders{CacheControl: "no-store"}}, nil
}
