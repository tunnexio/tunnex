package http

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/connectivity"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) connectivityPrincipal(ctx context.Context, org uuid.UUID) (connectivity.Principal, error) {
	_, err := authorize(ctx, org, rbac.PermConnectivityUse)
	if err != nil {
		return connectivity.Principal{}, err
	}
	if s.connectivity == nil {
		return connectivity.Principal{}, connectivityError(connectivity.ErrDenied)
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return connectivity.Principal{}, connectivityError(connectivity.ErrDenied)
	}
	return connectivity.Principal{Side: connectivity.DeviceSide, OrgID: org, SubjectID: p.UserID}, nil
}

func (s apiServer) CreateConnectivitySession(ctx context.Context, req api.CreateConnectivitySessionRequestObject) (api.CreateConnectivitySessionResponseObject, error) {
	p, err := s.connectivityPrincipal(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	m, err := s.connectivity.Create(ctx, p, req.DeviceId)
	if err != nil {
		return nil, connectivityError(err)
	}
	return api.CreateConnectivitySession201JSONResponse(toConnectivityMailbox(m)), nil
}

func (s apiServer) GetConnectivitySession(ctx context.Context, req api.GetConnectivitySessionRequestObject) (api.GetConnectivitySessionResponseObject, error) {
	p, err := s.connectivityPrincipal(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Params.Generation < 1 {
		return nil, connectivityError(connectivity.ErrDenied)
	}
	m, err := s.connectivity.Read(ctx, p, req.DeviceId, req.SessionId, uint64(req.Params.Generation))
	if err != nil {
		return nil, connectivityError(err)
	}
	return api.GetConnectivitySession200JSONResponse(toConnectivityMailbox(m)), nil
}

func (s apiServer) PublishConnectivitySnapshot(ctx context.Context, req api.PublishConnectivitySnapshotRequestObject) (api.PublishConnectivitySnapshotResponseObject, error) {
	p, err := s.connectivityPrincipal(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Sequence < 1 || req.Body.Sequence > connectivity.MaxMessages || req.Params.Generation < 1 {
		return nil, connectivityError(connectivity.ErrPayload)
	}
	m, err := s.connectivity.Publish(ctx, p, req.DeviceId, req.SessionId, uint64(req.Params.Generation), uint64(req.Body.Sequence), json.RawMessage(req.Body.Payload))
	if err != nil {
		return nil, connectivityError(err)
	}
	return api.PublishConnectivitySnapshot200JSONResponse(toConnectivityMailbox(m)), nil
}

func (s apiServer) CloseConnectivitySession(ctx context.Context, req api.CloseConnectivitySessionRequestObject) (api.CloseConnectivitySessionResponseObject, error) {
	p, err := s.connectivityPrincipal(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Params.Generation < 1 {
		return nil, connectivityError(connectivity.ErrDenied)
	}
	if err := s.connectivity.Close(ctx, p, req.DeviceId, req.SessionId, uint64(req.Params.Generation)); err != nil {
		return nil, connectivityError(err)
	}
	return api.CloseConnectivitySession204Response{}, nil
}

func connectivityError(err error) error {
	if errors.Is(err, connectivity.ErrDenied) {
		return apierr.Forbidden("connectivity_denied", "Connectivity session unavailable")
	}
	if errors.Is(err, connectivity.ErrPayload) {
		return apierr.BadRequest("invalid_connectivity_snapshot", "A bounded JSON object snapshot is required")
	}
	// Database errors may include signaling payload details; never forward them.
	return apierr.Internal()
}

func toConnectivityMailbox(m connectivity.Mailbox) api.ConnectivityMailbox {
	s := m.Session
	return api.ConnectivityMailbox{SessionId: s.Binding.SessionID, DeviceId: s.Binding.DeviceID, GatewayId: s.Binding.GatewayID,
		Generation: int64(s.Binding.Generation), ExpiresAt: s.ExpiresAt, DeviceSequence: int64(s.DeviceSequence), GatewaySequence: int64(s.GatewaySequence),
		DevicePayload: string(m.DevicePayload), GatewayPayload: string(m.GatewayPayload)}
}
