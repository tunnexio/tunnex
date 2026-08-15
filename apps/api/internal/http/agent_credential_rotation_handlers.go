package http

import (
	"context"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetAgentCredentialRotation(ctx context.Context, req api.GetAgentCredentialRotationRequestObject) (api.GetAgentCredentialRotationResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentCredentialRotate); err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	status, err := s.devices.GetAgentCredentialRotation(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	return api.GetAgentCredentialRotation200JSONResponse{Body: rotationStatusResponse(status), Headers: api.GetAgentCredentialRotation200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) RequestAgentCredentialRotation(ctx context.Context, req api.RequestAgentCredentialRotationRequestObject) (api.RequestAgentCredentialRotationResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentCredentialRotate); err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	status, err := s.devices.RequestAgentCredentialRotation(ctx, principal.UserID, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	return api.RequestAgentCredentialRotation200JSONResponse{Body: rotationStatusResponse(status), Headers: api.RequestAgentCredentialRotation200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func rotationStatusResponse(status devices.AgentCredentialRotationStatus) api.AgentCredentialRotationStatus {
	return api.AgentCredentialRotationStatus{
		DeviceId: status.DeviceID, CurrentRevision: status.CurrentRevision,
		State:             api.AgentCredentialRotationStatusState(status.State),
		RequestedRevision: status.RequestedRevision, Deadline: status.Deadline,
	}
}
