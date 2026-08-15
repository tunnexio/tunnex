package http

import (
	"context"
	"encoding/json"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func (s apiServer) GetAgentProfile(ctx context.Context, req api.GetAgentProfileRequestObject) (api.GetAgentProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	if err := s.requireAgentProfileAccess(ctx, req.OrgId, req.DeviceId); err != nil {
		return nil, err
	}
	p, err := s.devices.GetAgentProfile(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	return api.GetAgentProfile200JSONResponse{Body: agentProfileResponse(p), Headers: api.GetAgentProfile200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) UpdateAgentProfile(ctx context.Context, req api.UpdateAgentProfileRequestObject) (api.UpdateAgentProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)
	admin := agentProfileLifecycleAllowed(role, "active")
	if !admin {
		owner, err := s.devices.IsAgentOwner(ctx, req.OrgId, req.DeviceId, p.UserID)
		if err != nil {
			return nil, err
		}
		if !owner {
			return nil, apierr.New(403, "forbidden", "you may not view this agent")
		}
	}
	current, err := s.devices.GetAgentProfile(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	environment, runtime := current.Environment, current.Runtime
	labels := map[string]string{}
	if err := json.Unmarshal(current.Labels, &labels); err != nil {
		return nil, err
	}
	if req.Body.Environment != nil {
		environment = *req.Body.Environment
	}
	if req.Body.Runtime != nil {
		runtime = *req.Body.Runtime
	}
	if req.Body.Labels != nil {
		labels = *req.Body.Labels
	}
	labelBytes, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}
	if req.Body.Status != nil && !agentProfileLifecycleAllowed(role, string(*req.Body.Status)) {
		return nil, apierr.New(403, "forbidden", "lifecycle changes require agent management permission")
	}
	var status *string
	if req.Body.Status != nil {
		v := string(*req.Body.Status)
		status = &v
	}
	updated, err := s.devices.UpdateAgentProfileWithLifecycle(ctx, p.UserID, req.OrgId, req.DeviceId, environment, runtime, labelBytes, status)
	if err != nil {
		return nil, err
	}
	return api.UpdateAgentProfile200JSONResponse{Body: agentProfileResponse(updated), Headers: api.UpdateAgentProfile200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) requireAgentProfileAccess(ctx context.Context, orgID, deviceID openapi_types.UUID) error {
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(orgID)
	if rbac.Can(role, rbac.PermMemberManage) {
		return nil
	}
	owner, err := s.devices.IsAgentOwner(ctx, orgID, deviceID, p.UserID)
	if err != nil {
		return err
	}
	if !owner {
		return apierr.New(403, "forbidden", "you may not view this agent")
	}
	return nil
}

func agentProfileLifecycleAllowed(role, status string) bool {
	return rbac.Can(role, rbac.PermMemberManage) && (status == "active" || status == "suspended")
}

func agentProfileResponse(p devices.AgentProfile) api.AgentProfile {
	labels := map[string]string{}
	_ = json.Unmarshal(p.Labels, &labels)
	return api.AgentProfile{DeviceId: p.DeviceID, Name: p.Name, Environment: p.Environment, Runtime: p.Runtime,
		Labels: labels, OwnerId: p.OwnerID, OwnerEmail: openapi_types.Email(p.OwnerEmail),
		Status: api.AgentProfileStatus(p.Status), LastHandshakeAt: p.LastHandshakeAt, RxBytes: p.RxBytes, TxBytes: p.TxBytes}
}
