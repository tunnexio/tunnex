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
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentViewPrivileged); err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	p, err := s.devices.GetAgentProfile(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	permissions, err := s.effectiveAgentPermissions(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	return api.GetAgentProfile200JSONResponse{Body: agentProfileResponse(p, permissions), Headers: api.GetAgentProfile200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) UpdateAgentProfile(ctx context.Context, req api.UpdateAgentProfileRequestObject) (api.UpdateAgentProfileResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.requireAgentPermission(ctx, req.OrgId, req.DeviceId, rbac.PermAgentManage); err != nil {
		return nil, err
	}
	if req.Body.OwnerId != nil || req.Body.ManagingGroupUpdate != nil {
		// Relational owner/team authority is intentionally insufficient for
		// changing the governance boundary itself. Only an organization-wide
		// agent:manage grant may include assignment fields.
		if _, err := authorize(ctx, req.OrgId, rbac.PermAgentManage); err != nil {
			return nil, err
		}
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	p, _ := authctx.PrincipalFrom(ctx)
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
	var status *string
	if req.Body.Status != nil {
		v := string(*req.Body.Status)
		status = &v
	}
	governance := devices.AgentGovernanceUpdate{
		OwnerID:                req.Body.OwnerId,
		ProfileUpdateRequested: req.Body.Environment != nil || req.Body.Runtime != nil || req.Body.Labels != nil || req.Body.Status != nil,
	}
	if req.Body.ManagingGroupUpdate != nil {
		governance.ManagingGroupSet = true
		governance.ManagingGroupID = req.Body.ManagingGroupUpdate.GroupId
	}
	updated, err := s.devices.UpdateAgentProfileWithLifecycleAndGovernance(ctx, p.UserID, req.OrgId, req.DeviceId, environment, runtime, labelBytes, status, governance)
	if err != nil {
		return nil, err
	}
	permissions, err := s.effectiveAgentPermissions(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	return api.UpdateAgentProfile200JSONResponse{Body: agentProfileResponse(updated, permissions), Headers: api.UpdateAgentProfile200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) effectiveAgentPermissions(ctx context.Context, orgID, deviceID openapi_types.UUID) (api.AgentEffectivePermissions, error) {
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(orgID)
	scope := devices.AgentScopedAuthority{}
	if s.devices != nil {
		var err error
		scope, err = s.devices.AgentScopedAuthority(ctx, orgID, deviceID, p.UserID)
		if err != nil {
			return api.AgentEffectivePermissions{}, err
		}
	}
	view := rbac.Can(role, rbac.PermAgentViewPrivileged) || scope.Owner || scope.Manager
	manage := rbac.Can(role, rbac.PermAgentManage) || scope.Owner || scope.Manager
	return api.AgentEffectivePermissions{
		ViewPrivileged:    view,
		Manage:            manage,
		Assign:            rbac.Can(role, rbac.PermAgentManage),
		GrantAccess:       rbac.Can(role, rbac.PermAgentGrantAccess),
		Revoke:            rbac.Can(role, rbac.PermAgentRevoke) || scope.Owner,
		RotateCredentials: rbac.Can(role, rbac.PermAgentCredentialRotate),
	}, nil
}

func (s apiServer) requireAgentPermission(ctx context.Context, orgID, deviceID openapi_types.UUID, permission rbac.Permission) error {
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(orgID)
	if rbac.Can(role, permission) {
		return nil
	}
	if permission != rbac.PermAgentViewPrivileged && permission != rbac.PermAgentManage && permission != rbac.PermAgentRevoke && permission != rbac.PermAgentAccessRequest {
		return apierr.New(403, "forbidden", "you may not access this agent")
	}
	if s.devices == nil {
		return apierr.New(403, "forbidden", "you may not access this agent")
	}
	scope, err := s.devices.AgentScopedAuthority(ctx, orgID, deviceID, p.UserID)
	if err != nil {
		return err
	}
	allowed := scope.Owner || (scope.Manager && (permission == rbac.PermAgentViewPrivileged || permission == rbac.PermAgentManage || permission == rbac.PermAgentAccessRequest))
	if !allowed {
		return apierr.New(403, "forbidden", "you may not access this agent")
	}
	return nil
}

func agentProfileLifecycleAllowed(role, status string) bool {
	return rbac.Can(role, rbac.PermAgentManage) && (status == "active" || status == "suspended")
}

func agentProfileResponse(p devices.AgentProfile, permissions api.AgentEffectivePermissions) api.AgentProfile {
	labels := map[string]string{}
	_ = json.Unmarshal(p.Labels, &labels)
	return api.AgentProfile{DeviceId: p.DeviceID, Name: p.Name, Environment: p.Environment, Runtime: p.Runtime,
		Labels: labels, OwnerId: p.OwnerID, OwnerEmail: openapi_types.Email(p.OwnerEmail),
		ManagingGroupId: p.ManagingGroupID, ManagingGroupName: p.ManagingGroupName, Permissions: permissions,
		Status: api.AgentProfileStatus(p.Status), LastHandshakeAt: p.LastHandshakeAt, RxBytes: p.RxBytes, TxBytes: p.TxBytes}
}
