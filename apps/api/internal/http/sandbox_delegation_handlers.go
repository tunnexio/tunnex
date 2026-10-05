package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

func sandboxDelegationActor(ctx context.Context, org uuid.UUID) (context.Context, uuid.UUID, error) {
	ctx, err := authorize(ctx, org, rbac.PermSandboxDelegateManage)
	if err != nil {
		return ctx, uuid.Nil, err
	}
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok || p.IsMachine() || p.IsAgent() || p.UserID == uuid.Nil {
		return ctx, uuid.Nil, apierr.New(403, "forbidden", "human delegation administration required")
	}
	return ctx, p.UserID, nil
}

// The generated router validates JSON before calling a handler. Authenticate
// sandbox and scoped-routing requests first, and gate human delegation administration too.
func authBeforeSandboxValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		parts := strings.Split(req.URL.Path, "/")
		orgSandbox := len(parts) >= 6 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "organizations" && (parts[5] == "sandboxes" || strings.HasPrefix(parts[5], "sandbox-") || parts[5] == "saved-ssh-keys" || parts[5] == "cross-gateway-settings")
		if orgSandbox {
			if _, ok := authctx.PrincipalFrom(req.Context()); !ok {
				apierr.Write(w, req, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required"))
				return
			}
		}
		if orgSandbox && (parts[5] == "sandbox-delegation-settings" || parts[5] == "sandbox-delegations") {
			org, err := uuid.Parse(parts[4])
			if err != nil || org == uuid.Nil {
				apierr.Write(w, req, apierr.BadRequest("invalid_organization", "invalid organization"))
				return
			}
			ctx, _, err := sandboxDelegationActor(req.Context(), org)
			if err != nil {
				apierr.Write(w, req, err)
				return
			}
			req = req.WithContext(ctx)
		}
		if orgSandbox && parts[5] == "sandbox-runner-enrollments" {
			org, err := uuid.Parse(parts[4])
			if err != nil || org == uuid.Nil {
				apierr.Write(w, req, apierr.BadRequest("invalid_organization", "invalid organization"))
				return
			}
			ctx, _, err := sandboxRunnerEnrollmentActor(req.Context(), org)
			if err != nil {
				apierr.Write(w, req, err)
				return
			}
			req = req.WithContext(ctx)
		}
		next.ServeHTTP(w, req)
	})
}

func (s apiServer) UpdateSandboxDelegationSettings(ctx context.Context, req api.UpdateSandboxDelegationSettingsRequestObject) (api.UpdateSandboxDelegationSettingsResponseObject, error) {
	ctx, actor, err := sandboxDelegationActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, ok := s.sandboxes.(sandboxDelegationRepository)
	if !ok {
		return nil, sandboxUnavailable()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_sandbox_delegation", "delegation settings body is required")
	}
	if err = repo.SetDelegationEnabled(ctx, req.OrgId, actor, req.Body.Enabled); err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	return api.UpdateSandboxDelegationSettings204Response{}, nil
}

func (s apiServer) IssueSandboxDelegation(ctx context.Context, req api.IssueSandboxDelegationRequestObject) (api.IssueSandboxDelegationResponseObject, error) {
	ctx, actor, err := sandboxDelegationActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, ok := s.sandboxes.(sandboxDelegationRepository)
	if !ok {
		return nil, sandboxUnavailable()
	}
	if req.Body == nil || req.Body.MaxTtlSeconds < 300 || req.Body.MaxTtlSeconds > 900 || req.Body.MaxActive < 1 || req.Body.MaxActive > 2 || len(req.Body.MaximumScope) > 64 || len(req.Body.SkillRevisionIds) > 32 {
		return nil, apierr.BadRequest("invalid_sandbox_delegation", "invalid delegation body")
	}
	b := req.Body
	d := sandboxes.Delegation{OrgID: req.OrgId, OwnerID: actor, MachineID: b.MachineId, TemplateID: b.TemplateId, MaxTTLSeconds: int32(b.MaxTtlSeconds), MaxActive: int32(b.MaxActive), MaximumScope: []sandboxes.Scope{}, SkillRevisionIDs: b.SkillRevisionIds, ExpiresAt: b.ExpiresAt}
	for _, scope := range b.MaximumScope {
		if scope.PortLow < 0 || scope.PortLow > 65535 || scope.PortHigh < 0 || scope.PortHigh > 65535 {
			return nil, apierr.BadRequest("invalid_sandbox_delegation", "invalid delegation scope")
		}
		d.MaximumScope = append(d.MaximumScope, sandboxes.Scope{CIDR: scope.Cidr, Protocol: string(scope.Protocol), PortLow: uint16(scope.PortLow), PortHigh: uint16(scope.PortHigh)})
	}
	d, err = repo.IssueDelegation(ctx, req.OrgId, actor, d)
	if errors.Is(err, sandboxes.ErrConflict) {
		return nil, apierr.Conflict("sandbox_delegation_conflict", "revoke the existing active delegation first")
	}
	if errors.Is(err, sandboxes.ErrDisabled) {
		return nil, apierr.New(403, "sandbox_delegation_disabled", "organization delegation is disabled")
	}
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.IssueSandboxDelegation201JSONResponse{Id: &d.ID, OrganizationId: &d.OrgID, OwnerId: &d.OwnerID, MachineId: d.MachineID, TemplateId: d.TemplateID, MaxTtlSeconds: int(d.MaxTTLSeconds), MaxActive: int(d.MaxActive), MaximumScope: sandboxScopes(d.MaximumScope), SkillRevisionIds: append([]uuid.UUID{}, d.SkillRevisionIDs...), ExpiresAt: d.ExpiresAt}, nil
}

func (s apiServer) RevokeSandboxDelegation(ctx context.Context, req api.RevokeSandboxDelegationRequestObject) (api.RevokeSandboxDelegationResponseObject, error) {
	ctx, actor, err := sandboxDelegationActor(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	repo, ok := s.sandboxes.(sandboxDelegationRepository)
	if !ok {
		return nil, sandboxUnavailable()
	}
	if req.DelegationId == uuid.Nil {
		return nil, apierr.BadRequest("invalid_sandbox_delegation", "invalid delegation ID")
	}
	if err = repo.RevokeDelegation(ctx, req.OrgId, actor, req.DelegationId); err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	return api.RevokeSandboxDelegation204Response{}, nil
}
