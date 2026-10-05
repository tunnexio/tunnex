package http

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
)

type sandboxCreationAvailability interface {
	CreationAvailable(uuid.UUID, uuid.UUID) bool
}

type sandboxRepository interface {
	Create(context.Context, uuid.UUID, uuid.UUID, sandboxes.CreateInput) (sandboxes.Sandbox, bool, error)
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.Sandbox, error)
	List(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int) (sandboxes.Inventory, error)
	Templates(context.Context, uuid.UUID, uuid.UUID) ([]sandboxes.Template, error)
	SetDesired(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, string) (sandboxes.Sandbox, error)
}

func (s apiServer) sandboxActor(ctx context.Context, org uuid.UUID, permission rbac.Permission) (uuid.UUID, error) {
	if _, err := authorize(ctx, org, permission); err != nil {
		return uuid.Nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if p == nil || p.IsMachine() || p.IsAgent() || p.UserID == uuid.Nil {
		return uuid.Nil, apierr.New(403, "forbidden", "sandboxes require a human user")
	}
	if s.sandboxes == nil {
		return uuid.Nil, sandboxUnavailable()
	}
	return p.UserID, nil
}
func sandboxUnavailable() *apierr.Error {
	return apierr.New(503, "sandbox_runtime_unavailable", "sandbox provisioning is unavailable")
}
func sandboxError(err error) error {
	switch {
	case errors.Is(err, sandboxes.ErrForbidden):
		return apierr.New(403, "forbidden", "sandbox operation forbidden")
	case errors.Is(err, sandboxes.ErrNotFound):
		return apierr.NotFound("sandbox_not_found", "sandbox not found")
	case errors.Is(err, sandboxes.ErrInvalid), errors.Is(err, sandboxscope.ErrInvalidScope):
		return apierr.BadRequest("invalid_sandbox_request", "invalid sandbox request")
	case errors.Is(err, sandboxscope.ErrScopeExceeded):
		return apierr.New(403, "sandbox_scope_exceeded", "requested scope exceeds current access or template limits")
	case errors.Is(err, sandboxes.ErrQuota):
		return apierr.Conflict("sandbox_quota_exceeded", "sandbox quota exceeded")
	case errors.Is(err, sandboxes.ErrConflict):
		return apierr.Conflict("sandbox_generation_conflict", "sandbox state changed; refresh and retry")
	case errors.Is(err, sandboxes.ErrDisabled):
		return sandboxUnavailable()
	default:
		return apierr.Internal()
	}
}
func sandboxScopes(entries []sandboxes.Scope) []api.SandboxScope {
	out := make([]api.SandboxScope, 0, len(entries))
	for _, v := range entries {
		out = append(out, api.SandboxScope{Cidr: v.CIDR, Protocol: api.SandboxScopeProtocol(v.Protocol), PortLow: int(v.PortLow), PortHigh: int(v.PortHigh)})
	}
	return out
}
func sandboxResponse(v sandboxes.Sandbox) api.Sandbox {
	skills := []api.SandboxSkillSelection{}
	for _, item := range v.SelectedSkills {
		skills = append(skills, api.SandboxSkillSelection{RevisionId: item.RevisionID, Configuration: item.Configuration})
	}
	var connection *api.SandboxConnection
	if v.Connection != nil && v.State == sandboxes.StateReady && v.DesiredState == "started" {
		c := v.Connection
		connection = &api.SandboxConnection{Address: c.Address, Username: api.SandboxConnectionUsername(c.Username), Port: api.SandboxConnectionPort(c.Port), HostPublicKey: c.HostPublicKey, HostKeyFingerprint: c.HostKeyFingerprint}
	}
	return api.Sandbox{Connection: connection, SelectedSkills: skills, Id: v.Identity.ID, OrganizationId: v.Identity.OrgID, CreatorId: v.Identity.CreatorID, TemplateId: v.TemplateVersionID, Name: v.Name, RequestedScope: sandboxScopes(v.RequestedScope), DesiredState: api.SandboxDesiredState(v.DesiredState), ObservedState: api.SandboxObservedState(v.State), Generation: v.Revision, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt}
}
func (s apiServer) ListSandboxes(ctx context.Context, req api.ListSandboxesRequestObject) (api.ListSandboxesResponseObject, error) {
	if p, ok := authctx.PrincipalFrom(ctx); ok && (p.IsMachine() || p.IsAgent()) {
		return nil, apierr.New(403, "forbidden", "human catalog access required")
	}

	actor, err := s.sandboxActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	cursor := uuid.Nil
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	limit := 50
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	result, err := s.sandboxes.List(ctx, req.OrgId, actor, cursor, limit)
	if err != nil {
		return nil, sandboxError(err)
	}
	body := api.SandboxList{Items: []api.Sandbox{}, NextCursor: result.NextCursor, CreateAvailable: false}
	if repo, ok := s.sandboxes.(sandboxSetupRepository); ok {
		setup, e := repo.Setup(ctx, req.OrgId, actor)
		if e != nil {
			return nil, sandboxError(e)
		}
		status := s.sandboxCreationStatus(setup)
		body.CreationStatus = &status
		body.CreateAvailable = len(status.BlockedReasons) == 0
	} else {
		body.CreateAvailable = result.OrganizationEnabled && s.sandboxProvisioningReady != nil && s.sandboxProvisioningReady()
		if availability, ok := s.sandboxes.(sandboxCreationAvailability); ok {
			body.CreateAvailable = body.CreateAvailable && availability.CreationAvailable(req.OrgId, actor)
		}
	}
	for _, item := range result.Items {
		body.Items = append(body.Items, sandboxResponse(item))
	}
	return api.ListSandboxes200JSONResponse{Body: body, Headers: api.ListSandboxes200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) GetSandbox(ctx context.Context, req api.GetSandboxRequestObject) (api.GetSandboxResponseObject, error) {
	actor, err := s.sandboxLifecycleActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	item, err := s.sandboxes.Get(ctx, req.OrgId, actor, req.SandboxId)
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.GetSandbox200JSONResponse{Body: sandboxResponse(item), Headers: api.GetSandbox200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) CreateSandbox(ctx context.Context, req api.CreateSandboxRequestObject) (api.CreateSandboxResponseObject, error) {
	actor, err := s.sandboxLifecycleActor(ctx, req.OrgId, rbac.PermSandboxCreate)
	if err != nil {
		return nil, err
	}
	if s.sandboxProvisioningReady == nil || !s.sandboxProvisioningReady() {
		return nil, sandboxUnavailable()
	}
	if req.Body == nil || req.Body.TtlSeconds < 300 || req.Body.TtlSeconds > 86400 || len(req.Body.RequestedScope) > 64 {
		return nil, apierr.BadRequest("invalid_sandbox_request", "invalid sandbox request")
	}
	keys, err := sandboxes.NormalizeSSHPublicKeys(req.Body.SshPublicKeys, 7)
	if err != nil {
		return nil, apierr.BadRequest("invalid_sandbox_ssh_keys", "provide valid SSH public keys")
	}
	input := sandboxes.CreateInput{Name: req.Body.Name, TemplateID: req.Body.TemplateId, TerminalDeviceID: req.Body.TerminalDeviceId, TTLSeconds: int32(req.Body.TtlSeconds), IdempotencyKey: req.Params.IdempotencyKey, Requested: []sandboxes.Scope{}, SSHPublicKeys: keys}
	if req.Body.SelectedSkills != nil {
		if len(*req.Body.SelectedSkills) > 0 && (s.sandboxSkillsReady == nil || !s.sandboxSkillsReady()) {
			return nil, sandboxUnavailable()
		}
		for _, item := range *req.Body.SelectedSkills {
			input.SelectedSkills = append(input.SelectedSkills, sandboxes.SkillSelection{RevisionID: item.RevisionId, Configuration: item.Configuration})
		}
	}
	for _, scope := range req.Body.RequestedScope {
		if scope.PortLow < 0 || scope.PortLow > 65535 || scope.PortHigh < 0 || scope.PortHigh > 65535 {
			return nil, apierr.BadRequest("invalid_sandbox_request", "invalid sandbox scope")
		}
		input.Requested = append(input.Requested, sandboxes.Scope{CIDR: scope.Cidr, Protocol: string(scope.Protocol), PortLow: uint16(scope.PortLow), PortHigh: uint16(scope.PortHigh)})
	}
	item, _, err := s.sandboxes.Create(ctx, req.OrgId, actor, input)
	if err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	return api.CreateSandbox202JSONResponse{Body: sandboxResponse(item), Headers: api.CreateSandbox202ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) SandboxAction(ctx context.Context, req api.SandboxActionRequestObject) (api.SandboxActionResponseObject, error) {
	actor, err := s.sandboxLifecycleActor(ctx, req.OrgId, rbac.PermSandboxManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_sandbox_request", "action body is required")
	}
	if req.Body.DesiredState == "started" && (s.sandboxProvisioningReady == nil || !s.sandboxProvisioningReady()) {
		return nil, sandboxUnavailable()
	}
	item, err := s.sandboxes.SetDesired(ctx, req.OrgId, actor, req.SandboxId, req.Body.Generation, string(req.Body.DesiredState))
	if err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	return api.SandboxAction202JSONResponse{Body: sandboxResponse(item), Headers: api.SandboxAction202ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) ListSandboxTemplates(ctx context.Context, req api.ListSandboxTemplatesRequestObject) (api.ListSandboxTemplatesResponseObject, error) {
	if p, ok := authctx.PrincipalFrom(ctx); ok && (p.IsMachine() || p.IsAgent()) {
		return nil, apierr.New(403, "forbidden", "human catalog access required")
	}

	actor, err := s.sandboxActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	templates, err := s.sandboxes.Templates(ctx, req.OrgId, actor)
	if err != nil {
		return nil, sandboxError(err)
	}
	profiles := sandboxCandidateProfiles()
	body := api.SandboxTemplateList{Items: []api.SandboxTemplate{}, CandidateProfiles: &profiles}
	for _, t := range templates {
		body.Items = append(body.Items, sandboxTemplateResponse(t))
	}
	return api.ListSandboxTemplates200JSONResponse{Body: body, Headers: api.ListSandboxTemplates200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) ListSandboxSkills(ctx context.Context, req api.ListSandboxSkillsRequestObject) (api.ListSandboxSkillsResponseObject, error) {
	if p, ok := authctx.PrincipalFrom(ctx); ok && (p.IsMachine() || p.IsAgent()) {
		return nil, apierr.New(403, "forbidden", "human catalog access required")
	}

	actor, err := s.sandboxActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	body := api.SandboxSkillList{Items: []api.SandboxSkill{}, ConfigurationAvailable: s.sandboxSkillsReady != nil && s.sandboxSkillsReady()}
	if catalog, ok := s.sandboxes.(interface {
		Skills(context.Context, uuid.UUID, uuid.UUID) ([]sandboxes.SkillRevision, error)
	}); ok {
		revisions, e := catalog.Skills(ctx, req.OrgId, actor)
		if e != nil {
			return nil, sandboxError(e)
		}
		for _, revision := range revisions {
			fields := []api.SandboxSkillField{}
			for _, field := range revision.Fields {
				fields = append(fields, api.SandboxSkillField{Key: field.Key, Label: field.Label, Choices: field.Choices, Required: field.Required})
			}
			body.Items = append(body.Items, api.SandboxSkill{Id: revision.ID, UserOwned: revision.UserOwned, CustomSkillId: revision.CustomSkillID, Name: revision.Name, Description: revision.Description, Version: revision.Version, Digest: revision.Digest, Fields: fields, RequiredScope: sandboxScopes(revision.RequiredScope)})
		}
	}
	// Materialization is unqualified; catalogue presence cannot enable selection.
	return api.ListSandboxSkills200JSONResponse{Body: body, Headers: api.ListSandboxSkills200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) sandboxLifecycleActor(ctx context.Context, org uuid.UUID, permission rbac.Permission) (uuid.UUID, error) {
	p, _ := authctx.PrincipalFrom(ctx)
	if p != nil && p.IsMachine() {
		if p.AuthMethod != authctx.AuthMachine || p.UserID != uuid.Nil || p.OwnerUserID == uuid.Nil || p.MustChangePassword {
			return uuid.Nil, apierr.New(403, "forbidden", "sandbox delegation required")
		}
		if _, ok := p.RoleIn(org); !ok {
			return uuid.Nil, apierr.New(403, "forbidden", "sandbox delegation required")
		}
		if s.sandboxes == nil {
			return uuid.Nil, sandboxUnavailable()
		}
		return p.OwnerUserID, nil // store checks current grant, membership and ownership transactionally
	}
	return s.sandboxActor(ctx, org, permission)
}
