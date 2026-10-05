package http

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type sandboxSetupRepository interface {
	Setup(context.Context, uuid.UUID, uuid.UUID) (sandboxes.SetupStatus, error)
	UpdateSetup(context.Context, uuid.UUID, uuid.UUID, sandboxes.SetupSettings, sandboxes.SetupSettings, bool) error
	PublishTemplate(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool, bool) error
}

func (s apiServer) sandboxSetupActor(ctx context.Context, org uuid.UUID, permission rbac.Permission) (uuid.UUID, sandboxSetupRepository, error) {
	actor, err := s.sandboxActor(ctx, org, permission)
	if err != nil {
		return uuid.Nil, nil, err
	}
	repo, ok := s.sandboxes.(sandboxSetupRepository)
	if !ok {
		return uuid.Nil, nil, apierr.New(503, "sandbox_setup_unavailable", "sandbox setup support is unavailable")
	}
	return actor, repo, nil
}
func (s apiServer) sandboxCreationStatus(v sandboxes.SetupStatus) api.SandboxCreationStatus {
	ready := s.sandboxProvisioningReady != nil && s.sandboxProvisioningReady()
	reasons := append([]string{}, v.BlockedReasons...)
	if !ready {
		reasons = append(reasons, "runtime_not_ready")
	}
	enrollmentRequired := s.runnerEnrollment != nil
	return api.SandboxCreationStatus{RunnerEnrollmentRequired: &enrollmentRequired, CanAdmin: v.CanAdmin, CanManageCatalog: v.CanManageCatalog, RuntimeReady: ready, BlockedReasons: reasons, RequiresTerminalDevice: v.RequiresTerminalDevice, TerminalGatewayId: v.TerminalGatewayID}
}
func sandboxTemplateResponse(t sandboxes.Template) api.SandboxTemplate {
	skills := t.AllowedSkills
	if skills == nil {
		skills = []uuid.UUID{}
	}
	out := api.SandboxTemplate{Id: t.ID, Name: t.Name, ImageDigest: t.ImageDigest, MaximumScope: sandboxScopes(t.MaximumScope), MemoryMib: int(t.MemoryMiB), MaxTtlSeconds: int(t.MaxTTLSeconds), AllowedSkillRevisionIds: skills}
	if measured := sandboxes.ImageProfileForDigest(t.ImageDigest); measured != nil {
		raw, _ := json.Marshal(measured)
		var profile api.SandboxImageProfile
		if json.Unmarshal(raw, &profile) == nil {
			out.ImageProfile = &profile
		}
	}
	return out
}
func sandboxCandidateProfiles() []api.SandboxImageProfile {
	raw, _ := json.Marshal(sandboxes.CandidateImageProfiles())
	out := []api.SandboxImageProfile{}
	if json.Unmarshal(raw, &out) != nil {
		return []api.SandboxImageProfile{}
	}
	return out
}

func (s apiServer) sandboxSetupResponse(v sandboxes.SetupStatus) api.SandboxSetup {
	profiles := sandboxCandidateProfiles()
	out := api.SandboxSetup{CandidateProfiles: &profiles, Settings: api.SandboxSetupSettings{Enabled: v.Settings.Enabled, MaxPerUser: int(v.Settings.MaxPerUser), MaxTotal: int(v.Settings.MaxTotal)}, PolicyMode: v.PolicyMode, CreationStatus: s.sandboxCreationStatus(v), Catalog: []api.SandboxCatalogEntry{}}
	if limits := v.RuntimeLimits; limits != nil {
		out.RuntimeLimits = &api.SandboxBoundedRuntimeLimits{MaxRetained: int(limits.MaxRetained), MaxWorkloads: int(limits.MaxWorkloads), Retained: limits.Retained, Workloads: limits.Workloads, ReservationId: limits.ReservationID}
		if limits.ReservationState != "" {
			state := api.SandboxBoundedRuntimeLimitsReservationState(limits.ReservationState)
			out.RuntimeLimits.ReservationState = &state
		}
	}
	for _, entry := range v.Catalog {
		out.Catalog = append(out.Catalog, api.SandboxCatalogEntry{Template: sandboxTemplateResponse(entry.Template), Enabled: entry.Enabled, RuntimeCompatible: entry.RuntimeCompatible})
	}
	return out
}
func (s apiServer) GetSandboxSetup(ctx context.Context, req api.GetSandboxSetupRequestObject) (api.GetSandboxSetupResponseObject, error) {
	actor, repo, err := s.sandboxSetupActor(ctx, req.OrgId, rbac.PermSandboxAdmin)
	if err != nil {
		return nil, err
	}
	result, err := repo.Setup(ctx, req.OrgId, actor)
	if err != nil {
		return nil, sandboxError(err)
	}
	if !result.CanAdmin {
		return nil, sandboxError(sandboxes.ErrForbidden)
	}
	return api.GetSandboxSetup200JSONResponse{Body: s.sandboxSetupResponse(result), Headers: api.GetSandboxSetup200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) UpdateSandboxSetup(ctx context.Context, req api.UpdateSandboxSetupRequestObject) (api.UpdateSandboxSetupResponseObject, error) {
	actor, repo, err := s.sandboxSetupActor(ctx, req.OrgId, rbac.PermSandboxAdmin)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_sandbox_setup", "settings are required")
	}
	convert := func(v api.SandboxSetupSettings) sandboxes.SetupSettings {
		return sandboxes.SetupSettings{Enabled: v.Enabled, MaxPerUser: int32(v.MaxPerUser), MaxTotal: int32(v.MaxTotal)}
	}
	// Validate before narrowing request integers; direct generated-handler calls must also fail closed.
	for _, v := range []api.SandboxSetupSettings{req.Body.Expected, req.Body.Settings} {
		if v.MaxPerUser < 1 || v.MaxPerUser > 100 || v.MaxTotal < 1 || v.MaxTotal > 10000 {
			return nil, sandboxError(sandboxes.ErrInvalid)
		}
	}
	ready := s.sandboxProvisioningReady != nil && s.sandboxProvisioningReady()
	if err = repo.UpdateSetup(ctx, req.OrgId, actor, convert(req.Body.Expected), convert(req.Body.Settings), ready); err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	result, err := repo.Setup(ctx, req.OrgId, actor)
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.UpdateSandboxSetup200JSONResponse{Body: s.sandboxSetupResponse(result), Headers: api.UpdateSandboxSetup200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
func (s apiServer) PublishSandboxTemplate(ctx context.Context, req api.PublishSandboxTemplateRequestObject) (api.PublishSandboxTemplateResponseObject, error) {
	actor, repo, err := s.sandboxSetupActor(ctx, req.OrgId, rbac.PermSandboxTemplateManage)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, sandboxError(sandboxes.ErrInvalid)
	}
	if err = repo.PublishTemplate(ctx, req.OrgId, actor, req.TemplateId, req.Body.ExpectedEnabled, req.Body.Enabled); err != nil {
		return nil, sandboxError(err)
	}
	if s.sandboxWake != nil {
		s.sandboxWake()
	}
	result, err := repo.Setup(ctx, req.OrgId, actor)
	if err != nil {
		return nil, sandboxError(err)
	}
	return api.PublishSandboxTemplate200JSONResponse{Body: s.sandboxSetupResponse(result), Headers: api.PublishSandboxTemplate200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
