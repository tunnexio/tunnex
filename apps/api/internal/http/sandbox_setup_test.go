package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"testing"
)

type setupStub struct {
	sandboxStub
	calls  int
	ready  bool
	limits *sandboxes.BoundedRuntimeLimits
}

func (s *setupStub) Setup(context.Context, uuid.UUID, uuid.UUID) (sandboxes.SetupStatus, error) {
	s.calls++
	return sandboxes.SetupStatus{CanAdmin: true, CanManageCatalog: true, BlockedReasons: []string{"organization_disabled"}, RuntimeLimits: s.limits}, nil
}

func TestSandboxSetupExposesReservationAndWorkloadLimitsWithoutInventingReady(t *testing.T) {
	org, user, historical := uuid.New(), uuid.New(), uuid.New()
	repo := &setupStub{limits: &sandboxes.BoundedRuntimeLimits{MaxRetained: 2, MaxWorkloads: 1, Retained: 1, Workloads: 0, ReservationID: &historical, ReservationState: "pending"}}
	server := apiServer{sandboxes: repo}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}})
	response, err := server.GetSandboxSetup(ctx, api.GetSandboxSetupRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	body := response.(api.GetSandboxSetup200JSONResponse).Body
	if body.RuntimeLimits == nil || body.RuntimeLimits.MaxRetained != 2 || body.RuntimeLimits.MaxWorkloads != 1 || body.RuntimeLimits.Workloads != 0 || body.RuntimeLimits.ReservationId == nil || *body.RuntimeLimits.ReservationId != historical || body.RuntimeLimits.ReservationState == nil || *body.RuntimeLimits.ReservationState != "pending" || body.CreationStatus.RuntimeReady {
		t.Fatal("reservation/readiness contract", body)
	}
	repo.limits = nil
	response, err = server.GetSandboxSetup(ctx, api.GetSandboxSetupRequestObject{OrgId: org})
	if err != nil || response.(api.GetSandboxSetup200JSONResponse).Body.RuntimeLimits != nil {
		t.Fatal("invented unbounded limits", response, err)
	}
}
func (s *setupStub) UpdateSetup(_ context.Context, _ uuid.UUID, _ uuid.UUID, _, _ sandboxes.SetupSettings, ready bool) error {
	s.calls++
	s.ready = ready
	return nil
}
func (s *setupStub) PublishTemplate(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool, bool) error {
	s.calls++
	return nil
}
func TestSandboxSetupHandlersHumanPermissionsAndRuntimeTruth(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	repo := &setupStub{}
	server := apiServer{sandboxes: repo}
	for _, principal := range []*authctx.Principal{
		{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}},
		{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}},
		{UserID: user, MachineID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
		{UserID: user, AuthMethod: authctx.AuthAgent, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
	} {
		ctx := authctx.WithPrincipal(context.Background(), principal)
		if _, err := server.GetSandboxSetup(ctx, api.GetSandboxSetupRequestObject{OrgId: org}); err == nil {
			t.Fatal("unauthorized setup read")
		}
		if _, err := server.UpdateSandboxSetup(ctx, api.UpdateSandboxSetupRequestObject{OrgId: org}); err == nil {
			t.Fatal("unauthorized update")
		}
		if _, err := server.PublishSandboxTemplate(ctx, api.PublishSandboxTemplateRequestObject{OrgId: org}); err == nil {
			t.Fatal("unauthorized catalog write")
		}
	}
	if repo.calls != 0 {
		t.Fatal("unauthorized principal reached store")
	}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}})
	response, err := server.GetSandboxSetup(ctx, api.GetSandboxSetupRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	status := response.(api.GetSandboxSetup200JSONResponse).Body.CreationStatus
	if status.RuntimeReady || len(status.BlockedReasons) != 2 {
		t.Fatal("admin identity invented runtime readiness", status)
	}
	body := api.SandboxSetupUpdate{Expected: api.SandboxSetupSettings{MaxPerUser: 2, MaxTotal: 20}, Settings: api.SandboxSetupSettings{Enabled: true, MaxPerUser: 2, MaxTotal: 20}}
	if _, err = server.UpdateSandboxSetup(ctx, api.UpdateSandboxSetupRequestObject{OrgId: org, Body: &body}); err != nil || repo.ready {
		t.Fatal("admin supplied runtime proof", err)
	}
}

func TestSandboxImageMetadataExactIdentityAndCandidateSeparation(t *testing.T) {
	candidates := sandboxes.CandidateImageProfiles()
	if len(candidates) != 6 {
		t.Fatal("missing profiles")
	}
	for _, candidate := range candidates {
		got := sandboxTemplateResponse(sandboxes.Template{ID: uuid.New(), ImageDigest: candidate.ConfigDigest})
		if got.ImageProfile == nil || got.ImageProfile.ImageDigest != candidate.ImageDigest || got.ImageProfile.Qualification != "candidate" {
			t.Fatal("exact image measurements lost")
		}
	}
	if sandboxTemplateResponse(sandboxes.Template{Name: "Ubuntu", ImageDigest: "sha256:unknown"}).ImageProfile != nil {
		t.Fatal("fabricated Ubuntu measurements")
	}
	repo := &setupStub{}
	server := apiServer{sandboxes: repo}
	org := uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}})
	response, err := server.ListSandboxTemplates(ctx, api.ListSandboxTemplatesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	body := response.(api.ListSandboxTemplates200JSONResponse).Body
	if len(body.Items) != 0 || body.CandidateProfiles == nil || len(*body.CandidateProfiles) != 6 {
		t.Fatal("candidate metadata became launchable template", body)
	}
}
