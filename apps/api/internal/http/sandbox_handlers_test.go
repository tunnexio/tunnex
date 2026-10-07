package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

type sandboxStub struct {
	calls      int
	created    sandboxes.CreateInput
	org, actor uuid.UUID
}

const sandboxFixtureSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"

func (f *sandboxStub) Create(_ context.Context, org, actor uuid.UUID, in sandboxes.CreateInput) (sandboxes.Sandbox, bool, error) {
	f.calls++
	f.created = in
	f.org = org
	f.actor = actor
	return sandboxes.Sandbox{Identity: sandboxes.Identity{ID: uuid.New(), OrgID: org, CreatorID: actor}, State: sandboxes.StateCreating, Revision: 1, RequestedScope: in.Requested}, false, nil
}
func (f *sandboxStub) Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (sandboxes.Sandbox, error) {
	f.calls++
	return sandboxes.Sandbox{}, sandboxes.ErrNotFound
}
func (f *sandboxStub) List(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int) (sandboxes.Inventory, error) {
	f.calls++
	return sandboxes.Inventory{Items: []sandboxes.Sandbox{}, OrganizationEnabled: true}, nil
}
func (f *sandboxStub) Templates(context.Context, uuid.UUID, uuid.UUID) ([]sandboxes.Template, error) {
	f.calls++
	return []sandboxes.Template{}, nil
}
func (f *sandboxStub) SetDesired(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, string) (sandboxes.Sandbox, error) {
	f.calls++
	return sandboxes.Sandbox{}, sandboxes.ErrConflict
}

func TestSandboxAPIProvisioningAndHumanAuthorization(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	repo := &sandboxStub{}
	server := apiServer{sandboxes: repo}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}})
	req := api.CreateSandboxRequestObject{OrgId: org, Params: api.CreateSandboxParams{IdempotencyKey: "request"}, Body: &api.SandboxCreate{TemplateId: uuid.New(), Name: "work", TtlSeconds: 3600, SshPublicKeys: []string{sandboxFixtureSSHKey}, RequestedScope: []api.SandboxScope{{Cidr: "10.1.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}}}}
	if _, err := server.CreateSandbox(ctx, req); err == nil || repo.calls != 0 {
		t.Fatal("unqualified provisioner created sandbox")
	}
	response, err := server.ListSandboxes(ctx, api.ListSandboxesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	if response.(api.ListSandboxes200JSONResponse).Body.CreateAvailable {
		t.Fatal("unqualified creation advertised")
	}
	server.sandboxProvisioningReady = func() bool { return true }
	terminal := uuid.New()
	req.Body.TerminalDeviceId = &terminal
	if _, err = server.CreateSandbox(ctx, req); err != nil {
		t.Fatal(err)
	}
	if repo.actor != user || repo.org != org || repo.created.IdempotencyKey != "request" {
		t.Fatal("creator association or idempotency lost")
	}
	if repo.created.TerminalDeviceID == nil || *repo.created.TerminalDeviceID != terminal {
		t.Fatal("selected terminal intent lost")
	}
	selected := []api.SandboxSkillSelection{{RevisionId: uuid.New(), Configuration: map[string]string{"format": "short"}}}
	req.Body.SelectedSkills = &selected
	beforeSkills := repo.calls
	if _, err = server.CreateSandbox(ctx, req); err == nil || repo.calls != beforeSkills {
		t.Fatal("unqualified skill materialization accepted")
	}
	server.sandboxSkillsReady = func() bool { return true }
	if _, err = server.CreateSandbox(ctx, req); err != nil || len(repo.created.SelectedSkills) != 1 {
		t.Fatal("qualified skill intent lost", err)
	}
	req.Body.SelectedSkills = nil
	before := repo.calls
	for _, p := range []*authctx.Principal{
		{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}},
		{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAIAdmin}},
		{UserID: user, MachineID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
		{UserID: user, AuthMethod: authctx.AuthAgent, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
	} {
		if _, err = server.CreateSandbox(authctx.WithPrincipal(context.Background(), p), req); err == nil {
			t.Fatal("unauthorized principal created")
		}
	}
	if repo.calls != before {
		t.Fatal("unauthorized principal reached store")
	}
}

func TestSandboxCreationStatusOrganizationTerminalSelection(t *testing.T) {
	gateway := uuid.New()
	server := apiServer{sandboxProvisioningReady: func() bool { return true }}
	status := server.sandboxCreationStatus(sandboxes.SetupStatus{RequiresTerminalDevice: true, TerminalGatewayID: &gateway})
	if !status.RequiresTerminalDevice || status.TerminalGatewayId == nil || *status.TerminalGatewayId != gateway || !status.RuntimeReady {
		t.Fatal("organization terminal selection requirements missing from wire response")
	}
	legacy := server.sandboxCreationStatus(sandboxes.SetupStatus{})
	if legacy.RequiresTerminalDevice || legacy.TerminalGatewayId != nil {
		t.Fatal("legacy binding unexpectedly requires request terminal selection")
	}
}
func TestSandboxGeneratedRoutesSeparateFromAgents(t *testing.T) {
	org := uuid.New()
	repo := &sandboxStub{}
	handler, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Sandboxes: repo, Orgs: tenancy.NewService(nil), AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"sandboxes", "sandbox-templates", "sandbox-skills"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+org.String()+"/"+suffix, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: %d %s", suffix, rr.Code, rr.Body.String())
		}
	}
	if repo.calls != 0 {
		t.Fatal("unexpected repository calls")
	}
}
