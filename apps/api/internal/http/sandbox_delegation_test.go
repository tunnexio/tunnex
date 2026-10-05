package http

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type delegationRepoStub struct {
	calls      int
	owner, org uuid.UUID
}

func (s *delegationRepoStub) SetDelegationEnabled(context.Context, uuid.UUID, uuid.UUID, bool) error {
	s.calls++
	return nil
}
func (s *delegationRepoStub) IssueDelegation(_ context.Context, org, owner uuid.UUID, d sandboxes.Delegation) (sandboxes.Delegation, error) {
	s.calls++
	s.owner = owner
	s.org = org
	d.ID = uuid.New()
	return d, nil
}
func (s *delegationRepoStub) RevokeDelegation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	s.calls++
	return nil
}
func TestSandboxDelegationHTTPHumanBoundary(t *testing.T) {
	org, owner := uuid.New(), uuid.New()
	repo := &delegationRepoStub{}
	router := chi.NewRouter()
	RegisterSandboxDelegationRoutes(router, repo)
	human := &authctx.Principal{UserID: owner, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}, EmailVerified: true}
	request := func(p *authctx.Principal, method, path, body string) int {
		r := httptest.NewRequest(method, "/api/v1/organizations/"+org.String()+path, strings.NewReader(body))
		r = r.WithContext(authctx.WithPrincipal(r.Context(), p))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if got := request(human, http.MethodPut, "/sandbox-delegation-settings", `{"enabled":true}`); got != 204 {
		t.Fatalf("settings: %d", got)
	}
	if got := request(human, http.MethodPost, "/sandbox-delegations", `{"machine_id":"`+uuid.NewString()+`","template_id":"`+uuid.NewString()+`","max_ttl_seconds":900,"max_active":1,"maximum_scope":[],"skill_revision_ids":[],"expires_at":"2099-01-01T00:00:00Z"}`); got != 201 || repo.owner != owner || repo.org != org {
		t.Fatalf("grant owner binding: %d", got)
	}
	before := repo.calls
	for _, p := range []*authctx.Principal{authctx.NewMachinePrincipal(owner, uuid.New(), org, "machine", rbac.RoleOwner, ""), authctx.NewAgentPrincipal(uuid.New(), org, "node", rbac.RoleOwner, owner, ""), {UserID: owner, Roles: map[uuid.UUID]string{org: rbac.RoleMember}, EmailVerified: true}, {UserID: owner, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}, EmailVerified: true}} {
		if got := request(p, http.MethodPut, "/sandbox-delegation-settings", `{"enabled":true}`); got < 400 {
			t.Fatalf("escalation: %d", got)
		}
	}
	if got := request(human, http.MethodPost, "/sandbox-delegations", `{"owner_id":"`+uuid.NewString()+`"}`); got != 400 {
		t.Fatalf("client ownership: %d", got)
	}
	if got := request(human, http.MethodPut, "/sandbox-delegation-settings", `{}`); got != 400 {
		t.Fatalf("missing opt-in: %d", got)
	}
	if repo.calls != before {
		t.Fatal("denied caller reached store")
	}
}
func TestSandboxMachineCatalogAndLifecycleBoundary(t *testing.T) {
	org, owner := uuid.New(), uuid.New()
	repo := &sandboxStub{}
	server := apiServer{sandboxes: repo}
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewMachinePrincipal(owner, uuid.New(), org, "machine", rbac.RoleOperator, ""))
	if actor, err := server.sandboxLifecycleActor(ctx, org, rbac.PermSandboxCreate); err != nil || actor != owner {
		t.Fatal("machine identity did not reach transactional store seam", err)
	}
	if _, err := server.sandboxActor(ctx, org, rbac.PermSandboxView); err == nil {
		t.Fatal("human-only seam expanded")
	}
	if _, err := server.sandboxLifecycleActor(ctx, uuid.New(), rbac.PermSandboxView); err == nil {
		t.Fatal("cross-org lifecycle")
	}
}
