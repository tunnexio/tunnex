package http

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

type generatedDelegationRepo struct {
	sandboxStub
	delegationRepoStub
}

func TestSandboxDelegationGeneratedRouter(t *testing.T) {
	org, owner := uuid.New(), uuid.New()
	repo := &generatedDelegationRepo{}
	principal := &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	handler, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Sandboxes: repo, Orgs: tenancy.NewService(nil), AuthFn: func(*http.Request) *authctx.Principal { return principal }})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/organizations/"+org.String()+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request(http.MethodPut, "/sandbox-delegation-settings", `{"enabled":true}`); w.Code != 204 {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	machine, template := uuid.New(), uuid.New()
	body := `{"machine_id":"` + machine.String() + `","template_id":"` + template.String() + `","max_ttl_seconds":900,"max_active":1,"maximum_scope":[],"skill_revision_ids":[],"expires_at":"2099-01-01T00:00:00Z"}`
	w := request(http.MethodPost, "/sandbox-delegations", body)
	if w.Code != 201 {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var grant api.SandboxDelegation
	if err = json.Unmarshal(w.Body.Bytes(), &grant); err != nil || grant.OwnerId == nil || *grant.OwnerId != owner || grant.OrganizationId == nil || *grant.OrganizationId != org || grant.Id == nil || grant.MachineId != machine || grant.TemplateId != template || repo.owner != owner || repo.delegationRepoStub.org != org {
		t.Fatalf("server-owned grant identity: %+v %v", grant, err)
	}
	if w = request(http.MethodDelete, "/sandbox-delegations/"+grant.Id.String(), ""); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	before := repo.delegationRepoStub.calls
	principal = nil
	for _, route := range []struct{ method, path string }{{http.MethodPost, "/saved-ssh-keys"}, {http.MethodDelete, "/saved-ssh-keys/not-a-uuid"}, {http.MethodPut, "/saved-ssh-keys/not-a-uuid/default"}, {http.MethodPut, "/sandbox-setup"}, {http.MethodPut, "/sandbox-catalog/not-a-uuid"}, {http.MethodPut, "/cross-gateway-settings"}} {
		if w = request(route.method, route.path, "malformed JSON"); w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous sandbox caller reached validation: %d %s", w.Code, w.Body.String())
		}
	}
	for _, p := range []*authctx.Principal{nil, authctx.NewMachinePrincipal(owner, uuid.New(), org, "machine", rbac.RoleOwner, ""), authctx.NewAgentPrincipal(uuid.New(), org, "node", rbac.RoleOwner, owner, ""), {UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}} {
		principal = p
		for _, route := range []struct{ method, path string }{{http.MethodPut, "/sandbox-delegation-settings"}, {http.MethodPost, "/sandbox-delegations"}, {http.MethodDelete, "/sandbox-delegations/" + uuid.NewString()}} {
			w = request(route.method, route.path, "malformed JSON")
			if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized caller reached validation: %d %s", w.Code, w.Body.String())
			}
		}
	}
	principal = &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	for _, invalid := range []string{`{}`, strings.TrimSuffix(body, "}") + `,"owner_id":"` + uuid.NewString() + `"}`, strings.Replace(body, `"max_active":1`, `"max_active":2147483648`, 1)} {
		w = request(http.MethodPost, "/sandbox-delegations", invalid)
		if w.Code != 400 {
			t.Fatalf("invalid grant: %d %s", w.Code, w.Body.String())
		}
	}
	if w = request(http.MethodPut, "/sandbox-delegation-settings", `{}`); w.Code != 400 {
		t.Fatalf("implicit opt-in accepted: %d %s", w.Code, w.Body.String())
	}
	if repo.delegationRepoStub.calls != before {
		t.Fatal("denied request reached delegation store")
	}
}
