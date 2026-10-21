package http

import (
	"bytes"
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
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/apps/api/internal/vault"
)

func vaultSecurityPrincipal(org, user uuid.UUID, role string) *authctx.Principal {
	return &authctx.Principal{UserID: user, SessionID: "vault-security-session", EmailVerified: true,
		AuthMethod: authctx.AuthLocalPassword, Roles: map[uuid.UUID]string{org: role}}
}

func vaultSecurityRouter(t *testing.T, d Deps) http.Handler {
	t.Helper()
	h, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), d)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func vaultSecurityRequest(h http.Handler, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "tunnex_session", Value: "vault-security-session"})
	if csrf {
		r.Header.Set("X-Tunnex-CSRF", "1")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Exercise the generated route and shared middleware, rather than just a
// service call, so browser-only policy cannot accidentally differ by endpoint.
func TestVaultRouterRequiresVerifiedHumanBrowserIdentity(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	base := "/api/v1/organizations/" + org.String() + "/vault"
	principal := func() *authctx.Principal { return vaultSecurityPrincipal(org, user, "member") }
	cases := []struct {
		name string
		edit func(*authctx.Principal) *authctx.Principal
		want int
	}{
		{"signed out", func(*authctx.Principal) *authctx.Principal { return nil }, 401},
		{"unverified", func(p *authctx.Principal) *authctx.Principal { p.EmailVerified = false; return p }, 403},
		{"forced password change", func(p *authctx.Principal) *authctx.Principal { p.MustChangePassword = true; return p }, 403},
		{"no browser session", func(p *authctx.Principal) *authctx.Principal { p.SessionID = ""; return p }, 403},
		{"no human identity", func(p *authctx.Principal) *authctx.Principal { p.UserID = uuid.Nil; return p }, 403},
		{"CLI credential", func(p *authctx.Principal) *authctx.Principal { p.AuthMethod = authctx.AuthBearer; return p }, 403},
		{"unknown authentication method", func(p *authctx.Principal) *authctx.Principal { p.AuthMethod = "unknown"; return p }, 403},
		{"machine", func(*authctx.Principal) *authctx.Principal {
			return authctx.NewMachinePrincipal(user, uuid.New(), org, "vault test", "owner", "")
		}, 403},
		{"agent", func(*authctx.Principal) *authctx.Principal {
			return authctx.NewAgentPrincipal(uuid.New(), org, "vault test", "owner", user, "")
		}, 403},
		{"foreign organization", func(p *authctx.Principal) *authctx.Principal {
			p.Roles = map[uuid.UUID]string{uuid.New(): "owner"}
			return p
		}, 404},
		{"ungranted role", func(p *authctx.Principal) *authctx.Principal { p.Roles[org] = "ai-view"; return p }, 403},
		{"verified browser reaches dependency", func(p *authctx.Principal) *authctx.Principal { return p }, 503},
		{"verified SSO browser reaches dependency", func(p *authctx.Principal) *authctx.Principal { p.AuthMethod = authctx.AuthSSO; return p }, 503},
	}
	paths := []struct{ method, path, body string }{
		{"GET", "/entries", ""}, {"GET", "/services", ""},
		{"POST", "/entries", `{"title":"Test","kind":"password","secret":"test-only-value","visibility":"personal","service_name":"Example"}`},
		{"POST", "/entries/" + uuid.NewString() + "/reveal", `{}`},
		{"GET", "/entries/" + uuid.NewString() + "/versions", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.edit(principal())
			h := vaultSecurityRouter(t, Deps{AuthFn: func(*http.Request) *authctx.Principal { return p }})
			for _, route := range paths {
				w := vaultSecurityRequest(h, route.method, base+route.path, route.body, true)
				if w.Code != tc.want {
					t.Fatalf("%s %s: got %d want %d: %s", route.method, route.path, w.Code, tc.want, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("Vault response was cacheable")
				}
			}
		})
	}
}

func TestVaultRouterRejectsUnsafeAndSecretBearingInvalidRequests(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	p := vaultSecurityPrincipal(org, user, "admin")
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{13}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	h, err := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{
		Vault: vault.New(nil, sealer), AuthFn: func(*http.Request) *authctx.Principal { return p },
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/organizations/" + org.String() + "/vault"
	for _, route := range []struct{ method, path, body string }{
		{"POST", "/entries", `{"title":"Test","kind":"password","secret":"test-only-value","visibility":"personal","service_name":"Example"}`},
		{"POST", "/services", `{"name":"Example"}`},
		{"POST", "/entries/" + uuid.NewString() + "/reveal", `{}`},
		{"PUT", "/entries/" + uuid.NewString(), `{"title":"Test","secret":"test-only-value","expected_version":1}`},
		{"DELETE", "/entries/" + uuid.NewString() + "?expected_version=1", ""},
	} {
		w := vaultSecurityRequest(h, route.method, base+route.path, route.body, false)
		if w.Code != 403 {
			t.Fatalf("%s %s accepted without CSRF: %d", route.method, route.path, w.Code)
		}
	}
	const marker = "vault-validation-secret-must-never-be-echoed"
	invalid := []struct{ name, body string }{
		{"invalid enum", `{"title":"Test","kind":"invalid","secret":"` + marker + `","visibility":"personal","service_name":"Example"}`},
		{"wrong secret type", `{"title":"Test","kind":"password","secret":{"private":"` + marker + `"},"visibility":"personal","service_name":"Example"}`},
		{"unknown field", `{"title":"Test","kind":"password","secret":"` + marker + `","visibility":"personal","service_name":"Example","unknown":true}`},
		{"trailing data", `{"title":"Test","kind":"password","secret":"` + marker + `","visibility":"personal","service_name":"Example"} trailing`},
		{"oversized body", strings.Repeat(" ", 65537) + `{"secret":"` + marker + `"}`},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			w := vaultSecurityRequest(h, "POST", base+"/entries", tc.body, true)
			if w.Code != 400 && w.Code != 413 {
				t.Fatalf("invalid Vault body: got %d want400/413: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), marker) || strings.Contains(logs.String(), marker) {
				t.Fatal("secret leaked through validation response or request log")
			}
		})
	}
	// An unauthenticated caller must not reach the secret-bearing parser, even
	// when the body would otherwise fail both syntax and size validation.
	p = nil
	w := vaultSecurityRequest(h, "POST", base+"/entries", strings.Repeat("x", 65537), true)
	if w.Code != 401 {
		t.Fatalf("anonymous malformed write reached validation: %d", w.Code)
	}
}

func TestVaultRouterPrivateAndAssignedVersionAuthority(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, owner, admin, other, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Vault security',$2)`, org, "vault-security-"+org.String())
	for user, role := range map[uuid.UUID]string{owner: "member", admin: "admin", other: "member"} {
		exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Vault test user',now())`, user, user.String()+"@example.test")
		exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, org, user, role)
	}
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Vault recipients')`, group, org)
	exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, org, group, owner)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{17}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	actor := owner
	roles := map[uuid.UUID]string{owner: "member", admin: "admin", other: "member"}
	h := vaultSecurityRouter(t, Deps{Vault: vault.New(pool, sealer), AuthFn: func(*http.Request) *authctx.Principal {
		return vaultSecurityPrincipal(org, actor, roles[actor])
	}})
	base := "/api/v1/organizations/" + org.String() + "/vault"
	call := func(user uuid.UUID, method, path string, body any, want int) []byte {
		t.Helper()
		actor = user
		var encoded []byte
		if body != nil {
			var e error
			encoded, e = json.Marshal(body)
			if e != nil {
				t.Fatal(e)
			}
		}
		w := vaultSecurityRequest(h, method, base+path, string(encoded), true)
		if w.Code != want {
			t.Fatalf("%s %s got%d want%d: %s", method, path, w.Code, want, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("Vault response cache policy missing")
		}
		return w.Body.Bytes()
	}
	const first = "vault-http-personal-first-secret"
	const second = "vault-http-personal-second-secret"
	created := call(owner, "POST", "/entries", map[string]any{"title": "Personal login", "kind": "password", "secret": first, "visibility": "personal", "service_name": "Private service", "username": "first-user"}, 201)
	if bytes.Contains(created, []byte(first)) {
		t.Fatal("create response leaked secret")
	}
	var entry api.VaultEntry
	if err = json.Unmarshal(created, &entry); err != nil {
		t.Fatal(err)
	}
	entryPath := "/entries/" + entry.Id.String()
	for _, user := range []uuid.UUID{admin, other} {
		listed := call(user, "GET", "/entries", nil, 200)
		if bytes.Contains(listed, []byte(entry.Id.String())) || bytes.Contains(listed, []byte("Private service")) {
			t.Fatal("private entry leaked into another user's index")
		}
		call(user, "POST", entryPath+"/reveal", map[string]any{}, 404)
		call(user, "GET", entryPath+"/versions", nil, 404)
		call(user, "PUT", entryPath, map[string]any{"title": "Unauthorized", "secret": "replacement-test-value", "expected_version": 1}, 404)
		call(user, "DELETE", entryPath+"?expected_version=1", nil, 404)
	}
	call(owner, "PUT", entryPath, map[string]any{"title": "Personal login", "secret": second, "username": "second-user", "expected_version": 1}, 200)
	call(owner, "PUT", entryPath, map[string]any{"title": "Stale write", "secret": "must-not-save", "expected_version": 1}, 409)
	history := call(owner, "GET", entryPath+"/versions", nil, 200)
	if bytes.Contains(history, []byte(first)) || bytes.Contains(history, []byte(second)) {
		t.Fatal("version metadata leaked secret")
	}
	var versions api.VaultHistory
	if err = json.Unmarshal(history, &versions); err != nil {
		t.Fatal(err)
	}
	if versions.Total != 2 || versions.CurrentVersion != 2 {
		t.Fatal("history lost versions or accepted a stale write")
	}
	for version, want := range map[int]string{1: first, 2: second} {
		body := call(owner, "POST", entryPath+"/reveal", map[string]any{"version": version}, 200)
		var revealed api.VaultSecret
		if err = json.Unmarshal(body, &revealed); err != nil {
			t.Fatal(err)
		}
		if revealed.Value != want || revealed.Version != version {
			t.Fatal("old/current version reveal did not match its immutable value")
		}
	}
	serviceBody := call(admin, "POST", "/services", map[string]any{"name": "Assigned service"}, 201)
	var service api.VaultService
	if err = json.Unmarshal(serviceBody, &service); err != nil {
		t.Fatal(err)
	}
	assignedBody := call(admin, "POST", "/entries", map[string]any{"title": "Group API key", "kind": "api_key", "secret": "vault-http-assigned-api-key", "visibility": "assigned", "service_id": service.Id, "subject_kind": "group", "subject_id": group}, 201)
	var assigned api.VaultEntry
	if err = json.Unmarshal(assignedBody, &assigned); err != nil {
		t.Fatal(err)
	}
	assignedPath := "/entries/" + assigned.Id.String()
	call(owner, "POST", assignedPath+"/reveal", map[string]any{}, 200)
	call(owner, "GET", assignedPath+"/versions", nil, 200)
	call(other, "POST", assignedPath+"/reveal", map[string]any{}, 404)
	// Recipient authority includes rotation/history, never deleting the assignment.
	call(owner, "PUT", assignedPath, map[string]any{"title": "Group API key", "secret": "vault-http-assigned-rotated-key", "expected_version": 1}, 200)
	call(owner, "DELETE", assignedPath+"?expected_version=2", nil, 403)
	exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, owner)
	call(owner, "POST", assignedPath+"/reveal", map[string]any{}, 404)
	call(owner, "GET", assignedPath+"/versions", nil, 404)
	call(admin, "POST", assignedPath+"/reveal", map[string]any{"version": 1}, 200)
	call(admin, "DELETE", assignedPath+"?expected_version=2", nil, 204)
	call(admin, "POST", assignedPath+"/reveal", map[string]any{}, 404)
	exec(`UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, org, owner)
	call(owner, "POST", entryPath+"/reveal", map[string]any{}, 403)
	var audit string
	if err = pool.QueryRow(ctx, `SELECT coalesce(string_agg(metadata::text,''),'') FROM audit_logs WHERE org_id=$1 AND action LIKE 'vault.%'`, org).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{first, second, "vault-http-assigned-api-key", "vault-http-assigned-rotated-key"} {
		if strings.Contains(audit, secret) {
			t.Fatal("audit metadata leaked secret")
		}
	}
}
