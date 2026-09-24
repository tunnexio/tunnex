package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type settingsFake struct {
	calls      int
	org, actor uuid.UUID
	enabled    bool
	revision   int64
	result     ipsec.Settings
	err        error
	scoped     bool
}

func (f *settingsFake) Read(ctx context.Context, org uuid.UUID) (ipsec.Settings, error) {
	f.calls++
	f.org = org
	scoped, ok := authctx.OrgFrom(ctx)
	f.scoped = ok && scoped == org
	return f.result, f.err
}
func (f *settingsFake) Configure(ctx context.Context, org, actor uuid.UUID, enabled bool, rev int64) (ipsec.Settings, error) {
	f.actor = actor
	f.enabled = enabled
	f.revision = rev
	return f.Read(ctx, org)
}
func settingsContext(org, user uuid.UUID, role string, verified bool) context.Context {
	return authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: verified, Roles: map[uuid.UUID]string{org: role}})
}
func TestIPsecSettingsAuthorization(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		status int
		code   string
	}{
		{"anonymous", context.Background(), 401, "unauthenticated"}, {"cross-org", settingsContext(uuid.New(), user, rbac.RoleOwner, true), 404, "org_not_found"}, {"member", settingsContext(org, user, rbac.RoleMember, true), 403, "forbidden"}, {"unverified", settingsContext(org, user, rbac.RoleOwner, false), 403, "email_not_verified"}, {"operator", settingsContext(org, user, rbac.RoleOperator, true), 403, "forbidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &settingsFake{}
			_, err := (apiServer{ipsecSettings: f}).SetIPsecSettings(tc.ctx, api.SetIPsecSettingsRequestObject{OrgId: org})
			if !hasCode(err, tc.status, tc.code) || f.calls != 0 {
				t.Fatalf("authority must precede validation/store: %v calls=%d", err, f.calls)
			}
		})
	}
	for _, role := range []string{rbac.RoleMember, rbac.RoleOwner, rbac.RoleAdmin} {
		f := &settingsFake{}
		r, err := (apiServer{ipsecSettings: f}).GetIPsecSettings(settingsContext(org, user, role, false), api.GetIPsecSettingsRequestObject{OrgId: org})
		if err != nil || !f.scoped || f.org != org {
			t.Fatalf("scoped read: %v", err)
		}
		b, _ := json.Marshal(r.(api.GetIPsecSettings200JSONResponse).Body)
		if string(b) != "{\"enabled\":false,\"revision\":0}" {
			t.Fatalf("unexpected fields: %s", b)
		}
	}
	for _, ctx := range []context.Context{context.Background(), settingsContext(uuid.New(), user, rbac.RoleOwner, true)} {
		f := &settingsFake{}
		_, err := (apiServer{ipsecSettings: f}).GetIPsecSettings(ctx, api.GetIPsecSettingsRequestObject{OrgId: org})
		if err == nil || f.calls != 0 {
			t.Fatal("unauthorized read reached store")
		}
	}
}
func TestIPsecSettingsRefusesInvalidActor(t *testing.T) {
	org := uuid.New()
	for _, p := range []*authctx.Principal{
		{EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
		{UserID: uuid.New(), MachineID: uuid.New(), AuthMethod: authctx.AuthMachine, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
		{UserID: uuid.New(), EmailVerified: true, MustChangePassword: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}},
	} {
		f := &settingsFake{}
		_, err := (apiServer{ipsecSettings: f}).SetIPsecSettings(authctx.WithPrincipal(context.Background(), p), api.SetIPsecSettingsRequestObject{OrgId: org, Body: &api.SetIPsecSettingsJSONRequestBody{}})
		if err == nil || f.calls != 0 {
			t.Fatal("invalid actor reached settings storage")
		}
	}
}

func TestIPsecSettingsWriteAndValidation(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	ctx := settingsContext(org, user, rbac.RoleAdmin, true)
	for _, body := range []*api.SetIPsecSettingsJSONRequestBody{nil, {ExpectedRevision: -1}} {
		f := &settingsFake{}
		_, err := (apiServer{ipsecSettings: f}).SetIPsecSettings(ctx, api.SetIPsecSettingsRequestObject{OrgId: org, Body: body})
		if !hasCode(err, 400, "invalid_ipsec_settings") || f.calls != 0 {
			t.Fatal("invalid input reached store")
		}
	}
	f := &settingsFake{result: ipsec.Settings{Enabled: true, Revision: 4}}
	r, err := (apiServer{ipsecSettings: f}).SetIPsecSettings(ctx, api.SetIPsecSettingsRequestObject{OrgId: org, Body: &api.SetIPsecSettingsJSONRequestBody{Enabled: true, ExpectedRevision: 3}})
	if err != nil || f.org != org || f.actor != user || !f.enabled || f.revision != 3 || !f.scoped {
		t.Fatalf("incorrect scoped write: %v", err)
	}
	if got := r.(api.SetIPsecSettings200JSONResponse).Body; !got.Enabled || got.Revision != 4 {
		t.Fatal("response must use committed revision")
	}
}
func TestIPsecSettingsErrorMapping(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	ctx := settingsContext(org, user, rbac.RoleOwner, true)
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{{ipsec.ErrSettingsConflict, 409, "ipsec_settings_conflict"}, {ipsec.ErrSettingsOrgUnavailable, 404, "org_not_found"}, {ipsec.ErrSettingsInvalid, 400, "invalid_ipsec_settings"}, {ipsec.ErrSettingsUnavailable, 500, "ipsec_settings_unavailable"}, {errors.New("private database detail"), 500, "ipsec_settings_unavailable"}} {
		s := apiServer{ipsecSettings: &settingsFake{err: tc.err}}
		_, err := s.SetIPsecSettings(ctx, api.SetIPsecSettingsRequestObject{OrgId: org, Body: &api.SetIPsecSettingsJSONRequestBody{}})
		if !hasCode(err, tc.status, tc.code) || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe write mapping: %v", err)
		}
		_, err = s.GetIPsecSettings(ctx, api.GetIPsecSettingsRequestObject{OrgId: org})
		if !hasCode(err, tc.status, tc.code) || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe read mapping: %v", err)
		}
	}
	_, err := (apiServer{}).GetIPsecSettings(ctx, api.GetIPsecSettingsRequestObject{OrgId: org})
	if !hasCode(err, 500, "ipsec_settings_unavailable") {
		t.Fatal("missing store must fail closed")
	}
}

func TestIPsecSettingsRouteValidation(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	f := &settingsFake{result: ipsec.Settings{Enabled: true, Revision: 1}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecSettings: f, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"enabled":"private-value","expected_revision":0}`, `{"enabled":true,"expected_revision":0} {}`, `{}`, `{"enabled":true}`, `{"expected_revision":0}`, `{"enabled":true,"expected_revision":-1}`, `{"enabled":true,"expected_revision":1.5}`, `{"enabled":true,"expected_revision":0,"actor_id":"ignored"}`, `{"enabled":null,"expected_revision":0}`, `{"enabled":true,"expected_revision":9223372036854775808}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/organizations/"+org.String()+"/ipsec/settings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != 400 || f.calls != 0 || strings.Contains(rec.Body.String(), "private-value") {
			t.Fatalf("invalid body %s got %d calls %d: %s", body, rec.Code, f.calls, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/organizations/"+org.String()+"/ipsec/settings", strings.NewReader(`{"enabled":true,"expected_revision":0}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != 200 || f.calls != 1 || f.actor != user {
		t.Fatalf("valid route failed: %d %s", rec.Code, rec.Body.String())
	}
}
