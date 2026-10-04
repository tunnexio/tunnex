package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type appMFAPolicyRecorder struct {
	appAccessRecorder
	required bool
	app      uuid.UUID
}

func (f *appMFAPolicyRecorder) UpdateMFAPolicy(_ context.Context, org, actor, app uuid.UUID, required bool, version int64) (appaccess.Application, error) {
	f.calls++
	f.org = org
	f.actor = actor
	f.app = app
	f.required = required
	f.version = version
	return appaccess.Application{ID: app, OrgID: org, Version: version + 1, State: "draft", RequireMFA: required}, f.err
}
func TestAppMFAPolicyAuthority(t *testing.T) {
	org, app := uuid.New(), uuid.New()
	req := api.UpdateAppAccessMFAPolicyRequestObject{OrgId: org, AppId: app, Body: &api.AppAccessMFAPolicyInput{RequireMfa: true, ExpectedVersion: 7}}
	for _, tc := range []struct {
		name, role, method, session, reason string
		verified                            bool
	}{
		{"member", rbac.RoleMember, authctx.AuthLocalPassword, "s", "forbidden", true},
		{"unverified", rbac.RoleOwner, authctx.AuthLocalPassword, "s", "email_not_verified", false},
		{"machine", rbac.RoleOwner, authctx.AuthMachine, "s", "human_session_required", true},
		{"bearer", rbac.RoleOwner, authctx.AuthBearer, "s", "human_session_required", true},
		{"missing cookie", rbac.RoleOwner, authctx.AuthLocalPassword, "", "human_session_required", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := appAccessPrincipal(org, tc.role)
			p.AuthMethod = tc.method
			p.SessionID = tc.session
			p.EmailVerified = tc.verified
			f := &appMFAPolicyRecorder{}
			s := apiServer{appAccess: f}
			_, err := s.UpdateAppAccessMFAPolicy(authctx.WithPrincipal(context.Background(), p), req)
			if !hasCode(err, 403, tc.reason) || f.calls != 0 {
				t.Fatalf("authority %v calls%d", err, f.calls)
			}
		})
	}
	for _, method := range []string{authctx.AuthLocalPassword, authctx.AuthSSO} {
		t.Run(method, func(t *testing.T) {
			p := appAccessPrincipal(org, rbac.RoleAdmin)
			p.AuthMethod = method
			f := &appMFAPolicyRecorder{}
			s := apiServer{appAccess: f}
			out, err := s.UpdateAppAccessMFAPolicy(authctx.WithPrincipal(context.Background(), p), req)
			if err != nil {
				t.Fatal(err)
			}
			body := out.(api.UpdateAppAccessMFAPolicy200JSONResponse)
			if f.org != org || f.app != app || f.actor != p.UserID || f.version != 7 || !f.required || !body.Body.RequireMfa || body.Body.MfaFreshnessSeconds != 900 || body.Headers.CacheControl != "no-store" {
				t.Fatal("policy projection/scope lost")
			}
		})
	}
	f := &appMFAPolicyRecorder{}
	s := apiServer{appAccess: f}
	_, err := s.UpdateAppAccessMFAPolicy(authctx.WithPrincipal(context.Background(), appAccessPrincipal(uuid.New(), rbac.RoleOwner)), req)
	if !hasCode(err, 404, "org_not_found") || f.calls != 0 {
		t.Fatal("foreign scope", err)
	}
}

func TestAppMFAPolicyBrowserRouterSecurity(t *testing.T) {
	org := uuid.New()
	stub := &appMFAPolicyRecorder{}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AppAccess: stub, AppBaseURL: "https://internal.tunnex.app", AuthFn: func(r *http.Request) *authctx.Principal {
		cookie, err := r.Cookie("__Host-tunnex_session")
		if err != nil {
			return nil
		}
		p := appAccessPrincipal(org, cookie.Value)
		return p
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, role, origin string
		csrf               bool
		want               int
	}{
		{"sessionless", "", "", true, 401},
		{"member", rbac.RoleMember, "https://internal.tunnex.app", true, 403},
		{"missing CSRF", rbac.RoleAdmin, "https://internal.tunnex.app", false, 403},
		{"sibling origin", rbac.RoleAdmin, "https://wiki.internal.tunnex.app", true, 403},
		{"admin browser", rbac.RoleAdmin, "https://internal.tunnex.app", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := stub.calls
			req := httptest.NewRequest(http.MethodPatch, "https://internal.tunnex.app/api/v1/organizations/"+org.String()+"/app-access/applications/"+uuid.NewString()+"/mfa-policy", strings.NewReader("{\"require_mfa\":true,\"expected_version\":7}"))
			req.Header.Set("Content-Type", "application/json")
			if tc.role != "" {
				req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: tc.role})
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.csrf {
				req.Header.Set("X-Tunnex-CSRF", "1")
			}
			out := httptest.NewRecorder()
			router.ServeHTTP(out, req)
			if out.Code != tc.want {
				t.Fatalf("HTTP%d want%d: %s", out.Code, tc.want, out.Body.String())
			}
			if tc.want != 200 && stub.calls != before {
				t.Fatal("unauthorized request reached policy storage")
			}
		})
	}
}
