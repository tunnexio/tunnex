package http

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

type appDomainsStub struct {
	calls int
	input appdomains.Update
	actor uuid.UUID
	err   error
}

func (s *appDomainsStub) Get(context.Context) (appdomains.View, error) {
	s.calls++
	return appdomains.View{Config: appdomains.Config{PortalURL: "https://internal.tunnex.app", AppBaseDomain: "internal.tunnex.app"}, Source: "database", Version: 2, ConfigurationReady: true}, s.err
}
func (s *appDomainsStub) Save(_ context.Context, actor uuid.UUID, in appdomains.Update) (appdomains.View, error) {
	s.actor = actor
	s.input = in
	return s.Get(context.Background())
}
func (s *appDomainsStub) Effective(context.Context) (appdomains.Config, error) {
	return appdomains.Config{}, s.err
}
func TestAppDomainsRequiresCPAdminHumanSession(t *testing.T) {
	for _, p := range []*authctx.Principal{nil, {UserID: uuid.New(), SessionID: "s", EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}, {UserID: uuid.New(), SessionID: "s", CPAdmin: true}, {UserID: uuid.New(), SessionID: "s", CPAdmin: true, EmailVerified: true, MustChangePassword: true}, {UserID: uuid.New(), CPAdmin: true, EmailVerified: true}, {UserID: uuid.New(), SessionID: "s", CPAdmin: true, EmailVerified: true, AuthMethod: authctx.AuthBearer}} {
		ctx := context.Background()
		if p != nil {
			ctx = authctx.WithPrincipal(ctx, p)
		}
		stub := &appDomainsStub{}
		s := apiServer{appDomains: stub}
		if _, err := s.GetAppAccessDomains(ctx, api.GetAppAccessDomainsRequestObject{}); err == nil {
			t.Fatal("read bypass")
		}
		if _, err := s.UpdateAppAccessDomains(ctx, api.UpdateAppAccessDomainsRequestObject{}); err == nil {
			t.Fatal("write bypass")
		}
		if stub.calls != 0 {
			t.Fatal("unauthorized store access")
		}
	}
}
func TestAppDomainsAdminSettingsProjection(t *testing.T) {
	p := &authctx.Principal{UserID: uuid.New(), SessionID: "browser", CPAdmin: true, EmailVerified: true}
	ctx := authctx.WithPrincipal(context.Background(), p)
	stub := &appDomainsStub{}
	s := apiServer{appDomains: stub}
	out, err := s.UpdateAppAccessDomains(ctx, api.UpdateAppAccessDomainsRequestObject{Body: &api.AppAccessDomainsInput{PortalUrl: "https://internal.tunnex.app", AppBaseDomain: "internal.tunnex.app", ExpectedVersion: 1}})
	if err != nil || stub.actor != p.UserID || stub.input.ExpectedVersion != 1 {
		t.Fatal("save contract", err)
	}
	v := out.(api.UpdateAppAccessDomains200JSONResponse).Body
	if v.Version != 2 || v.Source != "database" || !v.ConfigurationReady {
		t.Fatal("response contract", v)
	}
	stub.err = errors.New("sensitive database endpoint")
	if _, err = s.GetAppAccessDomains(ctx, api.GetAppAccessDomainsRequestObject{}); err == nil || err.Error() == stub.err.Error() {
		t.Fatal("raw store error exposed")
	}
}

func TestAppDomainsBrowserRouterAuthorizationAndCSRF(t *testing.T) {
	stub := &appDomainsStub{}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AppDomains: stub, AppBaseURL: "https://internal.tunnex.app", AuthFn: func(r *http.Request) *authctx.Principal {
		cookie, err := r.Cookie("__Host-tunnex_session")
		if err != nil {
			return nil
		}
		return &authctx.Principal{UserID: uuid.New(), SessionID: "fixture-session", EmailVerified: true, CPAdmin: cookie.Value == "admin", AuthMethod: authctx.AuthSSO}
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, identity, origin string
		csrf                   bool
		want                   int
	}{
		{"sessionless", "", "", true, 401},
		{"owner is not CP admin", "owner", "https://internal.tunnex.app", true, 403},
		{"missing CSRF", "admin", "https://internal.tunnex.app", false, 403},
		{"sibling origin", "admin", "https://payroll.internal.tunnex.app", true, 403},
		{"admin browser save", "admin", "https://internal.tunnex.app", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := stub.calls
			req := httptest.NewRequest(http.MethodPatch, "https://internal.tunnex.app/api/v1/admin/app-access/domains", strings.NewReader(`{"portal_url":"https://internal.tunnex.app","app_base_domain":"internal.tunnex.app","expected_version":1}`))
			req.Header.Set("Content-Type", "application/json")
			if tc.identity != "" {
				req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: tc.identity})
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
				t.Fatalf("got %d want %d: %s", out.Code, tc.want, out.Body.String())
			}
			if tc.want != 200 && stub.calls != before {
				t.Fatal("unauthorized mutation reached store")
			}
			if tc.want == 200 && (stub.input.AppBaseDomain != "internal.tunnex.app" || stub.input.ExpectedVersion != 1 || stub.calls != before+1) {
				t.Fatal("validated request lost settings")
			}
		})
	}
}
