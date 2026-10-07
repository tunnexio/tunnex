package http

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBeamReadinessOperatorAndOuterGates(t *testing.T) {
	principal := func() *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, CPAdmin: true}
	}
	orgOwner := principal()
	orgOwner.CPAdmin = false
	orgOwner.Roles = map[uuid.UUID]string{uuid.New(): "owner"}
	forced := principal()
	forced.MustChangePassword = true
	unverified := principal()
	unverified.EmailVerified = false
	bearer := principal()
	bearer.AuthMethod = authctx.AuthBearer
	for _, tc := range []struct {
		name, method, body, auth, cookie string
		p                                *authctx.Principal
		status                           int
	}{
		{"signed out", "GET", "", "", "", nil, 401},
		{"organization owner cannot configure installation", "GET", "", "", "", orgOwner, 403},
		{"operator reads fixed config", "GET", "", "", "", principal(), 503},
		{"forced password", "GET", "", "", "", forced, 403},
		{"unverified", "GET", "", "", "", unverified, 403},
		{"bearer denied", "GET", "", "Bearer fixture", "", bearer, 403},
		{"invalid bearer cannot fallback", "GET", "", "Bearer invalid", "", principal(), 403},
		{"browser csrf inherited", "POST", "{}", "", "tunnex_session=fixture", principal(), 403},
		{"caller cannot change probe targets", "POST", `{"url":"https://localhost/"}`, "", "", principal(), 400},
		{"authorized check fails closed without registry", "POST", `{"expected_configuration_version":"stale"}`, "", "", principal(), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Beam: beam.New(nil, beam.Config{}, nil, nil), AuthFn: func(*http.Request) *authctx.Principal { return tc.p }})
			if e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest(tc.method, "/api/v1/admin/beam/readiness", strings.NewReader(tc.body))
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("want%d got%d %s", tc.status, w.Code, w.Body.String())
			}
		})
	}
}
func TestBeamSettingsOperatorAndStrictMutationGates(t *testing.T) {
	operator := func() *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, CPAdmin: true}
	}
	owner := operator()
	owner.CPAdmin = false
	owner.Roles = map[uuid.UUID]string{uuid.New(): "owner"}
	for _, tc := range []struct {
		name, method, body, auth, cookie string
		p                                *authctx.Principal
		status                           int
	}{
		{"signedout", "GET", "", "", "", nil, 401},
		{"orgowner", "PUT", "{}", "", "", owner, 403},
		{"operatorunavailabledependency", "GET", "", "", "", operator(), 503},
		{"invalidbearernoCookieFallback", "GET", "", "Bearer invalid", "", operator(), 403},
		{"csrfprotectsinstallationchange", "PUT", "{}", "", "tunnex_session=fixture", operator(), 403},
		{"cannotwritereadonlyportal", "PUT", `{"portal_url":"https://changed.example.com"}`, "", "", operator(), 400},
		{"cannotsetmeasuredready", "PUT", `{"authority_ready":true}`, "", "", operator(), 400},
		{"cannotselectdevelopmenttrust", "PUT", `{"development_allow_loopback":true,"public_ca_pem":"fake"}`, "", "", operator(), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Beam: beam.New(nil, beam.Config{}, nil, nil), AuthFn: func(*http.Request) *authctx.Principal { return tc.p }})
			if e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest(tc.method, "/api/v1/admin/beam/settings", strings.NewReader(tc.body))
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("want%d got%d %s", tc.status, w.Code, w.Body.String())
			}
		})
	}
}
