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

func TestBeamPublicRoutesInheritPrincipalAndCSRF(t *testing.T) {
	org := uuid.New()
	owner := func() *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}
	}
	cases := []struct {
		name, method, path, cookie, authorization string
		p                                         *authctx.Principal
		status                                    int
	}{
		{"signed out", "GET", "policy", "", "", nil, 401},
		{"projects signed out", "GET", "projects", "", "", nil, 401},
		{"rooms csrf", "POST", "projects", "tunnex_session=fixture", "", owner(), 403},
		{"feedback csrf", "POST", "shares/" + uuid.NewString() + "/feedback", "tunnex_session=fixture", "", owner(), 403},
		{"screenshot signed out", "GET", "shares/" + uuid.NewString() + "/feedback/" + uuid.NewString() + "/screenshot", "", "", nil, 401},
		{"notifications signed out", "GET", "notifications", "", "", nil, 401},
		{"foreign room", "GET", "projects/" + uuid.NewString(), "", "", &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "member"}}, 404},
		{"impact signed out", "POST", "policy/impact", "", "", nil, 401},
		{"member impact denied", "POST", "policy/impact", "", "", &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, Roles: map[uuid.UUID]string{org: "member"}}, 403},
		{"impact csrf", "POST", "policy/impact", "tunnex_session=fixture", "", owner(), 403},
		{"grant impact csrf", "POST", "shares/" + uuid.NewString() + "/grants/impact", "tunnex_session=fixture", "", owner(), 403},
		{"owner history signed out", "GET", "shares/" + uuid.NewString() + "/events", "", "", nil, 401},
		{"diagnostics foreign org", "GET", "shares/" + uuid.NewString() + "/diagnostics", "", "", &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}, 404},
		{"member policy denied", "PUT", "policy", "", "", &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", AuthMethod: authctx.AuthLocalPassword, EmailVerified: true, Roles: map[uuid.UUID]string{org: "member"}}, 403},
		{"machine denied", "GET", "policy", "", "", authctx.NewMachinePrincipal(uuid.New(), uuid.New(), org, "fixture", "owner", ""), 403},
		{"foreign organization", "GET", "policy", "", "", &authctx.Principal{UserID: uuid.New(), SessionID: "fixture", EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}, 404},
		{"browser csrf", "PUT", "policy", "tunnex_session=fixture", "", owner(), 403},
		{"invalid bearer cannot fall back", "GET", "policy", "", "Bearer invalid", owner(), 401},
	}
	forced := owner()
	forced.MustChangePassword = true
	cases = append(cases, struct {
		name, method, path, cookie, authorization string
		p                                         *authctx.Principal
		status                                    int
	}{"forced password change", "GET", "policy", "", "", forced, 403})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Beam: beam.New(nil, beam.Config{}, nil, nil), AuthFn: func(*http.Request) *authctx.Principal { return tc.p }})
			if e != nil {
				t.Fatal(e)
			}
			req := httptest.NewRequest(tc.method, "/api/v1/organizations/"+org.String()+"/beam/"+tc.path, strings.NewReader("{}"))
			if tc.cookie != "" {
				req.Header.Set("Cookie", tc.cookie)
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("got %d expected %d: %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}
func TestBeamStrictMetadataDecoder(t *testing.T) {
	for _, body := range []string{`{"unknown":true}`, `{} {}`, strings.Repeat(" ", 33000) + `{}`} {
		r := httptest.NewRequest("POST", "/api/v1/organizations/"+uuid.NewString()+"/beam/policy", strings.NewReader(body))
		w := httptest.NewRecorder()
		var in beam.PolicyInput
		if e := beamDecode(w, r, &in); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
}

func TestBeamRoomStrictBoundedDecoders(t *testing.T) {
	for _, body := range []string{`{"body":"ok","status":"comment","unsafe":true}`, `{"body":"ok","status":"comment"} {}`, strings.Repeat(" ", 524289) + `{}`} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		rec := httptest.NewRecorder()
		var input beam.FeedbackInput
		if e := beamDecodeLimit(rec, req, &input, 524288); e == nil {
			t.Fatal("Unbounded or unknown feedback metadata accepted")
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"body":"","status":"approved"}`))
	var in beam.FeedbackInput
	if e := beamDecodeLimit(httptest.NewRecorder(), req, &in, 524288); e != nil {
		t.Fatal("Valid status-only review rejected", e)
	}
}
