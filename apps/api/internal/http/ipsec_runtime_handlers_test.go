package http

import (
	"context"
	"errors"
	"github.com/google/uuid"
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

func TestIPsecRuntimeIntentAuthorityBeforeInput(t *testing.T) {
	org := uuid.New()
	for _, tt := range []struct {
		name   string
		p      *authctx.Principal
		status int
	}{
		{"anonymous", nil, 401},
		{"member", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403},
		{"unverified", &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"foreign", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404},
	} {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return tt.p }})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("PUT", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+uuid.NewString()+"/intent", strings.NewReader("invalid secret-marker"))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != tt.status {
				t.Fatalf("got %d want %d", recorder.Code, tt.status)
			}
			if strings.Contains(recorder.Body.String(), "secret-marker") {
				t.Fatal("body reflected")
			}
		})
	}
}

type runtimeIntentFake struct {
	calls          int
	org, actor, id uuid.UUID
	revision       int64
	intent         string
	err            error
}

func (f *runtimeIntentFake) SetIntent(_ context.Context, org, actor, id uuid.UUID, revision int64, intent string) (ipsec.Connection, error) {
	f.calls++
	f.org, f.actor, f.id, f.revision, f.intent = org, actor, id, revision, intent
	return ipsec.Connection{ID: id, OrgID: org, DesiredRevision: revision + 1, DesiredIntent: intent}, f.err
}
func TestIPsecRuntimeIntentCASAndStrictBody(t *testing.T) {
	org, actor, id := uuid.New(), uuid.New(), uuid.New()
	fake := &runtimeIntentFake{}
	p := &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAdmin}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecRuntime: fake, AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(body string, headers []string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("PUT", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+id.String()+"/intent", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for _, h := range headers {
			r.Header.Add("If-Match", h)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, intent := range []string{"enabled", "disabled"} {
		w := call(`{"intent":"`+intent+`"}`, []string{`"7"`})
		if w.Code != 200 || w.Header().Get("ETag") != `"8"` || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("success lost %d %s", w.Code, w.Body.String())
		}
		if fake.org != org || fake.actor != actor || fake.id != id || fake.revision != 7 || fake.intent != intent {
			t.Fatal("scope/CAS lost")
		}
	}
	for _, body := range []string{`{}`, `null`, `{"intent":null}`, `{"intent":"deleted"}`, `{"intent":"enabled","unknown":"secret-marker"}`, `{"intent":"enabled","in\u0074ent":"disabled"}`, `{"intent":"enabled"}{}`, strings.Repeat("x", 128*1024+1)} {
		before := fake.calls
		w := call(body, []string{`"7"`})
		if w.Code != 400 || fake.calls != before || strings.Contains(w.Body.String(), "secret-marker") {
			t.Fatalf("invalid body crossed boundary %d", w.Code)
		}
	}
	for _, headers := range [][]string{nil, {`7`}, {`"0"`}, {`"01"`}, {`W/"7"`}, {`"9223372036854775808"`}, {`"7"`, `"7"`}} {
		before := fake.calls
		if w := call(`{"intent":"enabled"}`, headers); w.Code != 400 || fake.calls != before {
			t.Fatal("invalid CAS accepted")
		}
	}
	for _, tt := range []struct {
		err    error
		status int
	}{{ipsec.ErrConnectionConflict, 409}, {ipsec.ErrConnectionIneligible, 409}, {ipsec.ErrConnectionNotFound, 404}, {errors.New("secret-marker"), 503}} {
		fake.err = tt.err
		w := call(`{"intent":"enabled"}`, []string{`"7"`})
		if w.Code != tt.status || strings.Contains(w.Body.String(), "secret-marker") {
			t.Fatal("error boundary failed")
		}
	}
}
