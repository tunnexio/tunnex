package http

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type configCheckReadSpy struct{ reads int }

func (s *configCheckReadSpy) Read(p []byte) (int, error) { s.reads++; return 0, io.EOF }
func TestIPsecConfigurationCheckDoesNotReadUnauthorizedSecrets(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name   string
		p      *authctx.Principal
		status int
	}{
		{"anonymous", nil, 401},
		{"member", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403},
		{"unverified", &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"machine owner", &authctx.Principal{UserID: uuid.New(), MachineID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"other organization", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return tc.p }})
			if err != nil {
				t.Fatal(err)
			}
			spy := &configCheckReadSpy{}
			req := httptest.NewRequest("POST", "/api/v1/organizations/"+org.String()+"/ipsec/configuration-check", spy)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status || spy.reads != 0 {
				t.Fatalf("status%d reads%d expected%d/0", rec.Code, spy.reads, tc.status)
			}
		})
	}
}
func TestIPsecConfigurationCheckEncodedDuplicatesStayRedacted(t *testing.T) {
	org := uuid.New()
	var logs bytes.Buffer
	router, err := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	// JSON escapes resolve to the same property name; spelling cannot bypass the duplicate guard.
	body := strings.Replace(configurationCheckFixture, `"psk":"Synthetic.fixturePSK_123"`, `"psk":"Synthetic.fixturePSK_123","p\u0073k":"Duplicate.SECRET_987"`, 1)
	req := httptest.NewRequest("POST", "/api/v1/organizations/"+org.String()+"/ipsec/configuration-check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("duplicate accepted: status%d", rec.Code)
	}
	for _, marker := range []string{"Synthetic.fixturePSK_123", "Duplicate.SECRET_987"} {
		if strings.Contains(rec.Body.String(), marker) || strings.Contains(logs.String(), marker) {
			t.Fatal("secret escaped through response or logs")
		}
	}
}
