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
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

const configurationCheckFixture = `{"mode":"ipv4-static","customer_outside_address":"9.9.9.9","local_prefixes":["10.10.0.0/16"],"remote_prefixes":["10.20.0.0/16"],"tunnels":[{"outside_address":"8.8.8.8","inside_cidr":"169.254.10.0/30","customer_inside_address":"169.254.10.2","cloud_inside_address":"169.254.10.1","psk":"Synthetic.fixturePSK_123"},{"outside_address":"1.1.1.1","inside_cidr":"169.254.10.4/30","customer_inside_address":"169.254.10.5","cloud_inside_address":"169.254.10.6","psk":"Synthetic.fixturePSK_456"}]}`

func TestIPsecConfigurationCheckRoute(t *testing.T) {
	org := uuid.New()
	var logs bytes.Buffer
	p := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	// No store/settings/capability dependency: a preflight must not persist state.
	router, err := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	check := func(body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/configuration-check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("status%d want%d: %s", rec.Code, want, rec.Body.String())
		}
		for _, secret := range []string{"fixturePSK", "private-secret-marker"} {
			if strings.Contains(rec.Body.String(), secret) || strings.Contains(logs.String(), secret) {
				t.Fatal("preflight disclosed request secret")
			}
		}
		return rec
	}
	if rec := check(configurationCheckFixture, 200); strings.TrimSpace(rec.Body.String()) != `{"valid":true}` {
		t.Fatal("success must contain validation result only")
	}
	for _, body := range []string{`{}`, `{"mode":"private-secret-marker"}`, configurationCheckFixture + ` {}`, strings.Replace(configurationCheckFixture, `"mode":"ipv4-static"`, `"mode":"ipv4-static","mode":"ipv4-static"`, 1), strings.Replace(configurationCheckFixture, `"psk":"Synthetic.fixturePSK_123"`, `"psk":"private-secret-marker"`, 1), strings.Replace(configurationCheckFixture, `"mode":"ipv4-static"`, `"mode":"ipv4-static","unknown":"private-secret-marker"`, 1), strings.Repeat(" ", 128*1024) + configurationCheckFixture} {
		check(body, 400)
	}

	semantic := check(strings.Replace(configurationCheckFixture, `"psk":"Synthetic.fixturePSK_123"`, `"psk":"private-secret-marker"`, 1), 400)
	var failure struct {
		Error struct {
			Code    string `json:"code"`
			Details []struct {
				Field string `json:"field"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(semantic.Body.Bytes(), &failure); err != nil || failure.Error.Code != "credential_invalid" || len(failure.Error.Details) != 1 || failure.Error.Details[0].Field != "tunnels[1].psk" {
		t.Fatal("semantic refusal missing static code and structural slot field")
	}
	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin} {
		p.Roles[org] = role
		check(configurationCheckFixture, 200)
	}
}
func TestIPsecConfigurationCheckAuthorityBeforeParsing(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name   string
		p      *authctx.Principal
		status int
	}{
		{"anonymous", nil, 401}, {"member", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403},
		{"unverified", &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"foreign", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404},
		{"machine", &authctx.Principal{UserID: uuid.New(), MachineID: uuid.New(), AuthMethod: authctx.AuthMachine, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"no-user", &authctx.Principal{EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"password-wall", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, MustChangePassword: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return tc.p }})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/configuration-check", strings.NewReader(`invalid secret body`))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("authority precedence status%d want%d", rec.Code, tc.status)
			}
		})
	}
}
