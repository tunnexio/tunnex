package http

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPsecProviderSecretsRequireAuthorityBeforeRead(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name      string
		principal *authctx.Principal
		status    int
	}{
		{"anonymous", nil, 401},
		{"member", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403},
		{"unverified", &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"machine", &authctx.Principal{UserID: uuid.New(), MachineID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
		{"foreign", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404},
		{"password wall", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, MustChangePassword: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return tc.principal }})
			if err != nil {
				t.Fatal(err)
			}
			spy := &configCheckReadSpy{}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/connections", spy)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status || spy.reads != 0 {
				t.Fatalf("status %d/read %d want %d/0", rec.Code, spy.reads, tc.status)
			}
		})
	}
}

type providerSecurityFake struct {
	creates int
	reads   int
	result  ipsec.ProviderConfiguration
}

func (f *providerSecurityFake) CreateProviderDisabled(context.Context, uuid.UUID, uuid.UUID, *crypto.Sealer, ipsec.CreateProviderRequest) (ipsec.Connection, error) {
	f.creates++
	return ipsec.Connection{}, nil
}
func (f *providerSecurityFake) ReadProvider(context.Context, uuid.UUID, uuid.UUID) (ipsec.ProviderConfiguration, error) {
	f.reads++
	return f.result, nil
}
func providerSecurityBody() string {
	return `{"id":"11111111-1111-4111-8111-111111111111","name":"Office cloud","site_id":"22222222-2222-4222-8222-222222222222","gateway_node_id":"33333333-3333-4333-8333-333333333333","tunnel_ids":["44444444-4444-4444-8444-444444444444","55555555-5555-4555-8555-555555555555"],"configuration":` + configurationCheckFixture + `}`
}
func TestIPsecProviderMalformedSecretsStayRedacted(t *testing.T) {
	org := uuid.New()
	f := &providerSecurityFake{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	old := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(old)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(logger, Deps{IPsecProviders: f, IPsecSealer: sealer, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := providerSecurityBody()
	for _, input := range []string{
		body + ` {}`, strings.Repeat(" ", 128*1024) + body,
		strings.Replace(body, `"name":"Office cloud"`, `"name":"Office cloud","na\u006de":"Marker.SECRET_987"`, 1),
		strings.Replace(body, `"psk":"Synthetic.fixturePSK_123"`, `"psk":"Synthetic.fixturePSK_123","p\u0073k":"Marker.SECRET_987"`, 1),
		strings.Replace(body, `"name":"Office cloud"`, `"name":"Office cloud","unknown":"Marker.SECRET_987"`, 1),
		strings.Replace(body, `"psk":"Synthetic.fixturePSK_123"`, `"psk":{"secret":"Marker.SECRET_987"}`, 1),
		strings.Replace(body, `"psk":"Synthetic.fixturePSK_123"`, `"psk":null`, 1),
		strings.Replace(body, `"name":"Office cloud"`, `"name":null`, 1),
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/connections", strings.NewReader(input))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != 400 || f.creates != 0 {
			t.Fatalf("bad request status%d calls%d", rec.Code, f.creates)
		}
		for _, marker := range []string{"Marker.SECRET_987", "Synthetic.fixturePSK"} {
			if strings.Contains(rec.Body.String(), marker) || strings.Contains(logs.String(), marker) {
				t.Fatal("credential escaped body/log boundary")
			}
		}
	}
}
func TestIPsecProviderReadProjectsCredentialsOut(t *testing.T) {
	org := uuid.New()
	f := &providerSecurityFake{result: ipsec.ProviderConfiguration{ProfileID: "aws-static-ipv4-v1", ConfigurationRevision: 1, Config: &ipsec.StaticConfig{Mode: "ipv4-static", Tunnels: []ipsec.StaticTunnel{{PSK: "Marker.SECRET_987"}, {PSK: "Marker.SECRET_654"}}}}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecProviders: f, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tombstone := range []bool{false, true} {
		if tombstone {
			f.result.Config = nil
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+uuid.NewString()+"/configuration", nil)
		router.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("read status%d cache%q", rec.Code, rec.Header().Get("Cache-Control"))
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if tombstone && len(decoded) != 2 {
			t.Fatal("tombstone contains configuration")
		}
		for _, key := range []string{"psk", "secret_revision", "sealed_psk", "credential", "Marker.SECRET"} {
			if strings.Contains(rec.Body.String(), key) {
				t.Fatal("read exposed credential field")
			}
		}
	}
}
