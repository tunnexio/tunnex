package http

import (
	"context"
	"errors"
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

func TestIPsecRotationAuthorityBeforeInput(t *testing.T) {
	org := uuid.New()
	for _, tt := range []struct {
		name   string
		p      *authctx.Principal
		status int
	}{{"anonymous", nil, 401},
		{"machine", &authctx.Principal{MachineID: uuid.New(), AuthMethod: authctx.AuthMachine, Roles: map[uuid.UUID]string{org: rbac.RoleOperator}}, 403}, {"member", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403}, {"unverified", &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, 403}, {"foreign", &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404}} {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return tt.p }})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+uuid.NewString()+"/rotate-psks", strings.NewReader("invalid secret-marker"))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != tt.status || strings.Contains(w.Body.String(), "secret-marker") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("authority/redaction boundary failed: %d", w.Code)
			}
		})
	}
}

type rotationWireFake struct {
	providerWireFake
	id       uuid.UUID
	revision int64
	keys     []ipsec.RotatePSK
}

func (f *rotationWireFake) RotatePSKs(_ context.Context, org, actor, id uuid.UUID, rev int64, keys []ipsec.RotatePSK, _ *crypto.Sealer) (ipsec.Connection, error) {
	f.calls++
	f.org, f.actor, f.id, f.revision = org, actor, id, rev
	f.keys = append([]ipsec.RotatePSK(nil), keys...)
	return ipsec.Connection{ID: id, OrgID: org, DesiredRevision: rev + 1, DesiredIntent: "disabled"}, f.err
}
func TestIPsecRotationStrictCASRedactionAndCommunity(t *testing.T) {
	org, actor, id, tunnel := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	f := &rotationWireFake{}
	p := &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleAdmin}}
	sealer, err := crypto.NewSealer([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecProviders: f, IPsecSealer: sealer, AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"expected_desired_revision":7,"tunnels":[{"tunnel_id":"` + tunnel.String() + `","psk":"secret-marker"}]}`
	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+id.String()+"/rotate-psks", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "secret-marker") {
			t.Fatal("sensitive response leaked")
		}
		return w
	}
	if w := call(valid); w.Code != 200 || w.Header().Get("ETag") != `"8"` {
		t.Fatalf("community maintenance refused %d %s", w.Code, w.Body.String())
	}
	if f.org != org || f.actor != actor || f.id != id || f.revision != 7 || len(f.keys) != 1 || f.keys[0].TunnelID != tunnel || f.keys[0].PSK != "secret-marker" {
		t.Fatal("scope/key/CAS lost")
	}
	p.Roles[org] = rbac.RoleOwner
	second := uuid.New()
	both := strings.Replace(valid, `}]}`, `},{"tunnel_id":"`+second.String()+`","psk":"second-secret"}]}`, 1)
	if w := call(both); w.Code != 200 || len(f.keys) != 2 || f.keys[1].TunnelID != second || strings.Contains(w.Body.String(), "second-secret") {
		t.Fatal("owner two-key rotation failed", w.Code)
	}
	for _, body := range []string{`null`, `{}`, `{"expected_desired_revision":7,"tunnels":[]}`, strings.Replace(valid, `:7`, `:0`, 1), strings.Replace(valid, `:7`, `:9223372036854775808`, 1), strings.Replace(valid, `:7`, `:7,"expected_desired_revision":8`, 1), strings.Replace(valid, `"psk":"secret-marker"`, `"psk":null`, 1), strings.Replace(valid, `"psk":"secret-marker"`, `"psk":"secret-marker","unknown":true`, 1), strings.Replace(valid, `"psk":"secret-marker"`, `"psk":"secret-marker","p\u0073k":"other"`, 1), valid + `{}`, strings.Repeat("x", 128*1024+1), `{"expected_desired_revision":7,"tunnels":[{"tunnel_id":"` + tunnel.String() + `","psk":"a"},{"tunnel_id":"` + tunnel.String() + `","psk":"b"}]}`} {
		before := f.calls
		if w := call(body); w.Code != 400 || f.calls != before {
			t.Fatalf("strict body bypass %d", w.Code)
		}
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{ipsec.ErrConnectionConflict, 409}, {ipsec.ErrConnectionNotFound, 404}, {ipsec.ErrConnectionInvalid, 400}, {errors.New("secret-marker"), 503}} {
		f.err = tc.err
		if w := call(valid); w.Code != tc.status {
			t.Fatalf("error status %d", w.Code)
		}
	}
}
