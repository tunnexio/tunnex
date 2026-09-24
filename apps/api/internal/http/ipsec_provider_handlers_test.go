package http

import (
	"context"
	"encoding/json"
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

type providerWireFake struct {
	actor, org uuid.UUID
	input      ipsec.CreateProviderRequest
	calls      int
	err        error
	tombstone  bool
}

func (f *providerWireFake) CreateProviderDisabled(_ context.Context, org, actor uuid.UUID, _ *crypto.Sealer, r ipsec.CreateProviderRequest) (ipsec.Connection, error) {
	f.calls++
	f.org = org
	f.actor = actor
	f.input = r
	return ipsec.Connection{ID: r.ID, OrgID: org, Name: r.Name, DesiredRevision: 1, DesiredIntent: "disabled"}, f.err
}
func (f *providerWireFake) ReadProvider(_ context.Context, org, id uuid.UUID) (ipsec.ProviderConfiguration, error) {
	f.calls++
	f.org = org
	c := &ipsec.StaticConfig{Mode: "ipv4-static", Tunnels: []ipsec.StaticTunnel{{PSK: "never-output-marker"}}}
	if f.tombstone {
		c = nil
	}
	return ipsec.ProviderConfiguration{ProfileID: "aws-static-ipv4-v1", ConfigurationRevision: 1, Config: c}, f.err
}
func providerWireBody() string {
	return `{"id":"00000000-0000-4000-8000-000000000001","name":"Provider fixture","site_id":"00000000-0000-4000-8000-000000000002","gateway_node_id":"00000000-0000-4000-8000-000000000003","tunnel_ids":["00000000-0000-4000-8000-000000000004","00000000-0000-4000-8000-000000000005"],"configuration":` + configurationCheckFixture + `}`
}
func TestIPsecProviderWire(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	p := &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	f := &providerWireFake{}
	sealer, err := crypto.NewSealer([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecProviders: f, IPsecSealer: sealer, AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/organizations/" + org.String() + "/ipsec/connections"
	call := func(method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s got%d want%d: %s", method, w.Code, want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "fixturePSK") || strings.Contains(w.Body.String(), "never-output-marker") {
			t.Fatal("secret response")
		}
		return w
	}
	for _, role := range []string{rbac.RoleOwner, rbac.RoleAdmin} {
		p.Roles[org] = role
		w := call("POST", base, providerWireBody(), 201)
		if w.Header().Get("ETag") != `"1"` || w.Header().Get("Location") != base+"/00000000-0000-4000-8000-000000000001" {
			t.Fatal("missing created identity headers")
		}
	}
	if f.org != org || f.actor != actor || f.input.Config.Tunnels[0].PSK != "Synthetic.fixturePSK_123" || f.input.TunnelIDs[0] == uuid.Nil {
		t.Fatal("scope or explicit input mapping lost")
	}
	for _, body := range []string{`{}`, providerWireBody() + ` {}`, strings.Replace(providerWireBody(), `"name":"Provider fixture"`, `"name":"Provider fixture","unknown":"marker"`, 1), strings.Replace(providerWireBody(), `"name":"Provider fixture"`, `"name":"Provider fixture","name":"duplicate"`, 1)} {
		before := f.calls
		call("POST", base, body, 400)
		if f.calls != before {
			t.Fatal("invalid request reached store")
		}
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{ipsec.ErrConnectionInvalid, 400}, {ipsec.ErrConnectionNotFound, 404}, {ipsec.ErrConnectionIneligible, 409}, {ipsec.ErrConnectionConflict, 409}, {ipsec.ErrConnectionUnavailable, 503}, {errors.New("never-output-marker"), 503}} {
		f.err = tc.err
		call("POST", base, providerWireBody(), tc.status)
	}
	f.err = nil
	p.Roles[org] = rbac.RoleMember
	path := base + "/00000000-0000-4000-8000-000000000001/configuration"
	w := call("GET", path, "", 200)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("configuration cached")
	}
	var shape map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &shape); err != nil {
		t.Fatal(err)
	}
	if _, ok := shape["configuration"]; !ok {
		t.Fatal("configuration omitted")
	}
	call("POST", base, providerWireBody(), 403)
	f.tombstone = true
	w = call("GET", path, "", 200)
	if strings.Contains(w.Body.String(), `"configuration":`) {
		t.Fatal("tombstone exposes configuration")
	}
}
