package http

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

const bgpCheckFields = `"bgp":{"local_asn":65000,"remote_asn":7224,"router_id":"10.10.0.1","maximum_prefixes":16}`

func TestIPsecBGPPreflightAndCreateWire(t *testing.T) {
	org := uuid.New()
	p := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	var logs bytes.Buffer
	store := &providerWireFake{}
	sealer, err := crypto.NewSealer([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{IPsecProviders: store, IPsecSealer: sealer, AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	bgp := strings.Replace(configurationCheckFixture, `"mode":"ipv4-static"`, `"mode":"ipv4-bgp",`+bgpCheckFields, 1)
	for _, tc := range []struct {
		body string
		want int
	}{
		{bgp, 200},
		{strings.Replace(configurationCheckFixture, `"mode":"ipv4-static"`, `"mode":"ipv4-bgp"`, 1), 400},
		{strings.Replace(configurationCheckFixture, `"mode":"ipv4-static"`, `"mode":"ipv4-static",`+bgpCheckFields, 1), 400},
		{strings.Replace(bgp, `"local_asn":65000`, `"local_asn":7224`, 1), 400},
		{strings.Replace(bgp, `"maximum_prefixes":16`, `"maximum_prefixes":0`, 1), 400},
		{strings.Replace(bgp, `"remote_asn":7224`, `"remote_asn":7224,"unknown":"private-secret-marker"`, 1), 400},
		{strings.Replace(bgp, `"remote_asn":7224`, `"remote_asn":7224,"remote_asn":65001`, 1), 400},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/configuration-check", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("preflight got %d want %d: %s", w.Code, tc.want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "fixturePSK") || strings.Contains(logs.String(), "private-secret-marker") {
			t.Fatal("secret disclosed")
		}
	}
	body := strings.Replace(providerWireBody(), configurationCheckFixture, bgp, 1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/connections", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create got %d: %s", w.Code, w.Body.String())
	}
	b := store.input.Config.BGP
	if store.calls != 1 || b == nil || b.LocalASN != 65000 || b.RemoteASN != 7224 || b.RouterID != "10.10.0.1" || b.MaximumPrefixes != 16 {
		t.Fatal("BGP intent mapping lost")
	}
	if strings.Contains(w.Body.String(), "fixturePSK") {
		t.Fatal("secret disclosed")
	}
	p.Roles[org] = rbac.RoleMember
	req = httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+org.String()+"/ipsec/configuration-check", strings.NewReader(bgp))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("BGP bypassed existing role boundary")
	}
}
