package http

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPsecEligibilityAuthorityAndValidation(t *testing.T) {
	org := uuid.New()
	p := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/organizations/" + org.String() + "/ipsec/eligibility"
	good := "?site_id=" + uuid.NewString() + "&gateway_node_id=" + uuid.NewString()
	check := func(query string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", base+query, nil))
		if w.Code != want {
			t.Fatalf("got%d want%d: %s", w.Code, want, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable eligibility")
		}
	}
	check(good, 503)
	check("", 400)
	check("?site_id=marker&gateway_node_id=marker", 400)
	p.Roles = map[uuid.UUID]string{uuid.New(): rbac.RoleMember}
	check("?site_id=invalid", 404)
	p = nil
	check("?site_id=invalid", 401)
}

type eligibilityWireFake struct{ org, site, gateway uuid.UUID }

func (f *eligibilityWireFake) ReadEligibility(_ context.Context, org, site, gateway uuid.UUID) (ipsec.Eligibility, error) {
	f.org = org
	f.site = site
	f.gateway = gateway
	return ipsec.Eligibility{Eligible: true, Reason: "eligible"}, nil
}
func TestIPsecEligibilityProjection(t *testing.T) {
	org, site, gateway := uuid.New(), uuid.New(), uuid.New()
	f := &eligibilityWireFake{}
	p := &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}
	r, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecEligibility: f, AuthFn: func(*http.Request) *authctx.Principal { return p }})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/organizations/"+org.String()+"/ipsec/eligibility?site_id="+site.String()+"&gateway_node_id="+gateway.String(), nil))
	var out map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 || len(out) != 2 || out["eligible"] != true || out["reason"] != "eligible" || f.org != org || f.site != site || f.gateway != gateway {
		t.Fatalf("projection scope: %d %s", w.Code, w.Body.String())
	}
}
