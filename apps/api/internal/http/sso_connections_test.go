package http

import (
	"context"
	"encoding/json"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConnectionStartSetsPrivateBrowserBindingCookie(t *testing.T) {
	w := httptest.NewRecorder()
	r := connectionStartResponse{redirect: "https://id.example.com/auth", binding: strings.Repeat("x", 32), secure: true}
	if e := r.VisitStartSsoConnectionResponse(w); e != nil {
		t.Fatal(e)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing binding cookie")
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != 2 || c.MaxAge != 600 || c.Path != "/api/v1/auth/sso-connections" {
		t.Fatalf("unsafe cookie: %+v", c)
	}
	if strings.Contains(w.Body.String(), r.binding) {
		t.Fatal("browser secret exposed to JS")
	}
}
func TestConnectionReadProjectionNeverContainsSecrets(t *testing.T) {
	s := apiServer{}
	c := sqlc.SsoConnection{ClientSecretSealed: []byte("secret-ciphertext")}
	b, e := json.Marshal(s.connectionView(c))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatal("connection read leaked secret")
	}
}

func TestCompanyLoginFailureRetainsVerifiedFlowConnection(t *testing.T) {
	id := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	u, e := url.Parse(connectionLoginFailureURL("https://vpn.example.com", id, apierr.BadRequest("sso_consent_denied", "private-provider-details")))
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("connection") != id.String() || u.Query().Get("sso_error") != "sso_consent_denied" {
		t.Fatal("company login cannot retry")
	}
	if strings.Contains(u.String(), "private-provider-details") {
		t.Fatal("raw provider error exposed")
	}
	u, _ = url.Parse(connectionLoginFailureURL("https://vpn.example.com", uuid.Nil, apierr.BadRequest("unknown", "private")))
	if u.Query().Has("connection") {
		t.Fatal("unbound flow acquired a connection")
	}
}

func TestFirstSSOCallbackWithoutSessionDoesNotPanic(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	svc := sso.NewService(nil, nil, sso.NewFlowStore(rdb, time.Minute), nil, "http://localhost", nil)
	server := apiServer{sso: &ssoAdapter{svc: svc}, appBaseURL: "http://localhost"}
	response, err := server.SsoConnectionCallback(context.Background(), api.SsoConnectionCallbackRequestObject{Params: api.SsoConnectionCallbackParams{State: "missing-flow"}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err = response.VisitSsoConnectionCallbackResponse(w); err != nil {
		t.Fatal(err)
	}
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "sso_error=invalid_state") {
		t.Fatalf("unexpected refusal: %d %s", w.Code, w.Header().Get("Location"))
	}
}
