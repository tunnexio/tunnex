package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/aitransport"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Exercise actual password login, Redis sessions, database membership lookup,
// split cookies, OpenAPI middleware and organization/admin handlers together.
// An injected principal would conceal failures in cookie selection or auth.
func TestSessionTransportLoginAndProtectedRoutes(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	actor, org := uuid.New(), uuid.New()
	const plainPassword = "synthetic-transport-test-password"
	hash, err := password.Hash(plainPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO users(id,email,password_hash,cp_admin,email_verified_at) VALUES($1,'transport-login@example.test',$2,true,now())", []any{actor, hash}},
		{"INSERT INTO organizations(id,name,slug) VALUES($1,'Transport fixture',$2)", []any{org, "transport-" + org.String()}},
		{"INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')", []any{org, actor}},
	} {
		if _, err := pool.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { redisClient.Close() })
	sessions := session.NewWithClient(redisClient, time.Hour, 24*time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewRouter(logger, Deps{
		Auth:   auth.NewService(pool, nil, "https://console.example.test", sessions, logger),
		AuthFn: SessionAuth(sessions, sqlc.New(pool)), Sessions: sessions,
		Orgs: tenancy.NewService(pool), Members: tenancy.NewMembershipService(pool, sessions),
		AITransport: aitransport.New(pool), AppBaseURL: "https://console.example.test", CookieSecure: true,
		TrustedProxies: []string{"127.0.0.1", "::1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(handler)
	t.Cleanup(secure.Close)
	jar, _ := cookiejar.New(nil)
	client := secure.Client()
	client.Jar = jar
	call := func(server *httptest.Server, method, path, body string, want int) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
		req.Header.Set("X-Tunnex-CSRF", "1")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s%s got%d want%d: %s", method, req.URL.Scheme, path, res.StatusCode, want, raw)
		}
		return res
	}
	members := "/api/v1/organizations/" + org.String() + "/members"
	login := `{"email":"transport-login@example.test","password":"` + plainPassword + `"}`
	call(plain, "GET", members, "", 401)
	httpLogin := call(plain, "POST", "/api/v1/auth/login", login, 200)
	if cookies := httpLogin.Cookies(); len(cookies) != 1 || cookies[0].Name != "tunnex_session_http" || cookies[0].Secure {
		t.Fatal("HTTP login did not mint isolated HTTP cookie")
	}
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/organizations", "/api/v1/meta", members, "/api/v1/admin/ai-transport-settings"} {
		call(plain, "GET", path, "", 200)
	}
	// The HTTP login never authenticates the HTTPS console.
	call(secure, "GET", members, "", 401)
	httpsLogin := call(secure, "POST", "/api/v1/auth/login", login, 200)
	if cookies := httpsLogin.Cookies(); len(cookies) != 1 || cookies[0].Name != "__Host-tunnex_session" || !cookies[0].Secure {
		t.Fatal("HTTPS login did not mint isolated Secure cookie")
	}
	for _, server := range []*httptest.Server{plain, secure} {
		for _, path := range []string{"/api/v1/auth/me", "/api/v1/organizations", members, "/api/v1/admin/ai-transport-settings"} {
			call(server, "GET", path, "", 200)
		}
	}
	// HTTP logout revokes only its session; it cannot erase the secure login.
	call(plain, "POST", "/api/v1/auth/logout", "", 204)
	call(plain, "GET", members, "", 401)
	call(secure, "GET", members, "", 200)
}
