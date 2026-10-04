package http

// Nonshipping browser fixture: isolated child database, Redis DB2, real OIDC
// verification and production HTTP callback/session mint. No native identity edits.
import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type browserOIDCCode struct {
	Nonce, Challenge string
	ExpiresAt        time.Time
}

func TestAppAccessOwnedSSOBrowserFixture(t *testing.T) {
	if os.Getenv("APP_ACCESS_SSO_BROWSER_FIXTURE") != "1" {
		t.Skip("owned standalone SSO browser only")
	}
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/tunnex/tests/app-access-local" || os.Getenv("AA0_DB_PASSWORD") == "" {
		t.Fatal("owned SSO fixture refused")
	}
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", os.Getenv("AA0_DB_PASSWORD")), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	t.Setenv("TUNNEX_TEST_DATABASE_URL", dsn.String())
	_, pool := testpostgres.New(t)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	q := sqlc.New(pool)
	org, user := uuid.New(), uuid.New()
	email := "aa8-sso-browser@example.test"
	for _, item := range []struct {
		SQL  string
		Args []any
	}{{"INSERT INTO organizations(id,name,slug)VALUES($1,'Owned SSO browser',$2)", []any{org, "aa8-sso-" + org.String()}}, {"INSERT INTO users(id,email,email_verified_at,app_auth_epoch)VALUES($1,$2,now(),1)", []any{user, email}}, {"INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'member')", []any{org, user}}} {
		if _, e := pool.Exec(ctx, item.SQL, item.Args...); e != nil {
			t.Fatal("SSO child seed failed")
		}
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 2})
	defer rdb.Close()
	if rdb.Ping(ctx).Err() != nil {
		t.Fatal("owned Redis2 unavailable")
	}
	parents := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := crypto.NewSealer(key)
	signing, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	const issuer = "http://127.0.0.1:15187"
	const console = "http://sso.127.0.0.1.nip.io:15186"
	const clientID = "aa8-owned-browser"
	var mu sync.Mutex
	codes := map[string]browserOIDCCode{}
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "owned-sso", "n": base64.RawURLEncoding.EncodeToString(signing.N.Bytes()), "e": "AQAB"}}})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Query().Get("redirect_uri") != console+"/api/v1/auth/sso/google/callback" || r.URL.Query().Get("client_id") != clientID || r.URL.Query().Get("nonce") == "" || r.URL.Query().Get("state") == "" || r.URL.Query().Get("code_challenge_method") != "S256" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = template.Must(template.New("consent").Parse(`<html><body><h1>Owned test identity provider</h1><p>Sign in as the verified synthetic member.</p><form method="post" action="/approve"><input type="hidden" name="state" value="{{.State}}"><input type="hidden" name="nonce" value="{{.Nonce}}"><input type="hidden" name="challenge" value="{{.Challenge}}"><button>Continue with owned test identity</button></form></body></html>`)).Execute(w, map[string]string{"State": r.URL.Query().Get("state"), "Nonce": r.URL.Query().Get("nonce"), "Challenge": r.URL.Query().Get("code_challenge")})
	})
	mux.HandleFunc("/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.ParseForm() != nil || len(r.Form.Get("state")) > 256 || len(r.Form.Get("nonce")) > 256 || len(r.Form.Get("challenge")) != 43 {
			http.Error(w, "refused", 403)
			return
		}
		code := uuid.NewString()
		mu.Lock()
		for id, record := range codes {
			if !record.ExpiresAt.After(time.Now()) {
				delete(codes, id)
			}
		}
		if len(codes) >= 64 {
			mu.Unlock()
			http.Error(w, "unavailable", 503)
			return
		}
		codes[code] = browserOIDCCode{r.Form.Get("nonce"), r.Form.Get("challenge"), time.Now().Add(time.Minute)}
		mu.Unlock()
		http.Redirect(w, r, console+"/api/v1/auth/sso/google/callback?"+url.Values{"code": {code}, "state": {r.Form.Get("state")}}.Encode(), 303)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.ParseForm() != nil {
			http.Error(w, "refused", 403)
			return
		}
		mu.Lock()
		record, ok := codes[r.Form.Get("code")]
		delete(codes, r.Form.Get("code"))
		mu.Unlock()
		hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || !record.ExpiresAt.After(time.Now()) || base64.RawURLEncoding.EncodeToString(hash[:]) != record.Challenge {
			http.Error(w, "refused", 403)
			return
		}
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "aud": clientID, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "sub": "aa8-owned-subject", "email": email, "email_verified": true, "name": "AA8 SSO member", "nonce": record.Nonce})
		head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "owned-sso"})
		input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(input))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, signing, stdcrypto.SHA256, digest[:])
		write(w, map[string]any{"access_token": "owned-fixture-only", "token_type": "Bearer", "expires_in": 60, "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
	})
	listener, e := net.Listen("tcp", ":15187")
	if e != nil {
		t.Fatal("owned IdP port unavailable")
	}
	idpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	defer idpServer.Close()
	go idpServer.Serve(listener)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory := func(ctx context.Context, c sso.Config, redirect string) (sso.Provider, error) {
		return sso.NewOIDCProvider(ctx, c.Provider, issuer, c.ClientID, c.ClientSecret, redirect, []string{"openid", "email"}, func(r sso.RawClaims) (sso.Identity, error) {
			return sso.Identity{Subject: r.Sub, Email: r.Email, EmailVerified: r.EmailVerified, Name: r.Name}, nil
		})
	}
	configs := sso.NewConfigService(pool, sealer)
	if e = configs.Set(ctx, user, org, "google", clientID, "owned-test-secret", "", true); e != nil {
		t.Fatal("audited SSO config failed")
	}
	ssoSvc := sso.NewService(pool, configs, sso.NewFlowStore(rdb, 10*time.Minute), factory, console, logger)
	appSvc := appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.example.net", ConsoleHosts: []string{"console.example.com"}, ConsoleURL: "https://console.example.com"}).WithSessionAuthority(parents, appaccess.NewAppSessionStore(rdb), sealer, func(context.Context, uuid.UUID) (bool, error) { return false, nil })
	router, e := NewRouter(logger, Deps{System: q, Auth: auth.NewService(pool, nil, console, parents, logger), Orgs: tenancy.NewService(pool), Members: tenancy.NewMembershipService(pool, parents), Sessions: parents, AuthFn: SessionAuth(parents, q), SSO: &ssoAdapter{pool: pool, svc: ssoSvc}, AppAccess: appSvc, AppBaseURL: console, TrustedProxies: []string{"127.0.0.1", "::1"}})
	if e != nil {
		t.Fatal(e)
	}
	apiListener, e := net.Listen("tcp", ":15188")
	if e != nil {
		t.Fatal("owned SSO API port unavailable")
	}
	server := &http.Server{Handler: router, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 32768}
	defer server.Close()
	go server.Serve(apiListener)
	fmt.Println("owned_ssobrowser_ready; child_only; real_oidc_callback; no_publication")
	<-ctx.Done()
}
