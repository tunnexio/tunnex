package http

// Nonshipping owned native SSO fixture: exact existing member, Redis DB1, real
// OIDC verification and production callback. Scoped SSO configuration is restored.
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

	"crypto/ed25519"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
	"strings"
)

type nativeBrowserOIDCCode struct {
	Nonce, Challenge string
	ExpiresAt        time.Time
}

func TestAppAccessOwnedNativeSSOBrowserFixture(t *testing.T) {
	if os.Getenv("APP_ACCESS_NATIVE_SSO_BROWSER_FIXTURE") != "1" {
		t.Skip("owned standalone SSO browser only")
	}
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/tunnex/tests/app-access-local" || os.Getenv("AA0_DB_PASSWORD") == "" {
		t.Fatal("owned SSO fixture refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if os.Getenv("TUNNEX_APP_ACCESS_RESTORE_MARKER") != "/owned-app-restore/app-access.pending.json" || restorebarrier.Check(os.Getenv("TUNNEX_APP_ACCESS_RESTORE_MARKER")) != nil {
		t.Fatal("owned native SSO restore fence unavailable")
	}
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", os.Getenv("AA0_DB_PASSWORD")), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal("owned native SSO DB unavailable")
	}
	defer pool.Close()
	var version int
	var dirty bool
	if pool.QueryRow(ctx, "SELECT version,dirty FROM schema_migrations").Scan(&version, &dirty) != nil || version != 174 || dirty {
		t.Fatal("owned native SSO schema mismatch")
	}
	q := sqlc.New(pool)
	org := uuid.MustParse("01a100fb-d59d-7adc-b21f-1275c4e4bc4d")
	user := uuid.MustParse("56cc37e2-17d0-44d8-844b-710895969485")
	actor := uuid.MustParse("f6b426b1-a3ce-4af3-b861-8ff1b49d8c05")
	email := "aa8-direct@example.test"
	var count int
	if pool.QueryRow(ctx, `SELECT count(*) FROM users u JOIN memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.org_id WHERE u.id=$1 AND u.email=$2 AND u.status='active' AND u.email_verified_at IS NOT NULL AND NOT u.cp_admin AND NOT u.must_change_password AND m.org_id=$3 AND m.role='member' AND m.access_revoked_at IS NULL AND o.slug='first-organization'`, user, email, org).Scan(&count) != nil || count != 1 {
		t.Fatal("exact owned verified member unavailable")
	}
	if pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE org_id=$1 AND user_id=$2 AND role='owner' AND access_revoked_at IS NULL`, org, actor).Scan(&count) != nil || count != 1 {
		t.Fatal("owned actor unavailable")
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 1})
	defer rdb.Close()
	if rdb.Ping(ctx).Err() != nil {
		t.Fatal("owned Redis1 unavailable")
	}
	parents := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	encodedMaster, e := os.ReadFile("/owned-api-state/master.key")
	if e != nil {
		t.Fatal("owned sealer mount unavailable")
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedMaster)))
	if e != nil || len(key) != crypto.KeySize {
		t.Fatal("owned sealer invalid")
	}
	sealer, e := crypto.NewSealer(key)
	if e != nil {
		t.Fatal("owned sealer unavailable")
	}
	manager := &licence.Manager{}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if !fixtureInstallEntitlement(manager, pub, priv, licence.Claims{Version: 1, Kid: "aa9-sso-ephemeral", ID: uuid.NewString(), Domain: "sso-console.127.0.0.1.sslip.io", Tier: "trial", Band: "trial"}, "valid") {
		t.Fatal("ephemeral signed licence unavailable")
	}
	signing, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	const issuer = "http://127.0.0.1:15187"
	const console = "https://sso-console.127.0.0.1.sslip.io:15190"
	const clientID = "aa9-owned-native-browser"
	var mu sync.Mutex
	codes := map[string]nativeBrowserOIDCCode{}
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
		codes[code] = nativeBrowserOIDCCode{r.Form.Get("nonce"), r.Form.Get("challenge"), time.Now().Add(time.Minute)}
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
	backup := nativeSSOConfigBackup(t, ctx, pool, org, actor, clientID)
	defer backup.Restore()
	if e = configs.Set(ctx, actor, org, "google", clientID, "owned-test-secret", "", true); e != nil {
		t.Fatal("audited SSO config failed")
	}
	backup.CaptureInstalled()
	ssoSvc := sso.NewService(pool, configs, sso.NewFlowStore(rdb, 10*time.Minute), factory, console, logger).WithLicence(manager)
	mfaSvc := mfa.NewService(pool, sealer, nil, logger)
	appSvc := appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.127.0.0.1.nip.io", ConsoleHosts: []string{"sso-console.127.0.0.1.sslip.io"}, ConsoleURL: console}).WithSessionAuthority(parents, appaccess.NewAppSessionStore(rdb), sealer, func(ctx context.Context, user uuid.UUID) (bool, error) {
		if !NewMfaEnforceEdition() {
			return false, nil
		}
		return mfaSvc.IsEnrollmentGated(ctx, user)
	})
	producer := appaccess.NewEventProducer(pool)
	defer producer.Close()
	appSvc.WithEventProducer(producer)
	router, e := NewRouter(logger, Deps{System: q, Auth: auth.NewService(pool, nil, console, parents, logger), Orgs: tenancy.NewService(pool), Members: tenancy.NewMembershipService(pool, parents), Sessions: parents, Licence: manager, Mfa: mfaSvc, MfaEnforceEnabled: NewMfaEnforceEdition(), AuthFn: SessionAuth(parents, q), SSO: &ssoAdapter{pool: pool, svc: ssoSvc}, AppAccess: appSvc, AppBaseURL: console, TrustedProxies: []string{"127.0.0.1", "::1", "aa9-sso-console"}})
	if e != nil {
		t.Fatal(e)
	}
	apiListener, e := net.Listen("tcp", ":15189")
	if e != nil {
		t.Fatal("owned SSO API port unavailable")
	}
	// Sidebar inventories outside this fixture are deliberately unavailable; do
	// not invoke optional nil service ports through background UI prefetches.
	boundedRouter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, suffix := range []string{"/sites", "/nodes", "/devices"} {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, suffix) {
				http.NotFound(w, r)
				return
			}
		}
		router.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: boundedRouter, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 32768}
	defer server.Close()
	go server.Serve(apiListener)
	fmt.Println("owned_native_ssobrowser_ready; exact_member; real_oidc_callback; existing_publication")
	<-ctx.Done()
}
