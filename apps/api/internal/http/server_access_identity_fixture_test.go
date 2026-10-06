package http

// Nonshipping owned Server Access SSO fixture: exact existing member, Redis DB0, real
// OIDC verification and production callback. Scoped SSO configuration is restored.
import (
	"context"
	stdcrypto "crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
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

type serverAccessIdentityCode struct {
	Nonce, Challenge string
	Mode             string
	ExpiresAt        time.Time
}

func TestServerAccessOwnedSSOIdentityFixture(t *testing.T) {
	if os.Getenv("SERVER_ACCESS_SSO_IDENTITY_FIXTURE") != "1" {
		t.Skip("owned standalone SSO browser only")
	}
	if os.Getenv("SERVER_ACCESS_OWNED_PROJECT") != "tunnex-sa0-browser-1005" || os.Getenv("SERVER_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/.codex/worktrees/main-app-access-compare/tunnex/tests/server-access-local" || os.Getenv("AA0_DB_PASSWORD") == "" {
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
	if pool.QueryRow(ctx, "SELECT version,dirty FROM schema_migrations").Scan(&version, &dirty) != nil || version != 185 || dirty {
		t.Fatal("owned native SSO schema mismatch")
	}
	q := sqlc.New(pool)
	org := uuid.MustParse("01a109d9-382b-7bc1-82c9-2b0bf036139c")
	user := uuid.MustParse("11111111-1111-4111-8111-111111111182")
	actor := uuid.MustParse("11111111-1111-4111-8111-111111111181")
	email := "terminal-member@sa0.local"
	var count int
	if pool.QueryRow(ctx, `SELECT count(*) FROM users u JOIN memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.org_id WHERE u.id=$1 AND u.email=$2 AND u.status='active' AND u.email_verified_at IS NOT NULL AND NOT u.cp_admin AND NOT u.must_change_password AND m.org_id=$3 AND m.role='member' AND m.access_revoked_at IS NULL AND o.name='SA-0 local qualification'`, user, email, org).Scan(&count) != nil || count != 1 {
		t.Fatal("exact owned verified member unavailable")
	}
	if pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE org_id=$1 AND user_id=$2 AND role='admin' AND access_revoked_at IS NULL`, org, actor).Scan(&count) != nil || count != 1 {
		t.Fatal("owned actor unavailable")
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	if rdb.Ping(ctx).Err() != nil {
		t.Fatal("owned Redis0 unavailable")
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
	signing, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	const issuer = "http://127.0.0.1:15187"
	const console = "http://127.0.0.1:15189"
	const clientID = "sa9-owned-native-identity"
	var mu sync.Mutex
	codes := map[string]serverAccessIdentityCode{}
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
		_ = template.Must(template.New("consent").Parse(`<html><body><h1>Owned test identity provider</h1><p>Sign in as the verified synthetic member.</p><form method="post" action="/approve"><input type="hidden" name="state" value="{{.State}}"><input type="hidden" name="nonce" value="{{.Nonce}}"><input type="hidden" name="challenge" value="{{.Challenge}}"><label>Signed assurance <select name="mode"><option value="fresh">Fresh verified MFA</option><option value="absent">Absent MFA</option><option value="stale">Stale MFA</option><option value="future">Future MFA</option><option value="wrongnonce">Wrong nonce</option><option value="wrongaudience">Wrong audience</option><option value="badsignature">Invalid signature</option></select></label><button>Continue with owned test identity</button></form></body></html>`)).Execute(w, map[string]string{"State": r.URL.Query().Get("state"), "Nonce": r.URL.Query().Get("nonce"), "Challenge": r.URL.Query().Get("code_challenge")})
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
		mode := r.Form.Get("mode")
		switch mode {
		case "fresh", "absent", "stale", "future", "wrongnonce", "wrongaudience", "badsignature":
		default:
			mu.Unlock()
			http.Error(w, "refused", 403)
			return
		}
		codes[code] = serverAccessIdentityCode{r.Form.Get("nonce"), r.Form.Get("challenge"), mode, time.Now().Add(time.Minute)}
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
		tokenClaims := map[string]any{"iss": issuer, "aud": clientID, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "sub": "sa9-owned-sso-member", "email": email, "email_verified": true, "name": "SA9 SSO member", "nonce": record.Nonce}
		switch record.Mode {
		case "fresh":
			tokenClaims["amr"] = []string{"pwd", "mfa"}
			tokenClaims["auth_time"] = time.Now().Unix()
		case "stale":
			tokenClaims["amr"] = []string{"pwd", "mfa"}
			tokenClaims["auth_time"] = time.Now().Add(-2 * time.Hour).Unix()
		case "future":
			tokenClaims["amr"] = []string{"pwd", "mfa"}
			tokenClaims["auth_time"] = time.Now().Add(time.Minute).Unix()
		case "wrongnonce":
			tokenClaims["nonce"] = "incorrect-nonce"
		case "wrongaudience":
			tokenClaims["aud"] = "different-client"
		}
		claims, _ := json.Marshal(tokenClaims)
		head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "owned-sso"})
		input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(input))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, signing, stdcrypto.SHA256, digest[:])
		if record.Mode == "badsignature" {
			signature[0] ^= 1
		}
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
	router, e := NewRouter(logger, Deps{System: q, Auth: auth.NewService(pool, nil, console, parents, logger), Orgs: tenancy.NewService(pool), Members: tenancy.NewMembershipService(pool, parents), Sessions: parents, Licence: manager, Mfa: mfaSvc, MfaEnforceEnabled: NewMfaEnforceEdition(), AuthFn: SessionAuth(parents, q), SSO: &ssoAdapter{pool: pool, svc: ssoSvc}, AppBaseURL: console})
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
		if r.Method == "GET" && (r.URL.Path == "/browser-access/terminal" || r.URL.Path == "/" || r.URL.Path == "/login") {
			http.Redirect(w, r, "http://127.0.0.1:15195"+r.URL.RequestURI(), 303)
			return
		}
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
	fmt.Println("owned_server_access_sso_ready; exact_member; real_signed_oidc_callback; Redis0; no_shipping_auth_patch")
	<-ctx.Done()
}

// Separate nonshipping enrollment topology uses a signed test Scale entitlement
// only on this HTTP service. The baseline CP remains Community. Certificates
// are issued by the real encrypted installation CA and tested on baseline mTLS.
func TestServerAccessOwnedIdentityEnrollmentFixture(t *testing.T) {
	if os.Getenv("SERVER_ACCESS_IDENTITY_ENROLL_FIXTURE") != "1" {
		t.Skip("owned standalone enrollment only")
	}
	if os.Getenv("SERVER_ACCESS_OWNED_PROJECT") != "tunnex-sa0-browser-1005" || os.Getenv("SERVER_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/.codex/worktrees/main-app-access-compare/tunnex/tests/server-access-local" || os.Getenv("AA0_DB_PASSWORD") == "" {
		t.Fatal("foreign fixture refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", os.Getenv("AA0_DB_PASSWORD")), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal("owned DB unavailable")
	}
	defer pool.Close()
	var name string
	var count int
	if pool.QueryRow(ctx, `SELECT current_database(),count(*) FROM organizations WHERE id NOT IN ('b2891d06-c082-4800-a418-f987e52ef3e9','7e52582a-b12e-459d-8bd8-d167a727c4ef','0f310c80-342e-47ee-9c11-e9862c9f58c6') OR name <> 'SA9 owned identity ' || id::text GROUP BY current_database()`).Scan(&name, &count) != nil || name != "aa0" || count != 1 {
		t.Fatal("foreign DB refused")
	}
	var org uuid.UUID
	if pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA-0 local qualification'`).Scan(&org) != nil || org.String() != "01a109d9-382b-7bc1-82c9-2b0bf036139c" {
		t.Fatal("foreign org refused")
	}
	encoded, err := os.ReadFile("/owned-api-state/master.key")
	if err != nil {
		t.Fatal("owned master unavailable")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != crypto.KeySize {
		t.Fatal("owned key invalid")
	}
	defer clear(key)
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	ca, created, err := agentca.LoadOrCreate(ctx, q, sealer)
	if err != nil || created {
		t.Fatal("existing installation CA required")
	}
	manager := &licence.Manager{}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !fixtureInstallEntitlement(manager, pub, priv, licence.Claims{Version: 1, Kid: "sa9-enrollment-only", ID: uuid.NewString(), Domain: "localhost", Tier: "scale", Band: "scale"}, "valid") {
		t.Fatal("signed fixture entitlement failed")
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 0})
	defer rdb.Close()
	parents := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router, err := NewRouter(logger, Deps{System: q, Nodes: nodes.NewService(pool, ca, sealer).WithLicence(manager), AuthFn: SessionAuth(parents, q), Sessions: parents, Orgs: tenancy.NewService(pool), Members: tenancy.NewMembershipService(pool, parents), Licence: manager, AppBaseURL: "http://127.0.0.1:15189"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", ":15189")
	if err != nil {
		t.Fatal("owned fixture port busy")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/enroll" && !strings.HasSuffix(r.URL.Path, "/nodes/join-token") && !strings.HasSuffix(r.URL.Path, "/revoke") {
			http.NotFound(w, r)
			return
		}
		router.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 32768}
	defer server.Close()
	go server.Serve(listener)
	fmt.Println("owned_identity_enrollment_ready; real_installation_CA; ephemeral_test_Scale_entitlement; baseline_Community_unchanged")
	<-ctx.Done()
}
