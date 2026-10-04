package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
	"golang.org/x/net/netutil"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in nonshipping server: actual handlers, owned AA0 data and ephemeral signed
// entitlement. Production TrustedKeys and native Community CP remain untouched.
func TestAppAccessLocalPaidBrowserFixture(t *testing.T) {
	if os.Getenv("APP_ACCESS_BROWSER_FIXTURE") != "1" {
		t.Skip("owned browser fixture only")
	}
	marker := os.Getenv("TUNNEX_APP_ACCESS_RESTORE_MARKER")
	if marker != "/owned-app-restore/app-access.pending.json" || restorebarrier.Check(marker) != nil {
		t.Fatal("owned fixture restore fence unavailable")
	}
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != "/Users/pawangupta/tunnex/tests/app-access-local" {
		t.Fatal("unexpected fixture ownership")
	}
	password, email := os.Getenv("AA0_DB_PASSWORD"), os.Getenv("AA1_UI_EMAIL")
	if password == "" || email != "browser-aa1@example.test" {
		t.Fatal("owned fixture seed unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword("aa0", password), Host: "postgres:5432", Path: "/aa0", RawQuery: "sslmode=disable"}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var version int
	var dirty bool
	if err = pool.QueryRow(ctx, "SELECT version,dirty FROM schema_migrations").Scan(&version, &dirty); err != nil || version != 175 || dirty {
		t.Fatal("owned schema not clean AA7 compatible")
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM users u JOIN memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.org_id JOIN nodes n ON n.org_id=o.id WHERE u.email=$1 AND u.email_verified_at IS NOT NULL AND u.status='active' AND NOT u.must_change_password AND m.role='owner' AND o.slug='first-organization' AND n.name='aa0-gateway' AND n.status='active' AND n.enrolled_kind='gateway'`, email).Scan(&count); err != nil || count != 1 {
		t.Fatal("owned account/org/gateway seed not ready")
	}
	rdb := redis.NewClient(&redis.Options{Addr: "redis:6379", DB: 1})
	defer rdb.Close()
	if rdb.Ping(ctx).Err() != nil {
		t.Fatal("owned Redis db1 unavailable")
	}
	sessions := session.NewWithClient(rdb, time.Hour, 8*time.Hour)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := licence.Claims{Version: 1, Kid: "aa1-browser-ephemeral", ID: uuid.NewString(), Domain: "console.other.test", Tier: "trial", Band: "trial", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(4 * time.Hour).Unix()}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	wire := licence.Prefix + encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(encoded)))
	manager := &licence.Manager{}
	result, err := manager.Install(map[string]ed25519.PublicKey{claims.Kid: pub}, wire)
	if err != nil || !result.OK {
		t.Fatal("ephemeral signature rejected")
	}
	go fixtureEntitlementPoll(ctx, manager, pub, priv, claims)
	// Read existing owned roots only. A read-only transaction ensures that
	// LoadOrCreate cannot create or replace the CA even if the row disappears.
	masterEncoded, err := os.ReadFile("/owned-api-state/master.key")
	if err != nil {
		t.Fatal("owned read-only master key mount unavailable")
	}
	master, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(masterEncoded)))
	if err != nil || len(master) != 32 {
		t.Fatal("owned master key invalid")
	}
	sealer, err := crypto.NewSealer(master)
	if err != nil {
		t.Fatal("owned sealer unavailable")
	}
	readOnly, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Rollback(context.Background())
	queries := sqlc.New(readOnly)
	if _, err = queries.GetPlatformSecret(ctx, "agent_ca"); err != nil {
		t.Fatal("existing owned CA required")
	}
	ca, firstBoot, err := agentca.LoadOrCreate(ctx, queries, sealer)
	if err != nil || firstBoot {
		t.Fatal("existing owned CA load refused")
	}
	if err = readOnly.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mfaSvc := mfa.NewService(pool, sealer, nil, logger)
	domains := appdomains.New(pool, appdomains.Config{PortalURL: "https://console.127.0.0.1.sslip.io:15180", AppBaseDomain: "apps.127.0.0.1.nip.io"})
	appAccessSvc := appaccess.NewService(pool, appaccess.Config{AppBaseDomain: "apps.127.0.0.1.nip.io", ConsoleHosts: []string{"console.127.0.0.1.sslip.io"}, ConsoleURL: "https://console.127.0.0.1.sslip.io:15180"}).WithDomainProvider(domains).WithSessionAuthority(sessions, appaccess.NewAppSessionStore(rdb), sealer, func(ctx context.Context, user uuid.UUID) (bool, error) {
		if !NewMfaEnforceEdition() {
			return false, nil
		}
		return mfaSvc.IsEnrollmentGated(ctx, user)
	})
	appAccessFixturePublicCA(t, ca)
	appEvents := appaccess.NewEventProducer(pool)
	t.Cleanup(appEvents.Close)
	appAccessSvc.WithEventProducer(appEvents)
	appAccessFixtureLeaf(t, ca, "payroll.apps.127.0.0.1.nip.io", "app")
	appAccessFixtureLeaf(t, ca, "console.127.0.0.1.sslip.io", "console")
	appAccessFixtureLeaf(t, ca, "tunnex-app-proxy", "gateway-proxy")
	appAccessFixtureProxyCredential(t, ctx, appAccessSvc)
	handler, err := NewRouter(logger, Deps{AppDomains: domains, System: sqlc.New(pool), Auth: auth.NewService(pool, nil, "https://console.127.0.0.1.sslip.io:15180", sessions, logger), Orgs: tenancy.NewService(pool), Members: tenancy.NewMembershipService(pool, sessions), Nodes: nodes.NewService(pool, nil, nil), Devices: devices.NewService(pool, nil, logger), Policy: NewPolicyPortWithFQDN(pool, nil, manager), Sessions: sessions, AuthFn: SessionAuth(sessions, sqlc.New(pool)), Mfa: mfaSvc, MfaEnforceEnabled: NewMfaEnforceEdition(), Licence: manager, AppAccess: appAccessSvc, AppBaseURL: "https://console.127.0.0.1.sslip.io:15180", TrustedProxies: []string{"127.0.0.1", "::1", "app-console-fixture"}})
	if err != nil {
		t.Fatal(err)
	}

	lifecycle := appAccessLifecycleFixtureTargets{GroupName: "AA8 synthetic lifecycle group", GroupDescription: "Owned local lifecycle qualification; synthetic member only"}
	if err = pool.QueryRow(ctx, "SELECT id FROM organizations WHERE slug='first-organization' AND deleted_at IS NULL").Scan(&lifecycle.OrgID); err != nil {
		t.Fatal("owned lifecycle organization unavailable")
	}
	for fixtureEmail, target := range map[string]*uuid.UUID{"aa8-direct@example.test": &lifecycle.DirectUserID, "aa8-group@example.test": &lifecycle.GroupUserID} {
		if err = pool.QueryRow(ctx, "SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.email=$1 AND u.deleted_at IS NULL AND NOT u.cp_admin AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password AND m.org_id=$2 AND m.role='member' AND m.access_revoked_at IS NULL", fixtureEmail, lifecycle.OrgID).Scan(target); err != nil {
			t.Fatal("owned synthetic member unavailable")
		}
	}
	lifecycle.OwnedGroup = func(r *http.Request, id uuid.UUID) bool {
		bounded, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var owned bool
		err := pool.QueryRow(bounded, "SELECT EXISTS (SELECT 1 FROM user_groups g WHERE g.id=$1 AND g.org_id=$2 AND g.name=$3 AND g.description=$4 AND g.origin='manual' AND NOT EXISTS (SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.org_id=g.org_id AND gm.user_id<>$5))", id, lifecycle.OrgID, lifecycle.GroupName, lifecycle.GroupDescription, lifecycle.GroupUserID).Scan(&owned)
		return err == nil && owned
	}
	safe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ready","provenance":"test-only signed entitlement; real handlers; owned aa0 and redis db1"}`)
			return
		}
		if !appAccessBrowserFixtureAllowed(r) && !lifecycle.Allowed(r) {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: ":18084", Handler: safe, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	channel := NewAgentChannel(nodes.NewService(pool, ca, sealer), ca, nil, logger)
	channel.SetAppAccessConnector(appAccessSvc, manager)
	defer channel.CloseAppAccessConnector()
	tlsConfig, err := channel.TLSConfig("app-access-fixture")
	if err != nil {
		t.Fatal("owned app-control TLS leaf unavailable")
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	privateRoutes := channel.Handler()
	privateSafe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		allowed := r.Method == "CONNECT" && path == "/agent/app-access/channel" || r.Method == "GET" && (path == "/agent/app-access/desired-state" || path == "/agent/app-access/browser-desired-state") || r.Method == "POST" && (path == "/agent/app-access/capability" || path == "/agent/app-access/browser-capability" || path == "/agent/app-access/report" || strings.HasPrefix(path, "/agent/app-access/checks/") && strings.HasSuffix(path, "/result"))
		if !allowed {
			http.NotFound(w, r)
			return
		}
		privateRoutes.ServeHTTP(w, r)
	})
	agentServer := &http.Server{Addr: ":18447", Handler: privateSafe, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	authorityLeaf, err := ca.ServerTLSCertificate("tunnex-app-authority")
	if err != nil {
		t.Fatal("owned authority TLS leaf unavailable")
	}
	authorityServer := &http.Server{Addr: ":18448", Handler: NewAppProxyAuthorityHandler(appAccessSvc, func() bool { return manager.Has(licence.FeatAppAccess, time.Now()) }), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{authorityLeaf}, NextProtos: []string{"http/1.1"}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10}
	failures := make(chan error, 3)
	go func() { failures <- server.ListenAndServe() }()
	agentListener, err := net.Listen("tcp", ":18447")
	if err != nil {
		t.Fatal(err)
	}
	go func() { failures <- agentServer.ServeTLS(netutil.LimitListener(agentListener, 256), "", "") }()
	authorityListener, err := net.Listen("tcp", ":18448")
	if err != nil {
		t.Fatal(err)
	}
	go func() { failures <- authorityServer.ServeTLS(netutil.LimitListener(authorityListener, 256), "", "") }()
	t.Log("Test-only paid browser fixture :18084; host publish must stay loopback; native Community unchanged")
	select {
	case <-ctx.Done():
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		server.Shutdown(shutdown)
		agentServer.Shutdown(shutdown)
		authorityServer.Shutdown(shutdown)
	case err := <-failures:
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}
}

func appAccessBrowserFixtureAllowed(r *http.Request) bool {
	p := r.URL.Path
	if p == "/api/v1/admin/app-access/domains" && (r.Method == "GET" || r.Method == "PATCH") {
		return true
	}
	if r.Method == "GET" && (p == "/api/v1/meta" || p == "/api/v1/license" || p == "/api/v1/auth/me" || p == "/api/v1/organizations") {
		return true
	}
	if r.Method == "POST" && (p == "/api/v1/auth/login" || p == "/api/v1/auth/logout") {
		return true
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "organizations" {
		return false
	}
	if _, err := uuid.Parse(parts[3]); err != nil {
		return false
	}
	if len(parts) == 5 && (parts[4] == "members" || parts[4] == "nodes" || parts[4] == "audit-logs") && r.Method == "GET" {
		return true
	}
	if r.Method == "GET" && len(parts) == 5 && parts[4] == "groups" {
		return true
	}
	if r.Method == "GET" && len(parts) == 7 && parts[4] == "groups" && parts[6] == "members" {
		_, err := uuid.Parse(parts[5])
		return err == nil
	}
	if r.Method == "DELETE" && len(parts) == 7 && parts[4] == "app-access" && parts[5] == "my-sessions" {
		_, err := uuid.Parse(parts[6])
		return err == nil
	}
	if r.Method == "DELETE" && len(parts) == 7 && parts[4] == "app-access" && parts[5] == "applications" {
		_, err := uuid.Parse(parts[6])
		return err == nil
	}
	if r.Method == "DELETE" && len(parts) == 9 && parts[4] == "app-access" && parts[5] == "applications" && parts[7] == "sessions" {
		_, appErr := uuid.Parse(parts[6])
		_, sessionErr := uuid.Parse(parts[8])
		return appErr == nil && sessionErr == nil
	}
	return parts[4] == "app-access" && (r.Method == "GET" || r.Method == "POST" || r.Method == "PATCH")
}

func TestAppAccessBrowserFixtureAllowedRoutes(t *testing.T) {
	const org = "11111111-1111-4111-8111-111111111111"
	const app = "22222222-2222-4222-8222-222222222222"
	const sess = "33333333-3333-4333-8333-333333333333"
	base := "/api/v1/organizations/" + org
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", base + "/audit-logs", true},
		{"POST", base + "/audit-logs", false},
		{"GET", base + "/audit-logs/extra", false},
		{"GET", "/api/v1/organizations/invalid/audit-logs", false},
		{"DELETE", base + "/app-access/applications/" + app + "/sessions/" + sess, true},
		{"DELETE", base + "/app-access/applications/invalid/sessions/" + sess, false},
		{"DELETE", base + "/app-access/applications/" + app + "/sessions/invalid", false},
		{"DELETE", base + "/app-access/applications/" + app + "/sessions", false},
		{"DELETE", base + "/app-access/applications/" + app + "/sessions/" + sess + "/extra", false},
		{"DELETE", base + "/app-access/applications/" + app + "/grants/" + sess, false},
		{"DELETE", base + "/members/" + sess, false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, "http://fixture"+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := appAccessBrowserFixtureAllowed(r); got != tc.want {
				t.Fatalf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// These extra routes are nonshipping and target only explicitly seeded members.
// The real router still applies its unchanged human RBAC and CSRF middleware.
type appAccessLifecycleFixtureTargets struct {
	OrgID, DirectUserID, GroupUserID uuid.UUID
	GroupName, GroupDescription      string
	OwnedGroup                       func(*http.Request, uuid.UUID) bool
}

func fixtureBoundedBody(r *http.Request, target any) bool {
	if r.Body == nil {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) > 4096 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}
func (f appAccessLifecycleFixtureTargets) Allowed(r *http.Request) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "organizations" || parts[3] != f.OrgID.String() || f.OrgID == uuid.Nil || f.DirectUserID == uuid.Nil || f.GroupUserID == uuid.Nil {
		return false
	}
	if len(parts) == 7 && parts[4] == "members" && r.Method == "POST" && (parts[6] == "deactivate" || parts[6] == "reactivate") {
		return parts[5] == f.DirectUserID.String() || parts[5] == f.GroupUserID.String()
	}
	if parts[4] != "groups" {
		return false
	}
	if len(parts) == 5 && r.Method == "POST" {
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		return fixtureBoundedBody(r, &body) && body.Name == f.GroupName && body.Description == f.GroupDescription
	}
	if len(parts) < 6 || f.OwnedGroup == nil {
		return false
	}
	group, err := uuid.Parse(parts[5])
	if err != nil || !f.OwnedGroup(r, group) {
		return false
	}
	if len(parts) == 6 && r.Method == "DELETE" {
		return true
	}
	if len(parts) == 7 && parts[6] == "members" && r.Method == "POST" {
		var body struct {
			UserID uuid.UUID `json:"user_id"`
		}
		return fixtureBoundedBody(r, &body) && body.UserID == f.GroupUserID
	}
	return len(parts) == 8 && parts[6] == "members" && r.Method == "DELETE" && parts[7] == f.GroupUserID.String()
}
func TestAppAccessLifecycleFixtureTargetGuards(t *testing.T) {
	org, direct, groupUser, group, review := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	targets := appAccessLifecycleFixtureTargets{OrgID: org, DirectUserID: direct, GroupUserID: groupUser, GroupName: "AA8 synthetic lifecycle group", GroupDescription: "synthetic only", OwnedGroup: func(_ *http.Request, id uuid.UUID) bool { return id == group }}
	base := "/api/v1/organizations/" + org.String()
	groupBase := base + "/groups/" + group.String()
	for _, tc := range []struct {
		method, path, body string
		want               bool
	}{
		{"POST", base + "/groups", `{"name":"AA8 synthetic lifecycle group","description":"synthetic only"}`, true},
		{"POST", base + "/groups", `{"name":"production","description":"synthetic only"}`, false},
		{"POST", base + "/groups", `{"name":"AA8 synthetic lifecycle group","description":"synthetic only","extra":true}`, false},
		{"POST", groupBase + "/members", `{"user_id":"` + groupUser.String() + `"}`, true},
		{"POST", groupBase + "/members", `{"user_id":"` + review.String() + `"}`, false},
		{"DELETE", groupBase + "/members/" + groupUser.String(), "", true},
		{"DELETE", groupBase + "/members/" + review.String(), "", false},
		{"DELETE", base + "/groups/" + uuid.NewString(), "", false},
		{"DELETE", groupBase, "", true},
		{"POST", base + "/members/" + direct.String() + "/deactivate", "", true},
		{"POST", base + "/members/" + groupUser.String() + "/reactivate", "", true},
		{"POST", base + "/members/" + review.String() + "/deactivate", "", false},
		{"POST", "/api/v1/organizations/" + uuid.NewString() + "/members/" + direct.String() + "/deactivate", "", false},
		{"DELETE", base + "/members/" + direct.String(), "", false},
	} {
		t.Run(tc.method+tc.path+tc.body, func(t *testing.T) {
			r := http.Request{Method: tc.method, URL: &url.URL{Path: tc.path}, Body: io.NopCloser(strings.NewReader(tc.body))}
			if got := targets.Allowed(&r); got != tc.want {
				t.Fatalf("guard allowed=%v want%v", got, tc.want)
			}
			if tc.body != "" {
				body, _ := io.ReadAll(r.Body)
				if string(body) != tc.body {
					t.Fatal("guard changed handler body")
				}
			}
		})
	}
}
