package mcpoauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

type oauthFixture struct {
	svc               *Service
	pool              *pgxpool.Pool
	org, user, device uuid.UUID
	issuer            string
	// token is the issuer's reply to the next token request, by grant type.
	token map[string]func(w http.ResponseWriter)
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for the MCP OAuth lifecycle proof")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbName := "tnx_aisec1_oauth_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") })
	fresh := *base
	fresh.Path = "/" + dbName
	if err := db.MigrateTo(fresh.String(), 102); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, fresh.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f := &oauthFixture{pool: pool, org: uuid.New(), user: uuid.New(), device: uuid.New(), token: map[string]func(http.ResponseWriter){}}
	node := uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'AISEC1',$2,'10.124.0.0/24')`, []any{f.org, "aisec1-" + f.org.String()[:8]}},
		{`INSERT INTO users (id,email,name,status) VALUES ($1,$2,'AISEC1','active')`, []any{f.user, f.user.String() + "@aisec1.test"}},
		{`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw',$3)`, []any{node, f.org, "aisec1-" + node.String()}},
		{`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.124.0.2','active','agent')`, []any{f.device, f.org, f.user, node, "aisec1-" + f.device.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	mini, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mini.Close)
	sealer, err := crypto.NewSealer(make([]byte, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer/.well-known/oauth-authorization-server":
			_, _ = w.Write([]byte(`{"authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token"}`))
		case "/token":
			_ = r.ParseForm()
			if reply := f.token[r.Form.Get("grant_type")]; reply != nil {
				reply(w)
				return
			}
			http.Error(w, "unexpected grant", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	f.issuer = server.URL + "/issuer"
	f.svc = New(sqlc.New(pool), sealer, redis.NewClient(&redis.Options{Addr: mini.Addr()}), "https://cp.example")
	f.svc.http = server.Client()
	return f
}

func (f *oauthFixture) start(t *testing.T) (StartResult, string) {
	t.Helper()
	started, err := f.svc.Start(context.Background(), StartInput{OrgID: f.org, DeviceID: f.device, ActorID: f.user, Endpoint: "https://mcp.example/rpc", Resource: "https://mcp.example/resource", Issuer: f.issuer, Scopes: []string{"tools:read"}, ClientID: "registered-client"})
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(started.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	return started, authURL.Query().Get("state")
}

func (f *oauthFixture) connect(t *testing.T, tokenJSON string) StartResult {
	t.Helper()
	f.token["authorization_code"] = func(w http.ResponseWriter) { _, _ = w.Write([]byte(tokenJSON)) }
	started, state := f.start(t)
	if _, err := f.svc.Complete(context.Background(), state, "code", started.Binding); err != nil {
		t.Fatal(err)
	}
	return started
}

func (f *oauthFixture) state(t *testing.T, id uuid.UUID) (string, string, bool) {
	t.Helper()
	row, err := sqlc.New(f.pool).GetAgentMCPOAuthConnection(context.Background(), sqlc.GetAgentMCPOAuthConnectionParams{ID: id, OrgID: f.org, DeviceID: f.device})
	if err != nil {
		t.Fatal(err)
	}
	code := ""
	if row.FailureCode != nil {
		code = *row.FailureCode
	}
	return row.State, code, row.AccessTokenSealed != nil || row.RefreshTokenSealed != nil
}

func (f *oauthFixture) audited(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2`, f.org, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A forwarded authorization link must not let another browser finish consent.
func TestCompleteRequiresTheStartingBrowser(t *testing.T) {
	for name, binding := range map[string]string{"no cookie": "", "another browser": "not-the-binding"} {
		t.Run(name, func(t *testing.T) {
			f := newOAuthFixture(t)
			exchanged := false
			f.token["authorization_code"] = func(w http.ResponseWriter) {
				exchanged = true
				_, _ = w.Write([]byte(`{"access_token":"a","expires_in":60}`))
			}
			started, state := f.start(t)
			device, err := f.svc.Complete(context.Background(), state, "code", binding)
			if !errors.Is(err, ErrFlowNotFound) || device != f.device {
				t.Fatalf("device=%s err=%v", device, err)
			}
			if exchanged {
				t.Fatal("the authorization code was exchanged for a browser that did not start consent")
			}
			if got, code, sealed := f.state(t, started.ConnectionID); got != "failed" || code != "consent_browser_mismatch" || sealed {
				t.Fatalf("state=%s code=%s sealed=%v", got, code, sealed)
			}
			// The flow is consumed: the right browser cannot be raced afterwards.
			if _, err := f.svc.Complete(context.Background(), state, "code", started.Binding); !errors.Is(err, ErrFlowNotFound) {
				t.Fatalf("replay err=%v", err)
			}
			if f.audited(t, "agent.mcp_oauth.failed") != 1 {
				t.Fatal("the refused consent was not audited")
			}
		})
	}
}

func TestRefusedConsentFailsTheConnection(t *testing.T) {
	f := newOAuthFixture(t)
	started, state := f.start(t)
	if _, err := f.svc.Complete(context.Background(), state, "", started.Binding); !errors.Is(err, ErrExchange) {
		t.Fatalf("err=%v", err)
	}
	if got, code, _ := f.state(t, started.ConnectionID); got != "failed" || code != "consent_refused" {
		t.Fatalf("state=%s code=%s", got, code)
	}
}

// An issuer that states no lifetime issued a usable token.
func TestLeaseReturnsATokenWithoutAStatedLifetime(t *testing.T) {
	f := newOAuthFixture(t)
	f.connect(t, `{"access_token":"never-expires"}`)
	token, expires, err := f.svc.Lease(context.Background(), f.org, f.device, "https://mcp.example/rpc")
	if err != nil || token != "never-expires" || expires.IsZero() {
		t.Fatalf("token=%q expires=%s err=%v", token, expires, err)
	}
	if f.audited(t, "agent.mcp_oauth.connected") != 1 {
		t.Fatal("the connection was not audited")
	}
}

// A refresh the issuer rejects must stop reading as connected, and consent
// must be startable again.
func TestRejectedRefreshAsksForConsentAgain(t *testing.T) {
	f := newOAuthFixture(t)
	started := f.connect(t, `{"access_token":"short","refresh_token":"r","expires_in":1}`)
	f.token["refresh_token"] = func(w http.ResponseWriter) { http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest) }
	if _, _, err := f.svc.Lease(context.Background(), f.org, f.device, "https://mcp.example/rpc"); !errors.Is(err, ErrLease) {
		t.Fatalf("err=%v", err)
	}
	if got, code, sealed := f.state(t, started.ConnectionID); got != "expired" || code != "refresh_rejected" || sealed {
		t.Fatalf("state=%s code=%s sealed=%v", got, code, sealed)
	}
	if f.audited(t, "agent.mcp_oauth.reconsent_required") != 1 {
		t.Fatal("the lost credential was not audited")
	}
	again := f.connect(t, `{"access_token":"fresh","expires_in":3600}`)
	if got, _, _ := f.state(t, again.ConnectionID); got != "connected" || again.ConnectionID != started.ConnectionID {
		t.Fatalf("re-consent state=%s", got)
	}
	if token, _, err := f.svc.Lease(context.Background(), f.org, f.device, "https://mcp.example/rpc"); err != nil || token != "fresh" {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

// A temporary issuer outage is not a lost credential.
func TestIssuerOutageKeepsTheConnection(t *testing.T) {
	f := newOAuthFixture(t)
	started := f.connect(t, `{"access_token":"short","refresh_token":"r","expires_in":1}`)
	f.token["refresh_token"] = func(w http.ResponseWriter) { http.Error(w, "down", http.StatusServiceUnavailable) }
	if _, _, err := f.svc.Lease(context.Background(), f.org, f.device, "https://mcp.example/rpc"); !errors.Is(err, ErrLease) {
		t.Fatalf("err=%v", err)
	}
	if got, _, sealed := f.state(t, started.ConnectionID); got != "connected" || !sealed {
		t.Fatalf("state=%s sealed=%v", got, sealed)
	}
}

func TestDisconnectDiscardsTokensAndAllowsReconnect(t *testing.T) {
	f := newOAuthFixture(t)
	started := f.connect(t, `{"access_token":"a","refresh_token":"r","expires_in":3600}`)
	if err := f.svc.Disconnect(context.Background(), f.org, f.device, started.ConnectionID, f.user); err != nil {
		t.Fatal(err)
	}
	if got, _, sealed := f.state(t, started.ConnectionID); got != "disconnected" || sealed {
		t.Fatalf("state=%s sealed=%v", got, sealed)
	}
	if _, _, err := f.svc.Lease(context.Background(), f.org, f.device, "https://mcp.example/rpc"); !errors.Is(err, ErrLease) {
		t.Fatalf("lease after disconnect err=%v", err)
	}
	if f.audited(t, "agent.mcp_oauth.disconnected") != 1 {
		t.Fatal("the disconnect was not audited")
	}
	// Another organization's caller cannot disconnect it.
	if err := f.svc.Disconnect(context.Background(), uuid.New(), f.device, started.ConnectionID, f.user); !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("cross-org err=%v", err)
	}
	f.connect(t, `{"access_token":"b","expires_in":3600}`)
}
