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

func TestAuthorizationMetadataBindsProtectedResource(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issuer/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token","protected_resources":["https://mcp.example/resource"]}`))
	}))
	defer server.Close()
	svc := &Service{http: server.Client()}
	metadata, err := svc.authorizationMetadata(context.Background(), server.URL+"/issuer")
	if err != nil || !metadata.allowsResource("https://mcp.example/resource") || metadata.allowsResource("https://other.example/resource") {
		t.Fatalf("metadata=%#v err=%v", metadata, err)
	}
}

func TestStartAndCompleteUsesPKCEAndSealedCustody(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F13 database proof")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbName := "tnx_f13_oauth_" + uuid.NewString()[:8]
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
	defer pool.Close()
	org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F13',$2,'10.123.0.0/24')`, org, "f13-"+org.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,email,name,status) VALUES ($1,$2,'F13','active')`, user, user.String()+"@f13.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw',$3)`, node, org, "f13-"+node.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent',$5,'10.123.0.2','active','agent')`, device, org, user, node, "f13-"+device.String()); err != nil {
		t.Fatal(err)
	}
	mini, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mini.Close()
	sealer, err := crypto.NewSealer(make([]byte, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer/.well-known/oauth-authorization-server":
			_, _ = w.Write([]byte(`{"authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token","protected_resources":["https://mcp.example/resource"]}`))
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("resource") != "https://mcp.example/resource" || r.Form.Get("code_verifier") == "" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"access-secret","refresh_token":"refresh-secret","expires_in":60}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	svc := New(sqlc.New(pool), sealer, redis.NewClient(&redis.Options{Addr: mini.Addr()}), "https://cp.example")
	svc.http = server.Client()
	started, err := svc.Start(ctx, StartInput{OrgID: org, DeviceID: device, ActorID: user, Endpoint: "https://mcp.example/rpc", Resource: "https://mcp.example/resource", Issuer: server.URL + "/issuer", Scopes: []string{"tools:read"}, ClientID: "registered-client", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(started.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	state := authURL.Query().Get("state")
	if state == "" || authURL.Query().Get("code_challenge_method") != "S256" || authURL.Query().Get("resource") != "https://mcp.example/resource" {
		t.Fatalf("authorization URL=%s", started.RedirectURL)
	}
	if err := svc.Complete(ctx, state, "code"); err != nil {
		t.Fatal(err)
	}
	row, err := sqlc.New(pool).GetAgentMCPOAuthConnection(ctx, sqlc.GetAgentMCPOAuthConnectionParams{ID: started.ConnectionID, OrgID: org, DeviceID: device})
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "connected" || row.AccessTokenSealed == nil || *row.AccessTokenSealed == "access-secret" || row.RefreshTokenSealed == nil {
		t.Fatalf("sealed connection=%#v", row)
	}
	if _, err := sealer.Open(*row.AccessTokenSealed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, StartInput{OrgID: org, DeviceID: device, ActorID: user, Endpoint: "https://mcp.example/rpc", Resource: "https://mcp.example/resource", Issuer: server.URL + "/issuer", Scopes: []string{"tools:read"}, ClientID: "registered-client"}); !errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("repeat start err=%v", err)
	}
	if err := svc.Complete(ctx, state, "code"); !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("replay err=%v", err)
	}
}

func TestCleanScopesAndURLsFailClosed(t *testing.T) {
	if validURL("http://issuer.example") || validURL("https://user@issuer.example") || validURL("https://issuer.example/?q=1") {
		t.Fatal("unsafe issuer URL accepted")
	}
	got := cleanScopes([]string{"read", " read ", "", "write"})
	if len(got) != 2 || got[0] != "read" || got[1] != "write" {
		t.Fatalf("scopes=%#v", got)
	}
}
