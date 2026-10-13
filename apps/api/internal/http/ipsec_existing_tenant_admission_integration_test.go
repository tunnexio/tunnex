package http

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Real nonzero foreign identities in a unique disposable DB, not live entitlement bypass.
func TestIPsecExistingTenantAndWrongSiteAdmission(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires owned isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "tnx_tenant_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+name); e != nil {
		t.Fatal(e)
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.Exec(c, "DROP DATABASE "+name+" WITH (FORCE)"); e != nil {
			t.Error(e)
		}
	}()
	u.Path = "/" + name
	if e = db.Up(u.String()); e != nil {
		t.Fatal(e)
	}
	p, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	orgA, orgB, actor, siteA, siteB, siteC, nodeA, nodeB, nodeC := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, q, a...); e != nil {
			t.Fatal(e)
		}
	}
	for _, org := range []uuid.UUID{orgA, orgB} {
		exec(`INSERT INTO organizations(id,name,slug,pool_cidr)VALUES($1,'isolated tenant',$2,'10.198.0.0/24')`, org, org.String())
	}
	exec(`INSERT INTO users(id,email)VALUES($1,$2)`, actor, actor.String()+"@tenant.test")
	for _, v := range [][2]uuid.UUID{{siteA, orgA}, {siteB, orgB}, {siteC, orgA}} {
		exec(`INSERT INTO sites(id,org_id,name)VALUES($1,$2,$3)`, v[0], v[1], v[0].String())
		exec(`INSERT INTO site_subnets(id,site_id,cidr,status)VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), v[0])
	}
	for _, v := range [][3]uuid.UUID{{nodeA, orgA, siteA}, {nodeB, orgB, siteB}, {nodeC, orgA, siteC}} {
		exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at)VALUES($1,$2,$3,$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, v[0], v[1], v[0].String(), v[2])
	}
	settings := ipsec.NewSettingsStore(p)
	for _, org := range []uuid.UUID{orgA, orgB} {
		if _, e = settings.Configure(ctx, org, actor, true, 0); e != nil {
			t.Fatal(e)
		}
	}
	seal, e := crypto.NewSealer(bytes.Repeat([]byte{0x37}, 32))
	if e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	var cfg ipsec.StaticConfig
	if e = json.Unmarshal([]byte(configurationCheckFixture), &cfg); e != nil {
		t.Fatal(e)
	}
	// Store input deliberately excludes JSON PSKs; install only synthetic fixture values.
	cfg.Tunnels[0].PSK = "Synthetic.fixturePSK_123"
	cfg.Tunnels[1].PSK = "Synthetic.fixturePSK_456"
	b, e := store.CreateProviderDisabled(ctx, orgB, actor, seal, ipsec.CreateProviderRequest{ID: uuid.New(), SiteID: siteB, GatewayID: nodeB, Name: "real OrgB disabled", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: cfg})
	if e != nil {
		t.Fatal(e)
	}
	var logs bytes.Buffer
	router, e := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{IPsecProviders: store, IPsecConnections: store, IPsecSealer: seal, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{orgA: rbac.RoleAdmin}}
	}})
	if e != nil {
		t.Fatal(e)
	}
	snapshot := func() string {
		var raw string
		e := p.QueryRow(ctx, `SELECT json_build_array((SELECT json_agg(c ORDER BY id)FROM ipsec_connections c),(SELECT json_agg(b ORDER BY connection_id)FROM ipsec_provider_bindings b),(SELECT json_agg(s ORDER BY tunnel_id)FROM ipsec_tunnel_secrets s),(SELECT count(*)FROM audit_logs))::text`).Scan(&raw)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	before := snapshot()
	call := func(method, path string, body any, want int) {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s status%d expected%d", method, w.Code, want)
		}
		if strings.Contains(w.Body.String(), cfg.Tunnels[0].PSK) || strings.Contains(w.Body.String(), cfg.Tunnels[1].PSK) {
			t.Fatal("secret in refusal")
		}
		if snapshot() != before {
			t.Fatal("admission refusal persisted partial state")
		}
	}
	for _, org := range []uuid.UUID{orgA, orgB} {
		call("GET", "/api/v1/organizations/"+org.String()+"/ipsec/connections/"+b.ID.String()+"/configuration", nil, 404)
	}
	for _, v := range [][2]uuid.UUID{{siteB, nodeB}, {siteB, nodeA}, {siteA, nodeB}, {siteC, nodeA}, {siteA, nodeC}} {
		body := map[string]any{"id": uuid.New(), "name": "refused foreign binding", "site_id": v[0], "gateway_node_id": v[1], "tunnel_ids": []uuid.UUID{uuid.New(), uuid.New()}, "configuration": json.RawMessage(configurationCheckFixture)}
		call("POST", "/api/v1/organizations/"+orgA.String()+"/ipsec/connections", body, 409)
	}
	// Correct existing OrgA binding remains admissible, proving no generic capability blocker.
	if _, e = store.CreateProviderDisabled(ctx, orgA, actor, seal, ipsec.CreateProviderRequest{ID: uuid.New(), SiteID: siteA, GatewayID: nodeA, Name: "positive owned binding", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: cfg}); e != nil {
		t.Fatal("positive owned binding refused", e)
	}
	if strings.Contains(logs.String(), cfg.Tunnels[0].PSK) {
		t.Fatal("secret in HTTP logs")
	}
}
