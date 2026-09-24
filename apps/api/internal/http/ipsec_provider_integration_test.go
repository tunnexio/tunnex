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

// All migrations target a unique scratch database in the guarded test project.
func TestIPsecProviderHTTPStoredLifecycleAndGates(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires guarded isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_provider_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(c, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), 160); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, actor, site, gateway, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, s := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'provider HTTP',$2,'10.198.0.0/24')`, []any{org, org.String()}},
		{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{actor, actor.String() + "@provider-http.test"}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'local')`, []any{site, org}},
		{`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, []any{uuid.New(), site}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'gateway',$3,$4,'{"ipsec_config_version":0}',clock_timestamp())`, []any{gateway, org, gateway.String(), site}},
	} {
		if _, err := pool.Exec(ctx, s.q, s.a...); err != nil {
			t.Fatal(err)
		}
	}
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := ipsec.NewConnectionStore(pool)
	settings := ipsec.NewSettingsStore(pool)
	role := rbac.RoleOwner
	var logs bytes.Buffer
	makeRouter := func(seal *crypto.Sealer) http.Handler {
		h, e := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{IPsecProviders: store, IPsecConnections: store, IPsecSealer: seal, AuthFn: func(*http.Request) *authctx.Principal {
			return &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
		}})
		if e != nil {
			t.Fatal(e)
		}
		return h
	}
	router := makeRouter(sealer)
	input := map[string]any{"id": id, "name": "Disabled provider", "site_id": site, "gateway_node_id": gateway, "tunnel_ids": []uuid.UUID{uuid.New(), uuid.New()}, "configuration": json.RawMessage(configurationCheckFixture)}
	body := func() string {
		b, e := json.Marshal(input)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	base := "/api/v1/organizations/" + org.String() + "/ipsec/connections"
	detail := base + "/" + id.String()
	configPath := detail + "/configuration"
	request := func(h http.Handler, method, path, body, etag string, want int) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		h.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Fatalf("%s status%d want%d: %s", method, rec.Code, want, rec.Body.String())
		}
		for _, marker := range []string{"Synthetic.fixturePSK", "sealed_psk", "secret_revision"} {
			if strings.Contains(rec.Body.String(), marker) || strings.Contains(logs.String(), marker) {
				t.Fatal("secret escaped HTTP/logs")
			}
		}
		return rec
	}
	untouched := func() {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_connections)+(SELECT count(*) FROM ipsec_provider_bindings)+(SELECT count(*) FROM ipsec_tunnel_secrets)+(SELECT count(*) FROM audit_logs WHERE action='ipsec.connection_created')`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("refusal wrote%d %v", n, err)
		}
	}
	request(router, "POST", base, body(), "", 409)
	untouched()
	if _, err := settings.Configure(ctx, org, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	request(router, "POST", base, body(), "", 409)
	untouched()
	if _, err := pool.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1}',policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, gateway); err != nil {
		t.Fatal(err)
	}
	request(router, "POST", base, body(), "", 409)
	untouched()
	if _, err := pool.Exec(ctx, `UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, gateway); err != nil {
		t.Fatal(err)
	}
	input["site_id"] = uuid.New()
	request(router, "POST", base, body(), "", 409)
	untouched()
	input["site_id"] = site
	input["configuration"] = json.RawMessage(strings.Replace(configurationCheckFixture, "10.10.0.0/16", "10.11.0.0/16", 1))
	request(router, "POST", base, body(), "", 409)
	untouched()
	input["configuration"] = json.RawMessage(configurationCheckFixture)
	request(makeRouter(nil), "POST", base, body(), "", 503)
	untouched()
	role = rbac.RoleMember
	request(router, "POST", base, body(), "", 403)
	untouched()
	role = rbac.RoleAdmin
	created := request(router, "POST", base, body(), "", 201)
	if created.Header().Get("ETag") != `"1"` || created.Header().Get("Location") != detail {
		t.Fatal("missing create identity/revision headers")
	}
	var saved map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &saved); err != nil || saved["desired_intent"] != "disabled" {
		t.Fatal("wrong desired intent")
	}
	var oldEnvelopes string
	if err := pool.QueryRow(ctx, `SELECT string_agg(sealed_psk,',' ORDER BY tunnel_id) FROM ipsec_tunnel_secrets WHERE connection_id=$1`, id).Scan(&oldEnvelopes); err != nil {
		t.Fatal(err)
	}
	input["configuration"] = json.RawMessage(strings.ReplaceAll(configurationCheckFixture, "Synthetic.fixturePSK", "Changed.fixturePSK"))
	request(router, "POST", base, body(), "", 409)
	var newEnvelopes string
	if err := pool.QueryRow(ctx, `SELECT string_agg(sealed_psk,',' ORDER BY tunnel_id) FROM ipsec_tunnel_secrets WHERE connection_id=$1`, id).Scan(&newEnvelopes); err != nil || oldEnvelopes != newEnvelopes {
		t.Fatal("retry changed existing credentials")
	}
	role = rbac.RoleMember
	read := request(router, "GET", configPath, "", "", 200)
	if read.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("configuration response cacheable")
	}
	if strings.Contains(strings.ToLower(read.Body.String()), "psk") {
		t.Fatal("credential field in read DTO")
	}
	var decoded struct {
		Profile       string `json:"profile_id"`
		Revision      int64  `json:"configuration_revision"`
		Configuration struct {
			Customer string           `json:"customer_outside_address"`
			Tunnels  []map[string]any `json:"tunnels"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &decoded); err != nil || decoded.Profile != "aws-static-ipv4-v1" || decoded.Revision != 1 || decoded.Configuration.Customer != "9.9.9.9" || len(decoded.Configuration.Tunnels) != 2 {
		t.Fatalf("wrong nonsecret projection: %v", err)
	}
	request(router, "GET", strings.Replace(configPath, org.String(), uuid.NewString(), 1), "", "", 404)
	request(router, "DELETE", detail, "", `"1"`, 403)
	role = rbac.RoleOwner
	request(router, "DELETE", detail, "", `"1"`, 200)
	tomb := request(router, "GET", configPath, "", "", 200)
	var retained map[string]json.RawMessage
	if err := json.Unmarshal(tomb.Body.Bytes(), &retained); err != nil {
		t.Fatal(err)
	}
	if _, ok := retained["configuration"]; ok {
		t.Fatal("tombstone returned live configuration")
	}
	var envelopes, children, creates int
	var metadata string
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_tunnel_secrets),(SELECT count(*) FROM ipsec_aws_static_configs),(SELECT count(*) FROM audit_logs WHERE action='ipsec.connection_created'),COALESCE((SELECT string_agg(metadata::text,' ') FROM audit_logs),'')`).Scan(&envelopes, &children, &creates, &metadata); err != nil || envelopes != 0 || children != 0 || creates != 1 {
		t.Fatalf("unexpected persisted counts%d/%d/%d %v", envelopes, children, creates, err)
	}
	if strings.Contains(metadata, "fixturePSK") || strings.Contains(metadata, "9.9.9.9") {
		t.Fatal("audit exposes private configuration")
	}
	legacyID := uuid.New()
	legacy := ipsec.CreateDisabledRequest{ID: legacyID, SiteID: site, GatewayID: gateway, Name: "Identity only", Tunnels: [2]ipsec.CreateTunnel{{ID: uuid.New(), PSK: "synthetic-legacy-PSK_1"}, {ID: uuid.New(), PSK: "synthetic-legacy-PSK_2"}}}
	if _, err := store.CreateDisabled(ctx, org, actor, sealer, legacy); err != nil {
		t.Fatal(err)
	}
	request(router, "GET", base+"/"+legacyID.String()+"/configuration", "", "", 404)
}
