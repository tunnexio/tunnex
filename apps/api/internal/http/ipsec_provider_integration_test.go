package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
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
	testProviderHTTPStoredLifecycle(t, configurationCheckFixture, "aws-static-ipv4-v1", 2)
}

func TestGCPProviderHTTPStoredLifecycleAndRoles(t *testing.T) {
	for _, profile := range []string{ipsec.GCPHAProfile, ipsec.GCPClassicProfile} {
		t.Run(profile, func(t *testing.T) {
			var config map[string]any
			if err := json.Unmarshal([]byte(configurationCheckFixture), &config); err != nil {
				t.Fatal(err)
			}
			config["profile_id"] = profile
			count := 2
			if profile == ipsec.GCPHAProfile {
				config["mode"] = "ipv4-bgp"
				config["bgp"] = map[string]any{"local_asn": 65000, "remote_asn": 65002, "router_id": "10.10.0.1", "maximum_prefixes": 16}
			} else {
				count = 1
				tunnels := config["tunnels"].([]any)[:1]
				for _, key := range []string{"inside_cidr", "customer_inside_address", "cloud_inside_address"} {
					tunnels[0].(map[string]any)[key] = ""
				}
				config["tunnels"] = tunnels
			}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			testProviderHTTPStoredLifecycle(t, string(raw), profile, count)
		})
	}
}

func testProviderHTTPStoredLifecycle(t *testing.T, fixture, profile string, tunnelCount int) {
	t.Helper()
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
	if err := db.Up(u.String()); err != nil {
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
	store.ConfigureRuntimePolicy(func(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64), Grants: []ipsec.RuntimeGrant{{Source: in.Config.LocalPrefixes[0], Destination: in.Config.RemotePrefixes[0], Protocol: "any", RuleID: "http-fixture"}}}, nil
	})
	foreignOrg := uuid.New()
	role := rbac.RoleOwner
	var logs bytes.Buffer
	makeRouter := func(seal *crypto.Sealer) http.Handler {
		h, e := NewRouter(slog.New(slog.NewTextHandler(&logs, nil)), Deps{IPsecProviders: store, IPsecConnections: store, IPsecRuntime: store, IPsecEligibility: store, IPsecStatus: store, IPsecSealer: seal, AuthFn: func(*http.Request) *authctx.Principal {
			roles := map[uuid.UUID]string{org: role}
			if role == "" {
				roles = map[uuid.UUID]string{foreignOrg: rbac.RoleOwner}
			}
			return &authctx.Principal{UserID: actor, EmailVerified: true, Roles: roles}
		}})
		if e != nil {
			t.Fatal(e)
		}
		return h
	}
	router := makeRouter(sealer)
	input := map[string]any{"id": id, "name": "Disabled provider", "site_id": site, "gateway_node_id": gateway, "tunnel_ids": []uuid.UUID{uuid.New(), uuid.New()}[:tunnelCount], "configuration": json.RawMessage(fixture)}
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
	requestNumber := 0
	request := func(h http.Handler, method, path, body, etag string, want int) *httptest.ResponseRecorder {
		t.Helper()
		requestNumber++
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		h.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Fatalf("request %d %s %s status%d want%d: %s", requestNumber, method, path, rec.Code, want, rec.Body.String())
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
	input["configuration"] = json.RawMessage(strings.Replace(fixture, "10.10.0.0/16", "10.11.0.0/16", 1))
	request(router, "POST", base, body(), "", 409)
	untouched()
	input["configuration"] = json.RawMessage(fixture)
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
	reservations, err := sqlc.New(pool).ListIPsecProviderReservations(ctx, org)
	if err != nil {
		t.Fatal("stored provider poisoned common range reservations", err)
	}
	counts := map[string]int{}
	for _, reservation := range reservations {
		if reservation.Cidr == "" {
			t.Fatal("empty network reservation")
		}
		counts[reservation.Class]++
	}
	insideCount := tunnelCount
	if profile == ipsec.GCPClassicProfile {
		insideCount = 0
	}
	if counts["ipsec_remote"] != 1 || counts["ipsec_underlay"] != tunnelCount+1 || counts["ipsec_inside"] != insideCount {
		t.Fatal("provider range reservations lost", counts)
	}
	var oldEnvelopes string
	if err := pool.QueryRow(ctx, `SELECT string_agg(sealed_psk,',' ORDER BY tunnel_id) FROM ipsec_tunnel_secrets WHERE connection_id=$1`, id).Scan(&oldEnvelopes); err != nil {
		t.Fatal(err)
	}
	input["configuration"] = json.RawMessage(strings.ReplaceAll(fixture, "Synthetic.fixturePSK", "Changed.fixturePSK"))
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
	if err := json.Unmarshal(read.Body.Bytes(), &decoded); err != nil || decoded.Profile != profile || decoded.Revision != 1 || decoded.Configuration.Customer != "9.9.9.9" || len(decoded.Configuration.Tunnels) != tunnelCount {
		t.Fatalf("wrong nonsecret projection: %v", err)
	}
	request(router, "GET", strings.Replace(configPath, org.String(), uuid.NewString(), 1), "", "", 404)
	request(router, "DELETE", detail, "", `"1"`, 403)
	deleteRevision := `"1"`
	if profile != "aws-static-ipv4-v1" {
		intentPath := detail + "/intent"
		statusPath := detail + "/status"
		eligibilityPath := "/api/v1/organizations/" + org.String() + "/ipsec/eligibility?site_id=" + site.String() + "&gateway_node_id=" + gateway.String()
		request(router, "PUT", intentPath, `{"intent":"enabled"}`, `"1"`, 403)
		request(router, "GET", statusPath, "", "", 200)
		request(router, "GET", eligibilityPath, "", "", 200)
		// A caller with no membership cannot discover or change the stored GCP identity.
		role = ""
		request(router, "GET", configPath, "", "", 404)
		request(router, "PUT", intentPath, `{"intent":"enabled"}`, `"1"`, 404)
		request(router, "GET", strings.Replace(configPath, org.String(), foreignOrg.String(), 1), "", "", 404)
		request(router, "PUT", strings.Replace(intentPath, org.String(), foreignOrg.String(), 1), `{"intent":"enabled"}`, `"1"`, 404)
		role = rbac.RoleAdmin
		request(router, "PUT", intentPath, `{"intent":"enabled"}`, `"1"`, 409)
		if _, err := pool.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_bgp_version":1,"ipsec_gcp_ha_version":1,"ipsec_gcp_classic_version":1,"ipsec_retained_guard_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, gateway); err != nil {
			t.Fatal(err)
		}
		eligible := request(router, "GET", eligibilityPath, "", "", 200)
		var projection map[string]json.RawMessage
		if err := json.Unmarshal(eligible.Body.Bytes(), &projection); err != nil {
			t.Fatal(err)
		}
		key := "gcp_ha"
		if profile == ipsec.GCPClassicProfile {
			key = "gcp_classic"
		}
		var gate struct {
			Eligible bool `json:"eligible"`
		}
		if err := json.Unmarshal(projection[key], &gate); err != nil || !gate.Eligible {
			t.Fatal("profile gate not qualified", err)
		}
		enabled := request(router, "PUT", intentPath, `{"intent":"enabled"}`, `"1"`, 200)
		if enabled.Header().Get("ETag") != `"2"` {
			t.Fatal("activation CAS lost")
		}
		request(router, "PUT", intentPath, `{"intent":"disabled"}`, `"1"`, 409)
		principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: gateway, CertificateSerial: gateway.String()}
		material, err := store.Material(ctx, principal, id, 2, sealer)
		if err != nil {
			t.Fatal(err)
		}
		leaseRequest := ipsec.RuntimeLeaseRequest{DeliveryID: material.ID, DesiredRevision: 2, PolicyHash: material.Policy.Hash, Nonce: strings.Repeat("b", 64)}
		lease, err := store.PermitLease(ctx, principal, id, leaseRequest)
		if err != nil || lease.TTLMS != 60000 {
			t.Fatal("qualified bounded lease refused", err)
		}
		store.ConfigureRuntimePolicy(func(context.Context, *sqlc.Queries, ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
			return ipsec.RuntimePolicy{Hash: strings.Repeat("c", 64), Grants: []ipsec.RuntimeGrant{}}, nil
		})
		if _, err = store.PermitLease(ctx, principal, id, leaseRequest); !errors.Is(err, ipsec.ErrConnectionConflict) {
			t.Fatal("withdrawn policy renewed stale delivery", err)
		}
		store.ConfigureRuntimePolicy(func(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
			return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64), Grants: []ipsec.RuntimeGrant{{Source: in.Config.LocalPrefixes[0], Destination: in.Config.RemotePrefixes[0], Protocol: "any", RuleID: "http-fixture"}}}, nil
		})
		if _, err = pool.Exec(ctx, `UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, gateway); err != nil {
			t.Fatal(err)
		}
		if _, err = store.PermitLease(ctx, principal, id, leaseRequest); !errors.Is(err, ipsec.ErrConnectionIneligible) {
			t.Fatal("expired authority renewed lease", err)
		}
		if _, err = pool.Exec(ctx, `UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, gateway); err != nil {
			t.Fatal(err)
		}
		role = rbac.RoleMember
		status := request(router, "GET", statusPath, "", "", 200)
		var health struct {
			Tunnels []json.RawMessage `json:"tunnels"`
		}
		if err := json.Unmarshal(status.Body.Bytes(), &health); err != nil || len(health.Tunnels) != tunnelCount {
			t.Fatal("wrong actual tunnel cardinality", err)
		}
		request(router, "PUT", intentPath, `{"intent":"disabled"}`, `"2"`, 403)
		role = rbac.RoleOwner
		disabled := request(router, "PUT", intentPath, `{"intent":"disabled"}`, `"2"`, 200)
		if disabled.Header().Get("ETag") != `"3"` {
			t.Fatal("disable CAS lost")
		}
		cleanup, err := store.Cleanup(ctx, principal, id, 3)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Acknowledge(ctx, principal, id, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: 3, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); err != nil {
			t.Fatal(err)
		}
		deleteRevision = `"3"`
	}
	role = rbac.RoleOwner
	request(router, "DELETE", detail, "", deleteRevision, 200)
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
	if profile != "aws-static-ipv4-v1" {
		return
	}
	legacyID := uuid.New()
	legacy := ipsec.CreateDisabledRequest{ID: legacyID, SiteID: site, GatewayID: gateway, Name: "Identity only", Tunnels: [2]ipsec.CreateTunnel{{ID: uuid.New(), PSK: "synthetic-legacy-PSK_1"}, {ID: uuid.New(), PSK: "synthetic-legacy-PSK_2"}}}
	if _, err := store.CreateDisabled(ctx, org, actor, sealer, legacy); err != nil {
		t.Fatal(err)
	}
	request(router, "GET", base+"/"+legacyID.String()+"/configuration", "", "", 404)
}
