package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Exercise the actual authenticated report decoder -> AppliedPolicy -> persisted
// capabilities -> normal profile write and PostgreSQL activation trigger. No
// capability JSON is injected by fixture SQL. Certificate state is supplied as
// by the listener; this fixture does not claim a real TLS handshake.
func TestAgentDNSIPsecReportActivatesOwnedProfilePostgresContract(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 219)
	org, actor, site, gateway, other := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(gateway[:])
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'DNS report',$2,'10.99.0.0/24')`, []any{org, "dns-report-" + org.String()}},
		{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{actor, actor.String() + "@dns-report.test"}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'owned site')`, []any{site, org}},
		{`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, []any{uuid.New(), site}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,cert_delivered) VALUES($1,$2,'reporter',$3,$4,true),($5,$2,'untouched',$6,$4,true)`, []any{gateway, org, hex.EncodeToString(serial.Bytes()), site, other, "other-" + other.String()}},
	} {
		if _, err := pool.Exec(ctx, step.query, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	report := func(fields string, want int) {
		t.Helper()
		body := `{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","node_id":"` + other.String() + `"` + fields + `}`
		req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(body)).WithContext(ctx)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial}}}
		rr := httptest.NewRecorder()
		channel.report(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("report status=%d: %s", rr.Code, rr.Body.String())
		}
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT capabilities FROM nodes WHERE id=$1`, gateway).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		caps := nodes.Capabilities(raw)
		if caps.DNSIPsecResolveVersion != want {
			t.Fatalf("typed DNS IPsec capability=%d want%d", caps.DNSIPsecResolveVersion, want)
		}
		var fieldsMap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fieldsMap); err != nil {
			t.Fatal(err)
		}
		if string(fieldsMap["dns_ipsec_resolve_version"]) != string(rune('0'+want)) {
			t.Fatal("explicit bounded DNS capability not persisted")
		}
		var untouched bool
		if err := pool.QueryRow(ctx, `SELECT capabilities='{}'::jsonb FROM nodes WHERE id=$1`, other).Scan(&untouched); err != nil || !untouched {
			t.Fatal("body identity altered another node", err)
		}
	}
	const complete = `,"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1,"ipsec_config_version":1,"max_policy_version":11`
	report(complete, 1)
	sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x67}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := ipsec.NewConnectionStore(pool)
	store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
	if _, err := ipsec.NewSettingsStore(pool).Configure(ctx, org, actor, true, 0); err != nil {
		t.Fatal(err)
	}
	var input api.IPsecConfigurationCheckInput
	if err := json.Unmarshal([]byte(configurationCheckFixture), &input); err != nil {
		t.Fatal(err)
	}
	cfg, err := privateIPsecConfiguration(input)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := store.CreateProviderDisabled(ctx, org, actor, sealer, ipsec.CreateProviderRequest{ID: uuid.New(), SiteID: site, GatewayID: gateway, Name: "DNS transport", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	connection, err = store.SetIntent(ctx, org, actor, connection.ID, connection.DesiredRevision, "enabled")
	if err != nil {
		t.Fatal(err)
	}
	resolver := fqdnresources.New(pool)
	profiles := []fqdnresources.ResolverProfile{{Name: "AWS private", ProviderHint: "aws", ZoneSuffixes: []string{"private.example.test"}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}, IPsecPath: &fqdnresources.ResolverIPsecPath{ConnectionID: connection.ID, ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}}}
	set := func() (fqdnresources.ResolverConfig, error) {
		return resolver.SetResolverProfiles(ctx, org, site, gateway, actor, "", "report capability proof", profiles)
	}
	config, err := set()
	if err != nil {
		t.Fatalf("normal profile activation after actual report: %v", err)
	}
	assertActive := func() {
		t.Helper()
		var active, valid bool
		if err := pool.QueryRow(ctx, `SELECT c.state='active',fqdn_ipsec_resolver_profile_valid(p.id,p.org_id) FROM fqdn_resolver_context_profiles p JOIN fqdn_resolver_context_configs c ON c.id=p.config_id WHERE p.id=$1`, config.Profiles[0].ID).Scan(&active, &valid); err != nil || !active || !valid {
			t.Fatalf("real activation proof active=%t valid=%t err=%v", active, valid, err)
		}
	}
	assertActive()
	for _, tc := range []struct{ name, fields string }{
		{"legacy missing field", `,"dns_resolve_rpc_version":2,"ipsec_config_version":1,"max_policy_version":11`},
		{"unknown future", strings.Replace(complete, `"dns_ipsec_resolve_version":1`, `"dns_ipsec_resolve_version":2`, 1)},
		{"negative", strings.Replace(complete, `"dns_ipsec_resolve_version":1`, `"dns_ipsec_resolve_version":-1`, 1)},
		{"wrong RPC", strings.Replace(complete, `"dns_resolve_rpc_version":2`, `"dns_resolve_rpc_version":1`, 1)},
		{"missing IPsec", strings.Replace(complete, `,"ipsec_config_version":1`, "", 1)},
		{"old policy ceiling", strings.Replace(complete, `"max_policy_version":11`, `"max_policy_version":10`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report(tc.fields, 0)
			if _, err := set(); err == nil {
				t.Fatal("profile activated after incompatible report")
			}
			current, err := resolver.ResolverConfig(ctx, org, site, gateway)
			if err != nil || current.ID != config.ID || current.Version != config.Version {
				t.Fatal("refused capability retired prior immutable profile", err)
			}
			// Independently exercise SQL activation, not merely the Go admission query.
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE id=$1`, config.ID); err != nil {
				t.Fatal(err)
			}
			_, activationErr := tx.Exec(ctx, `UPDATE fqdn_resolver_context_configs SET state='active',retired_at=NULL WHERE id=$1`, config.ID)
			_ = tx.Rollback(ctx)
			if activationErr == nil {
				t.Fatal("DB activation trigger accepted incompatible report")
			}
			report(complete, 1)
			assertActive()
		})
	}
}
