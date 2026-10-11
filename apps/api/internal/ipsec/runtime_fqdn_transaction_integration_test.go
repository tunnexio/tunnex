package ipsec_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Real Material owns the transaction, org lock, stored capability selection,
// committed resolver reader and compiler. No snapshot/FQDN version is injected.
// All fixture writes target testpostgres's newly-created disposable child DB.
func TestTransactionalIPsecFQDNV2Compiler(t *testing.T) {
	ctx, p := testpostgres.New(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	// PostgreSQL supplies the same wall-clock authority as the real compiler.
	databaseNow := func() time.Time {
		t.Helper()
		var stamp time.Time
		if e := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&stamp); e != nil {
			t.Fatal(e)
		}
		return stamp.UTC()
	}
	publish := func(work *fqdnresolver.Work, generation fqdnresolver.Generation) error {
		// Observe this exact fixture resource's real publication CAS. Concurrent
		// changes still refuse; the test never retries or changes saved rows.
		if e := p.QueryRow(ctx, `SELECT COALESCE(max(generation),0) FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2`, work.OrgID, work.ResourceID).Scan(&work.ExpectedGeneration); e != nil {
			return e
		}
		return fqdnresolver.NewPostgresStore(p).Publish(ctx, *work, generation)
	}
	org, actor, site, node := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,fqdn_resources_enabled) VALUES($1,'transaction compiler',$2,'10.199.0.0/24','enforcing',true)`, org, "fqdn-tx-"+org.String())
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, actor, actor.String()+"@fixture.test")
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'compiler site')`, site, org)
	exec(`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), site)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'compiler node',$3,$4,'{"ipsec_config_version":1,"ipsec_fqdn_policy_version":2,"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1}',clock_timestamp())`, node, org, node.String(), site)
	if _, e := ipsec.NewSettingsStore(p).Configure(ctx, org, actor, true, 0); e != nil {
		t.Fatal(e)
	}
	sealer, e := crypto.NewSealer(bytes.Repeat([]byte{0x49}, 32))
	if e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(policy.IPsecRuntimePolicyCompiler(func() bool { return true }))
	req := ipsec.CreateProviderRequest{ID: uuid.New(), SiteID: site, GatewayID: node, Name: "compiler", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: staticConfigFixture()}
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	profiles := fqdnresources.New(p)
	profile := fqdnresources.ResolverProfile{Name: "compiler DNS", ProviderHint: "aws", ZoneSuffixes: []string{"private.example.test"}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}, IPsecPath: &fqdnresources.ResolverIPsecPath{ConnectionID: c.ID, ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}}
	config, e := profiles.SetResolverProfiles(ctx, org, site, node, actor, "test", "transaction proof", []fqdnresources.ResolverProfile{profile})
	if e != nil {
		t.Fatal(e)
	}
	resource, rule := uuid.New(), uuid.New()
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,protocol,port_low,port_high,resolver_site_id,resolver_node_id)VALUES($1,$2,'compiler app','service.private.example.test','tcp',8080,8080,$3,$4)`, resource, org, site, node)
	ruleEnd := databaseNow().Add(45 * time.Second)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_fqdn_resource_id,expires_at)VALUES($1,$2,'cidr','10.10.0.2/32','fqdn_resource',$3,$4)`, rule, org, resource, ruleEnd)
	work := fqdnresolver.Work{OrgID: org, ResourceID: resource, Hostname: "service.private.example.test", Context: fqdnresolver.Context{ResolverID: site.String(), GatewayID: node.String()}, ResolverConfig: fqdnresolver.ResolverConfig{ID: config.ID.String(), Version: config.Version, ProfileID: config.Profiles[0].ID.String(), ProfileName: "compiler DNS", ProfileProvider: "aws", MatchedSuffix: "private.example.test", IPsecPath: &fqdnresolver.ResolverIPsecPath{ConnectionID: c.ID.String(), ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}, Endpoints: []fqdnresolver.ResolverEndpoint{{Address: netip.MustParseAddr("10.20.0.53"), Port: 53, Transport: "udp"}}}}
	resolved := databaseNow()
	if e := publish(&work, fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: resolved, Addresses: []netip.Addr{netip.MustParseAddr("10.20.1.4")}}); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: node, CertificateSerial: node.String()}
	material := func() ipsec.RuntimeMaterial {
		t.Helper()
		m, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	check := func(m ipsec.RuntimeMaterial, cutoff time.Time) {
		t.Helper()
		if m.Policy.FQDNPolicyVersion != 2 || len(m.Policy.FQDNGrants) != 1 {
			t.Fatal("cap2 committed answer missing")
		}
		g := m.Policy.FQDNGrants[0]
		if !g.ExpiresAt.Equal(cutoff) || g.ResolverSourceAddress != "10.10.0.5" || g.ConnectionID != c.ID.String() || g.ConfigurationRevision != 1 || g.SelectedSiteID != site.String() || g.SelectedGatewayID != node.String() || g.ResolverConfigID != config.ID.String() || g.ResolverConfigVersion != config.Version || g.ResolverProfileID != config.Profiles[0].ID.String() || g.ResourceID != resource.String() || g.Generation == "" || g.Name != "service.private.example.test" || g.Source != "10.10.0.2/32" || g.Destination != "10.20.1.4/32" || g.Protocol != "tcp" || g.PortLow != 8080 || g.PortHigh != 8080 {
			t.Fatal("expiry/provenance/tuple mismatch")
		}
		if len(m.Policy.Grants) != 0 {
			t.Fatal("FQDN answer leaked into ordinary grants")
		}
	}
	check(material(), ruleEnd)
	check(material(), ruleEnd) // renewal cannot slide absolute cutoff
	exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	check(material(), resolved.Add(time.Minute))
	// A durable pending generation with a different answer must not displace the
	// committed active generation, even though both are visible to SQL readers.
	pendingID := uuid.New()
	exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,resolver_profile_id,resolver_match_suffix,state,effective_ttl,resolved_at) VALUES($1,$2,$3,2,$4,$5,$6,$7,'private.example.test','pending','1 minute',clock_timestamp())`, pendingID, org, resource, node, site, config.ID, config.Profiles[0].ID)
	exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address)VALUES($1,$2,'10.20.9.9/32')`, pendingID, org)
	check(material(), resolved.Add(time.Minute))

	t.Run("missing cap2", func(t *testing.T) {
		exec(`UPDATE nodes SET capabilities=capabilities-'ipsec_fqdn_policy_version' WHERE id=$1`, node)
		if m := material(); len(m.Policy.FQDNGrants) != 0 || m.Policy.FQDNPolicyVersion != 0 {
			t.Fatal("missing capability widened authority")
		}
		exec(`UPDATE nodes SET capabilities=capabilities||'{"ipsec_fqdn_policy_version":2}' WHERE id=$1`, node)
	})
	t.Run("stale capability report", func(t *testing.T) {
		exec(`UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, node)
		if _, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); e == nil {
			t.Fatal("stale node report accepted material")
		}
		exec(`UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, node)
	})
	t.Run("legacy v1 actual database cutoff", func(t *testing.T) {
		exec(`UPDATE policy_rules SET expires_at=$2 WHERE id=$1`, rule, ruleEnd)
		exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{ipsec_fqdn_policy_version}','1'),policy_reported_at=clock_timestamp() WHERE id=$1`, node)
		legacy := material()
		if legacy.Policy.FQDNPolicyVersion != 1 || len(legacy.Policy.FQDNGrants) != 1 || !legacy.Policy.FQDNLeaseDeadline.Equal(ruleEnd) {
			t.Fatal("legacy real compiler cutoff missing")
		}
		grant := legacy.Policy.FQDNGrants[0]
		if !grant.ExpiresAt.IsZero() || grant.ResolverSourceAddress != "" {
			t.Fatal("v1 exposed absolute authority fields")
		}
		wire, e := json.Marshal(legacy.Policy)
		if e != nil || strings.Contains(string(wire), "expires_at") || strings.Contains(string(wire), "resolver_source_address") || strings.Contains(string(wire), "FQDNLeaseDeadline") || strings.Contains(string(wire), "fqdn_lease_deadline") {
			t.Fatal("v1/private cutoff leaked into wire")
		}
		remaining := ruleEnd.Sub(databaseNow()).Milliseconds()
		if remaining <= 0 {
			t.Fatal("fixture original legacy cutoff elapsed before positive lease")
		}
		lease, e := store.PermitLease(ctx, principal, c.ID, ipsec.RuntimeLeaseRequest{DeliveryID: legacy.ID, DesiredRevision: c.DesiredRevision, PolicyHash: legacy.Policy.Hash, Nonce: strings.Repeat("c", 64)})
		if e != nil || lease.TTLMS <= 0 || lease.TTLMS > remaining || lease.TTLMS >= 60000 || len(lease.FQDNPermits) != 0 || len(lease.FQDNGrants) != 0 || lease.PolicyHash != legacy.Policy.Hash {
			t.Fatal("v1 normal lease not capped by genuine database cutoff")
		}
		exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{ipsec_fqdn_policy_version}','2'),policy_reported_at=clock_timestamp() WHERE id=$1`, node)
		exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	})
	t.Run("expired rule", func(t *testing.T) {
		exec(`UPDATE policy_rules SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, rule)
		if m := material(); len(m.Policy.FQDNGrants) != 0 {
			t.Fatal("expired rule retained authority")
		}
		exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	})
	t.Run("retired committed generation", func(t *testing.T) {
		exec(`UPDATE fqdn_resource_answer_generations SET state='retired',ended_at=clock_timestamp() WHERE resource_id=$1 AND state='active'`, resource)
		if m := material(); len(m.Policy.FQDNGrants) != 0 {
			t.Fatal("retired generation retained authority")
		}
	})
	// A committed answer whose absolute TTL already elapsed is not authority.
	if e := publish(&work, fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: databaseNow().Add(-2 * time.Minute), Addresses: []netip.Addr{netip.MustParseAddr("10.20.1.4")}}); e != nil {
		t.Fatal(e)
	}
	if m := material(); len(m.Policy.FQDNGrants) != 0 {
		t.Fatal("expired committed answer retained authority")
	}
	// Publish a new committed generation, then genuinely replace its resolver
	// context. An old answer cannot retain provenance under the new version.
	if e := publish(&work, fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: databaseNow(), Addresses: []netip.Addr{netip.MustParseAddr("10.20.1.4")}}); e != nil {
		t.Fatal(e)
	}
	if _, e := profiles.SetResolverProfiles(ctx, org, site, node, actor, "test", "replace context", []fqdnresources.ResolverProfile{profile}); e != nil {
		t.Fatal(e)
	}
	if m := material(); len(m.Policy.FQDNGrants) != 0 {
		t.Fatal("superseded resolver context retained old answer")
	}
}
