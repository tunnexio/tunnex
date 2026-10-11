package ipsec_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
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

// Real transactions, stored cap2 and committed resolver generations. Time is
// allowed to pass across the original cutoff; material/expiry are never forged.
// This component proves normal API continuity, not cloud packet acceptance.
func TestTransactionalIPsecFQDNV2LeaseExpiryContinuity(t *testing.T) {
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
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'compiler node',$3,$4,'{"ipsec_config_version":1,"ipsec_recovery_version":1,"ipsec_fqdn_policy_version":2,"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1}',clock_timestamp())`, node, org, node.String(), site)
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

	ordinary, ordinaryRule := uuid.New(), uuid.New()
	exec(`INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high)VALUES($1,$2,'ordinary','10.20.1.8/32','tcp',9090,9090)`, ordinary, org)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_resource_id)VALUES($1,$2,'cidr','10.10.0.2/32','resource',$3)`, ordinaryRule, org, ordinary)
	resources := [2]uuid.UUID{uuid.New(), uuid.New()}
	rules := [2]uuid.UUID{uuid.New(), uuid.New()}
	cutoffs := [2]time.Time{databaseNow().Add(4 * time.Second), databaseNow().Add(10 * time.Second)}
	works := [2]fqdnresolver.Work{}
	for i := range resources {
		name := []string{"short.private.example.test", "long.private.example.test"}[i]
		exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,protocol,port_low,port_high,resolver_site_id,resolver_node_id)VALUES($1,$2,$3,$3,'tcp',8080,8080,$4,$5)`, resources[i], org, name, site, node)
		exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_fqdn_resource_id,expires_at)VALUES($1,$2,'cidr','10.10.0.2/32','fqdn_resource',$3,$4)`, rules[i], org, resources[i], cutoffs[i])
		works[i] = fqdnresolver.Work{OrgID: org, ResourceID: resources[i], Hostname: name, Context: fqdnresolver.Context{ResolverID: site.String(), GatewayID: node.String()}, ResolverConfig: fqdnresolver.ResolverConfig{ID: config.ID.String(), Version: config.Version, ProfileID: config.Profiles[0].ID.String(), ProfileName: "compiler DNS", ProfileProvider: "aws", MatchedSuffix: "private.example.test", IPsecPath: &fqdnresolver.ResolverIPsecPath{ConnectionID: c.ID.String(), ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}, Endpoints: []fqdnresolver.ResolverEndpoint{{Address: netip.MustParseAddr("10.20.0.53"), Port: 53, Transport: "udp"}}}}
		if e := publish(&works[i], fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: databaseNow(), Addresses: []netip.Addr{netip.MustParseAddr([]string{"10.20.1.4", "10.20.1.5"}[i])}}); e != nil {
			t.Fatal(e)
		}
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
	original := material()
	if original.Policy.FQDNPolicyVersion != 2 || len(original.Policy.FQDNGrants) != 2 || len(original.Policy.Grants) != 1 || len(original.Policy.DNSResolverGrants) != 1 || len(original.Policy.DNSResolverProfiles) != 1 {
		t.Fatal("genuine initial ordinary/DNS/two-grant policy missing")
	}
	descriptors := append([]ipsec.RuntimeFQDNGrant(nil), original.Policy.FQDNGrants...)
	digest := func(g ipsec.RuntimeFQDNGrant) string {
		raw, e := json.Marshal(g)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	short, long := "", ""
	for _, g := range descriptors {
		switch g.RuleID {
		case rules[0].String():
			if !g.ExpiresAt.Equal(cutoffs[0]) {
				t.Fatal("short original cutoff changed")
			}
			short = digest(g)
		case rules[1].String():
			if !g.ExpiresAt.Equal(cutoffs[1]) {
				t.Fatal("long original cutoff changed")
			}
			long = digest(g)
		default:
			t.Fatal("foreign original descriptor")
		}
	}
	request := ipsec.RuntimeLeaseRequest{DeliveryID: original.ID, DesiredRevision: c.DesiredRevision, PolicyHash: original.Policy.Hash, Nonce: strings.Repeat("a", 64), FQDNGrants: descriptors}
	lease := func(r ipsec.RuntimeLeaseRequest) ipsec.RuntimeLease {
		t.Helper()
		got, e := store.PermitLease(ctx, principal, c.ID, r)
		if e != nil {
			t.Fatal(e)
		}
		if got.TTLMS != 60000 || len(got.FQDNGrants) != 0 || got.DeliveryID != r.DeliveryID || got.PolicyHash != r.PolicyHash || got.Nonce != r.Nonce {
			t.Fatal("ordinary lease or identity-only response changed")
		}
		return got
	}
	permits := func(got ipsec.RuntimeLease) map[string]int64 {
		t.Helper()
		out := map[string]int64{}
		for _, p := range got.FQDNPermits {
			if _, duplicate := out[p.GrantDigest]; duplicate {
				t.Fatal("duplicate permit")
			}
			out[p.GrantDigest] = p.TTLMS
		}
		if len(out) != 2 {
			t.Fatal("exact original descriptor permits missing")
		}
		return out
	}
	beforeRequest := request
	before := lease(beforeRequest)
	first := permits(before)
	if first[short] <= 0 || first[long] <= 0 || first[short] > 4000 || first[long] > 10000 {
		t.Fatal("initial positive permits not bounded by original cutoffs")
	}
	refuse := func(r ipsec.RuntimeLeaseRequest) {
		t.Helper()
		got, e := store.PermitLease(ctx, principal, c.ID, r)
		if e == nil || !reflect.DeepEqual(got, ipsec.RuntimeLease{}) {
			t.Fatal("refused request returned lease/echo authority")
		}
	}
	for _, kind := range []string{"missing", "omit", "change", "duplicate", "reorder"} {
		r := request
		r.FQDNGrants = append([]ipsec.RuntimeFQDNGrant(nil), descriptors...)
		switch kind {
		case "missing":
			r.FQDNGrants = nil
		case "omit":
			r.FQDNGrants = r.FQDNGrants[:1]
		case "change":
			r.FQDNGrants[0].PortHigh++
		case "duplicate":
			r.FQDNGrants = append(r.FQDNGrants, r.FQDNGrants[0])
		case "reorder":
			r.FQDNGrants[0], r.FQDNGrants[1] = r.FQDNGrants[1], r.FQDNGrants[0]
		}
		refuse(r)
	}
	for _, version := range []string{"0", "1"} {
		exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{ipsec_fqdn_policy_version}',$2::jsonb) WHERE id=$1`, node, version)
		refuse(request)
	}
	exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{ipsec_fqdn_policy_version}','2') WHERE id=$1`, node)
	exec(`UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, node)
	refuse(request)
	exec(`UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, node)
	exec(`UPDATE policy_rules SET disabled=true WHERE id=$1`, rules[1])
	refuse(request)
	exec(`UPDATE policy_rules SET disabled=false WHERE id=$1`, rules[1])
	exec(`UPDATE resources SET port_high=9091 WHERE id=$1`, ordinary)
	refuse(request)
	exec(`UPDATE resources SET port_high=9090 WHERE id=$1`, ordinary)
	// Cross the actual original short cutoff BEFORE Material or PermitLease compiles.
	waitPast := func(end time.Time) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			actual := databaseNow()
			if actual.After(end) {
				return
			}
			delay := end.Sub(actual) + 20*time.Millisecond
			if delay <= 0 || delay > 15*time.Second || time.Now().Add(delay).After(deadline) {
				t.Fatal("fixture database cutoff not crossed within bounded wait")
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("fixture context expired before database cutoff")
			}
		}

	}
	waitPast(cutoffs[0])
	current := material()
	if len(current.Policy.FQDNGrants) != 1 || current.Policy.FQDNGrants[0].RuleID != rules[1].String() || !reflect.DeepEqual(current.Policy.Grants, original.Policy.Grants) || !reflect.DeepEqual(current.Policy.DNSResolverGrants, original.Policy.DNSResolverGrants) || !reflect.DeepEqual(current.Policy.DNSResolverProfiles, original.Policy.DNSResolverProfiles) {
		t.Fatal("short expiry changed ordinary/DNS/current long authority")
	}
	afterRequest := request
	afterRequest.Nonce = strings.Repeat("b", 64)
	after := lease(afterRequest)
	second := permits(after)
	if second[short] != 0 || second[long] <= 0 || second[long] > first[long] {
		t.Fatal("expired descriptor resurrected or live duration extended")
	}
	// Genuine changed answer content must not be accepted through an old descriptor.
	if e := publish(&works[1], fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: databaseNow(), Addresses: []netip.Addr{netip.MustParseAddr("10.20.1.9")}}); e != nil {
		t.Fatal(e)
	}
	refuse(afterRequest)
	if e := publish(&works[1], fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: databaseNow(), Addresses: []netip.Addr{netip.MustParseAddr("10.20.1.5")}}); e != nil {
		t.Fatal(e)
	}
	restored := material()
	if len(restored.Policy.FQDNGrants) != 1 || !reflect.DeepEqual(restored.Policy.FQDNGrants, current.Policy.FQDNGrants) {
		t.Fatal("restored committed content changed original long descriptor")
	}
	if got := permits(lease(afterRequest)); got[short] != 0 || got[long] <= 0 {
		t.Fatal("renewal revived expired descriptor")
	}
	waitPast(cutoffs[1])
	last := permits(lease(afterRequest))
	if last[short] != 0 || last[long] != 0 {
		t.Fatal("last expiry retained app authority")
	}
	// Changing the dedicated resolver context also changes DNS authority. Old hash
	// cannot preserve a lease even though its two application cutoffs are past.
	profile.Endpoints[0].Address = "10.20.0.54"
	if _, e := profiles.SetResolverProfiles(ctx, org, site, node, actor, "test", "change DNS", []fqdnresources.ResolverProfile{profile}); e != nil {
		t.Fatal(e)
	}
	refuse(afterRequest)
	exportTransactionalFQDNLeaseWire(t, map[string]any{"delivery_before_expiry": original.RuntimeDelivery, "request_before_expiry": beforeRequest, "response_before_expiry": before, "request_after_expiry": afterRequest, "response_after_expiry": after, "policy_before_expiry": original.Policy, "policy_after_expiry": current.Policy})
}

// Explicit opt-in exports only genuine asserted request/response/policy wire;
// never material, PSKs, sealing envelopes, database credentials or timestamps
// made by the exporter. Existing files/symlink/public parents refuse.
func exportTransactionalFQDNLeaseWire(t *testing.T, value any) {
	t.Helper()
	path := os.Getenv("TUNNEX_TEST_IPSEC_FQDN_LEASE_WIRE_PATH")
	if path == "" {
		return
	}
	absolute, e := filepath.Abs(path)
	if e != nil || absolute != path {
		t.Fatal("absolute private wire path required")
	}
	parent := filepath.Dir(path)
	resolved, e := filepath.EvalSymlinks(parent)
	info, e2 := os.Stat(parent)
	if e != nil || e2 != nil || resolved != parent || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private non-symlink wire parent required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("owned wire parent required")
	}
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 262144 {
		t.Fatal("bounded nonsecret wire marshal")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal("exclusive wire output refused")
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		t.Fatal("wire write")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		t.Fatal("wire durability")
	}
	if e = f.Close(); e != nil {
		t.Fatal("wire close")
	}
}
