package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

// Frozen independent descriptor bytes; neither producer nor consumer self-seals it.
const fqdnLeaseDescriptorGolden = `{"expires_at":"2026-10-11T12:00:30Z","resolver_source_address":"10.1.0.1","source":"10.1.0.2/32","destination":"10.2.0.3/32","protocol":"tcp","port_low":8080,"port_high":8080,"rule_id":"11111111-1111-4111-8111-111111111111","fqdn_managed":true,"resource_id":"22222222-2222-4222-8222-222222222222","name":"app.private.test","generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resolver_config_id":"33333333-3333-4333-8333-333333333333","resolver_config_version":3,"selected_site_id":"44444444-4444-4444-8444-444444444444","selected_gateway_id":"55555555-5555-4555-8555-555555555555","resolver_profile_id":"66666666-6666-4666-8666-666666666666","resolver_match_suffix":"private.test","connection_id":"77777777-7777-4777-8777-777777777777","configuration_revision":1}`
const fqdnLeaseDescriptorDigestGolden = "c536d00baa7858437e8ad953576edaaabdd9ac7acdce4c71eb7abcb06b0f0d62"

func TestRuntimeFQDNLeaseDescriptorGolden(t *testing.T) {
	var g RuntimeFQDNGrant
	if json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g) != nil {
		t.Fatal("golden decode")
	}
	raw, err := json.Marshal(g)
	if err != nil || string(raw) != fqdnLeaseDescriptorGolden || runtimeFQDNGrantDigest(g) != fqdnLeaseDescriptorDigestGolden {
		t.Fatal("API/node exact descriptor wire changed", err, string(raw))
	}
	for _, mutate := range []func(*RuntimeFQDNGrant){func(g *RuntimeFQDNGrant) { g.ExpiresAt = g.ExpiresAt.Add(time.Second) }, func(g *RuntimeFQDNGrant) { g.ResolverSourceAddress = "10.1.0.4" }, func(g *RuntimeFQDNGrant) { g.Generation = strings.Repeat("b", 64) }, func(g *RuntimeFQDNGrant) { g.PortHigh++ }, func(g *RuntimeFQDNGrant) { g.ResourceID = "88888888-8888-4888-8888-888888888888" }} {
		next := g
		mutate(&next)
		if runtimeFQDNGrantDigest(next) == fqdnLeaseDescriptorDigestGolden {
			t.Fatal("descriptor field omitted from identity")
		}
	}
}

func TestRuntimeFQDNLeasePostCommitDurationAndSelectiveZero(t *testing.T) {
	var g RuntimeFQDNGrant
	_ = json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g)
	start := g.ExpiresAt.Add(-30 * time.Second)
	p := RuntimePolicy{FQDNPolicyVersion: 2, FQDNGrants: []RuntimeFQDNGrant{g}}
	for _, tc := range []struct {
		name   string
		delta  time.Duration
		want   int64
		refuse bool
	}{
		{"fresh", 0, 30000, false}, {"commit_and_transport", 25 * time.Second, 5000, false}, {"expired_during_commit", 31 * time.Second, 0, false}, {"exact_expiry", 30 * time.Second, 0, false}, {"round_down", time.Nanosecond, 29999, false}, {"backwards_clock", -time.Second, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := runtimeFQDNLeasePermits(p, start, tc.delta)
			if (err != nil) != tc.refuse {
				t.Fatal(err)
			}
			if !tc.refuse && (len(proof) != 1 || proof[0].TTLMS != tc.want || proof[0].GrantDigest != fqdnLeaseDescriptorDigestGolden) {
				t.Fatal(proof)
			}
		})
	}
	for _, version := range []int{0, 1} {
		p.FQDNPolicyVersion = version
		proof, err := runtimeFQDNLeasePermits(p, time.Time{}, 0)
		if err != nil || proof != nil {
			t.Fatal("legacy authority changed")
		}
	}
	p.FQDNPolicyVersion = 2
	if _, err := runtimeFQDNLeasePermits(p, time.Time{}, 0); err == nil {
		t.Fatal("missing fence accepted")
	}
	p.FQDNGrants = append(p.FQDNGrants, g)
	if _, err := runtimeFQDNLeasePermits(p, start, 0); err == nil {
		t.Fatal("duplicate descriptor accepted")
	}
	p.FQDNGrants = p.FQDNGrants[:1]
	p.FQDNGrants[0].ExpiresAt = time.Time{}
	if _, err := runtimeFQDNLeasePermits(p, start, 0); err == nil {
		t.Fatal("missing expiry accepted")
	}
}
func TestRuntimeFQDNLeaseV1ResponseOmission(t *testing.T) {
	raw, err := json.Marshal(RuntimeLease{TTLMS: 60000})
	if err != nil || strings.Contains(string(raw), "fqdn_permits") {
		t.Fatal("legacy wire changed")
	}
}

func TestRuntimeFQDNLeaseExpiredContinuity(t *testing.T) {
	var g RuntimeFQDNGrant
	_ = json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g)
	input := RuntimePolicyInput{OrgID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), NodeID: uuid.MustParse(g.SelectedGatewayID), SiteID: uuid.MustParse(g.SelectedSiteID), ConnectionID: uuid.MustParse(g.ConnectionID), Config: StaticConfig{LocalPrefixes: []string{"10.1.0.0/24"}, RemotePrefixes: []string{"10.2.0.0/24"}}, ConfigurationRevision: 1, FQDNPolicyVersion: 2}
	before := RuntimePolicy{FQDNPolicyVersion: 2, FQDNGrants: []RuntimeFQDNGrant{g}, Grants: []RuntimeGrant{{Source: "10.1.0.4/32", Destination: "10.2.0.5/32", Protocol: "tcp", PortLow: 443, PortHigh: 443, RuleID: g.RuleID}}}
	before, e := HashRuntimePolicy(before, input)
	if e != nil {
		t.Fatal(e)
	}
	current := before
	current.FQDNPolicyVersion = 0
	current.FQDNGrants = nil
	current, _ = HashRuntimePolicy(current, input)
	q := RuntimeLeaseRequest{PolicyHash: before.Hash, FQDNGrants: []RuntimeFQDNGrant{g}}
	got, zero, e := runtimeFQDNLeaseContinuity(current, q, input, g.ExpiresAt.Add(time.Second))
	if e != nil || got.Hash != before.Hash || !zero[fqdnLeaseDescriptorDigestGolden] {
		t.Fatal("expired continuity", e)
	}
	if len(got.Grants) != 1 || got.Grants[0] != current.Grants[0] {
		t.Fatal("current ordinary changed")
	}
	for _, name := range []string{"capability", "positive_extra", "ordinary_changed", "source", "connection", "missing_expiry", "duplicate", "current_omitted", "hash"} {
		t.Run(name, func(t *testing.T) {
			in := input
			c := current
			r := q
			r.FQDNGrants = append([]RuntimeFQDNGrant(nil), q.FQDNGrants...)
			c.Grants = append([]RuntimeGrant(nil), current.Grants...)
			fence := g.ExpiresAt.Add(time.Second)
			switch name {
			case "capability":
				in.FQDNPolicyVersion = 1
			case "positive_extra":
				fence = g.ExpiresAt.Add(-time.Second)
			case "ordinary_changed":
				c.Grants[0].PortHigh++
			case "source":
				r.FQDNGrants[0].ResolverSourceAddress = "10.9.0.1"
			case "connection":
				r.FQDNGrants[0].ConnectionID = uuid.NewString()
			case "missing_expiry":
				r.FQDNGrants[0].ExpiresAt = time.Time{}
			case "duplicate":
				r.FQDNGrants = append(r.FQDNGrants, g)
			case "current_omitted":
				next := g
				next.Generation = strings.Repeat("b", 64)
				next.ExpiresAt = fence.Add(20 * time.Second)
				c.FQDNPolicyVersion = 2
				c.FQDNGrants = []RuntimeFQDNGrant{next}
			case "hash":
				r.PolicyHash = strings.Repeat("c", 64)
			}
			if _, _, e := runtimeFQDNLeaseContinuity(c, r, in, fence); e == nil {
				t.Fatal("unsafe continuity accepted")
			}
		})
	}
}

func TestRuntimeFQDNCanonicalPolicyHashFrozen(t *testing.T) {
	var g RuntimeFQDNGrant
	_ = json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g)
	input := RuntimePolicyInput{OrgID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), NodeID: uuid.MustParse(g.SelectedGatewayID), SiteID: uuid.MustParse(g.SelectedSiteID), ConnectionID: uuid.MustParse(g.ConnectionID)}
	v1 := g
	v1.ExpiresAt = time.Time{}
	v1.ResolverSourceAddress = ""
	for _, tc := range []struct {
		name   string
		policy RuntimePolicy
		hash   string
	}{
		{"nil", RuntimePolicy{}, "d967425731dfe7f92e73686559f1e5ed91552284b8851ef3a60315cc4242ccfd"},
		{"empty", RuntimePolicy{Grants: []RuntimeGrant{}}, "ff94fc5cce75ea93daade1649888b7445d84f6a7f3f60a96496d3a697e26153d"},
		{"v1", RuntimePolicy{FQDNPolicyVersion: 1, FQDNGrants: []RuntimeFQDNGrant{v1}}, "c048ea4dad84476eec05064ca97d58d9101498426ca72b95436bda7161d0cb72"},
		{"v2", RuntimePolicy{FQDNPolicyVersion: 2, FQDNGrants: []RuntimeFQDNGrant{g}}, "33dc1ab43eb35da35e3e3504afb1feee0ab2bdcf1df6babf8ca0de3e9ae46003"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := HashRuntimePolicy(tc.policy, input)
			if e != nil || got.Hash != tc.hash {
				t.Fatal("canonical hash drift", got.Hash, e)
			}
		})
	}
}

func TestRuntimeFQDNV1WholeLeaseDBFence(t *testing.T) {
	db := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	p := RuntimePolicy{FQDNPolicyVersion: 1, FQDNGrants: []RuntimeFQDNGrant{{}}, FQDNLeaseDeadline: db.Add(20 * time.Second)}
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		want    int64
		refuse  bool
	}{{"fresh", 0, 20000, false}, {"query_and_commit", 5 * time.Second, 15000, false}, {"at_deadline", 20 * time.Second, 0, true}, {"after_deadline", 21 * time.Second, 0, true}, {"backwards", -time.Second, 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ttl, e := runtimeFQDNWholeLeaseTTL(p, db, tc.elapsed)
			if (e != nil) != tc.refuse || ttl != tc.want {
				t.Fatal(ttl, e)
			}
		})
	}
	// An API wall clock behind the DB is deliberately not an input. Missing or
	// expired authoritative metadata cannot mint the original owner lease.
	p.FQDNLeaseDeadline = time.Time{}
	if _, e := runtimeFQDNWholeLeaseTTL(p, db, 0); e == nil {
		t.Fatal("missing answer bound")
	}
	p.FQDNPolicyVersion = 2
	if ttl, e := runtimeFQDNWholeLeaseTTL(p, db, 0); e != nil || ttl != 60000 {
		t.Fatal("v2 ordinary/DNS shortened", ttl, e)
	}
	p.FQDNPolicyVersion = 0
	p.FQDNGrants = nil
	if ttl, e := runtimeFQDNWholeLeaseTTL(p, db, 0); e != nil || ttl != 60000 {
		t.Fatal("ordinary shortened", ttl, e)
	}
}
func TestRuntimeFQDNLeaseExpiredDurationCannotUnderflow(t *testing.T) {
	observed := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	p := RuntimePolicy{FQDNPolicyVersion: 2, FQDNGrants: []RuntimeFQDNGrant{{ExpiresAt: time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	permits, e := runtimeFQDNLeasePermits(p, observed, time.Duration(1<<63-1))
	if e != nil || len(permits) != 1 || permits[0].TTLMS != 0 {
		t.Fatal("expired subtraction minted authority", permits, e)
	}
}
