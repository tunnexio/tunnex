package policyspec_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// S10.3 v7: a VIP map triggers RequiredVersion=7 (an old agent has no DNAT/DNS-rewrite render — dead-while-
// green — so it must REFUSE), but the map is HASH-BLIND (out of the enforcement projection), so a re-
// allocated VIP never churns the policy hash. And WITHOUT a map, RequiredVersion is NOT bumped.
func TestRequiredVersionVIPTriggerV7AndHashBlind(t *testing.T) {
	base := policyspec.Compiled{Version: 4, NodeID: "n", Mode: "enforcing", Mesh: false}
	withVIP := base
	withVIP.Version = 7
	withVIP.VIPMappings = []policyspec.VIPMapping{{VIP: "100.64.0.5", Namespace: "prod", Service: "api"}}
	if v := policyspec.RequiredVersion(withVIP); v != 7 {
		t.Fatalf("a VIP map must trigger RequiredVersion=7, got %d", v)
	}
	if v := policyspec.RequiredVersion(base); v == 7 {
		t.Fatalf("no VIP map must NOT trigger v7 (zero-config golden), got %d", v)
	}
	other := withVIP
	other.VIPMappings = []policyspec.VIPMapping{{VIP: "100.64.0.9", Namespace: "prod", Service: "web"}}
	if policyspec.CanonicalHash(withVIP) != policyspec.CanonicalHash(other) {
		t.Fatal("the VIP map must be OUT of the hash — its contents changed the policy hash")
	}
}

// The zero-config golden's serialization half: a non-cluster gateway's artifact omits vip_mappings entirely
// (omitempty), so an empty map never serializes as {} / [] and its bytes are unchanged by S10.3.
func TestVIPMapOmitemptyElidesForNonCluster(t *testing.T) {
	b, err := json.Marshal(policyspec.Compiled{Version: 4, NodeID: "n", Mode: "enforcing"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "vip_mappings") {
		t.Fatalf("a non-cluster artifact must not serialize vip_mappings (golden broken): %s", b)
	}
}

// CROSS-MODULE GOLDEN: apps/node/internal/nodepolicy has the IDENTICAL fixtures and
// expected hex (its own golden test). apps/api and apps/node are separate modules, so
// this twin-golden pair is the only guard pinning both CanonicalHash implementations
// (and both struct's field order/tags) to the same canonical bytes. If this test and
// nodepolicy's disagree, pushed-vs-applied staleness comparison is broken — fix the
// drifted struct, do NOT just update one golden.
func TestCanonicalHashGolden(t *testing.T) {
	enforcing := policyspec.Compiled{
		Version: 4, NodeID: "node-a", Mode: "enforcing", Mesh: false,
		Allow: []policyspec.AllowEntry{
			{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: policyspec.ProtoTCP, PortLow: 5432, PortHigh: 5432},
			{SrcIP: "10.99.0.10", DstCIDR: "10.99.0.20/32", Protocol: policyspec.ProtoAny},
		},
	}
	if got := policyspec.CanonicalHash(enforcing); got != "56814207daee" {
		t.Fatalf("enforcing golden = %q, want 56814207daee (nodepolicy twin must match)", got)
	}
	mesh := policyspec.Compiled{Version: 4, NodeID: "node-a", Mode: "off", Mesh: true}
	if got := policyspec.CanonicalHash(mesh); got != "5696d2570ee8" {
		t.Fatalf("mesh golden = %q, want 5696d2570ee8 (nodepolicy twin must match)", got)
	}
	// S8.2 v5 twin: a CIDR-SOURCE (site LAN) grant. SrcIP carries a prefix (a new hashed value shape)
	// and the version is 5 — pins that both modules hash the v5 site-source shape IDENTICALLY.
	siteSrc := policyspec.Compiled{
		Version: 5, NodeID: "node-a", Mode: "enforcing", Mesh: false,
		Allow: []policyspec.AllowEntry{{SrcIP: "10.1.0.0/24", DstCIDR: "10.2.0.0/24", Protocol: policyspec.ProtoAny}},
	}
	if got := policyspec.CanonicalHash(siteSrc); got != "92a15b8df267" {
		t.Fatalf("v5 site-source golden = %q, want 92a15b8df267 (nodepolicy twin must match)", got)
	}
}

// TestRequiredVersionRoutesTriggerV5 — S8.2 Slice-1 LAW guard (the first customer is Slice 2's Routes[]).
// A Compiled carrying a Routes[] section MUST derive RequiredVersion >= 5: an old agent has no kernel-
// route code, so it must REFUSE rather than silently not-route. This red-fails if a future change adds
// routes to the enforcement/render shape without teaching RequiredVersion. Routes are ALSO hash-blind
// (plumbing, out of the CanonicalHash enforcement projection).
func TestRequiredVersionRoutesTriggerV5(t *testing.T) {
	withRoutes := policyspec.Compiled{NodeID: "n", Mode: "off", Mesh: true, Routes: []policyspec.Route{{DstCIDR: "10.2.0.0/24"}}}
	if v := policyspec.RequiredVersion(withRoutes); v < 5 {
		t.Fatalf("a Compiled with Routes[] must derive RequiredVersion >= 5 (the LAW guard); got %d", v)
	}
	noRoutes := policyspec.Compiled{NodeID: "n", Mode: "off", Mesh: true}
	if policyspec.CanonicalHash(withRoutes) != policyspec.CanonicalHash(noRoutes) {
		t.Fatal("Routes[] must be hash-blind (plumbing, out of the projection) — adding routes changed CanonicalHash")
	}
}

// TestDNSForwardsHashBlindAndNoVersionTrigger — S8.4 D5 LAW guard, the D2-checklist row exercised. UNLIKE
// Routes, DNSForwards is CONVENIENCE (a DNS-blind agent serves a WORKING bridge where names just don't
// resolve — visibly degraded, nothing silently unsafe), so it is BOTH hash-blind AND does NOT trigger a
// RequiredVersion bump. This red-fails if a future change hashes DNS or version-gates it.
func TestDNSForwardsHashBlindAndNoVersionTrigger(t *testing.T) {
	base := policyspec.Compiled{NodeID: "n", Mode: "off", Mesh: true}
	withDNS := base
	withDNS.DNSForwards = []policyspec.DNSForward{{Domain: "corp.local", ResolverIP: "10.0.0.53"}}
	if policyspec.CanonicalHash(withDNS) != policyspec.CanonicalHash(base) {
		t.Fatal("DNSForwards must be hash-blind — adding a forward changed CanonicalHash")
	}
	if policyspec.RequiredVersion(withDNS) != policyspec.RequiredVersion(base) {
		t.Fatalf("DNSForwards must NOT trigger a version bump (convenience, not reachability); got %d vs %d",
			policyspec.RequiredVersion(withDNS), policyspec.RequiredVersion(base))
	}
}

// TestCanonicalHashRuleIDIsObservabilityOnly is the A-1/A-3 red pair: rule_id
// (observability) must be INVISIBLE to the hash in BOTH directions, and an
// enforcement-field change MUST move the hash. This is the "observability, never
// semantics" law proven at the hash layer — and the death of the delete+recreate
// desync flap (a rule re-created with a new uuid but identical grant hashes the same).
func TestCanonicalHashRuleIDIsObservabilityOnly(t *testing.T) {
	entry := func(dst, ruleID string) policyspec.AllowEntry {
		return policyspec.AllowEntry{SrcIP: "10.99.0.10", DstCIDR: dst, Protocol: policyspec.ProtoTCP, PortLow: 5432, PortHigh: 5432, RuleID: ruleID}
	}
	base := policyspec.Compiled{Version: policyspec.ProtocolVersion, NodeID: "node-a", Mode: "enforcing"}

	noRule := base
	noRule.Allow = []policyspec.AllowEntry{entry("10.0.5.0/24", "")}
	withRule := base
	withRule.Allow = []policyspec.AllowEntry{entry("10.0.5.0/24", "rule-uuid-1")}
	otherRule := base
	otherRule.Allow = []policyspec.AllowEntry{entry("10.0.5.0/24", "rule-uuid-2")}
	enfChanged := base
	enfChanged.Allow = []policyspec.AllowEntry{entry("10.0.6.0/24", "rule-uuid-1")}

	// Observability direction: rule_id present vs absent, and one uuid vs another,
	// must NOT change the hash.
	if policyspec.CanonicalHash(noRule) != policyspec.CanonicalHash(withRule) {
		t.Fatal("rule_id present vs absent must NOT change the hash")
	}
	if policyspec.CanonicalHash(withRule) != policyspec.CanonicalHash(otherRule) {
		t.Fatal("a DIFFERENT rule_id must NOT change the hash (delete+recreate = no flap)")
	}
	// Enforcement direction: a real grant change MUST change the hash.
	if policyspec.CanonicalHash(withRule) == policyspec.CanonicalHash(enfChanged) {
		t.Fatal("changing an enforcement field (DstCIDR) MUST change the hash")
	}
}

// TestCanonicalHashSrcDeviceIDIsObservabilityOnly (v3, S7.5.4): src_device_id, like
// rule_id, must be INVISIBLE to the hash — adding/changing it must NOT move the hash, so
// the v3 field bump never false-alarms an enforcing gateway.
func TestCanonicalHashSrcDeviceIDIsObservabilityOnly(t *testing.T) {
	base := policyspec.Compiled{Version: policyspec.ProtocolVersion, NodeID: "node-a", Mode: "enforcing"}
	mk := func(devID string) policyspec.Compiled {
		c := base
		c.Allow = []policyspec.AllowEntry{{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: policyspec.ProtoTCP, PortLow: 5432, PortHigh: 5432, RuleID: "r1", SrcDeviceID: devID}}
		return c
	}
	if policyspec.CanonicalHash(mk("")) != policyspec.CanonicalHash(mk("dev-1")) {
		t.Fatal("src_device_id present vs absent must NOT change the hash")
	}
	if policyspec.CanonicalHash(mk("dev-1")) != policyspec.CanonicalHash(mk("dev-2")) {
		t.Fatal("a DIFFERENT src_device_id must NOT change the hash")
	}
}

// TestRequiredVersionPoolTriggerV6 — A3b (S8.6) LAW guard. A Compiled carrying PoolCIDR MUST derive
// RequiredVersion == 6: an old agent has no pool-class DOCKER-USER render, so it must REFUSE rather than
// silently strand device transit on Docker hosts (dead-while-green — the Routes precedent). PoolCIDR is
// ALSO hash-blind (reachability plumbing, out of the CanonicalHash enforcement projection).
func TestRequiredVersionPoolTriggerV6(t *testing.T) {
	withPool := policyspec.Compiled{NodeID: "n", Mode: "off", Mesh: true, PoolCIDR: "10.99.0.0/24"}
	if v := policyspec.RequiredVersion(withPool); v != 6 {
		t.Fatalf("a Compiled with PoolCIDR must derive RequiredVersion == 6 (the LAW guard); got %d", v)
	}
	// pool WITH routes still 6 (the max shape wins, not the first trigger hit)
	withBoth := withPool
	withBoth.Routes = []policyspec.Route{{DstCIDR: "10.2.0.0/24"}}
	if v := policyspec.RequiredVersion(withBoth); v != 6 {
		t.Fatalf("PoolCIDR+Routes must derive 6, got %d", v)
	}
	noPool := policyspec.Compiled{NodeID: "n", Mode: "off", Mesh: true}
	if policyspec.CanonicalHash(withPool) != policyspec.CanonicalHash(noPool) {
		t.Fatal("PoolCIDR must be hash-blind (plumbing, out of the projection) — adding the pool changed CanonicalHash")
	}
	// a pool-less artifact must NOT version-bump (content-derived: single-site orgs keep pre-v6 bytes)
	if v := policyspec.RequiredVersion(noPool); v != 4 {
		t.Fatalf("a pool-less mesh artifact must stay v4 (content-derived), got %d", v)
	}
}
