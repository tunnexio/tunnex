package nodepolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// CROSS-MODULE GOLDEN: apps/api/internal/policyspec has the IDENTICAL fixtures and
// expected hex (its own golden test). This twin-golden pair is the only guard pinning
// both CanonicalHash implementations (and both struct's field order/tags) to the same
// canonical bytes across the two modules. If this test and policyspec's disagree,
// pushed-vs-applied staleness comparison is broken — fix the drifted struct, do NOT
// just update one golden.
func TestCanonicalHashGolden(t *testing.T) {
	enforcing := &nodepolicy.Compiled{
		Version: 4, NodeID: "node-a", Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
			{SrcIP: "10.99.0.10", DstCIDR: "10.99.0.20/32", Protocol: "any"},
		},
	}
	if got := nodepolicy.CanonicalHash(enforcing); got != "56814207daee" {
		t.Fatalf("enforcing golden = %q, want 56814207daee (policyspec twin must match)", got)
	}
	mesh := &nodepolicy.Compiled{Version: 4, NodeID: "node-a", Mode: nodepolicy.ModeOff, Mesh: true}
	if got := nodepolicy.CanonicalHash(mesh); got != "5696d2570ee8" {
		t.Fatalf("mesh golden = %q, want 5696d2570ee8 (policyspec twin must match)", got)
	}
	// S8.2 v5 twin: a CIDR-SOURCE (site LAN) grant — must hash IDENTICALLY to the policyspec side.
	siteSrc := &nodepolicy.Compiled{
		Version: 5, NodeID: "node-a", Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{{SrcIP: "10.1.0.0/24", DstCIDR: "10.2.0.0/24", Protocol: "any"}},
	}
	if got := nodepolicy.CanonicalHash(siteSrc); got != "92a15b8df267" {
		t.Fatalf("v5 site-source golden = %q, want 92a15b8df267 (policyspec twin must match)", got)
	}
	if nodepolicy.CanonicalHash(nil) != "" {
		t.Fatal("nil policy must hash to empty (mesh/none)")
	}
}

// DECODE-THEN-REHASH round-trip: the hash the agent computes over what it DECODED from
// the wire must equal the hash the control plane computed over what it MARSHALED —
// i.e. decode(marshal(x)) re-marshals to the same canonical bytes. This is the
// property staleness comparison actually depends on.
func TestCanonicalHashSurvivesWireRoundTrip(t *testing.T) {
	wire := `{"version":4,"node_id":"node-a","mode":"enforcing","mesh":false,"allow":[{"src_ip":"10.99.0.10","dst_cidr":"10.0.5.0/24","protocol":"tcp","port_low":5432,"port_high":5432},{"src_ip":"10.99.0.10","dst_cidr":"10.99.0.20/32","protocol":"any"}]}`
	var c nodepolicy.Compiled
	if err := json.Unmarshal([]byte(wire), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := nodepolicy.CanonicalHash(&c); got != "56814207daee" {
		t.Fatalf("round-trip hash = %q, want 56814207daee", got)
	}
}

// TWIN of policyspec.TestCanonicalHashRuleIDIsObservabilityOnly — rule_id must be
// invisible to the agent's hash in both directions; an enforcement change must move it.
func TestCanonicalHashRuleIDIsObservabilityOnly(t *testing.T) {
	entry := func(dst, ruleID string) nodepolicy.AllowEntry {
		return nodepolicy.AllowEntry{SrcIP: "10.99.0.10", DstCIDR: dst, Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: ruleID}
	}
	base := &nodepolicy.Compiled{Version: 2, NodeID: "node-a", Mode: nodepolicy.ModeEnforcing}
	mk := func(dst, ruleID string) *nodepolicy.Compiled {
		c := *base
		c.Allow = []nodepolicy.AllowEntry{entry(dst, ruleID)}
		return &c
	}
	if nodepolicy.CanonicalHash(mk("10.0.5.0/24", "")) != nodepolicy.CanonicalHash(mk("10.0.5.0/24", "r1")) {
		t.Fatal("rule_id present vs absent must NOT change the hash")
	}
	if nodepolicy.CanonicalHash(mk("10.0.5.0/24", "r1")) != nodepolicy.CanonicalHash(mk("10.0.5.0/24", "r2")) {
		t.Fatal("a different rule_id must NOT change the hash (delete+recreate = no flap)")
	}
	if nodepolicy.CanonicalHash(mk("10.0.5.0/24", "r1")) == nodepolicy.CanonicalHash(mk("10.0.6.0/24", "r1")) {
		t.Fatal("changing an enforcement field MUST change the hash")
	}
}

// TestCanonicalHashDNSForwardsBlind — S8.4 D5 (agent side): DNSForwards is convenience plumbing, out of
// the hash, so the agent's applied hash matches the CP's pushed hash whether or not DNS is configured
// (no false silent_desync from a DNS-only change). Mirror of policyspec's guard.
func TestCanonicalHashDNSForwardsBlind(t *testing.T) {
	base := &nodepolicy.Compiled{Version: 5, NodeID: "node-a", Mode: nodepolicy.ModeEnforcing}
	withDNS := *base
	withDNS.DNSForwards = []nodepolicy.DNSForward{{Domain: "corp.local", ResolverIP: "10.0.0.53"}}
	if nodepolicy.CanonicalHash(base) != nodepolicy.CanonicalHash(&withDNS) {
		t.Fatal("DNSForwards must be hash-blind on the agent side too (else a DNS change false-alarms silent_desync)")
	}
}

// The agent must CAPTURE rule_id off the v2 wire (it stamps flow/deny events with it,
// D6) — while the hash stays blind to it (equal to the rule_id-free equivalent).
func TestWireRuleIDCapturedButHashBlind(t *testing.T) {
	wire := `{"version":2,"node_id":"node-a","mode":"enforcing","mesh":false,"allow":[{"src_ip":"10.99.0.10","dst_cidr":"10.0.5.0/24","protocol":"tcp","port_low":5432,"port_high":5432,"rule_id":"rule-uuid-1"}]}`
	var withID nodepolicy.Compiled
	if err := json.Unmarshal([]byte(wire), &withID); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if withID.Allow[0].RuleID != "rule-uuid-1" {
		t.Fatalf("agent must capture rule_id for event stamping, got %q", withID.Allow[0].RuleID)
	}
	noID := withID
	noID.Allow = []nodepolicy.AllowEntry{{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432}}
	if nodepolicy.CanonicalHash(&withID) != nodepolicy.CanonicalHash(&noID) {
		t.Fatal("captured rule_id must not perturb the applied-hash (metadata-blind staleness)")
	}
}

// TestWireSrcDeviceIDCapturedButHashBlind (v3, S7.5.4): the agent decodes src_device_id
// from a v3 wire artifact (for flow-event stamping) but it stays OUT of the applied hash.
func TestWireSrcDeviceIDCapturedButHashBlind(t *testing.T) {
	wire := `{"version":3,"node_id":"node-a","mode":"enforcing","mesh":false,"allow":[{"src_ip":"10.99.0.10","dst_cidr":"10.0.5.0/24","protocol":"tcp","port_low":5432,"port_high":5432,"rule_id":"r1","src_device_id":"dev-uuid-1"}]}`
	var withDev nodepolicy.Compiled
	if err := json.Unmarshal([]byte(wire), &withDev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if withDev.Allow[0].SrcDeviceID != "dev-uuid-1" {
		t.Fatalf("agent must capture src_device_id for event stamping, got %q", withDev.Allow[0].SrcDeviceID)
	}
	noDev := withDev
	noDev.Allow = []nodepolicy.AllowEntry{{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: "r1"}}
	if nodepolicy.CanonicalHash(&withDev) != nodepolicy.CanonicalHash(&noDev) {
		t.Fatal("captured src_device_id must not perturb the applied-hash")
	}
}
