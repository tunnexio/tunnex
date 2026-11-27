package policyspec

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDenyEntriesAreContentDerived — AI-SEC-2. A deny closes a device's direct path to an MCP endpoint that
// it may only reach through the gateway. An agent that cannot render the deny would leave that path open while
// reporting the policy applied, so the artifact must be one it refuses: any deny raises the version to 16.
// An artifact with no deny keeps the version, the bytes and therefore the hash it had before.
func TestDenyEntriesAreContentDerived(t *testing.T) {
	plain := Compiled{NodeID: "node-a", Mode: "enforcing", Allow: []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.99.0.9/32", Protocol: ProtoAny}}}
	denied := plain
	denied.Deny = []DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9000, PortHigh: 9000}}

	if got := RequiredVersion(denied); got != 16 {
		t.Fatalf("an artifact carrying a deny requires v16, got v%d", got)
	}
	if got := RequiredVersion(plain); got != 4 {
		t.Fatalf("without a deny the artifact stays at v4, got v%d", got)
	}
	if ProtocolVersion < 16 {
		t.Fatalf("deny entries need ProtocolVersion >= 16, got %d", ProtocolVersion)
	}

	plain.Version, denied.Version = RequiredVersion(plain), RequiredVersion(denied)
	b, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "deny") {
		t.Fatalf("an artifact with no deny must not serialize the section: %s", b)
	}
	if CanonicalHash(plain) == CanonicalHash(denied) {
		t.Fatal("adding a deny must change the hash, or the gateway would never re-converge")
	}
}

// TestDenyIsInTheEnforcementHash — the deny is enforcement, not plumbing: two artifacts at the SAME version
// that differ only in what they deny must not hash alike, or withdrawing or retargeting a deny would be
// invisible to the pushed-versus-applied comparison.
func TestDenyIsInTheEnforcementHash(t *testing.T) {
	base := Compiled{Version: 16, NodeID: "node-a", Mode: "off", Mesh: true}
	a, b := base, base
	a.Deny = []DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9000, PortHigh: 9000}}
	b.Deny = []DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9001, PortHigh: 9001}}
	if CanonicalHash(a) == CanonicalHash(b) {
		t.Fatal("a different denied port must change the hash")
	}
	c := a
	c.Deny = []DenyEntry{{SrcIP: "10.99.0.8", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9000, PortHigh: 9000}}
	if CanonicalHash(a) == CanonicalHash(c) {
		t.Fatal("a different denied source must change the hash")
	}
}

// TestDenyMetadataIsObservabilityOnly — the reason and the source device id explain a drop in the access log.
// They never decide a packet, so they stay out of the hash like rule_id and src_device_id on an allow.
func TestDenyMetadataIsObservabilityOnly(t *testing.T) {
	a := Compiled{Version: 16, NodeID: "node-a", Mode: "enforcing", Deny: []DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9000, PortHigh: 9000}}}
	b := a
	b.Deny = []DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9000, PortHigh: 9000, Reason: DenyReasonMCPGatewayOnly, SrcDeviceID: "01a21b38-dc70-7d21-9c08-2772c26b7a3c"}}
	if CanonicalHash(a) != CanonicalHash(b) {
		t.Fatal("deny metadata must not enter the enforcement hash")
	}
}

// TestDenyCanonicalHashGolden pins the deny projection to the same bytes as the gateway's mirror
// (apps/node/internal/nodepolicy). The two modules cannot share a type, so this pair of goldens is the only
// guard that both sides hash a deny identically. If one changes, change the other from a deliberate decision.
func TestDenyCanonicalHashGolden(t *testing.T) {
	c := Compiled{Version: 16, NodeID: "node-a", Mode: "enforcing",
		Allow: []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.99.0.9/32", Protocol: ProtoAny}},
		Deny:  []DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: ProtoTCP, PortLow: 9000, PortHigh: 9000, Reason: DenyReasonMCPGatewayOnly}},
	}
	if got := CanonicalHash(c); got != denyGolden {
		t.Fatalf("deny golden = %q, want %q (nodepolicy twin must match)", got, denyGolden)
	}
}

const denyGolden = "d834f35abc49"
