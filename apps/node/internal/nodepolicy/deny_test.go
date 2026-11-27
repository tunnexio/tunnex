package nodepolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// TestDenyCanonicalHashGolden is the gateway half of the deny twin-golden (the other half is
// apps/api/internal/policyspec TestDenyCanonicalHashGolden). The two modules cannot share a type, so this pair
// is the only guard that both sides hash an explicit drop identically. If one changes, change the other from
// a deliberate decision — never by updating a single golden.
func TestDenyCanonicalHashGolden(t *testing.T) {
	c := nodepolicy.Compiled{Version: 16, NodeID: "node-a", Mode: nodepolicy.ModeEnforcing,
		Allow: []nodepolicy.AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.99.0.9/32", Protocol: "any"}},
		Deny:  []nodepolicy.DenyEntry{{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000, Reason: "mcp_gateway_only"}},
	}
	if got := nodepolicy.CanonicalHash(&c); got != "d834f35abc49" {
		t.Fatalf("deny golden = %q, want d834f35abc49 (policyspec twin must match)", got)
	}
}

// TestDenySurvivesWireRoundTrip — the deny arrives as JSON from the control plane. The match fields must be
// captured exactly and hash the same after decoding; the reason and source device id are captured for the
// access log but never change the hash.
func TestDenySurvivesWireRoundTrip(t *testing.T) {
	wire := `{"version":16,"node_id":"node-a","mode":"enforcing","mesh":false,"allow":[{"src_ip":"10.99.0.7","dst_cidr":"10.99.0.9/32","protocol":"any"}],"deny":[{"src_ip":"10.99.0.7","dst_cidr":"172.30.0.10/32","protocol":"tcp","port_low":9000,"port_high":9000,"reason":"mcp_gateway_only","src_device_id":"01a21b38-dc70-7d21-9c08-2772c26b7a3c"}]}`
	var c nodepolicy.Compiled
	if err := json.Unmarshal([]byte(wire), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Deny) != 1 {
		t.Fatalf("deny entries = %d, want 1", len(c.Deny))
	}
	d := c.Deny[0]
	if d.SrcIP != "10.99.0.7" || d.DstCIDR != "172.30.0.10/32" || d.Protocol != "tcp" || d.PortLow != 9000 || d.PortHigh != 9000 {
		t.Fatalf("deny match fields not captured: %+v", d)
	}
	if d.Reason != "mcp_gateway_only" || d.SrcDeviceID == "" {
		t.Fatalf("deny metadata not captured: %+v", d)
	}
	if got := nodepolicy.CanonicalHash(&c); got != "d834f35abc49" {
		t.Fatalf("hash after round trip = %q, want d834f35abc49", got)
	}
}

// TestDenyArtifactIsRefusedUntilTheGatewayRendersIt — an artifact that carries a deny is stamped v16 by the
// control plane. Until this gateway renders denies it must keep refusing that version (the fail-closed gate in
// egress), never accept the artifact and silently leave the denied path open. Raising MaxSupportedVersion
// belongs in the same change as the forward-chain render.
func TestDenyArtifactIsRefusedUntilTheGatewayRendersIt(t *testing.T) {
	if nodepolicy.MaxSupportedVersion >= 16 && !nodepolicy.RendersDeny {
		t.Fatalf("MaxSupportedVersion is %d but the gateway does not render denies: a v16 artifact would be accepted with its denied paths left open", nodepolicy.MaxSupportedVersion)
	}
}
