package policyspec

import "testing"

// TestNMinusOneAgentsCanStillApply — D1's contract, enforced rather than intended.
//
// "We support agent version N-1" drifts on the first artifact-shape change unless something fails when it
// does — and v7 is proof that shapes change (v5 site sources, v6 pool CIDR, v7 K8s VIP maps all moved it).
//
// What makes the contract KEEPABLE is that RequiredVersion is CONTENT-DERIVED: an artifact is stamped with
// the OLDEST protocol version whose shape covers its content, so an organization using no new-version
// features still receives an OLD-version artifact that an N-1 agent applies correctly. This red pins that
// property per version: an artifact whose content uses only features available at version v must stamp <= v.
//
// If a future change makes some artifact require the current version UNCONDITIONALLY — for instance by
// emitting a new mandatory section for every org — this test fails, and correctly: at that moment every N-1
// agent in the field would begin refusing its artifact (fail-closed, so safe, but a fleet-wide outage of
// policy updates). That is a decide-item for a human, not a number to bump.
func TestNMinusOneAgentsCanStillApply(t *testing.T) {
	if ProtocolVersion < SupportedWindow {
		t.Fatalf("ProtocolVersion %d cannot support a window of %d", ProtocolVersion, SupportedWindow)
	}
	oldest := ProtocolVersion - SupportedWindow + 1 // the oldest agent version still supported

	// The ZERO-CONFIG artifact — a plain org with device-to-device allows and nothing else — must be
	// applicable by the OLDEST supported agent. This is the case that covers most deployments, and if it ever
	// requires the newest version then N-1 support is over for everyone at once.
	zeroConfig := Compiled{
		Allow: []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.99.0.9/32", Protocol: "any"}},
	}
	if got := RequiredVersion(zeroConfig); got > oldest {
		t.Fatalf("the zero-config artifact requires v%d, but the oldest SUPPORTED agent is v%d — every "+
			"N-1 agent in the field would refuse its artifact (fail-closed, but a fleet-wide policy-update "+
			"outage). D1's N/N-1 contract is broken; this is a decide-item, not a number to bump.", got, oldest)
	}

	// And the artifact must not be stamped ABOVE the CP's own protocol version — an artifact no agent could
	// ever apply, including a brand-new one.
	for name, c := range map[string]Compiled{
		"zero-config":  zeroConfig,
		"site-source":  {Allow: []AllowEntry{{SrcIP: "10.1.0.0/24", DstCIDR: "10.2.0.0/24", Protocol: "any"}}},
		"with-routes":  {Routes: []Route{{DstCIDR: "10.5.0.0/24"}}},
		"with-pool":    {PoolCIDR: "10.99.0.0/24"},
		"with-k8s-vip": {VIPMappings: []VIPMapping{{VIP: "100.64.0.3"}}},
	} {
		v := RequiredVersion(c)
		if v > ProtocolVersion {
			t.Fatalf("%s stamps v%d, above the CP's own ProtocolVersion %d — no agent could apply it",
				name, v, ProtocolVersion)
		}
		if v < 1 {
			t.Fatalf("%s stamps v%d — an artifact must always carry a version", name, v)
		}
	}
}

// TestNewContentRaisesRequiredVersion — the inverse half, and the one that keeps the contract HONEST.
//
// N-1 support must never be bought by silence: an artifact carrying content an old agent cannot render must
// stamp a version that old agent REFUSES, so it fails closed instead of mis-enforcing. (The S8.2 law: every
// enforcement-significant content addition adds its trigger in the same change.)
func TestNewContentRaisesRequiredVersion(t *testing.T) {
	base := RequiredVersion(Compiled{Allow: []AllowEntry{{SrcIP: "10.99.0.7", DstCIDR: "10.99.0.9/32"}}})
	for name, c := range map[string]Compiled{
		"site source (v5)":  {Allow: []AllowEntry{{SrcIP: "10.1.0.0/24", DstCIDR: "10.2.0.0/24"}}},
		"routes (v5)":       {Routes: []Route{{DstCIDR: "10.5.0.0/24"}}},
		"pool cidr (v6)":    {PoolCIDR: "10.99.0.0/24"},
		"k8s vip map (v7)":  {VIPMappings: []VIPMapping{{VIP: "100.64.0.3"}}},
		"k8s dns zone (v7)": {K8sDNSZones: []K8sDNSZone{{Zone: "prod.k8s.local", ListenVIP: "100.64.0.2"}}},
	} {
		if got := RequiredVersion(c); got <= base {
			t.Fatalf("%s does not raise RequiredVersion above the baseline v%d (got v%d) — an old agent "+
				"would ACCEPT an artifact it cannot render, and mis-enforce silently", name, base, got)
		}
	}
}
