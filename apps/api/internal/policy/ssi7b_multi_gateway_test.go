package policy_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

// TestSiteGrantsReachEveryGatewayOfASite — SSI-7b, finding F9. A site may hold more than one gateway (the
// single-gateway index was lifted for hub HA). The compiler kept one gateway per site in a last-write-wins
// map, so a site rule was granted on whichever gateway happened to be listed last and the other one, being
// default-deny, dropped the same flow. Every gateway of the source and destination site must hold the grant:
// which of them carries the traffic is a data-plane choice and can change on promotion.
func TestSiteGrantsReachEveryGatewayOfASite(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000057b001")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000057b002")
	a1 := uuid.MustParse("00000000-0000-0000-0000-0000000057a1")
	a2 := uuid.MustParse("00000000-0000-0000-0000-0000000057a2")
	b1 := uuid.MustParse("00000000-0000-0000-0000-0000000057b1")
	b2 := uuid.MustParse("00000000-0000-0000-0000-0000000057b2")
	resB := uuid.New()
	dev := uuid.MustParse("00000000-0000-0000-0000-0000000057d1")
	snap := policy.Snapshot{
		Mode:        policy.ModeEnforcing,
		Devices:     []policy.Device{{ID: uuid.New(), UserID: uAlice, NodeID: dev, AssignedIP: "10.99.0.10"}},
		Memberships: []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Resources:   []policy.Resource{{ID: resB, CIDR: "10.2.0.8/32", Protocol: "tcp", PortLow: 8080, PortHigh: 8080}},
		Rules: []policy.Rule{
			{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "site", DstSiteID: siteB},
			{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteB, DstKind: "resource", DstResourceID: resB},
			{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "resource", DstResourceID: resB},
			{ID: uuid.New(), SrcKind: "group", SrcGroupID: gAdmins, DstKind: "site", DstSiteID: siteB},
		},
		SiteSubnets: []policy.SiteSubnet{{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}},
		SiteNodes: []policy.SiteNode{
			{SiteID: siteA, NodeID: a1, Endpoint: "a1.example:51820"}, {SiteID: siteA, NodeID: a2, Endpoint: "a2.example:51820"},
			{SiteID: siteB, NodeID: b1}, {SiteID: siteB, NodeID: b2},
		},
		ActiveHub: a1,
	}
	out := policy.Compile(snap)

	// site → site: both gateways of both sites.
	for _, n := range []uuid.UUID{a1, a2, b1, b2} {
		if !hasAllow(allowsFor(out, n), "10.1.0.0/24", "10.2.0.0/24") {
			t.Fatalf("site→site grant must reach gateway %s, got %+v", n, allowsFor(out, n))
		}
	}
	// site → resource in another site: both source gateways and both destination gateways.
	for _, n := range []uuid.UUID{a1, a2, b1, b2} {
		if !hasAllow(allowsFor(out, n), "10.1.0.0/24", "10.2.0.8/32") {
			t.Fatalf("site→resource grant must reach gateway %s, got %+v", n, allowsFor(out, n))
		}
	}
	// device → site: the device's node, the hub, and both gateways of the destination site.
	for _, n := range []uuid.UUID{dev, a1, b1, b2} {
		if !hasAllow(allowsFor(out, n), "10.99.0.10", "10.2.0.0/24") {
			t.Fatalf("device→site grant must reach node %s, got %+v", n, allowsFor(out, n))
		}
	}
	// The order SiteNodes arrives in must not matter.
	snap.SiteNodes = []policy.SiteNode{
		{SiteID: siteB, NodeID: b2}, {SiteID: siteA, NodeID: a2, Endpoint: "a2.example:51820"},
		{SiteID: siteB, NodeID: b1}, {SiteID: siteA, NodeID: a1, Endpoint: "a1.example:51820"},
	}
	reordered := policy.Compile(snap)
	for _, n := range []uuid.UUID{a1, a2, b1, b2} {
		if len(allowsFor(reordered, n)) != len(allowsFor(out, n)) {
			t.Fatalf("gateway %s: placement changed with SiteNodes order: %d vs %d entries", n, len(allowsFor(reordered, n)), len(allowsFor(out, n)))
		}
	}
}
