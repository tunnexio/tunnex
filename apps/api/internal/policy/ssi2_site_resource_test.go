package policy_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

// TestSiteSourceResourceInOtherSiteFarPlacement — SSI-2, finding F3. A site-source rule to a RESOURCE that
// lives in ANOTHER site must be granted on every gateway that forwards the flow: the source gateway, the
// destination site's gateway, and the transit hub. Before SSI-2 only the source gateway received it, so the
// rule showed active while the hub and the destination gateway, both default-deny, dropped the traffic.
// That left "site → site, every port" as the only site rule that worked.
func TestSiteSourceResourceInOtherSiteFarPlacement(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000055a201")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000055a202")
	siteH := uuid.MustParse("00000000-0000-0000-0000-00000055a203")
	nodeH := uuid.MustParse("00000000-0000-0000-0000-0000000055c1")
	resB := uuid.New()   // inside site B
	resOut := uuid.New() // inside no site
	resA := uuid.New()   // inside the SOURCE site itself
	snap := policy.Snapshot{
		Mode: policy.ModeEnforcing,
		Resources: []policy.Resource{
			{ID: resB, CIDR: "10.2.0.8/32", Protocol: "tcp", PortLow: 8080, PortHigh: 8080},
			{ID: resOut, CIDR: "192.0.2.0/24", Protocol: "any"},
			{ID: resA, CIDR: "10.1.0.9/32", Protocol: "tcp", PortLow: 22, PortHigh: 22},
		},
		Rules: []policy.Rule{
			{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "resource", DstResourceID: resB},
			{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "resource", DstResourceID: resOut},
			{ID: uuid.New(), SrcKind: "site", SrcSiteID: siteA, DstKind: "resource", DstResourceID: resA},
		},
		SiteSubnets: []policy.SiteSubnet{
			{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"}, {SiteID: siteH, CIDR: "10.3.0.0/24"},
		},
		SiteNodes: []policy.SiteNode{
			{SiteID: siteA, NodeID: nodeA},
			{SiteID: siteB, NodeID: nodeB},
			{SiteID: siteH, NodeID: nodeH, Endpoint: "hub.example:51820"},
		},
		ActiveHub: nodeH,
	}
	out := policy.Compile(snap)

	// The cross-site resource: source gateway, destination gateway and hub all carry the grant.
	for _, n := range []uuid.UUID{nodeA, nodeB, nodeH} {
		if !hasAllow(allowsFor(out, n), "10.1.0.0/24", "10.2.0.8/32") {
			t.Fatalf("site→resource grant must reach node %s, got %+v", n, allowsFor(out, n))
		}
	}
	// It stays port-scoped everywhere: the far gateway never receives a wider entry than the resource.
	for _, n := range []uuid.UUID{nodeA, nodeB, nodeH} {
		for _, a := range allowsFor(out, n) {
			if a.SrcIP == "10.1.0.0/24" && a.DstCIDR == "10.2.0.8/32" && (a.PortLow != 8080 || a.PortHigh != 8080) {
				t.Fatalf("node %s holds a grant wider than the resource's port: %+v", n, a)
			}
		}
		if hasAllow(allowsFor(out, n), "10.1.0.0/24", "10.2.0.0/24") {
			t.Fatalf("node %s must not hold a whole-site grant for a resource rule", n)
		}
	}
	// A resource in no site: the source gateway only (it egresses there), never the hub or site B.
	if !hasAllow(allowsFor(out, nodeA), "10.1.0.0/24", "192.0.2.0/24") {
		t.Fatalf("non-site resource must still land on the source gateway, got %+v", allowsFor(out, nodeA))
	}
	for _, n := range []uuid.UUID{nodeB, nodeH} {
		if hasAllow(allowsFor(out, n), "10.1.0.0/24", "192.0.2.0/24") {
			t.Fatalf("a resource in no site must not land on node %s", n)
		}
	}
	// A resource inside the source site itself never crosses a link: source gateway only.
	for _, n := range []uuid.UUID{nodeB, nodeH} {
		if hasAllow(allowsFor(out, n), "10.1.0.0/24", "10.1.0.9/32") {
			t.Fatalf("a same-site resource must not land on node %s", n)
		}
	}
}

// TestCIDRSourceResourceInOtherSiteFarPlacement — the same placement for a CIDR source inside a site.
func TestCIDRSourceResourceInOtherSiteFarPlacement(t *testing.T) {
	siteA := uuid.MustParse("00000000-0000-0000-0000-00000055a211")
	siteB := uuid.MustParse("00000000-0000-0000-0000-00000055a212")
	resB := uuid.New()
	snap := policy.Snapshot{
		Mode:      policy.ModeEnforcing,
		Resources: []policy.Resource{{ID: resB, CIDR: "10.2.0.8/32", Protocol: "tcp", PortLow: 8080, PortHigh: 8080}},
		Rules:     []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "10.1.0.7/32", DstKind: "resource", DstResourceID: resB}},
		SiteSubnets: []policy.SiteSubnet{
			{SiteID: siteA, CIDR: "10.1.0.0/24"}, {SiteID: siteB, CIDR: "10.2.0.0/24"},
		},
		SiteNodes: []policy.SiteNode{
			{SiteID: siteA, NodeID: nodeA, Endpoint: "a.example:51820"},
			{SiteID: siteB, NodeID: nodeB},
		},
		ActiveHub: nodeA,
	}
	out := policy.Compile(snap)
	for _, n := range []uuid.UUID{nodeA, nodeB} {
		if !hasAllow(allowsFor(out, n), "10.1.0.7/32", "10.2.0.8/32") {
			t.Fatalf("cidr→resource grant must reach node %s, got %+v", n, allowsFor(out, n))
		}
	}
}
