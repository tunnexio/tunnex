package nodes

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestSiteLinkCarriesAnotherSitesClusterServices — K8L-5. A device connects to one gateway. A cluster's
// exposed Services are served by a gateway in another site. Every device is told to route the cluster's
// addresses, so the site link has to carry them or the traffic stops at the first gateway with no
// message. They ride the site link exactly like that site's approved subnets.
func TestSiteLinkCarriesAnotherSitesClusterServices(t *testing.T) {
	fresh := time.Now()
	officeSite, cloudSite := idAt(0xA), idAt(0xB)
	office := gw(1, "office:51820", "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=", pri(1), &fresh)
	office.SiteID = pgtype.UUID{Bytes: officeSite, Valid: true}
	cloud := gw(2, "cloud:51820", "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM=", nil, &fresh)
	cloud.SiteID = pgtype.UUID{Bytes: cloudSite, Valid: true}
	nodeOf := func(g sqlc.ListSiteGatewaysForOrgRow) sqlc.Node { return sqlc.Node{ID: g.ID, SiteID: g.SiteID} }
	const serviceVIP, dnsVIP = "100.65.0.3/32", "100.65.0.1/32"
	topo := siteTopology{
		gws:      []sqlc.ListSiteGatewaysForOrgRow{office, cloud},
		subnets:  map[uuid.UUID][]string{officeSite: {"10.80.0.0/24"}, cloudSite: {"10.70.0.0/24"}},
		siteVIPs: map[uuid.UUID][]string{cloudSite: {dnsVIP, serviceVIP}},
		poolCIDR: "10.99.0.0/24",
	}
	routeSet := func(routes []string) []string { slices.Sort(routes); return routes }

	// The office gateway (where the device is) must send the cloud cluster's addresses to the cloud peer.
	peers, routes := siteLinkGraphFrom(topo, nodeOf(office))
	if len(peers) != 1 || peers[0].PublicKey != cloud.WgPublicKey {
		t.Fatalf("office must have exactly the cloud peer, got %+v", peers)
	}
	for _, want := range []string{"10.70.0.0/24", serviceVIP, dnsVIP} {
		if !slices.Contains(peers[0].AllowedIPs, want) {
			t.Errorf("office's cloud peer AllowedIPs %v lack %s", peers[0].AllowedIPs, want)
		}
	}
	var got []string
	for _, r := range routes {
		got = append(got, r.DstCIDR)
	}
	if want := []string{"10.70.0.0/24", dnsVIP, serviceVIP}; !slices.Equal(routeSet(got), routeSet(want)) {
		t.Errorf("office routes = %v, want %v", got, want)
	}

	// The cloud gateway must not be told to send its OWN cluster addresses back over the link.
	peers, routes = siteLinkGraphFrom(topo, nodeOf(cloud))
	for _, p := range peers {
		if slices.Contains(p.AllowedIPs, serviceVIP) || slices.Contains(p.AllowedIPs, dnsVIP) {
			t.Errorf("cloud gateway routes its own cluster address to a peer: %v", p.AllowedIPs)
		}
	}
	for _, r := range routes {
		if r.DstCIDR == serviceVIP || r.DstCIDR == dnsVIP {
			t.Errorf("cloud gateway has a site-link route for its own cluster address %s", r.DstCIDR)
		}
	}

	// No cluster anywhere: the graph is exactly what it was before.
	topo.siteVIPs = nil
	peers, _ = siteLinkGraphFrom(topo, nodeOf(office))
	if want := []string{"10.70.0.0/24"}; len(peers) != 1 || !slices.Equal(peers[0].AllowedIPs, want) {
		t.Errorf("without a cluster the office peer must carry only the subnet, got %+v", peers)
	}
}
