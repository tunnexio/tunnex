package nodes

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestHubGivesARemoteSiteOneCarrier — SSI-7b, finding F9. A spoke site with two gateways gave the hub two
// peers with the SAME AllowedIPs. WireGuard keeps an allowed range on one peer only, so which gateway
// received the site's traffic was whatever was configured last. The hub now gives the site's ranges to
// exactly one gateway (the carrier) and keeps the other as a warm, keepalive-only peer, the same shape a
// spoke already gives a standby hub.
func TestHubGivesARemoteSiteOneCarrier(t *testing.T) {
	fresh := time.Now()
	hubSite, spokeSite := idAt(0xA), idAt(0xB)
	hub := gw(1, "hub:51820", "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=", pri(1), &fresh)
	hub.SiteID = pgtype.UUID{Bytes: hubSite, Valid: true}
	// Two gateways on the SPOKE site, neither a hub member. Listed second-first on purpose: the carrier
	// must not depend on list order.
	spoke2 := gw(3, "", "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo=", nil, &fresh)
	spoke2.SiteID = pgtype.UUID{Bytes: spokeSite, Valid: true}
	spoke1 := gw(2, "", "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM=", nil, &fresh)
	spoke1.SiteID = pgtype.UUID{Bytes: spokeSite, Valid: true}
	subnets := map[uuid.UUID][]string{hubSite: {"172.31.0.0/16"}, spokeSite: {"10.70.0.0/24"}}
	nodeOf := func(g sqlc.ListSiteGatewaysForOrgRow) sqlc.Node { return sqlc.Node{ID: g.ID, SiteID: g.SiteID} }

	carrying := func(peers []Peer, cidr string) []string {
		var keys []string
		for i := range peers {
			for _, a := range peers[i].AllowedIPs {
				if a == cidr {
					keys = append(keys, peers[i].PublicKey)
				}
			}
		}
		return keys
	}

	var first string
	for _, order := range [][]sqlc.ListSiteGatewaysForOrgRow{{hub, spoke2, spoke1}, {spoke1, hub, spoke2}} {
		topo := siteTopology{gws: order, subnets: subnets}
		peers, _ := siteLinkGraphFrom(topo, nodeOf(hub))
		got := carrying(peers, "10.70.0.0/24")
		if len(got) != 1 {
			t.Fatalf("the spoke site's range must be on EXACTLY ONE hub peer, got %d: %v", len(got), got)
		}
		if first == "" {
			first = got[0]
		} else if got[0] != first {
			t.Fatalf("the carrier must not depend on gateway list order: %s vs %s", first, got[0])
		}
		// The other gateway is still a peer, with no ranges: warm, and structurally unable to receive traffic.
		if len(peers) != 2 {
			t.Fatalf("the hub must keep both spoke gateways as peers (one carrier, one warm), got %d", len(peers))
		}
		for i := range peers {
			if peers[i].PublicKey != got[0] && len(peers[i].AllowedIPs) != 0 {
				t.Fatalf("the non-carrier peer must have no allowed ranges, got %v", peers[i].AllowedIPs)
			}
			if !peers[i].SiteLink || peers[i].PersistentKeepalive == 0 {
				t.Fatalf("both spoke peers must be keepalive site links, got %+v", peers[i])
			}
		}
	}
	// Deterministic choice: the lowest gateway id of the site.
	if first != spoke1.WgPublicKey {
		t.Fatalf("the carrier of a site with no hub member is its lowest-id gateway, got %s", first)
	}
}
