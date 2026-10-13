package bgp

import (
	"net/netip"
	"strings"
	"testing"
)

func TestFilteredRIBUsesFRRBestPath(t *testing.T) {
	c := fixture()
	s := Status{Peers: [2]PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}}
	raw := `{"routes":{"10.20.0.0/24":[{"valid":true,"network":"10.20.0.0/24","peerId":"169.254.20.2","nexthops":[{"ip":"169.254.20.2","afi":"ipv4","used":true}]},{"valid":true,"bestpath":true,"network":"10.20.0.0/24","peerId":"169.254.20.6","nexthops":[{"ip":"169.254.20.6","afi":"ipv4","used":true}]}]}}`
	routes, e := ParseRoutes([]byte(raw), c, s)
	if e != nil || len(routes) != 1 || routes[0].Slot != 2 {
		t.Fatal("FRR selected path overridden", e, routes)
	}
	for _, bad := range []string{strings.ReplaceAll(raw, "10.20.0.0/24", "0.0.0.0/0"), strings.Replace(raw, `"169.254.20.6","afi"`, `"169.254.99.2","afi"`, 1), strings.Replace(raw, `"valid":true`, `"valid":true,"bestpath":true`, 1)} {
		if _, e = ParseRoutes([]byte(bad), c, s); e == nil {
			t.Fatal("invalid RIB accepted", bad)
		}
	}
	s.Peers[1].State = "active"
	s.Peers[1].AcceptedPrefixes = 0
	if routes, e = ParseRoutes([]byte(raw), c, s); e != nil || len(routes) != 0 {
		t.Fatal("unhealthy best path installed", routes, e)
	}
	s.Peers[1].State = "established"
	s.Peers[1].AcceptedPrefixes = 1
	stale := strings.Replace(raw, `"valid":true`, `"valid":true,"stale":true`, 1)
	if routes, e = ParseRoutes([]byte(stale), c, s); e != nil || len(routes) != 1 || routes[0].Slot != 2 {
		t.Fatal("stale alternate poisoned fresh best", routes, e)
	}
}
func TestDisjointPeersPerPeerMaximum(t *testing.T) {
	c := fixture()
	c.MaximumPrefixes = 1
	c.RemotePrefixes = append(c.RemotePrefixes, netip.MustParsePrefix("10.30.0.0/24"))
	status := Status{Peers: [2]PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}}
	raw := `{"routes":{"10.20.0.0/24":[{"valid":true,"bestpath":true,"network":"10.20.0.0/24","peerId":"169.254.20.2","nexthops":[{"ip":"169.254.20.2","afi":"ipv4","used":true}]}],"10.30.0.0/24":[{"valid":true,"bestpath":true,"network":"10.30.0.0/24","peerId":"169.254.20.6","nexthops":[{"ip":"169.254.20.6","afi":"ipv4","used":true}]}]}}`
	routes, e := ParseRoutes([]byte(raw), c, status)
	if e != nil || len(routes) != 2 || routes[0].Slot != 1 || routes[1].Slot != 2 {
		t.Fatal("per-peer limit treated as total union limit", routes, e)
	}
	invalid := strings.Replace(raw, `"valid":true,"bestpath":true`, `"valid":false`, 1)
	routes, e = ParseRoutes([]byte(invalid), c, status)
	if e != nil || len(routes) != 1 || routes[0].Slot != 2 {
		t.Fatal("accepted invalid path poisoned healthy selected route", routes, e)
	}
}
