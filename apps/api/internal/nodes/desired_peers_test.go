package nodes

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestComposeDesiredPeersSharedSiteAndKubernetesEdge(t *testing.T) {
	input := []Peer{
		{PublicKey: "device", AllowedIPs: []string{"10.99.0.2/32"}},
		{PublicKey: "edge", AllowedIPs: []string{"10.99.0.0/24", "172.31.0.0/16"}, Endpoint: "65.2.179.105:31083", SiteLink: true, PersistentKeepalive: 25},
		{PublicKey: "edge", AllowedIPs: []string{"10.99.0.0/24"}, Endpoint: "65.2.179.105:31083", SiteLink: true, PersistentKeepalive: 25},
	}
	got, err := composeDesiredPeers(input)
	if err != nil || len(got) != 2 {
		t.Fatalf("one kernel peer per key required: got=%+v err=%v", got, err)
	}
	if !reflect.DeepEqual(got[1].AllowedIPs, []string{"10.99.0.0/24", "172.31.0.0/16"}) {
		t.Fatalf("ordinary site route lost: %+v", got)
	}
	reversed := []Peer{input[2], input[1], input[0]}
	again, err := composeDesiredPeers(reversed)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("composition depends on input order: %+v %v", again, err)
	}
	got[1].AllowedIPs[0] = "mutated"
	if input[1].AllowedIPs[0] != "10.99.0.0/24" {
		t.Fatal("output aliases source graph")
	}
}

func TestComposeDesiredPeersFromCoexistingTopologyGraphs(t *testing.T) {
	site, remote, connector, edge := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	edgeRow := sqlc.ListSiteGatewaysForOrgRow{ID: edge, SiteID: pgtype.UUID{Bytes: site, Valid: true}, WgPublicKey: "edge", Endpoint: "edge:51820"}
	topo := siteTopology{
		hubMembers: []sqlc.ListSiteGatewaysForOrgRow{edgeRow}, poolCIDR: "10.99.0.0/24",
		gws:           []sqlc.ListSiteGatewaysForOrgRow{edgeRow, {ID: uuid.New(), SiteID: pgtype.UUID{Bytes: remote, Valid: true}}},
		subnets:       map[uuid.UUID][]string{remote: {"172.31.0.0/16"}},
		k8sConnectors: map[uuid.UUID]k8sConnector{connector: {nodeID: connector, siteID: site}},
	}
	node := sqlc.Node{ID: connector, SiteID: pgtype.UUID{Bytes: site, Valid: true}}
	sitePeers, _ := siteLinkGraphFrom(topo, node)
	k8sPeers, _ := k8sHandoffGraph(topo, node)
	if len(sitePeers) != 1 || len(k8sPeers) != 1 {
		t.Fatal("fixture must exercise both graphs")
	}
	got, err := composeDesiredPeers(append(sitePeers, k8sPeers...))
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].AllowedIPs, []string{"10.99.0.0/24", "172.31.0.0/16"}) {
		t.Fatalf("shared topology edge: %+v %v", got, err)
	}
	device := Peer{PublicKey: "device", AllowedIPs: []string{"10.99.0.2/32"}}
	if _, err := composeDesiredPeers([]Peer{device, device}); err == nil {
		t.Fatal("duplicate device identities must not be hidden")
	}
}

func TestComposeDesiredPeersWarmDisjointAndConflict(t *testing.T) {
	base := Peer{PublicKey: "edge", SiteLink: true, Endpoint: "edge:51820", PersistentKeepalive: 25}
	first := base
	first.AllowedIPs = []string{"10.1.0.0/24"}
	second := base
	second.AllowedIPs = []string{"10.2.0.0/24"}
	got, err := composeDesiredPeers([]Peer{second, base, first})
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].AllowedIPs, []string{"10.1.0.0/24", "10.2.0.0/24"}) {
		t.Fatalf("union: %+v %v", got, err)
	}
	for _, mutate := range []func(*Peer){func(p *Peer) { p.Endpoint = "other:51820" }, func(p *Peer) { p.PersistentKeepalive = 10 }, func(p *Peer) { p.SiteLink = false }} {
		changed := base
		mutate(&changed)
		if _, err := composeDesiredPeers([]Peer{base, changed}); err == nil {
			t.Fatal("conflicting transport accepted")
		}
	}
}
