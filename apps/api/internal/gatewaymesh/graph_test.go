package gatewaymesh

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestGraphOptInOwnershipAndNAT(t *testing.T) {
	hub, a, b := uuid.New(), uuid.New(), uuid.New()
	gateways := []Gateway{{ID: hub, PublicKey: "hub", Endpoint: "hub.example:51820"}, {ID: a, PublicKey: "a"}, {ID: b, PublicKey: "b"}}
	clients := []Client{{NodeID: a, Address: "10.99.0.2"}, {NodeID: b, Address: "10.99.0.3"}}
	off, err := Build(false, gateways, clients, nil)
	if err != nil || len(off.Peers(a)) != 0 {
		t.Fatalf("default enabled: %+v %v", off, err)
	}
	on, err := Build(true, gateways, clients, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := on.Peers(a); len(got) != 1 || got[0].NodeID != hub || !reflect.DeepEqual(got[0].Prefixes, []string{"10.99.0.3/32"}) {
		t.Fatalf("NAT source path: %+v", got)
	}
	if got := on.Peers(hub); len(got) != 2 {
		t.Fatalf("relay must have both client owners: %+v", got)
	}
	if !reflect.DeepEqual(on.EnforcementNodes("10.99.0.2", "10.99.0.3/32"), sortedIDs(a, b, hub)) {
		t.Fatal("both endpoints and relay must enforce")
	}
	changed := append([]Client(nil), clients...)
	changed[1].NodeID = a
	moved, err := Build(true, gateways, changed, nil)
	if err != nil || len(moved.Peers(a)) != 1 || len(moved.Peers(a)[0].Prefixes) != 0 {
		t.Fatalf("move retained remote route: %+v %v", moved.Peers(a), err)
	}
	// A client-less spoke retains a warm relay peer with no authorized addresses.
	relayPeers := moved.Peers(hub)
	if len(relayPeers) != 2 {
		t.Fatalf("move dropped gateway handshake: %+v", relayPeers)
	}
	for _, p := range relayPeers {
		if p.NodeID == b && len(p.Prefixes) != 0 {
			t.Fatal("warm peer retained revoked addresses")
		}
	}
	revoked, err := Build(true, gateways, clients[:1], nil)
	if err != nil || len(revoked.EnforcementNodes("10.99.0.2", "10.99.0.3/32")) != 0 {
		t.Fatal("removed destination retained authorization placement")
	}
	if _, err := Build(true, gateways, append(clients, Client{NodeID: a, Address: "10.99.0.3"}), nil); err == nil {
		t.Fatal("ambiguous address ownership accepted")
	}
}

func TestGraphHubFailoverAndNoCarrier(t *testing.T) {
	old, primary, spoke := uuid.New(), uuid.New(), uuid.New()
	gateways := []Gateway{{ID: old, PublicKey: "old", Endpoint: "old.example:51820"}, {ID: primary, PublicKey: "new", Endpoint: "new.example:51820"}, {ID: spoke, PublicKey: "spoke"}}
	clients := []Client{{NodeID: old, Address: "10.99.0.2"}, {NodeID: spoke, Address: "10.99.0.3"}}
	graph, err := Build(true, gateways, clients, []uuid.UUID{primary, old})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Owner("10.99.0.2") != primary || graph.Relay != primary {
		t.Fatal("HA primary does not own member clients")
	}
	for _, p := range graph.Peers(primary) {
		for _, prefix := range p.Prefixes {
			if prefix == "10.99.0.2/32" {
				t.Fatal("remote peer stole locally hosted HA client")
			}
		}
	}
	for i := range gateways {
		gateways[i].Endpoint = ""
	}
	blocked, err := Build(true, gateways, clients, nil)
	if err != nil || blocked.Unavailable == "" || len(blocked.Peers(spoke)) != 0 {
		t.Fatal("no public carrier must withdraw routes and report unavailability")
	}
}

func TestDualStackAliasesPreserveIdentityAndWithdraw(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	gateways := []Gateway{{ID: a, PublicKey: "a", Endpoint: "a.example:51820"}, {ID: b, PublicKey: "b"}}
	clients := []Client{{NodeID: a, Address: "10.99.0.2", IPv6Address: "fd99::2"}, {NodeID: b, Address: "10.99.0.3", IPv6Address: "fd99::3"}}
	graph, err := Build(true, gateways, clients, []uuid.UUID{a})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Owner("fd99::3") != b {
		t.Fatal("IPv6 ownership differs from IPv4")
	}
	tuples := graph.IPv6Tuples("10.99.0.2", "10.99.0.0/24")
	if len(tuples) != 1 || tuples[0].Source != "fd99::2" || tuples[0].Destination != "fd99::3/128" {
		t.Fatalf("IPv6 scope widened: %+v", tuples)
	}
	if got := graph.Peers(a); len(got) != 1 || !reflect.DeepEqual(got[0].Prefixes, []string{"10.99.0.3/32", "fd99::3/128"}) {
		t.Fatalf("dual stack route: %+v", got)
	}
	revoked, err := Build(true, gateways, clients[:1], []uuid.UUID{a})
	if err != nil || len(revoked.IPv6Tuples("10.99.0.2", "10.99.0.0/24")) != 0 {
		t.Fatal("IPv6 alias survived revocation")
	}
}
