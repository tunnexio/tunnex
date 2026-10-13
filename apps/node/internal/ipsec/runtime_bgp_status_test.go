package ipsec

import (
	"encoding/json"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"strings"
	"testing"
)

func TestBGPStatusProjectionRequiresObservedCompletedRoutes(t *testing.T) {
	e, _, _ := bgpRouteWriterFixture(t)
	route := routeTupleFixture(e, 2)
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{route}, Target: []RuntimeBGPRouteTuple{route}}
	observed := bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}}
	out := projectBGPStatus(e, observed, [2]string{"up", "up"})
	if out == nil || len(out.Routes) != 1 || out.Routes[0].Slot != 2 || out.Peers[0].InstalledPrefixes != 0 || out.Peers[1].InstalledPrefixes != 1 || out.Peers[0].RejectedPrefixes != nil {
		t.Fatal("actual selected path projection invalid", out)
	}
	for _, change := range []func(*RuntimeJournalEntry, *bgpengine.Status, *[2]string){
		func(e *RuntimeJournalEntry, _ *bgpengine.Status, _ *[2]string) { e.BGPRoutes.Stage = "pending" },
		func(e *RuntimeJournalEntry, _ *bgpengine.Status, _ *[2]string) { e.Phase = RuntimeCleanupPending },
		func(_ *RuntimeJournalEntry, s *bgpengine.Status, _ *[2]string) { s.Peers[1].AcceptedPrefixes = 0 },
		func(_ *RuntimeJournalEntry, s *bgpengine.Status, _ *[2]string) { s.Peers[1].State = "idle" },
		func(_ *RuntimeJournalEntry, s *bgpengine.Status, _ *[2]string) { s.Peers[0].Slot = 2 },
		func(_ *RuntimeJournalEntry, _ *bgpengine.Status, tunnels *[2]string) { tunnels[1] = "down" },
	} {
		copy := e
		routes := *e.BGPRoutes
		copy.BGPRoutes = &routes
		peers := observed
		tunnels := [2]string{"up", "up"}
		change(&copy, &peers, &tunnels)
		if projectBGPStatus(copy, peers, tunnels) != nil {
			t.Fatal("unobserved/inconsistent path projected")
		}
	}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "completed", Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	observed.Peers[1] = bgpengine.PeerStatus{Slot: 2, State: "idle"}
	if out = projectBGPStatus(e, observed, [2]string{"up", "down"}); out == nil || len(out.Routes) != 0 || out.Peers[0].AcceptedPrefixes != 1 {
		t.Fatal("accepted invalid path was confused with installed route", out)
	}
}

func TestStaticStatusWireOmitsBGP(t *testing.T) {
	raw, err := json.Marshal(RuntimeStatusReport{})
	if err != nil || strings.Contains(string(raw), `"bgp"`) {
		t.Fatal("static status wire changed", string(raw), err)
	}
}

func TestBGPStatusIndependentPrefixWithdrawal(t *testing.T) {
	e, _, _ := bgpRouteWriterFixture(t)
	e.BGP.MaximumPrefixes = 1
	secondPrefix := netip.MustParsePrefix("10.21.0.0/24")
	for i := range e.Allocation.Tunnels {
		e.Allocation.Tunnels[i].RemotePrefixes = append(e.Allocation.Tunnels[i].RemotePrefixes, secondPrefix)
	}
	first := routeTupleFixture(e, 1)
	second := routeTupleFixture(e, 2)
	second.Prefix = secondPrefix
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{first, second}, Target: []RuntimeBGPRouteTuple{first, second}}
	observed := bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}}
	out := projectBGPStatus(e, observed, [2]string{"up", "up"})
	if out == nil || len(out.Routes) != 2 || out.Peers[0].InstalledPrefixes != 1 || out.Peers[1].InstalledPrefixes != 1 {
		t.Fatal("disjoint per-peer limit incorrectly global", out)
	}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "completed", Owned: []RuntimeBGPRouteTuple{second}, Target: []RuntimeBGPRouteTuple{second}}
	observed.Peers[0] = bgpengine.PeerStatus{Slot: 1, State: "idle"}
	out = projectBGPStatus(e, observed, [2]string{"down", "up"})
	if out == nil || len(out.Routes) != 1 || out.Routes[0].Prefix != secondPrefix.String() || out.Peers[0].InstalledPrefixes != 0 || out.Peers[1].InstalledPrefixes != 1 {
		t.Fatal("failed peer obscured surviving prefix", out)
	}
}
