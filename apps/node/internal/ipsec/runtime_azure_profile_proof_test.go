package ipsec

import (
	"fmt"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"reflect"
	"testing"
)

type azureProfileProofBinding struct {
	azureMaxProofBinding
	ProfileID string `json:"profile_id"`
}

func azureProfileProofEntryHistory(p runtimeJournalPayload, b azureProfileProofBinding, ns string, historical map[uuid.UUID]bool) (RuntimeJournalEntry, error) {
	bad := func() (RuntimeJournalEntry, error) { return RuntimeJournalEntry{}, fmt.Errorf("journal_scope_refused") }
	if !validJournalPayload(p) || p.OwnerID != b.GatewayID || b.OrgID == uuid.Nil || b.SiteID == uuid.Nil || b.ConnectionID == uuid.Nil || b.DesiredRevision < 1 || b.ConfigurationRevision < 1 || (b.Mode != "baseline" && b.Mode != "absence") || len(p.Entries) == 0 || len(p.Guards) != 1 || p.Guards[0].Namespace != ns {
		return bad()
	}
	var selected RuntimeJournalEntry
	active := 0
	latest := int64(0)
	for _, e := range p.Entries {
		// Site mapping is directly recorded, not filled from a normal API response.
		if e.SiteID != b.SiteID || (e.Allocation.Namespace != ns && !historical[e.DeliveryID]) || e.Engines[0].Binding.OrgID != b.OrgID || e.Engines[0].Binding.GatewayID != b.GatewayID {
			return bad()
		}
		if e.Phase != RuntimeRetainedRefusal {
			active++
			if b.Mode == "absence" || e.Phase != RuntimeApplied {
				return bad()
			}
			selected = e
		}
		if e.Phase == RuntimeRetainedRefusal {
			if e.BGPRoutes != nil && (e.BGPRoutes.Stage != "completed" || !e.BGPRoutes.Withdrawal || len(e.BGPRoutes.Owned) != 0 || len(e.BGPRoutes.Target) != 0) {
				return bad()
			}
			duties := append([]bgpengine.ProcessIdentity(nil), e.BGPProcessRetired...)
			if e.BGPProcess != nil {
				duties = append(duties, *e.BGPProcess)
			}
			for _, d := range duties {
				if d.Stage != "cleaned" {
					return bad()
				}
			}
			if b.Mode == "absence" && e.Allocation.ConnectionID == b.ConnectionID && e.Engines[0].Binding.ConfigurationRevision == b.ConfigurationRevision && e.Engines[0].Binding.DesiredRevision > latest {
				selected = e
				latest = e.Engines[0].Binding.DesiredRevision
			}
		}
	}
	if (b.Mode == "baseline" || b.Mode == "post-limit") && active != 1 || b.Mode == "absence" && (active != 0 || latest == 0) {
		return bad()
	}
	if selected.Allocation.ConnectionID != b.ConnectionID || selected.SiteID != b.SiteID || selected.Allocation.ProfileID != b.ProfileID || !IsAzureRuntimeProfile(b.ProfileID) || !validClassicJournal(selected) || !validJournalBGP(selected) {
		return bad()
	}
	// A genuine Cleanup may durably record authenticated lineage never admitted
	// locally. It can prove only fresh absence, never baseline or restage rights.
	if selected.AbsenceOnly && (b.Mode != "absence" || selected.Phase != RuntimeRetainedRefusal || selected.Allocation.Namespace != ns || selected.Observed != ([2]Ownership{}) || selected.BGPRoutes != nil || selected.BGPProcess != nil || len(selected.BGPProcessRetired) != 0 || selected.BGPProcessHistory != nil || selected.Restoration != nil || selected.ResetCleanup != nil || selected.Recovery != nil) {
		return bad()
	}
	if !sameEnginePrefixes(selected.Engines[0].LocalPrefixes, []netip.Prefix{netip.MustParsePrefix("10.233.10.0/24")}) || !sameEnginePrefixes(selected.Engines[0].RemotePrefixes, []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16")}) {
		return bad()
	}
	if selected.BGP != nil {
		if selected.BGP.MaximumPrefixes != 8 || b.MaximumPrefixes != 8 {
			return bad()
		}
	} else if b.MaximumPrefixes != 0 {
		return bad()
	}
	actualRevision := selected.Engines[0].Binding.DesiredRevision
	if b.Mode == "absence" {
		actualRevision = selected.CleanupDesiredRevision
	}
	if actualRevision != b.DesiredRevision || selected.Engines[0].Binding.ConfigurationRevision != b.ConfigurationRevision {
		return bad()
	}
	return selected, nil
}

func azureProfileProofBaseline(e RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory, status bgpengine.Status, routes []bgpengine.LearnedRoute) error {
	bad := func() error { return fmt.Errorf("profile_baseline_refused") }
	n := e.Allocation.activeTunnelCount()
	if !IsAzureRuntimeProfile(e.Allocation.ProfileID) || !validClassicJournal(e) || !validJournalBGP(e) || k.Namespace != e.Allocation.Namespace || x.Namespace != e.Allocation.Namespace || len(d.SAs) != n || len(d.Connections) != n || len(d.SharedKeys) != n || len(x.States) != 2*n || len(x.Policies) != 3*n {
		return bad()
	}
	// This single-active-owner oracle refuses even inactive foreign XFRM links.
	ownedLinks := map[int]Ownership{}
	for _, o := range e.Observed[:n] {
		ownedLinks[o.InterfaceIndex] = o
	}
	xfrmLinks := 0
	for _, link := range k.Links {
		if link.XFRMID == 0 {
			continue
		}
		xfrmLinks++
		o, ok := ownedLinks[link.Index]
		if !ok || o.InterfaceName != link.Name || o.XFRMID != link.XFRMID {
			return bad()
		}
	}
	if xfrmLinks != n {
		return bad()
	}
	slots := azureNativeSlotDiagnostic(e, d, k, x)
	if len(slots) != n {
		return bad()
	}
	expected := map[RouteTuple]bool{}
	for i, s := range slots {
		if s.Status != "up" || s.Category != "native_observation" || s.IKEMatches != 1 || s.ChildStates["INSTALLED"] != 1 || len(s.ChildStates) != 1 || s.SADMatches != 2 || !reflect.DeepEqual(s.SPDDirections, map[string]int{"in": 1, "out": 1, "fwd": 1}) || !s.StoredConnection || !s.StoredSharedKey {
			return bad()
		}
		tunnel := e.Allocation.Tunnels[i]
		if e.BGP != nil {
			if status.Peers[i].Slot != i+1 || status.Peers[i].State != "established" || status.Peers[i].AcceptedPrefixes != 1 {
				return bad()
			}
			expected[RouteTuple{Destination: netip.PrefixFrom(tunnel.BGP.Peer, 32), Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: e.Observed[i].InterfaceIndex}] = true
		} else if tunnel.Selected {
			for _, p := range tunnel.RemotePrefixes {
				expected[RouteTuple{Destination: p, Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: e.Observed[i].InterfaceIndex}] = true
			}
		}
	}
	if e.BGP != nil {
		if e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || e.BGPRoutes.Withdrawal || !reflect.DeepEqual(e.BGPRoutes.Owned, e.BGPRoutes.Target) || len(e.BGPRoutes.Owned) != 1 || len(routes) != 1 || routes[0].Prefix != netip.MustParsePrefix("10.231.0.0/16") {
			return bad()
		}
		r := e.BGPRoutes.Owned[0]
		if r.Prefix != routes[0].Prefix || int(r.Slot) != routes[0].Slot || r.Slot < 1 || int(r.Slot) > n || r.InterfaceIndex != e.Observed[r.Slot-1].InterfaceIndex || r.Table != 254 || r.Protocol != 242 || r.Metric != 50000+uint32(r.Slot) {
			return bad()
		}
		expected[RouteTuple{Destination: r.Prefix, Table: r.Table, Protocol: uint8(r.Protocol), Metric: r.Metric, OutputInterface: r.InterfaceIndex}] = true
	} else if e.BGPRoutes != nil || e.BGPProcess != nil || len(routes) != 0 || status != (bgpengine.Status{}) {
		return bad()
	}
	for _, r := range k.Routes {
		if r.Protocol != 242 {
			continue
		}
		if r.Kind != 1 || !expected[r.RouteTuple] {
			return bad()
		}
		delete(expected, r.RouteTuple)
	}
	if len(expected) != 0 {
		return bad()
	}
	return nil
}

func TestAzureProfileProofFourCardinalitiesAndForeignSurvivors(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			e, d, k, x := azureSchedulerBGPProofFixture(t, profile)
			e.Phase = RuntimeApplied
			prefix := netip.MustParsePrefix("10.231.0.0/16")
			for i := 0; i < e.Allocation.activeTunnelCount(); i++ {
				e.Engines[i].RemotePrefixes = []netip.Prefix{prefix}
				e.Allocation.Tunnels[i].RemotePrefixes = []netip.Prefix{prefix}
				d.SAs[i].Children[0].State = "INSTALLED"
			}
			k.Routes = nil
			var status bgpengine.Status
			var learned []bgpengine.LearnedRoute
			if e.BGP != nil {
				for i := 0; i < e.Allocation.activeTunnelCount(); i++ {
					status.Peers[i].Slot = i + 1
					status.Peers[i].State = "established"
					status.Peers[i].AcceptedPrefixes = 1
					k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: netip.PrefixFrom(e.Allocation.Tunnels[i].BGP.Peer, 32), Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: e.Observed[i].InterfaceIndex}})
				}
				r := RuntimeBGPRouteTuple{Prefix: prefix, Slot: 1, InterfaceIndex: 10, Table: 254, Protocol: 242, Metric: 50001}
				e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{r}, Target: []RuntimeBGPRouteTuple{r}}
				learned = []bgpengine.LearnedRoute{{Prefix: prefix, Slot: 1}}
				k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: prefix, Table: 254, Protocol: 242, Metric: 50001, OutputInterface: 10}})
			} else {
				e.BGPRoutes = nil
				for i, tunnel := range e.Allocation.Tunnels[:e.Allocation.activeTunnelCount()] {
					if tunnel.Selected {
						k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: prefix, Table: 254, Protocol: 242, Metric: 50001 + uint32(i), OutputInterface: e.Observed[i].InterfaceIndex}})
					}
				}
			}
			if err := azureProfileProofBaseline(e, d, k, x, status, learned); err != nil {
				t.Fatal("actual cardinality fixture refused", err)
			}
			foreign := d
			foreign.SAs = append(append([]DaemonIKE(nil), d.SAs...), d.SAs[0])
			if azureProfileProofBaseline(e, foreign, k, x, status, learned) == nil {
				t.Fatal("competing IKE accepted")
			}
			foreignLinks := k
			foreignLinks.Links = append(append([]KernelLink(nil), k.Links...), KernelLink{Name: "renamed-retired", Index: 99, XFRMID: 0x12345678, Up: false})
			if azureProfileProofBaseline(e, d, foreignLinks, x, status, learned) == nil {
				t.Fatal("inactive retired XFRM survivor accepted")
			}
			extra := k
			extra.Routes = append(append([]KernelRoute(nil), k.Routes...), KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: netip.MustParsePrefix("10.235.77.0/24"), Protocol: 242}})
			if azureProfileProofBaseline(e, d, extra, x, status, learned) == nil {
				t.Fatal("removed-prefix route survivor accepted")
			}
		})
	}
}
