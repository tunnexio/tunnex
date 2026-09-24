package ipsec

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func evidenceFixture() (ExpectedAssignment, Snapshot, time.Time) {
	now := time.Date(2026, 9, 24, 1, 2, 3, 0, time.UTC)
	b := Binding{OrgID: uuid.New(), GatewayID: uuid.New(), ConnectionID: uuid.New(), DesiredRevision: 3, ConfigurationRevision: 2, PolicyRevision: 4}
	expected := ExpectedAssignment{Binding: b}
	observed := Snapshot{Binding: b, CollectionID: "collection-1", CollectedAt: now.Add(-time.Second), Complete: true, Consistent: true, DaemonIdentityConfirmed: true, OwnershipInventoryComplete: true, OwnershipCollisionFree: true, ForwardedTrafficRefused: true, HostTrafficRefused: true, EstablishedTrafficRefused: true}
	for i := range expected.Tunnels {
		tunnel := TunnelAssignment{TunnelID: uuid.New(), Slot: uint8(i + 1), SecretRevision: 5, Ownership: Ownership{Namespace: "owned", InterfaceName: []string{"ipsec-a", "ipsec-b"}[i], InterfaceIndex: 10 + i, XFRMID: uint32(20 + i)}, Routes: []RouteTuple{{Destination: netip.MustParsePrefix("10.20.0.0/16"), Table: 200, Protocol: 99, Metric: 0, OutputInterface: 10 + i}}}
		expected.Tunnels[i] = tunnel
		copyTunnel := tunnel
		copyTunnel.Routes = append([]RouteTuple(nil), tunnel.Routes...)
		observed.Tunnels = append(observed.Tunnels, TunnelObservation{Binding: b, Tunnel: copyTunnel, CollectionID: observed.CollectionID, InterfaceOwnershipConfirmed: true, RouteOwnershipConfirmed: true, ChildSAInventoryComplete: true, ChildSAs: []ChildSA{{ID: []string{"sa-a", "sa-b"}[i], TunnelID: tunnel.TunnelID, DesiredRevision: 3, ConfigurationRevision: 2, SecretRevision: 5, Established: true}}, PolicyEnforced: true, EnforcedPolicyRevision: 4, AntiSpoofEnforced: true, UnderlaySeparated: true})
	}
	return expected, observed, now
}
func assertCandidates(t *testing.T, got [2]TunnelEvidence, wantA, wantB bool) {
	t.Helper()
	if got[0].Candidate != wantA || got[1].Candidate != wantB {
		t.Fatalf("unexpected candidates: %+v", got)
	}
	for _, v := range got {
		if v.Candidate != (v.Reason == ReasonCandidate) {
			t.Fatalf("contradictory reason: %+v", v)
		}
	}
}
func TestEvidenceHealthyAndImmutable(t *testing.T) {
	e, s, now := evidenceFixture()
	beforeE := e
	beforeS := s
	beforeE.Tunnels[0].Routes = append([]RouteTuple(nil), e.Tunnels[0].Routes...)
	beforeS.Tunnels = append([]TunnelObservation(nil), s.Tunnels...)
	for i := range beforeS.Tunnels {
		beforeS.Tunnels[i].Tunnel.Routes = append([]RouteTuple(nil), s.Tunnels[i].Tunnel.Routes...)
		beforeS.Tunnels[i].ChildSAs = append([]ChildSA(nil), s.Tunnels[i].ChildSAs...)
	}
	got := EvaluateEvidence(e, s, now, time.Second)
	assertCandidates(t, got, true, true)
	if !reflect.DeepEqual(e, beforeE) || !reflect.DeepEqual(s, beforeS) {
		t.Fatal("mutated caller input")
	}
	for i := range got {
		if got[i].TunnelID != e.Tunnels[i].TunnelID || got[i].Slot != uint8(i+1) {
			t.Fatal("lost identity")
		}
	}
}
func TestEvidenceRefusesGlobalFlags(t *testing.T) {
	for _, field := range []string{"Complete", "Consistent", "DaemonIdentityConfirmed", "OwnershipInventoryComplete", "OwnershipCollisionFree", "ForwardedTrafficRefused", "HostTrafficRefused", "EstablishedTrafficRefused"} {
		t.Run(field, func(t *testing.T) {
			e, s, n := evidenceFixture()
			reflect.ValueOf(&s).Elem().FieldByName(field).SetBool(false)
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
}
func TestEvidenceFreshness(t *testing.T) {
	for _, tt := range []struct {
		name              string
		age, budget       time.Duration
		zeroTime, zeroNow bool
		want              bool
	}{{"boundary", time.Second, time.Second, false, false, true}, {"stale", time.Second + 1, time.Second, false, false, false}, {"future", -1, time.Second, false, false, false}, {"zero budget", 0, 0, false, false, false}, {"negative budget", 0, -1, false, false, false}, {"missing time", 0, time.Second, true, false, false}, {"missing clock", 0, time.Second, false, true, false}} {
		t.Run(tt.name, func(t *testing.T) {
			e, s, n := evidenceFixture()
			s.CollectedAt = n.Add(-tt.age)
			if tt.zeroTime {
				s.CollectedAt = time.Time{}
			}
			if tt.zeroNow {
				n = time.Time{}
			}
			assertCandidates(t, EvaluateEvidence(e, s, n, tt.budget), tt.want, tt.want)
		})
	}
}
func TestEvidenceMalformedAssignment(t *testing.T) {
	cases := map[string]func(*ExpectedAssignment){"org": func(e *ExpectedAssignment) { e.Binding.OrgID = uuid.Nil }, "gateway": func(e *ExpectedAssignment) { e.Binding.GatewayID = uuid.Nil }, "connection": func(e *ExpectedAssignment) { e.Binding.ConnectionID = uuid.Nil }, "desired": func(e *ExpectedAssignment) { e.Binding.DesiredRevision = 0 }, "configuration": func(e *ExpectedAssignment) { e.Binding.ConfigurationRevision = -1 }, "policy": func(e *ExpectedAssignment) { e.Binding.PolicyRevision = 0 }, "tunnel": func(e *ExpectedAssignment) { e.Tunnels[0].TunnelID = uuid.Nil }, "duplicate tunnel": func(e *ExpectedAssignment) { e.Tunnels[1].TunnelID = e.Tunnels[0].TunnelID }, "slot": func(e *ExpectedAssignment) { e.Tunnels[0].Slot = 2 }, "secret": func(e *ExpectedAssignment) { e.Tunnels[0].SecretRevision = 0 }, "namespace": func(e *ExpectedAssignment) { e.Tunnels[0].Ownership.Namespace = "" }, "interface": func(e *ExpectedAssignment) { e.Tunnels[0].Ownership.InterfaceName = "" }, "index": func(e *ExpectedAssignment) { e.Tunnels[0].Ownership.InterfaceIndex = 0 }, "xfrm": func(e *ExpectedAssignment) { e.Tunnels[0].Ownership.XFRMID = 0 }, "duplicate index": func(e *ExpectedAssignment) {
		e.Tunnels[1].Ownership.InterfaceIndex = e.Tunnels[0].Ownership.InterfaceIndex
	}, "duplicate name": func(e *ExpectedAssignment) {
		e.Tunnels[1].Ownership.InterfaceName = e.Tunnels[0].Ownership.InterfaceName
	}, "duplicate xfrm": func(e *ExpectedAssignment) { e.Tunnels[1].Ownership.XFRMID = e.Tunnels[0].Ownership.XFRMID }, "empty routes": func(e *ExpectedAssignment) { e.Tunnels[0].Routes = nil }, "duplicate routes": func(e *ExpectedAssignment) { e.Tunnels[0].Routes = append(e.Tunnels[0].Routes, e.Tunnels[0].Routes[0]) }, "noncanonical": func(e *ExpectedAssignment) {
		e.Tunnels[0].Routes[0].Destination = netip.MustParsePrefix("10.20.1.0/16")
	}, "ipv6": func(e *ExpectedAssignment) {
		e.Tunnels[0].Routes[0].Destination = netip.MustParsePrefix("2001:db8::/64")
	}, "table": func(e *ExpectedAssignment) { e.Tunnels[0].Routes[0].Table = 0 }, "protocol": func(e *ExpectedAssignment) { e.Tunnels[0].Routes[0].Protocol = 0 }, "output": func(e *ExpectedAssignment) { e.Tunnels[0].Routes[0].OutputInterface = 999 }, "ipv6 gateway": func(e *ExpectedAssignment) { e.Tunnels[0].Routes[0].Gateway = netip.MustParseAddr("::1") }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e, s, n := evidenceFixture()
			change(&e)
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
	assertCandidates(t, EvaluateEvidence(ExpectedAssignment{}, Snapshot{}, time.Time{}, 0), false, false)
}
func TestEvidenceObservationInventory(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Snapshot)
		a, b   bool
	}{{"missing", func(s *Snapshot) { s.Tunnels = s.Tunnels[1:] }, false, true}, {"duplicate", func(s *Snapshot) { s.Tunnels = append(s.Tunnels, s.Tunnels[0]) }, false, false}, {"extra", func(s *Snapshot) { v := s.Tunnels[0]; v.Tunnel.TunnelID = uuid.New(); s.Tunnels = append(s.Tunnels, v) }, false, false}, {"unknown", func(s *Snapshot) { s.Tunnels[0].Tunnel.TunnelID = uuid.Nil }, false, false}, {"collection missing", func(s *Snapshot) { s.CollectionID = "" }, false, false}} {
		t.Run(tt.name, func(t *testing.T) {
			e, s, n := evidenceFixture()
			tt.change(&s)
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), tt.a, tt.b)
		})
	}
}
func TestEvidenceTunnelSpecificRefusals(t *testing.T) {
	cases := map[string]func(*TunnelObservation){"org": func(o *TunnelObservation) { o.Binding.OrgID = uuid.New() }, "gateway": func(o *TunnelObservation) { o.Binding.GatewayID = uuid.New() }, "connection": func(o *TunnelObservation) { o.Binding.ConnectionID = uuid.New() }, "desired": func(o *TunnelObservation) { o.Binding.DesiredRevision++ }, "configuration": func(o *TunnelObservation) { o.Binding.ConfigurationRevision++ }, "policy binding": func(o *TunnelObservation) { o.Binding.PolicyRevision++ }, "slot": func(o *TunnelObservation) { o.Tunnel.Slot = 2 }, "secret": func(o *TunnelObservation) { o.Tunnel.SecretRevision++ }, "namespace": func(o *TunnelObservation) { o.Tunnel.Ownership.Namespace = "other" }, "name": func(o *TunnelObservation) { o.Tunnel.Ownership.InterfaceName = "other" }, "index": func(o *TunnelObservation) { o.Tunnel.Ownership.InterfaceIndex += 100 }, "xfrm": func(o *TunnelObservation) { o.Tunnel.Ownership.XFRMID += 100 }, "collection": func(o *TunnelObservation) { o.CollectionID = "other" }, "route destination": func(o *TunnelObservation) { o.Tunnel.Routes[0].Destination = netip.MustParsePrefix("10.21.0.0/16") }, "route table": func(o *TunnelObservation) { o.Tunnel.Routes[0].Table++ }, "route protocol": func(o *TunnelObservation) { o.Tunnel.Routes[0].Protocol++ }, "route metric": func(o *TunnelObservation) { o.Tunnel.Routes[0].Metric++ }, "route interface": func(o *TunnelObservation) { o.Tunnel.Routes[0].OutputInterface++ }, "route gateway": func(o *TunnelObservation) { o.Tunnel.Routes[0].Gateway = netip.MustParseAddr("10.0.0.1") }, "extra route": func(o *TunnelObservation) { o.Tunnel.Routes = append(o.Tunnel.Routes, o.Tunnel.Routes[0]) }, "missing route": func(o *TunnelObservation) { o.Tunnel.Routes = nil }, "missing SA": func(o *TunnelObservation) { o.ChildSAs = nil }, "rekey SA": func(o *TunnelObservation) { o.ChildSAs = append(o.ChildSAs, o.ChildSAs[0]) }, "SA id": func(o *TunnelObservation) { o.ChildSAs[0].ID = "" }, "SA tunnel": func(o *TunnelObservation) { o.ChildSAs[0].TunnelID = uuid.New() }, "SA desired": func(o *TunnelObservation) { o.ChildSAs[0].DesiredRevision++ }, "SA config": func(o *TunnelObservation) { o.ChildSAs[0].ConfigurationRevision++ }, "SA secret": func(o *TunnelObservation) { o.ChildSAs[0].SecretRevision++ }, "SA down": func(o *TunnelObservation) { o.ChildSAs[0].Established = false }, "enforced policy": func(o *TunnelObservation) { o.EnforcedPolicyRevision++ }}
	for _, field := range []string{"InterfaceOwnershipConfirmed", "RouteOwnershipConfirmed", "ChildSAInventoryComplete", "PolicyEnforced", "AntiSpoofEnforced", "UnderlaySeparated"} {
		cases[field] = func(o *TunnelObservation) { reflect.ValueOf(o).Elem().FieldByName(field).SetBool(false) }
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e, s, n := evidenceFixture()
			change(&s.Tunnels[0])
			global := name == "org" || name == "gateway" || name == "connection" || name == "collection"
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, !global)
		})
	}
}

func TestEvidenceGlobalBinding(t *testing.T) {
	for _, field := range []string{"OrgID", "GatewayID", "ConnectionID", "DesiredRevision", "ConfigurationRevision", "PolicyRevision"} {
		t.Run(field, func(t *testing.T) {
			e, s, n := evidenceFixture()
			v := reflect.ValueOf(&s.Binding).Elem().FieldByName(field)
			v.Set(reflect.Zero(v.Type()))
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
}
func TestEvidenceObservedObjectAliases(t *testing.T) {
	for _, field := range []string{"InterfaceName", "InterfaceIndex", "XFRMID", "ChildSA"} {
		t.Run(field, func(t *testing.T) {
			e, s, n := evidenceFixture()
			if field == "ChildSA" {
				s.Tunnels[1].ChildSAs[0].ID = s.Tunnels[0].ChildSAs[0].ID
			} else {
				v := reflect.ValueOf(&s.Tunnels[1].Tunnel.Ownership).Elem().FieldByName(field)
				v.Set(reflect.ValueOf(s.Tunnels[0].Tunnel.Ownership).FieldByName(field))
			}
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
}

func TestEvidenceFreshnessDoesNotSaturate(t *testing.T) {
	e, s, n := evidenceFixture()
	s.CollectedAt = time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
	assertCandidates(t, EvaluateEvidence(e, s, n, time.Duration(1<<63-1)), false, false)
}
func TestEvidenceInterfaceNamesRefuseDotEntries(t *testing.T) {
	for _, name := range []string{".", ".."} {
		e, s, n := evidenceFixture()
		e.Tunnels[0].Ownership.InterfaceName = name
		assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
	}
}
