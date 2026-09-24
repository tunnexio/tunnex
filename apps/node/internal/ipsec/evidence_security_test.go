package ipsec

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// Equal lengths must not hide a repeated route replacing a required route.
func TestEvidenceSecurityRouteSet(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		e, s, n := evidenceFixture()
		second := e.Tunnels[0].Routes[0]
		second.Destination = netip.MustParsePrefix("10.21.0.0/16")
		e.Tunnels[0].Routes = append(e.Tunnels[0].Routes, second)
		s.Tunnels[0].Tunnel.Routes = []RouteTuple{second, e.Tunnels[0].Routes[0]}
		if duplicate {
			s.Tunnels[0].Tunnel.Routes[1] = second
		}
		assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), !duplicate, true)
	}
}

func TestEvidenceSecurityObservationOrderAndMultiplicity(t *testing.T) {
	e, s, n := evidenceFixture()
	s.Tunnels[0], s.Tunnels[1] = s.Tunnels[1], s.Tunnels[0]
	got := EvaluateEvidence(e, s, n, time.Second)
	assertCandidates(t, got, true, true)
	for i := range got {
		if got[i].TunnelID != e.Tunnels[i].TunnelID {
			t.Fatal("candidate identity follows untrusted observation order")
		}
	}
	s.Tunnels[1] = s.Tunnels[0]
	assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
}

func TestEvidenceSecurityRefusesOwnershipAliases(t *testing.T) {
	for _, field := range []string{"InterfaceName", "InterfaceIndex", "XFRMID"} {
		t.Run(field, func(t *testing.T) {
			e, s, n := evidenceFixture()
			reflect.ValueOf(&e.Tunnels[1].Ownership).Elem().FieldByName(field).Set(reflect.ValueOf(e.Tunnels[0].Ownership).FieldByName(field))
			// Mirror invalid ownership: equality must not qualify one object twice.
			if field == "InterfaceIndex" {
				e.Tunnels[1].Routes[0].OutputInterface = e.Tunnels[1].Ownership.InterfaceIndex
			}
			s.Tunnels[1].Tunnel = e.Tunnels[1]
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
}

func TestEvidenceSecurityReusedChildSAIdentity(t *testing.T) {
	e, s, n := evidenceFixture()
	s.Tunnels[1].ChildSAs[0].ID = s.Tunnels[0].ChildSAs[0].ID
	assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
}

func TestEvidenceSecurityRefusalCannotBeOverriddenByHealthyTunnel(t *testing.T) {
	for _, field := range []string{"ForwardedTrafficRefused", "HostTrafficRefused", "EstablishedTrafficRefused"} {
		t.Run(field, func(t *testing.T) {
			e, s, n := evidenceFixture()
			s.Tunnels = s.Tunnels[1:]
			reflect.ValueOf(&s).Elem().FieldByName(field).SetBool(false)
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
}

func TestEvidenceSecurityAllInputSlicesRemainUntouched(t *testing.T) {
	e, s, n := evidenceFixture()
	for i := range e.Tunnels {
		r := e.Tunnels[i].Routes[0]
		r.Destination = netip.MustParsePrefix("10.1.0.0/16")
		e.Tunnels[i].Routes = append(e.Tunnels[i].Routes, r)
		s.Tunnels[i].Tunnel.Routes = append([]RouteTuple{r}, s.Tunnels[i].Tunnel.Routes...)
	}
	beforeE := e
	for i := range beforeE.Tunnels {
		beforeE.Tunnels[i].Routes = append([]RouteTuple(nil), e.Tunnels[i].Routes...)
	}
	beforeS := s
	beforeS.Tunnels = append([]TunnelObservation(nil), s.Tunnels...)
	for i := range beforeS.Tunnels {
		beforeS.Tunnels[i].Tunnel.Routes = append([]RouteTuple(nil), s.Tunnels[i].Tunnel.Routes...)
		beforeS.Tunnels[i].ChildSAs = append([]ChildSA(nil), s.Tunnels[i].ChildSAs...)
	}
	assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), true, true)
	if !reflect.DeepEqual(e, beforeE) || !reflect.DeepEqual(s, beforeS) {
		t.Fatal("evaluator mutated caller-owned slices")
	}
}

func TestEvidenceSecurityGlobalAssignmentCannotBeBorrowed(t *testing.T) {
	for _, field := range []string{"OrgID", "GatewayID", "ConnectionID", "DesiredRevision", "ConfigurationRevision", "PolicyRevision"} {
		t.Run(field, func(t *testing.T) {
			e, s, n := evidenceFixture()
			binding := reflect.ValueOf(&s.Binding).Elem()
			f := binding.FieldByName(field)
			f.Set(reflect.Zero(f.Type()))
			// Tunnel-local copies remain valid; global safety evidence from another
			// assignment still cannot qualify either candidate.
			assertCandidates(t, EvaluateEvidence(e, s, n, time.Second), false, false)
		})
	}
}
