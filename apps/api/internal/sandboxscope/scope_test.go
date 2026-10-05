package sandboxscope

import "testing"

func TestScopeIntersectionAndAdmission(t *testing.T) {
	all := Scope{CIDR: "10.0.0.0/8", Protocol: "any"}
	a := Scope{CIDR: "10.1.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}
	b := Scope{CIDR: "10.2.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}
	if AdmitScope([]Scope{a}, []Scope{all}, []Scope{a}) != nil {
		t.Fatal("covered scope refused")
	}
	if AdmitScope([]Scope{b}, []Scope{all}, []Scope{a}) != ErrScopeExceeded {
		t.Fatal("template widening accepted")
	}
	if AdmitScope([]Scope{all}, []Scope{a}, []Scope{all}) != ErrScopeExceeded {
		t.Fatal("entitlement widening accepted")
	}
	got := EffectiveScope([]Scope{all}, []Scope{a, b}, []Scope{a})
	if len(got) != 1 || got[0] != a {
		t.Fatalf("intersection widened: %+v", got)
	}
	if len(EffectiveScope([]Scope{a}, nil, []Scope{all})) != 0 {
		t.Fatal("revocation retained access")
	}
	udp := a
	udp.Protocol = "udp"
	if _, ok := Intersect(a, udp); ok {
		t.Fatal("protocol mismatch matched")
	}
	broader := a
	broader.PortLow = 20
	broader.PortHigh = 30
	if got, ok := Intersect(a, broader); !ok || got != a {
		t.Fatal("port intersection wrong")
	}
	for _, s := range []Scope{{CIDR: "::/0", Protocol: "any"}, {CIDR: "10.1.1.1/16", Protocol: "any"}, {CIDR: "10.0.0.0/8", Protocol: "icmp"}, {CIDR: "10.0.0.0/8", Protocol: "any", PortLow: 22, PortHigh: 22}} {
		if s.Validate() == nil || len(EffectiveScope([]Scope{s}, []Scope{all}, []Scope{all})) != 0 {
			t.Fatal("invalid scope accepted")
		}
	}
}
