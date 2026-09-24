package policy_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"reflect"
	"testing"
)

func ipsecPolicyFixture() (policy.Snapshot, uuid.UUID, uuid.UUID, uuid.UUID) {
	site, gw, other, hub, res := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := policy.Snapshot{Mode: policy.ModeEnforcing, ActiveHub: hub, SiteSubnets: []policy.SiteSubnet{{SiteID: site, CIDR: "10.10.0.0/16"}}, SiteNodes: []policy.SiteNode{{SiteID: site, NodeID: gw}, {SiteID: site, NodeID: other}}, Resources: []policy.Resource{{ID: res, CIDR: "10.10.0.5/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}, Rules: []policy.Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "10.20.0.9/32", DstKind: "resource", DstResourceID: res}}, IPsecNetworks: []policy.IPsecNetwork{{ConnectionID: uuid.New(), AssignedGatewayID: gw, LocalSiteID: site, RemotePrefixes: []string{"10.20.0.0/16"}}}}
	return s, gw, other, hub
}
func TestIPsecProjectionExactGatewayAndScope(t *testing.T) {
	s, gw, other, hub := ipsecPolicyFixture()
	out := policy.Compile(s)
	a := allowsFor(out, gw)
	if len(a) != 1 || a[0].SrcIP != "10.20.0.9/32" || a[0].DstCIDR != "10.10.0.5/32" || a[0].Protocol != policyspec.ProtoTCP || a[0].PortLow != 443 || a[0].PortHigh != 443 || a[0].RuleID != s.Rules[0].ID.String() {
		t.Fatalf("narrow grant lost: %+v", a)
	}
	for _, n := range []uuid.UUID{other, hub} {
		if len(allowsFor(out, n)) != 0 {
			t.Fatal("grant escaped assigned gateway")
		}
	}
	s.Rules[0].DstKind = "site"
	s.Rules[0].DstSiteID = s.IPsecNetworks[0].LocalSiteID
	out = policy.Compile(s)
	if !hasAllow(allowsFor(out, gw), "10.20.0.9/32", "10.10.0.0/16") || len(allowsFor(out, other)) != 0 || len(allowsFor(out, hub)) != 0 {
		t.Fatal("site target placement escaped")
	}
}
func TestIPsecProjectionRefusals(t *testing.T) {
	cases := map[string]func(*policy.Snapshot){
		"no identity": func(s *policy.Snapshot) { s.IPsecNetworks[0].ConnectionID = uuid.Nil },
		"duplicate identity": func(s *policy.Snapshot) {
			n := s.IPsecNetworks[0]
			n.RemotePrefixes = []string{"10.30.0.0/16"}
			s.IPsecNetworks = append(s.IPsecNetworks, n)
		},
		"overlapping connections": func(s *policy.Snapshot) {
			n := s.IPsecNetworks[0]
			n.ConnectionID = uuid.New()
			n.RemotePrefixes = []string{"10.20.0.0/24"}
			s.IPsecNetworks = append(s.IPsecNetworks, n)
		},
		"overlapping own prefixes": func(s *policy.Snapshot) {
			s.IPsecNetworks[0].RemotePrefixes = append(s.IPsecNetworks[0].RemotePrefixes, "10.20.0.0/24")
		},
		"noncanonical":        func(s *policy.Snapshot) { s.IPsecNetworks[0].RemotePrefixes = []string{"10.20.0.1/16"} },
		"invalid":             func(s *policy.Snapshot) { s.IPsecNetworks[0].RemotePrefixes = []string{"broken"} },
		"ipv6":                func(s *policy.Snapshot) { s.IPsecNetworks[0].RemotePrefixes = []string{"2001:db8::/64"} },
		"missing binding":     func(s *policy.Snapshot) { s.IPsecNetworks[0].AssignedGatewayID = uuid.New() },
		"wrong site binding":  func(s *policy.Snapshot) { s.IPsecNetworks[0].LocalSiteID = uuid.New() },
		"broader source":      func(s *policy.Snapshot) { s.Rules[0].SrcCIDR = "10.0.0.0/8" },
		"outside source":      func(s *policy.Snapshot) { s.Rules[0].SrcCIDR = "10.30.0.9/32" },
		"broader destination": func(s *policy.Snapshot) { s.Resources[0].CIDR = "10.0.0.0/8" },
		"outside destination": func(s *policy.Snapshot) { s.Resources[0].CIDR = "10.30.0.5/32" },
		"other site": func(s *policy.Snapshot) {
			s.Rules[0].DstKind = "site"
			s.Rules[0].DstSiteID = uuid.New()
			s.SiteSubnets = append(s.SiteSubnets, policy.SiteSubnet{SiteID: s.Rules[0].DstSiteID, CIDR: "10.30.0.0/16"})
		},
		"group destination":    func(s *policy.Snapshot) { s.Rules[0].DstKind = "group" },
		"FQDN destination":     func(s *policy.Snapshot) { s.Rules[0].DstKind = "fqdn_resource" },
		"K8s destination":      func(s *policy.Snapshot) { s.Rules[0].DstKind = "k8s_service" },
		"disabled":             func(s *policy.Snapshot) { s.Rules[0].Disabled = true },
		"withdrawn projection": func(s *policy.Snapshot) { s.IPsecNetworks = nil },
		"no rules":             func(s *policy.Snapshot) { s.Rules = nil },
		"mesh":                 func(s *policy.Snapshot) { s.Mode = policy.ModeOff },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, _, _ := ipsecPolicyFixture()
			change(&s)
			for _, c := range policy.Compile(s) {
				if len(c.Allow) != 0 {
					t.Fatalf("refusal emitted %+v", c.Allow)
				}
			}
		})
	}
}
func TestIPsecProjectionPreservesExistingAndDeterminism(t *testing.T) {
	s, gw, _, _ := ipsecPolicyFixture()
	s.IPsecNetworks[0].RemotePrefixes = append(s.IPsecNetworks[0].RemotePrefixes, "10.21.0.0/16")
	first := policy.Compile(s)
	s.IPsecNetworks[0].RemotePrefixes[0], s.IPsecNetworks[0].RemotePrefixes[1] = s.IPsecNetworks[0].RemotePrefixes[1], s.IPsecNetworks[0].RemotePrefixes[0]
	if !reflect.DeepEqual(first, policy.Compile(s)) {
		t.Fatal("order-dependent projection")
	}
	s.IPsecNetworks = nil
	if policyspec.CanonicalHash(first[gw]) == policyspec.CanonicalHash(policy.Compile(s)[gw]) {
		t.Fatal("withdrawal did not change policy hash")
	}
	s, _, _, _ = ipsecPolicyFixture()
	s.Rules[0].SrcCIDR = "10.10.0.9/32"
	s.Resources[0].CIDR = "10.20.0.5/32"
	with := policy.Compile(s)
	s.IPsecNetworks = nil
	without := policy.Compile(s)
	if !reflect.DeepEqual(with, without) {
		t.Fatal("local to remote behavior changed")
	}
	found := false
	for _, c := range with {
		found = found || hasAllow(c.Allow, "10.10.0.9/32", "10.20.0.5/32")
	}
	if !found {
		t.Fatal("existing local to remote resource grant disappeared")
	}
	s, _, _, _ = ipsecPolicyFixture()
	s.SiteSubnets = append(s.SiteSubnets, policy.SiteSubnet{SiteID: uuid.New(), CIDR: "10.20.0.0/16"})
	for _, c := range policy.Compile(s) {
		if len(c.Allow) != 0 {
			t.Fatal("ambiguous local and remote ownership emitted")
		}
	}
}

func TestIPsecProjectionDoesNotExpandOtherDestinationKinds(t *testing.T) {
	for _, kind := range []string{"group", "fqdn_resource", "k8s_service"} {
		t.Run(kind, func(t *testing.T) {
			s, gw, _, _ := ipsecPolicyFixture()
			n := s.IPsecNetworks[0]
			s.Rules[0].DstKind = kind
			switch kind {
			case "group":
				group, user := uuid.New(), uuid.New()
				s.Rules[0].DstGroupID = group
				s.Memberships = []policy.Membership{{GroupID: group, UserID: user}}
				s.Devices = []policy.Device{{ID: uuid.New(), UserID: user, NodeID: gw, AssignedIP: "10.199.0.9"}}
			case "fqdn_resource":
				id := uuid.New()
				s.FQDNResourcesLicensed = true
				s.FQDNResourcesEnabled = true
				s.FQDNResources = []policy.FQDNResource{{ID: id, FQDN: "api.example.com", Protocol: "tcp", PortLow: 443, PortHigh: 443, Active: activeFQDN(id, n.LocalSiteID, gw, uuid.New(), "10.10.0.5")}}
				s.FQDNRuleReferences = []policy.FQDNRuleReference{{PolicyRuleID: s.Rules[0].ID, FQDNResourceID: id}}
			case "k8s_service":
				id := uuid.New()
				s.Rules[0].DstK8sServiceID = id
				s.ExposedServices = []policy.ExposedService{{ID: id, VIP: "10.10.0.5", Protocol: "tcp", PortLow: 443, PortHigh: 443, SiteID: n.LocalSiteID, ConnectorNodeID: gw}}
			}
			for _, c := range policy.Compile(s) {
				if len(c.Allow) != 0 || len(c.FQDNGenerations) != 0 {
					t.Fatalf("remote source expanded unsupported destination: %+v", c)
				}
			}
			// Positive control: fixture really resolves through the existing local-Site path.
			s.Rules[0].SrcKind = "site"
			s.Rules[0].SrcSiteID = n.LocalSiteID
			found := false
			for _, c := range policy.Compile(s) {
				found = found || len(c.Allow) > 0
			}
			if !found {
				t.Fatal("unsupported destination fixture did not resolve local positive control")
			}
		})
	}
}
