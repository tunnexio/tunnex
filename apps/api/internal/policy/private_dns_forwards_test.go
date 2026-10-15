package policy

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"testing"
)

func TestPrivateDNSForwardsNeedExplicitGatewayPermission(t *testing.T) {
	s, in := desktopPolicyFixture()
	s.Resources[0].CIDR = "10.99.0.1/32"
	s.Resources[0].PortLow, s.Resources[0].PortHigh = 53, 53
	s.Resources[0].Protocol = "any"
	device := s.Devices[0]
	profile := dnsProfileFixture()
	static := profile
	static.Profile.ProfileID = uuid.NewString()
	static.Profile.ZoneSuffixes = []string{"office.test"}
	static.Profile.Endpoints = nil
	static.Profile.IPsecPath = policyspec.DNSResolverIPsecPath{}
	static.Profile.StaticRecords = []policyspec.DNSStaticRecord{{Name: "app.office.test", Type: "A", Value: "10.180.1.8", TTL: 300}}
	project := func(s Snapshot) []policyspec.DNSForward {
		return devicePrivateDNSForwardsFromSnapshot(s, device.ID, in.NodeID, "10.99.0.1", []IPsecDNSProfile{profile, static})
	}
	// No FQDN licence, FQDN resource, or application parent is present.
	if got := project(s); len(got) != 2 || got[0].ResolverIP != "10.99.0.1" || got[1].ResolverIP != "10.99.0.1" {
		t.Fatal("explicit private DNS missing", got)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"UDP only":                 func(s *Snapshot) { s.Resources[0].Protocol = "udp" },
		"TCP only":                 func(s *Snapshot) { s.Resources[0].Protocol = "tcp" },
		"endpoint permission only": func(s *Snapshot) { s.Resources[0].CIDR = "10.20.0.0/24" },
		"CIDR source":              func(s *Snapshot) { s.Rules[0].SrcKind = "cidr"; s.Rules[0].SrcCIDR = "10.99.0.0/24" },
		"membership withdrawn":     func(s *Snapshot) { s.Memberships = nil },
		"wrong gateway":            func(s *Snapshot) { s.Devices[0].NodeID = uuid.New() },
		"off":                      func(s *Snapshot) { s.Mode = ModeOff },
		"device absent":            func(s *Snapshot) { s.Devices = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := s
			bad.Resources = append([]Resource(nil), s.Resources...)
			bad.Rules = append([]Rule(nil), s.Rules...)
			bad.Devices = append([]Device(nil), s.Devices...)
			mutate(&bad)
			if got := project(bad); len(got) != 0 {
				t.Fatal("unqualified forwards", got)
			}
		})
	}
	// The gateway policy must allow the same explicitly authorized proxy client
	// without turning its DNS permission into an upstream application grant.
	allows := Compile(s)[in.NodeID].Allow
	got := DNSProfileForAllowedTraffic(profile, allows, "10.99.0.1")
	if len(got.AllowedSources) != 1 || got.AllowedSources[0] != "10.99.0.7/32" {
		t.Fatal("IPsec proxy differs from desktop DNS projection", got)
	}
}
