package policy

import (
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"testing"
)

func TestStaticDNSRequiresGatewayDNSPermissionAndPreservesExplicitLANScope(t *testing.T) {
	declared := dnsProfileFixture()
	p := &declared.Profile
	p.IPsecPath = policyspec.DNSResolverIPsecPath{}
	p.Endpoints = []policyspec.DNSResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}
	p.StaticRecords = []policyspec.DNSStaticRecord{{Name: "app.private.test", Type: "A", Value: "10.20.0.80", TTL: 300}}
	p.LANListener = &policyspec.DNSLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: []string{"1.1.1.1"}}
	udp := policyspec.AllowEntry{SrcIP: "10.99.0.7", DstCIDR: "10.99.0.1/32", Protocol: "udp", PortLow: 53, PortHigh: 53}
	tcp := udp
	tcp.Protocol = "tcp"
	for _, allows := range [][]policyspec.AllowEntry{nil, {udp}, {tcp}, {{SrcIP: "10.99.0.7", DstCIDR: "10.20.0.80/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}} {
		got := DNSProfileForAllowedTraffic(declared, allows, "10.99.0.1")
		if len(got.AllowedSources) != 0 || len(got.LANListener.AllowedSources) != 1 || len(got.LANListener.DefaultUpstreams) != 1 {
			t.Fatal("LAN or application permission leaked into WG DNS", got)
		}
	}
	got := DNSProfileForAllowedTraffic(declared, []policyspec.AllowEntry{udp, tcp}, "10.99.0.1")
	if len(got.AllowedSources) != 1 || got.AllowedSources[0] != "10.99.0.7/32" {
		t.Fatal("explicit WG DNS permission missing", got)
	}
	if got := DNSProfileForAllowedTraffic(declared, []policyspec.AllowEntry{udp, tcp}); len(got.AllowedSources) != 0 {
		t.Fatal("unknown gateway address implicitly authorized static DNS")
	}
	raw, _ := json.Marshal(declared.Profile)
	decoded, err := DecodeIPsecDNSProfile(sqlc.ListIPsecDNSResolverProfilesRow{Profile: raw, LocalPrefixes: []byte("[]"), TransportAvailable: false})
	if err != nil || len(decoded.Profile.StaticRecords) != 1 || len(decoded.Profile.LANListener.DefaultUpstreams) != 1 {
		t.Fatal("static DNS depends on IPsec availability", err)
	}
}
