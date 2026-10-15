package main

import (
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestDNSResolverAdapterPreservesExplicitLANDefaults(t *testing.T) {
	policy := &nodepolicy.Compiled{Version: 13, DNSResolverProfiles: []nodepolicy.DNSResolverProfile{{LANListener: &nodepolicy.DNSLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: []string{"1.1.1.1", "8.8.8.8"}}}}}
	got := dnsResolverProfilesFrom(policy)
	if len(got) != 1 || got[0].LANListener == nil || len(got[0].LANListener.DefaultUpstreams) != 2 || got[0].LANListener.DefaultUpstreams[1] != "8.8.8.8" || len(got[0].AllowedSources) != 0 {
		t.Fatal("LAN defaults lost or expanded WireGuard entitlement", got)
	}
}

func TestDNSResolverAdapterPreservesStaticTargetAuthority(t *testing.T) {
	policy := &nodepolicy.Compiled{Version: 14, DNSResolverProfiles: []nodepolicy.DNSResolverProfile{{
		ContextConfigID: "config", ContextConfigVersion: 4, ProfileID: "profile", ZoneSuffixes: []string{"office.test"}, AllowedSources: []string{"10.99.0.7/32"},
		StaticRecords: []nodepolicy.DNSStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "internal.app.elb.amazonaws.com", TTL: 300}},
		Endpoints:     []nodepolicy.DNSResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}, {Address: "8.8.8.8", Port: 53, Transport: "tcp"}},
	}}}
	got := dnsResolverProfilesFrom(policy)
	if len(got) != 1 || got[0].Config.IPsecPath != nil || got[0].LANListener != nil || len(got[0].StaticRecords) != 1 || len(got[0].Config.Endpoints) != 2 || got[0].Config.Endpoints[1].Transport != "tcp" || len(got[0].AllowedSources) != 1 || got[0].AllowedSources[0] != "10.99.0.7/32" {
		t.Fatalf("static target authority lost or expanded: %+v", got)
	}
}
