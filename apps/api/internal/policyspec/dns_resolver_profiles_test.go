package policyspec

import (
	"testing"
)

func TestDNSResolverProfilesAreVersionedAndHashSignificant(t *testing.T) {
	c := Compiled{Version: 1, NodeID: "gateway", Mode: "enforcing"}
	base := CanonicalHash(c)
	c.DNSResolverProfiles = []DNSResolverProfile{{ContextConfigID: "config", ContextConfigVersion: 2, ProfileID: "profile", ZoneSuffixes: []string{"private.test"}, Endpoints: []DNSResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}, IPsecPath: DNSResolverIPsecPath{ConnectionID: "conn", ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}, AllowedSources: []string{"10.10.0.7/32"}}}
	if RequiredVersion(c) != 11 || CanonicalHash(c) == base {
		t.Fatal("DNS transport silently accepted by old agents")
	}
	h := CanonicalHash(c)
	c.DNSResolverProfiles[0].IPsecPath.SourceAddress = "10.10.0.6"
	if CanonicalHash(c) == h {
		t.Fatal("source authority not hashed")
	}
	h = CanonicalHash(c)
	c.DNSResolverProfiles[0].AllowedSources = nil
	if CanonicalHash(c) == h {
		t.Fatal("proxy client scope not hashed")
	}
}
