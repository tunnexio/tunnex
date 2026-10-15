package policyspec

import "testing"

func TestStaticCNAMECompletionRequiresV14AndHashesEndpoints(t *testing.T) {
	c := Compiled{DNSResolverProfiles: []DNSResolverProfile{{StaticRecords: []DNSStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "public.example", TTL: 300}}}}}
	before := CanonicalHash(c)
	if RequiredVersion(c) != 12 {
		t.Fatal("unchanged static profile bumped")
	}
	c.DNSResolverProfiles[0].Endpoints = []DNSResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}
	if RequiredVersion(c) != 14 || CanonicalHash(c) == before {
		t.Fatal("completion has no version/hash boundary")
	}
	changed := CanonicalHash(c)
	c.DNSResolverProfiles[0].Endpoints[0].Transport = "tcp"
	if CanonicalHash(c) == changed {
		t.Fatal("transport omitted from hash")
	}
	c.DNSResolverProfiles[0].Endpoints = nil
	if RequiredVersion(c) != 12 || CanonicalHash(c) != before {
		t.Fatal("withdrawal changed legacy behavior")
	}
	c.DNSResolverProfiles[0].StaticRecords = nil
	c.DNSResolverProfiles[0].Endpoints = []DNSResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}
	if RequiredVersion(c) != 11 {
		t.Fatal("private upstream profile bumped")
	}
}
