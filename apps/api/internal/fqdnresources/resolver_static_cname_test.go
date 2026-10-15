package fqdnresources

import (
	"github.com/google/uuid"
	"slices"
	"testing"
)

func cnameProfile() ResolverProfile {
	return ResolverProfile{Name: "Aliases", ProviderHint: "on_premises", ZoneSuffixes: []string{"office.test"}, StaticRecords: []ResolverStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "public.example", TTL: 300}}}
}
func TestStaticCNAMEEndpointValidationAndIsolation(t *testing.T) {
	for _, endpoints := range [][]ResolverEndpoint{nil, {{Address: "1.1.1.1", Port: 53, Transport: "udp"}}, {{Address: "8.8.8.8", Port: 53, Transport: "tcp"}, {Address: " 1.1.1.1 ", Transport: "udp"}}} {
		p := cnameProfile()
		p.Endpoints = endpoints
		if err := validateProfiles([]ResolverProfile{p}); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []string{"0.0.0.0", "10.1.0.53", "172.16.0.53", "192.168.1.53", "127.0.0.1", "169.254.1.1", "100.64.0.1", "192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::ffff:1.1.1.1", "2606:4700:4700::1111", "resolver.example"} {
		p := cnameProfile()
		p.Endpoints = []ResolverEndpoint{{Address: address, Port: 53, Transport: "udp"}}
		if err := validateProfiles([]ResolverProfile{p}); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
	for _, endpoints := range [][]ResolverEndpoint{
		{{Address: "1.1.1.1", Port: 5353, Transport: "udp"}}, {{Address: "1.1.1.1", Port: 53, Transport: "doh"}},
		{{Address: "1.1.1.1", Port: 53, Transport: "udp"}, {Address: "1.1.1.1", Port: 53, Transport: "tcp"}},
		{{Address: "1.1.1.1", Port: 53, Transport: "udp"}, {Address: "8.8.8.8", Port: 53, Transport: "udp"}, {Address: "9.9.9.9", Port: 53, Transport: "udp"}, {Address: "8.8.4.4", Port: 53, Transport: "udp"}},
	} {
		p := cnameProfile()
		p.Endpoints = endpoints
		if err := validateProfiles([]ResolverProfile{p}); err == nil {
			t.Fatal("accepted invalid endpoints", endpoints)
		}
	}
	p := cnameProfile()
	p.Endpoints = []ResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}
	p.LANListener = &ResolverLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: []string{"1.1.1.1"}}
	if err := validateProfiles([]ResolverProfile{p}); err != nil {
		t.Fatal("shared public resolver roles conflict", err)
	}
	if !slices.Equal(p.LANListener.AllowedSources, []string{"192.168.1.0/24"}) {
		t.Fatal("source scope changed")
	}
	private := ResolverProfile{Name: "Private", ProviderHint: "on_premises", ZoneSuffixes: []string{"private.test"}, Endpoints: []ResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}}
	if err := validateProfiles([]ResolverProfile{p, private}); err == nil {
		t.Fatal("private authority resolver overlap accepted")
	}
	p.IPsecPath = &ResolverIPsecPath{ConnectionID: uuid.New(), ConfigurationRevision: 1, SourceAddress: "192.168.1.39"}
	if err := validateProfiles([]ResolverProfile{p}); err == nil {
		t.Fatal("IPsec mixed with public static completion")
	}
}
