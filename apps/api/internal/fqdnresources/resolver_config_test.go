package fqdnresources

import "testing"

func TestValidateResolverEndpointsRequiresDirectBoundedTransport(t *testing.T) {
	valid := []ResolverEndpoint{{Address: "10.20.0.53", Transport: "udp"}, {Address: "fd00::53", Port: 53, Transport: "tcp"}}
	if err := validateEndpoints(valid); err != nil {
		t.Fatalf("valid direct endpoints rejected: %v", err)
	}
	if valid[0].Port != 53 {
		t.Fatalf("zero port must normalize to DNS port 53, got %d", valid[0].Port)
	}
	for _, endpoints := range [][]ResolverEndpoint{
		{{Address: "resolver.example.test", Port: 53, Transport: "udp"}},
		{{Address: "127.0.0.1", Port: 53, Transport: "udp"}},
		{{Address: "10.20.0.53", Port: 53, Transport: "doh"}},
		{{Address: "10.20.0.53", Port: 53, Transport: "udp"}, {Address: "10.20.0.53", Port: 53, Transport: "udp"}},
	} {
		if err := validateEndpoints(endpoints); err == nil {
			t.Fatalf("invalid resolver endpoint set accepted: %#v", endpoints)
		}
	}
}
