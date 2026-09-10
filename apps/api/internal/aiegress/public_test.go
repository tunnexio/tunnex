package aiegress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func publicPolicy(t *testing.T) *Policy {
	t.Helper()
	p := &Policy{PublicHTTPS: true, ProtectedHosts: []string{"control.example.com"}, DeniedCIDRs: []string{"8.8.4.0/24"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPublicEndpointEligibility(t *testing.T) {
	p := publicPolicy(t)
	if !p.PublicEndpointsEnabled() {
		t.Fatal("validated public mode missing")
	}
	for _, raw := range []string{"https://models.example.com/base", "https://MODELS.example.com:443/base", "https://8.8.8.8", "https://[2606:4700:4700::1111]"} {
		if !p.AllowsPublicEndpoint(raw) || !p.AllowsEndpoint(raw) {
			t.Errorf("public URL denied: %s", raw)
		}
	}
	for _, raw := range []string{"http://models.example.com", "https://models.example.com:8443", "https://control.example.com", "https://CONTROL.example.com", "https://localhost", "https://model.local", "https://model.internal", "https://host.home.arpa", "https://models.example.com.", "https://bad_host.example.com", "https://user@models.example.com", "https://models.example.com/?", "https://models.example.com/%2e", "https://127.0.0.1", "https://10.0.0.1", "https://100.64.0.1", "https://[fd00::1]", "https://[fe80::1]", "https://[::ffff:127.0.0.1]"} {
		if p.AllowsPublicEndpoint(raw) || p.AllowsEndpoint(raw) {
			t.Errorf("unsafe URL allowed: %s", raw)
		}
	}
	unvalidated := &Policy{PublicHTTPS: true, ProtectedHosts: p.ProtectedHosts}
	if unvalidated.PublicEndpointsEnabled() || unvalidated.AllowsPublicEndpoint("https://models.example.com") {
		t.Fatal("unvalidated public mode enabled")
	}
	p.ProtectedHosts = nil
	if p.validate() == nil || p.PublicEndpointsEnabled() || p.AllowsPublicEndpoint("https://models.example.com") {
		t.Fatal("failed revalidation left public mode enabled")
	}
	p = &Policy{ProtectedHosts: []string{"control.example.com"}}
	if p.validate() == nil {
		t.Fatal("empty default policy allowed")
	}
}

func TestPublicEndpointExplicitAuthorityPrecedence(t *testing.T) {
	p := publicPolicy(t)
	p.Endpoints = []Endpoint{{Provider: "sagemaker", Name: "reserved", URL: "https://models.example.com/base", AllowedCIDRs: []string{"8.8.8.8/32"}}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if !p.AllowsEndpoint("https://models.example.com/base") {
		t.Fatal("exact rule lost")
	}
	for _, raw := range []string{"https://models.example.com/base", "https://models.example.com/other", "https://MODELS.example.com:443/base"} {
		if p.AllowsPublicEndpoint(raw) {
			t.Fatalf("reserved authority bypassed: %s", raw)
		}
	}
	if p.AllowsEndpoint("https://models.example.com/other") {
		t.Fatal("explicit path restriction bypassed")
	}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "control.example.com" {
			return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	for _, authority := range []string{"models.example.com:443", "MODELS.example.com:443"} {
		if _, err := p.addresses(context.Background(), authority, lookup); err == nil {
			t.Fatal("explicit CIDR restriction bypassed")
		}
	}
	private := fixturePolicy(t)
	private.PublicHTTPS = true
	if err := private.validate(); err != nil {
		t.Fatal(err)
	}
	if !private.AllowsEndpoint("https://models.internal/base") || private.AllowsPublicEndpoint("https://models.internal/base") {
		t.Fatal("private explicit rule classification changed")
	}
}

func TestPublicAddressWholeAnswerBoundary(t *testing.T) {
	p := publicPolicy(t)
	for _, tc := range []struct {
		name    string
		ips     []string
		allowed bool
	}{
		{"public-v4", []string{"8.8.8.8"}, true}, {"public-v6", []string{"2606:4700:4700::1111"}, true},
		{"mixed-private", []string{"8.8.8.8", "10.0.0.1"}, false}, {"protected-alias", []string{"9.9.9.9"}, false},
		{"denied", []string{"8.8.4.4"}, false}, {"loopback", []string{"127.0.0.1"}, false},
		{"mapped-private", []string{"::ffff:10.0.0.1"}, false}, {"ula", []string{"fd00::1"}, false},
		{"metadata", []string{"169.254.169.254"}, false}, {"azure-metadata", []string{"168.63.129.16"}, false},
		{"cgnat", []string{"100.64.0.1"}, false}, {"doc-v4", []string{"192.0.2.1"}, false},
		{"benchmark", []string{"198.18.0.1"}, false}, {"protocol-v4", []string{"192.0.0.8"}, false},
		{"doc-v6", []string{"2001:db8::1"}, false}, {"new-doc-v6", []string{"3fff::1"}, false},
		{"teredo", []string{"2001::1"}, false}, {"6to4", []string{"2002::1"}, false},
		{"nat64", []string{"64:ff9b::808:808"}, false}, {"site-local", []string{"fec0::1"}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "control.example.com" {
					return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
				}
				calls++
				ips := []netip.Addr{}
				for _, raw := range tc.ips {
					ips = append(ips, netip.MustParseAddr(raw))
				}
				return ips, nil
			}
			ips, err := p.addresses(context.Background(), "models.example.com:443", lookup)
			if (err == nil) != tc.allowed || calls != 1 || (!tc.allowed && len(ips) != 0) {
				t.Fatalf("result=%v ips=%v lookup calls=%d", err, ips, calls)
			}
		})
	}
	lookupCount := 0
	rebinding := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "control.example.com" {
			return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
		}
		lookupCount++
		if lookupCount == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, err := p.addresses(context.Background(), "models.example.com:443", rebinding); err != nil {
		t.Fatal(err)
	}
	if _, err := p.addresses(context.Background(), "models.example.com:443", rebinding); err == nil || lookupCount != 2 {
		t.Fatal("DNS rebind was accepted or destination resolved twice")
	}
	for _, authority := range []string{"models.example.com:80", "models.example.com:0443", "models.example.com:8443", "control.example.com:443", "models.example.com.:443", "localhost:443"} {
		if _, err := p.addresses(context.Background(), authority, rebinding); err == nil {
			t.Errorf("authority accepted: %s", authority)
		}
	}
	failedProtection := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("DNS unavailable") }
	if _, err := p.addresses(context.Background(), "models.example.com:443", failedProtection); err == nil {
		t.Fatal("protected DNS failure opened public access")
	}
}

func TestFoundryCognitiveServices(t *testing.T) {
	if !FoundryEndpoint("https://resource.cognitiveservices.azure.com/openai") {
		t.Fatal("cognitive resource missing")
	}
	for _, raw := range []string{"https://cognitiveservices.azure.com/openai", "https://resource.cognitiveservices.azure.com.evil.example/openai", "https://resource.cognitiveservices.azure.com/models"} {
		if FoundryEndpoint(raw) {
			t.Errorf("invalid Foundry endpoint: %s", raw)
		}
	}
}

func TestPublicNumericDialAndMixedAnswerNoDial(t *testing.T) {
	p := publicPolicy(t)
	for _, mixed := range []bool{false, true} {
		lookups, dials := 0, 0
		lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "control.example.com" {
				return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
			}
			lookups++
			ips := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}
			if mixed {
				ips = append(ips, netip.MustParseAddr("10.0.0.1"))
			}
			return ips, nil
		}
		dial := func(_ context.Context, network, authority string) (net.Conn, error) {
			dials++
			expected := "8.8.8.8:443"
			if dials == 2 {
				expected = "1.1.1.1:443"
			}
			if network != "tcp" || authority != expected {
				t.Errorf("non-numeric or unvalidated dial %s %s", network, authority)
			}
			return nil, errors.New("fixture connection refusal")
		}
		_, err := p.dialResolved(context.Background(), "models.example.com:443", lookup, dial)
		expectedDials := 2
		if mixed {
			expectedDials = 0
		}
		if err == nil || lookups != 1 || dials != expectedDials {
			t.Fatalf("mixed=%v err=%v lookups=%d dials=%d", mixed, err, lookups, dials)
		}
	}
}
