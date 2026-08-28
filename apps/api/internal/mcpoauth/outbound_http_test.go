package mcpoauth

import (
	"net/netip"
	"net/url"
	"testing"
)

func TestOAuthOutboundAddressPolicy(t *testing.T) {
	tests := []struct {
		address string
		allowed bool
	}{
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := allowedOAuthAddress(netip.MustParseAddr(test.address)); got != test.allowed {
				t.Fatalf("allowedOAuthAddress(%s)=%v, want %v", test.address, got, test.allowed)
			}
		})
	}
}

func TestOAuthRequestURLPolicy(t *testing.T) {
	for _, raw := range []string{
		"https://localhost/oauth",
		"https://metadata.local/token",
		"https://127.0.0.1/token",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]/token",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if validOAuthRequestURL(u) {
			t.Fatalf("unsafe OAuth request URL accepted: %s", raw)
		}
	}
	u, _ := url.Parse("https://issuer.example/oauth")
	if !validOAuthRequestURL(u) {
		t.Fatal("public HTTPS OAuth URL rejected")
	}
}

func TestOAuthMetadataEndpointsStayOnIssuerOrigin(t *testing.T) {
	if !sameOrigin("https://issuer.example/path", "https://issuer.example/token") {
		t.Fatal("same issuer origin rejected")
	}
	if sameOrigin("https://issuer.example/path", "https://attacker.example/token") {
		t.Fatal("cross-origin OAuth endpoint accepted")
	}
}
