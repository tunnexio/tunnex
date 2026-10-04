package appdomains

import "testing"

func TestAddressConfigurationValidation(t *testing.T) {
	for _, tc := range []struct {
		name, portal, base string
		ok                 bool
	}{
		{"parent portal", "https://internal.tunnex.app", "internal.tunnex.app", true},
		{"independent site", "https://console.example.com", "apps.example.net", true},
		{"HTTPS IP portal", "https://192.0.2.4:9443", "apps.example.net", true},
		{"HTTPS IPv6 portal", "https://[2001:db8::1]:9443", "apps.example.net", true},
		{"console sibling", "https://console.example.com", "apps.example.com", false},
		{"wildcard", "https://internal.tunnex.app", "*.internal.tunnex.app", false},
		{"IP app base", "https://internal.tunnex.app", "192.0.2.4", false},
		{"public suffix", "https://console.example.com", "com", false},
		{"private suffix", "https://console.example.com", "apps.github.io", false},
		{"unknown suffix", "https://console.other.test", "apps.fixture.test", false},
		{"HTTP portal", "http://internal.tunnex.app", "internal.tunnex.app", false},
		{"URL app base", "https://internal.tunnex.app", "https://internal.tunnex.app", false},
		{"path", "https://internal.tunnex.app/console", "internal.tunnex.app", false},
		{"credentials", "https://user@internal.tunnex.app", "internal.tunnex.app", false},
		{"fragment", "https://internal.tunnex.app#", "internal.tunnex.app", false},
		{"query", "https://internal.tunnex.app?", "internal.tunnex.app", false},
		{"badport", "https://internal.tunnex.app:0", "internal.tunnex.app", false},
		{"emptyport", "https://internal.tunnex.app:", "internal.tunnex.app", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalize(Config{PortalURL: tc.portal, AppBaseDomain: tc.base})
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v, want=%v: %v", err == nil, tc.ok, err)
			}
		})
	}
	normalized, err := Normalize(Config{PortalURL: " https://Internal.Tunnex.App/ ", AppBaseDomain: " INTERNAL.TUNNEX.APP "})
	if err != nil || normalized.PortalURL != "https://internal.tunnex.app" || normalized.AppBaseDomain != "internal.tunnex.app" {
		t.Fatal("canonicalization", normalized, err)
	}
}
