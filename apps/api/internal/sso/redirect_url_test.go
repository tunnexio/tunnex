package sso

import "testing"

func TestRedirectURLPreservesConfiguredSchemeAndHost(t *testing.T) {
	for _, base := range []string{"https://vpn.example.com", "http://10.0.0.8:8080"} {
		svc := &Service{baseURL: base}
		got := svc.redirectURL("microsoft")
		want := base + "/api/v1/auth/sso/microsoft/callback"
		if got != want {
			t.Fatalf("redirectURL(%q) = %q, want %q", base, got, want)
		}
	}
}
