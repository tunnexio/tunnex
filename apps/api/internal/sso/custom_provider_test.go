package sso

import (
	"context"
	"net/netip"
	"testing"
)

func TestCustomIssuerRefusesUnsafeTargets(t *testing.T) {
	for _, v := range []string{"http://example.com", "https://localhost", "https://127.0.0.1", "https://169.254.169.254", "https://10.0.0.1", "https://[::1]", "https://example.com:8443", "https://user:pass@example.com", "https://example.com?x=1"} {
		if ValidateCustomIssuer(v) == nil {
			t.Errorf("accepted %s", v)
		}
	}
	for _, v := range []string{"https://company.okta.com", "https://id.example.com/realms/company"} {
		if err := ValidateCustomIssuer(v); err != nil {
			t.Error(err)
		}
	}
	for _, v := range []string{"100.100.100.200", "::ffff:127.0.0.1", "192.168.1.1", "64:ff9b::7f00:1"} {
		if publicOIDCAddress(netip.MustParseAddr(v)) {
			t.Errorf("accepted %s", v)
		}
	}
}
func TestCustomNormalizerRequiresVerifiedIdentity(t *testing.T) {
	for _, r := range []RawClaims{{Email: "a@example.com", EmailVerified: true}, {Sub: "x", Email: "a@example.com"}} {
		if _, err := customNormalizer(r); err == nil {
			t.Fatal("accepted missing or unverified identity")
		}
	}
}
func TestCustomProviderUsesLocalTestIDP(t *testing.T) {
	f := newFakeIdP(t, "client")
	p, err := newCustomProviderWithClient(context.Background(), f.issuer(), "client", "secret", "http://localhost/callback", f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "oidc" {
		t.Fatal("wrong provider")
	}
}

func TestCustomProviderVerifiesLocalIDPTokens(t *testing.T) {
	f := newFakeIdP(t, "client")
	p, err := newCustomProviderWithClient(context.Background(), f.issuer(), "client", "secret", "http://localhost/callback", f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.mint(f.key, map[string]any{"sub": "subject-1", "email": "user@example.com", "email_verified": true, "nonce": "nonce-1"})
	id, err := p.Exchange(context.Background(), "local-code", "verifier", "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "subject-1" || id.Email != "user@example.com" {
		t.Fatal("wrong verified identity")
	}
	if _, err = p.Exchange(context.Background(), "local-code", "verifier", "wrong-nonce"); err == nil {
		t.Fatal("accepted replayed nonce")
	}
	f.mint(f.key, map[string]any{"sub": "subject-1", "email": "user@example.com", "email_verified": true, "nonce": "nonce-1", "aud": "other-client"})
	if _, err = p.Exchange(context.Background(), "local-code", "verifier", "nonce-1"); err == nil {
		t.Fatal("accepted another client's token")
	}
	f.mint(f.key, map[string]any{"sub": "subject-1", "email": "user@example.com", "email_verified": false, "nonce": "nonce-1"})
	if _, err = p.Exchange(context.Background(), "local-code", "verifier", "nonce-1"); err == nil {
		t.Fatal("accepted unverified email")
	}
}

func TestCustomUserInfoCompletion(t *testing.T) {
	for _, tc := range []struct {
		name         string
		claim        any
		include      bool
		sub, email   string
		verified, ok bool
		calls        int
	}{
		{"missing verified", nil, false, "subject", "a@example.com", true, true, 1},
		{"subject mismatch", nil, false, "other", "a@example.com", true, false, 1},
		{"email mismatch", nil, false, "subject", "b@example.com", true, false, 1},
		{"userinfo unverified", nil, false, "subject", "a@example.com", false, false, 1},
		{"explicit false", false, true, "subject", "a@example.com", true, false, 0},
		{"null claim", nil, true, "subject", "a@example.com", true, false, 0},
		{"complete token", true, true, "other", "b@example.com", false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIdP(t, "client")
			f.userinfo = map[string]any{"sub": tc.sub, "email": tc.email, "email_verified": tc.verified}
			claims := map[string]any{"sub": "subject", "email": "a@example.com", "nonce": "nonce"}
			if tc.include {
				claims["email_verified"] = tc.claim
			}
			f.mint(f.key, claims)
			p, err := newCustomProviderWithClient(context.Background(), f.issuer(), "client", "secret", "http://localhost/callback", f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Exchange(context.Background(), "code", "verifier", "nonce")
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v want %v", err == nil, tc.ok)
			}
			if f.userinfoCalls != tc.calls {
				t.Fatalf("calls=%d want %d", f.userinfoCalls, tc.calls)
			}
		})
	}
}
