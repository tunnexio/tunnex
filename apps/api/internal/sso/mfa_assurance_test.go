package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestOIDCMFAAssuranceUsesVerifiedAuthenticationEvent(t *testing.T) {
	f := newFakeIdP(t, "mfa-test")
	p, err := NewOIDCProvider(context.Background(), "test", f.issuer(), f.clientID, "secret", "https://portal.test/callback", []string{"openid", "email"}, googleNormalizer)
	if err != nil {
		t.Fatal(err)
	}
	verified := time.Now().Add(-time.Minute).Unix()
	old := time.Now().Add(-time.Hour).Unix()
	cases := []struct {
		name  string
		extra map[string]any
		want  int64
	}{
		{"verified MFA", map[string]any{"amr": []string{"pwd", "mfa"}, "auth_time": verified}, verified},
		{"preserve old authentication time", map[string]any{"amr": []string{"mfa"}, "auth_time": old}, old},
		{"password is not MFA", map[string]any{"amr": []string{"pwd"}, "auth_time": verified}, 0},
		{"OTP alone is not MFA", map[string]any{"amr": []string{"otp"}, "auth_time": verified}, 0},
		{"unmapped ACR", map[string]any{"acr": "2", "auth_time": verified}, 0},
		{"no auth time", map[string]any{"amr": []string{"mfa"}}, 0},
		{"issue time is not auth time", map[string]any{"amr": []string{"mfa"}, "iat": verified}, 0},
		{"future authentication", map[string]any{"amr": []string{"mfa"}, "auth_time": time.Now().Add(time.Hour).Unix()}, 0},
		{"zero authentication", map[string]any{"amr": []string{"mfa"}, "auth_time": 0}, 0},
		{"string method is malformed", map[string]any{"amr": "mfa", "auth_time": verified}, 0},
		{"string time is malformed", map[string]any{"amr": []string{"mfa"}, "auth_time": "123"}, 0},
		{"fractional time unsupported", map[string]any{"amr": []string{"mfa"}, "auth_time": float64(verified) + 0.5}, 0},
		{"unknown assurance", map[string]any{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"sub": "mfa-user", "email": "mfa@example.test", "email_verified": true, "nonce": "bound-nonce"}
			for k, v := range tc.extra {
				claims[k] = v
			}
			f.mint(f.key, claims)
			id, err := p.Exchange(context.Background(), "code", "verifier", "bound-nonce")
			if err != nil {
				t.Fatalf("unknown MFA claims must not break ordinary sign in: %v", err)
			}
			if tc.want == 0 {
				if !id.MFAVerifiedAt.IsZero() {
					t.Fatal("unproven MFA accepted")
				}
				return
			}
			if id.MFAVerifiedAt.Unix() != tc.want {
				t.Fatalf("authentication event changed: got %v", id.MFAVerifiedAt)
			}
		})
	}
	claims := map[string]any{"sub": "mfa-user", "email": "mfa@example.test", "email_verified": true, "nonce": "bound-nonce", "amr": []string{"mfa"}, "auth_time": verified}
	f.mint(f.key, claims)
	if _, err := p.Exchange(context.Background(), "code", "verifier", "different-nonce"); err == nil {
		t.Fatal("MFA accepted despite nonce mismatch")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mint(key, claims)
	if _, err := p.Exchange(context.Background(), "code", "verifier", "bound-nonce"); err == nil {
		t.Fatal("MFA accepted despite invalid signature")
	}
}

func TestUserInfoCannotSupplyMFAAssurance(t *testing.T) {
	f := newFakeIdP(t, "mfa-userinfo-test")
	f.userinfo = map[string]any{"sub": "mfa-user", "email": "mfa@example.test", "email_verified": true, "amr": []string{"mfa"}, "auth_time": time.Now().Unix()}
	p, err := newCustomProviderWithClient(context.Background(), f.issuer(), f.clientID, "secret", "https://portal.test/callback", f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.mint(f.key, map[string]any{"sub": "mfa-user", "nonce": "bound-nonce"})
	id, err := p.Exchange(context.Background(), "code", "verifier", "bound-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if !id.MFAVerifiedAt.IsZero() {
		t.Fatal("UserInfo promoted MFA assurance")
	}
	if f.userinfoCalls == 0 {
		t.Fatal("test did not exercise UserInfo")
	}
}
