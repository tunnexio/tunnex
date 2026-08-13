package sso

import (
	"context"
	"testing"
)

func TestMicrosoftNormalizer(t *testing.T) {
	// email present -> used, and Entra login counts as verified (tenant-vouched).
	id, err := microsoftNormalizer(RawClaims{Sub: "s", Email: "a@x.com", Name: "A"})
	if err != nil || id.Email != "a@x.com" || !id.EmailVerified {
		t.Fatalf("email case: %+v err=%v", id, err)
	}
	// email absent -> falls back to preferred_username (a UPN), lowercased.
	id, err = microsoftNormalizer(RawClaims{Sub: "s", PreferredUsername: "Bob@X.COM"})
	if err != nil || id.Email != "bob@x.com" {
		t.Fatalf("upn fallback: %+v err=%v", id, err)
	}
	// neither usable -> error (can't link without an email).
	if _, err := microsoftNormalizer(RawClaims{Sub: "s", PreferredUsername: "not-an-email"}); err == nil {
		t.Fatal("expected error when no usable email")
	}
}

func TestNewMicrosoftRejectsSharedTenant(t *testing.T) {
	for _, tid := range []string{"", "common", "organizations", "consumers"} {
		if _, err := NewMicrosoft(context.Background(), tid, "cid", "secret", "http://cb"); err == nil {
			t.Errorf("tenant %q: expected rejection (B2B requires a pinned tenant)", tid)
		}
	}
}

// TestSSOFlowRejectsWrongIssuer proves exact-issuer validation — the mechanism
// behind Microsoft tenant pinning: a token whose `iss` is a different tenant
// than the one configured/discovered is rejected.
func TestSSOFlowRejectsWrongIssuer(t *testing.T) {
	h := newFlowHarness(t)
	state, nonce := h.start(t)
	// Same signing key + audience, but claim to be a DIFFERENT issuer (tenant).
	h.idp.mint(h.idp.key, map[string]any{
		"iss": "https://login.microsoftonline.com/some-other-tenant/v2.0",
		"sub": "s", "email": "wrong@example.com", "email_verified": true, "nonce": nonce,
	})
	if _, err := h.svc.HandleCallback(h.ctx, "google", "code", state); code(err) != "sso_verification_failed" {
		t.Fatalf("wrong issuer/tenant: want sso_verification_failed, got %v", err)
	}
}
