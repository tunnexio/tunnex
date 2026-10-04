package http

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

type fixtureEntitlementControl struct {
	Version int64  `json:"version"`
	State   string `json:"state"`
}

func fixtureInstallEntitlement(m *licence.Manager, pub ed25519.PublicKey, priv ed25519.PrivateKey, c licence.Claims, state string) bool {
	now := time.Now()
	switch state {
	case "valid":
		c.IssuedAt = now.Add(-time.Minute).Unix()
		c.ExpiresAt = now.Add(4 * time.Hour).Unix()
	case "lapsed":
		c.IssuedAt = now.Add(-200 * 24 * time.Hour).Unix()
		c.ExpiresAt = now.Add(-licence.GracePeriod - time.Hour).Unix()
	default:
		return false
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	wire := licence.Prefix + encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(encoded)))
	result, err := m.Install(map[string]ed25519.PublicKey{c.Kid: pub}, wire)
	return err == nil && result.OK && m.Has(licence.FeatAppAccess, time.Now()) == (state == "valid")
}

// Nonshipping fixed owned mount; private monotonically versioned control only.
// Invalid or replayed control never changes the actual installed claims.
func fixtureEntitlementPoll(ctx context.Context, m *licence.Manager, pub ed25519.PublicKey, priv ed25519.PrivateKey, c licence.Claims) {
	const path = "/owned-aa6-proxy/entitlement-control.json"
	var applied int64
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 256 {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var control fixtureEntitlementControl
			if json.Unmarshal(raw, &control) != nil || control.Version <= applied || !fixtureInstallEntitlement(m, pub, priv, c, control.State) {
				continue
			}
			applied = control.Version
			response, _ := json.Marshal(struct {
				Version   int64  `json:"version"`
				State     string `json:"state"`
				Available bool   `json:"app_access_available"`
			}{applied, control.State, m.Has(licence.FeatAppAccess, time.Now())})
			const tmp = "/owned-aa6-proxy/entitlement-readback.tmp"
			f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				continue
			}
			_, err = f.Write(response)
			closeErr := f.Close()
			if err == nil && closeErr == nil {
				_ = os.Rename(tmp, "/owned-aa6-proxy/entitlement-readback.json")
			}
		}
	}
}

func TestFixtureSignedEntitlementTransitions(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager := &licence.Manager{}
	claims := licence.Claims{Version: 1, Kid: "fixture-test", ID: "fixture-transition", Domain: "console.example.com", Tier: "trial", Band: "trial"}
	for _, state := range []string{"valid", "lapsed", "valid"} {
		if !fixtureInstallEntitlement(manager, pub, priv, claims, state) {
			t.Fatalf("signed %s transition failed", state)
		}
	}
	if fixtureInstallEntitlement(manager, pub, priv, claims, "unknown") || !manager.Has(licence.FeatAppAccess, time.Now()) {
		t.Fatal("invalid state changed entitlement")
	}
}
