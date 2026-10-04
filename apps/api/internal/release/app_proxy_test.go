package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestOptionalAppProxyDigestBinding(t *testing.T) {
	for _, arm := range []string{"", "sha256:" + strings.Repeat("b", 64)} {
		s, _ := signedFixture(t)
		s.Manifest.Images["app-proxy"] = Images{AMD64Digest: "sha256:" + strings.Repeat("a", 64), ARM64Digest: arm}
		pub, private, _ := ed25519.GenerateKey(rand.Reader)
		raw, _ := json.Marshal(s.Manifest)
		s.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, raw))
		err := Verify(s, pub)
		if (arm == "") != (err != nil) {
			t.Fatalf("optional image digest validation: %v", err)
		}
	}
	s, pub := signedFixture(t)
	if err := Verify(s, pub); err != nil {
		t.Fatal("legacy descriptor incompatible", err)
	}
}
