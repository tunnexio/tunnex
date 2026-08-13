package sso

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeIdP is a minimal in-process OpenID Provider for assembled-flow tests:
// it serves discovery + JWKS and mints RS256-signed ID tokens the test controls.
// ~150 lines, reused by S2.4 (Microsoft) and S2.5 (JIT provisioning).
type fakeIdP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string
	nextTok  string // the id_token the token endpoint returns next
}

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	f := &fakeIdP{key: key, kid: "test-key", clientID: clientID}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                f.issuer(),
			"authorization_endpoint":                f.issuer() + "/auth",
			"token_endpoint":                        f.issuer() + "/token",
			"jwks_uri":                              f.issuer() + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]any{f.jwk()}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.nextTok,
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) issuer() string { return f.server.URL }

// factory returns a ProviderFactory that points at this fake IdP (google-style
// claims normalization is sufficient for the flow tests).
func (f *fakeIdP) factory() ProviderFactory {
	return func(ctx context.Context, cfg Config, redirectURL string) (Provider, error) {
		return NewOIDCProvider(ctx, cfg.Provider, f.issuer(), cfg.ClientID, cfg.ClientSecret, redirectURL, []string{"openid", "email"}, googleNormalizer)
	}
}

// mint sets the id_token the next exchange returns, signed by signer (use
// f.key for a valid token; a different key to simulate a tampered signature).
func (f *fakeIdP) mint(signer *rsa.PrivateKey, claims map[string]any) {
	base := map[string]any{
		"iss": f.issuer(),
		"aud": f.clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		base[k] = v
	}
	f.nextTok = signJWT(f.kid, signer, base)
}

func (f *fakeIdP) jwk() map[string]any {
	pub := f.key.Public().(*rsa.PublicKey)
	eBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(eBuf, uint32(pub.E))
	eBuf = trimLeadingZeros(eBuf)
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid,
		"n": b64(pub.N.Bytes()),
		"e": b64(eBuf),
	}
}

func signJWT(kid string, key *rsa.PrivateKey, claims map[string]any) string {
	header := b64(mustJSON(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}))
	payload := b64(mustJSON(claims))
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + b64(sig)
}

func b64(b []byte) string   { return base64.RawURLEncoding.EncodeToString(b) }
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func trimLeadingZeros(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// unused helper kept for symmetry with big.Int-based exponents.
var _ = big.NewInt
