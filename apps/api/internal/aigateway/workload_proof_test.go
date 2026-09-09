package aigateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func workloadTestClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "instance-client", "sub": "instance-client", "aud": "https://gateway.example/api/v1/workload/token",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "request-1234567890",
		"request_id": "enrollment-request", "enrollment_hash": "enrollment-digest", "next_key": "candidate-public-key",
	}
}

func signWorkloadTestProof(t *testing.T, key ed25519.PrivateKey, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
}

func marshalWorkloadTestClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestWorkloadProofAcceptsRegisteredEd25519Key(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	claims := workloadTestClaims(now)
	claims["nbf"] = now.Unix()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "registered-key"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(marshalWorkloadTestClaims(t, claims)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now, now.Add(-30 * time.Second), now.Add(89 * time.Second)} {
		proof, err := verifyWorkloadProof(raw, public, claims["aud"].(string), "instance-client", at)
		if err != nil {
			t.Fatalf("valid proof at %s: %v", at, err)
		}
		if proof.ID != claims["jti"] || proof.RequestID != claims["request_id"] || proof.EnrollmentHash != claims["enrollment_hash"] ||
			proof.NextKey != claims["next_key"] || !proof.Expires.Equal(now.Add(time.Minute)) {
			t.Fatalf("wrong verified claims: %+v", proof)
		}
	}
	for _, aud := range []any{claims["aud"], []string{claims["aud"].(string)}} {
		claims["aud"] = aud
		delete(claims, "nbf")
		raw = signWorkloadTestProof(t, private, `{"alg":"EdDSA"}`, marshalWorkloadTestClaims(t, claims))
		if _, err := verifyWorkloadProof(raw, public, "https://gateway.example/api/v1/workload/token", "instance-client", now); err != nil {
			t.Fatalf("optional nbf/single audience: %v", err)
		}
	}
}

func TestWorkloadProofRejectsInvalidSignedClaims(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name   string
		change func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "other-client" }},
		{"subject", func(c map[string]any) { c["sub"] = "other-client" }},
		{"missing-issuer", func(c map[string]any) { delete(c, "iss") }},
		{"missing-subject", func(c map[string]any) { delete(c, "sub") }},
		{"audience", func(c map[string]any) { c["aud"] = "https://other.example/token" }},
		{"multiple-audiences", func(c map[string]any) { c["aud"] = []any{c["aud"], "another"} }},
		{"duplicate-audiences", func(c map[string]any) { c["aud"] = []any{c["aud"], c["aud"]} }},
		{"missing-audience", func(c map[string]any) { delete(c, "aud") }},
		{"missing-iat", func(c map[string]any) { delete(c, "iat") }},
		{"null-iat", func(c map[string]any) { c["iat"] = nil }},
		{"missing-exp", func(c map[string]any) { delete(c, "exp") }},
		{"null-exp", func(c map[string]any) { c["exp"] = nil }},
		{"long-lifetime", func(c map[string]any) { c["exp"] = now.Add(61 * time.Second).Unix() }},
		{"zero-lifetime", func(c map[string]any) { c["exp"] = c["iat"] }},
		{"reversed-lifetime", func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }},
		{"future-issued", func(c map[string]any) { c["iat"] = now.Add(31 * time.Second).Unix() }},
		{"expired", func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-91*time.Second).Unix(), now.Add(-31*time.Second).Unix()
		}},
		{"expiry-skew-boundary", func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-90*time.Second).Unix(), now.Add(-30*time.Second).Unix()
		}},
		{"future-nbf", func(c map[string]any) { c["nbf"] = now.Add(31 * time.Second).Unix() }},
		{"nbf-after-exp", func(c map[string]any) {
			c["exp"], c["nbf"] = now.Add(10*time.Second).Unix(), now.Add(11*time.Second).Unix()
		}},
		{"missing-jti", func(c map[string]any) { delete(c, "jti") }},
		{"short-jti", func(c map[string]any) { c["jti"] = strings.Repeat("a", 15) }},
		{"long-jti", func(c map[string]any) { c["jti"] = strings.Repeat("a", 129) }},
		{"non-ascii-jti", func(c map[string]any) { c["jti"] = "request-1234567890é" }},
		{"whitespace-jti", func(c map[string]any) { c["jti"] = "request-1234567890 " }},
		{"control-jti", func(c map[string]any) { c["jti"] = "request-1234567890\n" }},
		{"numeric-jti", func(c map[string]any) { c["jti"] = 1234567890123456 }},
		{"long-request", func(c map[string]any) { c["request_id"] = strings.Repeat("a", 513) }},
		{"long-enrollment-hash", func(c map[string]any) { c["enrollment_hash"] = strings.Repeat("a", 513) }},
		{"long-next-key", func(c map[string]any) { c["next_key"] = strings.Repeat("a", 513) }},
		{"numeric-request", func(c map[string]any) { c["request_id"] = 123 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := workloadTestClaims(now)
			tc.change(claims)
			raw := signWorkloadTestProof(t, private, `{"alg":"EdDSA","typ":"JWT"}`, marshalWorkloadTestClaims(t, claims))
			proof, err := verifyWorkloadProof(raw, public, "https://gateway.example/api/v1/workload/token", "instance-client", now)
			if err == nil || err.Error() != "invalid workload proof" || proof != (workloadProof{}) {
				t.Fatalf("invalid signed claims accepted or exposed: %+v, %v", proof, err)
			}
		})
	}
}

func TestWorkloadProofRejectsHeadersAndTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	payload := marshalWorkloadTestClaims(t, workloadTestClaims(now))
	for _, header := range []string{
		`{"alg":"none"}`, `{"alg":"HS256"}`, `{"alg":"RS256"}`, `{"alg":"ES256"}`, `{}`,
		`{"alg":"EdDSA","jwk":{"kty":"OKP"}}`, `{"alg":"EdDSA","jku":"https://untrusted.example/key"}`,
		`{"alg":"EdDSA","x5u":"https://untrusted.example/key"}`, `{"alg":"EdDSA","x5c":[]}`,
		`{"alg":"EdDSA","crit":[]}`, `{"alg":"EdDSA","b64":true}`, `{"alg":"EdDSA","nonce":"nonce"}`,
		`{"alg":"EdDSA","unknown":"value"}`, `{"alg":"EdDSA","typ":{}}`, `{"alg":"EdDSA","kid":null}`,
		`{"alg":"none","alg":"EdDSA"}`, `{"ALG":"EdDSA"}`,
	} {
		t.Run(header, func(t *testing.T) {
			raw := signWorkloadTestProof(t, private, header, payload)
			if _, err := verifyWorkloadProof(raw, public, "https://gateway.example/api/v1/workload/token", "instance-client", now); err == nil {
				t.Fatal("forbidden signed header accepted")
			}
		})
	}
	raw := signWorkloadTestProof(t, private, `{"alg":"EdDSA"}`, payload)
	parts := strings.Split(raw, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	for name, malformed := range map[string]string{
		"empty": "", "oversized": strings.Repeat("a", (8<<10)+1), "missing-signature": parts[0] + "." + parts[1] + ".",
		"bad-signature":       parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature),
		"tampered-payload":    parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(payload, "request-1234567890", "request-0987654321", 1))) + "." + parts[2],
		"duplicate-claim":     signWorkloadTestProof(t, private, `{"alg":"EdDSA"}`, strings.TrimSuffix(payload, "}")+`,"iss":"instance-client"}`),
		"multiple-signatures": `{"payload":"` + parts[1] + `","signatures":[{"protected":"` + parts[0] + `","signature":"` + parts[2] + `"},{"protected":"` + parts[0] + `","signature":"` + parts[2] + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if proof, err := verifyWorkloadProof(malformed, public, "https://gateway.example/api/v1/workload/token", "instance-client", now); err == nil || err.Error() != "invalid workload proof" || proof != (workloadProof{}) {
				t.Fatal("malformed proof accepted or exposed")
			}
		})
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, public[:31], append(append([]byte{}, public...), 0), otherPublic} {
		if _, err := verifyWorkloadProof(raw, key, "https://gateway.example/api/v1/workload/token", "instance-client", now); err == nil {
			t.Fatal("invalid registered key accepted")
		}
	}
	for _, identity := range [][2]string{{"", "instance-client"}, {"https://gateway.example/api/v1/workload/token", ""}} {
		if _, err := verifyWorkloadProof(raw, public, identity[0], identity[1], now); err == nil {
			t.Fatal("missing verification identity accepted")
		}
	}
}
