package aigateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type workloadProof struct {
	ID, RequestID, EnrollmentHash, NextKey string
	Expires                                time.Time
}

func verifyWorkloadProof(raw string, public []byte, audience, subject string, now time.Time) (workloadProof, error) {
	invalid := errors.New("invalid workload proof")
	if len(raw) == 0 || len(raw) > 8<<10 || len(public) != ed25519.PublicKeySize || audience == "" || subject == "" || now.IsZero() {
		return workloadProof{}, invalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return workloadProof{}, invalid
	}
	header, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return workloadProof{}, invalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(header, &fields) != nil || len(fields) == 0 {
		return workloadProof{}, invalid
	}
	for name, value := range fields {
		if name != "alg" && name != "typ" && name != "kid" {
			return workloadProof{}, invalid
		}
		var text string
		if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &text) != nil {
			return workloadProof{}, invalid
		}
	}
	signed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(signed.Headers) != 1 {
		return workloadProof{}, invalid
	}
	var claims struct {
		jwt.Claims
		RequestID      string `json:"request_id"`
		EnrollmentHash string `json:"enrollment_hash"`
		NextKey        string `json:"next_key"`
	}
	if signed.Claims(ed25519.PublicKey(public), &claims) != nil || claims.IssuedAt == nil || claims.Expiry == nil {
		return workloadProof{}, invalid
	}
	issued, expires := claims.IssuedAt.Time(), claims.Expiry.Time()
	if !expires.After(issued) || expires.Sub(issued) > time.Minute || !now.Add(-30*time.Second).Before(expires) ||
		len(claims.Audience) != 1 || claims.Audience[0] != audience ||
		claims.ValidateWithLeeway(jwt.Expected{Issuer: subject, Subject: subject, Time: now}, 30*time.Second) != nil ||
		claims.NotBefore != nil && !claims.NotBefore.Time().Before(expires) ||
		len(claims.ID) < 16 || len(claims.ID) > 128 ||
		len(claims.RequestID) > 512 || len(claims.EnrollmentHash) > 512 || len(claims.NextKey) > 512 {
		return workloadProof{}, invalid
	}
	for _, c := range claims.ID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return workloadProof{}, invalid
		}
	}
	return workloadProof{ID: claims.ID, RequestID: claims.RequestID, EnrollmentHash: claims.EnrollmentHash, NextKey: claims.NextKey, Expires: expires}, nil
}
