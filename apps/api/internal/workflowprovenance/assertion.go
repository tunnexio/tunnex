// Package workflowprovenance verifies F15's compact, agent-signed run claims.
// It intentionally has no network, OAuth, or MCP dependency: provenance is a
// separate assertion made after a workflow has selected its tool and resource.
package workflowprovenance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersion = 1
	MaxLifetime   = 5 * time.Minute
	ClockSkew     = 30 * time.Second
)

var (
	ErrMalformed        = errors.New("workflow provenance assertion is malformed")
	ErrExpired          = errors.New("workflow provenance assertion is expired")
	ErrNotYetValid      = errors.New("workflow provenance assertion is not yet valid")
	ErrLifetimeExceeded = errors.New("workflow provenance assertion lifetime exceeds maximum")
	ErrBadSignature     = errors.New("workflow provenance assertion signature is invalid")
)

// Claims are deliberately a fixed struct rather than an unbounded map. This
// makes the exact signed bytes reproducible across the SDK and control plane.
type Claims struct {
	AssertionID          uuid.UUID `json:"assertion_id"`
	WorkflowID           string    `json:"workflow_id"`
	RunID                string    `json:"run_id"`
	TriggerKind          string    `json:"trigger_kind"`
	InitiatingSubjectRef string    `json:"initiating_subject_ref"`
	Tool                 string    `json:"tool"`
	Resource             string    `json:"resource"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	KeyID                string    `json:"kid"`
}

type Assertion struct {
	Version   int    `json:"version"`
	Claims    Claims `json:"claims"`
	Signature string `json:"signature"`
}

// CanonicalBytes validates claims before emitting the only bytes an SDK may
// sign. The struct's declaration order is the protocol order; maps are never
// part of the signed representation.
func CanonicalBytes(version int, claims Claims) ([]byte, error) {
	if version != SchemaVersion || !validClaims(claims) {
		return nil, ErrMalformed
	}
	return json.Marshal(struct {
		Version int    `json:"version"`
		Claims  Claims `json:"claims"`
	}{Version: version, Claims: normalizeClaims(claims)})
}

func Sign(privateKey ed25519.PrivateKey, claims Claims) (Assertion, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Assertion{}, ErrMalformed
	}
	canonical, err := CanonicalBytes(SchemaVersion, claims)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{Version: SchemaVersion, Claims: normalizeClaims(claims), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}, nil
}

// Verify authenticates one assertion against a single already-bound public
// key. Device/key lookup and replay persistence deliberately live above this
// pure verifier.
func Verify(publicKey ed25519.PublicKey, assertion Assertion, now time.Time) error {
	canonical, err := CanonicalBytes(assertion.Version, assertion.Claims)
	if err != nil {
		return err
	}
	claims := normalizeClaims(assertion.Claims)
	now = now.UTC()
	if claims.ExpiresAt.Before(now) {
		return ErrExpired
	}
	if claims.IssuedAt.After(now.Add(ClockSkew)) {
		return ErrNotYetValid
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt) > MaxLifetime {
		return ErrLifetimeExceeded
	}
	signature, err := base64.RawURLEncoding.DecodeString(assertion.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, canonical, signature) {
		return ErrBadSignature
	}
	return nil
}

func normalizeClaims(claims Claims) Claims {
	claims.IssuedAt = claims.IssuedAt.UTC().Round(0)
	claims.ExpiresAt = claims.ExpiresAt.UTC().Round(0)
	return claims
}

func validClaims(claims Claims) bool {
	if claims.AssertionID == uuid.Nil || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) {
		return false
	}
	return bounded(claims.WorkflowID, 256) && bounded(claims.RunID, 256) &&
		bounded(claims.TriggerKind, 64) && bounded(claims.InitiatingSubjectRef, 256) &&
		bounded(claims.Tool, 256) && bounded(claims.Resource, 2048) && bounded(claims.KeyID, 128)
}

func bounded(value string, max int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= max
}
