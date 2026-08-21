package workflowprovenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVerifyAcceptsCanonicalSignedAssertion(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	claims := fixtureClaims(now)
	assertion, err := Sign(private, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, assertion, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	first, err := CanonicalBytes(SchemaVersion, claims)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalBytes(SchemaVersion, assertion.Claims)
	if err != nil || string(first) != string(second) {
		t.Fatalf("canonical bytes changed: %q / %q / %v", first, second, err)
	}
}

func TestVerifyRejectsTamperAndTimeViolations(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	assertion, err := Sign(private, fixtureClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	tampered := assertion
	tampered.Claims.Tool = "delete_everything"
	if err := Verify(public, tampered, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tamper err=%v", err)
	}
	expired := assertion
	expired.Claims.IssuedAt = now.Add(-2 * time.Minute)
	expired.Claims.ExpiresAt = now.Add(-time.Minute)
	if err := Verify(public, expired, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired err=%v", err)
	}
	futureClaims := fixtureClaims(now.Add(ClockSkew + time.Second))
	future, err := Sign(private, futureClaims)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, future, now); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("future err=%v", err)
	}
	tooLongClaims := fixtureClaims(now)
	tooLongClaims.ExpiresAt = now.Add(MaxLifetime + time.Second)
	tooLong, err := Sign(private, tooLongClaims)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, tooLong, now); !errors.Is(err, ErrLifetimeExceeded) {
		t.Fatalf("long lifetime err=%v", err)
	}
}

func TestCanonicalBytesRejectsIncompleteClaims(t *testing.T) {
	claims := fixtureClaims(time.Now().UTC())
	claims.Resource = ""
	if _, err := CanonicalBytes(SchemaVersion, claims); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err=%v", err)
	}
}

func fixtureClaims(now time.Time) Claims {
	return Claims{AssertionID: uuid.New(), WorkflowID: "nightly-reconciliation", RunID: "run-42", TriggerKind: "human", InitiatingSubjectRef: "user:opaque-123", Tool: "read_account", Resource: "mcp://finance/accounts", IssuedAt: now, ExpiresAt: now.Add(time.Minute), KeyID: "agent-signing-key-1"}
}
