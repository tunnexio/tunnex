package agentca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func newSealer(t *testing.T, key []byte) *crypto.Sealer {
	t.Helper()
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func setup(t *testing.T) (*sqlc.Queries, context.Context, []byte) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	key := make([]byte, crypto.KeySize)
	_, _ = rand.Read(key)
	return sqlc.New(tx), ctx, key
}

func TestCALoadOrCreateAndReuse(t *testing.T) {
	q, ctx, key := setup(t)
	ca, created, err := LoadOrCreate(ctx, q, newSealer(t, key))
	if err != nil || !created {
		t.Fatalf("first LoadOrCreate: created=%v err=%v", created, err)
	}
	if err := ca.SelfTest(); err != nil {
		t.Fatalf("selftest: %v", err)
	}
	// Reload with the SAME master key -> same CA, not regenerated.
	ca2, created2, err := LoadOrCreate(ctx, q, newSealer(t, key))
	if err != nil || created2 {
		t.Fatalf("reload: created=%v err=%v", created2, err)
	}
	if ca.Fingerprint() != ca2.Fingerprint() {
		t.Fatal("CA fingerprint changed across loads — regenerated!")
	}
}

func TestCAWrongKeyFailsLoud(t *testing.T) {
	q, ctx, key := setup(t)
	if _, _, err := LoadOrCreate(ctx, q, newSealer(t, key)); err != nil {
		t.Fatalf("create: %v", err)
	}
	other := make([]byte, crypto.KeySize)
	_, _ = rand.Read(other)
	if _, _, err := LoadOrCreate(ctx, q, newSealer(t, other)); err == nil {
		t.Fatal("wrong master key must fail loud, not regenerate")
	}
}

func TestCASignedCertVerifiesAndExpires(t *testing.T) {
	q, ctx, key := setup(t)
	ca, _, err := LoadOrCreate(ctx, q, newSealer(t, key))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	// SelfTest already signs+verifies a leaf against the pool; assert TTL bound.
	if CertTTL < time.Hour || CertTTL > 96*time.Hour {
		t.Fatalf("cert TTL %v outside the short-lived range", CertTTL)
	}
	if len(ca.CertPEM()) == 0 || ca.Pool() == nil {
		t.Fatal("CA cert/pool missing")
	}
}

// TestSignCSRRefusesKeyTypesRecoveryCannotVerify — review pass 1 #17.
//
// rekey.Verify narrowed to RSA deliberately and wrote down why. The ISSUER that populates the very field that
// verifier reads was never narrowed to match, so a node enrolling with an ECDSA key received a perfectly good
// certificate and a recorded public key its own recovery path can never verify — proof-of-possession recovery
// silently and permanently unavailable for that node, with nothing saying so until the day it is needed.
func TestSignCSRRefusesKeyTypesRecoveryCannotVerify(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "gw"}}, ek)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	q, ctx, key := setup(t)
	ca, _, cerr := LoadOrCreate(ctx, q, newSealer(t, key))
	if cerr != nil {
		t.Fatal(cerr)
	}
	if _, err := ca.SignCSR(csrPEM, "gw"); err == nil {
		t.Fatal("issuing over a key type the recovery verifier cannot accept must be REFUSED at the door: the " +
			"certificate would work and the recovery would not, and nothing would say so until it was needed")
	}
}

// TestCertTTLOnlyEverSHORTENS — the knob's security property, asserted in the direction that matters.
//
// Revocation in this product IS refusal-to-renew, so the certificate lifetime is exactly the window a revoked
// agent keeps working. The knob exists because an expired certificate cannot be manufactured — the clock is the
// only way — and rehearsing recovery at 48h per subject is impractical. It must therefore be impossible to use it
// to LENGTHEN that window, from any environment, by any typo.
func TestCertTTLOnlyEverSHORTENS(t *testing.T) {
	for _, c := range []struct {
		set  string
		want time.Duration
		why  string
	}{
		{"", MaxCertTTL, "unset must be the shipped default"},
		{"10m", 10 * time.Minute, "a shorter TTL is honoured — that is the point"},
		{"720h", MaxCertTTL, "a MONTH must be clamped to the ceiling: lengthening weakens revocation for the " +
			"entire fleet, and no environment may do that at runtime"},
		{"49h", MaxCertTTL, "one hour over the ceiling is still over the ceiling"},
		{"1s", MinCertTTL, "below the floor an agent races its own renewal"},
		{"not-a-duration", MaxCertTTL, "an unparseable value must fall back to the SAFE default, never to zero"},
	} {
		t.Setenv("TUNNEX_AGENT_CERT_TTL", c.set)
		if got := resolveCertTTL(); got != c.want {
			t.Errorf("TUNNEX_AGENT_CERT_TTL=%q -> %v, want %v: %s", c.set, got, c.want, c.why)
		}
	}
}
