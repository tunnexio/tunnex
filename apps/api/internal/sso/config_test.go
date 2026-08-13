package sso

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
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

// TestConfigSealAndDecryptAfterRestart proves the client secret is encrypted at
// rest and recoverable by a NEW sealer built from the SAME master key — the S0.3
// persistence property, now exercised with a real secret payload.
func TestConfigSealAndDecryptAfterRestart(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// A real org + actor user to satisfy the FKs (audit_logs.actor_user_id).
	org := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)",
		org, "O", "sso-"+org.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	actor := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'Actor')", actor, actor.String()+"@t.local"); err != nil {
		t.Fatalf("actor: %v", err)
	}

	masterKey := make([]byte, crypto.KeySize)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	const secret = "super-secret-google-client-secret"

	// Write with one sealer instance.
	writer := newConfigService(sqlc.New(tx), newSealer(t, masterKey))
	if err := writer.Set(ctx, actor, org, "google", "client-id-123", secret, "", true); err != nil {
		t.Fatalf("set: %v", err)
	}

	// (e) The config write records an actor-attributed audit row whose metadata
	// contains NO secret material — neither the plaintext secret nor the sealed
	// bytes may ever land in an audit_logs.metadata payload.
	var auditCount int
	var meta []byte
	if err := tx.QueryRow(ctx,
		"SELECT count(*) OVER (), metadata FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='sso.config_updated' LIMIT 1",
		org, actor).Scan(&auditCount, &meta); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("want 1 sso.config_updated audit row attributed to the actor, got %d", auditCount)
	}
	if contains(meta, secret) {
		t.Fatal("audit metadata contains the plaintext client secret")
	}
	var sealedBytes []byte
	if err := tx.QueryRow(ctx, "SELECT client_secret_sealed FROM sso_configs WHERE org_id=$1 AND provider='google'", org).Scan(&sealedBytes); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if contains(meta, string(sealedBytes)) {
		t.Fatal("audit metadata contains the sealed secret bytes")
	}
	// Positive check: the non-secret client_id IS present, so a regression that
	// drops the metadata entirely (which would trivially pass the no-secret
	// checks above) is still caught.
	if !contains(meta, "client-id-123") {
		t.Fatal("audit metadata missing the expected non-secret client_id")
	}

	// The stored bytes must NOT contain the plaintext.
	var stored []byte
	if err := tx.QueryRow(ctx, "SELECT client_secret_sealed FROM sso_configs WHERE org_id=$1 AND provider='google'", org).Scan(&stored); err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if len(stored) == 0 || contains(stored, secret) {
		t.Fatal("client secret stored in the clear")
	}

	// A fresh sealer from the SAME key (simulating a restart) decrypts it.
	reader := newConfigService(sqlc.New(tx), newSealer(t, masterKey))
	got, err := reader.Get(ctx, org, "google")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientSecret != secret {
		t.Fatalf("decrypted secret = %q, want %q", got.ClientSecret, secret)
	}

	// View is the display projection: it carries the KEYED fingerprint (matching
	// an independent HMAC of the same secret) and — structurally — no secret at
	// all (ConfigView has no secret field). This is what the settings GET returns.
	view, err := reader.View(ctx, org, "google")
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	wantFP := newSealer(t, masterKey).Fingerprint([]byte(secret))
	if wantFP == "" || view.SecretFingerprint != wantFP {
		t.Fatalf("view fingerprint = %q, want %q (keyed HMAC of the stored secret)", view.SecretFingerprint, wantFP)
	}
	if view.ClientID != "client-id-123" || !view.Enabled {
		t.Fatalf("view = %+v, want client-id-123 + enabled", view)
	}

	// A DIFFERENT key cannot decrypt it.
	otherKey := make([]byte, crypto.KeySize)
	_, _ = rand.Read(otherKey)
	wrong := newConfigService(sqlc.New(tx), newSealer(t, otherKey))
	if _, err := wrong.Get(ctx, org, "google"); err == nil {
		t.Fatal("wrong master key decrypted the secret")
	}
}

func contains(haystack []byte, needle string) bool {
	return len(needle) > 0 && bytesContains(haystack, []byte(needle))
}

func bytesContains(h, n []byte) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if string(h[i:i+len(n)]) == string(n) {
			return true
		}
	}
	return false
}
