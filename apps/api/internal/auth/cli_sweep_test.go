package auth

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestPasswordResetSweepsCliCredentials pins the S5.1 sweep through the REAL
// trigger: consuming a reset token revokes every live CLI credential in the
// same tx as the password change (a surviving header-borne credential would be
// a back door around the session revocation).
func TestPasswordResetSweepsCliCredentials(t *testing.T) {
	svc, _, cleanup := newTestAuth(t)
	defer cleanup()
	ctx := context.Background()

	// A verified user with a live CLI credential.
	if err := svc.Signup(ctx, "sweep@t.local", "Sweep", "a-long-password-123"); err != nil {
		t.Fatalf("signup: %v", err)
	}
	user, err := svc.q.GetUserByEmail(ctx, "sweep@t.local")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	tokHash := sha256.Sum256([]byte("tnx_sweep-test-credential"))
	cred, err := svc.q.CreateCliCredential(ctx, sqlc.CreateCliCredentialParams{
		UserID: user.ID, Name: "t", TokenHash: tokHash[:], Fingerprint: "abcdef012345",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := svc.q.GetActiveCliCredentialByHash(ctx, tokHash[:]); err != nil {
		t.Fatalf("credential should be live pre-reset: %v", err)
	}

	// The real trigger: request + consume a password reset.
	rawReset, resetHash, err := newToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if _, err := svc.q.CreateAuthToken(ctx, sqlc.CreateAuthTokenParams{
		UserID: user.ID, Purpose: purposeReset, TokenHash: resetHash, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("reset token: %v", err)
	}
	if err := svc.ResetPassword(ctx, rawReset, "another-long-password-456"); err != nil {
		t.Fatalf("reset: %v", err)
	}

	// SWEPT: the credential no longer authenticates.
	if _, err := svc.q.GetActiveCliCredentialByHash(ctx, tokHash[:]); err == nil {
		t.Fatalf("CLI credential %s survived the password reset — the sweep is broken", cred.ID)
	}
}
