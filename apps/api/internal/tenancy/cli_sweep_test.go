package tenancy

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestDeactivationSweepsCliCredentials pins the S5.1 sweep through the REAL
// trigger: DeactivateMember revokes every live CLI credential in the SAME tx
// as the status flip (session parity — S2.6 kills sessions, S5.1 credentials).
func TestDeactivationSweepsCliCredentials(t *testing.T) {
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
	q := sqlc.New(tx)

	org, actor, target := uuid.New(), uuid.New(), uuid.New()
	for _, s := range [][]any{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", org, "O", "cs-" + org.String()},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actor, actor.String() + "@t", "A"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", target, target.String() + "@t", "T"},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, target},
	} {
		if _, err := tx.Exec(ctx, s[0].(string), s[1:]...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	h := sha256.Sum256([]byte("tnx_deactivation-sweep-test"))
	if _, err := q.CreateCliCredential(ctx, sqlc.CreateCliCredentialParams{
		UserID: target, Name: "t", TokenHash: h[:], Fingerprint: "0123456789ab",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("credential: %v", err)
	}

	svc := &MembershipService{q: q} // tx-scoped; nil revoker/pusher are skipped
	if err := svc.DeactivateMember(ctx, actor, org, target); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := q.GetActiveCliCredentialByHash(ctx, h[:]); err == nil {
		t.Fatal("CLI credential survived deactivation — the sweep is broken")
	}
}
