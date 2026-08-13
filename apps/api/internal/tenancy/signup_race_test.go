package tenancy

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPublicSignupIsClosedWhileUsersExist — the live half of the race fix.
//
// ⛔ THE RACE: the gate used to ask SetupComplete, "has this deployment ever had an ORGANIZATION". That is
// ZERO on a fresh install, so between `docker compose up` and the operator creating the first org,
// `/auth/signup` was OPEN — and on a public address that window belongs to whoever finds it first: sign up,
// create the first organization, own the deployment.
//
// ⚠ `curl … | sh` TURNS THAT WINDOW INTO A PRODUCT FEATURE. The installer ends with a running, publicly
// reachable, UNCLAIMED control plane, and the gap until the operator reads the first-run credential is the
// attacker's opportunity.
//
// ⛔ WHAT THIS TEST CANNOT DO, SAID PLAINLY: it cannot reach the zero-user state. `audit_logs` is
// append-only at the DATABASE layer — UPDATE, DELETE and TRUNCATE all raise — so clearing users on a shared
// database is impossible by construction, and that property is correct and worth more than this
// convenience. So this proves the CLOSED direction on real data, and
// TestSignupGateIsKeyedOnUsersNotOrganizations (below) proves the gate is keyed on the right question.
// Neither alone is the whole claim; together they are.
func TestPublicSignupIsClosedWhileUsersExist(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	svc := NewService(pool)

	var users int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	// ⛔ THE VACUITY FLOOR. With zero users this test would assert nothing and pass, reporting "signup is
	// correctly closed" about a database where it is correctly OPEN.
	if users == 0 {
		t.Skip("this database has no users — the closed direction cannot be observed here")
	}

	open, err := svc.PublicSignupOpen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("users exist and public signup is still open — a stranger can sign up and, while no " +
			"organization exists yet, create the first one and own the deployment")
	}
}
