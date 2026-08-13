package tenancy

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ REWRITTEN, NOT DELETED (S12.1). It used to assert the boundary was the BUILD: the open build capped
// org creation at one, `-tags enterprise` did not. That boundary no longer exists — `enterprise.Unlimited`
// is a compatibility constant that is always true, so under the old assertions the enterprise leg demanded
// unlimited orgs and got the Community band.
//
// ⚠ THAT IS THE REAL FINDING, AND IT IS ABOUT WHEN IT SURFACED. The failure was created by slice 5 and
// only appeared here, at the end, because the tagged leg runs ONLY under `make test-editions` — a package
// test run never executes it. A guard that runs in one gate leg is invisible to every other check.
//
// The boundary is now the LICENCE, and this asserts it from both sides in one run rather than from two
// builds. It runs inside a transaction that zeroes live orgs and is always rolled back.
func TestOrgLimitByLicence(t *testing.T) {
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
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is the point

	// Start from a clean slate within the (rolled-back) transaction.
	// ⛔ HARD-DELETE, NOT SOFT (S12.5 signup boundary). This used to soft-delete, which leaves
	// `CountOrganizationsEver > 0` — so the fresh creator below is a STRANGER on an already-set-up
	// deployment and is correctly refused `invitation_required`. This test is about the CEILING, not the
	// admission boundary, so it needs a genuinely never-set-up deployment.
	//
	// ⚠ Triggers off for this tx only: audit_logs is append-only and refuses the SET NULL the org cascade
	// attempts. Rolled back either way.
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		t.Skipf("cannot disable triggers: %v", err)
	}
	for _, stmt := range []string{"DELETE FROM memberships", "DELETE FROM organizations"} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Skipf("cannot clear (%s): %v", stmt, err)
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = DEFAULT"); err != nil {
		t.Fatal(err)
	}

	creator := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,$3)",
		creator, "creator-"+creator.String()+"@t", "Creator"); err != nil {
		t.Fatalf("create creator: %v", err)
	}

	// ── Community: one organization, then a typed refusal ────────────────────────────────────────────
	unlicensed := &Service{q: sqlc.New(tx)}

	if _, err := unlicensed.CreateOrganization(ctx, creator, "Licence A", "licence-test-a"); err != nil {
		t.Fatalf("the first org must always succeed: %v", err)
	}

	_, err = unlicensed.CreateOrganization(ctx, creator, "Licence B", "licence-test-b")
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("Community: expected *apierr.Error, got %v", err)
	}
	// ⛔ THE CODE IS LOAD-BEARING BEYOND THIS TEST: apps/web's CreateOrg funnel branches on
	// `org_limit_reached` to swap the form for an invitation-only card.
	if apiErr.Code != "org_limit_reached" || apiErr.Status != 403 {
		t.Fatalf("Community: expected 403 org_limit_reached, got %d %s", apiErr.Status, apiErr.Code)
	}

	// ── A paid licence: the same call, the same data, allowed ────────────────────────────────────────
	//
	// ⭐ THE SAME TRANSACTION AND THE SAME ROW COUNT. Only the licence differs, so a pass here cannot be
	// explained by anything except the entitlement being read.
	licensed := (&Service{q: sqlc.New(tx)}).WithLicence(licence.NewTestManager("starter", time.Now().Add(time.Hour)))
	if _, err := licensed.CreateOrganization(ctx, creator, "Licence C", "licence-test-c"); err != nil {
		t.Fatalf("⛔ A PAID LICENCE WAS REFUSED A SECOND ORGANIZATION — the customer paid for multi_org "+
			"and cannot use it: %v", err)
	}

	// ── And a LAPSED paid licence falls back to Community ────────────────────────────────────────────
	lapsed := (&Service{q: sqlc.New(tx)}).WithLicence(licence.NewTestManager("starter", time.Now().Add(-100*24*time.Hour)))
	if _, err := lapsed.CreateOrganization(ctx, creator, "Licence D", "licence-test-d"); err == nil {
		t.Error("⛔ a licence lapsed past its full grace period still created organizations past the " +
			"Community band")
	}
}
