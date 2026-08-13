package tenancy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// ⛔ DELETING AN ORGANIZATION IS A SOFT DELETE, SO EVERYTHING IT OWNED SURVIVES IT.
//
// The row gets `deleted_at` and nothing else happens: gateways keep carrying traffic on the customer's own
// servers, devices keep their pool addresses, machine credentials keep authenticating — all of it owned by
// an organization no screen will ever show again.
//
// > ## ⛔ **THAT IS NOT A DELETION, IT IS AN ABANDONMENT.**
//
// Both directions, because a refusal with no permitted case is indistinguishable from a broken button.
func TestAnOrganizationCannotBeDeletedWhileItOwnsAnything(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is the point

	org := uuid.New()
	if _, e := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'Doomed',$2)",
		org, "doomed-"+uuid.NewString()[:8]); e != nil {
		t.Fatal(e)
	}
	svc := &Service{q: sqlc.New(tx)}

	// ── EMPTY: the permitted case, asserted FIRST so a later failure cannot be read as "delete is broken".
	if e := svc.SoftDeleteOrganization(ctx, org); e != nil {
		t.Fatalf("⛔ an EMPTY organization could not be deleted — the guard has become a wall: %v", e)
	}

	// ── AND WITH A GATEWAY, REFUSED. A live node is the worst thing to strand: it is running on hardware
	// the operator can no longer see from any organization screen.
	org2 := uuid.New()
	if _, e := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'Busy',$2)",
		org2, "busy-"+uuid.NewString()[:8]); e != nil {
		t.Fatal(e)
	}
	if _, e := tx.Exec(ctx,
		"INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw-1',$3)",
		uuid.New(), org2, uuid.NewString()); e != nil {
		// ⛔ FATAL, NOT SKIP. A fixture that cannot be built means this test measured NOTHING — and a skip
		// reads as a pass in every summary. That is the exact shape this session has been fixing all day.
		t.Fatalf("could not build the blocked-org fixture: %v", e)
	}

	err = svc.SoftDeleteOrganization(ctx, org2)
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Code != "org_not_empty" {
		t.Fatalf("⛔ AN ORGANIZATION WITH A LIVE GATEWAY WAS DELETED. err = %v; want 409 org_not_empty", err)
	}
	// ⛔ THE MESSAGE NAMES THE BLOCKER. "Cannot delete" with no subject sends an operator hunting through
	// five screens; this is the one moment they are certain something is wrong and uncertain what.
	if !strings.Contains(ae.Message, "1 gateway") {
		t.Errorf("the refusal does not name what is blocking it: %s", ae.Message)
	}
	// And the org is still there — a refusal that half-applied would be worse than either outcome.
	var deleted *time.Time
	if e := tx.QueryRow(ctx, "SELECT deleted_at FROM organizations WHERE id=$1", org2).Scan(&deleted); e != nil {
		t.Fatal(e)
	}
	if deleted != nil {
		t.Error("⛔ the refusal still marked the organization deleted")
	}

	// ── THE PREFLIGHT AGREES WITH THE REFUSAL. Two renderings of one state is how a screen ends up saying
	// "nothing left" beside an error saying "1 gateway".
	res, e := svc.OrgResourceCount(ctx, org2)
	if e != nil {
		t.Fatal(e)
	}
	if res.Empty() || res.Gateways != 1 {
		t.Errorf("preflight = %+v, want 1 gateway and not empty", res)
	}
	if got := strings.Join(res.Blockers(), ", "); !strings.Contains(ae.Message, got) {
		t.Errorf("preflight blockers %q are not what the refusal said: %s", got, ae.Message)
	}

	// ── AND REVOKING IT UNBLOCKS THE DELETE. The counts are LIVE rows, so the operator's remedy actually
	// works — a count that included revoked gateways would make the org undeletable forever.
	if _, e := tx.Exec(ctx, "UPDATE nodes SET revoked_at = now() WHERE org_id = $1", org2); e != nil {
		t.Fatal(e)
	}
	if e := svc.SoftDeleteOrganization(ctx, org2); e != nil {
		t.Fatalf("⛔ the organization stayed undeletable after its gateway was revoked — the remedy the "+
			"refusal recommends does not work: %v", e)
	}
}
