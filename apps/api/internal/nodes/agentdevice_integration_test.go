package nodes

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestAgentDeviceRowsAreCapExempt — S15.2 slice 3.
//
// ⛔ THE CAP CONVENTION IS RIGHT FOR HUMANS AND WRONG FOR AGENTS. `CountDevicesForUserCap` counts active +
// pending (S7.3 finding #1: a pending device reserves a real /32, so excluding it was a cap bypass). An
// agent is now a `devices` row — so without an explicit exemption every gateway an admin enrolled would
// spend that admin's PERSONAL laptop allowance, and a fleet of gateways would be charged to one human.
//
// ⚠ THE SECOND HALF IS WHY THE FIRST MEANS ANYTHING. An exemption that counted NOTHING would pass a
// "agents are not counted" assertion and would silently disable the cap for humans too — the guard would be
// gone and the test would be green.
func TestAgentDeviceRowsAreCapExempt(t *testing.T) {
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
	q := sqlc.New(pool)

	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'A',$2,'10.95.0.0/24')`, org, "a-"+org.String()[:8])
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, owner, "ag-"+owner.String()[:8]+"@ex.com")
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,$3,$4)`,
		node, org, "gw-"+node.String()[:8], "s-"+node.String()[:8])

	count := func() int64 {
		n, e := q.CountDevicesForUserCap(ctx, sqlc.CountDevicesForUserCapParams{OrgID: org, UserID: owner})
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	mkDevice := func(kind, name string) {
		t.Helper()
		ex(`INSERT INTO devices (org_id, user_id, node_id, name, public_key, status, kind)
		    VALUES ($1,$2,$3,$4,$5,'active',$6)`, org, owner, node, name, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4="+name, kind)
	}

	if got := count(); got != 0 {
		t.Fatalf("baseline must be 0, got %d", got)
	}

	// ── A HUMAN'S DEVICE IS COUNTED — without this the exemption could be "count nothing" ────────────
	mkDevice("human", "laptop-"+org.String()[:6])
	if got := count(); got != 1 {
		t.Fatalf("a HUMAN device must count toward the cap; want 1, got %d", got)
	}

	// ── AN AGENT'S DEVICE IS NOT ────────────────────────────────────────────────────────────────────
	mkDevice("agent", "agent-"+org.String()[:6])
	if got := count(); got != 1 {
		t.Fatalf("an AGENT device must be cap-EXEMPT; the count must stay 1, got %d", got)
	}

	// ⛔ AND THE EXEMPTION IS NOT A LICENCE TO ACCUMULATE ADDRESSES. One agent device per node, enforced by
	// a partial unique index — otherwise a re-enrolment loop exhausts the org pool through a door the cap
	// now explicitly does not watch. That is the org-pool DoS the cap convention was written against.
	_, e := pool.Exec(ctx, `INSERT INTO devices (org_id, user_id, node_id, name, public_key, status, kind)
	    VALUES ($1,$2,$3,$4,$5,'active','agent')`, org, owner, node, "agent-dup", "E0+UqQyG5hBHoAo/AGNQaImKFk3LZUM7zBvHStspoIY=")
	if e == nil {
		t.Fatal("a SECOND agent device for the same node must be refused — a re-enrolment loop would " +
			"otherwise exhaust the org pool, and the cap no longer watches this door")
	}

	// ⚠ A SECOND HUMAN DEVICE ON THE SAME NODE IS STILL FINE — the uniqueness is scoped to agent rows, and
	// asserting only the refusal above would not catch an index that refused everything.
	mkDevice("human", "phone-"+org.String()[:6])
	if got := count(); got != 2 {
		t.Fatalf("a second HUMAN device must still count; want 2, got %d", got)
	}
}
