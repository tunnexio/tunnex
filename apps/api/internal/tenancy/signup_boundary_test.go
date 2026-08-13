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
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ⛔ SIGNING UP CREATES AN ACCOUNT. IT MUST NEVER CREATE AN ORGANIZATION.
//
// `/api/v1/auth/signup` is `security: []` — open to anyone who can reach the deployment, with no
// invitation, no allow-list and no domain restriction. Until this boundary existed, a stranger could sign
// up, verify an email they control, and become OWNER of a new organization on a private VPN control plane.
//
// ⛔ AND THE ONLY THING STOPPING THEM WAS A COMMERCIAL NUMBER — the org ceiling, which held it to one on
// Community and which the customer PAYS TO RAISE.
//
// > ## ⛔ **THE PRODUCT WAS SELLING THE REMOVAL OF ITS ONLY SIGNUP CONTROL.**
func TestOnlyBootstrapOrInsidersMayCreateAnOrg(t *testing.T) {
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

	// ⛔ HARD-DELETE INSIDE THE ROLLED-BACK TX, NOT A SOFT ONE. The bootstrap window keys on
	// CountOrganizationsEver, which counts soft-deleted rows precisely so deletion cannot reopen setup —
	// so soft-deleting here would leave `ever > 0` and the bootstrap leg would never be exercised.
	// ⚠ TRIGGERS OFF FOR THIS TRANSACTION ONLY. audit_logs is append-only and its trigger REFUSES the
	// SET NULL the org-delete cascade attempts, so a plain DELETE cannot clear the table. Scoped to this
	// tx, which is rolled back — the same bypass sso_config_payload_enterprise_test.go uses.
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		t.Skipf("cannot disable triggers in this database: %v", err)
	}
	for _, stmt := range []string{"DELETE FROM memberships", "DELETE FROM organizations"} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Skipf("cannot clear for the bootstrap leg (%s): %v", stmt, err)
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = DEFAULT"); err != nil {
		t.Fatal(err)
	}

	mkUser := func() uuid.UUID {
		id := uuid.New()
		if _, e := tx.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'U')",
			id, id.String()+"@t.local"); e != nil {
			t.Fatal(e)
		}
		return id
	}

	// ⚠ A PAID LICENCE THROUGHOUT, DELIBERATELY: it proves this boundary is NOT the org ceiling wearing a
	// different hat. With multi_org unlocked the ceiling permits every creation below, so only the new
	// check can refuse — which is the whole point, since the ceiling is a number customers PAY to raise.
	svc := (&Service{q: sqlc.New(tx)}).WithLicence(
		licence.NewTestManager("growth", time.Now().Add(time.Hour)))

	// ── 1. BOOTSTRAP: never been set up, so somebody has to make the first one ────────────────────────
	founder := mkUser()
	first, err := svc.CreateOrganization(ctx, founder, "First", "first-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatalf("⛔ THE FIRST ORGANIZATION ON A FRESH DEPLOYMENT WAS REFUSED — the product cannot be "+
			"installed at all: %v", err)
	}

	// ── 2. THE HOLE, CLOSED: a verified stranger with no membership ───────────────────────────────────
	stranger := mkUser()
	_, err = svc.CreateOrganization(ctx, stranger, "Theirs", "theirs-"+uuid.NewString()[:8])
	if err == nil {
		t.Fatal("⛔ A STRANGER BECAME OWNER OF A NEW ORGANIZATION. Signup is open to anyone who can reach " +
			"this deployment, so this is self-service ownership of someone's VPN control plane")
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "invitation_required" {
		t.Errorf("refusal = %v; want 403 invitation_required", err)
	} else if !strings.Contains(ae.Message, "invite") {
		// ⚠ It must TELL them how to get in. The funnel routes every 0-membership user to this form, so a
		// silent refusal leaves them staring at a page that will never work.
		t.Errorf("the refusal does not mention being invited: %s", ae.Message)
	}

	// ── 3. ⛔ MEMBERSHIP IS NOT THE CAPABILITY — THE WHOLE RULING IN ONE ASSERTION ────────────────────
	//
	// A member of an existing organization is an INSIDER and still may not create. Authority inside org A
	// cannot license an act that creates org B. Without this leg the boundary is just "signed up vs not",
	// which any invited member trivially clears.
	member := mkUser()
	if _, e := tx.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')",
		first.ID, member); e != nil {
		t.Fatal(e)
	}
	if _, e := svc.CreateOrganization(ctx, member, "ByMember", "bymember-"+uuid.NewString()[:8]); e == nil {
		t.Fatal("⛔ A MEMBER OF ANOTHER ORGANIZATION CREATED ONE. Being admitted to org A is not authority " +
			"over the deployment, and this is the ruling the whole change exists for")
	}

	// ── 4. A HOLDER MAY. The bootstrap founder was granted the capability in the same tx that used it. ─
	if _, e := svc.CreateOrganization(ctx, founder, "Second", "second-"+uuid.NewString()[:8]); e != nil {
		t.Errorf("⛔ the capability holder was refused — the paid multi_org capability is unreachable "+
			"and the deployment cannot grow: %v", e)
	}
	// ⚠ AND THE GRANT PERSISTED. Bootstrap's condition is destroyed by using it, so authority that was
	// only implied by `ever == 0` would evaporate the instant the first org existed.
	var may bool
	if e := tx.QueryRow(ctx, "SELECT cp_admin FROM users WHERE id=$1", founder).Scan(&may); e != nil {
		t.Fatal(e)
	}
	if !may {
		t.Error("⛔ bootstrap did not GRANT the capability, only exercised it — the founder would lose the " +
			"ability to create anything the moment the first organization existed")
	}

	// ── 4. ⛔ DELETING EVERY ORG MUST NOT REOPEN SETUP ────────────────────────────────────────────────
	//
	// Organizations are soft-deletable and `CountOrganizations` filters `deleted_at IS NULL`. Keyed on
	// that, deleting them all restores the bootstrap condition and the next verified account to reach the
	// funnel becomes owner of the deployment. `CountOrganizationsEver` counts soft-deleted rows so the
	// window shuts once and stays shut.
	if _, e := tx.Exec(ctx, "UPDATE organizations SET deleted_at = now() WHERE deleted_at IS NULL"); e != nil {
		t.Fatal(e)
	}
	outsider := mkUser()
	if _, e := svc.CreateOrganization(ctx, outsider, "Reopened", "reopened-"+uuid.NewString()[:8]); e == nil {
		t.Fatal("⛔ SETUP REOPENED AFTER EVERY ORGANIZATION WAS DELETED. A stranger just claimed a " +
			"deployment that had already been set up — the bootstrap window must close once, permanently")
	}

	// ── 5. ⛔ THE OWNER INVARIANT SURVIVES. An org with no owner is unadministrable forever. ───────────
	var owners int64
	if e := tx.QueryRow(ctx,
		"SELECT count(*) FROM memberships WHERE org_id=$1 AND role=$2", first.ID, rbac.RoleOwner).
		Scan(&owners); e != nil {
		t.Fatal(e)
	}
	if owners != 1 {
		t.Errorf("⛔ the bootstrap org has %d owners, want exactly 1 — the org row and its owner "+
			"membership are written in ONE transaction precisely so this cannot drift", owners)
	}
}
