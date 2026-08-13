package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ⛔ THE ONE OPERATION IN THE PRODUCT THAT CROSSES A TENANT BOUNDARY (S12.11).
//
// Everything else is authorized by membership: `authorize()` asks `RoleIn(orgID)` and a caller who is not
// in the org reads as `org_not_found`. This asks a DIFFERENT question — does this account hold
// `users.cp_admin` — of a caller who is typically a member of NONE of the organizations they are editing.
//
// Four invariants, each with the refusal AND the permission, because a rule that only ever says no is
// indistinguishable from a broken feature.
func TestCrossOrgRoleGrants(t *testing.T) {
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

	mkUser := func(cpAdmin bool) uuid.UUID {
		id := uuid.New()
		if _, e := tx.Exec(ctx, "INSERT INTO users (id,email,name,cp_admin,status) VALUES ($1,$2,'U',$3,'active')",
			id, id.String()+"@t.local", cpAdmin); e != nil {
			t.Fatal(e)
		}
		return id
	}
	mkOrg := func(owner uuid.UUID) uuid.UUID {
		id := uuid.New()
		if _, e := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)",
			id, "o-"+uuid.NewString()[:8]); e != nil {
			t.Fatal(e)
		}
		if _, e := tx.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')",
			id, owner); e != nil {
			t.Fatal(e)
		}
		return id
	}
	roleIn := func(org, user uuid.UUID) string {
		var r string
		if e := tx.QueryRow(ctx, "SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2", org, user).
			Scan(&r); e != nil {
			return ""
		}
		return r
	}

	svc := &Service{q: sqlc.New(tx)}

	// ⚠ THE ACTOR IS A MEMBER OF NOTHING, and that is not a convenience of the fixture — it is the state
	// this feature exists for. The bootstrap administrator of a deployment need never join a tenant.
	admin := mkUser(true)
	tenantOwner := mkUser(false)
	newcomer := mkUser(false)
	orgA := mkOrg(tenantOwner)
	otherOwner := mkUser(false)
	orgB := mkOrg(otherOwner)

	// ── 1. THE GRANT ITSELF: no membership becomes one, across a boundary the actor has not crossed ────
	if e := svc.GrantOrgRole(ctx, admin, "admin@t.local", orgA, newcomer, rbac.RoleAdmin); e != nil {
		t.Fatalf("⛔ the deployment administrator could not grant a role in an organization they are not "+
			"in — which is the entire capability: %v", e)
	}
	if got := roleIn(orgA, newcomer); got != rbac.RoleAdmin {
		t.Fatalf("role after first grant = %q, want admin (the membership must be CREATED, not merely updated)", got)
	}
	// And it changes an existing one.
	if e := svc.GrantOrgRole(ctx, admin, "admin@t.local", orgA, newcomer, rbac.RoleOwner); e != nil {
		t.Fatalf("re-grant failed: %v", e)
	}
	if got := roleIn(orgA, newcomer); got != rbac.RoleOwner {
		t.Fatalf("role after re-grant = %q, want owner", got)
	}

	// ── 2. ⛔ THE LAST OWNER — REFUSED, THEN ALLOWED ───────────────────────────────────────────────────
	//
	// orgB has exactly one owner. A cross-tenant actor is the person MOST likely to demote them by
	// accident: they cannot see the roster they are editing, so "make this person a member" looks
	// identical whether or not that person is the only owner left. An org with no owner can never be
	// administered from inside again.
	err = svc.GrantOrgRole(ctx, admin, "admin@t.local", orgB, otherOwner, rbac.RoleMember)
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Code != "last_owner" {
		t.Fatalf("⛔ THE SOLE OWNER OF AN ORGANIZATION WAS DEMOTED FROM OUTSIDE IT. err = %v; want 409 last_owner", err)
	}
	if got := roleIn(orgB, otherOwner); got != rbac.RoleOwner {
		t.Fatalf("the refusal did not hold: role is now %q", got)
	}
	// ⭐ THE SECOND DIRECTION, WHICH IS THE RULING. Give orgB a second owner and the same demotion must
	// succeed — otherwise "cannot demote an owner" would be the rule, and this feature could never fix a
	// mis-assigned role.
	if e := svc.GrantOrgRole(ctx, admin, "admin@t.local", orgB, newcomer, rbac.RoleOwner); e != nil {
		t.Fatal(e)
	}
	if e := svc.GrantOrgRole(ctx, admin, "admin@t.local", orgB, otherOwner, rbac.RoleMember); e != nil {
		t.Fatalf("⛔ a demotion was refused with TWO owners present — the last-owner guard has become a "+
			"blanket refusal, and no mis-assigned owner can ever be corrected: %v", e)
	}

	// ── 3. ⛔ AUDITED INTO THE TARGET ORGANIZATION'S LOG — who, what, WHICH ORG ────────────────────────
	//
	// The org's own owners read one feed: their own. A privilege change made inside their tenant by
	// somebody outside it is exactly the event they are owed sight of, and a row filed anywhere else is a
	// row they will never see.
	var rows int
	var actor uuid.UUID
	var meta []byte
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs
	    WHERE org_id=$1 AND action='member.role_granted_by_cp_admin'`, orgA).Scan(&rows); e != nil {
		t.Fatal(e)
	}
	if rows != 2 { // the create + the change; the no-op re-grant writes nothing
		t.Fatalf("orgA carries %d cross-tenant grant rows, want 2", rows)
	}
	if e := tx.QueryRow(ctx, `SELECT actor_user_id, metadata FROM audit_logs
	    WHERE org_id=$1 AND action='member.role_granted_by_cp_admin' ORDER BY created_at LIMIT 1`, orgA).
		Scan(&actor, &meta); e != nil {
		t.Fatal(e)
	}
	if actor != admin {
		t.Errorf("the row does not name WHO acted: actor=%v want %v", actor, admin)
	}
	var m map[string]any
	if e := json.Unmarshal(meta, &m); e != nil {
		t.Fatal(e)
	}
	// ⚠ THE ACTOR'S EMAIL IS IN THE ROW BECAUSE THE ROSTER CANNOT NAME THEM. The audit screen resolves an
	// actor id against the org's members; an id that is not on that list renders as "former member
	// 019fc421" — a confident false claim about somebody who was never a member at all.
	if m["actor_email"] != "admin@t.local" || m["actor_kind"] != "cp_admin" {
		t.Errorf("⛔ the row cannot name a cross-tenant actor: %v", m)
	}
	if r, ok := m["role"].(map[string]any); !ok || r["to"] != rbac.RoleAdmin {
		t.Errorf("the row does not say WHAT changed: %v", m["role"])
	}
	// ⛔ AND NOT SOMEWHERE ELSE. A grant filed under an org it was not made in would put one tenant's
	// history in another's feed. The grants above targeted orgA and orgB only.
	//
	// ⚠ SCOPED TO THIS TEST'S ACTOR, AND IT WAS NOT AT FIRST. The unscoped version counted every row of
	// this action in a SHARED database and went red the moment the e2e suite exercised the same surface —
	// reporting six strays that were somebody else's perfectly correct rows. A global assertion inside a
	// per-test transaction is a claim about the whole deployment, which is not what this leg is checking.
	var strays int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs
	    WHERE action='member.role_granted_by_cp_admin' AND actor_user_id = $3
	      AND (org_id IS NULL OR org_id NOT IN ($1,$2))`,
		orgA, orgB, admin).Scan(&strays); e != nil {
		t.Fatal(e)
	}
	if strays != 0 {
		t.Errorf("⛔ %d cross-tenant grant rows landed outside the organizations they were made in", strays)
	}

	// ── 4. ⛔ THE LAST DEPLOYMENT ADMINISTRATOR — REFUSED, THEN ALLOWED ────────────────────────────────
	//
	// There is no public signup. A deployment with zero holders cannot create an organization, cannot
	// grant a role, and has no way back that does not involve a database client.
	//
	// ⚠ Other rows in this shared database may hold the capability, so the leg is made deterministic by
	// clearing it for everyone else INSIDE the rolled-back transaction — otherwise "the last one" would
	// depend on what the seed happened to leave behind and the guard could never be reached.
	if _, e := tx.Exec(ctx, "UPDATE users SET cp_admin=false WHERE id <> $1", admin); e != nil {
		t.Fatal(e)
	}
	err = svc.SetCPAdmin(ctx, admin, admin, false)
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Code != "last_cp_admin" {
		t.Fatalf("⛔ THE LAST DEPLOYMENT ADMINISTRATOR REVOKED THEMSELVES. The deployment is now "+
			"unadministrable and has no signup to recover through. err = %v; want 409 last_cp_admin", err)
	}
	// ⭐ THE SECOND DIRECTION: with a successor in place the same revoke must go through, or the
	// capability would be permanent-by-accident and a departing administrator could never be removed.
	if e := svc.SetCPAdmin(ctx, admin, tenantOwner, true); e != nil {
		t.Fatalf("granting the capability to a second account failed: %v", e)
	}
	if e := svc.SetCPAdmin(ctx, admin, admin, false); e != nil {
		t.Fatalf("⛔ a holder could not step down with a successor present — the guard has become "+
			"'nobody may ever be revoked': %v", e)
	}
	var stillAdmin bool
	if e := tx.QueryRow(ctx, "SELECT cp_admin FROM users WHERE id=$1", admin).Scan(&stillAdmin); e != nil {
		t.Fatal(e)
	}
	if stillAdmin {
		t.Error("the revoke reported success and changed nothing")
	}
	// The deployment-scoped rows carry no org — they belong to no tenant (see writeDeploymentAudit).
	var deployRows int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs
	    WHERE org_id IS NULL AND action IN ('cp_admin.granted','cp_admin.revoked') AND actor_user_id=$1`,
		admin).Scan(&deployRows); e != nil {
		t.Fatal(e)
	}
	if deployRows != 2 {
		t.Errorf("deployment-scoped audit rows = %d, want 2 (one grant, one revoke)", deployRows)
	}
}

// ⚠ A DEACTIVATED HOLDER IS NOT A HOLDER WHO CAN SIGN IN, and the guard counts the ones who can.
//
// SessionAuth 401s a deactivated account, so counting one as the last administrator would let the
// deployment reach the state the guard exists to prevent: it reports a holder, and no human can log in.
// The symmetric error is worse in the other direction too — refusing to revoke a DEACTIVATED holder while a
// live one exists would be a refusal that protects nothing.
func TestDeactivatedHolderDoesNotCountAsTheLastAdministrator(t *testing.T) {
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
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e := tx.Exec(ctx, "UPDATE users SET cp_admin=false"); e != nil {
		t.Fatal(e)
	}
	mk := func(status string) uuid.UUID {
		id := uuid.New()
		if _, e := tx.Exec(ctx, "INSERT INTO users (id,email,name,cp_admin,status) VALUES ($1,$2,'U',true,$3)",
			id, id.String()+"@t.local", status); e != nil {
			t.Fatal(e)
		}
		return id
	}
	live, frozen := mk("active"), mk("deactivated")
	svc := &Service{q: sqlc.New(tx)}

	// Revoking the frozen holder leaves the live one — permitted.
	if e := svc.SetCPAdmin(ctx, live, frozen, false); e != nil {
		t.Fatalf("⛔ revoking a DEACTIVATED holder was refused while a live administrator exists — the "+
			"guard is counting accounts that cannot sign in: %v", e)
	}
	// Revoking the live one now leaves nobody who can sign in — refused.
	err = svc.SetCPAdmin(ctx, live, live, false)
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "last_cp_admin" {
		t.Fatalf("err = %v; want last_cp_admin", err)
	}
}
