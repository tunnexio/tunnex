package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// RBAC-0 (docs/RBAC-0-people-management-security.md) D3/D6 regression tests at the service seam.

type rbac0Org struct {
	ctx  context.Context
	pool *pgxpool.Pool
	q    *sqlc.Queries
	svc  *MembershipService
}

func newRBAC0Org(t *testing.T) *rbac0Org {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	return &rbac0Org{ctx: ctx, pool: pool, q: sqlc.New(pool), svc: NewMembershipService(pool, &fakeRevoker{})}
}

func (o *rbac0Org) org(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := o.pool.Exec(o.ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'RBAC-0',$2)`, id, "rbac0-"+id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func (o *rbac0Org) user(t *testing.T, memberships map[uuid.UUID]string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := o.pool.Exec(o.ctx, `INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'RBAC-0',now())`, id, id.String()+"@rbac0.test"); err != nil {
		t.Fatal(err)
	}
	for org, role := range memberships {
		if _, err := o.pool.Exec(o.ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)`, org, id, role); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (o *rbac0Org) status(t *testing.T, user uuid.UUID) string {
	t.Helper()
	var s string
	if err := o.pool.QueryRow(o.ctx, `SELECT status FROM users WHERE id=$1`, user).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (o *rbac0Org) hasAccess(t *testing.T, org, user uuid.UUID) bool {
	t.Helper()
	_, err := o.q.GetMembership(o.ctx, sqlc.GetMembershipParams{OrgID: org, UserID: user})
	return err == nil
}

func rbac0Code(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// D3: deactivating a person in org A must not lock them out of org B, where they are an owner.
func TestRBAC0DeactivationIsOrgScopedForMultiOrgPeople(t *testing.T) {
	o := newRBAC0Org(t)
	a, b := o.org(t), o.org(t)
	actor := o.user(t, map[uuid.UUID]string{a: "owner"})
	multi := o.user(t, map[uuid.UUID]string{a: "member", b: "owner"})
	if err := o.svc.DeactivateMember(o.ctx, actor, "owner", a, multi); err != nil {
		t.Fatal(err)
	}
	if got := o.status(t, multi); got != "active" {
		t.Fatalf("deactivation in A flipped the account-wide status to %q, locking them out of B", got)
	}
	if o.hasAccess(t, a, multi) {
		t.Fatal("deactivated person kept access to A")
	}
	if !o.hasAccess(t, b, multi) {
		t.Fatal("deactivation in A removed access to B")
	}
	// Reactivating in A restores A, and only A.
	if err := o.svc.ReactivateMember(o.ctx, actor, "owner", a, multi); err != nil {
		t.Fatal(err)
	}
	if !o.hasAccess(t, a, multi) {
		t.Fatal("reactivation did not restore access to A")
	}
}

// D3: one org's directory sync must not deactivate the person account-wide when they belong elsewhere.
func TestRBAC0DirectorySyncIsOrgScopedForMultiOrgPeople(t *testing.T) {
	o := newRBAC0Org(t)
	a, b := o.org(t), o.org(t)
	o.user(t, map[uuid.UUID]string{a: "owner"})
	multi := o.user(t, map[uuid.UUID]string{a: "member", b: "owner"})
	if _, err := o.svc.DeactivateMemberBySync(o.ctx, a, multi, "disabled_in_directory"); err != nil {
		t.Fatal(err)
	}
	if got := o.status(t, multi); got != "active" {
		t.Fatalf("A's directory sync deactivated the account-wide status (%q)", got)
	}
	if o.hasAccess(t, a, multi) || !o.hasAccess(t, b, multi) {
		t.Fatal("directory sync must remove A's access and only A's")
	}
}

// D3: a person must not reverse directory sync's deprovisioning.
func TestRBAC0ReactivationDoesNotReverseDirectorySync(t *testing.T) {
	o := newRBAC0Org(t)
	a := o.org(t)
	actor := o.user(t, map[uuid.UUID]string{a: "owner"})
	single := o.user(t, map[uuid.UUID]string{a: "member"})
	if _, err := o.svc.DeactivateMemberBySync(o.ctx, a, single, "disabled_in_directory"); err != nil {
		t.Fatal(err)
	}
	if err := o.svc.ReactivateMember(o.ctx, actor, "owner", a, single); rbac0Code(err) != "directory_managed" {
		t.Fatalf("reactivating a directory-deprovisioned person: want directory_managed, got %v", err)
	}
	if got := o.status(t, single); got != "deactivated" {
		t.Fatalf("status = %q", got)
	}
	// The org-scoped form (directory provenance exhausted) is refused the same way.
	multi := o.user(t, map[uuid.UUID]string{a: "member", o.org(t): "member"})
	if _, err := o.svc.RevokeOrgAccessBySync(o.ctx, a, multi, "directory_provenance_exhausted"); err != nil {
		t.Fatal(err)
	}
	if err := o.svc.ReactivateMember(o.ctx, actor, "owner", a, multi); rbac0Code(err) != "directory_managed" {
		t.Fatalf("reactivating a directory-revoked membership: want directory_managed, got %v", err)
	}
}

// D3: org B's admin must not reverse a deactivation that org A made.
func TestRBAC0ReactivationDoesNotReverseAnotherOrg(t *testing.T) {
	o := newRBAC0Org(t)
	a, b := o.org(t), o.org(t)
	actorA := o.user(t, map[uuid.UUID]string{a: "owner"})
	actorB := o.user(t, map[uuid.UUID]string{b: "owner"})
	person := o.user(t, map[uuid.UUID]string{a: "member"})
	if err := o.svc.DeactivateMember(o.ctx, actorA, "owner", a, person); err != nil {
		t.Fatal(err)
	}
	// Later the person is added to B (e.g. by a deployment administrator) while deactivated.
	if _, err := o.pool.Exec(o.ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, b, person); err != nil {
		t.Fatal(err)
	}
	if err := o.svc.ReactivateMember(o.ctx, actorB, "owner", b, person); rbac0Code(err) != "deactivated_elsewhere" {
		t.Fatalf("B reactivating A's deactivation: want deactivated_elsewhere, got %v", err)
	}
	if got := o.status(t, person); got != "deactivated" {
		t.Fatalf("status = %q", got)
	}
}

// D6: a deactivated owner must not satisfy the last-owner guard.
func TestRBAC0DeadOwnerDoesNotSatisfyLastOwnerGuard(t *testing.T) {
	o := newRBAC0Org(t)
	a := o.org(t)
	live := o.user(t, map[uuid.UUID]string{a: "owner"})
	dead := o.user(t, map[uuid.UUID]string{a: "owner"})
	if _, err := o.pool.Exec(o.ctx, `UPDATE users SET status='deactivated' WHERE id=$1`, dead); err != nil {
		t.Fatal(err)
	}
	if n, err := o.q.CountOwners(o.ctx, a); err != nil || n != 1 {
		t.Fatalf("CountOwners must count only active owners: n=%d err=%v", n, err)
	}
	if _, err := o.svc.ChangeMemberRole(o.ctx, &live, "owner", a, live, "admin"); rbac0Code(err) != "last_owner" {
		t.Fatalf("demoting the only ACTIVE owner: want last_owner, got %v", err)
	}
	// A revoked owner membership is not an owner either.
	revoked := o.user(t, map[uuid.UUID]string{a: "owner"})
	if _, err := o.pool.Exec(o.ctx, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, a, revoked); err != nil {
		t.Fatal(err)
	}
	if n, err := o.q.CountOwners(o.ctx, a); err != nil || n != 1 {
		t.Fatalf("CountOwners counted a revoked owner: n=%d err=%v", n, err)
	}
}

// D3.6: an owner whose access to the credential's org was revoked must not keep a working machine
// credential there.
func TestRBAC0MachineCredentialStopsWithOrgScopedRevocation(t *testing.T) {
	o := newRBAC0Org(t)
	a, b := o.org(t), o.org(t)
	owner := o.user(t, map[uuid.UUID]string{a: "owner", b: "owner"})
	if _, err := o.pool.Exec(o.ctx, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, a, owner); err != nil {
		t.Fatal(err)
	}
	standing := rbac0MachineStanding(t, o, owner, a)
	if standing {
		t.Fatal("a machine credential in A stayed valid after its owner's access to A was revoked")
	}
	if !rbac0MachineStanding(t, o, owner, b) {
		t.Fatal("the owner's credential in B must keep working")
	}
}

// rbac0MachineStanding asks the exact query the machine-credential auth seam runs.
func rbac0MachineStanding(t *testing.T, o *rbac0Org, owner, org uuid.UUID) bool {
	t.Helper()
	active, err := o.q.GetMachineOwnerStanding(o.ctx, sqlc.GetMachineOwnerStandingParams{OrgID: org, UserID: owner})
	if err != nil {
		t.Fatal(err)
	}
	return active
}

// D3: directory sync — and only sync — reverses its own deprovisioning when the directory lists the
// person as active again; an administrator's deactivation is never undone by sync.
func TestRBAC0RestoreForSyncReversesOnlyDirectoryActs(t *testing.T) {
	o := newRBAC0Org(t)
	a := o.org(t)
	actor := o.user(t, map[uuid.UUID]string{a: "owner"})
	bySync := o.user(t, map[uuid.UUID]string{a: "member"})
	byAdmin := o.user(t, map[uuid.UUID]string{a: "member"})
	if _, err := o.svc.DeactivateMemberBySync(o.ctx, a, bySync, "disabled_in_directory"); err != nil {
		t.Fatal(err)
	}
	if err := o.svc.DeactivateMember(o.ctx, actor, "owner", a, byAdmin); err != nil {
		t.Fatal(err)
	}
	if did, err := o.svc.RestoreForSync(o.ctx, a, bySync); err != nil || !did {
		t.Fatalf("sync restore of its own deactivation: did=%v err=%v", did, err)
	}
	if got := o.status(t, bySync); got != "active" {
		t.Fatalf("status after sync restore = %q", got)
	}
	if did, err := o.svc.RestoreForSync(o.ctx, a, byAdmin); err != nil || did {
		t.Fatalf("sync must not reverse an administrator: did=%v err=%v", did, err)
	}
	if got := o.status(t, byAdmin); got != "deactivated" {
		t.Fatalf("admin-deactivated status = %q", got)
	}
	// Org-scoped: the administrator's revocation of a multi-org member is not the directory's either.
	multi := o.user(t, map[uuid.UUID]string{a: "member", o.org(t): "member"})
	if err := o.svc.DeactivateMember(o.ctx, actor, "owner", a, multi); err != nil {
		t.Fatal(err)
	}
	if did, err := o.svc.RestoreForSync(o.ctx, a, multi); err != nil || did || o.hasAccess(t, a, multi) {
		t.Fatalf("sync restored an administrator's org-scoped deactivation: did=%v err=%v", did, err)
	}
	// And the directory's own org-scoped removal comes back.
	if _, err := o.pool.Exec(o.ctx, `UPDATE memberships SET access_revoked_at=NULL, access_revoked_source=NULL WHERE org_id=$1 AND user_id=$2`, a, multi); err != nil {
		t.Fatal(err)
	}
	if _, err := o.svc.RevokeOrgAccessBySync(o.ctx, a, multi, "directory_provenance_exhausted"); err != nil {
		t.Fatal(err)
	}
	if did, err := o.svc.RestoreForSync(o.ctx, a, multi); err != nil || !did || !o.hasAccess(t, a, multi) {
		t.Fatalf("sync did not restore its own org-scoped removal: did=%v err=%v", did, err)
	}
}
