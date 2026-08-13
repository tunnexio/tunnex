package tenancy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// TestRoleManagement exercises the RBAC relational rules, the last-owner
// invariant, and audit-with-actor — all against the live DB in a rolled-back tx.
func TestRoleManagement(t *testing.T) {
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

	org := uuid.New()
	ownerA, ownerB, memberC := uuid.New(), uuid.New(), uuid.New()
	setup := [][]any{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", org, "O", "rm-" + org.String()},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", ownerA, "a-" + ownerA.String() + "@t", "A"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", ownerB, "b-" + ownerB.String() + "@t", "B"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", memberC, "c-" + memberC.String() + "@t", "C"},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", org, ownerA},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", org, ownerB},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, memberC},
	}
	for _, s := range setup {
		if _, err := tx.Exec(ctx, s[0].(string), s[1:]...); err != nil {
			t.Fatalf("setup %q: %v", s[0], err)
		}
	}

	// The actor must be a real user (audit_logs.actor_user_id has an FK).
	actor := ownerA
	svc := &MembershipService{q: sqlc.New(tx)}

	// Owner demotes the other owner (2 owners -> allowed).
	if _, err := svc.ChangeMemberRole(ctx, &actor, rbac.RoleOwner, org, ownerB, rbac.RoleAdmin); err != nil {
		t.Fatalf("owner demote co-owner: %v", err)
	}
	// Now ownerA is the last owner: demoting them is blocked.
	if _, err := svc.ChangeMemberRole(ctx, &actor, rbac.RoleOwner, org, ownerA, rbac.RoleMember); !isCode(err, "last_owner") {
		t.Fatalf("demote last owner: want last_owner, got %v", err)
	}
	// Admin cannot modify an owner.
	if _, err := svc.ChangeMemberRole(ctx, &actor, rbac.RoleAdmin, org, ownerA, rbac.RoleAdmin); !isCode(err, "forbidden") {
		t.Fatalf("admin modifies owner: want forbidden, got %v", err)
	}
	// Admin promotes a member to admin (allowed) ...
	if _, err := svc.ChangeMemberRole(ctx, &actor, rbac.RoleAdmin, org, memberC, rbac.RoleAdmin); err != nil {
		t.Fatalf("admin promote member->admin: %v", err)
	}
	// ... but cannot grant owner.
	if _, err := svc.ChangeMemberRole(ctx, &actor, rbac.RoleAdmin, org, memberC, rbac.RoleOwner); !isCode(err, "forbidden") {
		t.Fatalf("admin grants owner: want forbidden, got %v", err)
	}
	// Removing the last owner is blocked.
	if err := svc.RemoveMember(ctx, &actor, rbac.RoleOwner, org, ownerA); !isCode(err, "last_owner") {
		t.Fatalf("remove last owner: want last_owner, got %v", err)
	}
	// Owner removes a non-owner (allowed).
	if err := svc.RemoveMember(ctx, &actor, rbac.RoleOwner, org, ownerB); err != nil {
		t.Fatalf("owner removes admin: %v", err)
	}

	// Audit: the successful mutations recorded events WITH a non-null actor.
	var withActor int
	if err := tx.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action IN ('member.role_changed','member.removed')",
		org, actor).Scan(&withActor); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if withActor < 3 { // demote B, promote C, remove B (at least)
		t.Fatalf("expected >=3 actor-attributed audit rows, got %d", withActor)
	}
}
