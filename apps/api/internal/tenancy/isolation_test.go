package tenancy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestCrossTenantIsolation proves org-scoped reads never cross tenants: with a
// member in each of two orgs, org A's queries return only A's rows, and looking
// up B's member through org A reads as not-found (no existence leak).
//
// Orgs are inserted directly in a rolled-back transaction (bypassing the edition
// cap, which is irrelevant to isolation), so this runs identically in both
// editions and never touches real data.
func TestCrossTenantIsolation(t *testing.T) {
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

	orgA, orgB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	stmts := []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)", []any{orgA, "A", "iso-a-" + orgA.String()}},
		{"INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)", []any{orgB, "B", "iso-b-" + orgB.String()}},
		{"INSERT INTO users (id, email, name) VALUES ($1,$2,$3)", []any{userA, "a-" + userA.String() + "@t.local", "A"}},
		{"INSERT INTO users (id, email, name) VALUES ($1,$2,$3)", []any{userB, "b-" + userB.String() + "@t.local", "B"}},
		{"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')", []any{orgA, userA}},
		{"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')", []any{orgB, userB}},
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("setup exec %q: %v", s.sql, err)
		}
	}

	svc := &MembershipService{q: sqlc.New(tx)}

	// List is org-scoped: A sees only userA, B sees only userB.
	membersA, err := svc.ListMembers(ctx, orgA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(membersA) != 1 || membersA[0].UserID != userA {
		t.Fatalf("org A members = %+v, want only userA", membersA)
	}
	membersB, err := svc.ListMembers(ctx, orgB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(membersB) != 1 || membersB[0].UserID != userB {
		t.Fatalf("org B members = %+v, want only userB", membersB)
	}

	// Cross-tenant lookup: userB via org A must be not-found (404), not a leak.
	if _, err := svc.GetMember(ctx, orgA, userB); !isCode(err, "member_not_found") {
		t.Fatalf("cross-tenant GetMember(A, userB): want member_not_found, got %v", err)
	}
	// Same-tenant lookup works.
	if _, err := svc.GetMember(ctx, orgA, userA); err != nil {
		t.Fatalf("GetMember(A, userA): unexpected error %v", err)
	}
}
