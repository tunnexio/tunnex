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
)

// TestOrgLifecycle exercises the S1.2 semantics against the live DB inside a
// rolled-back transaction: soft-delete exclusion, slug-reuse blocked, immutable
// slug, and atomic audit coverage.
func TestOrgLifecycle(t *testing.T) {
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
	svc := &Service{q: sqlc.New(tx)}

	// Create.
	org, err := svc.CreateOrganization(ctx, creator, "Acme", "acme-test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Get + list include it. The list assertion is SCOPED to THIS org (present after create,
	// absent after soft-delete below) — a GLOBAL count here races with any concurrently-running
	// package whose integration fixtures commit org rows (pool.Exec, no rollback; the S8.5 sites
	// suite was the first to expose it on CI's shared test DB). The soft-delete-exclusion
	// semantics are fully proven on the test's own org; a global count proves nothing extra.
	if _, err := svc.GetOrganization(ctx, org.ID); err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if orgs, _ := svc.ListOrganizations(ctx); !containsOrg(orgs, org.ID) {
		t.Fatalf("list after create must include the created org, got %d orgs", len(orgs))
	}

	// Update name; slug must be unchanged (immutable).
	upd, err := svc.UpdateOrganization(ctx, org.ID, "Acme Renamed")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Name != "Acme Renamed" || upd.Slug != "acme-test" {
		t.Fatalf("update result name=%q slug=%q (slug must be immutable)", upd.Name, upd.Slug)
	}

	// Soft-delete.
	if err := svc.SoftDeleteOrganization(ctx, org.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Excluded from get/list/count after soft-delete.
	if _, err := svc.GetOrganization(ctx, org.ID); !isCode(err, "org_not_found") {
		t.Fatalf("get after delete: want org_not_found, got %v", err)
	}
	if orgs, _ := svc.ListOrganizations(ctx); containsOrg(orgs, org.ID) {
		t.Fatal("list after delete must EXCLUDE the soft-deleted org")
	}

	// Deleting again is a not-found (idempotent, no phantom audit).
	if err := svc.SoftDeleteOrganization(ctx, org.ID); !isCode(err, "org_not_found") {
		t.Fatalf("double delete: want org_not_found, got %v", err)
	}

	// Audit coverage: created + updated + deleted all recorded for this org.
	// (Checked before the slug-reuse case below, which raises a unique violation
	// that aborts this shared test transaction — in production each mutation runs
	// in its own transaction, so a failed create never poisons prior work.)
	var auditCount int
	if err := tx.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action IN ('org.created','org.updated','org.deleted')",
		org.ID).Scan(&auditCount); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 3 {
		t.Fatalf("audit rows = %d, want 3 (created, updated, deleted)", auditCount)
	}

	// Slug reuse is blocked even though the org is soft-deleted. This raises a
	// unique violation, so it MUST be the last DB operation in this transaction.
	if _, err := svc.CreateOrganization(ctx, creator, "Acme2", "acme-test"); !isCode(err, "slug_taken") {
		t.Fatalf("slug reuse: want slug_taken, got %v", err)
	}
}

func isCode(err error, code string) bool {
	var apiErr *apierr.Error
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// containsOrg reports whether the list carries the given org id (the race-free scoped assertion).
func containsOrg(orgs []sqlc.Organization, id uuid.UUID) bool {
	for _, o := range orgs {
		if o.ID == id {
			return true
		}
	}
	return false
}
