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

// TestListAuditLogsKeysetAndFilters exercises the audit-viewer query: keyset
// paging (no overlap, no gap, newest-first), the actor + action filters, and
// cross-tenant isolation — all through the SAME query the dashboard's latest-N
// slice uses. Rolled-back tx; runs identically in both editions.
func TestListAuditLogsKeysetAndFilters(t *testing.T) {
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
	alice, bob := uuid.New(), uuid.New()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,'A',$2)", []any{orgA, "aud-a-" + orgA.String()}},
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,'B',$2)", []any{orgB, "aud-b-" + orgB.String()}},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,'Alice')", []any{alice, "al-" + alice.String() + "@t"}},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,'Bob')", []any{bob, "bo-" + bob.String() + "@t"}},
	} {
		if _, e := tx.Exec(ctx, s.sql, s.args...); e != nil {
			t.Fatalf("setup %q: %v", s.sql, e)
		}
	}
	// 5 events in orgA at strictly increasing times; 1 in orgB (must never leak).
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := func(org, actor uuid.UUID, action string, tOff int) {
		if _, e := tx.Exec(ctx,
			"INSERT INTO audit_logs (org_id,actor_user_id,action,created_at) VALUES ($1,$2,$3,$4)",
			org, actor, action, base.Add(time.Duration(tOff)*time.Minute)); e != nil {
			t.Fatalf("event: %v", e)
		}
	}
	ev(orgA, alice, "org.updated", 1)
	ev(orgA, bob, "member.role_changed", 2)
	ev(orgA, alice, "device.created", 3)
	ev(orgA, bob, "device.revoked", 4)
	ev(orgA, alice, "org.cidr_resized", 5) // newest
	ev(orgB, alice, "org.updated", 9)      // other org

	svc := &Service{q: sqlc.New(tx)}

	// Page 1 (limit 3): the 3 newest orgA events, DESC. orgB never appears.
	p1, err := svc.ListAuditLogs(ctx, orgA, AuditFilter{Limit: 3})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(p1) != 3 || p1[0].Action != "org.cidr_resized" || p1[1].Action != "device.revoked" || p1[2].Action != "device.created" {
		t.Fatalf("page1 = %v, want [cidr_resized, device.revoked, device.created] (full order, incl. the middle row)", actions(p1))
	}
	for _, r := range p1 {
		if r.OrgID.Bytes != [16]byte(orgA) {
			t.Fatalf("orgB row leaked into orgA feed: %+v", r)
		}
	}
	// Page 2 via keyset cursor = last row of page 1: no overlap, no gap.
	last := p1[2]
	cts, cid := last.CreatedAt, uuid.UUID(last.ID)
	p2, err := svc.ListAuditLogs(ctx, orgA, AuditFilter{Limit: 3, CursorTS: &cts, CursorID: &cid})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(p2) != 2 || p2[0].Action != "member.role_changed" || p2[1].Action != "org.updated" {
		t.Fatalf("page2 = %v, want [role_changed, org.updated] (the older 2, no overlap)", actions(p2))
	}

	// Actor filter: only alice's orgA events (3 of them), newest-first.
	af, err := svc.ListAuditLogs(ctx, orgA, AuditFilter{Limit: 50, Actor: &alice})
	if err != nil {
		t.Fatalf("actor filter: %v", err)
	}
	if len(af) != 3 {
		t.Fatalf("alice filter = %d rows, want 3", len(af))
	}
	for _, r := range af {
		if r.ActorUserID.Bytes != [16]byte(alice) {
			t.Fatalf("actor filter leaked a non-alice row: %+v", r)
		}
	}
	// Action filter.
	act := "device.created"
	acf, err := svc.ListAuditLogs(ctx, orgA, AuditFilter{Limit: 50, Action: &act})
	if err != nil {
		t.Fatalf("action filter: %v", err)
	}
	if len(acf) != 1 || acf[0].Action != act {
		t.Fatalf("action filter = %v, want [device.created]", actions(acf))
	}
}

func actions(rows []sqlc.AuditLog) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Action
	}
	return out
}
