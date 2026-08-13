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

// TestOverviewPopulated proves the dashboard aggregate against a populated org:
// the counts exclude revoked/soft-deleted rows, "online" is the S3.6 recency
// approximation (recent handshake AND an active owner), and recent activity is
// the org's audit log surfaced newest-first. A second org's rows are inserted
// alongside to prove every read is tenant-scoped (nothing leaks across orgs).
//
// Everything runs in a rolled-back transaction, so it never touches real data
// and behaves identically in both editions.
func TestOverviewPopulated(t *testing.T) {
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
	// orgA members: two active users + one deactivated user (still a member).
	uActive1, uActive2, uDeact := uuid.New(), uuid.New(), uuid.New()
	uB := uuid.New()
	nodeActive, nodeRevoked := uuid.New(), uuid.New()
	nodeB := uuid.New()
	// devices: online, stale, revoked, soft-deleted, deactivated-owner.
	dOnline, dStale, dRevoked, dDeleted, dDeactOwner := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	dB := uuid.New()

	recent := time.Now().Add(-30 * time.Second) // within the 3-min window
	stale := time.Now().Add(-10 * time.Minute)  // outside it
	tOld := time.Now().Add(-2 * time.Hour)
	tNew := time.Now().Add(-1 * time.Hour)

	stmts := []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)", []any{orgA, "A", "ov-a-" + orgA.String()}},
		{"INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)", []any{orgB, "B", "ov-b-" + orgB.String()}},
		{"INSERT INTO users (id, email, name) VALUES ($1,$2,$3)", []any{uActive1, "a1-" + uActive1.String() + "@t.local", "A1"}},
		{"INSERT INTO users (id, email, name) VALUES ($1,$2,$3)", []any{uActive2, "a2-" + uActive2.String() + "@t.local", "A2"}},
		{"INSERT INTO users (id, email, name, status) VALUES ($1,$2,$3,'deactivated')", []any{uDeact, "ad-" + uDeact.String() + "@t.local", "AD"}},
		{"INSERT INTO users (id, email, name) VALUES ($1,$2,$3)", []any{uB, "b-" + uB.String() + "@t.local", "B"}},
		{"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')", []any{orgA, uActive1}},
		{"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'member')", []any{orgA, uActive2}},
		{"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'member')", []any{orgA, uDeact}},
		{"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')", []any{orgB, uB}},
		// nodes: one active, one revoked (orgA) + one active (orgB).
		{"INSERT INTO nodes (id, org_id, name, status, cert_serial) VALUES ($1,$2,'n1','active',$3)", []any{nodeActive, orgA, "cs-" + nodeActive.String()}},
		{"INSERT INTO nodes (id, org_id, name, status, cert_serial) VALUES ($1,$2,'n2','revoked',$3)", []any{nodeRevoked, orgA, "cs-" + nodeRevoked.String()}},
		{"INSERT INTO nodes (id, org_id, name, status, cert_serial) VALUES ($1,$2,'nb','active',$3)", []any{nodeB, orgB, "cs-" + nodeB.String()}},
		// devices (orgA).
		{"INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, status) VALUES ($1,$2,$3,$4,'d-online',$5,'active')", []any{dOnline, orgA, uActive1, nodeActive, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4=" + dOnline.String()}},
		{"INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, status) VALUES ($1,$2,$3,$4,'d-stale',$5,'active')", []any{dStale, orgA, uActive1, nodeActive, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4=" + dStale.String()}},
		{"INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, status) VALUES ($1,$2,$3,$4,'d-revoked',$5,'revoked')", []any{dRevoked, orgA, uActive1, nodeActive, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4=" + dRevoked.String()}},
		{"INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, status, deleted_at) VALUES ($1,$2,$3,$4,'d-deleted',$5,'active',now())", []any{dDeleted, orgA, uActive2, nodeActive, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4=" + dDeleted.String()}},
		{"INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, status) VALUES ($1,$2,$3,$4,'d-deact',$5,'active')", []any{dDeactOwner, orgA, uDeact, nodeActive, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4=" + dDeactOwner.String()}},
		// device (orgB) — must never appear in orgA's overview.
		{"INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, status) VALUES ($1,$2,$3,$4,'d-b',$5,'active')", []any{dB, orgB, uB, nodeB, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4=" + dB.String()}},
		// device_status: online device has a recent handshake; the stale one is
		// outside the window; the deactivated-owner device IS recent (proving the
		// owner-active filter, not staleness, excludes it).
		{"INSERT INTO device_status (device_id, last_handshake_at) VALUES ($1,$2)", []any{dOnline, recent}},
		{"INSERT INTO device_status (device_id, last_handshake_at) VALUES ($1,$2)", []any{dStale, stale}},
		{"INSERT INTO device_status (device_id, last_handshake_at) VALUES ($1,$2)", []any{dDeactOwner, recent}},
		{"INSERT INTO device_status (device_id, last_handshake_at) VALUES ($1,$2)", []any{dB, recent}},
		// audit (orgA): two events; assert newest-first ordering.
		{"INSERT INTO audit_logs (org_id, actor_user_id, action, created_at) VALUES ($1,$2,'device.created',$3)", []any{orgA, uActive1, tOld}},
		{"INSERT INTO audit_logs (org_id, actor_user_id, action, created_at) VALUES ($1,$2,'device.revoked',$3)", []any{orgA, uActive1, tNew}},
		// audit (orgB) — must not surface in orgA's activity.
		{"INSERT INTO audit_logs (org_id, actor_user_id, action, created_at) VALUES ($1,$2,'org.created',now())", []any{orgB, uB}},
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("setup exec %q: %v", s.sql, err)
		}
	}

	svc := &Service{q: sqlc.New(tx)}
	ov, err := svc.Overview(ctx, orgA, nil)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}

	if ov.Members != 3 {
		t.Errorf("Members = %d, want 3 (two active + one deactivated member)", ov.Members)
	}
	if ov.Nodes != 1 {
		t.Errorf("Nodes = %d, want 1 (revoked node excluded)", ov.Nodes)
	}
	if ov.Devices != 3 {
		t.Errorf("Devices = %d, want 3 (revoked + soft-deleted excluded; deactivated-owner still active)", ov.Devices)
	}
	// Only dOnline: dStale is outside the window, dDeactOwner's owner is inactive.
	if ov.Online != 1 {
		t.Errorf("Online = %d, want 1 (recent handshake AND active owner)", ov.Online)
	}

	if len(ov.RecentActivity) != 2 {
		t.Fatalf("RecentActivity len = %d, want 2 (orgB's event must not leak)", len(ov.RecentActivity))
	}
	if ov.RecentActivity[0].Action != "device.revoked" {
		t.Errorf("RecentActivity[0].Action = %q, want device.revoked (newest first)", ov.RecentActivity[0].Action)
	}
	for _, a := range ov.RecentActivity {
		if a.OrgID.Bytes != [16]byte(orgA) {
			t.Errorf("activity row from a foreign org leaked: %+v", a)
		}
	}
}
