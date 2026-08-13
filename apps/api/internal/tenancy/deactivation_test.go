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

type fakeRevoker struct{ called []uuid.UUID }

func (f *fakeRevoker) DeleteAllForUser(_ context.Context, id uuid.UUID) error {
	f.called = append(f.called, id)
	return nil
}

func TestDeactivationFreezesAndGuardsLastOwner(t *testing.T) {
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
	actor, member, soleOwner := uuid.New(), uuid.New(), uuid.New()
	stmts := [][]any{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", orgA, "A", "da-" + orgA.String()},
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", orgB, "B", "db-" + orgB.String()},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actor, "actor@t", "Actor"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", member, "member@t", "Member"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", soleOwner, "owner@t", "Owner"},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", orgA, member},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", orgB, soleOwner},
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s[0].(string), s[1:]...); err != nil {
			t.Fatalf("setup %q: %v", s[0], err)
		}
	}

	rev := &fakeRevoker{}
	svc := &MembershipService{q: sqlc.New(tx), revoker: rev}

	// Deactivating a regular member freezes the account and revokes sessions,
	// but keeps the membership (frozen, not deleted).
	if err := svc.DeactivateMember(ctx, actor, orgA, member); err != nil {
		t.Fatalf("deactivate member: %v", err)
	}
	var status string
	if err := tx.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", member).Scan(&status); err != nil || status != "deactivated" {
		t.Fatalf("status = %q err=%v, want deactivated", status, err)
	}
	if _, err := svc.q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgA, UserID: member}); err != nil {
		t.Fatalf("membership should be preserved: %v", err)
	}
	if len(rev.called) != 1 || rev.called[0] != member {
		t.Fatalf("sessions not revoked for member: %v", rev.called)
	}
	// Audit: the deactivation recorded a user.deactivated event attributed to the
	// acting user (watch-item e — every mutation lands in audit_logs with actor).
	var deactivatedRows int
	if err := tx.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='user.deactivated' AND target_id=$3",
		orgA, actor, member.String()).Scan(&deactivatedRows); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if deactivatedRows != 1 {
		t.Fatalf("want 1 actor-attributed user.deactivated audit row, got %d", deactivatedRows)
	}

	// The last-owner invariant blocks deactivating an org's sole owner.
	if err := svc.DeactivateMember(ctx, actor, orgB, soleOwner); !isCode(err, "last_owner") {
		t.Fatalf("deactivate sole owner: want last_owner, got %v", err)
	}

	// Reactivation restores the frozen account.
	if err := svc.ReactivateMember(ctx, actor, orgA, member); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if err := tx.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", member).Scan(&status); err != nil || status != "active" {
		t.Fatalf("status = %q, want active", status)
	}
}

type fakePusher struct {
	orgPushes  []uuid.UUID
	userPushes []uuid.UUID
}

func (f *fakePusher) PushUserNodes(_ context.Context, id uuid.UUID) {
	f.userPushes = append(f.userPushes, id)
}
func (f *fakePusher) PushOrgNodes(_ context.Context, id uuid.UUID) {
	f.orgPushes = append(f.orgPushes, id)
}

// S7.2 finding #1 (multi-node guard): deactivating a member must push ORG-WIDE, not
// just the member's own device-nodes — a DIFFERENT node (node2) that referenced the
// member as a Zero Trust policy group-destination must also recompile. Single-gateway
// hid this; this test seeds TWO nodes with the target's device on node1 only, and
// asserts (a) DeactivateMember calls PushOrgNodes (not PushUserNodes), and (b) the
// org's active-node set — what PushOrgNodes notifies — includes node2.
func TestDeactivatePushesOrgWideNotJustUserNodes(t *testing.T) {
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
	actor, owner, target, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	node1, node2 := uuid.New(), uuid.New()
	dev1, dev2 := uuid.New(), uuid.New()
	stmts := [][]any{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", org, "O", "o-" + org.String()},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actor, "a@t", "A"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", owner, "own@t", "Own"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", target, "tgt@t", "Tgt"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", other, "oth@t", "Oth"},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", org, owner}, // so target isn't sole owner
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, target},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, other},
		{"INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw1',$3)", node1, org, "s1-" + node1.String()},
		{"INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw2',$3)", node2, org, "s2-" + node2.String()},
		// target's device on node1; another member's device on node2 (target has NONE there).
		{"INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'd1', 'HMMxVkG5cwpRWhIHl7OSfO6ydf63a9uWJ7Xpjhp53o8=', '10.99.0.2')", dev1, org, target, node1},
		{"INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'd2', 'sb+LFfBl6cbN3we5ubB6GQ9XzjVRcXu+CVM9C6C2vSg=', '10.99.0.3')", dev2, org, other, node2},
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s[0].(string), s[1:]...); err != nil {
			t.Fatalf("setup %q: %v", s[0], err)
		}
	}

	fp := &fakePusher{}
	svc := &MembershipService{q: sqlc.New(tx), revoker: &fakeRevoker{}, pusher: fp}
	if err := svc.DeactivateMember(ctx, actor, org, target); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	// (a) org-wide push, NOT user-scoped.
	if len(fp.orgPushes) != 1 || fp.orgPushes[0] != org {
		t.Fatalf("deactivate must PushOrgNodes(org) exactly once; got org=%v user=%v", fp.orgPushes, fp.userPushes)
	}
	if len(fp.userPushes) != 0 {
		t.Fatalf("deactivate must NOT PushUserNodes (would miss node2); got %v", fp.userPushes)
	}
	// (b) the org's active-node set (what PushOrgNodes notifies) includes node2 —
	// where the target has NO device but is a policy group-dst.
	ids, err := sqlc.New(tx).ListActiveNodeIDsForOrg(ctx, org)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen[node1] || !seen[node2] {
		t.Fatalf("org push set must include BOTH nodes (esp node2 without target's device); got %v", ids)
	}
}
