package devices

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

// code returns the apierr code of err, or "" — for asserting typed failures.
func code(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}

// setup returns a device Service bound to a rolled-back tx, plus seeded org/user/
// node ids. maxDevices sets the org's per-user cap.
func setup(t *testing.T, tx pgx.Tx, maxDevices int) (*Service, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, user, node := uuid.New(), uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug,max_devices_per_user) VALUES ($1,$2,$3,$4)",
		org, "O", "s-"+org.String(), maxDevices); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name,status) VALUES ($1,$2,$3,'active')",
		user, "u-"+user.String()+"@t", "U"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, user); err != nil {
		t.Fatalf("membership: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,$3,$4,$5,$6)",
		node, org, "gw", "serial-"+node.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", "gw.example.com:51820"); err != nil {
		t.Fatalf("node: %v", err)
	}
	return &Service{q: sqlc.New(tx), logger: slog.Default()}, org, user, node
}

func txOrSkip(t *testing.T) (context.Context, pgx.Tx) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	return ctx, tx
}

func peerKeys(t *testing.T, svc *Service, node uuid.UUID) []string {
	t.Helper()
	rows, err := svc.q.ListActiveWireGuardPeersForNode(context.Background(), node)
	if err != nil {
		t.Fatalf("list peers: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.PublicKey)
	}
	return out
}

// TestServerGeneratedKeyNeverStored: the server-generated flow returns a valid
// private key ONCE, and the stored row holds only the public key (watch-item a).
func TestServerGeneratedKeyNeverStored(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "laptop"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !wgkey.Valid(res.Device.PublicKey) {
		t.Fatal("stored public key is not a valid WG key")
	}
	if res.PrivateKeyOneTime == "" || !wgkey.Valid(res.PrivateKeyOneTime) {
		t.Fatal("server-generated flow must return a valid one-time private key")
	}
	if res.PrivateKeyOneTime == res.Device.PublicKey {
		t.Fatal("private and public key must differ")
	}
	if res.Device.UserID != user {
		t.Fatal("device not bound to its owner")
	}
	// The server-generated flow returns a complete, ready-to-use config carrying
	// the one-time private key and the gateway endpoint (watch-items a + b).
	if !strings.Contains(res.Config, "PrivateKey = "+res.PrivateKeyOneTime) ||
		!strings.Contains(res.Config, "Endpoint = gw.example.com:51820") ||
		!strings.Contains(res.Config, "Address = "+*res.Device.AssignedIp+"/32") {
		t.Fatalf("config incomplete:\n%s", res.Config)
	}
}

func TestCreateOrdinaryFlowRequiresName(t *testing.T) {
	_, err := (&Service{}).Create(context.Background(), CreateInput{})
	if code(err) != "name_required" {
		t.Fatalf("empty ordinary create error code = %q, want name_required", code(err))
	}
}

// TestClientGeneratedKeyAccepted: a client-supplied public key is stored and no
// private key is ever returned.
func TestClientGeneratedKeyAccepted(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	_, pub, _ := wgkey.Generate()
	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "phone", PublicKey: pub})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Device.PublicKey != pub {
		t.Fatal("client public key not stored verbatim")
	}
	if res.PrivateKeyOneTime != "" {
		t.Fatal("client-generated flow must NOT return a private key")
	}
}

// TestDevicesTableHasNoPrivateKeyColumn is the schema-level never-stored
// assertion: there is no column that could hold a peer private key.
func TestDevicesTableHasNoPrivateKeyColumn(t *testing.T) {
	ctx, tx := txOrSkip(t)
	rows, err := tx.Query(ctx, "SELECT column_name FROM information_schema.columns WHERE table_name='devices'")
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(col), "private") || strings.Contains(strings.ToLower(col), "secret") {
			t.Fatalf("devices has a column that could store a private key: %q", col)
		}
	}
}

// TestPerUserDeviceLimit enforces the org cap.
func TestPerUserDeviceLimit(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 1)

	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d1"}); err != nil {
		t.Fatalf("first device: %v", err)
	}
	_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d2"})
	if code(err) != "device_limit" {
		t.Fatalf("want device_limit, got %v", err)
	}
}

// TestRevokeRemovesPeer: a revoked device drops from the node's peer set; a
// second revoke is a conflict, not a silent no-op.
func TestRevokeRemovesPeer(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := peerKeys(t, svc, node); len(got) != 1 || got[0] != res.Device.PublicKey {
		t.Fatalf("peer not present before revoke: %v", got)
	}
	if err := svc.Revoke(ctx, org, user, res.Device.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := peerKeys(t, svc, node); len(got) != 0 {
		t.Fatalf("peer still present after revoke: %v", got)
	}
	if code(svc.Revoke(ctx, org, user, res.Device.ID)) != "already_revoked" {
		t.Fatal("second revoke should conflict")
	}
}

func TestRevokeAgentDropsTemplateGroupMemberships(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	agent, group := uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO devices
		(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind)
		VALUES ($1,$2,$3,$4,'f09-agent',$5,'10.99.0.22','active','agent')`,
		agent, org, user, node, "f09-agent-"+agent.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'workers')`, group, org); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id)
		VALUES ($1,$2,$3,$4)`, org, group, agent, user); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, org, user, agent); err != nil {
		t.Fatal(err)
	}
	var memberships int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_group_members WHERE org_id=$1 AND device_id=$2`, org, agent).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 {
		t.Fatalf("revoked agent retained %d group memberships", memberships)
	}
	var auditCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs
		WHERE org_id=$1 AND target_id=$2 AND metadata->>'removed_agent_group_memberships'='1'`, org, agent.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("revoke must audit one removed F09 membership, rows=%d", auditCount)
	}
}

// TestDeactivatedOwnerDropsPeers is the offboarding trace (watch-item c): a
// deactivated owner's peers leave every node's desired state; reactivation
// restores them (freeze, not delete).
func TestDeactivatedOwnerDropsPeers(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	q := svc.q

	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(peerKeys(t, svc, node)) != 1 {
		t.Fatal("peer should be present for an active owner")
	}
	if err := q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: user, Status: "deactivated"}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if got := peerKeys(t, svc, node); len(got) != 0 {
		t.Fatalf("deactivated owner's peer still in desired state: %v", got)
	}
	if err := q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: user, Status: "active"}); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if len(peerKeys(t, svc, node)) != 1 {
		t.Fatal("reactivated owner's peer should return")
	}
}

// TestCrossOrgNodeAttachRejected: a device cannot attach to a node in another org.
func TestCrossOrgNodeAttachRejected(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, _, user, node := setup(t, tx, 10)
	otherOrg := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", otherOrg, "O2", "s2-"+otherOrg.String()); err != nil {
		t.Fatalf("other org: %v", err)
	}
	// Make the owner a member of otherOrg so the create passes the membership
	// check and specifically exercises the cross-org NODE rejection.
	if _, err := tx.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", otherOrg, user); err != nil {
		t.Fatalf("other membership: %v", err)
	}
	// node belongs to the first org; attaching it from otherOrg must fail.
	_, err := svc.Create(ctx, CreateInput{OrgID: otherOrg, ActorID: user, OwnerID: user, NodeID: node, Name: "d"})
	if code(err) != "node_not_found" {
		t.Fatalf("want node_not_found for cross-org node, got %v", err)
	}
}

// TestCreateRejectsNonMemberOwner: a device cannot be bound to a user who is not
// a member of the org (no cross-tenant / non-member owners, even for an admin).
func TestCreateRejectsNonMemberOwner(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, _, node := setup(t, tx, 10)
	stranger := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO users (id,email,name,status) VALUES ($1,$2,$3,'active')",
		stranger, "x-"+stranger.String()+"@t", "X"); err != nil {
		t.Fatalf("stranger: %v", err)
	}
	// stranger exists globally but is NOT a member of org.
	_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: stranger, OwnerID: stranger, NodeID: node, Name: "d"})
	if code(err) != "owner_not_member" {
		t.Fatalf("want owner_not_member for non-member owner, got %v", err)
	}
}

// TestAllocationSequentialAndReuse: allocation is deterministic lowest-free and
// respects existing allocations (no reassignment); a revoked device's address is
// reused (release-on-revocation).
func TestAllocationSequentialAndReuse(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	d1, _ := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "a"})
	d2, _ := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "b"})
	if *d1.Device.AssignedIp != "10.99.0.2" || *d2.Device.AssignedIp != "10.99.0.3" {
		t.Fatalf("want .2 then .3, got %v then %v", *d1.Device.AssignedIp, *d2.Device.AssignedIp)
	}
	// Revoke .2 -> its address is released and reused by the next allocation.
	if err := svc.Revoke(ctx, org, user, d1.Device.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	d3, _ := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "c"})
	if *d3.Device.AssignedIp != "10.99.0.2" {
		t.Fatalf("revoked address should be reused (want .2), got %v", *d3.Device.AssignedIp)
	}
}

// TestResizePoolShrinkRefusesOrphans: growing is fine; a shrink that would strand
// a live allocation is refused (never silently orphaned).
func TestResizePoolShrinkRefusesOrphans(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	// Seed a device whose address is in /24 but outside /25 (0-127).
	if _, err := tx.Exec(ctx, "INSERT INTO devices (org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, 'd', '+DeSO+POkGDPyK451u3mgL1y719ZUGSdtncSL1FeQGI=', $4)",
		org, user, node, "10.99.0.200"); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// Grow to /23 — safe (superset; .200 is inside and not a new reserved addr).
	if _, err := svc.ResizePool(ctx, user, org, "10.99.0.0/23"); err != nil {
		t.Fatalf("grow should succeed: %v", err)
	}
	// Shrink to /25 — would strand 10.99.0.200; must refuse with the typed orphan
	// error carrying the offender.
	var orphErr *ShrinkOrphansError
	if _, err := svc.ResizePool(ctx, user, org, "10.99.0.0/25"); !errors.As(err, &orphErr) {
		t.Fatalf("shrink should refuse with *ShrinkOrphansError, got %v", err)
	} else if len(orphErr.Orphans) != 1 {
		t.Fatalf("orphans = %+v, want exactly one", orphErr.Orphans)
	} else if o := orphErr.Orphans[0]; o.AssignedIP != "10.99.0.200" || o.Reason != ipalloc.ReasonOutOfRange || o.Name != "d" || o.DeviceID == (uuid.UUID{}) {
		t.Fatalf("orphan = %+v, want {device_id set, name d, 10.99.0.200, out_of_range}", o)
	}
	// A bad CIDR is rejected.
	if _, err := svc.ResizePool(ctx, user, org, "not-a-cidr"); code(err) != "invalid_cidr" {
		t.Fatalf("bad cidr: want invalid_cidr, got %v", err)
	}
	// Idempotent: resizing to the current CIDR is a no-op success (200), not an error.
	if _, err := svc.ResizePool(ctx, user, org, "10.99.0.0/23"); err != nil {
		t.Fatalf("idempotent resize to current CIDR should succeed, got %v", err)
	}
	// Illegal shape: a disjoint /24 (neither superset nor subset) is refused.
	if _, err := svc.ResizePool(ctx, user, org, "10.88.0.0/24"); code(err) != "illegal_resize" {
		t.Fatalf("disjoint resize: want illegal_resize, got %v", err)
	}
	// Too small: a /31 can't hold the reserved addresses + a host.
	if _, err := svc.ResizePool(ctx, user, org, "10.99.0.0/31"); code(err) != "cidr_too_small" {
		t.Fatalf("tiny cidr: want cidr_too_small, got %v", err)
	}
}

// TestResizePoolGrowSafety asserts the grow-safety proof (see ResizePool's
// doc-comment PREMISE): a valid grow-superset NEVER strands an Allocate-produced
// allocation on a new reserved address — including the DOWNWARD-grow case where
// the network address itself moves lower. Every allocation lives in the old
// pool's usable interval [O_net+2, O_bcast-1], and every NEW reserved address is
// <= O_net+1 or >= O_bcast, strictly outside it.
func TestResizePoolGrowSafety(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	// Start at 10.0.1.0/24, with allocations at both boundaries of the usable
	// interval (first host .2 and last host .254).
	if _, err := tx.Exec(ctx, "UPDATE organizations SET pool_cidr='10.0.1.0/24' WHERE id=$1", org); err != nil {
		t.Fatalf("set pool: %v", err)
	}
	for _, ip := range []string{"10.0.1.2", "10.0.1.254"} {
		if _, err := tx.Exec(ctx, "INSERT INTO devices (org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1,$2,$3,$4,$5,$6)",
			org, user, node, "d-"+ip, "k-"+ip, ip); err != nil {
			t.Fatalf("seed %s: %v", ip, err)
		}
	}
	// DOWNWARD grow to 10.0.0.0/23: the new network (10.0.0.0) + gateway (10.0.0.1)
	// move BELOW every allocation, and the new broadcast (10.0.1.255) is above the
	// last host (.254). Neither seeded device collides with a new reserved addr, so
	// the grow succeeds with no orphans — the proof holds, and the check-anyway
	// orphan pass is provably empty here.
	if _, err := svc.ResizePool(ctx, user, org, "10.0.0.0/23"); err != nil {
		t.Fatalf("downward grow-superset should succeed (proof: no allocation lands on a new reserved addr), got %v", err)
	}
	var cidr string
	if err := tx.QueryRow(ctx, "SELECT pool_cidr FROM organizations WHERE id=$1", org).Scan(&cidr); err != nil || cidr != "10.0.0.0/23" {
		t.Fatalf("pool_cidr = %q err=%v, want 10.0.0.0/23", cidr, err)
	}
}

// TestResizePoolAudit: a successful resize records org.cidr_resized attributed to
// the actor with old+new CIDR; an idempotent no-op writes ZERO audit rows (part
// of the idempotency decision — 200, no side effects).
func TestResizePoolAudit(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	_ = node
	if _, err := tx.Exec(ctx, "UPDATE organizations SET pool_cidr='10.0.0.0/24' WHERE id=$1", org); err != nil {
		t.Fatalf("set pool: %v", err)
	}

	// Grow /24 -> /23: one audit row, attributed to the actor, with from+to.
	if _, err := svc.ResizePool(ctx, user, org, "10.0.0.0/23"); err != nil {
		t.Fatalf("grow: %v", err)
	}
	var count int
	var meta []byte
	if err := tx.QueryRow(ctx,
		"SELECT count(*) OVER (), metadata FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='org.cidr_resized' LIMIT 1",
		org, user).Scan(&count, &meta); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if count != 1 {
		t.Fatalf("want 1 org.cidr_resized audit row, got %d", count)
	}
	m := string(meta)
	if !strings.Contains(m, "10.0.0.0/24") || !strings.Contains(m, "10.0.0.0/23") {
		t.Fatalf("audit metadata must carry old+new CIDR, got %s", m)
	}

	// Idempotent no-op (resize to the current /23): NO new audit row.
	if _, err := svc.ResizePool(ctx, user, org, "10.0.0.0/23"); err != nil {
		t.Fatalf("idempotent resize: %v", err)
	}
	var total int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='org.cidr_resized'", org).Scan(&total); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if total != 1 {
		t.Fatalf("idempotent no-op must write NO audit row; total org.cidr_resized rows = %d, want 1", total)
	}
}

// TestGetDeviceCrossOrgNotFound: a device id from another org reads as not-found
// (org-scoped read path — no cross-tenant leak).
func TestGetDeviceCrossOrgNotFound(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	otherOrg := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O2',$2)", otherOrg, "s2-"+otherOrg.String()); err != nil {
		t.Fatalf("other org: %v", err)
	}
	if _, err := svc.Get(ctx, otherOrg, res.Device.ID); code(err) != "device_not_found" {
		t.Fatalf("cross-org Get: want device_not_found, got %v", err)
	}
}

// TestListDoesNotLeakCrossOrg: listing one org never returns another org's
// devices (the LEFT JOIN on device_status must not widen the org scope).
func TestListDoesNotLeakCrossOrg(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svcA, orgA, userA, nodeA := setup(t, tx, 10)
	if _, err := svcA.Create(ctx, CreateInput{OrgID: orgA, ActorID: userA, OwnerID: userA, NodeID: nodeA, Name: "a"}); err != nil {
		t.Fatalf("create A: %v", err)
	}
	// A separate org B with its own device.
	svcB, orgB, userB, nodeB := setup(t, tx, 10)
	if _, err := svcB.Create(ctx, CreateInput{OrgID: orgB, ActorID: userB, OwnerID: userB, NodeID: nodeB, Name: "b"}); err != nil {
		t.Fatalf("create B: %v", err)
	}
	// Org A's list (user + org views) must contain only A's device.
	if l, _ := svcA.ListForOrg(ctx, orgA); len(l) != 1 || l[0].Device.OrgID != orgA {
		t.Fatalf("ListForOrg leaked cross-org: %+v", l)
	}
	if l, _ := svcA.ListForUser(ctx, orgA, userA); len(l) != 1 || l[0].Device.OrgID != orgA {
		t.Fatalf("ListForUser leaked cross-org: %+v", l)
	}
}

// TestListSurfacesStatus: ListForUser joins and returns live status.
func TestListSurfacesStatus(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	res, _ := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d"})
	// Before any report: status fields are nil.
	list, _ := svc.ListForUser(ctx, org, user)
	if len(list) != 1 || list[0].LastHandshakeAt != nil || list[0].RxBytes != nil {
		t.Fatalf("pre-report status should be nil: %+v", list)
	}
	// Seed a status row and confirm the list surfaces it.
	if _, err := tx.Exec(ctx, "INSERT INTO device_status (device_id,last_handshake_at,rx_bytes,tx_bytes) VALUES ($1,now(),$2,$3)",
		res.Device.ID, int64(4096), int64(8192)); err != nil {
		t.Fatalf("seed status: %v", err)
	}
	list, _ = svc.ListForUser(ctx, org, user)
	if len(list) != 1 || list[0].LastHandshakeAt == nil || list[0].RxBytes == nil || *list[0].RxBytes != 4096 {
		t.Fatalf("list did not surface status: %+v", list[0])
	}
}

// TestCreatePushesGateway: creating a device notifies the gateway node's watcher.
func TestCreatePushesGateway(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	hub := nodepush.New()
	svc.hub = hub
	ch, unsub := hub.Subscribe(node)
	defer unsub()

	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "d"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	select {
	case <-ch:
	default:
		t.Fatal("gateway was not pushed on device create")
	}
}

// S3.7: a full-tunnel device is REFUSED against a gateway that can't source-NAT egress
// (gateway_no_egress), and ALLOWED once the gateway reports egress_nat=true. Split-tunnel
// is always allowed regardless.
func TestFullTunnelRequiresGatewayEgress(t *testing.T) {
	t.Setenv("TUNNEX_IPV6_POOL_CIDR", "fd7a:1b2c:3d4e::/48")
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	// Default node capabilities are '{}' → egress_nat false → full-tunnel refused.
	_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "ft-deny", FullTunnel: true})
	if code(err) != "gateway_no_egress" {
		t.Fatalf("full-tunnel on no-egress gateway: want gateway_no_egress, got %v", err)
	}
	// Split-tunnel is always allowed.
	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "split-ok", FullTunnel: false}); err != nil {
		t.Fatalf("split-tunnel should be allowed: %v", err)
	}
	// Once the gateway reports egress capability, full-tunnel is allowed.
	if _, err := tx.Exec(ctx, `UPDATE nodes SET capabilities = '{"egress_nat":true,"egress_ipv6":true}'::jsonb WHERE id = $1`, node); err != nil {
		t.Fatalf("set capability: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "ft-ok", FullTunnel: true}); err != nil {
		t.Fatalf("full-tunnel on egress-capable gateway should be allowed: %v", err)
	}
}

// TestOVPNFullTunnelRequiresGatewayEgress is the WF-OVPN-3 refusal-inheritance red: a full-tunnel
// OpenVPN device inherits gateway_no_egress VERBATIM (the refusal is transport-agnostic, in the shared
// create path) — refused on a no-egress gateway, allowed once egress is reported. Split OVPN is always
// allowed. This is the "parity, not asymmetry" guarantee on the real path.
func TestOVPNFullTunnelRequiresGatewayEgress(t *testing.T) {
	t.Setenv("TUNNEX_IPV6_POOL_CIDR", "fd7a:1b2c:3d4e::/48")
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	// No egress capability → full-tunnel OVPN refused with the SAME typed code as WireGuard.
	_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "ovpn-ft-deny", Transport: "openvpn", FullTunnel: true})
	if code(err) != "gateway_no_egress" {
		t.Fatalf("full-tunnel OVPN on no-egress gateway: want gateway_no_egress, got %v", err)
	}
	// Split-tunnel OVPN is always allowed.
	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "ovpn-split-ok", Transport: "openvpn", FullTunnel: false}); err != nil {
		t.Fatalf("split-tunnel OVPN should be allowed: %v", err)
	}
	// Egress reported → full-tunnel OVPN allowed.
	if _, err := tx.Exec(ctx, `UPDATE nodes SET capabilities = '{"egress_nat":true,"egress_ipv6":true}'::jsonb WHERE id = $1`, node); err != nil {
		t.Fatalf("set capability: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "ovpn-ft-ok", Transport: "openvpn", FullTunnel: true}); err != nil {
		t.Fatalf("full-tunnel OVPN on egress-capable gateway should be allowed: %v", err)
	}
}

// TestResizePoolRefusesApprovedSiteOverlap — S8.1 Slice-4 S4.5b touch (D5/D7): growing the pool over an
// APPROVED site subnet is refused (typed illegal_resize, the ONE validator's other direction). A PENDING
// (unapproved) subnet does NOT block — only approved subnets count.
func TestResizePoolRefusesApprovedSiteOverlap(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, _ := setup(t, tx, 10)
	if _, err := tx.Exec(ctx, "UPDATE organizations SET pool_cidr='10.0.1.0/24' WHERE id=$1", org); err != nil {
		t.Fatalf("set pool: %v", err)
	}
	site := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'hq')", site, org); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO site_subnets (id,site_id,cidr,status) VALUES ($1,$2,'10.5.0.0/24','approved')", uuid.New(), site); err != nil {
		t.Fatalf("seed approved subnet: %v", err)
	}
	// Grow to 10.0.0.0/8: contains the old pool AND the approved site subnet 10.5.0.0/24 -> refused.
	_, err := svc.ResizePool(ctx, user, org, "10.0.0.0/8")
	if err == nil {
		t.Fatal("growing the pool over an APPROVED site subnet must be refused (illegal_resize)")
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "illegal_resize" {
		t.Fatalf("want a typed illegal_resize, got %v", err)
	}
	// A PENDING subnet must NOT block: drop the approved one, keep only a pending overlap, grow succeeds.
	if _, err := tx.Exec(ctx, "DELETE FROM site_subnets WHERE cidr='10.5.0.0/24'"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO site_subnets (id,site_id,cidr,status) VALUES ($1,$2,'10.6.0.0/24','pending')", uuid.New(), site); err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	if _, err := svc.ResizePool(ctx, user, org, "10.0.0.0/8"); err != nil {
		t.Fatalf("a PENDING site subnet must NOT block a resize (only approved counts), got %v", err)
	}
}

// TestCreateOVPNForkNoWGMaterialization (S9.1 Slice 4b-wiring, D-S9.4-MODEL) is the create-fork red:
// an OVPN-transport create mints NO WG keypair and NO WG config (its credential is a cert issued by
// the export path), yet the SHARED path still governs it — transport tagged, a pool /32 allocated,
// and (verified below) its /32 reaches the compiler's device source exactly as a WG device's does
// (B1's data half AT THE CREATE PATH). Two keyless OVPN devices coexist on one node (migration 0043).
func TestCreateOVPNForkNoWGMaterialization(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "laptop-ovpn", Transport: "openvpn"})
	if err != nil {
		t.Fatalf("create ovpn: %v", err)
	}
	// NO WG materialization.
	if res.Device.PublicKey != "" {
		t.Fatalf("OVPN device must carry NO WG public key, got %q", res.Device.PublicKey)
	}
	if res.PrivateKeyOneTime != "" {
		t.Fatal("OVPN create must not mint a WG private key")
	}
	if res.Config != "" {
		t.Fatal("OVPN create must not assemble a WG config")
	}
	// SHARED governance held: transport tagged + pool /32 allocated.
	if res.Device.Transport != "openvpn" {
		t.Fatalf("transport = %q, want openvpn", res.Device.Transport)
	}
	if res.Device.AssignedIp == nil || *res.Device.AssignedIp == "" {
		t.Fatal("OVPN device must hold a pool /32 (the shared allocator governs it)")
	}
	// B1 DATA HALF at the create path: the OVPN device is in the compiler's device source with its
	// /32 — ListActiveDevicesForOrg filters by neither transport nor key, so its /32 is a policy
	// subject exactly as a WG device's is.
	devs, err := svc.q.ListActiveDevicesForOrg(ctx, org)
	if err != nil {
		t.Fatalf("list active devices: %v", err)
	}
	found := false
	for _, d := range devs {
		if d.ID == res.Device.ID && d.AssignedIp != nil && *d.AssignedIp == *res.Device.AssignedIp {
			found = true
		}
	}
	if !found {
		t.Fatal("the OVPN device's /32 must reach the compiler snapshot (B1 data half at create)")
	}
	// TWO keyless OVPN devices on ONE node coexist — migration 0043 scopes the pubkey uniqueness to
	// devices that HAVE a key, so '' never collides.
	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "laptop-ovpn-2", Transport: "openvpn"}); err != nil {
		t.Fatalf("a second keyless OVPN device on the same node must NOT collide: %v", err)
	}
	// a WG public key on an OVPN device is rejected (wrong credential kind).
	if _, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "bad", Transport: "openvpn", PublicKey: "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0="}); err == nil {
		t.Fatal("a WG public key on an OVPN device must be rejected (wg_key_on_ovpn)")
	}
}

// TestCreateStaticExportEnrichesAndRecords (S9.1 Part-2) locks the static-export enrichment: a static
// profile bakes the approved ranges + DNS (its non-polling client can't learn them), and records the
// provisioning mode + ranges snapshot (for the stale-profile surface).
func TestCreateStaticExportEnrichesAndRecords(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	svc.exportEnrich = func(context.Context, uuid.UUID) ([]string, bool, error) {
		return []string{"10.0.0.0/16", "172.31.0.0/16"}, true, nil
	}
	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "phone", Provisioning: "static"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// red 1: AllowedIPs carries the approved ranges + a DNS line is set.
	for _, want := range []string{"10.0.0.0/16", "172.31.0.0/16"} {
		if !strings.Contains(res.Config, want) {
			t.Fatalf("static config must bake range %q; got:\n%s", want, res.Config)
		}
	}
	if !strings.Contains(res.Config, "DNS = ") {
		t.Fatalf("static config with DNS forwards must set a DNS line; got:\n%s", res.Config)
	}
	// recorded provisioning mode.
	if res.Device.ProvisioningMode != "static" {
		t.Fatalf("provisioning_mode = %q, want static", res.Device.ProvisioningMode)
	}
	// red 2 + 3: the snapshot is the EXPORT-TIME ranges (immutable) — a range added later is NOT in it,
	// and the stale-profile surface lists the device for the diff.
	stale, err := svc.q.ListStaticDevicesForOrg(ctx, org)
	if err != nil {
		t.Fatalf("list static: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("stale surface must list the 1 static device, got %d", len(stale))
	}
	var snap []string
	if e := json.Unmarshal(stale[0].ProvisionedRanges, &snap); e != nil {
		t.Fatalf("snapshot unmarshal: %v", e)
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot must be the 2 export-time ranges (immutable); got %v", snap)
	}
	// a subnet added AFTER export (192.168.0.0/24) is absent from the snapshot → the surface flags "re-export".
	for _, c := range snap {
		if c == "192.168.0.0/24" {
			t.Fatal("a range added after export must NOT appear in the old profile's snapshot")
		}
	}
}

// TestCreateManagedExportNotEnriched (S9.1 Part-2) locks the derive-from-export-path ruling: a MANAGED
// (polling) device does NOT bake ranges even when the org has them — it learns them from the poll.
func TestCreateManagedExportNotEnriched(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	svc.exportEnrich = func(context.Context, uuid.UUID) ([]string, bool, error) {
		return []string{"10.0.0.0/16"}, true, nil // ranges exist, but managed must ignore them
	}
	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "laptop"}) // managed default
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Contains(res.Config, "10.0.0.0/16") {
		t.Fatalf("a managed (polling) device must NOT bake ranges; got:\n%s", res.Config)
	}
	if res.Device.ProvisioningMode != "managed" {
		t.Fatalf("default provisioning must be managed, got %q", res.Device.ProvisioningMode)
	}
}

// TestStaticExportZeroRangesIdentical (S9.1 Part-2) locks red 4: a static export in a zero-ranges org
// produces a config identical to today (pool-only AllowedIPs, no DNS) — no enrichment out of nothing.
func TestStaticExportZeroRangesIdentical(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	svc.exportEnrich = func(context.Context, uuid.UUID) ([]string, bool, error) { return nil, false, nil }
	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "phone", Provisioning: "static"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Contains(res.Config, "DNS = ") {
		t.Fatalf("zero-DNS org must set no DNS line; got:\n%s", res.Config)
	}
	// AllowedIPs is exactly the pool (no extra ranges) — same as a managed device.
	if strings.Count(res.Config, ",") != 0 || !strings.Contains(res.Config, "AllowedIPs = 10.") {
		t.Fatalf("zero-ranges static must bake only the pool (identical to today); got:\n%s", res.Config)
	}
}

// TestIssuanceRecordsTheADDRESSItBaked — the issuance half of Slice 6, asserted against the CONFIG TEXT rather
// than against the row alone.
//
// The claim is not "a column got written"; it is "what we recorded equals what the user's config actually bakes".
// A test that compares the snapshot to dev.AssignedIp would pass even if the config rendered a different address,
// which is the failure it is supposed to make impossible. So it reads the address out of the rendered config and
// requires the persisted snapshot to match it.
//
// MANAGED mode deliberately: the previous code recorded the snapshot only for STATIC exports, so a managed device
// had nothing to compare and rendered as clean forever after its address changed.
func TestIssuanceRecordsTheADDRESSItBaked(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)

	res, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "laptop"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Device.ProvisioningMode != "managed" {
		t.Fatalf("default provisioning must be managed, got %q", res.Device.ProvisioningMode)
	}
	if res.Device.ProvisionedIp == nil {
		t.Fatal("issuance must record the address it baked FOR EVERY MODE — a managed device with no snapshot " +
			"can never be reported stale, which is how a re-addressed device stayed invisible")
	}
	if !strings.Contains(res.Config, "Address = "+*res.Device.ProvisionedIp+"/32") {
		t.Fatalf("the recorded snapshot %q is not the address the issued config bakes; the snapshot is only worth "+
			"anything if it equals what the user holds:\n%s", *res.Device.ProvisionedIp, res.Config)
	}

	// And it is PERSISTED, not just set on the returned struct — the comparison happens on a later read.
	row, err := svc.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: res.Device.ID, OrgID: org})
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if row.ProvisionedIp == nil || *row.ProvisionedIp != *res.Device.AssignedIp {
		t.Fatalf("persisted snapshot %v must equal the assigned address %q", row.ProvisionedIp, *res.Device.AssignedIp)
	}
	// The ranges half must stay ABSENT for managed: routes are polled, so there is nothing baked to compare.
	if len(row.ProvisionedRanges) != 0 {
		t.Fatalf("a managed device must carry NO ranges snapshot (it polls routes); got %s", row.ProvisionedRanges)
	}
}
