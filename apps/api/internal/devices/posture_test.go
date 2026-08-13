package devices

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
)

// S7.3 device posture — the four pins (proof obligations), DB-backed.

func postureDSN(t *testing.T) string {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL")
	}
	return dsn
}

// seedPostureOrg commits an org (with the given device_approval), an owner member, and a
// ready gateway node. Returns ids + a cleanup that CASCADE-deletes the org.
func seedPostureOrg(t *testing.T, pool *pgxpool.Pool, approval string) (org, owner, node uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, owner, node = uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user,device_approval) VALUES ($1,$2,$3,'10.0.0.0/24',0,$4)",
		org, "O", "post-"+org.String(), approval)
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", owner, owner.String()+"@t.local")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", org, owner)
	ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,$5)",
		node, org, "serial-"+node.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", "gw.example.com:51820")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org) })
	return org, owner, node
}

// TestApprovalEnforcementIsEnterpriseOnly is the WF-OVPN-6 red, BOTH ways: the SAME org with
// device_approval='on' enrolls devices PENDING under the enterprise edition (approvalEnforced) and ACTIVE
// under the open edition (default). Approval enforcement is an enterprise feature (S7.5.3 unlock-then-opt-in);
// the open build gates the admin surface, so it must not enforce — else a stored 'on' traps every new device
// with no way to approve (the edition line inverted). This is the downgrade-release seam by construction.
func TestApprovalEnforcementIsEnterpriseOnly(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	org, owner, node := seedPostureOrg(t, pool, "on") // device_approval = 'on'

	// ENTERPRISE (approvalEnforced=true): device enrolls PENDING.
	ent := NewService(pool, nil, nil)
	ent.SetApprovalEnforced(true)
	if e := mkDevice(t, ent, org, owner, owner, node, "ent"); e.Device.Status != "pending" || !e.PendingApproval {
		t.Fatalf("enterprise + approval=on must enroll PENDING; got status=%q pending=%v", e.Device.Status, e.PendingApproval)
	}

	// OPEN (default approvalEnforced=false): the SAME org's device enrolls ACTIVE — enforcement releases.
	open := NewService(pool, nil, nil)
	if o := mkDevice(t, open, org, owner, owner, node, "open"); o.Device.Status != "active" || o.PendingApproval {
		t.Fatalf("open + approval=on must enroll ACTIVE (enforcement is enterprise-only); got status=%q pending=%v", o.Device.Status, o.PendingApproval)
	}
}

func mkDevice(t *testing.T, svc *Service, org, actor, owner, node uuid.UUID, name string) CreateResult {
	t.Helper()
	res, err := svc.Create(context.Background(), CreateInput{OrgID: org, ActorID: actor, OwnerID: owner, NodeID: node, Name: name})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return res
}

// A split/full switch is a routing change, not a second workstation. It must
// retain the original device principal, WireGuard credential and allocation.
func TestUpdateModePreservesDeviceIdentityAndAllocation(t *testing.T) {
	ctx := context.Background()
	dsn := postureDSN(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	org, owner, node := seedPostureOrg(t, pool, "off")
	if _, err := pool.Exec(ctx, `UPDATE nodes SET capabilities = '{"egress_nat":true}' WHERE id = $1`, node); err != nil {
		t.Fatalf("set egress capability: %v", err)
	}
	svc := NewService(pool, nil, nil)
	created := mkDevice(t, svc, org, owner, owner, node, "laptop")

	full, err := svc.UpdateMode(ctx, owner, org, created.Device.ID, true)
	if err != nil {
		t.Fatalf("switch to full tunnel: %v", err)
	}
	if full.Device.ID != created.Device.ID || full.Device.NodeID != created.Device.NodeID ||
		full.Device.PublicKey != created.Device.PublicKey || full.Device.AssignedIp == nil ||
		created.Device.AssignedIp == nil || *full.Device.AssignedIp != *created.Device.AssignedIp {
		t.Fatalf("mode change changed device identity/allocation: before=%+v after=%+v", created.Device, full.Device)
	}
	if full.Config.Address != *created.Device.AssignedIp+"/32" || len(full.Config.Addresses) == 0 ||
		full.Config.Addresses[0] != *created.Device.AssignedIp+"/32" {
		t.Fatalf("mode config must carry a helper-valid primary CIDR: %+v", full.Config)
	}
	if len(full.Config.AllowedIPs) != 1 || full.Config.AllowedIPs[0] != "0.0.0.0/0" {
		t.Fatalf("full-tunnel mode routes = %v, want IPv4 default", full.Config.AllowedIPs)
	}
	if len(full.Config.DNS) != 1 || full.Config.DNS[0] != fullTunnelDNS {
		t.Fatalf("full-tunnel DNS = %v, want %s", full.Config.DNS, fullTunnelDNS)
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM devices WHERE org_id = $1", org).Scan(&count); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if count != 1 {
		t.Fatalf("mode change created %d device rows, want 1", count)
	}
}

// PIN 1 (a+b): a pending device HOLDS its IP — a concurrent/subsequent create must never
// be handed it (the allocator counts pending as in-flight); and reject FREES the IP so the
// NEXT create reuses it (the D1b sweep). Race-grade: exercised through the real Create path
// under its per-org LockDeviceKey.
func TestPendingDeviceHoldsIPThenRejectFrees(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on") // approval ON -> devices land pending
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	a := mkDevice(t, svc, org, owner, owner, node, "A")
	if !a.PendingApproval || a.Device.Status != "pending" {
		t.Fatalf("device A must be pending under approval=on; got status=%q pending=%v", a.Device.Status, a.PendingApproval)
	}
	ipA := *a.Device.AssignedIp

	// A concurrent create must NOT reuse A's held IP (allocator sees pending A as in-flight).
	b := mkDevice(t, svc, org, owner, owner, node, "B")
	if *b.Device.AssignedIp == ipA {
		t.Fatalf("create B was handed pending A's IP %s — allocator must count pending as in-flight", ipA)
	}

	// Reject A -> its IP is FREED (assigned_ip=NULL) and returns to the pool.
	if err := svc.Reject(ctx, org, owner, a.Device.ID); err != nil {
		t.Fatalf("reject A: %v", err)
	}
	// The next create takes the lowest free address == A's freed IP (it is the lowest gap).
	c := mkDevice(t, svc, org, owner, owner, node, "C")
	if *c.Device.AssignedIp != ipA {
		t.Fatalf("after rejecting A, its IP %s must be reusable by the next create; C got %s", ipA, *c.Device.AssignedIp)
	}
}

// PIN 1 (c): resize's orphan check shares the allocator's live-allocation definition, so a
// pending device stranded by a shrink must appear in the 409 orphan list (excluding pending
// would let a shrink silently strand its allocation).
func TestResizeStrandsPendingDeviceInOrphanList(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	a := mkDevice(t, svc, org, owner, owner, node, "A") // pending, holds the low IP (10.0.0.2)
	ipA := *a.Device.AssignedIp

	// Shrink to the upper half (10.0.0.128/25) — a valid shrink (contained in the /24) that
	// does NOT contain A's low address, so the pending device is a stranded orphan.
	_, err = svc.ResizePool(ctx, owner, org, "10.0.0.128/25")
	var orphans *ShrinkOrphansError
	if !errors.As(err, &orphans) {
		t.Fatalf("shrink stranding a pending device must return ShrinkOrphansError; got %v", err)
	}
	found := false
	for _, o := range orphans.Orphans {
		if o.AssignedIP == ipA {
			found = true
		}
	}
	if !found {
		t.Fatalf("the pending device (IP %s) must appear in the orphan list; got %+v", ipA, orphans.Orphans)
	}
}

// PIN 3: approve PUSHES ORG-WIDE (a newly-trusted device can enter group-resolved grants on
// gateways that do NOT host it — the F1-part-2 shape in reverse), reject pushes own-node.
// Observed via the hub's per-node Version (bumped on every Notify).
func TestApprovePushesOrgWideRejectOwnNode(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	// A SECOND active node that does NOT host the device — the org-wide push must still reach it.
	other := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw2',$3,$4,$5)",
		other, org, "serial-"+other.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", "gw2.example.com:51820"); err != nil {
		t.Fatalf("seed node2: %v", err)
	}
	hub := nodepush.New()
	svc := NewService(pool, hub, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	a := mkDevice(t, svc, org, owner, owner, node, "A") // pending, on `node`
	otherBefore := hub.Version(other)
	if err := svc.Approve(ctx, org, owner, a.Device.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if hub.Version(other) <= otherBefore {
		t.Fatal("approve must push ORG-WIDE: a node NOT hosting the device must be nudged (group-dst reachability, <5s)")
	}

	b := mkDevice(t, svc, org, owner, owner, node, "B") // another pending, on `node`
	nodeBefore := hub.Version(node)
	if err := svc.Reject(ctx, org, owner, b.Device.ID); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if hub.Version(node) <= nodeBefore {
		t.Fatal("reject must push the device's own node")
	}
}

// F1-part-3: every device-lifecycle event that changes compiled membership pushes ORG-WIDE.
// Create and Revoke each nudge a node that does NOT host the device — its /32 can be a
// group-resolved DESTINATION there. Revoke is the SECURITY case: a stale group-dst allow
// rule left on a non-hosting gateway + the freed IP (S3.5/D1b) = an address-reuse privilege
// leak if not stripped <5s (F1-part-2's fail-open sibling at the push layer).
func TestCreateAndRevokePushOrgWide(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "off") // off -> devices are active
	other := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw2',$3,$4,$5)",
		other, org, "serial-"+other.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", "gw2.example.com:51820"); err != nil {
		t.Fatalf("seed node2: %v", err)
	}
	hub := nodepush.New()
	svc := NewService(pool, hub, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	// CREATE nudges the non-hosting node (group-dst reachability must land <5s there too).
	before := hub.Version(other)
	d := mkDevice(t, svc, org, owner, owner, node, "A") // on `node`, active
	if hub.Version(other) <= before {
		t.Fatal("create must push ORG-WIDE: a node NOT hosting the device must be nudged")
	}
	// REVOKE nudges the non-hosting node — strip any stale group-dst grant before the freed
	// IP can be reallocated (the privilege-leak fix).
	before = hub.Version(other)
	if err := svc.Revoke(ctx, org, owner, d.Device.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if hub.Version(other) <= before {
		t.Fatal("revoke must push ORG-WIDE: a stale group-dst grant on a non-hosting gateway + freed-IP reuse = privilege leak")
	}
}

// PIN 4: a pending device is excluded from BOTH enforcement layers by construction (the
// status='active' filter) — the peer desired-state AND the compiler's device input.
func TestPendingExcludedFromPeersAndCompilerInput(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise
	q := sqlc.New(pool)

	a := mkDevice(t, svc, org, owner, owner, node, "A") // pending

	peers, err := q.ListActiveWireGuardPeersForNode(ctx, node)
	if err != nil {
		t.Fatalf("peers: %v", err)
	}
	for _, p := range peers {
		if p.PublicKey == a.Device.PublicKey {
			t.Fatal("pending device must NOT be served as a peer (no tunnel)")
		}
	}
	compiled, err := q.ListActiveDevicesForOrg(ctx, org)
	if err != nil {
		t.Fatalf("compiler input: %v", err)
	}
	for _, d := range compiled {
		if d.ID == a.Device.ID {
			t.Fatal("pending device must NOT be a compiler input (no grants, no /32 as dst)")
		}
	}

	// Approve -> now it appears in BOTH.
	if err := svc.Approve(ctx, org, owner, a.Device.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	peers, _ = q.ListActiveWireGuardPeersForNode(ctx, node)
	inPeers := false
	for _, p := range peers {
		if p.PublicKey == a.Device.PublicKey {
			inPeers = true
		}
	}
	if !inPeers {
		t.Fatal("an approved device must be served as a peer")
	}
}

// D3: approve records the approver; self-approval (actor==owner) is allowed but audited
// distinctly (device.self_approved vs device.approved).
func TestApproveRecordsApproverAndSelfApproveAudit(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	// A distinct admin (approves someone else's device).
	admin := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users (id,email,name,status) VALUES ($1,$2,'Adm','active')", admin, admin.String()+"@t.local"); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'admin')", org, admin); err != nil {
		t.Fatalf("admin membership: %v", err)
	}
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	// Admin approves the owner's device -> device.approved + approved_by=admin.
	a := mkDevice(t, svc, org, owner, owner, node, "A")
	if err := svc.Approve(ctx, org, admin, a.Device.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	var approvedBy uuid.UUID
	var action string
	if err := pool.QueryRow(ctx, "SELECT approved_by FROM devices WHERE id=$1", a.Device.ID).Scan(&approvedBy); err != nil {
		t.Fatalf("read approved_by: %v", err)
	}
	if approvedBy != admin {
		t.Fatalf("approved_by must be the actor; want %s got %s", admin, approvedBy)
	}
	if err := pool.QueryRow(ctx, "SELECT action FROM audit_logs WHERE org_id=$1 AND target_id=$2 ORDER BY created_at DESC LIMIT 1", org, a.Device.ID.String()).Scan(&action); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if action != "device.approved" {
		t.Fatalf("admin approving another's device: want device.approved, got %q", action)
	}

	// Owner self-approves their own device -> device.self_approved (the designed-against case).
	b := mkDevice(t, svc, org, owner, owner, node, "B")
	if err := svc.Approve(ctx, org, owner, b.Device.ID); err != nil {
		t.Fatalf("self-approve: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT action FROM audit_logs WHERE org_id=$1 AND target_id=$2 ORDER BY created_at DESC LIMIT 1", org, b.Device.ID.String()).Scan(&action); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if action != "device.self_approved" {
		t.Fatalf("owner self-approving: want device.self_approved, got %q", action)
	}
}

// D4: turning approval ON grandfathers existing active devices and reports the count
// (best-effort, after commit). Turning it on must not retro-pend the fleet.
func TestSetDeviceApprovalGrandfathersAndCounts(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "off") // start OFF -> devices are active
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	mkDevice(t, svc, org, owner, owner, node, "A")
	mkDevice(t, svc, org, owner, owner, node, "B")

	n, err := svc.SetDeviceApproval(ctx, owner, org, "on")
	if err != nil {
		t.Fatalf("set on: %v", err)
	}
	if n != 2 {
		t.Fatalf("grandfathered count: want 2 existing active devices, got %d", n)
	}
	// Existing devices stay active (grandfathered), not retro-pended.
	var active int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM devices WHERE org_id=$1 AND status='active'", org).Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 2 {
		t.Fatalf("flip on must grandfather existing devices active; got %d active", active)
	}
	// A NEW enrollment after the flip is pending.
	c := mkDevice(t, svc, org, owner, owner, node, "C")
	if !c.PendingApproval {
		t.Fatal("a device enrolled after approval=on must be pending")
	}
}

// Finding #1: the per-user cap counts PENDING devices (each reserves a pool /32). Under
// approval=on with cap=2, the 3rd enrollment is refused device_limit — no unbounded pending
// creation (the cap bypass + org-pool DoS the review found).
func TestPendingDevicesCountAgainstCap(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	if _, err := pool.Exec(ctx, "UPDATE organizations SET max_devices_per_user=2 WHERE id=$1", org); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	mkDevice(t, svc, org, owner, owner, node, "A") // pending, counts
	mkDevice(t, svc, org, owner, owner, node, "B") // pending, counts (now at cap 2)
	_, err = svc.Create(ctx, CreateInput{OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node, Name: "C"})
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "device_limit" {
		t.Fatalf("3rd enrollment must be refused device_limit (pending counts against the cap); got %v", err)
	}
}

// Finding #2: revoking a node sweeps its PENDING devices too (active+pending), so the address returns to the pool
// and the device stops lingering in the approval queue on a dead node.
//
// ASSERTION AMENDED (S13.1 D5). It used to require assigned_ip to become NULL. The address was never made free BY
// nulling it — it is free the instant status leaves ('active','pending'), because both readers that define
// taken-ness filter on exactly that predicate: the devices_org_ip_key partial unique index and
// ListActiveDeviceAllocations, "the SINGLE definition of live allocation".
//
// Nulling it destroyed the only record of what each user held, which is what made Wall 6 unrecoverable rather than
// merely painful: a cascade-revoked device could not be restored to its own address because nothing remembered it.
// So this now asserts the property that actually matters — the address is RE-ALLOCATABLE — and that the record
// survives. Revocation preserves what it invalidates.
func TestNodeRevokeSweepsPendingAndFreesIP(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true)                       // WF-OVPN-6: approval is enterprise
	a := mkDevice(t, svc, org, owner, owner, node, "A") // pending, holds an IP
	if a.Device.Status != "pending" || a.Device.AssignedIp == nil {
		t.Fatalf("precondition: A must be pending with an IP; got %+v", a.Device)
	}

	if _, err := sqlc.New(pool).RevokeDevicesForNode(ctx, node); err != nil {
		t.Fatalf("revoke node: %v", err)
	}
	var status string
	var ip *string
	if err := pool.QueryRow(ctx, "SELECT status, assigned_ip FROM devices WHERE id=$1", a.Device.ID).Scan(&status, &ip); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != "revoked" {
		t.Fatalf("pending device on a revoked node must be swept to revoked; got %q", status)
	}
	// The RECORD survives — restore needs it to reclaim the user's own address.
	if ip == nil {
		t.Fatal("the swept device must KEEP its assigned_ip as a record of what the revocation took: without it a " +
			"cascade-revoked device cannot be restored to its own address, which is Wall 6 (S13.1 D5)")
	}
	// And the address is genuinely re-allocatable, which is the property the old NULL assertion was reaching for.
	// Asked of the canonical oracle rather than inferred from the row.
	allocs, aerr := sqlc.New(pool).ListActiveDeviceAllocations(ctx, org)
	if aerr != nil {
		t.Fatalf("oracle: %v", aerr)
	}
	for _, al := range allocs {
		if al.AssignedIp != nil && *al.AssignedIp == *ip {
			t.Fatalf("a revoked device's address must not appear as a LIVE allocation — the pool must be free to "+
				"hand %s out again", *ip)
		}
	}
}

// Finding #3 (server half): an owner CANCELLING their own pending device revokes it, frees
// the IP, and is audited as device.cancelled (≠ device.revoked for an active device).
func TestOwnerCancelPendingAuditedDistinctly(t *testing.T) {
	dsn := postureDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	org, owner, node := seedPostureOrg(t, pool, "on")
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true) // WF-OVPN-6: approval is enterprise

	// Cancel a PENDING device -> device.cancelled + IP freed.
	a := mkDevice(t, svc, org, owner, owner, node, "A")
	if err := svc.Revoke(ctx, org, owner, a.Device.ID); err != nil {
		t.Fatalf("cancel pending: %v", err)
	}
	var status, action string
	var ip *string
	if err := pool.QueryRow(ctx, "SELECT status, assigned_ip FROM devices WHERE id=$1", a.Device.ID).Scan(&status, &ip); err != nil {
		t.Fatalf("read: %v", err)
	}
	// AMENDED with the sweep assertion above (S13.1 D5): cancelling revokes, and the address is re-allocatable the
	// moment status leaves ('active','pending') — it is not made free by being nulled. The record is KEPT, because
	// nulling it destroyed the only trace of what the revocation took.
	if status != "revoked" {
		t.Fatalf("cancel must revoke; got status=%q", status)
	}
	if ip == nil {
		t.Fatal("a cancelled device must KEEP its assigned_ip as the record of what it held (S13.1 D5)")
	}
	if err := pool.QueryRow(ctx, "SELECT action FROM audit_logs WHERE org_id=$1 AND target_id=$2 ORDER BY created_at DESC LIMIT 1", org, a.Device.ID.String()).Scan(&action); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if action != "device.cancelled" {
		t.Fatalf("cancelling a pending device must audit device.cancelled; got %q", action)
	}

	// Contrast: revoking an ACTIVE device -> device.revoked.
	b := mkDevice(t, svc, org, owner, owner, node, "B")
	if err := svc.Approve(ctx, org, owner, b.Device.ID); err != nil {
		t.Fatalf("approve B: %v", err)
	}
	if err := svc.Revoke(ctx, org, owner, b.Device.ID); err != nil {
		t.Fatalf("revoke active B: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT action FROM audit_logs WHERE org_id=$1 AND target_id=$2 ORDER BY created_at DESC LIMIT 1", org, b.Device.ID.String()).Scan(&action); err != nil {
		t.Fatalf("audit B: %v", err)
	}
	if action != "device.revoked" {
		t.Fatalf("revoking an active device must audit device.revoked; got %q", action)
	}
}
