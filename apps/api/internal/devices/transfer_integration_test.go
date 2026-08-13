//go:build enterprise

package devices

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
)

// transferFixture is an org + owner + TWO gateways, because a transfer is the one act that cannot be
// expressed with one. Devices are inserted directly so each test can construct the exact SHAPE it needs —
// static vs managed, active vs pending — including combinations no single product path produces.
type transferFixture struct {
	ctx          context.Context
	pool         *pgxpool.Pool
	svc          *Service
	org, owner   uuid.UUID
	nodeA, nodeB uuid.UUID
}

func seedTransferFixture(t *testing.T) *transferFixture {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	f := &transferFixture{ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(),
		nodeA: uuid.New(), nodeB: uuid.New()}
	ex := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'O',$2,'10.99.0.0/24',0)",
		f.org, "xfer-"+f.org.String())
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", f.owner, f.owner.String()+"@t.local")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", f.org, f.owner)
	for i, n := range []uuid.UUID{f.nodeA, f.nodeB} {
		ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,$3,$4,$5,$6)",
			n, f.org, []string{"gw-a", "gw-b"}[i], "serial-"+n.String(),
			"c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", []string{"a.example.com:51820", "b.example.com:51820"}[i])
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", f.org) })

	f.svc = NewService(pool, nodepush.New(), nil)
	return f
}

// addDevice inserts a device homed on nodeA, RECORDING provisioned_node_id — which is the column the whole
// point-6 proof turns on. A fixture that left it NULL would make every assertion below pass for the wrong
// reason: unknown is not stale, so an unrecorded provisioning gateway can never report a moved config.
func (f *transferFixture) addDevice(t *testing.T, name, ip, mode, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,transport,
		                      provisioning_mode,provisioned_node_id,provisioned_ip)
		 VALUES ($1,$2,$3,$4,$5,'linux',$6,$7,$8,'wireguard',$9,$4,$7)`,
		id, f.org, f.owner, f.nodeA, name, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4="+id.String(), ip,
		status, mode); err != nil {
		t.Fatalf("addDevice %s: %v", name, err)
	}
	return id
}

type deviceRow struct {
	nodeID          uuid.UUID
	status          string
	assignedIP      string
	mode            string
	provisionedNode pgtype.UUID
}

func (f *transferFixture) read(t *testing.T, id uuid.UUID) deviceRow {
	t.Helper()
	var r deviceRow
	if err := f.pool.QueryRow(f.ctx,
		"SELECT node_id, status, assigned_ip, provisioning_mode, provisioned_node_id FROM devices WHERE id=$1",
		id).Scan(&r.nodeID, &r.status, &r.assignedIP, &r.mode, &r.provisionedNode); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return r
}

// TestTransferMovesLiveDevicesWithoutTouchingStatusOrAddress — S12.12 D1/D4, the row half.
func TestTransferMovesLiveDevicesWithoutTouchingStatusOrAddress(t *testing.T) {
	f := seedTransferFixture(t)
	active := f.addDevice(t, "laptop", "10.99.0.10", "managed", "active")
	// D4 — PENDING MOVES TOO. An outstanding approval is about the PERSON, not the gateway: leaving it behind
	// strands an approval queue pointing at a gateway that is about to be revoked, which is the same reason
	// RevokeDevicesForNode sweeps pending rather than only active.
	pending := f.addDevice(t, "phone", "10.99.0.11", "managed", "pending")
	// A DELIBERATELY REVOKED DEVICE MUST NOT COME ALONG. It is not homed anywhere in the sense that matters —
	// nobody is connecting through it — and moving it would quietly resurrect the question a human already
	// answered about that device.
	revoked := f.addDevice(t, "old-laptop", "10.99.0.12", "managed", "active")
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE devices SET status='revoked', revoked_at=now(), revoked_cause='deliberate' WHERE id=$1",
		revoked); err != nil {
		t.Fatal(err)
	}

	res, err := f.svc.TransferDevicesToNode(f.ctx, f.owner, f.org, f.nodeA, f.nodeB)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected the two LIVE devices to move, got %d", len(res))
	}

	for _, tc := range []struct {
		id         uuid.UUID
		wantStatus string
	}{{active, "active"}, {pending, "pending"}} {
		got := f.read(t, tc.id)
		if got.nodeID != f.nodeB {
			t.Fatalf("device %s did not move: node_id=%s", tc.id, got.nodeID)
		}
		// ⛔ STATUS IS UNTOUCHED, and pending is the case that proves it. A transfer that promoted a pending
		// device would walk it past the org's approval gate as a side effect of maintenance — the same defect
		// the restore path hit when it declared a terminal status for a set whose members were not all in it.
		if got.status != tc.wantStatus {
			t.Fatalf("transfer changed status of %s: want %s, got %s", tc.id, tc.wantStatus, got.status)
		}
	}
	// ⛔ THE ADDRESS IS UNTOUCHED, because the pool is ORG-scoped and a same-org move cannot collide.
	// Reallocating would cost every moved user a re-import for a contention that does not exist.
	if got := f.read(t, active); got.assignedIP != "10.99.0.10" {
		t.Fatalf("transfer reallocated an address it had no reason to: %s", got.assignedIP)
	}
	if got := f.read(t, revoked); got.nodeID != f.nodeA {
		t.Fatal("a deliberately revoked device must not be swept along by a transfer")
	}
}

// TestTransferProvesTheCONFIGMoved — ⛔ THE POINT-6 RED, AND THE ONE THE PAPER SAID WOULD BE UNDER-SCOPED.
//
// > Moving the row is the easy half. A device whose config still names the old gateway is moved in the
// > database and broken on the wire.
//
// So this asserts on the CONFIG, twice and from both ends:
//
//  1. The transfer REPORTS, per device, that the issued config no longer works — the one-shot answer, at the
//     moment of the act, when the operator can still do something about it.
//  2. The device's ROW, read back after the move, makes ProfileStale fire — the standing answer, so the
//     Devices list says the same thing tomorrow to a user who was not watching.
//
// ⚠ A RED THAT ONLY CHECKED node_id WOULD PASS ON A FLEET THAT IS ENTIRELY BROKEN. That is the whole warning,
// and it is why (2) reads the row back from the database instead of asserting against arguments this test
// constructed: hand-built inputs prove the comparison works, never that the data reaching it is right.
func TestTransferProvesTheCONFIGMoved(t *testing.T) {
	f := seedTransferFixture(t)
	static := f.addDevice(t, "kiosk", "10.99.0.20", "static", "active")
	managed := f.addDevice(t, "laptop", "10.99.0.21", "managed", "active")

	// NEITHER GATEWAY IS IN A HUB SET — this org has no sites, which is the ordinary two-gateway deployment
	// and the case that makes the managed half bite. `selfHomingNodes` is unwired on this fixture, so the
	// transfer takes its UNKNOWN branch, which resolves to "assume a re-issue is needed": the safe direction.
	res, err := f.svc.TransferDevicesToNode(f.ctx, f.owner, f.org, f.nodeA, f.nodeB)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	byID := map[uuid.UUID]TransferResult{}
	for _, r := range res {
		byID[r.DeviceID] = r
	}
	if !byID[static].NeedsReissue || byID[static].ReissueCause != "static_export" {
		t.Fatalf("a STATIC export is a file that never polls and bakes the gateway's endpoint and public key — "+
			"it MUST be reported as needing a re-issue, got %+v", byID[static])
	}
	if !byID[managed].NeedsReissue {
		t.Fatalf("a managed device whose destination's self-homing is UNKNOWN must be reported as needing a "+
			"re-issue: overstating the work costs a minute, understating it means the user finds out by "+
			"failing to connect, got %+v", byID[managed])
	}

	// (2) THE STANDING SURFACE AGREES, computed from the row as it now exists in the database — the same
	// inputs ListDevices passes. `false` for self-homing is what this org's two ordinary gateways are.
	row := f.read(t, static)
	if !ProfileStale(row.mode, nil, nil, &row.assignedIP, &row.assignedIP, row.provisionedNode, row.nodeID, false) {
		t.Fatal("the transferred STATIC device's row must report needs_reexport: its config names gw-a and it " +
			"is now homed on gw-b")
	}
	mrow := f.read(t, managed)
	if !ProfileStale(mrow.mode, nil, nil, &mrow.assignedIP, &mrow.assignedIP, mrow.provisionedNode, mrow.nodeID, false) {
		t.Fatal("the transferred MANAGED device's row must report needs_reexport too: gw-b is not in the active " +
			"hub set, so it keeps its baked endpoint and dials the gateway it just left (S12.12 D7)")
	}
	// ⭐ AND THE OTHER DIRECTION, or this test would pass on a ProfileStale that returned true unconditionally.
	// A managed device on a SELF-HOMING destination re-homes itself and is genuinely fresh.
	if ProfileStale(mrow.mode, nil, nil, &mrow.assignedIP, &mrow.assignedIP, mrow.provisionedNode, mrow.nodeID, true) {
		t.Fatal("a managed device moved onto a hub-set member follows itself there; flagging it would be a " +
			"permanent false positive on a fleet that healed")
	}
}

// TestTransferRefusesAnUnusableDestination — the destination is validated, and the refusal is distinct.
func TestTransferRefusesAnUnusableDestination(t *testing.T) {
	f := seedTransferFixture(t)
	f.addDevice(t, "laptop", "10.99.0.30", "managed", "active")

	// ⛔ THE OBVIOUS OPERATOR MISTAKE IS TO NAME THE GATEWAY THEY ARE RETIRING. Falling back to the source
	// silently would report a successful move that moved nothing, which is worse than a refusal.
	if _, err := f.svc.TransferDevicesToNode(f.ctx, f.owner, f.org, f.nodeA, f.nodeA); err == nil {
		t.Fatal("transferring a gateway's devices onto itself must be refused")
	}
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE nodes SET status='revoked', revoked_at=now() WHERE id=$1", f.nodeB); err != nil {
		t.Fatal(err)
	}
	// A REVOKED DESTINATION IS THE SECOND OBVIOUS MISTAKE, and the one that produces devices which are
	// `active` and point at something that will never serve them — healthy on every surface, working nowhere.
	if _, err := f.svc.TransferDevicesToNode(f.ctx, f.owner, f.org, f.nodeA, f.nodeB); err == nil {
		t.Fatal("a revoked destination must be refused")
	}
	// An org that does not own the destination cannot receive its devices either.
	if _, err := f.svc.TransferDevicesToNode(f.ctx, f.owner, f.org, f.nodeA, uuid.New()); err == nil {
		t.Fatal("a destination outside this organization must be refused")
	}
}
