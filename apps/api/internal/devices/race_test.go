package devices

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestResizeAllocationRace proves the per-org advisory lock (LockDeviceKey)
// actually EXCLUDES a concurrent device allocation from slipping past a resize's
// orphan check — i.e. that resize and CreateDevice serialize on the same key.
//
// The lock primitive is pg_advisory_xact_lock(hashtextextended(orgID)) — a
// TRANSACTION-SCOPED, per-SESSION lock, released only at COMMIT. So this test
// pins each goroutine to its OWN connection (two size-1 pools): two goroutines on
// one pooled connection could never contend, and the test would pass vacuously.
// Both paths are lock-then-read (verified in the source): resize and CreateDevice
// each take LockDeviceKey as the first statement, before reading pool_cidr /
// allocations — so a blocked tx resumes only after the holder COMMITS and then
// reads the holder's committed state. That commit-as-serialization-point is what
// makes the end-state invariant below sound.
//
// Scenario (no device seeding needed): empty /24 pool, shrink to the UPPER half
// 10.0.0.128/25 (a legal subset). A concurrent CreateDevice that reads the OLD
// /24 allocates .2 (lowest-free) — OUTSIDE the shrink target. The afterResizeCheck
// seam holds resize inside its window (after the orphan check, before commit) so
// the concurrent create is FORCED to attempt during that window:
//   - WITH the lock (this test, green): the create blocks on LockDeviceKey until
//     resize commits, then reads the NEW range and allocates .130 (in-range).
//   - WITHOUT the lock (comment out ResizePool's LockDeviceKey — the RED run): the
//     create reads the old /24, allocates .2, and commits inside the window →
//     resize commits the shrink → .2 is stranded outside the committed pool.
//
// So the assertions below are GREEN with the lock and RED without it; the RED run
// is done manually (comment the lock, run, observe the failure, restore).
func TestResizeAllocationRace(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()

	// Two size-1 pools → each goroutine gets its own dedicated connection, so the
	// advisory lock genuinely contends (the load-bearing detail).
	mkPool := func() *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse dsn: %v", err)
		}
		cfg.MaxConns = 1
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		return p
	}
	poolResize, poolCreate := mkPool(), mkPool()
	t.Cleanup(poolResize.Close)
	t.Cleanup(poolCreate.Close)

	// Seed committed rows (this is a real-concurrency test, not a rolled-back tx):
	// an org with a known /24 pool, an active owner, and a ready gateway node.
	org, user, node := uuid.New(), uuid.New(), uuid.New()
	mustExec := func(sql string, args ...any) {
		if _, err := poolResize.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	mustExec("INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,$2,$3,'10.0.0.0/24',0)",
		org, "O", "race-"+org.String())
	mustExec("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", user, user.String()+"@t.local")
	mustExec("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", org, user)
	mustExec("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,$5)",
		node, org, "serial-"+node.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", "gw.example.com:51820")
	// CASCADE cleanup — this test commits real rows.
	t.Cleanup(func() { _, _ = poolResize.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org) })

	svcResize := NewService(poolResize, nil, nil)
	svcCreate := NewService(poolCreate, nil, nil)

	// Barrier: the seam signals it's holding the resize window, then waits for the
	// create to commit OR a timeout. WITH the lock the create is blocked, so the
	// wait times out and resize commits first; WITHOUT the lock the create commits
	// inside the window and unblocks the seam immediately (deterministic red).
	resizeInWindow := make(chan struct{})
	createDone := make(chan struct{})
	svcResize.afterResizeCheck = func() {
		close(resizeInWindow)
		select {
		case <-createDone:
		case <-time.After(3 * time.Second):
		}
	}

	var resizeErr, createErr error
	var createdIP string
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, resizeErr = svcResize.ResizePool(ctx, user, org, "10.0.0.128/25")
	}()

	// Only start the create once resize is inside its window (holding the lock in
	// the green case) — this FORCES the interleave the lock must exclude, so a
	// green pass means "excluded by the lock", not "happened not to overlap".
	<-resizeInWindow

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(createDone)
		res, err := svcCreate.Create(ctx, CreateInput{OrgID: org, ActorID: user, OwnerID: user, NodeID: node, Name: "racer"})
		createErr = err
		if err == nil && res.Device.AssignedIp != nil {
			createdIP = *res.Device.AssignedIp
		}
	}()

	wg.Wait()

	if resizeErr != nil {
		t.Fatalf("resize failed: %v", resizeErr)
	}
	if createErr != nil {
		t.Fatalf("create failed: %v", createErr)
	}

	newP := netip.MustParsePrefix("10.0.0.128/25")

	// CONTENTION assertion: the create was forced to attempt inside the window, so
	// a valid allocation inside the NEW range proves it BLOCKED on the lock and ran
	// only after resize committed (then read the new pool_cidr). Without the lock
	// it would have read the old /24 and gotten .2 — this is the assertion that
	// goes red on lock removal.
	ip, err := netip.ParseAddr(createdIP)
	if err != nil || !newP.Contains(ip) {
		t.Fatalf("RACE: created device %q is outside the committed pool %s — the allocation was NOT serialized behind the resize (lock removed/ineffective)", createdIP, newP)
	}

	// END-STATE INVARIANT (outcome-shaped, order-independent): after both commit,
	// no active device may sit outside the committed pool_cidr.
	var committed string
	if err := poolResize.QueryRow(ctx, "SELECT pool_cidr FROM organizations WHERE id=$1", org).Scan(&committed); err != nil {
		t.Fatalf("read committed pool: %v", err)
	}
	if committed != "10.0.0.128/25" {
		t.Fatalf("committed pool_cidr = %q, want 10.0.0.128/25", committed)
	}
	rows, err := poolResize.Query(ctx, "SELECT assigned_ip FROM devices WHERE org_id=$1 AND status='active' AND deleted_at IS NULL AND assigned_ip IS NOT NULL", org)
	if err != nil {
		t.Fatalf("scan devices: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		pa, perr := netip.ParseAddr(a)
		if perr != nil || !newP.Contains(pa) {
			t.Fatalf("INVARIANT VIOLATED: device %q is stranded outside the committed pool %s", a, newP)
		}
	}
}
