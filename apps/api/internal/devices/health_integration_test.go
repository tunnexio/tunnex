package devices

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// activeDevice seeds an active device with a WG key + assigned IP so it appears in
// the peer/desired-state readers. Returns its id.
func activeDevice(t *testing.T, ctx context.Context, tx pgx.Tx, org, user, node uuid.UUID, pub, ip string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := tx.Exec(ctx,
		"INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status) VALUES ($1,$2,$3,$4,$5,$6,$7,'active')",
		id, org, user, node, "d-"+id.String()[:8], pub, ip); err != nil {
		t.Fatalf("device: %v", err)
	}
	return id
}

func setBlocked(t *testing.T, ctx context.Context, tx pgx.Tx, id uuid.UUID, blocked bool) {
	t.Helper()
	if _, err := tx.Exec(ctx, "UPDATE devices SET health_blocked=$2 WHERE id=$1", id, blocked); err != nil {
		t.Fatalf("set blocked: %v", err)
	}
}

func seedHealth(t *testing.T, ctx context.Context, tx pgx.Tx, id uuid.UUID, plat, osv string, disk *bool, state string, reportedAt time.Time) {
	t.Helper()
	if _, err := tx.Exec(ctx,
		"INSERT INTO device_health (device_id,platform,os_version,disk_encrypted,evaluated_state,failed_checks,reported_at) VALUES ($1,$2,$3,$4,$5,'[]',$6)",
		id, plat, osv, disk, state, reportedAt); err != nil {
		t.Fatalf("seed health: %v", err)
	}
}

// [1] RED — downgrade release: a device left health_blocked (by a prior enterprise
// deployment) is excluded from every gateway; ReleaseAllHealthBlocks (open-build
// boot) MUST free it so its /32 returns to the peer set. Disabling the feature
// releases its enforcement — never petrifies it.
func TestReleaseAllHealthBlocksReturnsPeer(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	pub := "aGVhbHRoYmxvY2tlZHBlZXJrZXkwMDAwMDAwMDAwMD0="
	id := activeDevice(t, ctx, tx, org, user, node, pub, "10.0.0.5")

	setBlocked(t, ctx, tx, id, true)
	if got := peerKeys(t, svc, node); len(got) != 0 {
		t.Fatalf("blocked device must be excluded from peers, got %v", got)
	}

	n, err := svc.ReleaseAllHealthBlocks(ctx)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 released, got %d", n)
	}
	if got := peerKeys(t, svc, node); len(got) != 1 || got[0] != pub {
		t.Fatalf("released device must return to peers, got %v", got)
	}
	// Idempotent: a second boot releases nothing.
	if n, _ := svc.ReleaseAllHealthBlocks(ctx); n != 0 {
		t.Fatalf("second release must be a no-op, got %d", n)
	}
}

// [3] RED — a configured-check org with a blocked device: ListForOrg MUST surface
// the block (Health non-nil, Blocked true) so the admin sees "posture blocked".
// The prior code hid the whole surface on a config-read error; the surface is now
// gated by (bool,error) that PROPAGATES rather than silently omitting.
func TestListForOrgSurfacesBlockWhenChecksConfigured(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	pub := "c3VyZmFjZWJsb2NrZWRwZWVya2V5MDAwMDAwMDAwMD0="
	id := activeDevice(t, ctx, tx, org, user, node, pub, "10.0.0.6")
	setBlocked(t, ctx, tx, id, true)
	disk := false
	seedHealth(t, ctx, tx, id, "macos", "14.0", &disk, "noncompliant", time.Now())

	// No checks configured yet → surface inactive → no posture noise.
	before, err := svc.ListForOrg(ctx, org)
	if err != nil {
		t.Fatalf("list (no checks): %v", err)
	}
	if before[0].Health != nil {
		t.Fatal("no configured checks must yield no health surface")
	}

	// Opt into a check → the active block MUST become visible.
	if _, err := tx.Exec(ctx, "INSERT INTO org_health_checks (org_id,check_kind,mode) VALUES ($1,'disk_encryption','require')", org); err != nil {
		t.Fatalf("config: %v", err)
	}
	after, err := svc.ListForOrg(ctx, org)
	if err != nil {
		t.Fatalf("list (with check): %v", err)
	}
	h := after[0].Health
	if h == nil || !h.Blocked || h.State != "noncompliant" {
		t.Fatalf("configured check must surface the live block, got %+v", h)
	}
}

// [5] RED — would-fail blast radius must NOT count STALE devices: a device whose
// last report is past the TTL is posture_unknown (will never report again, never
// blocked), so it must not inflate the save banner. Only a FRESH non-compliant
// report counts.
func TestWouldFailExcludesStaleReports(t *testing.T) {
	ctx, tx := txOrSkip(t)
	svc, org, user, node := setup(t, tx, 10)
	disk := false

	fresh := activeDevice(t, ctx, tx, org, user, node, "ZnJlc2hkZXZpY2VwdWJrZXkwMDAwMDAwMDAwMDAwMD0=", "10.0.0.7")
	seedHealth(t, ctx, tx, fresh, "macos", "14.0", &disk, "compliant", time.Now())
	stale := activeDevice(t, ctx, tx, org, user, node, "c3RhbGVkZXZpY2VwdWJrZXkwMDAwMDAwMDAwMDAwMD0=", "10.0.0.8")
	seedHealth(t, ctx, tx, stale, "macos", "14.0", &disk, "noncompliant", time.Now().Add(-HealthStaleTTL-time.Hour))

	// Enable disk_encryption=require. Both devices last reported disk_encrypted=false,
	// but only the FRESH one will actually be blocked at its next report.
	wouldFail, err := svc.SetHealthCheck(ctx, user, org, CheckDiskEncryption, ModeRequire, nil)
	if err != nil {
		t.Fatalf("set check: %v", err)
	}
	if wouldFail != 1 {
		t.Fatalf("stale device must not be counted: want 1, got %d", wouldFail)
	}
}
