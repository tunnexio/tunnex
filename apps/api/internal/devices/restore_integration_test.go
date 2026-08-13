//go:build enterprise

package devices

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
)

// restoreFixture is a committed org + owner + gateway plus helpers that mutate device rows directly, so each test
// can construct the exact revocation SHAPE it needs — including the pre-0059 NULL-cause shape that production code
// can no longer produce. A fixture that cannot express the failing case cannot catch it.
type restoreFixture struct {
	ctx              context.Context
	pool             *pgxpool.Pool
	svc              *Service
	org, owner, node uuid.UUID
}

func seedRestoreFixture(t *testing.T) *restoreFixture {
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

	f := &restoreFixture{ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(), node: uuid.New()}
	ex := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'O',$2,'10.99.0.0/24',0)",
		f.org, "rest-"+f.org.String())
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", f.owner, f.owner.String()+"@t.local")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", f.org, f.owner)
	ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,'gw.example.com:51820')",
		f.node, f.org, "serial-"+f.node.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", f.org) })

	f.svc = NewService(pool, nodepush.New(), nil)
	return f
}

func (f *restoreFixture) addDevice(t *testing.T, name, ip string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,transport)
		 VALUES ($1,$2,$3,$4,$5,'linux',$6,$7,'active','wireguard')`,
		id, f.org, f.owner, f.node, name, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4="+id.String(), ip); err != nil {
		t.Fatalf("addDevice %s: %v", name, err)
	}
	return id
}

// revokeDeliberately mirrors what RevokeDevice writes: cause='deliberate', address PRESERVED.
func (f *restoreFixture) revokeDeliberately(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE devices SET status='revoked', revoked_at=now(), revoked_cause='deliberate' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
}

// revokeGatewayCascade mirrors RevokeDevicesForNode: it sweeps whatever is still active/pending, exactly as a
// gateway revocation does, so a deliberately-revoked row is already out of range.
func (f *restoreFixture) revokeGatewayCascade(t *testing.T) {
	t.Helper()
	// CALLS THE PRODUCTION SWEEP, rather than restating it.
	//
	// This helper used to hand-write the UPDATE, and the EPIC 13 walk found what that hides: the production
	// query had never been given `revoked_prev_status` (a bare string replace whose anchor missed by one space),
	// while this fixture set it. The red then asserted against a fixture simulating a fix that did not exist,
	// and passed — only the wire caught it.
	//
	// A fixture that RESTATES production tests the restatement. Calling the real query makes the divergence
	// impossible by construction.
	if _, err := f.svc.q.RevokeDevicesForNode(f.ctx, f.node); err != nil {
		t.Fatalf("cascade sweep: %v", err)
	}
}

// revokeWithNoCause reproduces the PRE-0059 row shape, which production code can no longer write.
func (f *restoreFixture) revokeWithNoCause(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE devices SET status='revoked', revoked_at=now(), revoked_cause=NULL WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
}

func (f *restoreFixture) statusOf(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.pool.QueryRow(f.ctx, "SELECT status FROM devices WHERE id=$1", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRestoreNeverRevivesADeliberatelyRevokedDevice — THE load-bearing property of D5, and the reason the cause
// column exists at all.
//
// Wall 6 could not be closed without it: un-revoking the whole cascade set would have resurrected a device an
// operator deliberately killed (a lost laptop), and refusing to un-revoke anything left every user of a rebuilt
// gateway needing a re-issued one-time config. "Its gateway went away" and "the user lost the laptop" rendered
// IDENTICALLY before this column, so the two outcomes were indistinguishable to any code that tried.
//
// A lost laptop coming back online because someone rebuilt a gateway is a security failure, not an inconvenience.
func TestRestoreNeverRevivesADeliberatelyRevokedDevice(t *testing.T) {
	f := seedRestoreFixture(t)

	// Two devices on the same gateway: one revoked BY THE CASCADE, one revoked ON PURPOSE.
	cascade := f.addDevice(t, "laptop-cascade", "10.99.0.10")
	deliberate := f.addDevice(t, "laptop-lost", "10.99.0.11")

	f.revokeDeliberately(t, deliberate)
	f.revokeGatewayCascade(t) // sweeps whatever is still active — i.e. only `cascade`

	got, err := f.svc.RestoreCascadeRevokedDevices(f.ctx, f.org, f.node, f.node, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	restored := map[uuid.UUID]bool{}
	for _, r := range got {
		restored[r.DeviceID] = true
	}
	if !restored[cascade] {
		t.Error("a cascade-revoked device MUST be restored — leaving it revoked is Wall 6: a recovered gateway with " +
			"zero users, each needing a re-issued one-time config")
	}
	if restored[deliberate] {
		t.Fatal("a DELIBERATELY revoked device must NEVER be revived by a gateway coming back. An operator decided " +
			"this device must stop; a gateway rebuild is not a decision about it, and reviving a lost laptop " +
			"because someone rebuilt a gateway is a security failure")
	}
	if s := f.statusOf(t, deliberate); s != "revoked" {
		t.Errorf("the deliberately revoked device must still be revoked, got %q", s)
	}
}

// TestRestoreReclaimsTheOriginalAddressWhenFree — the ruled fork's common case, which must cost users nothing.
//
// A gateway rebuilt within minutes with nothing else having taken the address: the user's existing WireGuard config
// keeps working, because the interface address it embeds is still theirs. Unconditionally allocating fresh would
// impose a fleet-wide re-import for a contention that usually did not happen.
func TestRestoreReclaimsTheOriginalAddressWhenFree(t *testing.T) {
	f := seedRestoreFixture(t)
	dev := f.addDevice(t, "laptop", "10.99.0.20")
	f.revokeGatewayCascade(t)

	got, err := f.svc.RestoreCascadeRevokedDevices(f.ctx, f.org, f.node, f.node, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 restored, got %d", len(got))
	}
	if !got[0].KeptAddress || got[0].NewIP != "10.99.0.20" {
		t.Errorf("the original address must be reclaimed when nothing took it (kept=%v ip=%q) — the common case is a "+
			"gateway rebuilt within minutes, and that case must not invalidate every user's config",
			got[0].KeptAddress, got[0].NewIP)
	}
	if f.statusOf(t, dev) != "active" {
		t.Error("the restored device must be active")
	}
}

// TestRestoreAllocatesFreshWhenTheAddressWasTaken — the fallback, and the case that must be visibly different.
//
// The address may be genuinely gone: reallocated to a live device now using it. Restore cannot take it back, so the
// device returns on a NEW address — which means its exported profile embeds the wrong one and will not connect until
// re-imported. That is why this case is reported distinctly rather than silently.
func TestRestoreAllocatesFreshWhenTheAddressWasTaken(t *testing.T) {
	f := seedRestoreFixture(t)
	f.addDevice(t, "laptop", "10.99.0.30")
	f.revokeGatewayCascade(t)
	// Someone else takes the freed address while the gateway is down — which is legitimate: the moment status left
	// ('active','pending') the pool considered it free, and both the unique index and the allocation oracle agree.
	squatter := f.addDevice(t, "someone-else", "10.99.0.30")

	got, err := f.svc.RestoreCascadeRevokedDevices(f.ctx, f.org, f.node, f.node, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 restored, got %d", len(got))
	}
	if got[0].KeptAddress {
		t.Fatal("restore must NOT reclaim an address a live device now holds — that would hand one address to two " +
			"devices and the pool's own oracle says it is taken")
	}
	if got[0].NewIP == "10.99.0.30" {
		t.Fatalf("the fresh address must differ from the held one, got %q", got[0].NewIP)
	}
	if got[0].OldIP != "10.99.0.30" {
		t.Errorf("the previous address must be reported so the change is auditable, got %q", got[0].OldIP)
	}
	if f.statusOf(t, squatter) != "active" {
		t.Error("the device that legitimately took the address must be untouched")
	}
}

// TestRestoreSkipsRowsWithNoRecordedCause — rows revoked before 0059 carry NULL, which is honestly unknown.
// Reviving one would be exactly the deliberate-revocation risk the column exists to avoid.
func TestRestoreSkipsRowsWithNoRecordedCause(t *testing.T) {
	f := seedRestoreFixture(t)
	legacy := f.addDevice(t, "legacy", "10.99.0.40")
	f.revokeWithNoCause(t, legacy) // pre-0059 shape: revoked, cause NULL

	got, err := f.svc.RestoreCascadeRevokedDevices(f.ctx, f.org, f.node, f.node, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, r := range got {
		if r.DeviceID == legacy {
			t.Fatal("a device revoked before the cause column existed must NOT be restored: nobody recorded why, " +
				"and 'I cannot tell' must never resolve to 'it is safe to revive'")
		}
	}
}

// addNode seeds a second gateway — the REPLACEMENT an operator restores onto.
func (f *restoreFixture) addNode(t *testing.T, name string, revoked bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	status, rev := "active", "NULL"
	if revoked {
		status, rev = "revoked", "now()"
	}
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status,revoked_at)
		VALUES ($1,$2,$3,$4,$5,'gw.example.com:51820',$6,`+rev+`)`,
		id, f.org, name, "serial-"+id.String(), "c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=", status); err != nil {
		t.Fatalf("addNode %s: %v", name, err)
	}
	return id
}

func (f *restoreFixture) nodeOf(t *testing.T, deviceID uuid.UUID) uuid.UUID {
	t.Helper()
	var n uuid.UUID
	if err := f.pool.QueryRow(f.ctx, "SELECT node_id FROM devices WHERE id=$1", deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestOperatorRestoreIsREACHABLE — the Slice 7 red, and it is written to prove REACHABILITY, not behaviour.
//
// THE DEFECT IT CLOSES. Every earlier restore red called RestoreCascadeRevokedDevices directly and passed. They
// proved the restore does the right thing WHEN CALLED. Nothing proved it is ever called — and it was not:
// devices are cascade-revoked only by nodes.Revoke, and re-key REFUSES a revoked node (D3), so the only trigger
// that created the work put the node into the one state that could never reach the code which undoes it.
//
// So this red drives the OPERATOR'S ENTRY POINT — the same function the HTTP handler calls, with the same
// arguments a request produces — and asserts devices come back THROUGH it. A test that called the inner function
// would re-commit the original error with more code around it.
func TestOperatorRestoreIsREACHABLE(t *testing.T) {
	f := seedRestoreFixture(t)
	actor := f.owner
	replacement := f.addNode(t, "gw-replacement-"+uuid.NewString()[:8], false)

	keeps := f.addDevice(t, "keeps-address", "10.99.0.11")
	f.revokeGatewayCascade(t) // the gateway was revoked; every device homed on it went with it

	res, err := f.svc.RestoreCascadedDevicesByOperator(t.Context(), actor, f.org, f.node, replacement)
	if err != nil {
		t.Fatalf("the operator entry point must restore: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 device restored through the operator trigger, got %d", len(res))
	}
	if got := f.statusOf(t, keeps); got != "active" {
		t.Fatalf("the device must be active again; got %q", got)
	}

	// RE-HOMED, and this is why the trigger takes a target at all: the source gateway is revoked and never
	// coming back, so restoring onto it would produce an `active` device pointing at something that will never
	// serve it — a row that reads healthy on every surface and works nowhere.
	if got := f.nodeOf(t, keeps); got != replacement {
		t.Fatalf("the restored device must be homed to the REPLACEMENT gateway; got %v want %v", got, replacement)
	}

	// The act is on the record, with the HUMAN who did it — the authorization story of Slice 7 in one row.
	var actorID uuid.UUID
	var meta []byte
	if err := f.pool.QueryRow(f.ctx,
		`SELECT actor_user_id, metadata FROM audit_logs WHERE org_id=$1 AND action='node.devices_restored'
		 ORDER BY created_at DESC LIMIT 1`, f.org).Scan(&actorID, &meta); err != nil {
		t.Fatalf("the operator restore must be audited: %v", err)
	}
	if actorID != actor {
		t.Fatalf("the audit row must name the human who asked; got %v", actorID)
	}
	if !strings.Contains(string(meta), replacement.String()) {
		t.Fatalf("the audit must record which gateway the devices were restored onto; got %s", meta)
	}
}

// TestOperatorRestoreRefusesADEADTarget — the obvious operator mistake, refused.
//
// The natural thing to type is the gateway you just revoked. That node can never serve these devices again, so
// accepting it would hand back rows that are `active` and unreachable — worse than leaving them revoked, because
// revoked is honest and this is not.
func TestOperatorRestoreRefusesADEADTarget(t *testing.T) {
	f := seedRestoreFixture(t)
	dead := f.addNode(t, "gw-dead-"+uuid.NewString()[:8], true)
	d := f.addDevice(t, "stays-dead", "10.99.0.21")
	f.revokeGatewayCascade(t)

	if _, err := f.svc.RestoreCascadedDevicesByOperator(t.Context(), f.owner, f.org, f.node, dead); !errors.Is(err, ErrRestoreTargetUnusable) {
		t.Fatalf("a REVOKED target must be refused; got %v", err)
	}
	if got := f.statusOf(t, d); got != "revoked" {
		t.Fatalf("a refused restore must change nothing; device is %q", got)
	}

	// A target in ANOTHER org is the same refusal — the source is org-scoped and so is the target, or an admin
	// could rehome another tenant's devices onto their own gateway.
	if _, err := f.svc.RestoreCascadedDevicesByOperator(t.Context(), f.owner, f.org, f.node, uuid.New()); !errors.Is(err, ErrRestoreTargetUnusable) {
		t.Fatalf("an unknown/foreign target must be refused; got %v", err)
	}
	if _, err := f.svc.RestoreCascadedDevicesByOperator(t.Context(), f.owner, f.org, uuid.New(), f.addNode(t, "gw-ok-"+uuid.NewString()[:8], false)); !errors.Is(err, ErrRestoreSourceUnknown) {
		t.Fatalf("an unknown source must be refused distinctly; got %v", err)
	}
}

// TestOperatorRestoreIsAuditedEVENWhenNothingComesBack — the swallowed-audit law, one step earlier.
//
// "An admin restored a gateway's devices and nothing came back" is exactly the event someone needs to find later.
// An audit that only fires when work happened cannot answer "did anyone try?".
func TestOperatorRestoreIsAuditedEVENWhenNothingComesBack(t *testing.T) {
	f := seedRestoreFixture(t)
	target := f.addNode(t, "gw-empty-"+uuid.NewString()[:8], false)

	res, err := f.svc.RestoreCascadedDevicesByOperator(t.Context(), f.owner, f.org, f.node, target)
	if err != nil {
		t.Fatalf("restoring nothing is a normal answer, not an error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("no candidates existed; got %d", len(res))
	}
	var n int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='node.devices_restored'`, f.org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the attempt must be audited even with zero candidates; got %d rows", n)
	}
}

// TestRestoreRefusesWhenTheTargetWasREVOKEDUnderIt — review pass 1 #7.
//
// The re-key path calls restore AFTER its own transaction commits, so authorization was taken against a state
// that may since have changed. An operator revoke landing in that window cascade-revokes these very devices, and
// restoring them re-activates what a human just deliberately switched off — the device tier contradicting D3
// while the node tier obeys it. The row is read FOR UPDATE inside the restore's own transaction, so a concurrent
// revoke either commits first (seen, refused) or waits.
func TestRestoreRefusesWhenTheTargetWasREVOKEDUnderIt(t *testing.T) {
	f := seedRestoreFixture(t)
	d := f.addDevice(t, "victim", "10.99.0.31")
	f.revokeGatewayCascade(t)

	// The node is revoked between the caller's decision and the restore — modelled by revoking it first, which is
	// the state the restore will read.
	if _, err := f.pool.Exec(f.ctx, "UPDATE nodes SET status='revoked', revoked_at=now() WHERE id=$1", f.node); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RestoreCascadeRevokedDevices(t.Context(), f.org, f.node, f.node, nil); !errors.Is(err, ErrRestoreTargetUnusable) {
		t.Fatalf("restoring onto a node that is no longer active must be refused; got %v", err)
	}
	if got := f.statusOf(t, d); got != "revoked" {
		t.Fatalf("a refused restore must change nothing; device is %q", got)
	}
}

// TestRestoreDoesNotPromoteANEVERAPPROVEDDevice — review pass 1 #8.
//
// The restore statement used to assert status='active' for a set whose members were not all active. A device
// sitting in `pending` — never approved by anyone — came back APPROVED, silently bypassing the org's device
// gate. The schema recorded WHY a device was revoked and not WHAT IT WAS.
func TestRestoreDoesNotPromoteANEVERAPPROVEDDevice(t *testing.T) {
	f := seedRestoreFixture(t)
	if _, err := f.pool.Exec(f.ctx, "UPDATE organizations SET device_approval='on' WHERE id=$1", f.org); err != nil {
		t.Fatal(err)
	}
	approved := f.addDevice(t, "was-active", "10.99.0.41")
	pendingDev := f.addDevice(t, "was-pending", "10.99.0.42")
	if _, err := f.pool.Exec(f.ctx, "UPDATE devices SET status='pending' WHERE id=$1", pendingDev); err != nil {
		t.Fatal(err)
	}
	f.revokeGatewayCascade(t)

	if _, err := f.svc.RestoreCascadeRevokedDevices(t.Context(), f.org, f.node, f.node, nil); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := f.statusOf(t, approved); got != "active" {
		t.Fatalf("a device that WAS active must come back active; got %q", got)
	}
	if got := f.statusOf(t, pendingDev); got != "pending" {
		t.Fatalf("a device that was PENDING must come back pending — a gateway rebuild must not grant an approval "+
			"no human granted; got %q", got)
	}
}

// TestRestoreReclaimsONLYAnAddressStillInsideThePool — review pass 1 #14.
//
// 0059 stopped clearing assigned_ip so a revoked row remembers what it held, and that is right for taken-ness.
// But the pool can be SHRUNK while those rows are invisible to the shrink guard, which inspects live allocations
// only. Reclaiming then hands a device an address its own org no longer routes — broken, and clean on every
// surface. Taken-ness and validity are different questions.
func TestRestoreReclaimsONLYAnAddressStillInsideThePool(t *testing.T) {
	f := seedRestoreFixture(t)
	outside := f.addDevice(t, "outside-pool", "10.99.0.200")
	f.revokeGatewayCascade(t)
	// The pool shrinks under the revoked row — exactly what the orphan guard cannot see.
	if _, err := f.pool.Exec(f.ctx, "UPDATE organizations SET pool_cidr='10.99.0.0/28' WHERE id=$1", f.org); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.RestoreCascadeRevokedDevices(t.Context(), f.org, f.node, f.node, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 restored, got %d", len(res))
	}
	if res[0].KeptAddress {
		t.Fatal("an address outside the org's CURRENT pool must NOT be reclaimed — nothing routes it, and the " +
			"device would read healthy everywhere and work nowhere")
	}
	var ip string
	if err := f.pool.QueryRow(f.ctx, "SELECT assigned_ip FROM devices WHERE id=$1", outside).Scan(&ip); err != nil {
		t.Fatal(err)
	}
	if ip == "10.99.0.200" {
		t.Fatal("the out-of-pool address was handed back")
	}
}

// TestRestoreRevivesTheOVPNCERTIFICATEToo — review pass 1 #9.
//
// Revoking a node is a THREE-PART ACT: the device rows, their OpenVPN client certificates, and the org CRL. The
// restore reversed one third, producing a state no revoke/restore pair should reach — control plane green, data
// plane refusing, operator told it succeeded. The device was `active` and its certificate was still revoked and
// still on the CRL, so the user's profile was rejected at connect time with nothing on any surface to explain it.
func TestRestoreRevivesTheOVPNCERTIFICATEToo(t *testing.T) {
	f := seedRestoreFixture(t)
	dev := f.addDevice(t, "ovpn-user", "10.99.0.51")
	if _, err := f.pool.Exec(f.ctx, "UPDATE devices SET transport='openvpn' WHERE id=$1", dev); err != nil {
		t.Fatal(err)
	}
	// A deliberately-revoked certificate on ANOTHER device, to prove the cause discrimination survives here too.
	other := f.addDevice(t, "ovpn-retired", "10.99.0.52")
	if _, err := f.pool.Exec(f.ctx, "UPDATE devices SET transport='openvpn' WHERE id=$1", other); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		id     uuid.UUID
		serial string
		// UNIQUE PER RUN: ovpn_client_certs.serial is globally unique, so fixed literals make a test that passes
		// exactly once and then fails on a constraint forever after — a fixture whose first green is the only one.
	}{{dev, "A1-" + uuid.NewString()}, {other, "A2-" + uuid.NewString()}} {
		if _, err := f.pool.Exec(f.ctx,
			`INSERT INTO ovpn_client_certs (org_id, device_id, serial, common_name, not_after)
			 VALUES ($1,$2,$3,'cn',now() + interval '365 days')`, f.org, d.id, d.serial); err != nil {
			t.Fatal(err)
		}
	}
	// `other`'s certificate is retired by a human BEFORE the gateway is revoked.
	if _, err := f.pool.Exec(f.ctx,
		"UPDATE ovpn_client_certs SET revoked_at=now(), revoked_cause='deliberate' WHERE device_id=$1", other); err != nil {
		t.Fatal(err)
	}
	f.revokeDeliberately(t, other)

	// The gateway revoke: devices cascade, and so do their live certificates.
	f.revokeGatewayCascade(t)
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE ovpn_client_certs SET revoked_at=now(), revoked_cause='cascade'
		 WHERE device_id=$1 AND revoked_at IS NULL`, dev); err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.RestoreCascadeRevokedDevices(t.Context(), f.org, f.node, f.node, nil); err != nil {
		t.Fatalf("restore: %v", err)
	}

	var revokedAt *time.Time
	if err := f.pool.QueryRow(f.ctx,
		"SELECT revoked_at FROM ovpn_client_certs WHERE device_id=$1", dev).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt != nil {
		t.Fatal("a restored OpenVPN device's certificate must be revived with it — otherwise the device is active " +
			"and the gateway still refuses its credential, which is the reassuring-green failure in one row")
	}
	// The deliberate one must NOT come back, by the same rule that governs the devices.
	if err := f.pool.QueryRow(f.ctx,
		"SELECT revoked_at FROM ovpn_client_certs WHERE device_id=$1", other).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == nil {
		t.Fatal("a certificate an operator revoked DELIBERATELY must never be revived by a gateway rebuild")
	}
}

// TestRestoreREFUSESAnAddressOutsideTheCURRENTPool — review pass 1 #14, and the red that row never had.
//
// #14's fix (ipalloc.InPool at restore.go:157) has been in the tree since Batch C. Every OTHER restore-address
// red covers TAKEN-ness — whether some live device now holds the address — and the decisions doc says plainly
// that "taken-ness and validity are different questions and only one was being asked." Only one was being
// TESTED, too: delete the InPool guard and every existing red stays green.
//
// THE SEQUENCE. A device is cascade-revoked with 10.99.0.200. The org's pool is then shrunk to 10.99.0.0/25,
// which excludes it. The shrink is ALLOWED because the orphan guard inspects LIVE allocations and a revoked row
// is not one — so the shrink cannot see the address it is stranding. On restore, the remembered address is free
// (nothing holds it) and every taken-ness check says "reclaim it" — handing the user an address the gateway will
// never route, while the device list, the config and the audit trail all read perfectly clean.
func TestRestoreREFUSESAnAddressOutsideTheCURRENTPool(t *testing.T) {
	f := seedRestoreFixture(t)
	d := f.addDevice(t, "stranded", "10.99.0.200")
	f.revokeGatewayCascade(t)

	// The shrink the orphan guard permits: it cannot see the revoked row holding .200.
	if _, err := f.pool.Exec(f.ctx, "UPDATE organizations SET pool_cidr='10.99.0.0/25' WHERE id=$1", f.org); err != nil {
		t.Fatal(err)
	}

	got, err := f.svc.RestoreCascadeRevokedDevices(f.ctx, f.org, f.node, f.node, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 restored, got %d", len(got))
	}
	if got[0].KeptAddress {
		t.Fatal("restore reclaimed an address OUTSIDE the org's current pool. Nothing holds it, so every " +
			"taken-ness check says it is free — but the gateway will never route it. The device comes back " +
			"'active' with a config that cannot work, and no surface says otherwise")
	}
	if got[0].NewIP == "10.99.0.200" {
		t.Fatalf("the fresh address must be inside the shrunken pool, got %q", got[0].NewIP)
	}
	if !ipalloc.InPool("10.99.0.0/25", got[0].NewIP) {
		t.Fatalf("the replacement address %q is not inside the current pool 10.99.0.0/25", got[0].NewIP)
	}
	// NOT asserted: OldIP. The remedy clears `old` to force a fresh allocation (restore.go:158), so the
	// out-of-pool path reports OldIP="" while the TAKEN path reports the previous address. That asymmetry is a
	// real audit gap — a user whose address was stranded by a shrink gets no record of what they had — but it is
	// NOT #14's subject, and encoding it here would make this red fail for a reason the remedy never promised to
	// address. Registered instead; see docs/S13.1-pass3-triage.md.
	if f.statusOf(t, d) != "active" {
		t.Error("the device must still be restored — an out-of-pool address costs a re-import, not the device")
	}
}

// TestRestoreSERIALIZESAgainstAConcurrentRevoke — review pass 1 #7, and the red that row never had.
//
// THE EXISTING RED IS SEQUENTIAL AND SAYS SO: TestRestoreRefusesWhenTheTargetWasREVOKEDUnderIt revokes the node
// FIRST, "modelled by revoking it first, which is the state the restore will read." That proves the STATUS CHECK.
// It cannot prove the FOR UPDATE lock, which is the half that addresses the actual defect — a restore authorized
// by state read BEFORE the identity commit and applied AFTER it. Delete FOR UPDATE from restore.go:81 and the
// sequential red stays green.
//
// THIS ONE IS DETERMINISTIC WITHOUT BEING SEQUENTIAL. A separate transaction takes the node's row lock and holds
// it. The restore then starts and MUST BLOCK on GetNodeForOrgForUpdate. Only after the holder revokes the node
// and commits does the restore proceed — and it must now see 'revoked' and refuse.
//
// WITHOUT THE LOCK the restore does not block: it reads the node while the revoke is still uncommitted, sees
// 'active', and restores every cascaded device onto a gateway that is being revoked out from under it. That is
// the device tier contradicting D3 while the node tier obeys it.
func TestRestoreSERIALIZESAgainstAConcurrentRevoke(t *testing.T) {
	f := seedRestoreFixture(t)
	d := f.addDevice(t, "racer", "10.99.0.51")
	f.revokeGatewayCascade(t)

	holder, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()
	if _, err := holder.Exec(f.ctx, "SELECT id FROM nodes WHERE id=$1 FOR UPDATE", f.node); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		res []RestoreResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, rerr := f.svc.RestoreCascadeRevokedDevices(context.Background(), f.org, f.node, f.node, nil)
		done <- outcome{res, rerr}
	}()

	// The restore must still be BLOCKED on the row lock. If it has already finished, it never took the lock.
	select {
	case got := <-done:
		t.Fatalf("the restore completed while another transaction held the node's row lock — it did not take "+
			"FOR UPDATE, so it read the node's status without serializing against a concurrent revoke "+
			"(err=%v, restored=%d)", got.err, len(got.res))
	case <-time.After(700 * time.Millisecond):
	}

	// The concurrent revoke commits while the restore waits.
	if _, err := holder.Exec(f.ctx, "UPDATE nodes SET status='revoked', revoked_at=now() WHERE id=$1", f.node); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-done:
		if !errors.Is(got.err, ErrRestoreTargetUnusable) {
			t.Fatalf("once the concurrent revoke committed, the restore must see it and refuse; got err=%v "+
				"restored=%d", got.err, len(got.res))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the restore never unblocked after the lock holder committed")
	}

	if got := f.statusOf(t, d); got != "revoked" {
		t.Fatalf("a restore refused because its target was revoked under it must change nothing; device is %q", got)
	}
}

// TestRestoreREBUILDSTheCRL — review pass 1 #9, the third part of the sweep, which no red asserted.
//
// Revoking a gateway is a THREE-PART act: the devices, their OpenVPN certificates, and the org CRL. Restore
// reversed the first two. TestRestoreRevivesTheOVPNCERTIFICATEToo proves the certificate tier — it revives
// `cascade` certs and correctly leaves `deliberate` ones alone — and stops there.
//
// THE CRL IS WHAT THE DATA PLANE READS. A revived certificate whose serial is still on the CRL means the control
// plane reports the device active, the operator sees green everywhere, and the OpenVPN server refuses the
// connection. That is #9's defect verbatim: "green control plane, refusing data plane." Asserting the cert rows
// without asserting the rebuild tests two thirds of a three-part sweep.
func TestRestoreREBUILDSTheCRL(t *testing.T) {
	f := seedRestoreFixture(t)
	dev := f.addDevice(t, "ovpn-crl", "10.99.0.61")
	if _, err := f.pool.Exec(f.ctx, "UPDATE devices SET transport='openvpn' WHERE id=$1", dev); err != nil {
		t.Fatal(err)
	}
	serial := "crl-" + uuid.NewString()
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO ovpn_client_certs (org_id, device_id, serial, common_name, not_after)
		 VALUES ($1,$2,$3,'cn',now()+interval '1 day')`, f.org, dev, serial); err != nil {
		t.Fatal(err)
	}
	f.revokeGatewayCascade(t)
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE ovpn_client_certs SET revoked_at=now(), revoked_cause='cascade' WHERE device_id=$1`, dev); err != nil {
		t.Fatal(err)
	}

	var rebuilt []uuid.UUID
	f.svc.rebuildCRL = func(ctx context.Context, org uuid.UUID) error {
		rebuilt = append(rebuilt, org)
		return nil
	}

	if _, err := f.svc.RestoreCascadeRevokedDevices(f.ctx, f.org, f.node, f.node, nil); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if len(rebuilt) == 0 {
		t.Fatal("restore revived a cascade-revoked OpenVPN certificate and NEVER rebuilt the CRL. The control " +
			"plane now reports the device active while its serial is still on the revocation list the OpenVPN " +
			"server enforces — green control plane, refusing data plane, which is exactly the defect")
	}
	if rebuilt[0] != f.org {
		t.Errorf("the CRL must be rebuilt for the device's own org; got %s want %s", rebuilt[0], f.org)
	}
}
