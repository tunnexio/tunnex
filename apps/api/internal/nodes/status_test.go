package nodes

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestReportStatus verifies per-peer telemetry maps to the right device (by
// node_id + public_key), an unknown pubkey is a no-op, and a report for a pubkey
// that lives on a DIFFERENT node does not update it (cross-node isolation).
func TestReportStatus(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
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
	q := sqlc.New(tx)
	svc := &Service{q: q}

	org, user := uuid.New(), uuid.New()
	node1, node2 := uuid.New(), uuid.New()
	var dev1 uuid.UUID
	mustExec := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("exec %q: %v", sql, e)
		}
	}
	mustExec("INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "s-"+org.String())
	mustExec("INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", user, user.String()+"@t")
	mustExec("INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'n1',$3)", node1, org, "c1-"+node1.String())
	mustExec("INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'n2',$3)", node2, org, "c2-"+node2.String())
	// device on node1 (pubkey K1) and device on node2 (pubkey K2).
	if err := tx.QueryRow(ctx, "INSERT INTO devices (org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, 'd1', 'kJ+D3mNKUQzae+23TrhT0g08UTSh9DfxXpKVyGw28EE=', '10.99.0.2') RETURNING id", org, user, node1).Scan(&dev1); err != nil {
		t.Fatalf("device1: %v", err)
	}
	mustExec("INSERT INTO devices (org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, 'd2', 'U1UKutt7rp0rN6FwRxL8NtPdPs55fpGRZiPq9MsrCbE=', '10.99.0.3')", org, user, node2)

	node1Row, err := q.GetNodeByCertSerial(ctx, "c1-"+node1.String())
	if err != nil {
		t.Fatalf("get node1: %v", err)
	}

	// Report for K1 (node1) + an unknown pubkey (no-op).
	hs := time.Now().Unix()
	if err := svc.ReportStatus(ctx, node1Row, []PeerStatus{
		{PublicKey: "kJ+D3mNKUQzae+23TrhT0g08UTSh9DfxXpKVyGw28EE=", LastHandshake: hs, RxBytes: 100, TxBytes: 200},
		{PublicKey: "WlEiCXJIkuDu09Ji0dvI1RwdkbLwkZ+qdR/M0r6/I94=", LastHandshake: hs, RxBytes: 9, TxBytes: 9},
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	// Exactly one status row (K1's device); rx/tx recorded.
	var count, rx int64
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM device_status").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("want 1 status row (unknown pubkey is a no-op), got %d", count)
	}
	if err := tx.QueryRow(ctx, "SELECT rx_bytes FROM device_status WHERE device_id=$1", dev1).Scan(&rx); err != nil {
		t.Fatalf("status for dev1: %v", err)
	}
	if rx != 100 {
		t.Fatalf("want rx 100, got %d", rx)
	}

	// Cross-node isolation: reporting K2 (which lives on node2) to node1 must not
	// create/update any status row.
	if err := svc.ReportStatus(ctx, node1Row, []PeerStatus{{PublicKey: "U1UKutt7rp0rN6FwRxL8NtPdPs55fpGRZiPq9MsrCbE=", RxBytes: 555}}); err != nil {
		t.Fatalf("cross-node report: %v", err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM device_status").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("cross-node report leaked into another node's device (rows=%d)", count)
	}

	// Future-handshake clamp — a LOAD-BEARING invariant: every online reader
	// (tenancy.OnlineWindow, deviceOnline) trusts that last_handshake_at is never
	// future-dated at rest, so this is the only place it's enforced. dev1 has a
	// valid handshake from the report above; an implausibly-future report must
	// DROP it to NULL (not store it) — otherwise time.Since() goes negative and
	// pins the device "online" forever.
	future := time.Now().Add(10 * time.Minute).Unix()
	if err := svc.ReportStatus(ctx, node1Row, []PeerStatus{{PublicKey: "kJ+D3mNKUQzae+23TrhT0g08UTSh9DfxXpKVyGw28EE=", LastHandshake: future, RxBytes: 101}}); err != nil {
		t.Fatalf("future report: %v", err)
	}
	var hsValid bool
	if err := tx.QueryRow(ctx, "SELECT last_handshake_at IS NOT NULL FROM device_status WHERE device_id=$1", dev1).Scan(&hsValid); err != nil {
		t.Fatalf("hs check: %v", err)
	}
	if hsValid {
		t.Fatal("future-dated handshake must be stored as NULL (else it pins the device online forever)")
	}

	// Skew tolerance: a slightly-future handshake (within the allowed skew) IS
	// stored — the clamp rejects bogus clocks, not normal jitter.
	withinSkew := time.Now().Add(30 * time.Second).Unix()
	if err := svc.ReportStatus(ctx, node1Row, []PeerStatus{{PublicKey: "kJ+D3mNKUQzae+23TrhT0g08UTSh9DfxXpKVyGw28EE=", LastHandshake: withinSkew, RxBytes: 102}}); err != nil {
		t.Fatalf("within-skew report: %v", err)
	}
	if err := tx.QueryRow(ctx, "SELECT last_handshake_at IS NOT NULL FROM device_status WHERE device_id=$1", dev1).Scan(&hsValid); err != nil {
		t.Fatalf("hs check 2: %v", err)
	}
	if !hsValid {
		t.Fatal("a handshake within the skew tolerance must be stored")
	}
}

// TestReportStatusNodePeerSibling (S8.6 Slice 1) — the SAME agent report feeds node_peer_status for
// GATEWAY peers (a peer pubkey that is another node) while device peers still land in device_status, and
// NEITHER crosses. This is the S8.5 UpsertDeviceStatus gateway-peer no-op's sibling — REPORTED != STORED,
// fixed: the CP finally stores the gateway-peer telemetry the agent already sends.
func TestReportStatusNodePeerSibling(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
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
	q := sqlc.New(tx)
	svc := &Service{q: q}

	org, user := uuid.New(), uuid.New()
	hub, spoke := uuid.New(), uuid.New()
	var devID uuid.UUID
	mustExec := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("exec %q: %v", sql, e)
		}
	}
	mustExec("INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "s-"+org.String())
	mustExec("INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", user, user.String()+"@t")
	// hub = the reporting gateway; spoke = a peer GATEWAY (carries a wg_public_key — a site-link peer).
	mustExec("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key) VALUES ($1,$2,'hub',$3,'HUBKEY')", hub, org, "c-hub-"+hub.String())
	mustExec("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key) VALUES ($1,$2,'spoke',$3,'5JvSqr+WZoVEq5LYgT0Wg/0xODukgcYGkR/IrMUWFVc=')", spoke, org, "c-spoke-"+spoke.String())
	// A DEVICE on the hub (pubkey DEVKEY) — a device peer in the same report.
	if err := tx.QueryRow(ctx, "INSERT INTO devices (org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, 'd', 'cwwtaql3GZodWq8nLUY1IQz315N5q2fU8bSAfpg57KA=', '10.99.0.2') RETURNING id", org, user, hub).Scan(&devID); err != nil {
		t.Fatalf("device: %v", err)
	}
	hubRow, err := q.GetNodeByCertSerial(ctx, "c-hub-"+hub.String())
	if err != nil {
		t.Fatalf("get hub: %v", err)
	}

	// The hub reports BOTH peers in ONE report: a device (DEVKEY) and a gateway (SPOKEKEY = the spoke node).
	hs := time.Now().Unix()
	if err := svc.ReportStatus(ctx, hubRow, []PeerStatus{
		{PublicKey: "cwwtaql3GZodWq8nLUY1IQz315N5q2fU8bSAfpg57KA=", LastHandshake: hs, RxBytes: 10, TxBytes: 20},
		{PublicKey: "5JvSqr+WZoVEq5LYgT0Wg/0xODukgcYGkR/IrMUWFVc=", LastHandshake: hs, RxBytes: 30, TxBytes: 40},
	}); err != nil {
		t.Fatalf("report: %v", err)
	}

	// node_peer_status: EXACTLY the gateway peer landed — (hub, SPOKEKEY), rx 30. The device peer did NOT
	// cross in.
	var npCount int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM node_peer_status WHERE node_id=$1", hub).Scan(&npCount); err != nil {
		t.Fatal(err)
	}
	if npCount != 1 {
		t.Fatalf("node_peer_status must hold ONLY the gateway peer (SPOKEKEY), got %d rows", npCount)
	}
	var npRx int64
	if err := tx.QueryRow(ctx, "SELECT rx_bytes FROM node_peer_status WHERE node_id=$1 AND public_key='5JvSqr+WZoVEq5LYgT0Wg/0xODukgcYGkR/IrMUWFVc='", hub).Scan(&npRx); err != nil {
		t.Fatalf("the gateway-peer row (hub, SPOKEKEY) must exist: %v", err)
	}
	if npRx != 30 {
		t.Fatalf("gateway-peer rx must be stored, got %d", npRx)
	}
	// NEITHER crosses: the DEVICE peer is NOT in node_peer_status; the GATEWAY peer is NOT in device_status.
	var devInNodePeer, gwInDevice int
	_ = tx.QueryRow(ctx, "SELECT count(*) FROM node_peer_status WHERE node_id=$1 AND public_key='cwwtaql3GZodWq8nLUY1IQz315N5q2fU8bSAfpg57KA='", hub).Scan(&devInNodePeer)
	if devInNodePeer != 0 {
		t.Fatal("a DEVICE peer must NOT land in node_peer_status (neither crosses)")
	}
	// device_status holds the device peer (unchanged behavior); the gateway peer no-ops there.
	var devStatus int
	_ = tx.QueryRow(ctx, "SELECT count(*) FROM device_status WHERE device_id=$1", devID).Scan(&devStatus)
	if devStatus != 1 {
		t.Fatalf("the device peer must still land in device_status (behavior unchanged), got %d", devStatus)
	}
	_ = tx.QueryRow(ctx, "SELECT count(*) FROM device_status ds JOIN devices d ON d.id=ds.device_id WHERE d.public_key='5JvSqr+WZoVEq5LYgT0Wg/0xODukgcYGkR/IrMUWFVc='").Scan(&gwInDevice)
	if gwInDevice != 0 {
		t.Fatal("a GATEWAY peer must NOT land in device_status (neither crosses)")
	}
}
