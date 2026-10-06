package serveraccess

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"os"
	"testing"
	"time"
)

// Explicitly opt-in: this test refuses every database except the owned local
// SA-0 fixture. It creates/deletes only its own random session and Redis parent.
func TestRecordingOwnedFixtureDurability(t *testing.T) {
	if os.Getenv("TUNNEX_SA0_RECORDING_DB") != "1" {
		t.Skip("requires explicit owned local fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, e := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	var database string
	var org uuid.UUID
	var count int
	if e = pool.QueryRow(ctx, `SELECT current_database(),count(*) FROM organizations GROUP BY current_database()`).Scan(&database, &count); e != nil || database != "aa0" || count != 1 {
		t.Fatal("foreign database refused")
	}
	if e = pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA-0 local qualification'`).Scan(&org); e != nil || org.String() != "01a109d9-382b-7bc1-82c9-2b0bf036139c" {
		t.Fatal("foreign organization refused")
	}
	var server, gateway, user uuid.UUID
	var epoch int64
	if e = pool.QueryRow(ctx, `SELECT id,gateway_id FROM server_access_servers WHERE org_id=$1 AND name='Local Linux fixture'`, org).Scan(&server, &gateway); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id,app_auth_epoch FROM users WHERE email='terminal-member@sa0.local'`).Scan(&user, &epoch); e != nil {
		t.Fatal(e)
	}
	master := make([]byte, 32)
	rand.Read(master)
	sealer, e := secret.NewSealer(master)
	if e != nil {
		t.Fatal(e)
	}
	clear(master)
	parents, e := session.New(os.Getenv("REDIS_URL"), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	parent, e := parents.CreateWithAuthority(ctx, user, authctx.AuthLocalPassword, epoch)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	svc := New(pool, parents, sealer, true)
	id := uuid.New()
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'test','test',$6,'fixture',1,'test','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, id, org, server, gateway, user, epoch)
	if e != nil {
		t.Fatal(e)
	}
	// Qualify the PG default independently of a concurrently configured external
	// destination. Restore settings within this same transaction: other callers
	// never observe the temporary override, while this manifest snapshots PG.
	var previousStorage []byte
	if e = tx.QueryRow(ctx, `SELECT recording_storage_sealed FROM server_access_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&previousStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=NULL WHERE org_id=$1`, org); e != nil {
		t.Fatal(e)
	}
	if e = svc.prepareRecording(ctx, tx, org, id); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, previousStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET max_payload_bytes=65536 WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	defer pool.Exec(context.Background(), `DELETE FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, id)
	start := time.Now()
	for i := 0; i < 2; i++ {
		if e = svc.capture(ctx, org, id, start, terminalwire.Frame{Type: "output", Data: bytes.Repeat([]byte("x"), 16384)}); e != nil {
			t.Fatal(e)
		}
	}
	if e = svc.capture(ctx, org, id, start, terminalwire.Frame{Type: "output", Data: bytes.Repeat([]byte("UNRECORDED"), 1638)}); authorityReason(e) != "recording_quota_reached" {
		t.Fatalf("quota must refuse before forwarding: %v", e)
	}
	var size, n int
	if e = pool.QueryRow(ctx, `SELECT payload_bytes,next_seq FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&size, &n); e != nil || size <= 32768 || size > 65536 || n != 2 {
		t.Fatalf("durable boundary wrong %d/%d %v", size, n, e)
	}
	p := &authctx.Principal{UserID: user, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}
	got, e := svc.Recording(ctx, org, id, p, false)
	if e != nil || len(got.Events) != 2 {
		t.Fatalf("qualified replay failed %v", e)
	}
	meta, e := svc.Recording(ctx, org, id, p, true)
	if e != nil || len(meta.Events) != 0 {
		t.Fatal("metadata read disclosed payload")
	}
	if _, e = svc.Recording(ctx, uuid.New(), id, p, false); e == nil {
		t.Fatal("foreign tenant read succeeded")
	}
	// Request-time roles cannot preserve administrator replay access after demotion.
	var other uuid.UUID
	if e = pool.QueryRow(ctx, `SELECT id FROM users WHERE id<>$1 LIMIT 1`, user).Scan(&other); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_sessions SET user_id=$3 WHERE org_id=$1 AND id=$2`, org, id, other); e != nil {
		t.Fatal(e)
	}
	p.Roles[org] = "admin"
	if _, e = svc.Recording(ctx, org, id, p, false); authorityReason(e) != "recording_permission_denied" {
		t.Fatalf("stale administrator role accepted: %v", e)
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_sessions SET user_id=$3 WHERE org_id=$1 AND id=$2`, org, id, user); e != nil {
		t.Fatal(e)
	}
	p.Roles[org] = "member"
	var chunk []byte
	if e = pool.QueryRow(ctx, `SELECT ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 AND seq=1`, org, id).Scan(&chunk); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `DELETE FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 AND seq=1`, org, id); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Recording(ctx, org, id, p, false); authorityReason(e) != "recording_integrity_failed" {
		t.Fatal("truncated recording accepted")
	}
	if _, e = pool.Exec(ctx, `INSERT INTO server_access_recording_chunks VALUES($1,$2,1,$3)`, org, id, chunk); e != nil {
		t.Fatal(e)
	}
	chunk[len(chunk)-1] ^= 1
	if _, e = pool.Exec(ctx, `UPDATE server_access_recording_chunks SET ciphertext=$3 WHERE org_id=$1 AND session_id=$2 AND seq=1`, org, id, chunk); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Recording(ctx, org, id, p, false); authorityReason(e) != "recording_integrity_failed" {
		t.Fatal("tampered recording accepted")
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_recordings SET expires_at=now()-interval '1 second' WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		t.Fatal(e)
	}
	if done, err := svc.expireRecordingStep(ctx, org, id); err != nil || !done {
		t.Fatalf("owned recording expiry failed: %v", err)
	}
	var status string
	var sealed []byte
	if e = pool.QueryRow(ctx, `SELECT status,key_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&status, &sealed); e != nil || status != "expired" || len(sealed) != 0 {
		t.Fatal("retention key tombstone failed")
	}
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&n); e != nil || n != 0 {
		t.Fatal("retention payload not removed")
	}
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND target_id=$2`, org, id.String()).Scan(&n); e != nil || n == 0 {
		t.Fatal("ordinary audit evidence lost")
	}
	beforeExpiredRead := n
	expired, e := svc.Recording(ctx, org, id, p, false)
	if e != nil || expired.Status != "expired" || len(expired.Events) != 0 {
		t.Fatalf("expired recording disclosed payload or lost metadata: %v", e)
	}
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND target_id=$2`, org, id.String()).Scan(&n); e != nil || n != beforeExpiredRead+1 {
		t.Fatalf("expired full read did not audit: %d => %d: %v", beforeExpiredRead, n, e)
	}
	// Durable logout denies a still-present Redis parent, independent of cache deletion.
	hash := sha256.Sum256([]byte(parent.ID))
	if _, e = pool.Exec(ctx, `INSERT INTO app_access_parent_logout_tombstones(parent_hash,user_id,parent_expires_at) VALUES($1,$2,$3)`, hash[:], user, parent.ExpiresAt); e != nil {
		t.Fatal(e)
	}
	defer pool.Exec(context.Background(), `DELETE FROM app_access_parent_logout_tombstones WHERE parent_hash=$1`, hash[:])
	if _, e = svc.Recording(ctx, org, id, p, false); authorityReason(e) != "parent_logout" {
		t.Fatalf("durable logout accepted: %v", e)
	}
	if e = parents.Delete(ctx, parent.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Recording(ctx, org, id, p, false); e == nil {
		t.Fatal("logout did not revoke replay")
	}
}

// External capture snapshots its destination even when settings change. The
// settings override is restored before commit, so other callers never see it.
func TestRecordingOwnedFixtureExternalStorage(t *testing.T) {
	if os.Getenv("TUNNEX_SA0_RECORDING_DB") != "1" {
		t.Skip("requires explicit owned local fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, e := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	var database string
	var org uuid.UUID
	var count int
	if e = pool.QueryRow(ctx, `SELECT current_database(),count(*) FROM organizations GROUP BY current_database()`).Scan(&database, &count); e != nil || database != "aa0" || count != 1 {
		t.Fatal("foreign database refused")
	}
	if e = pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA-0 local qualification'`).Scan(&org); e != nil || org.String() != "01a109d9-382b-7bc1-82c9-2b0bf036139c" {
		t.Fatal("foreign organization refused")
	}
	var server, gateway, user uuid.UUID
	var epoch int64
	if e = pool.QueryRow(ctx, `SELECT id,gateway_id FROM server_access_servers WHERE org_id=$1 AND name='Local Linux fixture'`, org).Scan(&server, &gateway); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id,app_auth_epoch FROM users WHERE email='terminal-member@sa0.local'`).Scan(&user, &epoch); e != nil {
		t.Fatal(e)
	}
	master := make([]byte, 32)
	rand.Read(master)
	sealer, e := secret.NewSealer(master)
	if e != nil {
		t.Fatal(e)
	}
	clear(master)
	parents, e := session.New(os.Getenv("REDIS_URL"), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	parent, e := parents.CreateWithAuthority(ctx, user, authctx.AuthLocalPassword, epoch)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	svc := New(pool, parents, sealer, true)
	id := uuid.New()
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'test','test',$6,'fixture',1,'test','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, id, org, server, gateway, user, epoch)
	if e != nil {
		t.Fatal(e)
	}

	root := t.TempDir()
	config := recordingStorageConfig{Org: org, Kind: "filesystem", Path: root}
	raw, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	sealed, e := svc.sealer.Seal(raw)
	clear(raw)
	if e != nil {
		t.Fatal(e)
	}
	var previousStorage []byte
	if e = tx.QueryRow(ctx, `SELECT recording_storage_sealed FROM server_access_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&previousStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, []byte(sealed)); e != nil {
		t.Fatal(e)
	}
	if e = svc.prepareRecording(ctx, tx, org, id); e != nil {
		t.Fatal(e)
	}
	// New admission ignores old direct-storage config: qualify compatibility by
	// constructing an already-persisted legacy destination snapshot explicitly.
	var pgSnapshot []byte
	if e = tx.QueryRow(ctx, `SELECT storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&pgSnapshot); e != nil || len(pgSnapshot) != 0 {
		t.Fatal("new recording did not choose PostgreSQL first")
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET storage_sealed=$3 WHERE org_id=$1 AND session_id=$2`, org, id, []byte(sealed)); e != nil {
		t.Fatal(e)
	}

	if _, e = tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, previousStorage); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	defer pool.Exec(context.Background(), `DELETE FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, id)
	var snapshot []byte
	if e = pool.QueryRow(ctx, `SELECT storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&snapshot); e != nil || !bytes.Equal(snapshot, []byte(sealed)) {
		t.Fatal("destination was not snapshotted")
	}
	start := time.Now()
	marker := []byte("EXTERNAL_ENCRYPTED_OUTPUT")
	if e = svc.capture(ctx, org, id, start, terminalwire.Frame{Type: "output", Data: marker}); e != nil {
		t.Fatal(e)
	}
	var index []byte
	if e = pool.QueryRow(ctx, `SELECT ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 AND seq=0`, org, id).Scan(&index); e != nil || len(index) != 0 {
		t.Fatal("external ciphertext remained in database")
	}
	store, e := svc.loadRecordingStorage(ctx, org, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	encrypted, e := store.Get(ctx, org, id, 0)
	if e != nil || len(encrypted) == 0 || bytes.Contains(encrypted, marker) {
		t.Fatal("external payload missing or plaintext")
	}
	p := &authctx.Principal{UserID: user, SessionID: parent.ID, Roles: map[uuid.UUID]string{org: "member"}}
	got, e := svc.Recording(ctx, org, id, p, false)
	if e != nil || len(got.Events) != 1 || !bytes.Equal(got.Events[0].Data, marker) {
		t.Fatalf("snapshot replay failed after settings restored: %v", e)
	}
	// Missing destination blocks durable capture and leaves no index/forwardable
	// event. It also refuses retention without erasing key/config or lying expired.
	hidden := root + "-unavailable"
	if e = os.Rename(root, hidden); e != nil {
		t.Fatal(e)
	}
	defer os.Rename(hidden, root)
	if e = store.Probe(ctx); e == nil {
		t.Fatal("missing legacy destination passed readiness probe")
	}
	if e = svc.capture(ctx, org, id, start, terminalwire.Frame{Type: "output", Data: []byte("MUST_NOT_FORWARD")}); e == nil {
		t.Fatal("unavailable storage accepted capture")
	}
	var n, size int
	if e = pool.QueryRow(ctx, `SELECT next_seq,payload_bytes FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&n, &size); e != nil || n != 1 || size != len(encrypted) {
		t.Fatal("failed upload committed metadata")
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_recordings SET expires_at=now()-interval '1 second' WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.expireRecordingStep(ctx, org, id); e == nil {
		t.Fatal("missing destination claimed successful cleanup")
	}
	var status string
	var key []byte
	if e = pool.QueryRow(ctx, `SELECT status,key_sealed,storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&status, &key, &snapshot); e != nil || status == "expired" || len(key) == 0 || len(snapshot) == 0 {
		t.Fatal("failed cleanup discarded key/config")
	}
	// An unavailable oldest destination must not starve an independent PG
	// recording. Use explicit owned targets, never sweep unrelated fixture rows.
	good := uuid.New()
	goodTx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer goodTx.Rollback(ctx)
	if _, e = goodTx.Exec(ctx, `INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'test','test',$6,'fixture',1,'test','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, good, org, server, gateway, user, epoch); e != nil {
		t.Fatal(e)
	}
	var originalStorage []byte
	if e = goodTx.QueryRow(ctx, `SELECT recording_storage_sealed FROM server_access_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&originalStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = goodTx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=NULL WHERE org_id=$1`, org); e != nil {
		t.Fatal(e)
	}
	if e = svc.prepareRecording(ctx, goodTx, org, good); e != nil {
		t.Fatal(e)
	}
	if _, e = goodTx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, originalStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = goodTx.Exec(ctx, `UPDATE server_access_recordings SET expires_at=now()-interval '1 second' WHERE org_id=$1 AND session_id=$2`, org, good); e != nil {
		t.Fatal(e)
	}
	if e = goodTx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	defer pool.Exec(context.Background(), `DELETE FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, good)
	if e = svc.expireRecordingTargets(ctx, []recordingExpiryTarget{{org, id}, {org, good}}); e == nil {
		t.Fatal("failed destination cleanup was not reported")
	}
	var goodStatus string
	var cooldown bool
	if e = pool.QueryRow(ctx, `SELECT status FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, good).Scan(&goodStatus); e != nil || goodStatus != "expired" {
		t.Fatal("bad destination starved good retention")
	}
	if e = pool.QueryRow(ctx, `SELECT storage_retry_after>now() FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&cooldown); e != nil || !cooldown {
		t.Fatal("failed destination did not persist retry cooldown")
	}
	if e = os.Rename(hidden, root); e != nil {
		t.Fatal(e)
	}
	// An orphan at next_seq models an upload whose metadata commit failed.
	store, e = svc.loadRecordingStorage(ctx, org, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Put(ctx, org, id, 1, encrypted); e != nil {
		t.Fatal(e)
	}
	done, e := svc.expireRecordingStep(ctx, org, id)
	if e != nil || done {
		t.Fatalf("first cleanup step lost resumable progress: %v", e)
	}
	var cursor int
	if e = pool.QueryRow(ctx, `SELECT storage_cleanup_seq,key_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&cursor, &key); e != nil || cursor != 1 || len(key) == 0 {
		t.Fatal("cleanup progress/key boundary failed")
	}
	done, e = svc.expireRecordingStep(ctx, org, id)
	if e != nil || !done {
		t.Fatalf("cleanup retry failed: %v", e)
	}
	if _, e = store.Get(ctx, org, id, 0); e == nil {
		t.Fatal("committed external payload survived retention")
	}
	if _, e = store.Get(ctx, org, id, 1); e == nil {
		t.Fatal("uncommitted external payload survived retention")
	}
	if e = pool.QueryRow(ctx, `SELECT status,key_sealed,storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&status, &key, &snapshot); e != nil || status != "expired" || len(key) != 0 || len(snapshot) != 0 {
		t.Fatal("cleanup did not remove key/destination after deletion")
	}
}

func TestRecordingOwnedFixtureResizeQuota(t *testing.T) {
	if os.Getenv("TUNNEX_SA0_RECORDING_DB") != "1" {
		t.Skip("requires explicit owned local fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, e := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	var database string
	var org uuid.UUID
	var count int
	if e = pool.QueryRow(ctx, `SELECT current_database(),count(*) FROM organizations GROUP BY current_database()`).Scan(&database, &count); e != nil || database != "aa0" || count != 1 {
		t.Fatal("foreign database refused")
	}
	if e = pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name='SA-0 local qualification'`).Scan(&org); e != nil || org.String() != "01a109d9-382b-7bc1-82c9-2b0bf036139c" {
		t.Fatal("foreign organization refused")
	}
	var server, gateway, user uuid.UUID
	var epoch int64
	if e = pool.QueryRow(ctx, `SELECT id,gateway_id FROM server_access_servers WHERE org_id=$1 AND name='Local Linux fixture'`, org).Scan(&server, &gateway); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT id,app_auth_epoch FROM users WHERE email='terminal-member@sa0.local'`).Scan(&user, &epoch); e != nil {
		t.Fatal(e)
	}
	master := make([]byte, 32)
	rand.Read(master)
	sealer, e := secret.NewSealer(master)
	if e != nil {
		t.Fatal(e)
	}
	clear(master)
	parents, e := session.New(os.Getenv("REDIS_URL"), time.Hour, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Client().Close()
	parent, e := parents.CreateWithAuthority(ctx, user, authctx.AuthLocalPassword, epoch)
	if e != nil {
		t.Fatal(e)
	}
	defer parents.Delete(context.Background(), parent.ID)
	svc := New(pool, parents, sealer, true)
	id := uuid.New()
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO server_access_sessions(id,org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,account,revision,gateway_serial,kind,status,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,'test','test',$6,'fixture',1,'test','terminal','connected',now()+interval '1 hour',now()+interval '1 hour',true)`, id, org, server, gateway, user, epoch)
	if e != nil {
		t.Fatal(e)
	}
	// Qualify the PG default independently of a concurrently configured external
	// destination. Restore settings within this same transaction: other callers
	// never observe the temporary override, while this manifest snapshots PG.
	var previousStorage []byte
	if e = tx.QueryRow(ctx, `SELECT recording_storage_sealed FROM server_access_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&previousStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=NULL WHERE org_id=$1`, org); e != nil {
		t.Fatal(e)
	}
	if e = svc.prepareRecording(ctx, tx, org, id); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, previousStorage); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET max_payload_bytes=65536 WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	defer pool.Exec(context.Background(), `DELETE FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, id)

	start := time.Now()
	captured := 0
	for ; captured < 1000; captured++ {
		e = svc.capture(ctx, org, id, start, terminalwire.Frame{Type: "resize", Rows: 24, Cols: 80})
		if authorityReason(e) == "recording_quota_reached" {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if captured == 0 || captured == 1000 {
		t.Fatal("resize ciphertext did not consume quota")
	}
	var size, n, total int
	if e = pool.QueryRow(ctx, `SELECT payload_bytes,next_seq FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&size, &n); e != nil || size <= 0 || size > 65536 || n != captured {
		t.Fatal("resize quota accounting failed")
	}
	if e = pool.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(ciphertext)),0) FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&total); e != nil || total != size {
		t.Fatal("quota did not charge persisted encrypted bytes")
	}
	if _, e = pool.Exec(ctx, `UPDATE server_access_recordings SET next_seq=4096 WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		t.Fatal(e)
	}
	if e = svc.capture(ctx, org, id, start, terminalwire.Frame{Type: "resize", Rows: 24, Cols: 80}); authorityReason(e) != "recording_quota_reached" {
		t.Fatalf("event bound ignored: %v", e)
	}
}
