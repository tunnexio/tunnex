package serveraccess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

const recordingSessionLimit = 4 << 20
const recordingOrgLimit = 64 << 20
const recordingEventLimit = 4096

// Capture stores bytes exactly, including split UTF-8/control sequences. Replay
// feeds bytes to xterm's streaming decoder. No raw input events are accepted.
type recordingEvent struct {
	Seq    int    `json:"seq"`
	Millis int64  `json:"millis"`
	Type   string `json:"type"`
	Data   []byte `json:"data,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Cols   int    `json:"cols,omitempty"`
}
type recordingKey struct {
	Org, Session uuid.UUID
	Key          []byte
}

func recordingAAD(org, id uuid.UUID, seq int) []byte {
	return []byte(fmt.Sprintf("tunnex:ssh-recording:v1:%s:%s:%d", org, id, seq))
}
func sealEvent(key []byte, org, id uuid.UUID, e recordingEvent) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, raw, recordingAAD(org, id, e.Seq)), nil
}
func openEvent(key []byte, org, id uuid.UUID, seq int, raw []byte) (recordingEvent, error) {
	var e recordingEvent
	b, err := aes.NewCipher(key)
	if err != nil {
		return e, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return e, err
	}
	if len(raw) < a.NonceSize() {
		return e, deny("recording_integrity_failed")
	}
	decoded, err := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], recordingAAD(org, id, seq))
	if err != nil {
		return e, deny("recording_integrity_failed")
	}
	if json.Unmarshal(decoded, &e) != nil || e.Seq != seq || e.Millis < 0 || e.Millis > 3600000 {
		return e, deny("recording_integrity_failed")
	}
	if e.Type == "output" {
		if len(e.Data) == 0 || len(e.Data) > terminalwire.MaxDataBytes || e.Rows != 0 || e.Cols != 0 {
			return e, deny("recording_integrity_failed")
		}
	} else if e.Type == "resize" {
		if len(e.Data) != 0 || e.Rows < 1 || e.Rows > 400 || e.Cols < 1 || e.Cols > 400 {
			return e, deny("recording_integrity_failed")
		}
	} else {
		return e, deny("recording_integrity_failed")
	}
	return e, nil
}
func (s *Service) prepareRecording(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) error {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return e
	}
	defer clear(key)
	raw, e := json.Marshal(recordingKey{org, id, key})
	if e != nil {
		return e
	}
	sealed, e := s.sealer.Seal(raw)
	clear(raw)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_recording'),hashtext($1))`, org.String())
	if e != nil {
		return e
	}
	var n, days, sessionLimit, orgLimit int
	var storageSealed []byte
	if e = tx.QueryRow(ctx, `SELECT recording_retention_days,recording_max_session_bytes,recording_max_org_bytes,recording_storage_sealed FROM server_access_settings WHERE org_id=$1 FOR SHARE`, org).Scan(&days, &sessionLimit, &orgLimit, &storageSealed); e != nil {
		return e
	}
	storageSealed = nil // New recordings are PostgreSQL-first; old manifest snapshots remain unchanged.
	e = tx.QueryRow(ctx, `SELECT COALESCE(sum(payload_bytes),0) FROM server_access_recordings WHERE org_id=$1 AND status<>'expired'`, org).Scan(&n)
	if e != nil {
		return e
	}
	if n >= orgLimit {
		return deny("recording_quota_reached")
	}
	_, e = tx.Exec(ctx, `INSERT INTO server_access_recordings(org_id,session_id,key_sealed,max_payload_bytes,max_org_bytes,expires_at,storage_sealed) VALUES($1,$2,$3,$4,$5,now()+make_interval(days => $6),$7)`, org, id, []byte(sealed), sessionLimit, orgLimit, days, storageSealed)
	return e
}
func (s *Service) recordingKey(org, id uuid.UUID, sealed []byte) ([]byte, error) {
	raw, e := s.sealer.Open(string(sealed))
	if e != nil {
		return nil, deny("recording_integrity_failed")
	}
	defer clear(raw)
	var k recordingKey
	if json.Unmarshal(raw, &k) != nil || k.Org != org || k.Session != id || len(k.Key) != 32 {
		clear(k.Key)
		return nil, deny("recording_integrity_failed")
	}
	return k.Key, nil
}

func (s *Service) postgresRecordingDestination(org uuid.UUID, sealed []byte) (bool, error) {
	if len(sealed) == 0 {
		return true, nil
	}
	c, e := s.openRecordingStorage(org, sealed)
	if e != nil {
		return false, e
	}
	return c.Kind == "postgres", nil
}

func validRecordingFrame(f terminalwire.Frame) bool {
	if f.Type == "output" {
		return len(f.Data) > 0 && len(f.Data) <= terminalwire.MaxDataBytes && f.Rows == 0 && f.Cols == 0
	}
	return f.Type == "resize" && len(f.Data) == 0 && f.Rows >= 1 && f.Rows <= 400 && f.Cols >= 1 && f.Cols <= 400
}

// Synchronous capture has no unbounded queue. Commit finishes before forwarding;
// a one-second caller deadline plus independent lease watchdog bounds failure.
func (s *Service) capture(ctx context.Context, org, id uuid.UUID, start time.Time, f terminalwire.Frame) error {
	if !validRecordingFrame(f) {
		return deny("invalid_recording_event")
	}
	millis := time.Since(start).Milliseconds()
	if millis < 0 || millis > 3600000 {
		return deny("invalid_recording_event")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_recording'),hashtext($1))`, org.String()); e != nil {
		return e
	}
	var sealed, storageSealed []byte
	var seq, size, sessionLimit, orgLimit int
	e = tx.QueryRow(ctx, `SELECT key_sealed,next_seq,payload_bytes,max_payload_bytes,max_org_bytes,storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2 AND status='capturing' AND expires_at>now() FOR UPDATE`, org, id).Scan(&sealed, &seq, &size, &sessionLimit, &orgLimit, &storageSealed)
	if e != nil {
		return deny("recording_unavailable")
	}
	if seq >= recordingEventLimit {
		return deny("recording_quota_reached")
	}
	key, e := s.recordingKey(org, id, sealed)
	if e != nil {
		return e
	}
	defer clear(key)
	chunk, e := sealEvent(key, org, id, recordingEvent{seq, millis, f.Type, f.Data, f.Rows, f.Cols})
	if e != nil {
		return e
	}
	// Charge persisted encrypted bytes, including JSON/base64/GCM overhead and
	// resize events. Quota refusal precedes every upload or database mutation.
	cost := len(chunk)
	if size+cost > sessionLimit {
		return deny("recording_quota_reached")
	}
	var total int
	e = tx.QueryRow(ctx, `SELECT COALESCE(sum(payload_bytes),0) FROM server_access_recordings WHERE org_id=$1 AND status<>'expired'`, org).Scan(&total)
	if e != nil {
		return e
	}
	if total+cost > orgLimit {
		return deny("recording_quota_reached")
	}
	store, e := s.loadRecordingStorage(ctx, org, storageSealed)
	if e != nil {
		return e
	}
	if store != nil {
		if e = store.Put(ctx, org, id, seq, chunk); e != nil {
			return deny("recording_storage_unavailable")
		}
		// External ciphertext is durable before the transactional metadata index and
		// before terminal output forwarding. The manifest retains its destination.
		chunk = []byte{}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO server_access_recording_chunks(org_id,session_id,seq,ciphertext) VALUES($1,$2,$3,$4)`, org, id, seq, chunk); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE server_access_recordings SET next_seq=next_seq+1,payload_bytes=payload_bytes+$3 WHERE org_id=$1 AND session_id=$2`, org, id, cost)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Service) recordingCurrentAudience(ctx context.Context, org uuid.UUID, p *authctx.Principal) (bool, error) {
	if p == nil || p.SessionID == "" {
		return false, deny("human_session_required")
	}
	if e := s.available(); e != nil {
		return false, e
	}
	// Current login/user/membership and separate replay permission are checked on
	// every read. Replay does not require a new content grant for historical data.
	parent, _, e := s.parents.GetNoTouch(ctx, p.SessionID)
	if e != nil || parent.UserID != p.UserID {
		return false, deny("parent_session_expired")
	}
	q := sqlc.New(s.pool)
	u, e := q.GetUserByID(ctx, p.UserID)
	if e != nil || u.Status != "active" || !u.EmailVerifiedAt.Valid || u.MustChangePassword || parent.AppAuthEpoch <= 0 || u.AppAuthEpoch != parent.AppAuthEpoch {
		return false, deny("replay_authority_changed")
	}
	hash := sha256.Sum256([]byte(p.SessionID))
	revoked, e := q.IsAppParentLogoutRevoked(ctx, hash[:])
	if e != nil || revoked {
		return false, deny("parent_logout")
	}
	m, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: org, UserID: p.UserID})
	if e != nil || m.AccessRevokedAt.Valid || !rbac.CanAny(m.Roles, rbac.PermServerAccessReplay) {
		return false, deny("recording_permission_denied")
	}
	return rbac.CanAny(m.Roles, rbac.PermServerAccessSessionManage), nil
}
func (s *Service) recordingAudience(ctx context.Context, org, id uuid.UUID, p *authctx.Principal) (record, error) {
	canManage, e := s.recordingCurrentAudience(ctx, org, p)
	if e != nil {
		return record{}, e
	}
	r, e := s.load(ctx, org, id)
	if e != nil {
		return record{}, e
	}
	if r.View.UserId != p.UserID && !canManage {
		return record{}, deny("recording_permission_denied")
	}
	return r, nil
}

func (s *Service) Recording(ctx context.Context, org, id uuid.UUID, p *authctx.Principal, metadataOnly bool) (api.ServerAccessRecording, error) {
	out := api.ServerAccessRecording{SessionId: id, Status: "disabled", Events: []api.ServerAccessRecordingEvent{}}
	if e := s.available(); e != nil {
		return out, e
	}
	r, e := s.recordingAudience(ctx, org, id, p)
	if e != nil {
		return out, e
	}
	if !r.View.RecordingEnabled || r.View.Kind != "terminal" {
		return out, nil
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var sealed, storageSealed, archiveStorage, expectedArchiveDigest []byte
	var archiveStatus, archiveError string
	var count int
	var persistedIncomplete bool
	e = tx.QueryRow(ctx, `SELECT status,key_sealed,next_seq,expires_at,storage_sealed,archive_storage_sealed,archive_status,archive_error,archive_retry_after,archive_digest,archive_incomplete FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&out.Status, &sealed, &count, &out.ExpiresAt, &storageSealed, &archiveStorage, &archiveStatus, &archiveError, &out.ArchiveRetryAt, &expectedArchiveDigest, &persistedIncomplete)
	if e != nil {
		return out, e
	}
	archivedSource := out.Status == "archived"
	if archivedSource && persistedIncomplete {
		out.Status = "incomplete"
	}
	out.ArchiveStatus = &archiveStatus
	if archiveError != "" {
		out.ArchiveError = &archiveError
	}
	if time.Now().After(out.ExpiresAt) && archiveStatus == "none" {
		out.Status = "expired"
	}
	if metadataOnly {
		if e = s.audit(ctx, tx, org, p.UserID, "recording_access_checked", id, map[string]any{"status": out.Status}); e != nil {
			return out, e
		}
		return out, tx.Commit(ctx)
	}
	if out.Status == "expired" || out.Status == "failed" {
		if e = s.audit(ctx, tx, org, p.UserID, "recording_read", id, map[string]any{"owner_user_id": r.View.UserId, "status": out.Status, "events": 0}); e != nil {
			return out, e
		}
		return out, tx.Commit(ctx)
	}
	if count < 0 || count > recordingEventLimit {
		return out, deny("recording_integrity_failed")
	}
	key, e := s.recordingKey(org, id, sealed)
	if e != nil {
		return out, e
	}
	defer clear(key)
	if archivedSource {
		storageSealed = archiveStorage
	}
	store, e := s.loadRecordingStorage(ctx, org, storageSealed)
	if e != nil {
		return out, e
	}
	var archivedIncomplete bool
	if archivedSource {
		if archivedIncomplete, e = s.verifyArchiveManifest(ctx, org, id, count, sealed, expectedArchiveDigest, store); e != nil {
			return out, e
		}
	}

	rows, e := tx.Query(ctx, `SELECT seq,ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 ORDER BY seq LIMIT 4097`, org, id)
	if e != nil {
		return out, e
	}
	seq := 0
	var elapsed int64
	replayDigest := make([]byte, 32)
	for rows.Next() {
		var n int
		var raw []byte
		if e = rows.Scan(&n, &raw); e != nil {
			rows.Close()
			return out, e
		}
		if n != seq {
			rows.Close()
			return out, deny("recording_integrity_failed")
		}
		if store != nil {
			if len(raw) != 0 {
				rows.Close()
				return out, deny("recording_integrity_failed")
			}
			raw, e = store.Get(ctx, org, id, n)
			if e != nil {
				rows.Close()
				return out, deny("recording_storage_unavailable")
			}
		}
		if archivedSource {
			replayDigest = archiveDigest(replayDigest, n, raw)
		}
		event, err := openEvent(key, org, id, n, raw)
		if err != nil || event.Millis < elapsed {
			rows.Close()
			return out, deny("recording_integrity_failed")
		}
		elapsed = event.Millis
		data := event.Data
		if data == nil {
			data = []byte{}
		}
		out.Events = append(out.Events, api.ServerAccessRecordingEvent{Seq: event.Seq, Millis: event.Millis, Type: api.ServerAccessRecordingEventType(event.Type), Data: data, Rows: event.Rows, Cols: event.Cols})
		seq++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if archivedSource && !bytes.Equal(replayDigest, expectedArchiveDigest) {
		return out, deny("recording_archive_integrity_failed")
	}
	if seq != count {
		return out, deny("recording_integrity_failed")
	}
	if archivedIncomplete {
		out.Status = "incomplete"
	}
	if e = s.audit(ctx, tx, org, p.UserID, "recording_read", id, map[string]any{"owner_user_id": r.View.UserId, "events": seq}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

type recordingExpiryTarget struct{ org, id uuid.UUID }

func (s *Service) expireRecordings(ctx context.Context) error {
	rows, e := s.pool.Query(ctx, `SELECT org_id,session_id FROM server_access_recordings WHERE expires_at<=now() AND status NOT IN ('expired','archived') AND archive_status IN ('none','available') AND (storage_retry_after IS NULL OR storage_retry_after<=now()) ORDER BY expires_at LIMIT 128`)
	if e != nil {
		return e
	}
	var targets []recordingExpiryTarget
	for rows.Next() {
		var r recordingExpiryTarget
		if e = rows.Scan(&r.org, &r.id); e != nil {
			rows.Close()
			return e
		}
		targets = append(targets, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	return s.expireRecordingTargets(ctx, targets)
}
func (s *Service) recordingCleanupRetry(org, id uuid.UUID, delay time.Duration) error {
	// A timeout must not strand the same oldest destination at the front forever.
	// Only cleanup metadata is updated; key/config remain intact for retry.
	retry, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e := s.pool.Exec(retry, `UPDATE server_access_recordings SET storage_retry_after=now()+make_interval(secs=>$3) WHERE org_id=$1 AND session_id=$2 AND status<>'expired'`, org, id, delay.Seconds())
	return e
}
func (s *Service) expireRecordingTargets(ctx context.Context, targets []recordingExpiryTarget) error {
	var failures []error
	for _, r := range targets {
		done, failed := false, false
		for step := 0; step < 16; step++ {
			var e error
			done, e = s.expireRecordingStep(ctx, r.org, r.id)
			if e != nil {
				failures = append(failures, e)
				if retryErr := s.recordingCleanupRetry(r.org, r.id, 30*time.Second); retryErr != nil {
					failures = append(failures, retryErr)
				}
				failed = true
				break
			}
			if done {
				break
			}
		}
		if !done && !failed {
			if e := s.recordingCleanupRetry(r.org, r.id, 2*time.Second); e != nil {
				failures = append(failures, e)
			}
		}
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
	}
	return errors.Join(failures...)
}
func (s *Service) expireRecordingStep(ctx context.Context, org, id uuid.UUID) (bool, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var count, cursor int
	var storage []byte
	var currentArchive string
	var verified bool
	e = tx.QueryRow(ctx, `SELECT next_seq,storage_cleanup_seq,storage_sealed,archive_status,archive_manifest_verified FROM server_access_recordings WHERE org_id=$1 AND session_id=$2 AND expires_at<=now() AND status NOT IN ('expired','archived') AND archive_status IN ('none','available') FOR UPDATE SKIP LOCKED`, org, id).Scan(&count, &cursor, &storage, &currentArchive, &verified)
	if e == pgx.ErrNoRows {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if count < 0 || count > recordingEventLimit || cursor < 0 || cursor > recordingEventLimit+1 {
		return false, deny("recording_integrity_failed")
	}
	pgPrimary, e := s.postgresRecordingDestination(org, storage)
	if e != nil {
		return false, e
	}
	if currentArchive == "available" && verified && pgPrimary {
		// Reverify the previously exported copy at expiry, retaining PG through
		// every bounded readback step. Existing deterministic objects are reused.
		if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET archive_status='uploading',archive_next_seq=0,archive_digest=NULL,archive_retry_after=NULL WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
			return false, e
		}
		return true, tx.Commit(ctx)
	}
	if pgPrimary {
		var archiveConfig []byte
		var automatic bool
		if e = tx.QueryRow(ctx, `SELECT archive_storage_sealed,archive_enabled FROM server_access_settings WHERE org_id=$1`, org).Scan(&archiveConfig, &automatic); e != nil {
			return false, e
		}
		if automatic && len(archiveConfig) > 0 {
			if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET archive_storage_sealed=$3,archive_status='pending',archive_requested_at=now(),archive_retry_after=NULL WHERE org_id=$1 AND session_id=$2`, org, id, archiveConfig); e != nil {
				return false, e
			}
			return true, tx.Commit(ctx)
		}
	}
	store, e := s.loadRecordingStorage(ctx, org, storage)
	if e != nil {
		return false, e
	}
	if store != nil && cursor <= count {
		// next_seq includes the possible uploaded object from a rolled-back capture.
		if e = store.Delete(ctx, org, id, cursor); e != nil {
			return false, deny("recording_storage_unavailable")
		}
		cursor++
		if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET storage_cleanup_seq=$3 WHERE org_id=$1 AND session_id=$2`, org, id, cursor); e != nil {
			return false, e
		}
		if cursor <= count {
			return false, tx.Commit(ctx)
		}
	}
	if _, e = tx.Exec(ctx, `DELETE FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		return false, e
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET status='expired',key_sealed=NULL,storage_sealed=NULL,payload_bytes=0 WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
		return false, e
	}
	return true, tx.Commit(ctx)
}
