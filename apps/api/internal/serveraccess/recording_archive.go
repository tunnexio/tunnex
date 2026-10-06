package serveraccess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// Archive configuration reuses the storage adapter, sealer and secret-merge
// rules. It never changes a legacy recording's snapshotted primary destination.
func (s *Service) savedArchive(ctx context.Context, org uuid.UUID) ([]byte, recordingStorageConfig, error) {
	var sealed []byte
	e := s.pool.QueryRow(ctx, `SELECT archive_storage_sealed FROM server_access_settings WHERE org_id=$1`, org).Scan(&sealed)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, recordingStorageConfig{Org: org, Kind: "s3"}, nil
	}
	if e != nil {
		return nil, recordingStorageConfig{}, e
	}
	if len(sealed) == 0 {
		return nil, recordingStorageConfig{Org: org, Kind: "s3"}, nil
	}
	c, e := s.openRecordingStorage(org, sealed)
	return sealed, c, e
}
func archiveView(c recordingStorageConfig, enabled bool) (api.ServerAccessRecordingArchive, error) {
	var out api.ServerAccessRecordingArchive
	if c.Endpoint == "" {
		out.Enabled = enabled
		return out, nil
	}
	v, e := storageView(c)
	if e != nil {
		return out, e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return out, e
	}
	e = json.Unmarshal(raw, &out)
	out.Enabled = enabled
	return out, e
}
func (s *Service) GetRecordingArchive(ctx context.Context, org uuid.UUID) (api.ServerAccessRecordingArchive, error) {
	if e := s.available(); e != nil {
		return api.ServerAccessRecordingArchive{}, e
	}
	sealed, c, e := s.savedArchive(ctx, org)
	if e != nil {
		return api.ServerAccessRecordingArchive{}, e
	}
	var automatic bool
	if len(sealed) > 0 {
		if e = s.pool.QueryRow(ctx, `SELECT archive_enabled FROM server_access_settings WHERE org_id=$1`, org).Scan(&automatic); e != nil {
			return api.ServerAccessRecordingArchive{}, e
		}
	}
	return archiveView(c, automatic)
}
func archiveInput(org uuid.UUID, in api.ServerAccessRecordingArchiveInput, saved recordingStorageConfig) (recordingStorageConfig, error) {
	raw, e := json.Marshal(in)
	if e != nil {
		return saved, e
	}
	var input api.ServerAccessRecordingStorageInput
	if e = json.Unmarshal(raw, &input); e != nil {
		return saved, e
	}
	input.Kind = "s3"
	return mergeStorageInput(org, input, saved)
}
func (s *Service) ConfigureRecordingArchive(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessRecordingArchiveInput) (api.ServerAccessRecordingArchive, error) {
	var out api.ServerAccessRecordingArchive
	if e := s.available(); e != nil {
		return out, e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_archive_config'),hashtext($1))`, org.String()); e != nil {
		return out, e
	}
	_, saved, e := s.savedArchive(ctx, org)
	if e != nil {
		return out, e
	}
	var sealed []byte
	c := saved
	hasFields := in.Endpoint != nil || in.Bucket != nil || in.Region != nil || in.Prefix != nil || in.AccessKeyId != nil || in.SecretAccessKey != nil
	if hasFields {
		c, e = archiveInput(org, in, saved)
		if e != nil {
			return out, e
		}
	} else if in.Enabled {
		if e = validateStorage(saved); e != nil {
			return out, e
		}
	}
	if c.Endpoint != "" {
		raw, err := json.Marshal(c)
		if err != nil {
			return out, err
		}
		wrapped, err := s.sealer.Seal(raw)
		clear(raw)
		if err != nil {
			return out, err
		}
		sealed = []byte(wrapped)
	}
	tag, e := tx.Exec(ctx, `UPDATE server_access_settings SET archive_storage_sealed=$2,archive_enabled=$3 WHERE org_id=$1`, org, sealed, in.Enabled)
	if e != nil {
		return out, e
	}
	if tag.RowsAffected() != 1 {
		return out, missing()
	}
	if e = s.audit(ctx, tx, org, actor, "recording_archive_configured", org, map[string]any{"enabled": in.Enabled}); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	return archiveView(c, in.Enabled)
}
func (s *Service) TestRecordingArchive(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessRecordingArchiveInput) error {
	if e := s.available(); e != nil {
		return e
	}

	_, saved, e := s.savedArchive(ctx, org)
	if e != nil {
		return e
	}
	c := saved
	if in.Endpoint != nil || in.Bucket != nil || in.Region != nil || in.Prefix != nil || in.AccessKeyId != nil || in.SecretAccessKey != nil {
		c, e = archiveInput(org, in, saved)
		if e != nil {
			return e
		}
	}
	store, e := newRecordingStore(c)
	if e != nil {
		return e
	}
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if e = store.Probe(bounded); e != nil {
		return storageUnavailable()
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.audit(ctx, tx, org, actor, "recording_archive_checked", org, map[string]any{"status": "passed"}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Service) archiveExport(ctx context.Context, org, id uuid.UUID) (api.ServerAccessRecordingExport, error) {
	out := api.ServerAccessRecordingExport{SessionId: id}
	var status, code string
	var snapshot []byte
	e := s.pool.QueryRow(ctx, `SELECT archive_status,archive_next_seq,next_seq,archive_error,archived_at,archive_storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&status, &out.ArchivedEvents, &out.TotalEvents, &code, &out.ArchivedAt, &snapshot)
	if e == nil && len(snapshot) > 0 {
		c, err := s.openRecordingStorage(org, snapshot)
		if err != nil {
			return out, err
		}
		key, err := recordingObjectKey(c, org, id, recordingEventLimit)
		if err != nil {
			return out, err
		}
		key = strings.TrimSuffix(key, "004096.bin") + "recording-v2.tunnex-recording"
		out.PackageKey = &key
	}
	out.Status = api.ServerAccessRecordingExportStatus(status)
	if code != "" {
		out.Error = &code
	}
	return out, e
}
func (s *Service) QueueRecordingArchive(ctx context.Context, org, id uuid.UUID, p *authctx.Principal) (api.ServerAccessRecordingExport, error) {
	r, e := s.recordingAudience(ctx, org, id, p)
	if e != nil {
		return api.ServerAccessRecordingExport{}, e
	}
	if !r.View.RecordingEnabled || r.View.Kind != "terminal" {
		return api.ServerAccessRecordingExport{}, deny("recording_disabled")
	}
	if r.View.Status == "pending" || r.View.Status == "connecting" || r.View.Status == "connected" {
		return api.ServerAccessRecordingExport{}, deny("recording_archive_session_active")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return api.ServerAccessRecordingExport{}, e
	}
	defer tx.Rollback(ctx)
	var status, archiveStatus string
	var legacy, snapshot []byte
	e = tx.QueryRow(ctx, `SELECT status,archive_status,storage_sealed,archive_storage_sealed FROM server_access_recordings WHERE org_id=$1 AND session_id=$2 FOR UPDATE`, org, id).Scan(&status, &archiveStatus, &legacy, &snapshot)
	if e != nil {
		return api.ServerAccessRecordingExport{}, e
	}
	if status == "expired" || status == "capturing" || status == "failed" || status == "disabled" {
		return api.ServerAccessRecordingExport{}, deny("recording_unavailable")
	}
	pgPrimary, e := s.postgresRecordingDestination(org, legacy)
	if e != nil {
		return api.ServerAccessRecordingExport{}, e
	}
	if !pgPrimary {
		return api.ServerAccessRecordingExport{}, deny("recording_archive_legacy_destination")
	}
	if archiveStatus != "available" {
		if len(snapshot) == 0 {
			if e = tx.QueryRow(ctx, `SELECT archive_storage_sealed FROM server_access_settings WHERE org_id=$1 FOR SHARE`, org).Scan(&snapshot); e != nil {
				return api.ServerAccessRecordingExport{}, e
			}
			if len(snapshot) == 0 {
				return api.ServerAccessRecordingExport{}, deny("recording_archive_not_configured")
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET archive_storage_sealed=$3,archive_status=CASE WHEN archive_next_seq=0 THEN 'pending' ELSE 'uploading' END,archive_requested_at=COALESCE(archive_requested_at,now()),archive_retry_after=NULL,archive_error='' WHERE org_id=$1 AND session_id=$2`, org, id, snapshot); e != nil {
			return api.ServerAccessRecordingExport{}, e
		}
		if e = s.audit(ctx, tx, org, p.UserID, "recording_archive_requested", id, map[string]any{"status": "queued"}); e != nil {
			return api.ServerAccessRecordingExport{}, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return api.ServerAccessRecordingExport{}, e
	}
	return s.archiveExport(ctx, org, id)
}
func (s *Service) DownloadRecording(ctx context.Context, org, id uuid.UUID, p *authctx.Principal) (api.ServerAccessRecording, error) {
	out, e := s.Recording(ctx, org, id, p, false)
	if e != nil {
		return out, e
	}
	if out.Status == "expired" || out.Status == "failed" || out.Status == "disabled" {
		return out, deny("recording_unavailable")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = s.audit(ctx, tx, org, p.UserID, "recording_download", id, map[string]any{"events": len(out.Events), "status": out.Status}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

type archiveManifest struct {
	Version      int `json:"version"`
	Org, Session uuid.UUID
	Count        int    `json:"count"`
	Digest       []byte `json:"digest"`
	WrappedDEK   []byte `json:"wrapped_dek"`
	Incomplete   bool   `json:"incomplete"`
}

func archiveDigest(previous []byte, seq int, ciphertext []byte) []byte {
	h := sha256.New()
	h.Write(previous)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(seq))
	h.Write(n[:])
	sum := sha256.Sum256(ciphertext)
	h.Write(sum[:])
	return h.Sum(nil)
}
func (s *Service) verifyArchiveManifest(ctx context.Context, org, id uuid.UUID, count int, key, expectedDigest []byte, store recordingStore) (bool, error) {
	if store == nil {
		return false, deny("recording_archive_integrity_failed")
	}
	encrypted, e := store.Get(ctx, org, id, recordingEventLimit)
	if e != nil {
		return false, storageUnavailable()
	}
	raw, e := s.sealer.Open(string(encrypted))
	if e != nil {
		return false, deny("recording_archive_integrity_failed")
	}
	defer clear(raw)
	var m archiveManifest
	if json.Unmarshal(raw, &m) != nil || m.Version != 1 || m.Org != org || m.Session != id || m.Count != count || len(m.Digest) != 32 || !bytes.Equal(m.WrappedDEK, key) || !bytes.Equal(m.Digest, expectedDigest) {
		return false, deny("recording_archive_integrity_failed")
	}
	return m.Incomplete, nil
}
func (s *Service) processRecordingArchives(ctx context.Context) error {
	rows, e := s.pool.Query(ctx, `SELECT r.org_id,r.session_id FROM server_access_recordings r JOIN server_access_sessions ss ON ss.org_id=r.org_id AND ss.id=r.session_id WHERE r.archive_status IN ('pending','uploading','failed') AND (r.archive_retry_after IS NULL OR r.archive_retry_after<=now()) AND ss.status NOT IN ('pending','connecting','connected') ORDER BY r.archive_requested_at LIMIT 8`)
	if e != nil {
		return e
	}
	var targets []recordingExpiryTarget
	for rows.Next() {
		var t recordingExpiryTarget
		if e = rows.Scan(&t.org, &t.id); e != nil {
			rows.Close()
			return e
		}
		targets = append(targets, t)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var failures []error
	for _, t := range targets {
		// At most two encrypted chunks per target/tick; durable cursor survives restart.
		for step := 0; step < 2; step++ {
			done, err := s.archiveRecordingStep(ctx, t.org, t.id)
			if err != nil {
				retry, stop := context.WithTimeout(context.Background(), time.Second)
				_, markErr := s.pool.Exec(retry, `UPDATE server_access_recordings SET archive_status='failed',archive_error='archive_storage_unavailable',archive_retry_after=now()+interval '30 seconds' WHERE org_id=$1 AND session_id=$2 AND archive_status<>'available'`, t.org, t.id)
				stop()
				failures = append(failures, err)
				if markErr != nil {
					failures = append(failures, markErr)
				}
				break
			}
			if done {
				break
			}
		}
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
	}
	return errors.Join(failures...)
}
func (s *Service) archiveRecordingStep(ctx context.Context, org, id uuid.UUID) (bool, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var snapshot, keySealed, digest []byte
	var next, count int
	var status string
	var previouslyVerified bool
	var expires time.Time
	var actor uuid.UUID
	e = tx.QueryRow(ctx, `SELECT r.archive_storage_sealed,r.key_sealed,r.archive_digest,r.archive_next_seq,r.next_seq,r.status,ss.user_id,r.archive_manifest_verified,r.expires_at FROM server_access_recordings r JOIN server_access_sessions ss ON ss.org_id=r.org_id AND ss.id=r.session_id WHERE r.org_id=$1 AND r.session_id=$2 AND r.archive_status IN ('pending','uploading','failed') AND ss.status NOT IN ('pending','connecting','connected') FOR UPDATE OF r SKIP LOCKED`, org, id).Scan(&snapshot, &keySealed, &digest, &next, &count, &status, &actor, &previouslyVerified, &expires)
	if errors.Is(e, pgx.ErrNoRows) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if len(snapshot) == 0 || next < 0 || next > count || count > recordingEventLimit {
		return false, deny("recording_archive_integrity_failed")
	}
	if len(digest) == 0 {
		digest = make([]byte, 32)
	}
	if len(digest) != 32 {
		return false, deny("recording_archive_integrity_failed")
	}
	store, e := s.loadRecordingStorage(ctx, org, snapshot)
	if e != nil || store == nil {
		return false, storageUnavailable()
	}
	key, e := s.recordingKey(org, id, keySealed)
	if e != nil {
		return false, e
	}
	defer clear(key)
	if next < count {
		var chunk []byte
		if e = tx.QueryRow(ctx, `SELECT ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 AND seq=$3`, org, id, next).Scan(&chunk); e != nil {
			return false, e
		}
		if _, e = openEvent(key, org, id, next, chunk); e != nil {
			return false, e
		}
		var actual []byte
		if previouslyVerified {
			actual, e = store.Get(ctx, org, id, next)
		}
		if !previouslyVerified || e != nil || !bytes.Equal(actual, chunk) {
			if e = store.Put(ctx, org, id, next, chunk); e != nil {
				return false, e
			}
			actual, e = store.Get(ctx, org, id, next)
		}
		if e != nil || !bytes.Equal(actual, chunk) {
			return false, storageUnavailable()
		}
		if _, e = openEvent(key, org, id, next, actual); e != nil {
			return false, e
		}
		digest = archiveDigest(digest, next, chunk)
		if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET archive_status='uploading',archive_next_seq=$3,archive_digest=$4,archive_error='',archive_retry_after=NULL WHERE org_id=$1 AND session_id=$2`, org, id, next+1, digest); e != nil {
			return false, e
		}
		return false, tx.Commit(ctx)
	}
	m := archiveManifest{Version: 1, Org: org, Session: id, Count: count, Digest: digest, WrappedDEK: keySealed, Incomplete: status == "incomplete" || status == "failed"}
	raw, e := json.Marshal(m)
	if e != nil {
		return false, e
	}
	encrypted, e := s.sealer.Seal(raw)
	clear(raw)
	if e != nil {
		return false, e
	}
	if e = store.Put(ctx, org, id, recordingEventLimit, []byte(encrypted)); e != nil {
		return false, e
	}
	if _, e = s.verifyArchiveManifest(ctx, org, id, count, keySealed, digest, store); e != nil {
		return false, e
	}
	// The complete encrypted package is verified while the source still exists.
	objects, ok := store.(recordingPackageStore)
	if !ok {
		return false, deny("recording_package_unavailable")
	}
	chunks, e := tx.Query(ctx, `SELECT seq,ciphertext FROM server_access_recording_chunks WHERE org_id=$1 AND session_id=$2 ORDER BY seq LIMIT 4097`, org, id)
	if e != nil {
		return false, e
	}
	pkg := recordingPackage{Version: 2, Org: org, Session: id, Owner: actor, Count: count, Digest: digest, WrappedDEK: keySealed, Incomplete: m.Incomplete, ExpiresAt: expires, Chunks: [][]byte{}}
	packageCipherBytes := 0
	for chunks.Next() {
		var seq int
		var ciphertext []byte
		if e = chunks.Scan(&seq, &ciphertext); e != nil {
			chunks.Close()
			return false, e
		}
		if seq != len(pkg.Chunks) {
			chunks.Close()
			return false, deny("recording_integrity_failed")
		}
		packageCipherBytes += len(ciphertext)
		if len(ciphertext) == 0 || len(ciphertext) > recordingObjectLimit || packageCipherBytes > 16<<20 {
			chunks.Close()
			return false, deny("recording_integrity_failed")
		}
		pkg.Chunks = append(pkg.Chunks, ciphertext)
	}
	e = chunks.Err()
	chunks.Close()
	if e != nil {
		return false, e
	}
	packageBytes, e := s.sealRecordingPackage(pkg)
	if e != nil {
		return false, e
	}
	defer clear(packageBytes)
	if _, _, e = s.openRecordingPackage(org, packageBytes); e != nil {
		return false, e
	}
	if e = objects.PutPackage(ctx, org, id, packageBytes); e != nil {
		return false, e
	}
	readback, e := objects.GetPackage(ctx, org, id)
	if e != nil {
		return false, e
	}
	defer clear(readback)
	if !bytes.Equal(readback, packageBytes) {
		return false, deny("recording_archive_integrity_failed")
	}
	if _, _, e = s.openRecordingPackage(org, readback); e != nil {
		return false, e
	}
	// Manual exports retain PG for its entire snapshotted retention. Expired
	// jobs release PG only after every object and encrypted manifest verifies.
	releasePG := !expires.After(time.Now())
	if releasePG {
		if _, e = tx.Exec(ctx, `UPDATE server_access_recording_chunks SET ciphertext=''::bytea WHERE org_id=$1 AND session_id=$2`, org, id); e != nil {
			return false, e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET status=CASE WHEN $3 THEN 'archived' ELSE status END,archive_status='available',archive_manifest_verified=true,archive_incomplete=$4,archived_at=now(),archive_error='',archive_retry_after=NULL,payload_bytes=CASE WHEN $3 THEN 0 ELSE payload_bytes END WHERE org_id=$1 AND session_id=$2`, org, id, releasePG, m.Incomplete); e != nil {
		return false, e
	}
	if e = s.audit(ctx, tx, org, actor, "recording_archived", id, map[string]any{"events": count, "incomplete": m.Incomplete, "postgres_payload_released": releasePG}); e != nil {
		return false, e
	}
	return true, tx.Commit(ctx)
}
