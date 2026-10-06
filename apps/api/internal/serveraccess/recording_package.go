package serveraccess

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

const RecordingPackageLimit = 32 << 20
const recordingPackageMagic = "TUNNEX-RECORDING-V2\n"

type recordingPackage struct {
	Version    int       `json:"version"`
	Org        uuid.UUID `json:"org"`
	Session    uuid.UUID `json:"session"`
	Owner      uuid.UUID `json:"owner"`
	Count      int       `json:"count"`
	Digest     []byte    `json:"digest"`
	WrappedDEK []byte    `json:"wrapped_dek"`
	Chunks     [][]byte  `json:"chunks"`
	Incomplete bool      `json:"incomplete"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type recordingPackageStore interface {
	PutPackage(context.Context, uuid.UUID, uuid.UUID, []byte) error
	GetPackage(context.Context, uuid.UUID, uuid.UUID) ([]byte, error)
}

func (o *objectRecordingStore) packageKey(org, id uuid.UUID) (string, error) {
	key, e := recordingObjectKey(o.c, org, id, recordingEventLimit)
	if e != nil {
		return "", e
	}
	return strings.TrimSuffix(key, "004096.bin") + "recording-v2.tunnex-recording", nil
}
func (o *objectRecordingStore) PutPackage(ctx context.Context, org, id uuid.UUID, data []byte) error {
	key, e := o.packageKey(org, id)
	if e != nil {
		return e
	}
	_, e = o.requestObject(ctx, http.MethodPut, key, data, RecordingPackageLimit)
	return e
}
func (o *objectRecordingStore) GetPackage(ctx context.Context, org, id uuid.UUID) ([]byte, error) {
	key, e := o.packageKey(org, id)
	if e != nil {
		return nil, e
	}
	return o.requestObject(ctx, http.MethodGet, key, nil, RecordingPackageLimit)
}
func invalidRecordingPackage() error {
	return apierr.BadRequest("recording_package_invalid", "Invalid or incompatible encrypted recording package")
}
func (s *Service) sealRecordingPackage(p recordingPackage) ([]byte, error) {
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, invalidRecordingPackage()
	}
	defer clear(raw)
	if len(raw) > 24<<20 {
		return nil, invalidRecordingPackage()
	}
	sealed, e := s.sealer.Seal(raw)
	if e != nil {
		return nil, e
	}
	out := append([]byte(recordingPackageMagic), []byte(sealed)...)
	if len(out) > RecordingPackageLimit {
		return nil, invalidRecordingPackage()
	}
	return out, nil
}
func (s *Service) openRecordingPackage(org uuid.UUID, data []byte) (recordingPackage, api.ServerAccessRecording, error) {
	var p recordingPackage
	out := api.ServerAccessRecording{Events: []api.ServerAccessRecordingEvent{}}
	if len(data) > RecordingPackageLimit || !bytes.HasPrefix(data, []byte(recordingPackageMagic)) {
		return p, out, invalidRecordingPackage()
	}
	raw, e := s.sealer.Open(string(data[len(recordingPackageMagic):]))
	if e != nil {
		return p, out, invalidRecordingPackage()
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil {
		return p, out, invalidRecordingPackage()
	}
	if p.Version != 2 || p.Org != org || org == uuid.Nil || p.Session == uuid.Nil || p.Owner == uuid.Nil || p.Count < 0 || p.Count > recordingEventLimit || len(p.Chunks) != p.Count || len(p.Digest) != 32 || p.ExpiresAt.IsZero() {
		return p, out, invalidRecordingPackage()
	}
	key, e := s.recordingKey(org, p.Session, p.WrappedDEK)
	if e != nil {
		return p, out, invalidRecordingPackage()
	}
	defer clear(key)
	digest := make([]byte, 32)
	var elapsed int64
	total := 0
	for n, ciphertext := range p.Chunks {
		total += len(ciphertext)
		if len(ciphertext) == 0 || len(ciphertext) > recordingObjectLimit || total > 16<<20 {
			return p, out, invalidRecordingPackage()
		}
		event, e := openEvent(key, org, p.Session, n, ciphertext)
		if e != nil || event.Millis < elapsed {
			return p, out, invalidRecordingPackage()
		}
		elapsed = event.Millis
		digest = archiveDigest(digest, n, ciphertext)
		data := event.Data
		if data == nil {
			data = []byte{}
		}
		out.Events = append(out.Events, api.ServerAccessRecordingEvent{Seq: n, Millis: event.Millis, Type: api.ServerAccessRecordingEventType(event.Type), Data: data, Rows: event.Rows, Cols: event.Cols})
	}
	if !bytes.Equal(digest, p.Digest) {
		return p, out, invalidRecordingPackage()
	}
	out.SessionId = p.Session
	out.ExpiresAt = p.ExpiresAt
	out.Status = "available"
	if p.Incomplete {
		out.Status = "incomplete"
	}
	return p, out, nil
}
func (s *Service) ImportRecordingPackage(ctx context.Context, org uuid.UUID, p *authctx.Principal, data []byte) (api.ServerAccessRecording, error) {
	canManage, e := s.recordingCurrentAudience(ctx, org, p)
	if e != nil {
		return api.ServerAccessRecording{}, e
	}
	pkg, out, e := s.openRecordingPackage(org, data)
	if e != nil {
		return out, e
	}
	if pkg.Owner != p.UserID && !canManage {
		return api.ServerAccessRecording{}, deny("recording_permission_denied")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = s.audit(ctx, tx, org, p.UserID, "recording_import", pkg.Session, map[string]any{"source": "encrypted_package", "events": pkg.Count, "owner_user_id": pkg.Owner, "incomplete": pkg.Incomplete}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Service) DownloadRecordingPackage(ctx context.Context, org, id uuid.UUID, p *authctx.Principal) ([]byte, error) {
	if _, e := s.recordingAudience(ctx, org, id, p); e != nil {
		return nil, e
	}
	var snapshot []byte
	var state string
	if e := s.pool.QueryRow(ctx, `SELECT archive_storage_sealed,archive_status FROM server_access_recordings WHERE org_id=$1 AND session_id=$2`, org, id).Scan(&snapshot, &state); e != nil {
		return nil, e
	}
	if state != "available" {
		return nil, deny("recording_unavailable")
	}
	store, e := s.loadRecordingStorage(ctx, org, snapshot)
	if e != nil {
		return nil, e
	}
	objects, ok := store.(recordingPackageStore)
	if !ok {
		return nil, deny("recording_package_unavailable")
	}
	data, e := objects.GetPackage(ctx, org, id)
	if e != nil {
		return nil, e
	}
	pkg, _, e := s.openRecordingPackage(org, data)
	if e != nil || pkg.Session != id {
		return nil, invalidRecordingPackage()
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if e = s.audit(ctx, tx, org, p.UserID, "recording_package_download", id, map[string]any{"events": pkg.Count}); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return data, nil
}
