package serveraccess

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func TestRecordingArchiveAuthenticatesIncompleteAndSnapshot(t *testing.T) {
	ctx := context.Background()
	org, id := uuid.New(), uuid.New()
	sealer, e := secret.NewSealer(bytes.Repeat([]byte{37}, 32))
	if e != nil {
		t.Fatal(e)
	}
	svc := New(nil, nil, sealer, true)
	store := &archiveManifestTestStore{}
	key, digest := []byte("synthetic-wrapped-dek"), bytes.Repeat([]byte{12}, 32)
	raw, _ := json.Marshal(archiveManifest{Version: 1, Org: org, Session: id, Count: 2, Digest: digest, WrappedDEK: key, Incomplete: true})
	manifest, e := sealer.Seal(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Put(ctx, org, id, recordingEventLimit, []byte(manifest)); e != nil {
		t.Fatal(e)
	}
	incomplete, e := svc.verifyArchiveManifest(ctx, org, id, 2, key, digest, store)
	if e != nil || !incomplete {
		t.Fatalf("authenticated incomplete marker lost: %v", e)
	}
	for _, check := range []struct {
		count       int
		key, digest []byte
	}{{3, key, digest}, {2, []byte("other-dek"), digest}, {2, key, bytes.Repeat([]byte{13}, 32)}} {
		if _, e = svc.verifyArchiveManifest(ctx, org, id, check.count, check.key, check.digest, store); authorityReason(e) != "recording_archive_integrity_failed" {
			t.Fatal("accepted mismatched immutable manifest")
		}
	}
	corrupt := []byte(manifest)
	corrupt[len(corrupt)-1] ^= 1
	if e = store.Put(ctx, org, id, recordingEventLimit, corrupt); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.verifyArchiveManifest(ctx, org, id, 2, key, digest, store); e == nil {
		t.Fatal("accepted tampered incomplete metadata")
	}
}

type archiveManifestTestStore struct{ data []byte }

func (m *archiveManifestTestStore) Put(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ int, b []byte) error {
	m.data = bytes.Clone(b)
	return nil
}
func (m *archiveManifestTestStore) Get(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ int) ([]byte, error) {
	return bytes.Clone(m.data), nil
}
func (m *archiveManifestTestStore) Delete(context.Context, uuid.UUID, uuid.UUID, int) error {
	return nil
}
func (m *archiveManifestTestStore) Probe(context.Context) error { return nil }
