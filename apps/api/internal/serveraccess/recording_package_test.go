package serveraccess

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func TestRecordingPackageSelfContainedIntegrity(t *testing.T) {
	org, id, owner := uuid.New(), uuid.New(), uuid.New()
	sealer, _ := secret.NewSealer(bytes.Repeat([]byte{17}, 32))
	svc := New(nil, nil, sealer, true)
	key := bytes.Repeat([]byte{29}, 32)
	raw, _ := json.Marshal(recordingKey{Org: org, Session: id, Key: key})
	wrapped, e := sealer.Seal(raw)
	if e != nil {
		t.Fatal(e)
	}
	pkg := recordingPackage{Version: 2, Org: org, Session: id, Owner: owner, Count: 3, WrappedDEK: []byte(wrapped), Digest: make([]byte, 32), Incomplete: true, ExpiresAt: time.Now()}
	for n, event := range []recordingEvent{{Seq: 0, Type: "output", Data: []byte{0xe2}, Millis: 2}, {Seq: 1, Type: "resize", Rows: 40, Cols: 120, Millis: 3}, {Seq: 2, Type: "output", Data: []byte{0x82, 0xac}, Millis: 4}} {
		cipher, e := sealEvent(key, org, id, event)
		if e != nil {
			t.Fatal(e)
		}
		pkg.Chunks = append(pkg.Chunks, cipher)
		pkg.Digest = archiveDigest(pkg.Digest, n, cipher)
	}
	data, e := svc.sealRecordingPackage(pkg)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte("wrapped_dek")) {
		t.Fatal("package exposes plaintext manifest")
	}
	got, out, e := svc.openRecordingPackage(org, data)
	if e != nil || got.Owner != owner || out.Status != "incomplete" || len(out.Events) != 3 || !bytes.Equal(out.Events[0].Data, []byte{0xe2}) || out.Events[1].Rows != 40 {
		t.Fatalf("lossless self-contained import failed: %v", e)
	}
	for _, bad := range [][]byte{data[:len(data)-1], []byte("raw chunk"), append([]byte(recordingPackageMagic), []byte("invalid")...)} {
		if _, _, e = svc.openRecordingPackage(org, bad); e == nil {
			t.Fatal("accepted corrupt/nonpackage object")
		}
	}
	if _, _, e = svc.openRecordingPackage(uuid.New(), data); e == nil {
		t.Fatal("accepted foreign tenant")
	}
	other, _ := secret.NewSealer(bytes.Repeat([]byte{21}, 32))
	if _, _, e = New(nil, nil, other, true).openRecordingPackage(org, data); e == nil {
		t.Fatal("accepted different installation master")
	}
	bad := pkg
	bad.Count = 4
	b, _ := svc.sealRecordingPackage(bad)
	if _, _, e = svc.openRecordingPackage(org, b); e == nil {
		t.Fatal("accepted missing event")
	}
	bad = pkg
	bad.Digest = bytes.Repeat([]byte{7}, 32)
	b, _ = svc.sealRecordingPackage(bad)
	if _, _, e = svc.openRecordingPackage(org, b); e == nil {
		t.Fatal("accepted wrong ciphertext digest")
	}
	bad = pkg
	bad.Chunks = append([][]byte(nil), pkg.Chunks...)
	bad.Chunks[0], bad.Chunks[2] = bad.Chunks[2], bad.Chunks[0]
	b, _ = svc.sealRecordingPackage(bad)
	if _, _, e = svc.openRecordingPackage(org, b); e == nil {
		t.Fatal("accepted reordered event audience")
	}
}

func TestRecordingPackageObjectLimitDoesNotWidenChunks(t *testing.T) {
	org, id := uuid.New(), uuid.New()
	payload := bytes.Repeat([]byte{73}, recordingObjectLimit+1)
	var saved []byte
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "recording-v2.tunnex-recording") {
			t.Error("package escaped deterministic object path")
		}
		if r.Method == http.MethodPut {
			saved, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
			return
		}
		w.Write(saved)
	}))
	defer endpoint.Close()
	u, _ := url.Parse(endpoint.URL)
	store := &objectRecordingStore{c: recordingStorageConfig{Org: org, Kind: "s3", Bucket: "synthetic", Region: "us-east-1", AccessKeyID: "fixture", SecretAccessKey: "fixture"}, endpoint: u, client: endpoint.Client()}
	if e := store.Put(context.Background(), org, id, 0, payload); e == nil {
		t.Fatal("package support widened ordinary chunk limit")
	}
	if e := store.PutPackage(context.Background(), org, id, payload); e != nil {
		t.Fatal(e)
	}
	got, e := store.GetPackage(context.Background(), org, id)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("dedicated package reader inherited chunk cap")
	}
	if _, e = store.GetPackage(context.Background(), uuid.New(), id); e == nil {
		t.Fatal("package object crossed tenant snapshot")
	}
}
