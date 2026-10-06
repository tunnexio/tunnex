package serveraccess

import (
	"bytes"
	"context"
	"crypto/rand"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"testing"
	"time"
)

func TestRecordingAuthenticatedAudienceAndSequence(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	org, id := uuid.New(), uuid.New()
	event := recordingEvent{Seq: 7, Millis: 42, Type: "output", Data: []byte("héllo\x1b[31m")}
	raw, e := sealEvent(key, org, id, event)
	if e != nil {
		t.Fatal(e)
	}
	got, e := openEvent(key, org, id, 7, raw)
	if e != nil || !bytes.Equal(got.Data, event.Data) {
		t.Fatalf("roundtrip failed: %v", e)
	}
	for _, tc := range []struct {
		o, s uuid.UUID
		n    int
	}{{uuid.New(), id, 7}, {org, uuid.New(), 7}, {org, id, 6}} {
		if _, e = openEvent(key, tc.o, tc.s, tc.n, raw); e == nil {
			t.Fatal("accepted foreign audience/sequence")
		}
	}
	corrupt := bytes.Clone(raw)
	corrupt[len(corrupt)-1] ^= 1
	if _, e = openEvent(key, org, id, 7, corrupt); e == nil {
		t.Fatal("accepted modified ciphertext")
	}
	if _, e = openEvent(key, org, id, 7, raw[:len(raw)-1]); e == nil {
		t.Fatal("accepted truncation")
	}
}
func TestRecordingPreservesSplitUTF8AndRejectsInput(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	org, id := uuid.New(), uuid.New()
	value := []byte("héllo")
	var reconstructed []byte
	for i, b := range value {
		event := recordingEvent{Seq: i, Millis: int64(i), Type: "output", Data: []byte{b}}
		raw, e := sealEvent(key, org, id, event)
		if e != nil {
			t.Fatal(e)
		}
		got, e := openEvent(key, org, id, i, raw)
		if e != nil {
			t.Fatal(e)
		}
		reconstructed = append(reconstructed, got.Data...)
	}
	if !bytes.Equal(value, reconstructed) {
		t.Fatal("split UTF8 was normalized")
	}
	for _, event := range []recordingEvent{{Type: "input", Data: []byte("secret")}, {Type: "resize", Rows: 401, Cols: 80}, {Type: "output", Data: []byte("data"), Rows: 24}, {Type: "output", Data: make([]byte, 16385)}} {
		raw, e := sealEvent(key, org, id, event)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = openEvent(key, org, id, 0, raw); e == nil {
			t.Fatal("accepted invalid recording event")
		}
	}
}
func TestRecordingPolicyBoundsBeforeMutation(t *testing.T) {
	s := &Service{enabled: true}
	for _, in := range []api.ServerAccessSettingsInput{{MfaFreshnessSeconds: ptr(0)}, {MfaFreshnessSeconds: ptr(901)}, {RecordingRetentionDays: ptr(0)}, {RecordingRetentionDays: ptr(3651)}, {RecordingMaxSessionBytes: ptr(1)}, {RecordingMaxSessionBytes: ptr(16777217)}, {RecordingMaxOrgBytes: ptr(1)}, {RecordingMaxOrgBytes: ptr(1073741825)}} {
		if e := s.Configure(context.Background(), uuid.New(), uuid.New(), in); e == nil {
			t.Fatal("accepted unsafe policy")
		}
	}
}
func ptr(n int) *int { return &n }

func TestCaptureRejectsMalformedEventsBeforeStorage(t *testing.T) {
	s := &Service{}
	for _, f := range []terminalwire.Frame{{Type: "input", Data: []byte("secret")}, {Type: "output"}, {Type: "output", Data: make([]byte, 16385)}, {Type: "output", Data: []byte("x"), Rows: 1}, {Type: "resize", Rows: 0, Cols: 80}, {Type: "resize", Rows: 24, Cols: 401}, {Type: "resize", Rows: 24, Cols: 80, Data: []byte("secret")}} {
		if e := s.capture(context.Background(), uuid.New(), uuid.New(), time.Now(), f); authorityReason(e) != "invalid_recording_event" {
			t.Fatalf("invalid frame reached storage: %v", e)
		}
	}
	for _, start := range []time.Time{time.Now().Add(time.Hour), time.Now().Add(-2 * time.Hour)} {
		if e := s.capture(context.Background(), uuid.New(), uuid.New(), start, terminalwire.Frame{Type: "output", Data: []byte("x")}); authorityReason(e) != "invalid_recording_event" {
			t.Fatalf("invalid timing reached storage: %v", e)
		}
	}
}
