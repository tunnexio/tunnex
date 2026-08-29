package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPoolVIPOwnershipDeliveryJSONRejectsOverflowAfterValidValue(t *testing.T) {
	var got PoolVIPOwnershipDeliveryEnvelope
	body := append([]byte(`{"version":1}`), bytes.Repeat([]byte(" "), poolVIPOwnershipDeliveryJSONLimit)...)
	if err := decodePoolVIPOwnershipDeliveryJSON(bytes.NewReader(body), &got); err == nil {
		t.Fatal("valid JSON followed by oversized trailing bytes must be refused")
	}
}

func TestPoolVIPOwnershipDeliveryJSONRejectsDuplicateKeys(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{"version":1,"version":2}`),
		[]byte(`{"version":1,"owned_routes":[{"prefix":"10.0.0.0/24","prefix":"10.0.1.0/24"}]}`),
	} {
		var got PoolVIPOwnershipDeliveryEnvelopeV2
		if err := decodePoolVIPOwnershipDeliveryJSON(bytes.NewReader(body), &got); err == nil {
			t.Fatalf("duplicate JSON key accepted: %s", body)
		}
	}
}

func FuzzPoolVIPOwnershipDeliveryJSON(f *testing.F) {
	f.Add([]byte(`{"version":2,"owned_routes":[]}`))
	f.Add([]byte(`{"version":2,"version":1}`))
	f.Add([]byte(`{"version":18446744073709551616}`))
	f.Add([]byte(`{"version":2}{"version":2}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var envelope PoolVIPOwnershipDeliveryEnvelopeV2
		_ = decodePoolVIPOwnershipDeliveryJSON(bytes.NewReader(body), &envelope)
	})
}

func TestPoolVIPOwnershipOwnedRouteDigestBoundsInputBeforeCopy(t *testing.T) {
	routes := make([]string, poolVIPOwnershipMaxOwnedRoutes+1)
	for i := range routes {
		routes[i] = "10.0.0.0/24"
	}
	if _, err := PoolVIPOwnershipOwnedRouteDigest(routes); err == nil {
		t.Fatal("over-limit route vector must be refused")
	}
	if _, err := PoolVIPOwnershipOwnedRouteDigest([]string{strings.Repeat("1", poolVIPOwnershipMaxOwnedRouteBytes+1)}); err == nil {
		t.Fatal("overlong route must be refused")
	}
}

type fakeOwnershipApplyReadback struct {
	applyErr error
	readErr  error
	readback PoolVIPOwnershipAppliedReadback
	applies  int
	reads    int
}

type blockingOwnershipApplyReadback struct {
	readback PoolVIPOwnershipAppliedReadback
	entered  chan struct{}
	release  chan struct{}
	mu       sync.Mutex
	applies  int
}

func (f *blockingOwnershipApplyReadback) ApplyPoolVIPOwnershipV2(context.Context, PoolVIPOwnershipDeliveryEnvelopeV2) error {
	f.mu.Lock()
	f.applies++
	f.mu.Unlock()
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.release
	return nil
}
func (f *blockingOwnershipApplyReadback) ReadPoolVIPOwnershipV2(context.Context, PoolVIPOwnershipDeliveryEnvelopeV2) (PoolVIPOwnershipAppliedReadback, error) {
	return f.readback, nil
}
func (f *blockingOwnershipApplyReadback) applyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies
}

func (f *fakeOwnershipApplyReadback) ApplyPoolVIPOwnershipV2(context.Context, PoolVIPOwnershipDeliveryEnvelopeV2) error {
	f.applies++
	return f.applyErr
}
func (f *fakeOwnershipApplyReadback) ReadPoolVIPOwnershipV2(context.Context, PoolVIPOwnershipDeliveryEnvelopeV2) (PoolVIPOwnershipAppliedReadback, error) {
	f.reads++
	return f.readback, f.readErr
}

type memoryOwnershipState struct {
	mu     sync.Mutex
	state  PoolVIPOwnershipAppliedState
	found  bool
	stores int
}

func (m *memoryOwnershipState) TransitionPoolVIPOwnershipAppliedState(_ context.Context, _ string, fn func(PoolVIPOwnershipAppliedState, bool) (PoolVIPOwnershipAppliedState, bool, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, commit, err := fn(m.state, m.found)
	if err != nil || !commit {
		return err
	}
	m.state, m.found, m.stores = next, true, m.stores+1
	return nil
}

func ownershipDeliveryV2(t *testing.T, role string) PoolVIPOwnershipDeliveryEnvelopeV2 {
	t.Helper()
	base := ownershipDeliveryClientEnvelope()
	base.Version = PoolVIPOwnershipDeliveryAttestationVersion
	v := PoolVIPOwnershipDeliveryEnvelopeV2{PoolVIPOwnershipDeliveryEnvelope: base}
	switch role {
	case "prepared":
		v.Role, v.DeliveryPhase = "prepared_non_serving", "prepare"
	case "withdrawal":
		v.Role, v.DeliveryPhase, v.PriorLeaseEpoch = "withdrawal", "withdraw", base.LeaseEpoch-1
	default:
		v.OwnedRoutes = []string{"10.44.0.0/16"}
		v.ExpectedVIPMapDigest = strings.Repeat("c", 64)
	}
	digest, err := PoolVIPOwnershipOwnedRouteDigest(v.OwnedRoutes)
	if err != nil {
		t.Fatal(err)
	}
	v.ExpectedRouteDigest = digest
	return v
}

func matchingReadback(t *testing.T, e PoolVIPOwnershipDeliveryEnvelopeV2) PoolVIPOwnershipAppliedReadback {
	t.Helper()
	lease := e.LeaseEpoch
	if e.Role == "withdrawal" {
		lease = e.PriorLeaseEpoch
	}
	return PoolVIPOwnershipAppliedReadback{Role: e.Role, ManifestIdentity: e.ManifestIdentity, PromotionGeneration: e.PromotionGeneration, ManifestRevision: e.ManifestRevision, LeaseEpoch: lease, OwnedRoutes: append([]string(nil), e.OwnedRoutes...), VIPMapDigest: e.ExpectedVIPMapDigest}
}

func TestPoolVIPOwnershipAttestorV2RoleEvidence(t *testing.T) {
	for _, role := range []string{"prepared", "serving", "withdrawal"} {
		t.Run(role, func(t *testing.T) {
			e := ownershipDeliveryV2(t, role)
			adapter := &fakeOwnershipApplyReadback{readback: matchingReadback(t, e)}
			state := &memoryOwnershipState{}
			attestor := NewPoolVIPOwnershipAttestor(adapter, state)
			attestor.now = func() time.Time { return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC) }
			ack, err := attestor.PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e)
			if err != nil || adapter.applies != 1 || adapter.reads != 1 || state.stores != 1 || ack.AgentObservedAt.IsZero() {
				t.Fatalf("v2 apply/attest=%+v err=%v apply=%d read=%d store=%d", ack, err, adapter.applies, adapter.reads, state.stores)
			}
			if err := ValidatePoolVIPOwnershipDeliveryAckV2(e, ack); err != nil {
				t.Fatalf("validate v2 ack: %v", err)
			}
		})
	}
}

func TestPoolVIPOwnershipAttestorFailsClosedBeforeACK(t *testing.T) {
	e := ownershipDeliveryV2(t, "serving")
	cases := []struct {
		name     string
		applyErr error
		mutate   func(*PoolVIPOwnershipAppliedReadback)
	}{
		{"partial apply", errors.New("partial route apply"), nil},
		{"wrong role", nil, func(v *PoolVIPOwnershipAppliedReadback) { v.Role = "prepared_non_serving" }},
		{"wrong VIP digest", nil, func(v *PoolVIPOwnershipAppliedReadback) { v.VIPMapDigest = strings.Repeat("d", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readback := matchingReadback(t, e)
			if tc.mutate != nil {
				tc.mutate(&readback)
			}
			adapter := &fakeOwnershipApplyReadback{applyErr: tc.applyErr, readback: readback}
			state := &memoryOwnershipState{}
			if _, err := NewPoolVIPOwnershipAttestor(adapter, state).PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e); err == nil || state.stores != 0 {
				t.Fatalf("failed/partial apply must persist no ACK proof: err=%v stores=%d", err, state.stores)
			}
		})
	}
}

func TestPoolVIPOwnershipAttestorReplayCrashRestartAndStaleFence(t *testing.T) {
	e := ownershipDeliveryV2(t, "serving")
	path := t.TempDir() + "/attestation.json"
	store := NewFilePoolVIPOwnershipAppliedStateStore(path)
	adapter := &fakeOwnershipApplyReadback{readback: matchingReadback(t, e)}
	if _, err := NewPoolVIPOwnershipAttestor(adapter, store).PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if adapter.applies != 1 {
		t.Fatalf("apply count=%d", adapter.applies)
	}
	// Simulate a crash after durable proof but before HTTP ACK: a fresh machine
	// re-reads exact local state and read-back, without repeating the apply.
	restarted := NewPoolVIPOwnershipAttestor(adapter, NewFilePoolVIPOwnershipAppliedStateStore(path))
	if _, err := restarted.PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e); err != nil || adapter.applies != 1 || adapter.reads != 2 {
		t.Fatalf("restart retry must read back without reapply: err=%v applies=%d reads=%d", err, adapter.applies, adapter.reads)
	}
	mismatch := e
	mismatch.ExpectedVIPMapDigest = strings.Repeat("d", 64)
	if _, err := restarted.PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), mismatch); err == nil {
		t.Fatal("same delivery ID with changed evidence must fail")
	}
	stale := e
	stale.DeliveryID = "00000000-0000-4000-8000-000000000009"
	stale.PromotionGeneration--
	if _, err := restarted.PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), stale); err == nil {
		t.Fatal("stale generation must fail")
	}
	stale = e
	stale.DeliveryID = "00000000-0000-4000-8000-000000000009"
	stale.LeaseEpoch--
	if _, err := restarted.PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), stale); err == nil {
		t.Fatal("stale lease must fail")
	}
}

func TestPoolVIPOwnershipAttestorSerializesTwoStoreInstancesPerPath(t *testing.T) {
	first := ownershipDeliveryV2(t, "serving")
	competing := first
	competing.DeliveryID = "00000000-0000-4000-8000-000000000009"
	competing.DeliveryNonce = strings.Repeat("d", 64)
	path := t.TempDir() + "/attestation.json"
	adapter := &blockingOwnershipApplyReadback{readback: matchingReadback(t, first), entered: make(chan struct{}, 1), release: make(chan struct{})}
	firstResult := make(chan error, 1)
	go func() {
		_, err := NewPoolVIPOwnershipAttestor(adapter, NewFilePoolVIPOwnershipAppliedStateStore(path)).PreparePoolVIPOwnershipDeliveryAckV2(context.Background(), first)
		firstResult <- err
	}()
	<-adapter.entered
	secondResult := make(chan error, 1)
	go func() {
		_, err := NewPoolVIPOwnershipAttestor(adapter, NewFilePoolVIPOwnershipAppliedStateStore(path)).PreparePoolVIPOwnershipDeliveryAckV2(context.Background(), competing)
		secondResult <- err
	}()
	select {
	case err := <-secondResult:
		t.Fatalf("competing successor entered transition before predecessor committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(adapter.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first transition: %v", err)
	}
	if err := <-secondResult; err == nil {
		t.Fatal("same-revision competing successor must be rejected after re-read")
	}
	if got := adapter.applyCount(); got != 1 {
		t.Fatalf("two stores on one path must apply once, got %d", got)
	}
}

func TestFilePoolVIPOwnershipAppliedStateStoreWriteAndSyncFailuresFailClosed(t *testing.T) {
	e := ownershipDeliveryV2(t, "serving")
	path := t.TempDir() + "/attestation.json"
	adapter := &fakeOwnershipApplyReadback{readback: matchingReadback(t, e)}
	writeFail := NewFilePoolVIPOwnershipAppliedStateStore(path)
	writeFail.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected write failure") }
	if _, err := NewPoolVIPOwnershipAttestor(adapter, writeFail).PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e); err == nil {
		t.Fatal("write failure must prevent ACK")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed write must not publish state: %v", err)
	}

	syncFail := NewFilePoolVIPOwnershipAppliedStateStore(path)
	syncFail.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	if _, err := NewPoolVIPOwnershipAttestor(adapter, syncFail).PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e); err == nil {
		t.Fatal("directory sync failure must prevent ACK")
	}
	// Rename happened before the injected fsync failure, so a restart must see
	// the exact state rather than fabricate an empty predecessor.
	if _, err := NewPoolVIPOwnershipAttestor(adapter, NewFilePoolVIPOwnershipAppliedStateStore(path)).PreparePoolVIPOwnershipDeliveryAckV2(t.Context(), e); err != nil {
		t.Fatalf("restart must read persisted post-rename state: %v", err)
	}
}

func TestFilePoolVIPOwnershipAppliedStateStoreRejectsAmbiguousOrOversizedState(t *testing.T) {
	path := t.TempDir() + "/attestation.json"
	store := NewFilePoolVIPOwnershipAppliedStateStore(path)
	for name, body := range map[string][]byte{
		"duplicate": []byte(`{"version":1,"version":1,"states":{}}`),
		"unknown":   []byte(`{"version":1,"states":{},"future":true}`),
		"oversized": bytes.Repeat([]byte("x"), poolVIPOwnershipAppliedStateFileLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.read(); err == nil {
				t.Fatal("invalid durable state must fail closed")
			}
		})
	}
}

func TestPoolVIPOwnershipAttestationV1StaysReceiptOnly(t *testing.T) {
	v1 := ownershipDeliveryClientEnvelope()
	if err := validPoolVIPOwnershipDeliveryEnvelope(v1); err != nil {
		t.Fatalf("v1 changed: %v", err)
	}
	v2 := ownershipDeliveryV2(t, "serving")
	if err := validPoolVIPOwnershipDeliveryEnvelope(v2.PoolVIPOwnershipDeliveryEnvelope); err == nil {
		t.Fatal("v1 validator must reject v2")
	}
}

func TestClientPollPoolVIPOwnershipDeliveryV2AcknowledgesOnlyAfterAttestation(t *testing.T) {
	ca := newTestCA(t)
	e := ownershipDeliveryV2(t, "serving")
	ackCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/pool-vip-ownership-delivery", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(poolVIPOwnershipDeliveryCapabilityHeader) != "2" {
			t.Errorf("v2 capability=%q", r.Header.Get(poolVIPOwnershipDeliveryCapabilityHeader))
		}
		_ = json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("/agent/pool-vip-ownership-delivery/ack", func(w http.ResponseWriter, r *http.Request) {
		ackCalls++
		if r.Header.Get(poolVIPOwnershipDeliveryCapabilityHeader) != "2" {
			t.Errorf("v2 ack capability=%q", r.Header.Get(poolVIPOwnershipDeliveryCapabilityHeader))
		}
		var ack PoolVIPOwnershipDeliveryAckV2
		if err := json.NewDecoder(r.Body).Decode(&ack); err != nil || ValidatePoolVIPOwnershipDeliveryAckV2(e, ack) != nil {
			t.Errorf("v2 ack=%+v err=%v", ack, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	client := ownershipDeliveryTestClient(t, ca, mux)
	good := NewPoolVIPOwnershipAttestor(&fakeOwnershipApplyReadback{readback: matchingReadback(t, e)}, &memoryOwnershipState{})
	if work, err := client.PollPoolVIPOwnershipDeliveryV2(t.Context(), good); err != nil || !work || ackCalls != 1 {
		t.Fatalf("valid v2 poll work=%v err=%v ack=%d", work, err, ackCalls)
	}
	bad := NewPoolVIPOwnershipAttestor(&fakeOwnershipApplyReadback{applyErr: errors.New("partial")}, &memoryOwnershipState{})
	if work, err := client.PollPoolVIPOwnershipDeliveryV2(t.Context(), bad); err == nil || work || ackCalls != 1 {
		t.Fatalf("failed v2 apply must send no ack: work=%v err=%v ack=%d", work, err, ackCalls)
	}
}
