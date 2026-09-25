package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func recoveryJournalEntry(t *testing.T) RuntimeJournalEntry {
	t.Helper()
	r := journalFixture()
	raw, _ := json.Marshal(r)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	fields["ContractVersion"] = json.RawMessage(`2`)
	fields["Recovery"] = json.RawMessage(`{"SelectedSlot":1,"Sequence":0,"PendingFrom":0,"PendingTo":0,"Stage":"completed"}`)
	raw, _ = json.Marshal(fields)
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestRecoveryJournalVersionTwoReservation(t *testing.T) {
	r := recoveryJournalEntry(t)
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	if j.payload.Version != 2 {
		t.Fatal("recovery authorization did not upgrade journal")
	}
}

func TestRecoveryJournalLegacyCanonicalPreserved(t *testing.T) {
	r := journalFixture()
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	before := cloneJournal(j.payload)
	oldBytes := legacyJournalPayloadBytes(before)
	currentBytes, _ := json.Marshal(before)
	if !bytes.Equal(oldBytes, currentBytes) {
		t.Fatal("pre-recovery canonical payload changed")
	}
	digest := sha256.Sum256(oldBytes)
	if journalChecksum(before) != hex.EncodeToString(digest[:]) {
		t.Fatal("pre-recovery checksum changed")
	}
	j.Close()
	path := filepath.Join(dir, "journal.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]json.RawMessage
	_ = json.Unmarshal(raw, &env)
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(env["Payload"], &payload)
	var entries []map[string]json.RawMessage
	_ = json.Unmarshal(payload["Entries"], &entries)
	for _, entry := range entries {
		if _, ok := entry["ContractVersion"]; ok {
			t.Fatal("legacy encoding changed")
		}
		if _, ok := entry["Recovery"]; ok {
			t.Fatal("legacy encoding changed")
		}
	}
	j, err = OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if !reflect.DeepEqual(before, j.payload) {
		t.Fatal("legacy open migrated state")
	}
	after, _ := os.ReadFile(path)
	if string(raw) != string(after) {
		t.Fatal("legacy open rewrote bytes")
	}
}

func TestRecoveryJournalPendingCompletionAndCleanup(t *testing.T) {
	r := recoveryJournalEntry(t)
	dir := journalDir(t)
	owner := r.Engines[0].Binding.GatewayID
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	save := func() {
		t.Helper()
		if err := j.Save([]RuntimeJournalEntry{r}); err != nil {
			t.Fatal(err)
		}
	}
	save()
	r.Phase = RuntimeApplying
	save()
	r.Phase = RuntimeApplied
	save()
	r.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
	save()
	j.Close()
	j, err = OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { j.Close() }()
	got, err := j.Entries()
	if err != nil || !reflect.DeepEqual(got[0], r) {
		t.Fatal("pending switch lost", err)
	}
	bad := r
	bad.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 2, Stage: "completed"}
	if j.Save([]RuntimeJournalEntry{bad}) != ErrRuntimeJournal {
		t.Fatal("completion sequence jump accepted")
	}
	r.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 1, Stage: "completed"}
	save()
	j.Close()
	j, err = OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	got, err = j.Entries()
	if err != nil || !reflect.DeepEqual(got[0], r) {
		t.Fatal("completed switch lost", err)
	}
	// A second interrupted switch must remain part of cleanup duty.
	r.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 2, PendingFrom: 2, PendingTo: 1, Stage: "pending"}
	save()
	r.Phase = RuntimeCleanupPending
	r.CleanupID = r.SiteID
	r.CoveredDeliveryRevision = r.Engines[0].Binding.DesiredRevision
	r.CleanupDesiredRevision = r.CoveredDeliveryRevision + 1
	save()
	bad = r
	bad.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 2, Stage: "completed"}
	if j.Save([]RuntimeJournalEntry{bad}) != ErrRuntimeJournal {
		t.Fatal("cleanup permitted selection completion")
	}
	r.Phase = RuntimeRetainedRefusal
	save()
	if j.Save([]RuntimeJournalEntry{bad}) != ErrRuntimeJournal {
		t.Fatal("retained refusal changed")
	}
}

func TestRecoveryJournalRefusesUnauthorizedAndUnstagedTransitions(t *testing.T) {
	for _, kind := range []string{"new-selected", "new-sequence", "new-pending", "legacy-authority", "direct-complete", "sequence-jump", "unknown-stage", "missing-state", "unknown-version", "explicit-legacy-version"} {
		t.Run(kind, func(t *testing.T) {
			r := recoveryJournalEntry(t)
			j, err := OpenRuntimeJournal(journalDir(t), r.Engines[0].Binding.GatewayID)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			switch kind {
			case "new-selected":
				r.Recovery.SelectedSlot = 2
				r.Recovery.Sequence = 1
			case "new-sequence":
				r.Recovery.Sequence = 1
			case "new-pending":
				r.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 1, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
			case "missing-state":
				r.Recovery = nil
			case "unknown-version":
				r.ContractVersion = 3
			case "explicit-legacy-version":
				r.ContractVersion = 1
				r.Recovery = nil
			default:
				if kind == "legacy-authority" {
					r.ContractVersion = 0
					r.Recovery = nil
				}
				if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
					t.Fatal(err)
				}
				r.Phase = RuntimeApplying
				if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
					t.Fatal(err)
				}
				r.Phase = RuntimeApplied
				if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "legacy-authority":
					r.ContractVersion = 2
					r.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}
				case "direct-complete":
					r.Recovery = &RuntimeRecoveryState{SelectedSlot: 2, Sequence: 1, Stage: "completed"}
				case "sequence-jump":
					r.Recovery = &RuntimeRecoveryState{SelectedSlot: 1, Sequence: 2, PendingFrom: 1, PendingTo: 2, Stage: "pending"}
				case "unknown-stage":
					r.Recovery.Stage = "ready"
				}
			}
			if j.Save([]RuntimeJournalEntry{r}) != ErrRuntimeJournal {
				t.Fatal("invalid recovery accepted")
			}
		})
	}
}

func TestRecoveryJournalMigrationPreservesLineageAndRejectsDowngrade(t *testing.T) {
	legacy := journalFixture()
	dir := journalDir(t)
	owner := legacy.Engines[0].Binding.GatewayID
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save([]RuntimeJournalEntry{legacy}); err != nil {
		t.Fatal(err)
	}
	next := recoveryJournalEntry(t)
	for i := range next.Engines {
		next.Engines[i].Binding.GatewayID = owner
	}
	if err = j.Save([]RuntimeJournalEntry{legacy, next}); err != nil {
		t.Fatal(err)
	}
	if j.payload.Version != 2 || !reflect.DeepEqual(j.payload.Entries[0], legacy) {
		t.Fatal("migration changed legacy duty")
	}
	payload := cloneJournal(j.payload)
	payload.Version = 1
	if validJournalPayload(payload) {
		t.Fatal("v1 format accepted v2 recovery state")
	}
	if validJournalSuccessor(j.payload, payload) {
		t.Fatal("downgrade accepted")
	}
	j.Close()
	// Even a correct checksum cannot turn v2 entries into v1 schema.
	raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
	if err = os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenRuntimeJournal(dir, owner); err != ErrRuntimeJournal {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("downgraded journal opened")
	}
}

func TestRecoveryJournalRejectsSerializedAuthority(t *testing.T) {
	r := recoveryJournalEntry(t)
	dir := journalDir(t)
	owner := r.Engines[0].Binding.GatewayID
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	path := filepath.Join(dir, "journal.json")
	original, _ := os.ReadFile(path)
	for _, field := range []string{"Lease", "PSK", "Grants", "Ready"} {
		var env map[string]any
		_ = json.Unmarshal(original, &env)
		entry := env["Payload"].(map[string]any)["Entries"].([]any)[0].(map[string]any)
		entry["Recovery"].(map[string]any)[field] = true
		raw, _ := json.Marshal(env)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if opened, err := OpenRuntimeJournal(dir, owner); err != ErrRuntimeJournal {
			if opened != nil {
				opened.Close()
			}
			t.Fatal("serialized authority accepted", field)
		}
	}
}

// Field order and fields copied from the format-1 source before recovery. This
// intentionally does not alias RuntimeJournalEntry: changing its encoder must
// not silently change the old canonical checksum accepted on disk.
func legacyJournalPayloadBytes(p runtimeJournalPayload) []byte {
	type oldEntry struct {
		AbsenceOnly                                     bool
		DeliveryID, SiteID                              uuid.UUID
		OwnershipDigest                                 string
		Allocation                                      KernelAllocation
		Engines                                         [2]EngineTunnel
		Observed                                        [2]Ownership
		Phase                                           RuntimePhase
		CleanupID                                       uuid.UUID
		CleanupDesiredRevision, CoveredDeliveryRevision int64
	}
	type oldPayload struct {
		Guards   []runtimeGuardTemplate
		Version  int
		OwnerID  uuid.UUID
		Sequence uint64
		Entries  []oldEntry
	}
	old := oldPayload{Guards: p.Guards, Version: p.Version, OwnerID: p.OwnerID, Sequence: p.Sequence}
	if p.Entries != nil {
		old.Entries = make([]oldEntry, 0, len(p.Entries))
	}
	for _, r := range p.Entries {
		old.Entries = append(old.Entries, oldEntry{r.AbsenceOnly, r.DeliveryID, r.SiteID, r.OwnershipDigest, r.Allocation, r.Engines, r.Observed, r.Phase, r.CleanupID, r.CleanupDesiredRevision, r.CoveredDeliveryRevision})
	}
	raw, _ := json.Marshal(old)
	return raw
}
