package ipsec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func resetJournalPending() RuntimeJournalEntry {
	r := journalFixture()
	r.Phase = RuntimeCleanupPending
	r.CleanupID = uuid.New()
	r.CoveredDeliveryRevision = r.Engines[0].Binding.DesiredRevision
	r.CleanupDesiredRevision = r.CoveredDeliveryRevision + 1
	return r
}
func resetJournalEvidence(r RuntimeJournalEntry) *RuntimeResetCleanup {
	ns := "net:[999999]"
	if ns == r.Allocation.Namespace {
		ns = "net:[999998]"
	}
	return &RuntimeResetCleanup{BootID: uuid.NewString(), Namespace: ns, ReceiptDigest: strings.Repeat("b", 64)}
}
func TestRuntimeResetJournalLegacyReadAndDurableAudit(t *testing.T) {
	r := journalFixture()
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ResetCleanup")) {
		t.Fatal("legacy canonical bytes changed")
	}
	var legacy runtimeJournalEnvelope
	if err = json.Unmarshal(raw, &legacy); err != nil || legacy.Payload.Version != 1 || legacy.Checksum != journalChecksum(legacy.Payload) {
		t.Fatal("legacy checksum changed", err)
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	r.Phase = RuntimeCleanupPending
	r.CleanupID = uuid.New()
	r.CoveredDeliveryRevision = r.Engines[0].Binding.DesiredRevision
	r.CleanupDesiredRevision = r.CoveredDeliveryRevision + 1
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	original := r
	r.ResetCleanup = resetJournalEvidence(r)
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	if j.payload.Version != 3 {
		t.Fatal("reset audit did not upgrade v1 directly to v3")
	}
	got, _ := j.Entries()
	if !reflect.DeepEqual(got[0].Allocation, original.Allocation) || got[0].Observed != original.Observed {
		t.Fatal("old ownership changed")
	}
	r.Phase = RuntimeRetainedRefusal
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	reopened, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entries, _ := reopened.Entries()
	if !reflect.DeepEqual(entries[0], r) {
		t.Fatal("reset audit lost on restart")
	}
}
func TestRuntimeResetJournalRefusesUnsafeMetadata(t *testing.T) {
	base := resetJournalPending()
	base.ResetCleanup = resetJournalEvidence(base)
	tests := map[string]func(*RuntimeJournalEntry){
		"nil boot": func(r *RuntimeJournalEntry) { r.ResetCleanup.BootID = uuid.Nil.String() },
		"noncanonical boot": func(r *RuntimeJournalEntry) {
			r.ResetCleanup.BootID = strings.ToUpper("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		},
		"invalid namespace": func(r *RuntimeJournalEntry) { r.ResetCleanup.Namespace = "unknown" },
		"same namespace":    func(r *RuntimeJournalEntry) { r.ResetCleanup.Namespace = r.Allocation.Namespace },
		"bad digest":        func(r *RuntimeJournalEntry) { r.ResetCleanup.ReceiptDigest = "bad" },
		"applied":           func(r *RuntimeJournalEntry) { r.Phase = RuntimeApplied },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := base
			evidence := *base.ResetCleanup
			r.ResetCleanup = &evidence
			mutate(&r)
			if validJournalResetCleanup(r) {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
	p := runtimeJournalPayload{Version: 2, OwnerID: base.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{base}}
	if validJournalPayload(p) {
		t.Fatal("v2 accepted reset metadata")
	}
	p.Version = 3
	if !validJournalPayload(p) {
		t.Fatal("valid v3 refused")
	}
}
func TestRuntimeResetJournalSuccessorBoundaries(t *testing.T) {
	base := resetJournalPending()
	payload := func(r RuntimeJournalEntry) runtimeJournalPayload {
		return runtimeJournalPayload{Version: 3, OwnerID: r.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{r}}
	}
	reset := base
	reset.ResetCleanup = resetJournalEvidence(base)
	if !validJournalSuccessor(payload(base), payload(reset)) {
		t.Fatal("pending audit addition refused")
	}
	changed := reset
	evidence := *reset.ResetCleanup
	evidence.ReceiptDigest = strings.Repeat("c", 64)
	changed.ResetCleanup = &evidence
	if validJournalSuccessor(payload(reset), payload(changed)) {
		t.Fatal("audit rewritten")
	}
	if validJournalSuccessor(payload(reset), payload(base)) {
		t.Fatal("audit removed")
	}
	applied := base
	applied.Phase = RuntimeApplied
	if validJournalSuccessor(payload(applied), payload(reset)) {
		t.Fatal("audit skipped durable cleanup pending")
	}
	retained := reset
	retained.Phase = RuntimeRetainedRefusal
	if validJournalSuccessor(payload(base), payload(retained)) {
		t.Fatal("audit added with completion")
	}
	changed = retained
	changed.CleanupDesiredRevision++
	if validJournalSuccessor(payload(retained), payload(changed)) {
		t.Fatal("retained entry mutable")
	}
	reserved := reset
	reserved.Phase = RuntimeReserved
	empty := payload(base)
	empty.Entries = nil
	if validJournalSuccessor(empty, payload(reserved)) {
		t.Fatal("new entry carried reset authority")
	}
}
