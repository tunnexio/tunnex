package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"testing"
)

func staticUnobservedRecoveryFixture(t *testing.T) (runtimeJournalPayload, azureProfileProofBinding, string) {
	t.Helper()
	p, prior, b, _, k, _, _, _ := azureMaxProofFixture(t)
	m := azureMaterialFixture(AzureActiveActiveStaticProfile)
	one := 1
	m.Manifest.RecoveryVersion = &one
	m.Manifest.OrgID = prior.Engines[0].Binding.OrgID
	m.Manifest.NodeID = p.OwnerID
	m.Manifest.SiteID = prior.SiteID
	m.Manifest.LocalPrefixes = []string{"10.233.10.0/24"}
	m.Manifest.RemotePrefixes = []string{"10.231.0.0/16"}
	m.DesiredRevision = 2
	m.Manifest.DesiredRevision = 2
	m.Manifest.ConfigurationRevision = 1
	runtimeReseal(&m)
	e, _, err := runtimeBuildEntry(RuntimeMaterial{RuntimeDelivery: m.RuntimeDelivery}, m.Manifest.OrgID, m.Manifest.NodeID, k.Namespace, false)
	if err != nil {
		t.Fatal(err)
	}
	if e.ContractVersion != 2 || e.Recovery == nil || *e.Recovery != (RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}) {
		t.Fatal("actual builder canonical recovery missing")
	}
	e.AbsenceOnly = true
	e.Phase = RuntimeRetainedRefusal
	e.CleanupID = uuid.New()
	e.CleanupDesiredRevision = 3
	e.CoveredDeliveryRevision = 2
	// Exercise real serialization, not a hand-written journal-key fixture.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RuntimeJournalEntry
	if json.Unmarshal(raw, &decoded) != nil {
		t.Fatal("entry roundtrip")
	}
	p.Entries = []RuntimeJournalEntry{decoded}
	b.Mode = "absence"
	b.ConnectionID = e.Allocation.ConnectionID
	b.DesiredRevision = 3
	b.ConfigurationRevision = 1
	b.MaximumPrefixes = 0
	if !validJournalPayload(p) {
		t.Fatal("real cleanup metadata invalid")
	}
	return p, azureProfileProofBinding{azureMaxProofBinding: b, ProfileID: AzureActiveActiveStaticProfile}, k.Namespace
}
func TestAzureProfileProofUnobservedStaticCanonicalRecovery(t *testing.T) {
	p, b, ns := staticUnobservedRecoveryFixture(t)
	if _, err := azureProfileProofEntryHistory(p, b, ns, nil); err != nil {
		t.Fatal("production-required unobserved static recovery refused", err)
	}
	cases := []struct {
		name   string
		change func(*RuntimeJournalEntry)
	}{
		{"sequence", func(e *RuntimeJournalEntry) { e.Recovery.Sequence = 1 }},
		{"pending_from", func(e *RuntimeJournalEntry) { e.Recovery.PendingFrom = 1 }},
		{"pending_to", func(e *RuntimeJournalEntry) { e.Recovery.PendingTo = 2 }},
		{"slot_two", func(e *RuntimeJournalEntry) { e.Recovery.SelectedSlot = 2 }},
		{"pending_stage", func(e *RuntimeJournalEntry) { e.Recovery.Stage = "pending" }},
		{"missing_recovery", func(e *RuntimeJournalEntry) { e.Recovery = nil }},
		{"observed", func(e *RuntimeJournalEntry) { e.Observed[0].InterfaceIndex = 123 }},
		{"applied", func(e *RuntimeJournalEntry) { e.Phase = RuntimeApplied }},
		{"cleanup_pending", func(e *RuntimeJournalEntry) { e.Phase = RuntimeCleanupPending }},
		{"wrong_contract", func(e *RuntimeJournalEntry) { e.ContractVersion = 4 }},
		{"partial_coverage", func(e *RuntimeJournalEntry) { e.CoveredDeliveryRevision = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := cloneJournal(p)
			tc.change(&q.Entries[0])
			if _, err := azureProfileProofEntryHistory(q, b, ns, nil); err == nil {
				t.Fatal("invalid negative lineage accepted")
			}
		})
	}
	baseline := b
	baseline.Mode = "baseline"
	if _, err := azureProfileProofEntryHistory(p, baseline, ns, nil); err == nil {
		t.Fatal("never admitted baseline accepted")
	}
}
