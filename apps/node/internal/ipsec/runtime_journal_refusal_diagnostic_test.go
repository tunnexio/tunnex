package ipsec

import (
	"github.com/google/uuid"
	"reflect"
	"testing"
)

func TestRuntimeJournalRefusalClassifierPreservesStrictFields(t *testing.T) {
	m := classicMaterialFixture()
	base, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, stage string
		change      func(*RuntimeJournalEntry)
	}{
		{"cleanup_phase", "journal_cleanup_phase_refused", func(e *RuntimeJournalEntry) { e.Phase = RuntimeCleanupPending }},
		{"retained_phase", "journal_retained_phase_refused", func(e *RuntimeJournalEntry) { e.Phase = RuntimeRetainedRefusal }},
		{"delivery", "journal_mismatch_lineage", func(e *RuntimeJournalEntry) { e.DeliveryID = uuid.New() }},
		{"empty_predecessors", "journal_mismatch_lineage", func(e *RuntimeJournalEntry) { e.RetainedGuardPredecessors = []RuntimeRetainedGuardPredecessor{} }},
		{"contract", "journal_mismatch_contract", func(e *RuntimeJournalEntry) { e.ContractVersion++ }},
		{"cleanup_id", "journal_mismatch_cleanup", func(e *RuntimeJournalEntry) { e.CleanupID = uuid.New() }},
		{"cleanup_revision", "journal_mismatch_cleanup", func(e *RuntimeJournalEntry) { e.CleanupDesiredRevision++ }},
		{"covered_revision", "journal_mismatch_cleanup", func(e *RuntimeJournalEntry) { e.CoveredDeliveryRevision++ }},
		{"absence", "journal_mismatch_cleanup", func(e *RuntimeJournalEntry) { e.AbsenceOnly = true }},
		{"allocation", "journal_mismatch_allocation", func(e *RuntimeJournalEntry) { e.Allocation.Generation = uuid.New() }},
		{"engine_revision", "journal_mismatch_engines", func(e *RuntimeJournalEntry) { e.Engines[0].Binding.DesiredRevision++ }},
		{"restoration", "journal_mismatch_history", func(e *RuntimeJournalEntry) {
			e.Restoration = &RuntimeRestoration{BootID: "9617762e-19db-4a21-bdee-909dfb31e501"}
		}},
		{"observed", "journal_mismatch_other", func(e *RuntimeJournalEntry) { e.Observed[0].InterfaceIndex = 999 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.change(&changed)
			if reflect.DeepEqual(base, changed) {
				t.Fatal("mutation must retain original strict refusal")
			}
			saved := changed
			if got := runtimeJournalContinuityRefusalStage(changed, base); got != tc.stage {
				t.Fatalf("stage=%s want%s", got, tc.stage)
			}
			if !reflect.DeepEqual(saved, changed) {
				t.Fatal("classifier mutated journal duty")
			}
		})
	}
	// A first-category label is not a claim that only one field differs.
	multiple := base
	multiple.CleanupID = uuid.New()
	multiple.DeliveryID = uuid.New()
	if runtimeJournalContinuityRefusalStage(multiple, base) != "journal_mismatch_lineage" {
		t.Fatal("fixed category order changed")
	}
	saved := base
	saved.Phase = RuntimeApplied
	saved.Restoration = &RuntimeRestoration{BootID: "9617762e-19db-4a21-bdee-909dfb31e501"}
	if !classicCommittedEntryMatches(base, saved, saved.Restoration.BootID) {
		t.Fatal("existing valid Classic committed admission changed")
	}
	foreign := saved
	foreign.CleanupID = uuid.New()
	if classicCommittedEntryMatches(base, foreign, saved.Restoration.BootID) {
		t.Fatal("existing Classic admitted foreign cleanup duty")
	}
	if runtimeJournalContinuityRefusalStage(foreign, saved) != "journal_mismatch_cleanup" {
		t.Fatal("foreign cleanup category changed")
	}
}
