package ipsec

import "reflect"

// Classification runs only after the existing continuity predicate refused.
// It exposes one closed category, never field values or new authority.
func runtimeJournalContinuityRefusalStage(old, candidate RuntimeJournalEntry) string {
	if old.Phase == RuntimeCleanupPending {
		return "journal_cleanup_phase_refused"
	}
	if old.Phase == RuntimeRetainedRefusal {
		return "journal_retained_phase_refused"
	}
	if old.DeliveryID != candidate.DeliveryID || old.SiteID != candidate.SiteID || old.OwnershipDigest != candidate.OwnershipDigest || !reflect.DeepEqual(old.RetainedGuardPredecessors, candidate.RetainedGuardPredecessors) {
		return "journal_mismatch_lineage"
	}
	if old.ContractVersion != candidate.ContractVersion || !reflect.DeepEqual(old.BGP, candidate.BGP) || !reflect.DeepEqual(old.Recovery, candidate.Recovery) {
		return "journal_mismatch_contract"
	}
	if old.AbsenceOnly != candidate.AbsenceOnly || old.CleanupID != candidate.CleanupID || old.CleanupDesiredRevision != candidate.CleanupDesiredRevision || old.CoveredDeliveryRevision != candidate.CoveredDeliveryRevision || !reflect.DeepEqual(old.ResetCleanup, candidate.ResetCleanup) {
		return "journal_mismatch_cleanup"
	}
	if !reflect.DeepEqual(old.Allocation, candidate.Allocation) {
		return "journal_mismatch_allocation"
	}
	if !reflect.DeepEqual(old.Engines, candidate.Engines) {
		return "journal_mismatch_engines"
	}
	if !reflect.DeepEqual(old.Restoration, candidate.Restoration) || !reflect.DeepEqual(old.BGPRoutes, candidate.BGPRoutes) || !reflect.DeepEqual(old.BGPProcess, candidate.BGPProcess) || !reflect.DeepEqual(old.BGPProcessRetired, candidate.BGPProcessRetired) || !reflect.DeepEqual(old.BGPProcessHistory, candidate.BGPProcessHistory) {
		return "journal_mismatch_history"
	}
	return "journal_mismatch_other"
}
