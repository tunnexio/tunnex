package ipsec

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// RuntimeHistoryContinuation is a durable hash-chain tombstone for an exact
// prefix of already discharged duties. It confers neither adoption nor deletion
// authority. Count is never reused as a generation; Digest binds every omitted
// original identity in order. v8 readers are required when this field is present.
type RuntimeHistoryContinuation struct {
	Count  uint64
	Digest string
}

func historyCount(h *RuntimeHistoryContinuation) uint64 {
	if h == nil {
		return 0
	}
	return h.Count
}
func validHistoryContinuation(h *RuntimeHistoryContinuation) bool {
	return h == nil || h.Count > 0 && validDigest(h.Digest)
}
func hasHistoryContinuation(e RuntimeJournalEntry) bool {
	return e.BGPProcessHistory != nil || e.Restoration != nil && e.Restoration.Compacted != nil
}
func advanceHistory(h *RuntimeHistoryContinuation, domain string, item any) (*RuntimeHistoryContinuation, error) {
	if !validHistoryContinuation(h) || historyCount(h) == ^uint64(0) {
		return nil, ErrRuntimeJournal
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}
	prior := ""
	if h != nil {
		prior = h.Digest
	}
	n := historyCount(h) + 1
	return &RuntimeHistoryContinuation{Count: n, Digest: stringDigest([]byte(fmt.Sprintf("%s\n%d\n%s\n%s", domain, n, prior, raw)))}, nil
}

// Only previously committed cleaned entries may be compacted. A newly appended
// duty is never included in this operation, including during trusted restoration.
func compactBGPProcessHistory(e *RuntimeJournalEntry) error {
	if len(e.BGPProcessRetired) < 16 {
		return nil
	}
	if len(e.BGPProcessRetired) != 16 || e.BGPProcessRetired[0].Stage != "cleaned" {
		return ErrRuntimeJournal
	}
	h, err := advanceHistory(e.BGPProcessHistory, "bgp-cleaned-process-v1", e.BGPProcessRetired[0])
	if err != nil {
		return err
	}
	e.BGPProcessHistory = h
	e.BGPProcessRetired = append(e.BGPProcessRetired[:0:0], e.BGPProcessRetired[1:]...)
	return nil
}
func processHistorySuccessorBase(before, after RuntimeJournalEntry) (RuntimeJournalEntry, bool) {
	if reflect.DeepEqual(before.BGPProcessHistory, after.BGPProcessHistory) {
		return before, true
	}
	expected := before
	if len(before.BGPProcessRetired) != 16 || compactBGPProcessHistory(&expected) != nil || !reflect.DeepEqual(expected.BGPProcessHistory, after.BGPProcessHistory) {
		return before, false
	}
	// Compaction is inseparable from a next-generation reservation. Merely erasing
	// history, or combining unproved cleanup with compaction, is not a successor.
	if before.BGPProcess == nil || after.BGPProcess == nil || before.BGPProcess.Generation == ^uint64(0) || after.BGPProcess.Generation != before.BGPProcess.Generation+1 || after.BGPProcess.Stage != "reserved" {
		return before, false
	}
	return expected, true
}
func retiredEpochDischarged(h RuntimeRetiredEpoch) bool {
	// This epoch is already committed following trusted stop/boot-change and full
	// new-namespace absence proof. Unknown older process artifacts remain duties.
	for _, p := range h.Entry.BGPProcessRetired {
		if p.Stage != "cleaned" {
			return false
		}
	}
	return true
}
func compactRestorationHistory(v *RuntimeRestoration) error {
	if len(v.Retired) < 16 {
		return nil
	}
	if len(v.Retired) != 16 || !retiredEpochDischarged(v.Retired[0]) {
		return ErrRuntimeJournal
	}
	h, err := advanceHistory(v.Compacted, "trusted-retired-epoch-v1", v.Retired[0])
	if err != nil {
		return err
	}
	v.Compacted = h
	v.Retired = append(v.Retired[:0:0], v.Retired[1:]...)
	return nil
}
