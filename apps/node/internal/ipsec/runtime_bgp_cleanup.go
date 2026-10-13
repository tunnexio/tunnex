package ipsec

import (
	"context"
	"reflect"
)

// cleanupBGPDuties runs only after verified denial. It consumes persisted
// obligations without renewing a CP lease or creating routes/sessions.
func (c *RuntimeController) cleanupBGPDuties(ctx context.Context, e RuntimeJournalEntry) error {
	if e.ContractVersion != 3 {
		return nil
	}
	refused := false
	if e.Phase == RuntimeCleanupPending {
		for _, retired := range e.BGPProcessRetired {
			if retired.Stage == "retired-uncertain" {
				if recoverUncertainRuntimeBGPProcess(retired) != nil {
					refused = true
					continue
				}
				entries, err := c.journal.Entries()
				if err != nil {
					return err
				}
				for i := range entries {
					if entries[i].DeliveryID == e.DeliveryID {
						for k := range entries[i].BGPProcessRetired {
							if entries[i].BGPProcessRetired[k].Generation == retired.Generation {
								entries[i].BGPProcessRetired[k].Stage = "cleaned"
							}
						}
					}
				}
				if c.journal.Save(entries) != nil {
					return ErrRuntimeJournal
				}
			}
		}
	}
	ns, err := c.namespace()
	if err != nil || ns != e.Allocation.Namespace {
		return ErrRuntimeController
	}
	if process := c.bgpProcesses[e.DeliveryID]; process != nil {
		if process.Close() != nil {
			refused = true
			if stopped, ok := process.(interface{ Stopped() bool }); ok && stopped.Stopped() {
				delete(c.bgpProcesses, e.DeliveryID)
			}
		} else {
			delete(c.bgpProcesses, e.DeliveryID)
		}
	}
	if e.BGPProcess != nil {
		if recoverRuntimeBGPProcess(*e.BGPProcess) != nil {
			if e.Phase == RuntimeCleanupPending || proveUncertainRuntimeBGPProcess(*e.BGPProcess) != nil {
				refused = true
			}
			// Retain uncertainty verbatim; only a subsequent fresh lease may reserve
			// a new generation and append this exact retired duty.
			// Unknown residue remains unchanged.
		} else if e.BGPProcess.Stage != "cleaned" {
			entries, err := c.journal.Entries()
			if err != nil {
				return err
			}
			found := false
			for i := range entries {
				if entries[i].DeliveryID == e.DeliveryID {
					identity := *entries[i].BGPProcess
					identity.Stage = "cleaned"
					entries[i].BGPProcess = &identity
					found = true
				}
			}
			if !found || c.journal.Save(entries) != nil {
				return ErrRuntimeJournal
			}
		}
	}
	if err := WithdrawBGPRoutes(ctx, c.journal, c.kernel, e.DeliveryID.String()); err != nil {
		return err
	}
	if refused {
		return ErrRuntimeController
	}
	return nil
}

// finishKnownBGPSession records completion only after exact persisted process
// identity recovery proves children/artifact absence and directory durability.
// It never treats a tracked Close result alone as a durable cleanup receipt.
func (c *RuntimeController) finishKnownBGPSession(e RuntimeJournalEntry) error {
	if p := c.bgpProcesses[e.DeliveryID]; p != nil {
		if p.Close() != nil {
			if stopped, ok := p.(interface{ Stopped() bool }); ok && stopped.Stopped() {
				delete(c.bgpProcesses, e.DeliveryID)
			}
			return ErrRuntimeController
		}
	}
	if e.BGPProcess != nil {
		recover := recoverRuntimeBGPProcess
		if c.bgpRecover != nil {
			recover = c.bgpRecover
		}
		if recover(*e.BGPProcess) != nil {
			return ErrRuntimeController
		}
		entries, err := c.journal.Entries()
		if err != nil {
			return err
		}
		found := false
		for i := range entries {
			if entries[i].DeliveryID == e.DeliveryID {
				if entries[i].BGPProcess == nil || !reflect.DeepEqual(*entries[i].BGPProcess, *e.BGPProcess) {
					return ErrRuntimeController
				}
				identity := *entries[i].BGPProcess
				identity.Stage = "cleaned"
				entries[i].BGPProcess = &identity
				found = true
			}
		}
		if !found || c.journal.Save(entries) != nil {
			return ErrRuntimeJournal
		}
	}
	delete(c.bgpProcesses, e.DeliveryID)
	return nil
}
