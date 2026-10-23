package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// A proven target withdrawal aborts the whole material page. The control caller
// must not replay stale material through ordinary Apply or acknowledge candidates.
// The error is not authority and carries no remote text or credential material.
type runtimeMaintenanceBatchAborted struct{}

func (*runtimeMaintenanceBatchAborted) Error() string                      { return ErrRuntimeController.Error() }
func (*runtimeMaintenanceBatchAborted) Unwrap() error                      { return ErrRuntimeController }
func (*runtimeMaintenanceBatchAborted) IPsecMaintenanceBatchAborted() bool { return true }

// withdrawMaintenanceConflict only removes an exact owner's existing permission.
// The caller has classified an authenticated Renew conflict and ruled out any
// pending denial or native candidate commit. Other owners keep their original
// finite authority; no candidate lease, route, template or acknowledgement escapes.
func (c *RuntimeController) withdrawMaintenanceConflict(ctx context.Context, old runtimeActive, entries []RuntimeJournalEntry, bgpCurrent func() bool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id := old.Entry.Allocation.ConnectionID
	current := func() bool {
		return ctx.Err() == nil && c.started && !c.closed && c.qualification.current() && c.config.DaemonAlive != nil && c.config.DaemonAlive() && bgpCurrent != nil && bgpCurrent()
	}
	if id == uuid.Nil || c.guard == nil || c.journal == nil || !current() || !reflect.DeepEqual(c.active[id], old) || old.Identity.DeliveryID != old.Entry.DeliveryID || old.Identity.Binding != old.Entry.Engines[0].Binding || old.Delivery.ID != old.Entry.DeliveryID {
		return ErrRuntimeController
	}
	journal, err := c.journal.Entries()
	if err != nil || !reflect.DeepEqual(journal, entries) {
		return ErrRuntimeController
	}
	templates, sequence, err := c.journal.guardTemplates()
	if err != nil || len(templates) != 1 || templates[0].Namespace != old.Entry.Allocation.Namespace {
		return ErrRuntimeController
	}
	originals := make(map[uuid.UUID]runtimeActive, len(c.active))
	deadlines := make(map[uuid.UUID]time.Duration, len(c.active))
	processes := make(map[uuid.UUID]runtimeBGPSession)
	for ownerID, a := range c.active {
		matched := 0
		for _, e := range entries {
			if e.Allocation.ConnectionID == ownerID && reflect.DeepEqual(e, a.Entry) {
				matched++
			}
		}
		if matched != 1 || a.Authority == nil || a.Entry.Allocation.Namespace != old.Entry.Allocation.Namespace {
			return ErrRuntimeController
		}
		originals[ownerID] = cloneMaintenanceActive(a)
		deadlines[ownerID] = a.Authority.deadline
		if a.Entry.ContractVersion == 3 {
			processes[ownerID] = c.bgpProcesses[a.Entry.DeliveryID]
		}
	}
	// Revoke this owner's resolver view before blocking native IO. Any failure
	// below returns to the caller's original complete fail-closed path.
	c.withdrawDNSOwnerView(id)
	if c.proveCurrent(ctx, old.Entry, old.Environment) != nil {
		return ErrRuntimeController
	}
	unchanged := func(after bool) bool {
		if !current() || len(c.active) != len(originals) {
			return false
		}
		for ownerID, a := range originals {
			if !reflect.DeepEqual(c.active[ownerID], a) || a.Authority.deadline != deadlines[ownerID] {
				return false
			}
			if ownerID == id {
				continue
			}
			if c.maintenanceCurrentWithNativeProof(ctx, a, bgpCurrent, !after) != nil {
				return false
			}
			if p, ok := processes[ownerID]; ok && (p == nil || !p.Alive() || c.bgpProcesses[a.Entry.DeliveryID] != p) {
				return false
			}
		}
		// IO for a later owner cannot let an earlier original lease cross its
		// authority floor unnoticed. This check never extends a deadline.
		for ownerID, a := range originals {
			if ownerID != id {
				if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
					return false
				}
			}
		}
		latest, err := c.journal.Entries()
		if err != nil || !reflect.DeepEqual(latest, entries) {
			return false
		}
		latestTemplates, latestSequence, err := c.journal.guardTemplates()
		return err == nil && latestSequence == sequence && reflect.DeepEqual(latestTemplates, templates) && current()
	}
	if !unchanged(false) || c.guard.withdrawConnection(ctx, old.Entry.Allocation.Namespace, id) != nil || !unchanged(true) {
		return ErrRuntimeController
	}
	delete(c.active, id)
	delete(c.recoveryHistory, id)
	delete(c.recoveryReportClocks, id)
	delete(c.fqdnNativeWindows, id)
	// Native denial precedes stopping target desktop exports; unrelated sessions
	// are deliberately outside this exact one-entry scope.
	delete(originals, id)
	if c.stopUnleasedDesktopExports([]RuntimeJournalEntry{old.Entry}, c.active) != nil || !unchanged(true) {
		return ErrRuntimeController
	}
	return nil
}
