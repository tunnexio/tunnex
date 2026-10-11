package ipsec

import (
	"context"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"path/filepath"
	"reflect"
)

func (c *RuntimeController) proveAzureBGPDutiesAbsent(ctx context.Context, e RuntimeJournalEntry) error {
	if e.Phase != RuntimeRetainedRefusal || !validBGPProcess(e) || !validBGPRoutes(e) || !validRestoration(e) {
		return ErrRuntimeController
	}
	boot, err := resetBootID()
	if err != nil {
		return ErrRuntimeController
	}
	ns, err := c.namespace()
	if err != nil {
		return ErrRuntimeController
	}
	for pass := 0; pass < 2; pass++ {
		before, err := c.namespace()
		if err != nil || before != ns {
			return ErrRuntimeController
		}
		raw, err := runKernelCommand(ctx, c.config.IPPath, "-j", "-d", "-N", "-4", "route", "show", "table", "all")
		after, nsErr := c.namespace()
		if err != nil || nsErr != nil || after != ns || ctx.Err() != nil || !azureBGPPeersAbsent(e, raw) {
			return ErrRuntimeController
		}
	}
	bootDischarged := c.retainedResetBootDischarged(ctx, e, boot, ns)
	type duty struct {
		entry   RuntimeJournalEntry
		retired bool
	}
	duties := []duty{{e, false}}
	if e.Restoration != nil {
		for _, epoch := range e.Restoration.Retired {
			duties = append(duties, duty{epoch.Entry, true})
		}
	}
	for _, d := range duties {
		entry := d.entry
		if !d.retired && entry.BGPRoutes != nil && (entry.BGPRoutes.Stage != "completed" || len(entry.BGPRoutes.Owned) > 0 || len(entry.BGPRoutes.Target) > 0) {
			return ErrRuntimeController
		}
		// A persisted trusted retirement discharges this exact previous allocation.
		// It still needs fresh current kernel/daemon absence, never object adoption.
		if d.retired {
			projected := entry
			projected.Allocation.Namespace = ns
			if c.proveAbsent(ctx, projected) != nil {
				return ErrRuntimeController
			}
		}
		processes := append([]bgpengine.ProcessIdentity(nil), entry.BGPProcessRetired...)
		if entry.BGPProcess != nil {
			processes = append(processes, *entry.BGPProcess)
		}
		for _, id := range processes {
			if !d.retired && id.Stage != "cleaned" {
				return ErrRuntimeController
			}
			if filepath.Dir(id.Directory) != c.config.JournalDir || bgpengine.ProveCleanedProcessAbsent(ctx, id, d.retired || bootDischarged) != nil {
				return ErrRuntimeController
			}
		}
		// Full generation census also covers hash-chain-compacted discharged duties.
		if bgpengine.ProveCleanedHistoryAbsent(ctx, c.config.JournalDir, "bgp-"+entry.DeliveryID.String()+"-g", ^uint64(0)) != nil {
			return ErrRuntimeController
		}
	}
	if ctx.Err() != nil {
		return ErrRuntimeController
	}
	return nil
}

// This census deliberately includes routes on renamed or non-XFRM devices.
func azureBGPPeersAbsent(e RuntimeJournalEntry, raw []byte) bool {
	rows, ok := kernelObjects(raw)
	if !ok {
		return false
	}
	for _, row := range rows {
		dst, ok := kernelString(row, "dst")
		if !ok {
			return false
		}
		prefix, ok := kernelDestination(dst)
		if !ok {
			return false
		}
		for _, tunnel := range e.Allocation.Tunnels {
			if tunnel.BGP != nil && prefix == netip.PrefixFrom(tunnel.BGP.Peer, 32) {
				return false
			}
		}
	}
	return true
}

// Reuse only the original receipt whose full coverage includes this historical
// delivery. A cleaned stage or a missing namespace cannot establish this proof.
func (c *RuntimeController) retainedResetBootDischarged(ctx context.Context, target RuntimeJournalEntry, boot, ns string) bool {
	if c.journal == nil || ctx.Err() != nil {
		return false
	}
	entries, err := c.journal.Entries()
	if err != nil {
		return false
	}
	for _, sibling := range entries {
		covered, ok := retainedResetCoverage(target, sibling, entries, boot, ns)
		if !ok {
			continue
		}
		cleanup := RuntimeCleanup{RuntimeDelivery: RuntimeDelivery{ID: sibling.CleanupID, DesiredRevision: sibling.CleanupDesiredRevision}, RetainGuard: true}
		receipt, err := c.resetCleanupReceipt(cleanup, covered)
		if err == nil && ctx.Err() == nil && retainedResetReceiptMatches(receipt, sibling.ResetCleanup, boot, ns) {
			return true
		}
	}
	return false
}

func retainedResetCoverage(target, sibling RuntimeJournalEntry, entries []RuntimeJournalEntry, boot, ns string) ([]RuntimeJournalEntry, bool) {
	if target.Phase != RuntimeRetainedRefusal || sibling.Phase != RuntimeRetainedRefusal || target.Allocation.ConnectionID != sibling.Allocation.ConnectionID || sibling.ResetCleanup == nil || !validJournalResetCleanup(sibling) || sibling.ResetCleanup.BootID != boot || sibling.ResetCleanup.Namespace != ns || target.Restoration == nil || sibling.Restoration == nil || target.Restoration.BootID == boot || target.Restoration.BootID != sibling.Restoration.BootID || sibling.CleanupID == uuid.Nil || sibling.CleanupDesiredRevision <= 0 || target.Engines[0].Binding.DesiredRevision > sibling.CoveredDeliveryRevision {
		return nil, false
	}
	var covered []RuntimeJournalEntry
	found := false
	for _, entry := range entries {
		if entry.Allocation.ConnectionID == sibling.Allocation.ConnectionID && entry.Engines[0].Binding.DesiredRevision <= sibling.CoveredDeliveryRevision {
			covered = append(covered, entry)
			if entry.DeliveryID == target.DeliveryID && reflect.DeepEqual(entry, target) {
				found = true
			}
		}
	}
	return covered, found
}

func retainedResetReceiptMatches(actual, persisted *RuntimeResetCleanup, boot, ns string) bool {
	return actual != nil && persisted != nil && actual.BootID == boot && actual.Namespace == ns && *actual == *persisted
}
