package ipsec

import (
	"context"
	"fmt"
	"reflect"
	"time"
)

// Version 14 is written only when a real cold Quiesced restoration first
// retains this negative predecessor. The payload version stays monotonic after
// history compaction; older readers must refuse rather than discard it.
func hasColdQuiescedRestoration(e RuntimeJournalEntry) bool {
	if e.Restoration != nil {
		for _, epoch := range e.Restoration.Retired {
			if epoch.Entry.Phase == RuntimeQuiesced {
				return true
			}
		}
	}
	return false
}

func (c *RuntimeController) restorationCurrent(ctx context.Context, boot, ns string) bool {
	b, err := resetBootID()
	n, nsErr := c.namespace()
	return err == nil && nsErr == nil && b == boot && n == ns && ctx.Err() == nil
}

// The old boot proves termination, never absence of conflicting current objects.
// Reuse the independent native and process-directory census, including every
// retained/refused duty and compacted generation; no stale PID is signalled.
func (c *RuntimeController) coldQuiescedRestorationAbsent(ctx context.Context, e RuntimeJournalEntry, boot, ns string) error {
	if e.Phase != RuntimeQuiesced || !validQuiescedEntry(e) || e.Restoration.BootID == boot || !c.restorationCurrent(ctx, boot, ns) {
		return ErrRuntimeController
	}
	entries, err := c.journal.Entries()
	if err != nil {
		return ErrRuntimeController
	}
	found := 0
	for _, historical := range entries {
		if historical.DeliveryID == e.DeliveryID {
			if !reflect.DeepEqual(historical, e) {
				return ErrRuntimeController
			}
			found++
		}
		if historical.DeliveryID != e.DeliveryID && !(historical.Phase == RuntimeRetainedRefusal && historical.ContractVersion == 3) {
			continue
		}
		if historical.Restoration == nil || !validBootID(historical.Restoration.BootID) || !validRestoration(historical) || !validBGPProcess(historical) || !validBGPRoutes(historical) {
			return ErrRuntimeController
		}
		if c.restorationAbsent(ctx, historical, boot, ns) != nil {
			return ErrRuntimeController
		}
		changedBoot := historical.Restoration.BootID != boot
		if c.proveStoppedBGPDutiesAbsentInBoot(ctx, historical, boot, ns, changedBoot) != nil {
			return ErrRuntimeController
		}
	}
	if found != 1 || !c.restorationCurrent(ctx, boot, ns) {
		return ErrRuntimeController
	}
	return nil
}

// These two modeled-I/O arguments are private transaction seams. Production
// reserveRestoration always supplies the actual readers above; no configuration,
// wire value or saved checkpoint can replace either proof.
func (c *RuntimeController) reserveColdQuiescedRestoration(ctx context.Context, m RuntimeMaterial, entries []RuntimeJournalEntry, pos int, candidate RuntimeJournalEntry, boot string, absent func(context.Context, RuntimeJournalEntry, string, string) error, current func(context.Context, string, string) bool) error {
	if pos < 0 || pos >= len(entries) || absent == nil || current == nil {
		return ErrRuntimeController
	}
	old := entries[pos]
	ns := candidate.Allocation.Namespace
	if old.Phase != RuntimeQuiesced || !validQuiescedEntry(old) || old.ResetCleanup != nil || !validBootID(boot) || old.Restoration.BootID == boot || !validKernelNamespace(ns) || !current(ctx, boot, ns) {
		return fmt.Errorf("%w: cold quiesced intent", ErrRuntimeController)
	}
	candidate.Phase, candidate.Observed, candidate.Recovery = old.Phase, old.Observed, old.Recovery
	candidate.BGPProcess, candidate.BGPRoutes = old.BGPProcess, old.BGPRoutes
	candidate.BGPProcessHistory, candidate.BGPProcessRetired = old.BGPProcessHistory, append(old.BGPProcessRetired[:0:0], old.BGPProcessRetired...)
	if !sameRestorationIntent(old, candidate) {
		return fmt.Errorf("%w: cold quiesced intent", ErrRuntimeController)
	}
	termination, digest, err := c.restorationProof(old, boot, ns)
	if err != nil || termination != "kernel-boot-change" {
		return fmt.Errorf("%w: cold quiesced boot", ErrRuntimeController)
	}
	c.active = nil
	if _, err = c.refuse(ctx, entries); err != nil {
		return fmt.Errorf("%w: cold quiesced denial", err)
	}
	authority, identity, err := c.recoveryLease(ctx, old, m.Policy.Hash, m.Policy)
	if err != nil {
		return fmt.Errorf("%w: cold quiesced lease", err)
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return err
	}
	if absent(ctx, old, boot, ns) != nil || !current(ctx, boot, ns) {
		return fmt.Errorf("%w: cold quiesced absence", ErrRuntimeController)
	}
	fresh, err := c.journal.Entries()
	if err != nil || !reflect.DeepEqual(fresh, entries) {
		return fmt.Errorf("%w: cold quiesced journal fence", ErrRuntimeController)
	}
	candidate, err = restorationReservation(old, candidate, boot, ns, termination, digest)
	if err != nil {
		return err
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil || !current(ctx, boot, ns) {
		return ErrRuntimeController
	}
	next := make([]RuntimeJournalEntry, len(entries))
	for i, entry := range entries {
		next[i] = copyDNSEntry(entry)
	}
	next[pos] = candidate
	if err = c.journal.Save(next); err != nil {
		return fmt.Errorf("%w: cold quiesced reservation", err)
	}
	entries[pos] = candidate
	delete(c.recoveryPrepared, old.DeliveryID)
	delete(c.recoveryHistory, old.Allocation.ConnectionID)
	// An interrupted/late save retains only Applying obligations. It cannot ACK
	// application access, and reopening still requires a new independent lease.
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil || !current(ctx, boot, ns) {
		return ErrRuntimeController
	}
	return nil
}
