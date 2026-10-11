package ipsec

import (
	"context"
	"time"
)

// Quiesced is a local negative checkpoint, never a permit or a CP cleanup ACK.
// Initially only the qualified shared BGP contract has a complete stop proof.
func validQuiescedEntry(e RuntimeJournalEntry) bool {
	if e.ContractVersion != 3 || e.AbsenceOnly || e.Restoration == nil || !validRestoration(e) || !validJournalBGP(e) || !validBGPProcess(e) || !validBGPRoutes(e) || e.BGPProcess == nil || e.BGPProcess.Stage != "cleaned" || e.BGPRoutes == nil || !e.BGPRoutes.Withdrawal || e.BGPRoutes.Stage != "completed" || e.BGPRoutes.Owned == nil || e.BGPRoutes.Target == nil || len(e.BGPRoutes.Owned) != 0 || len(e.BGPRoutes.Target) != 0 {
		return false
	}
	if e.BGPProcess.BootID != e.Restoration.BootID || e.BGPProcess.Namespace != e.Allocation.Namespace {
		return false
	}
	for i, tunnel := range e.Allocation.Tunnels[:e.Allocation.activeTunnelCount()] {
		o := e.Observed[i]
		if o.Namespace != e.Allocation.Namespace || o.InterfaceName != tunnel.Name || o.XFRMID != tunnel.XFRMID || o.InterfaceIndex <= 0 {
			return false
		}
	}
	for _, p := range e.BGPProcessRetired {
		if p.Stage != "cleaned" {
			return false
		}
	}
	return true
}

func (c *RuntimeController) proveQuiescedAbsent(ctx context.Context, e RuntimeJournalEntry) error {
	if !validQuiescedEntry(e) || ctx.Err() != nil {
		return ErrRuntimeController
	}
	boot, err := resetBootID()
	if err != nil || boot != e.Restoration.BootID {
		return ErrRuntimeController
	}
	ns, err := c.namespace()
	if err != nil || ns != e.Allocation.Namespace {
		return ErrRuntimeController
	}
	// Retained entries remain obligations; warm restart cannot hide their FRR
	// generations or manufacture old-boot discharge from a cleaned stage.
	entries, err := c.journal.Entries()
	if err != nil {
		return ErrRuntimeController
	}
	for _, historical := range entries {
		if historical.Phase == RuntimeRetainedRefusal && historical.ContractVersion == 3 {
			if c.proveAzureBGPDutiesAbsent(ctx, historical) != nil {
				return ErrRuntimeController
			}
		}
	}
	if c.restorationAbsent(ctx, e, boot, ns) != nil || c.proveStoppedBGPDutiesAbsent(ctx, e) != nil {
		return ErrRuntimeController
	}
	return nil
}

// Quiesce withdraws authority before removing only exactly owned native objects.
// No positive checkpoint is written until every selected entry proves absent.
// Failure leaves the original potential-installation phase and denial intact.
type quiesceProofInputs struct {
	boot     func() (string, error)
	absent   func(context.Context, RuntimeJournalEntry) error
	complete func(context.Context, []RuntimeJournalEntry, DaemonInventory, func() error) error
}

func (c *RuntimeController) Quiesce(ctx context.Context, closeDaemon func() error) error {
	return c.quiesce(ctx, closeDaemon, quiesceProofInputs{resetBootID, c.proveQuiescedAbsent, c.completeQuiesce})
}

// This private transaction core supplies no qualification override. Production
// always binds the actual readers above; tests explicitly model native readers.
func (c *RuntimeController) quiesce(ctx context.Context, closeDaemon func() error, proof quiesceProofInputs) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.started || closeDaemon == nil || proof.boot == nil || proof.absent == nil || proof.complete == nil || ctx.Err() != nil {
		return ErrRuntimeController
	}
	entries, err := c.journal.Entries()
	if err != nil {
		return ErrRuntimeController
	}
	c.active = nil
	if _, err = c.refuse(ctx, entries); err != nil {
		return ErrRuntimeController
	}
	c.started = false
	var selected []RuntimeJournalEntry
	for _, e := range entries {
		if e.Phase != RuntimeApplied {
			continue
		}
		// Unsupported contracts remain Applied and cannot gain warm restage rights.
		if e.ContractVersion != 3 {
			continue
		}
		boot, err := proof.boot()
		ns, nsErr := c.namespace()
		if err != nil || nsErr != nil || e.Restoration == nil || e.Restoration.BootID != boot || e.Allocation.Namespace != ns {
			return ErrRuntimeController
		}
		if c.finishKnownBGPSession(e) != nil || WithdrawBGPRoutes(ctx, c.journal, c.kernel, e.DeliveryID.String()) != nil {
			return ErrRuntimeController
		}
		// Consume the real cleaned checkpoint, retaining the original allocation.
		refreshed, err := c.journal.Entries()
		if err != nil {
			return ErrRuntimeController
		}
		for _, current := range refreshed {
			if current.DeliveryID == e.DeliveryID {
				e = current
			}
		}
		for slot, t := range e.Engines[:e.Allocation.activeTunnelCount()] {
			var err error
			if IsAzureBGPProfile(e.Allocation.ProfileID) {
				err = c.config.Daemon.removeAzureQuiesceTunnel(ctx, e, slot, ns, boot)
			} else {
				err = c.config.Daemon.removeTunnel(ctx, t)
			}
			if err != nil {
				return ErrRuntimeController
			}
		}
		if _, err := c.kernel.Remove(ctx, e.Allocation, e.Observed); err != nil {
			return ErrRuntimeController
		}
		selected = append(selected, e)
	}
	if len(selected) == 0 {
		return nil
	}
	if c.config.Environment.Drain(ctx, selected) != nil {
		return ErrRuntimeController
	}
	entries, err = c.journal.Entries()
	if err != nil {
		return ErrRuntimeController
	}
	for i, e := range entries {
		found := false
		for _, old := range selected {
			found = found || old.DeliveryID == e.DeliveryID
		}
		if !found {
			continue
		}
		if e.Phase != RuntimeApplied || proof.absent(ctx, e) != nil {
			return ErrRuntimeController
		}
		entries[i].Phase = RuntimeQuiesced
	}
	// The actual daemon snapshot is negative only, and is fenced by its exact
	// owned process join. It never substitutes for a new process inventory.
	d, err := c.config.Daemon.Inspect(ctx)
	if err != nil {
		return ErrRuntimeController
	}
	return proof.complete(ctx, entries, d, closeDaemon)
}

// Called only after full pre-join absence. A failed or canceled join cannot
// publish the negative checkpoint, even if transport removal already completed.
func (c *RuntimeController) completeQuiesce(ctx context.Context, entries []RuntimeJournalEntry, d DaemonInventory, closeDaemon func() error) error {
	if closeDaemon == nil || ctx.Err() != nil || closeDaemon() != nil || ctx.Err() != nil {
		return ErrRuntimeController
	}
	if c.config.DaemonAlive == nil || c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	kr, err := NewKernelReader(c.config.IPPath)
	if err != nil {
		return ErrRuntimeController
	}
	xr, err := NewXFRMReader(c.config.IPPath)
	if err != nil {
		return ErrRuntimeController
	}
	for pass := 0; pass < 2; pass++ {
		k, err := kr.Read(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		x, err := xr.Read(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		for _, e := range entries {
			if e.Phase != RuntimeQuiesced {
				continue
			}
			boot, err := resetBootID()
			ns, nsErr := c.namespace()
			if err != nil || nsErr != nil || boot != e.Restoration.BootID || ns != e.Allocation.Namespace || !runtimeObjectsAbsent(e, d, k, x) {
				return ErrRuntimeController
			}
		}
	}
	if _, err := c.refuse(ctx, entries); err != nil {
		return ErrRuntimeController
	}
	if ctx.Err() != nil || c.journal.Save(entries) != nil {
		return ErrRuntimeController
	}
	return nil
}

// A durable negative phase cannot supply a lease. The original request's fresh
// monotonic authority must survive all independent absence reads and the save.
func (c *RuntimeController) reserveQuiescedApply(ctx context.Context, entries []RuntimeJournalEntry, pos int, authority *PermitLeaseAuthority, identity PermitLeaseIdentity) error {
	return c.reserveQuiescedApplyProof(ctx, entries, pos, authority, identity, c.proveQuiescedAbsent)
}

func (c *RuntimeController) reserveQuiescedApplyProof(ctx context.Context, entries []RuntimeJournalEntry, pos int, authority *PermitLeaseAuthority, identity PermitLeaseIdentity, absent func(context.Context, RuntimeJournalEntry) error) error {
	if absent == nil || pos < 0 || pos >= len(entries) || entries[pos].Phase != RuntimeQuiesced || authority == nil || ctx.Err() != nil {
		return ErrRuntimeController
	}
	if _, err := authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return ErrRuntimeController
	}
	e := entries[pos]
	if identity.DeliveryID != e.DeliveryID || identity.Binding != e.Engines[0].Binding || absent(ctx, e) != nil {
		return ErrRuntimeController
	}
	if _, err := authority.RemainingForApply(identity, 5*time.Second); err != nil || ctx.Err() != nil {
		return ErrRuntimeController
	}
	e.Phase = RuntimeApplying
	e.Observed = [2]Ownership{}
	next := cloneRuntimeEntries(entries)
	next[pos] = e
	if c.journal.Save(next) != nil {
		return ErrRuntimeController
	}
	entries[pos] = e
	return nil
}
