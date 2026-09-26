package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// Restoration records retired obligations, not permission. Previous entries are
// flattened (Restoration=nil) so history cannot recursively amplify the journal.
type RuntimeRestoration struct {
	BootID  string
	Epoch   uint64
	Retired []RuntimeRetiredEpoch
}
type RuntimeRetiredEpoch struct {
	Entry                       RuntimeJournalEntry
	BootID                      string
	NewBootID, NewNamespace     string
	NewGeneration               uuid.UUID
	Termination, EvidenceDigest string
}
type runtimeRestorationReceipt struct {
	Version                                                     int
	OwnerID, DeliveryID                                         uuid.UUID
	EntryDigest, BootID, Namespace, Termination, EvidenceDigest string
}

func validBootID(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id != uuid.Nil && id.String() == s
}
func restorationEntryDigest(e RuntimeJournalEntry) string {
	b, _ := json.Marshal(e)
	return stringDigest(b)
}
func flattenedRestorationEntry(e RuntimeJournalEntry) RuntimeJournalEntry {
	e.Restoration = nil
	return e
}
func sameRestorationIntent(before, after RuntimeJournalEntry) bool {
	b, a := before, after
	a.Restoration = b.Restoration
	a.Allocation.Namespace = b.Allocation.Namespace
	a.Allocation.Generation = b.Allocation.Generation
	for i := range a.Allocation.Tunnels {
		a.Allocation.Tunnels[i].Alias = b.Allocation.Tunnels[i].Alias
		a.Engines[i].LocalAddress = b.Engines[i].LocalAddress
	}
	a.Observed = b.Observed
	return reflect.DeepEqual(b, a)
}
func validRestoration(r RuntimeJournalEntry) bool {
	v := r.Restoration
	if v == nil {
		return true
	}
	if r.ContractVersion != 2 || r.AbsenceOnly || !validBootID(v.BootID) || v.Epoch != uint64(len(v.Retired)) || v.Epoch > 16 {
		return false
	}
	for i, h := range v.Retired {
		if h.Entry.Restoration != nil || h.Entry.ResetCleanup != nil || h.Entry.Phase != RuntimeApplied || !validBootID(h.NewBootID) || !validKernelNamespace(h.NewNamespace) || h.NewGeneration == uuid.Nil || h.NewGeneration == h.Entry.Allocation.Generation || !validDigest(h.EvidenceDigest) {
			return false
		}
		if !validJournalPayload(runtimeJournalPayload{Version: 3, OwnerID: r.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{h.Entry}}) {
			return false
		}
		switch h.Termination {
		case "kernel-boot-change":
			if !validBootID(h.BootID) || h.BootID == h.NewBootID {
				return false
			}
		case "supervisor-confirmed-runtime-stop":
			if h.BootID != "" && !validBootID(h.BootID) {
				return false
			}
		default:
			return false
		}
		next := r
		nextBoot := v.BootID
		if i+1 < len(v.Retired) {
			next = v.Retired[i+1].Entry
			nextBoot = v.Retired[i+1].BootID
		}
		if next.Allocation.Namespace != h.NewNamespace || next.Allocation.Generation != h.NewGeneration || nextBoot != h.NewBootID {
			return false
		}
		// Recovery duty may advance after reservation, but CP-owned intent cannot.
		n := next
		n.Phase = h.Entry.Phase
		n.Recovery = h.Entry.Recovery
		n.CleanupID = h.Entry.CleanupID
		n.CleanupDesiredRevision = h.Entry.CleanupDesiredRevision
		n.CoveredDeliveryRevision = h.Entry.CoveredDeliveryRevision
		n.ResetCleanup = h.Entry.ResetCleanup
		if !sameRestorationIntent(h.Entry, n) {
			return false
		}
	}
	return true
}
func restorationAdvanced(before, after RuntimeJournalEntry) bool {
	a := after.Restoration
	oldEpoch := uint64(0)
	if before.Restoration != nil {
		oldEpoch = before.Restoration.Epoch
	}
	return a != nil && a.Epoch == oldEpoch+1
}
func validRestorationSuccessor(before, after RuntimeJournalEntry) bool {
	if !validRestoration(after) {
		return false
	}
	if reflect.DeepEqual(before.Restoration, after.Restoration) {
		return true
	}
	if before.Restoration == nil && after.Restoration != nil && after.Restoration.Epoch == 0 {
		return before.Phase == RuntimeApplied && after.Phase == RuntimeApplied && sameRestorationIntent(before, after)
	}
	if !restorationAdvanced(before, after) || before.Phase != RuntimeApplied || after.Phase != RuntimeApplied || before.ResetCleanup != nil || after.ResetCleanup != nil || after.Observed != ([2]Ownership{}) || !reflect.DeepEqual(before.Recovery, after.Recovery) || !sameRestorationIntent(before, after) {
		return false
	}
	v := after.Restoration
	oldBoot := ""
	if before.Restoration != nil {
		oldBoot = before.Restoration.BootID
		if !reflect.DeepEqual(before.Restoration.Retired, append([]RuntimeRetiredEpoch(nil), v.Retired[:len(v.Retired)-1]...)) {
			return false
		}
	}
	last := v.Retired[len(v.Retired)-1]
	return reflect.DeepEqual(last.Entry, flattenedRestorationEntry(before)) && last.BootID == oldBoot
}

// Current kernel boot ID is recorded only after a successful authorized apply.
// This never manufactures a historical boot ID for an inaccessible old runtime.
func (c *RuntimeController) recordRuntimeBoot(ctx context.Context, id uuid.UUID) error {
	boot, err := resetBootID()
	if err != nil {
		return err
	}
	ns, err := c.namespace()
	if err != nil {
		return err
	}
	entries, err := c.journal.Entries()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.DeliveryID != id {
			continue
		}
		if e.Allocation.Namespace != ns || e.Phase != RuntimeApplied || e.ContractVersion != 2 {
			return ErrRuntimeController
		}
		if e.Restoration != nil {
			if e.Restoration.BootID != boot {
				return ErrRuntimeController
			}
			return nil
		}
		// Prove exact surviving indices before binding a legacy entry to today's boot.
		missing, err := c.kernel.RestartNeedsRecreation(ctx, e.Allocation, e.Observed)
		if err != nil || missing {
			return ErrRuntimeController
		}
		after, err := resetBootID()
		if err != nil || after != boot {
			return ErrRuntimeController
		}
		entries[i].Restoration = &RuntimeRestoration{BootID: boot}
		return c.journal.Save(entries)
	}
	return ErrRuntimeController
}
func (c *RuntimeController) restorationProof(e RuntimeJournalEntry, boot, ns string) (string, string, error) {
	if e.Restoration != nil && e.Restoration.BootID != boot {
		return "kernel-boot-change", stringDigest([]byte(e.Restoration.BootID + "\n" + boot)), nil
	}
	if os.Geteuid() != 0 || !c.journal.pathsIntact() {
		return "", "", ErrRuntimeController
	}
	path := filepath.Join(c.config.JournalDir, "restore-"+e.DeliveryID.String()+".json")
	f, err := journalOpenNoFollow(path, false)
	if err != nil {
		return "", "", ErrRuntimeController
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !journalPrivate(info, false) || info.Size() > 8192 {
		return "", "", ErrRuntimeController
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return "", "", ErrRuntimeController
	}
	now, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, now) || !journalPrivate(now, false) {
		return "", "", ErrRuntimeController
	}
	if _, ok := runtimeJSONObject(raw); !ok {
		return "", "", ErrRuntimeController
	}
	var r runtimeRestorationReceipt
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		return "", "", ErrRuntimeController
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return "", "", ErrRuntimeController
	}
	if r.Version != 1 || r.OwnerID != c.config.GatewayID || r.DeliveryID != e.DeliveryID || r.EntryDigest != restorationEntryDigest(e) || r.BootID != boot || r.Namespace != ns || r.Termination != "supervisor-confirmed-runtime-stop" || !validDigest(r.EvidenceDigest) {
		return "", "", ErrRuntimeController
	}
	return r.Termination, stringDigest(raw), nil
}
func (c *RuntimeController) restorationAbsent(ctx context.Context, e RuntimeJournalEntry, boot, ns string) error {
	for pass := 0; pass < 2; pass++ {
		b, err := resetBootID()
		if err != nil || b != boot {
			return ErrRuntimeController
		}
		n, err := c.namespace()
		if err != nil || n != ns {
			return ErrRuntimeController
		}
		projected := e
		projected.Allocation.Namespace = ns
		if c.proveAbsent(ctx, projected) != nil {
			return ErrRuntimeController
		}
		links, err := c.kernel.run(ctx, "-j", "-d", "link", "show")
		if err != nil {
			return ErrRuntimeController
		}
		addresses, err := c.kernel.run(ctx, "-j", "addr", "show")
		if err != nil || !resetExtraObjectsAbsent(e, links, addresses) {
			return ErrRuntimeController
		}
		b, err = resetBootID()
		if err != nil || b != boot {
			return ErrRuntimeController
		}
		n, err = c.namespace()
		if err != nil || n != ns || ctx.Err() != nil {
			return ErrRuntimeController
		}
	}
	return nil
}
func (c *RuntimeController) reserveRestoration(ctx context.Context, m RuntimeMaterial, entries []RuntimeJournalEntry, pos int, candidate RuntimeJournalEntry, boot string) error {
	old := entries[pos]
	candidate.Phase = old.Phase
	candidate.Observed = old.Observed
	candidate.Recovery = old.Recovery
	if old.Phase != RuntimeApplied || old.ContractVersion != 2 || old.AbsenceOnly || old.ResetCleanup != nil || !sameRestorationIntent(old, candidate) {
		return ErrRuntimeController
	}
	ns := candidate.Allocation.Namespace
	termination, digest, err := c.restorationProof(old, boot, ns)
	if err != nil {
		return err
	}
	c.active = nil
	if _, err = c.refuse(ctx, entries); err != nil {
		return err
	}
	authority, identity, err := c.recoveryLease(ctx, old, m.Policy.Hash)
	if err != nil {
		return err
	}
	if c.restorationAbsent(ctx, old, boot, ns) != nil {
		return ErrRuntimeController
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return err
	}
	v := RuntimeRestoration{BootID: boot}
	oldBoot := ""
	if old.Restoration != nil {
		v.Epoch = old.Restoration.Epoch
		v.Retired = append(v.Retired, old.Restoration.Retired...)
		oldBoot = old.Restoration.BootID
	}
	if v.Epoch >= 16 {
		return ErrRuntimeController
	}
	candidate.Allocation.Generation = uuid.New()
	for i := range candidate.Allocation.Tunnels {
		candidate.Allocation.Tunnels[i].Alias = KernelTunnelAlias(candidate.Allocation.Generation, candidate.Allocation.Tunnels[i].TunnelID)
	}
	candidate.Observed = [2]Ownership{}
	v.Epoch++
	v.Retired = append(v.Retired, RuntimeRetiredEpoch{Entry: flattenedRestorationEntry(old), BootID: oldBoot, NewBootID: boot, NewNamespace: ns, NewGeneration: candidate.Allocation.Generation, Termination: termination, EvidenceDigest: digest})
	candidate.Restoration = &v
	entries[pos] = candidate
	if c.journal.Save(entries) != nil {
		return ErrRuntimeController
	}
	delete(c.recoveryPrepared, old.DeliveryID)
	delete(c.recoveryHistory, old.Allocation.ConnectionID)
	return nil
}
