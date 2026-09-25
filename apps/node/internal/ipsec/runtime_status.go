package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"reflect"
	"strconv"
	"time"
)

// ObserveIPsecStatus reports transport observations only. Applied, route
// selection, policy leases and forwarding intent cannot manufacture Up.
func (c *RuntimeController) ObserveIPsecStatus(ctx context.Context, d RuntimeDelivery) (RuntimeStatusReport, error) {
	if d.ID == uuid.Nil || d.Kind != "apply" || d.DesiredRevision <= 0 || d.Manifest.DesiredRevision != d.DesiredRevision || d.Manifest.ConfigurationRevision <= 0 {
		return RuntimeStatusReport{}, ErrRuntimeController
	}
	recovery, recoveryErr := runtimeRecoveryContract(d.Manifest)
	if recoveryErr != nil {
		return RuntimeStatusReport{}, ErrRuntimeController
	}
	report := RuntimeStatusReport{DeliveryID: d.ID, DesiredRevision: d.DesiredRevision, ConfigurationRevision: d.Manifest.ConfigurationRevision}
	for i, t := range d.Manifest.Tunnels {
		if t.ID == uuid.Nil || t.Slot != i+1 || t.Selected != (i == 0) {
			return RuntimeStatusReport{}, ErrRuntimeController
		}
		report.Tunnels[i] = RuntimeTunnelStatus{ID: t.ID, Slot: t.Slot, Status: "unknown", Selected: t.Selected}
	}
	if report.Tunnels[0].ID == report.Tunnels[1].ID {
		return RuntimeStatusReport{}, ErrRuntimeController
	}
	if c == nil {
		if recovery {
			return RuntimeStatusReport{}, ErrRuntimeController
		}
		return report, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started || c.closed || c.journal == nil || c.config.Daemon == nil || c.config.DaemonAlive == nil {
		return report, nil
	}
	if d.Manifest.OrgID != c.config.OrgID || d.Manifest.NodeID != c.config.GatewayID {
		return RuntimeStatusReport{}, ErrRuntimeController
	}
	entries, e := c.journal.Entries()
	if e != nil {
		return report, nil
	}
	var entry *RuntimeJournalEntry
	for i := range entries {
		candidate := &entries[i]
		if candidate.DeliveryID != d.ID {
			continue
		}
		if entry != nil {
			return report, nil
		}
		entry = candidate
	}
	if entry == nil || entry.Allocation.ConnectionID != d.Manifest.ConnectionID || entry.OwnershipDigest != d.OwnershipDigest {
		return report, nil
	}
	for i, t := range entry.Engines {
		if t.TunnelID != d.Manifest.Tunnels[i].ID || t.Binding.DesiredRevision != d.DesiredRevision || t.Binding.ConfigurationRevision != d.Manifest.ConfigurationRevision {
			return report, nil
		}
	}
	if recovery {
		if entry.ContractVersion != 2 || entry.Recovery == nil {
			return RuntimeStatusReport{}, ErrRuntimeController
		}
		// Persist an observation sequence before publishing; a restarted process
		// cannot replay an older active selection with a fresh receipt time.
		if c.journal.Save(entries) != nil {
			return RuntimeStatusReport{}, ErrRuntimeController
		}
		_, seq, seqErr := c.journal.guardTemplates()
		if seqErr != nil || seq == 0 || seq > 9007199254740991 {
			return RuntimeStatusReport{}, ErrRuntimeController
		}
		version := 1
		report.RecoveryVersion, report.SelectionSequence = &version, &seq
	}
	kr, e := NewKernelReader(c.config.IPPath)
	if e != nil {
		return report, nil
	}
	xr, e := NewXFRMReader(c.config.IPPath)
	if e != nil {
		return report, nil
	}
	statuses := runtimeObservedStatuses(ctx, *entry, runtimeStatusReaders{daemon: c.config.Daemon.Inspect, kernel: kr.Read, xfrm: xr.Read, alive: c.config.DaemonAlive})
	for i, status := range statuses {
		report.Tunnels[i].Status = status
	}
	if recovery {
		slot := c.observedRecoveryActiveSlot(ctx, *entry)
		if slot != nil && report.Tunnels[*slot-1].Status == "up" {
			report.ActiveSlot = slot
		}
	}
	return report, nil
}

type runtimeStatusReaders struct {
	daemon func(context.Context) (DaemonInventory, error)
	kernel func(context.Context) (KernelInventory, error)
	xfrm   func(context.Context) (XFRMInventory, error)
	alive  func() bool
}

func runtimeObservedStatuses(ctx context.Context, e RuntimeJournalEntry, r runtimeStatusReaders) [2]string {
	unknown := [2]string{"unknown", "unknown"}
	if r.daemon == nil || r.kernel == nil || r.xfrm == nil || r.alive == nil || !r.alive() {
		return unknown
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var before [2]string
	var previousX XFRMInventory
	var previousK KernelInventory
	for pass := 0; pass < 2; pass++ {
		d, de := r.daemon(ctx)
		k, ke := r.kernel(ctx)
		x, xe := r.xfrm(ctx)
		if de != nil || ke != nil || xe != nil || ctx.Err() != nil || !r.alive() {
			return unknown
		}
		current := runtimeTunnelStatuses(e, d, k, x)
		if pass == 0 {
			before = current
			previousX = x
			previousK = k
		} else {
			if !reflect.DeepEqual(previousX, x) || !reflect.DeepEqual(previousK, k) {
				return unknown
			}
			for i := range current {
				if current[i] != before[i] {
					current[i] = "unknown"
				}
			}
			return current
		}
	}
	return unknown
}
func runtimeTunnelStatuses(e RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory) [2]string {
	result := [2]string{"unknown", "unknown"}
	if k.Namespace != e.Allocation.Namespace || x.Namespace != e.Allocation.Namespace {
		return result
	}
	for i, t := range e.Engines {
		result[i] = runtimeTunnelStatus(t, e.Observed[i], d, k, x)
	}
	return result
}
func runtimeTunnelStatus(t EngineTunnel, own Ownership, d DaemonInventory, k KernelInventory, x XFRMInventory) string {
	if !validEngineTunnel(t) || t.ReqID == 0 {
		return "unknown"
	}
	var sa *DaemonIKE
	var child *DaemonChild
	for i := range d.SAs {
		candidate := &d.SAs[i]
		if candidate.Name == engineName(t) {
			if sa != nil || candidate.LocalAddress != t.LocalAddress || candidate.RemoteAddress != t.RemoteAddress {
				return "unknown"
			}
			sa = candidate
		}
		for j := range candidate.Children {
			c := &candidate.Children[j]
			related := c.Name == engineName(t) || c.ReqID == t.ReqID || c.IfIDIn == t.XFRMID || c.IfIDOut == t.XFRMID
			if !related {
				continue
			}
			if candidate.Name != engineName(t) || c.Name != engineName(t) || c.ReqID != t.ReqID || c.IfIDIn != t.XFRMID || c.IfIDOut != t.XFRMID || !sameEnginePrefixes(c.LocalPrefixes, t.LocalPrefixes) || !sameEnginePrefixes(c.RemotePrefixes, t.RemotePrefixes) || child != nil {
				return "unknown"
			}
			child = c
		}
	}
	statesIn, statesOut := 0, 0
	for _, state := range x.States {
		if state.IfID != t.XFRMID && state.ReqID != t.ReqID {
			continue
		}
		if state.IfID != t.XFRMID || state.ReqID != t.ReqID {
			return "unknown"
		}
		if state.Source == t.LocalAddress && state.Destination == t.RemoteAddress && (state.Direction == "" || state.Direction == "out") {
			statesOut++
			if child != nil && state.SPI != child.SPIOut {
				return "unknown"
			}
		} else if state.Source == t.RemoteAddress && state.Destination == t.LocalAddress && (state.Direction == "" || state.Direction == "in") {
			statesIn++
			if child != nil && state.SPI != child.SPIIn {
				return "unknown"
			}
		} else {
			return "unknown"
		}
	}
	if statesIn > 1 || statesOut > 1 {
		return "unknown"
	}
	linkCount := 0
	linkUp := false
	for _, link := range k.Links {
		if link.Name != own.InterfaceName && link.XFRMID != t.XFRMID && link.Index != own.InterfaceIndex {
			continue
		}
		if link.Name != own.InterfaceName || link.Index != own.InterfaceIndex || link.XFRMID != t.XFRMID {
			return "unknown"
		}
		linkCount++
		linkUp = link.Up
	}
	if linkCount > 1 {
		return "unknown"
	}
	policyCount := map[string]int{}
	for _, p := range x.Policies {
		if p.IfID != t.XFRMID && p.ReqID != t.ReqID {
			continue
		}
		if p.IfID != t.XFRMID || p.ReqID != t.ReqID {
			return "unknown"
		}
		matched := false
		for _, l := range t.LocalPrefixes {
			for _, r := range t.RemotePrefixes {
				src, dst, outerSrc, outerDst := r, l, t.RemoteAddress, t.LocalAddress
				spi := uint32(0)
				if child != nil {
					spi = child.SPIIn
				}
				if p.Direction == "out" {
					src, dst, outerSrc, outerDst = l, r, t.LocalAddress, t.RemoteAddress
					if child != nil {
						spi = child.SPIOut
					}
				} else if p.Direction != "in" && p.Direction != "fwd" {
					continue
				}
				if p.Source == src && p.Destination == dst && p.TemplateSource == outerSrc && p.TemplateDestination == outerDst {
					if p.TemplateSPI != 0 && child != nil && p.TemplateSPI != spi {
						return "unknown"
					}
					key := p.Direction + "|" + l.String() + "|" + r.String()
					policyCount[key]++
					if policyCount[key] > 1 {
						return "unknown"
					}
					matched = true
				}
			}
		}
		if !matched {
			return "unknown"
		}
	}
	if sa == nil || !sa.Established || child == nil || !child.Installed || linkCount == 0 || !linkUp || statesIn == 0 || statesOut == 0 {
		return "down"
	}
	for _, l := range t.LocalPrefixes {
		for _, r := range t.RemotePrefixes {
			for _, dir := range []string{"in", "fwd", "out"} {
				if policyCount[dir+"|"+l.String()+"|"+r.String()] != 1 {
					return "down"
				}
			}
		}
	}
	return "up"
}

// Called with the controller lock held. Stored preference and journal completion
// alone never establish an actively permitted path.
func (c *RuntimeController) observedRecoveryActiveSlot(ctx context.Context, entry RuntimeJournalEntry) *int {
	if c == nil || !c.started || c.closed || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || entry.ContractVersion != 2 || entry.Phase != RuntimeApplied || entry.Recovery == nil || entry.Recovery.Stage != "completed" || entry.Recovery.SelectedSlot < 1 || entry.Recovery.SelectedSlot > 2 {
		return nil
	}
	active, ok := c.active[entry.Allocation.ConnectionID]
	if !ok || active.Authority == nil || active.Entry.DeliveryID != entry.DeliveryID || active.Entry.OwnershipDigest != entry.OwnershipDigest || !reflect.DeepEqual(active.Entry.Recovery, entry.Recovery) || !reflect.DeepEqual(active.Entry.Observed, entry.Observed) || !reflect.DeepEqual(active.Entry.Engines, entry.Engines) {
		return nil
	}
	if _, err := active.Authority.RemainingForApply(active.Identity, time.Millisecond); err != nil {
		return nil
	}
	if c.proveCurrent(ctx, active.Entry, active.Environment) != nil || !c.recoveryGuardPermits(ctx, entry) {
		return nil
	}
	if ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
		return nil
	}
	if _, err := active.Authority.RemainingForApply(active.Identity, time.Millisecond); err != nil {
		return nil
	}
	slot := int(entry.Recovery.SelectedSlot)
	return &slot
}

// Read-only strict full-table verification; withdrawal matching deliberately does
// not suffice because it permits missing (expired) lease members.
func (c *RuntimeController) recoveryGuardPermits(ctx context.Context, entry RuntimeJournalEntry) bool {
	if c.journal == nil || c.guard == nil || c.guard.reader == nil {
		return false
	}
	templates, _, err := c.journal.guardTemplates()
	if err != nil || len(templates) != 1 {
		return false
	}
	g := templates[0]
	if g.Namespace != entry.Allocation.Namespace {
		return false
	}
	objects, ok := normalizedGuardObjects([]byte(g.ExpectedJSON))
	if !ok {
		return false
	}
	index := int(entry.Recovery.SelectedSlot) - 1
	required := map[string]string{guardLeaseName(entry.Allocation.ConnectionID): strconv.Itoa(entry.Observed[index].InterfaceIndex), guardSALeaseName(entry.Allocation.ConnectionID): strconv.FormatUint(uint64(entry.Engines[index].ReqID), 10)}
	for _, object := range objects {
		fields, ok := object.(map[string]any)
		if !ok {
			return false
		}
		set, ok := fields["set"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := set["name"].(string)
		want, needed := required[name]
		if !needed {
			continue
		}
		members, ok := set["elem"].([]any)
		if !ok || len(members) != 1 {
			return false
		}
		member, ok := members[0].(map[string]any)
		if !ok {
			return false
		}
		element, ok := member["elem"].(map[string]any)
		if !ok {
			return false
		}
		value, ok := element["val"].(json.Number)
		if !ok || value.String() != want {
			return false
		}
		delete(required, name)
	}
	if len(required) != 0 {
		return false
	}
	return c.guard.reader.Check(ctx, GuardManifest{Namespace: g.Namespace, ExpectedJSON: g.ExpectedJSON}) == nil
}
