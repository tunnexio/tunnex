package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// Private native-I/O seam. Production always binds the real qualification,
// finite guard, route, VICI and process-directory readers below.
type quiescedRetainedBGPProof struct {
	strict    func(context.Context, RuntimeJournalEntry) error
	current   func(context.Context, runtimeActive) error
	routes    func(context.Context) ([]byte, error)
	processes func(context.Context, RuntimeJournalEntry, string, string) error
	boot      func() (string, error)
	daemon    func(context.Context) (DaemonInventory, error)
}

func (c *RuntimeController) proveQuiescedRetainedBGPDuties(ctx context.Context, entries []RuntimeJournalEntry) error {
	return c.proveQuiescedRetainedBGP(ctx, entries, quiescedRetainedBGPProof{
		strict: c.proveAzureBGPDutiesAbsent,
		current: func(ctx context.Context, a runtimeActive) error {
			return c.maintenanceCurrent(ctx, a, c.bgpQualificationCurrent)
		},
		routes: func(ctx context.Context) ([]byte, error) {
			return runKernelCommand(ctx, c.config.IPPath, "-j", "-d", "-N", "-4", "route", "show", "table", "all")
		},
		processes: func(ctx context.Context, e RuntimeJournalEntry, boot, ns string) error {
			return c.proveStoppedBGPProcessesAbsentInBoot(ctx, e, boot, ns, false)
		},
		boot: resetBootID,
		daemon: func(ctx context.Context) (DaemonInventory, error) {
			if c.config.Daemon == nil {
				return DaemonInventory{}, ErrRuntimeController
			}
			return c.config.Daemon.Inspect(ctx)
		},
	})
}

// Re-enabled BGP keeps its peer addresses and kernel IDs. Their current use by
// an independently qualified newer delivery is not an old transport survivor.
// The immutable old process/history obligations are never discharged by this
// classification. All other callers retain the original strict absence proof.
func (c *RuntimeController) proveQuiescedRetainedBGP(ctx context.Context, entries []RuntimeJournalEntry, proof quiescedRetainedBGPProof) error {
	if c == nil || c.journal == nil || proof.strict == nil || proof.current == nil || proof.routes == nil || proof.processes == nil || proof.boot == nil || proof.daemon == nil || ctx.Err() != nil {
		return ErrRuntimeController
	}
	type cohort struct {
		active   runtimeActive
		old      []RuntimeJournalEntry
		deadline time.Duration
		process  runtimeBGPSession
	}
	var groups []*cohort
	byID := map[uuid.UUID]*cohort{}
	for _, old := range entries {
		if old.Phase != RuntimeRetainedRefusal || old.ContractVersion != 3 {
			continue
		}
		a, ok := c.active[old.Allocation.ConnectionID]
		if !ok || !sameQuiescedBGPTransport(old, a.Entry) {
			if proof.strict(ctx, old) != nil {
				return ErrRuntimeController
			}
			continue
		}
		group := byID[old.Allocation.ConnectionID]
		if group == nil {
			if a.Authority == nil {
				return ErrRuntimeController
			}
			group = &cohort{active: cloneMaintenanceActive(a), deadline: a.Authority.deadline, process: c.bgpProcesses[a.Entry.DeliveryID]}
			byID[old.Allocation.ConnectionID] = group
			groups = append(groups, group)
		}
		group.old = append(group.old, old)
	}
	if len(groups) == 0 {
		return nil
	}
	boot, err := proof.boot()
	ns, nsErr := c.namespace()
	if err != nil || nsErr != nil {
		return ErrRuntimeController
	}
	fence := func() bool {
		if ctx.Err() != nil || !c.started || c.closed || c.qualification == nil || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
			return false
		}
		b, err := proof.boot()
		n, nerr := c.namespace()
		if err != nil || nerr != nil || b != boot || n != ns {
			return false
		}
		current, err := c.journal.Entries()
		if err != nil || !reflect.DeepEqual(current, entries) {
			return false
		}
		for _, g := range groups {
			a := g.active
			e := a.Entry
			if e.Restoration.BootID != boot || e.Allocation.Namespace != ns || !reflect.DeepEqual(c.active[e.Allocation.ConnectionID], a) || a.Authority.deadline != g.deadline || a.Identity.DeliveryID != e.DeliveryID || a.Identity.Binding != e.Engines[0].Binding || a.Delivery.ID != e.DeliveryID || g.process == nil || !g.process.Alive() || c.bgpProcesses[e.DeliveryID] != g.process {
				return false
			}
			count := 0
			for _, candidate := range entries {
				if candidate.Allocation.ConnectionID != e.Allocation.ConnectionID {
					continue
				}
				if candidate.DeliveryID == e.DeliveryID && reflect.DeepEqual(candidate, e) {
					count++
					continue
				}
				if candidate.Phase != RuntimeRetainedRefusal || candidate.CleanupDesiredRevision >= e.Engines[0].Binding.DesiredRevision {
					return false
				}
			}
			if count != 1 {
				return false
			}
			if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
				return false
			}
		}
		return true
	}
	if !fence() {
		return ErrRuntimeController
	}
	for _, g := range groups {
		if proof.current(ctx, g.active) != nil || !fence() {
			return ErrRuntimeController
		}
	}
	// Complete native inventories bracket all historical duties. Duplicate or
	// foreign routes to a shared peer are never covered by the successor.
	native := func() error {
		raw, err := proof.routes(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		daemon, err := proof.daemon(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		for _, g := range groups {
			if !quiescedBGPPeerRoutesOwned(g.active.Entry, raw) {
				return ErrRuntimeController
			}
			for _, old := range g.old {
				for _, t := range old.Engines {
					name := engineName(t)
					if containsString(daemon.Connections, name) || containsString(daemon.SharedKeys, name) {
						return ErrRuntimeController
					}
					for _, sa := range daemon.SAs {
						if sa.Name == name {
							return ErrRuntimeController
						}
						for _, child := range sa.Children {
							if child.Name == name {
								return ErrRuntimeController
							}
						}
					}
				}
			}
		}
		if !fence() {
			return ErrRuntimeController
		}
		return nil
	}
	if native() != nil {
		return ErrRuntimeController
	}
	for _, g := range groups {
		for _, old := range g.old {
			if proof.processes(ctx, old, boot, ns) != nil || !fence() {
				return ErrRuntimeController
			}
		}
	}
	if native() != nil {
		return ErrRuntimeController
	}
	for _, g := range groups {
		if proof.current(ctx, g.active) != nil || !fence() {
			return ErrRuntimeController
		}
	}
	return nil
}

func sameQuiescedBGPTransport(old, next RuntimeJournalEntry) bool {
	// The native AWS profile is the empty profile ID. Other providers retain
	// strict absence until their transport reuse is separately qualified.
	if old.Allocation.ProfileID != "" || next.Allocation.ProfileID != "" || !old.Allocation.BGP || !next.Allocation.BGP || old.Allocation.activeTunnelCount() != 2 || next.Allocation.activeTunnelCount() != 2 {
		return false
	}
	if old.Phase != RuntimeRetainedRefusal || next.Phase != RuntimeApplied || old.ContractVersion != 3 || next.ContractVersion != 3 || old.AbsenceOnly || next.AbsenceOnly || old.DeliveryID == next.DeliveryID || old.SiteID != next.SiteID || !validJournalBGP(old) || !validJournalBGP(next) || !validBGPProcess(old) || !validBGPProcess(next) || !validBGPRoutes(old) || !validBGPRoutes(next) || old.BGPProcess == nil || old.BGPProcess.Stage != "cleaned" || next.BGPProcess == nil || next.BGPProcess.Stage != "ready" || old.BGPRoutes == nil || !old.BGPRoutes.Withdrawal || old.BGPRoutes.Stage != "completed" || len(old.BGPRoutes.Owned) != 0 || len(old.BGPRoutes.Target) != 0 || next.BGPRoutes == nil || next.BGPRoutes.Stage != "completed" || old.CleanupID == uuid.Nil || old.CleanupDesiredRevision <= old.Engines[0].Binding.DesiredRevision || old.CleanupDesiredRevision >= next.Engines[0].Binding.DesiredRevision || !reflect.DeepEqual(old.BGP, next.BGP) {
		return false
	}
	// Genuine restoration epochs retain the unchanged full absence path. This
	// narrow same-boot re-enable case carries no retired native allocation.
	for _, e := range []RuntimeJournalEntry{old, next} {
		if e.Restoration == nil || !validRestoration(e) || e.Restoration.Epoch != 0 || len(e.Restoration.Retired) != 0 || e.Restoration.Compacted != nil || e.ResetCleanup != nil || len(e.RetainedGuardPredecessors) != 0 {
			return false
		}
	}
	if old.Restoration.BootID != next.Restoration.BootID {
		return false
	}
	a, b := old.Allocation, next.Allocation
	b.Generation = a.Generation
	for i := range b.Tunnels {
		b.Tunnels[i].Alias = a.Tunnels[i].Alias
	}
	if !reflect.DeepEqual(a, b) {
		return false
	}
	for i := range old.Engines {
		a, b := old.Engines[i], next.Engines[i]
		b.Binding.DesiredRevision = a.Binding.DesiredRevision
		if !reflect.DeepEqual(a, b) {
			return false
		}
	}
	return true
}

func quiescedBGPPeerRoutesOwned(e RuntimeJournalEntry, raw []byte) bool {
	rows, ok := kernelObjects(raw)
	if !ok {
		return false
	}
	seen := [2]bool{}
	for _, row := range rows {
		dst, ok := kernelString(row, "dst")
		if !ok {
			return false
		}
		prefix, ok := kernelDestination(dst)
		if !ok {
			return false
		}
		for i, t := range e.Allocation.Tunnels {
			if t.BGP == nil || prefix != netip.PrefixFrom(t.BGP.Peer, 32) {
				continue
			}
			if seen[i] {
				return false
			}
			seen[i] = true
			for key := range row {
				switch key {
				case "dst", "dev", "table", "protocol", "scope", "type", "metric", "flags":
				default:
					return false
				}
			}
			dev, dok := kernelString(row, "dev")
			table, tok := kernelDecimal(row, "table", 32)
			protocol, pok := kernelDecimal(row, "protocol", 8)
			scope, sok := kernelDecimal(row, "scope", 8)
			kind, kok := kernelDecimal(row, "type", 8)
			metric, mok := kernelNumber(row["metric"], 32)
			flags, fok := kernelFlags(row["flags"])
			if !dok || dev != t.Name || !tok || table != 254 || !pok || protocol != 242 || !sok || scope != 253 || !kok || kind != 1 || !mok || metric != 50000+uint64(t.Slot) || !fok || len(flags) != 0 {
				return false
			}
		}
	}
	return seen == ([2]bool{true, true})
}
