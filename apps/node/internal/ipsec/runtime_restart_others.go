package ipsec

import (
	"context"
	"reflect"
)

// restartNeedsRecreation is controller-only: independently owned transport from
// another applied journal obligation is not evidence that this absent tunnel survived.
// Direct kernel callers retain the global-empty census.
func (c *RuntimeController) restartNeedsRecreation(ctx context.Context, target RuntimeJournalEntry) (bool, error) {
	return c.kernel.restartNeedsRecreation(ctx, target.Allocation, target.Observed, func(ctx context.Context, x XFRMInventory) error {
		if len(x.States) == 0 && len(x.Policies) == 0 {
			return nil
		}
		if c.journal == nil || c.config.Daemon == nil || c.config.DaemonAlive == nil || c.config.Environment == nil {
			return ErrRuntimeController
		}
		entries, err := c.journal.Entries()
		if err != nil || x.Namespace != target.Allocation.Namespace || !c.config.DaemonAlive() {
			return ErrRuntimeController
		}
		d, err := c.config.Daemon.Inspect(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		kr, err := NewKernelReader(c.config.IPPath)
		if err != nil {
			return ErrRuntimeController
		}
		k, err := kr.Read(ctx)
		if err != nil || k.Namespace != x.Namespace {
			return ErrRuntimeController
		}
		others := []RuntimeJournalEntry{}
		for _, e := range entries {
			if e.DeliveryID == target.DeliveryID || e.Phase != RuntimeApplied || e.AbsenceOnly || e.Allocation.Namespace != x.Namespace {
				continue
			}
			// Only actual state/policy ownership needs an exclusion. Empty obligations
			// remain independently absent; they do not authorize adopting any tuple.
			relevant := false
			for _, t := range e.Engines[:e.Allocation.activeTunnelCount()] {
				for _, s := range x.States {
					relevant = relevant || s.IfID == t.XFRMID || s.ReqID == t.ReqID
				}
				for _, p := range x.Policies {
					relevant = relevant || p.IfID == t.XFRMID || p.ReqID == t.ReqID
				}
			}
			if !relevant {
				continue
			}
			env, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
			if err != nil || c.proveCurrent(ctx, e, env) != nil {
				return ErrRuntimeController
			}
			others = append(others, e)
		}
		if !restartInventoryOwnedByOthers(target, others, d, k, x) {
			return ErrRuntimeController
		}
		xr, err := NewXFRMReader(c.config.IPPath)
		if err != nil {
			return ErrRuntimeController
		}
		after, err := xr.Read(ctx)
		if err != nil || !reflect.DeepEqual(x, after) || !c.config.DaemonAlive() {
			return ErrRuntimeController
		}
		return nil
	})
}

func restartInventoryOwnedByOthers(target RuntimeJournalEntry, others []RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory) bool {
	states := make([]bool, len(x.States))
	policies := make([]bool, len(x.Policies))
	for _, e := range others {
		if e.DeliveryID == target.DeliveryID || e.Phase != RuntimeApplied || e.AbsenceOnly || e.Allocation.Namespace != x.Namespace || k.Namespace != x.Namespace {
			return false
		}
		for i, t := range e.Engines[:e.Allocation.activeTunnelCount()] {
			for _, wanted := range target.Engines[:target.Allocation.activeTunnelCount()] {
				if t.XFRMID == wanted.XFRMID || t.ReqID == wanted.ReqID || engineName(t) == engineName(wanted) {
					return false
				}
			}
			relevant := false
			for _, s := range x.States {
				relevant = relevant || s.IfID == t.XFRMID || s.ReqID == t.ReqID
			}
			for _, p := range x.Policies {
				relevant = relevant || p.IfID == t.XFRMID || p.ReqID == t.ReqID
			}
			if !relevant {
				continue
			}
			if runtimeTunnelStatus(t, e.Observed[i], d, k, x) != "up" {
				return false
			}
			for j, s := range x.States {
				if s.IfID == t.XFRMID && s.ReqID == t.ReqID {
					if states[j] {
						return false
					}
					states[j] = true
				}
			}
			for j, p := range x.Policies {
				if p.IfID == t.XFRMID && p.ReqID == t.ReqID {
					if policies[j] {
						return false
					}
					policies[j] = true
				}
			}
		}
	}
	for _, owned := range states {
		if !owned {
			return false
		}
	}
	for _, owned := range policies {
		if !owned {
			return false
		}
	}
	return true
}
