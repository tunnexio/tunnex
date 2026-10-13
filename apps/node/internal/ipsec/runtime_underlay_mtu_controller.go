package ipsec

import (
	"context"
	"reflect"
	"time"
)

// ensureUnderlayMTUs runs under the controller lock. Unchanged ceilings do not
// replace guards or extend leases. Lowering first revokes this connection while
// preserving independently qualified other connections, and re-proves denial
// before each exact kernel mutation. The caller must explicitly reauthorize.
func (c *RuntimeController) ensureUnderlayMTUs(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, entries []RuntimeJournalEntry) (lowered bool, resultErr error) {
	stage := "mtu_dependencies"
	started := time.Now()
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "underlay_mtu", stage, e.Allocation.ConnectionID, started, resultErr != nil)
	}()
	if c.kernel == nil || c.config.Environment == nil {
		return false, ErrRuntimeController
	}
	stage = "mtu_environment_observe"
	fresh, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil {
		return false, ErrRuntimeController
	}
	stage = "mtu_environment_binding"
	if !reflect.DeepEqual(fresh, env) {
		return false, ErrRuntimeController
	}
	var routes []RuntimeBGPRouteTuple
	if e.ContractVersion == 3 {
		routes = bgpRouteUnion(e.BGPRoutes)
	}
	stage = "mtu_kernel_snapshot"
	snap, err := c.kernel.snapshotSelectionRoutes(ctx, e.Allocation, true, routes)
	if err != nil {
		return false, ErrRuntimeController
	}
	stage = "mtu_owned_ceiling"
	outer := [2]uint32{}
	need := false
	for i, underlay := range env.Underlays[:e.Allocation.activeTunnelCount()] {
		ceiling, ok := runtimeProfileInnerMTU(e.Allocation.ProfileID, underlay.OuterMTU)
		if !ok || underlay.InterfaceIndex <= 0 || !underlay.LocalAddress.Is4() || snap.ownership[i] != e.Observed[i] || snap.ownership[i].InterfaceIndex == 0 || !snap.address[i] || snap.mtu[i] < 68 {
			return false, ErrRuntimeController
		}
		outer[i] = underlay.OuterMTU
		need = need || snap.mtu[i] > uint64(ceiling)
	}
	stage = "mtu_unchanged"
	if !need {
		return false, nil
	}
	stage = "mtu_lowering"
	c.withdrawDNSOwnerView(e.Allocation.ConnectionID)
	delete(c.active, e.Allocation.ConnectionID)
	deny := func(ctx context.Context) error {
		current, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
		if err != nil || !reflect.DeepEqual(current, env) {
			return ErrRuntimeController
		}
		if _, ok := c.active[e.Allocation.ConnectionID]; ok {
			return ErrRuntimeController
		}
		return c.installActive(ctx, entries)
	}
	if c.kernel.LowerTunnelMTUs(ctx, e.Allocation, e.Observed, outer, routes, deny) != nil {
		return true, ErrRuntimeController
	}
	stage = "mtu_final_environment_observe"
	fresh, err = c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil {
		return true, ErrRuntimeController
	}
	stage = "mtu_final_environment_binding"
	if !reflect.DeepEqual(fresh, env) {
		return true, ErrRuntimeController
	}
	stage = "mtu_lowered"
	return true, nil
}
