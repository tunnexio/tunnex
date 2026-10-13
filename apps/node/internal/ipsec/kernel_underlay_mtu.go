package ipsec

import (
	"context"
	"strconv"
)

// LowerTunnelMTUs requires the caller to have already installed and verified
// denial. It mutates only exact owned links, never routes/SAs or grant authority.
// Existing smaller operator ceilings are preserved; restoration never raises an
// MTU based on a guess about whether its prior lowering was operator-managed.
func (a *KernelApplier) LowerTunnelMTUs(ctx context.Context, p KernelAllocation, previous [2]Ownership, outer [2]uint32, routes []RuntimeBGPRouteTuple, verifyDenial func(context.Context) error) error {
	if (p.activeTunnelCount() == 1 && (previous[1] != (Ownership{}) || outer[1] != 0)) || verifyDenial == nil || verifyDenial(ctx) != nil {
		return ErrKernelApply
	}
	ceilings := [2]uint32{}
	for i, value := range outer[:p.activeTunnelCount()] {
		var ok bool
		ceilings[i], ok = runtimeProfileInnerMTU(p.ProfileID, value)
		if !ok {
			return ErrKernelApply
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 6*kernelReadTimeout)
	defer cancel()
	snapshot, err := a.snapshotSelectionRoutes(ctx, p, true, routes)
	if err != nil {
		return ErrKernelApply
	}
	for i, owned := range snapshot.ownership[:p.activeTunnelCount()] {
		if owned.InterfaceIndex == 0 || owned != previous[i] || !snapshot.address[i] || snapshot.mtu[i] < 68 {
			return ErrKernelApply
		}
	}
	for i, tunnel := range p.Tunnels[:p.activeTunnelCount()] {
		if snapshot.mtu[i] > uint64(ceilings[i]) {
			current, err := a.snapshotSelectionRoutes(ctx, p, true, routes)
			if err != nil || verifyDenial(ctx) != nil {
				return ErrKernelApply
			}
			for k, owned := range current.ownership[:p.activeTunnelCount()] {
				expected := snapshot.mtu[k]
				if k < i && expected > uint64(ceilings[k]) {
					expected = uint64(ceilings[k])
				}
				if owned != previous[k] || !current.address[k] || current.mtu[k] != expected {
					return ErrKernelApply
				}
			}
			if a.mutate(ctx, p, "link", "set", "dev", tunnel.Name, "mtu", strconv.FormatUint(uint64(ceilings[i]), 10)) != nil {
				return ErrKernelApply
			}
		}
	}
	after, err := a.snapshotSelectionRoutes(ctx, p, true, routes)
	if err != nil {
		return ErrKernelApply
	}
	for i, owned := range after.ownership[:p.activeTunnelCount()] {
		expected := snapshot.mtu[i]
		if expected > uint64(ceilings[i]) {
			expected = uint64(ceilings[i])
		}
		if owned != previous[i] || !after.address[i] || after.mtu[i] != expected {
			return ErrKernelApply
		}
	}
	if verifyDenial(ctx) != nil {
		return ErrKernelApply
	}
	return nil
}
