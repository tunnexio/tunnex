package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"time"
)

// proveRuntime correlates independent VICI and keyless kernel observations. It
// does not confer authority: the caller still requires a fresh exact CP lease.
func (c *RuntimeController) proveRuntime(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) (resultErr error) {
	stage := "proof_readers"
	started := time.Now()
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "runtime_proof", stage, e.Allocation.ConnectionID, started, resultErr != nil)
	}()
	xr, err := NewXFRMReader(c.config.IPPath)
	if err != nil {
		c.emitRuntimeDiagnostic(ctx, "native_proof", "native_xfrm_reader", e.Allocation.ConnectionID, started, true)
		return ErrRuntimeController
	}
	kr, err := NewKernelReader(c.config.IPPath)
	if err != nil {
		c.emitRuntimeDiagnostic(ctx, "native_proof", "native_kernel_reader", e.Allocation.ConnectionID, started, true)
		return ErrRuntimeController
	}
	resultErr = c.proveRuntimeWithIndependentReaders(ctx, e, env, runtimeStatusReaders{daemon: c.config.Daemon.Inspect, kernel: kr.Read, xfrm: xr.Read})
	if resultErr == nil {
		stage = "proof_complete"
	}
	return resultErr
}

// runtimeXFRMCoherenceRefusal is internal and contains no observed material.
// It is returned only after both complete independent ownership proofs pass.
type runtimeXFRMCoherenceRefusal struct{}

func (runtimeXFRMCoherenceRefusal) Error() string { return ErrRuntimeController.Error() }

// Reader handles carry no snapshots. Every retry rereads all native sources
// under the same caller context and requires the original equality checks.
// Real clients use separate immutable transports; injected readers stay serial.
func (c *RuntimeController) proveRuntimeWithIndependentReaders(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, r runtimeStatusReaders) error {
	r.independent = true
	return c.proveRuntimeWithReaders(ctx, e, env, r)
}

func (c *RuntimeController) proveRuntimeWithReaders(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, r runtimeStatusReaders) error {
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return ErrRuntimeController
		}
		err := c.proveRuntimeAttempt(ctx, e, env, r)
		if err == nil {
			return nil
		}
		if _, moved := err.(runtimeXFRMCoherenceRefusal); !moved || ctx.Err() != nil {
			return ErrRuntimeController
		}
	}
	return ErrRuntimeController
}

func (c *RuntimeController) proveRuntimeAttempt(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, r runtimeStatusReaders) error {
	return c.runtimeNativeObservationAttempt(ctx, e, env, r, nil)
}

// An optional status output shares only this fresh observation's inventories.
// The ordinary proof keeps its exact retry and selected-owner proof contract.
func (c *RuntimeController) runtimeNativeObservationAttempt(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, r runtimeStatusReaders, observed *[2]string) (resultErr error) {
	stage := "native_xfrm_before_read"
	started := time.Now()
	defer func() {
		if resultErr != nil {
			c.emitRuntimeDiagnostic(ctx, "native_proof", stage, e.Allocation.ConnectionID, started, true)
		}
	}()
	stage = "native_xfrm_before_read"
	before, err := r.xfrm(ctx)
	if err != nil {
		return ErrRuntimeController
	}
	stage = "native_xfrm_before_namespace"
	if before.Namespace != e.Allocation.Namespace {
		return ErrRuntimeController
	}
	stage = "native_vici_before"
	daemon, kernel, daemonErr, kernelErr := runtimeNativeDaemonKernel(ctx, r)
	if daemonErr != nil {
		return ErrRuntimeController
	}
	stage = "native_kernel_before_read"
	if kernelErr != nil {
		return ErrRuntimeController
	}
	stage = "native_kernel_before_namespace"
	if kernel.Namespace != e.Allocation.Namespace {
		return ErrRuntimeController
	}
	var statusesBefore [2]string
	proveSelected := true
	if observed != nil {
		statusesBefore = runtimeTunnelStatuses(e, daemon, kernel, before)
		for _, status := range statusesBefore[:e.Allocation.activeTunnelCount()] {
			if status != "up" && status != "down" {
				return ErrRuntimeController
			}
		}
		slot := selectedRuntimeSlot(e)
		if slot < 1 || slot > 2 {
			return ErrRuntimeController
		}
		proveSelected = statusesBefore[slot-1] == "up"
	}
	stage = "native_inventory_before"
	if proveSelected && runtimeInventoryMatches(e, daemon, kernel, before) != nil {
		return ErrRuntimeController
	}
	// Environment includes independent hook and physical route qualification.
	stage = "native_environment_observe"
	if proveSelected {
		again, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
		if err != nil {
			return ErrRuntimeController
		}
		stage = "native_environment_equal"
		if !reflect.DeepEqual(again, env) {
			return ErrRuntimeController
		}
	}
	stage = "native_xfrm_after_read"
	after, err := r.xfrm(ctx)
	if err != nil {
		return ErrRuntimeController
	}
	stage = "native_xfrm_after_equal"
	if after.Namespace != e.Allocation.Namespace || after.Namespace != before.Namespace {
		return ErrRuntimeController
	}
	moved := !reflect.DeepEqual(connectionXFRMSnapshot(e, before), connectionXFRMSnapshot(e, after))
	stage = "native_daemon_alive"
	if !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	// Reprove the requested connection against a fresh complete independent
	// snapshot; unrelated namespace changes cannot supply target ownership.
	stage = "native_vici_after"
	daemonAfter, kernelAfter, daemonErr, kernelErr := runtimeNativeDaemonKernel(ctx, r)
	if daemonErr != nil {
		return ErrRuntimeController
	}
	stage = "native_kernel_after_read"
	if kernelErr != nil {
		return ErrRuntimeController
	}
	stage = "native_kernel_after_equal"
	if !reflect.DeepEqual(connectionKernelSnapshot(e, kernel), connectionKernelSnapshot(e, kernelAfter)) {
		return ErrRuntimeController
	}
	stage = "native_inventory_after"
	if proveSelected && runtimeInventoryMatches(e, daemonAfter, kernelAfter, after) != nil {
		return ErrRuntimeController
	}
	if observed != nil {
		statusesAfter := runtimeTunnelStatuses(e, daemonAfter, kernelAfter, after)
		if statusesAfter != statusesBefore {
			return ErrRuntimeController
		}
		for _, status := range statusesAfter[:e.Allocation.activeTunnelCount()] {
			if status != "up" && status != "down" {
				return ErrRuntimeController
			}
		}
	}
	stage = "native_daemon_alive"
	if !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	stage = "native_context_final"
	if ctx.Err() != nil {
		return ErrRuntimeController
	}
	if moved {
		stage = "native_xfrm_after_equal"
		return runtimeXFRMCoherenceRefusal{}
	}
	if observed != nil {
		*observed = statusesBefore
	}
	return nil
}

// A status observation never retries incoherence into an UP report. It uses
// the same caller context and one complete before/after ownership bracket.
func (c *RuntimeController) observeAndProveRecoveryWithIndependentReaders(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, r runtimeStatusReaders) ([2]string, error) {
	r.independent = true
	return c.observeAndProveRecoveryWithReaders(ctx, e, env, r)
}

func (c *RuntimeController) observeAndProveRecoveryWithReaders(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment, r runtimeStatusReaders) ([2]string, error) {
	unknown := [2]string{"unknown", "unknown"}
	if r.daemon == nil || r.kernel == nil || r.xfrm == nil || r.alive == nil || !r.alive() || ctx.Err() != nil {
		return unknown, ErrRuntimeController
	}
	statuses := unknown
	if err := c.runtimeNativeObservationAttempt(ctx, e, env, r, &statuses); err != nil || !r.alive() || ctx.Err() != nil {
		return unknown, ErrRuntimeController
	}
	return statuses, nil
}

func runtimeInventoryMatches(e RuntimeJournalEntry, daemon DaemonInventory, kernel KernelInventory, before XFRMInventory) error {
	if e.Allocation.ProfileID == GCPClassicStaticProfile && !validClassicJournal(e) {
		return ErrRuntimeController
	}
	slot := selectedRuntimeSlot(e)
	if slot == 0 {
		return ErrRuntimeController
	}
	selected := int(slot) - 1
	for _, remote := range e.Allocation.Tunnels[0].RemotePrefixes {
		count := 0
		for _, route := range kernel.Routes {
			if route.Destination != remote {
				continue
			}
			if route.Kind != 1 || route.Table != 254 || route.Protocol != 242 || route.Metric != 50000+uint32(slot) || route.OutputInterface != e.Observed[selected].InterfaceIndex || route.Gateway.IsValid() {
				return ErrRuntimeController
			}
			count++
		}
		if count != 1 {
			return ErrRuntimeController
		}
	}
	for _, route := range kernel.Routes {
		owned := -1
		for i, o := range e.Observed[:e.Allocation.activeTunnelCount()] {
			if route.OutputInterface == o.InterfaceIndex {
				owned = i
			}
		}
		if owned < 0 {
			continue
		}
		t := e.Allocation.Tunnels[owned]
		if route.Kind == 1 {
			expected := false
			for _, p := range t.RemotePrefixes {
				if route.Destination == p {
					expected = true
				}
			}
			if owned != selected || !expected || route.Table != 254 || route.Protocol != 242 || route.Metric != 50000+uint32(slot) || route.Gateway.IsValid() {
				return ErrRuntimeController
			}
			continue
		}
		if e.Allocation.ProfileID == GCPClassicStaticProfile && route.Kind != 2 {
			return ErrRuntimeController
		}
		expected := t.InsideAddress.Addr()
		scope := uint8(254)
		if route.Kind == 3 {
			address := t.InsideAddress.Masked().Addr().As4()
			address[3] |= 3
			expected = netip.AddrFrom4(address)
			scope = 253
		} else if route.Kind != 2 {
			return ErrRuntimeController
		}
		if route.Destination != netip.PrefixFrom(expected, 32) || route.Table != 255 || route.Protocol != 2 || route.Scope != scope || route.PreferredSource != t.InsideAddress.Addr() || route.Gateway.IsValid() || route.Metric != 0 {
			return ErrRuntimeController
		}
	}
	for i, t := range e.Engines[:e.Allocation.activeTunnelCount()] {
		own := e.Observed[i]
		found := false
		for _, link := range kernel.Links {
			if link.Name == own.InterfaceName && link.Index == own.InterfaceIndex && link.XFRMID == own.XFRMID && (link.Up || (e.ContractVersion == 2 && i != selected)) {
				found = true
			}
		}
		if !found {
			return ErrRuntimeController
		}
		if e.ContractVersion == 2 {
			status := runtimeTunnelStatus(t, own, daemon, kernel, before)
			if status == "unknown" || (i == selected && status != "up") {
				return ErrRuntimeController
			}
			continue
		}
		sa, child, retired, err := ownedRuntimeChildren(t, daemon)
		if err != nil || sa == nil || !sa.Established || child == nil || !child.Installed {
			return ErrRuntimeController
		}
		in, out, err := ownedRuntimeSPIStates(t, child, retired, before)
		if err != nil || in != 1 || out != 1 {
			return ErrRuntimeController
		}
		expectedSPIIn, expectedSPIOut := child.SPIIn, child.SPIOut
		for _, p := range before.Policies {
			if p.IfID != t.XFRMID {
				if p.ReqID == t.ReqID {
					return ErrRuntimeController
				}
				continue
			}
			expectedSPI := expectedSPIIn
			if p.Direction == "out" {
				expectedSPI = expectedSPIOut
			}
			if p.TemplateSPI != 0 && p.TemplateSPI != expectedSPI {
				return ErrRuntimeController
			}
			allowed := false
			for _, l := range engineTransportPrefixes(t, true) {
				for _, r := range engineTransportPrefixes(t, false) {
					if p.ReqID == t.ReqID && (p.Direction == "out" && p.Source == l && p.Destination == r && p.TemplateSource == t.LocalAddress && p.TemplateDestination == t.RemoteAddress || (p.Direction == "in" || p.Direction == "fwd") && p.Source == r && p.Destination == l && p.TemplateSource == t.RemoteAddress && p.TemplateDestination == t.LocalAddress) {
						allowed = true
					}
				}
			}
			if !allowed {
				return ErrRuntimeController
			}
		}
		for _, local := range engineTransportPrefixes(t, true) {
			for _, remote := range engineTransportPrefixes(t, false) {
				for _, dir := range []string{"in", "fwd", "out"} {
					found := false
					for _, p := range before.Policies {
						if p.IfID != t.XFRMID || p.ReqID != t.ReqID || p.Direction != dir {
							continue
						}
						src, dst, outerSrc, outerDst := remote, local, t.RemoteAddress, t.LocalAddress
						if dir == "out" {
							src, dst, outerSrc, outerDst = local, remote, t.LocalAddress, t.RemoteAddress
						}
						if p.Source == src && p.Destination == dst && p.TemplateSource == outerSrc && p.TemplateDestination == outerDst {
							found = true
						}
					}
					if !found {
						return ErrRuntimeController
					}
				}
			}
		}
	}

	return nil
}

func runtimeObjectsAbsent(e RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory) bool {
	if e.Allocation.ProfileID == GCPClassicStaticProfile && !validClassicJournal(e) {
		return false
	}
	if k.Namespace != e.Allocation.Namespace || x.Namespace != e.Allocation.Namespace {
		return false
	}
	for _, route := range k.Routes {
		if route.Protocol != 242 && route.Metric != 50001 && route.Metric != 50002 {
			continue
		}
		for _, remote := range e.Engines[0].RemotePrefixes {
			if route.Destination.Overlaps(remote) {
				return false
			}
		}
	}
	for i, t := range e.Engines[:e.Allocation.activeTunnelCount()] {
		name := engineName(t)
		if containsString(d.Connections, name) || containsString(d.SharedKeys, name) {
			return false
		}
		for _, sa := range d.SAs {
			if sa.Name == name {
				return false
			}
			for _, child := range sa.Children {
				if child.Name == name || child.ReqID == t.ReqID || child.IfIDIn == t.XFRMID || child.IfIDOut == t.XFRMID {
					return false
				}
			}
		}
		for _, link := range k.Links {
			if link.Name == e.Allocation.Tunnels[i].Name || link.XFRMID == t.XFRMID {
				return false
			}
		}
		for _, state := range x.States {
			if state.IfID == t.XFRMID || state.ReqID == t.ReqID {
				return false
			}
		}
		for _, policy := range x.Policies {
			if policy.IfID == t.XFRMID || policy.ReqID == t.ReqID {
				return false
			}
		}
	}
	return true
}
func (c *RuntimeController) proveAbsent(ctx context.Context, e RuntimeJournalEntry) error {
	xr, err := NewXFRMReader(c.config.IPPath)
	if err != nil {
		return ErrRuntimeController
	}
	kr, err := NewKernelReader(c.config.IPPath)
	if err != nil {
		return ErrRuntimeController
	}
	// Repeat complete independent inventories. Names/derived IDs can refuse
	// absence; they never justify deleting an unjournaled object.
	for pass := 0; pass < 2; pass++ {
		d, err := c.config.Daemon.Inspect(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		k, err := kr.Read(ctx)
		if err != nil {
			return ErrRuntimeController
		}
		x, err := xr.Read(ctx)
		if err != nil || !runtimeObjectsAbsent(e, d, k, x) {
			return ErrRuntimeController
		}
	}
	if !c.config.DaemonAlive() || ctx.Err() != nil {
		return ErrRuntimeController
	}
	return nil
}
