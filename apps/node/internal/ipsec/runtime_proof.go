package ipsec

import (
	"context"
	"net/netip"
	"reflect"
)

// proveRuntime correlates independent VICI and keyless kernel observations. It
// does not confer authority: the caller still requires a fresh exact CP lease.
func (c *RuntimeController) proveRuntime(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
	xr, err := NewXFRMReader(c.config.IPPath)
	if err != nil {
		return ErrRuntimeController
	}
	kr, err := NewKernelReader(c.config.IPPath)
	if err != nil {
		return ErrRuntimeController
	}
	before, err := xr.Read(ctx)
	if err != nil || before.Namespace != e.Allocation.Namespace {
		return ErrRuntimeController
	}
	daemon, err := c.config.Daemon.Inspect(ctx)
	if err != nil {
		return ErrRuntimeController
	}
	kernel, err := kr.Read(ctx)
	if err != nil || kernel.Namespace != e.Allocation.Namespace {
		return ErrRuntimeController
	}
	if runtimeInventoryMatches(e, daemon, kernel, before) != nil {
		return ErrRuntimeController
	}
	// Environment includes independent hook and physical route qualification.
	again, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil || !reflect.DeepEqual(again, env) {
		return ErrRuntimeController
	}
	after, err := xr.Read(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	return nil
}

func runtimeInventoryMatches(e RuntimeJournalEntry, daemon DaemonInventory, kernel KernelInventory, before XFRMInventory) error {
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
		for i, o := range e.Observed {
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
	for i, t := range e.Engines {
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
		matches := 0
		var expectedSPIIn, expectedSPIOut uint32
		for _, sa := range daemon.SAs {
			if sa.Name != engineName(t) {
				continue
			}
			if !sa.Established || sa.LocalAddress != t.LocalAddress || sa.RemoteAddress != t.RemoteAddress {
				return ErrRuntimeController
			}
			for _, child := range sa.Children {
				if child.Name != engineName(t) || !child.Installed || child.ReqID != t.ReqID || child.IfIDIn != t.XFRMID || child.IfIDOut != t.XFRMID || !sameEnginePrefixes(child.LocalPrefixes, t.LocalPrefixes) || !sameEnginePrefixes(child.RemotePrefixes, t.RemotePrefixes) {
					return ErrRuntimeController
				}
				in, out := false, false
				for _, state := range before.States {
					if state.IfID != t.XFRMID {
						if state.ReqID == t.ReqID {
							return ErrRuntimeController
						}
						continue
					}
					if state.ReqID != t.ReqID {
						return ErrRuntimeController
					}
					if state.Source == t.LocalAddress && state.Destination == t.RemoteAddress && state.SPI == child.SPIOut && (state.Direction == "" || state.Direction == "out") {
						out = true
					} else if state.Source == t.RemoteAddress && state.Destination == t.LocalAddress && state.SPI == child.SPIIn && (state.Direction == "" || state.Direction == "in") {
						in = true
					} else {
						return ErrRuntimeController
					}
				}
				if !in || !out {
					return ErrRuntimeController
				}
				expectedSPIIn, expectedSPIOut = child.SPIIn, child.SPIOut
				matches++
			}
		}
		if matches != 1 {
			return ErrRuntimeController
		}
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
			for _, l := range t.LocalPrefixes {
				for _, r := range t.RemotePrefixes {
					if p.ReqID == t.ReqID && (p.Direction == "out" && p.Source == l && p.Destination == r && p.TemplateSource == t.LocalAddress && p.TemplateDestination == t.RemoteAddress || (p.Direction == "in" || p.Direction == "fwd") && p.Source == r && p.Destination == l && p.TemplateSource == t.RemoteAddress && p.TemplateDestination == t.LocalAddress) {
						allowed = true
					}
				}
			}
			if !allowed {
				return ErrRuntimeController
			}
		}
		for _, local := range t.LocalPrefixes {
			for _, remote := range t.RemotePrefixes {
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
	for i, t := range e.Engines {
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
