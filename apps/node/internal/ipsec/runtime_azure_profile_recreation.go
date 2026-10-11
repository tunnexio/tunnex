package ipsec

import (
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"sort"
)

// Each side retains its own independently valid cardinality/transport contract.
// Only shared outside slots can coalesce; removed allocations are never adopted.
func sameAzureProfileRecreationDomain(a, b RuntimeJournalEntry) bool {
	if a.AzureProfileRecreationVersion != 1 || !IsAzureRuntimeProfile(a.Allocation.ProfileID) || !IsAzureRuntimeProfile(b.Allocation.ProfileID) || !validKernelAllocation(a.Allocation) || !validKernelAllocation(b.Allocation) || !validClassicJournal(a) || !validClassicJournal(b) || !validJournalBGP(a) || !validJournalBGP(b) {
		return false
	}
	x, y := a.Engines[0].Binding, b.Engines[0].Binding
	if a.SiteID != b.SiteID || x.OrgID != y.OrgID || x.GatewayID != y.GatewayID || !exactHandoffPrefixes(a.Engines[0].LocalPrefixes, b.Engines[0].LocalPrefixes) || !sharedDisjointRemote(a.Engines[0].RemotePrefixes, b.Engines[0].RemotePrefixes) {
		return false
	}
	if a.BGP != nil && b.BGP != nil {
		ac, bc := *a.BGP, *b.BGP
		ac.MaximumPrefixes = 0
		bc.MaximumPrefixes = 0
		if ac != bc {
			return false
		}
	}
	n := a.Allocation.activeTunnelCount()
	if b.Allocation.activeTunnelCount() < n {
		n = b.Allocation.activeTunnelCount()
	}
	for i := 0; i < n; i++ {
		at, bt := a.Engines[i], b.Engines[i]
		if at.LocalAddress != bt.LocalAddress || at.LocalIdentity != bt.LocalIdentity || at.RemoteIdentity != bt.RemoteIdentity || at.RemoteAddress != bt.RemoteAddress {
			return false
		}
		if IsAzureBGPProfile(a.Allocation.ProfileID) == IsAzureBGPProfile(b.Allocation.ProfileID) {
			ak, bk := a.Allocation.Tunnels[i], b.Allocation.Tunnels[i]
			if ak.InsideAddress != bk.InsideAddress || !reflect.DeepEqual(ak.BGP, bk.BGP) {
				return false
			}
		}
	}
	return true
}
func (c *RuntimeController) AzureProfileRecreationCapability() int {
	if c == nil || c.AzureCapability() != 1 || c.BGPCapability() != 1 || c.RetainedGuardCapability() != 1 {
		return 0
	}
	return 1
}

// Hidden predecessor transports retain explicit refusal only. A shared exact
// successor tuple is independently authorized; a removed tuple is never hidden.
func retainedAzureTransportRefusals(entries, projected []RuntimeJournalEntry, retired []uuid.UUID) []netip.Prefix {
	hidden := map[uuid.UUID]bool{}
	for _, id := range retired {
		hidden[id] = true
	}
	cross := false
	for _, e := range projected {
		cross = cross || e.AzureProfileRecreationVersion == 1
	}
	if !cross {
		return nil
	}
	live := map[netip.Addr]bool{}
	for _, e := range projected {
		for i := 0; i < e.Allocation.activeTunnelCount(); i++ {
			live[e.Engines[i].RemoteAddress] = true
			live[e.Allocation.Tunnels[i].InsideAddress.Addr()] = true
			if e.Allocation.Tunnels[i].BGP != nil {
				live[e.Allocation.Tunnels[i].BGP.Peer] = true
			}
		}
	}
	seen := map[netip.Prefix]bool{}
	for _, e := range entries {
		if !hidden[e.Allocation.ConnectionID] || !IsAzureRuntimeProfile(e.Allocation.ProfileID) {
			continue
		}
		for i := 0; i < e.Allocation.activeTunnelCount(); i++ {
			addresses := []netip.Addr{e.Engines[i].RemoteAddress, e.Allocation.Tunnels[i].InsideAddress.Addr()}
			if e.Allocation.Tunnels[i].BGP != nil {
				addresses = append(addresses, e.Allocation.Tunnels[i].BGP.Peer)
			}
			for _, a := range addresses {
				if a.Is4() && !live[a] {
					seen[netip.PrefixFrom(a, 32)] = true
				}
			}
		}
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
