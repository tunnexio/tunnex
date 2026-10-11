package ipsec

import (
	"context"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"sort"
)

func validAzureRecreationManifest(m RuntimeManifest) bool {
	if m.AzureProfileRecreationVersion != nil {
		return *m.AzureProfileRecreationVersion == 1 && m.AzureBGPRecreationVersion == nil && IsAzureRuntimeProfile(m.ProfileID) && len(m.RetainedGuardPredecessors) > 0
	}
	if m.AzureBGPRecreationVersion == nil {
		return true
	}
	return *m.AzureBGPRecreationVersion == 1 && m.ProfileID == AzureActiveActiveBGPProfile && len(m.RetainedGuardPredecessors) > 0
}
func validAzureRecreationEntry(e RuntimeJournalEntry) bool {
	if e.AzureProfileRecreationVersion != 0 {
		return e.AzureProfileRecreationVersion == 1 && e.AzureBGPRecreationVersion == 0 && IsAzureRuntimeProfile(e.Allocation.ProfileID) && len(e.RetainedGuardPredecessors) > 0 && validClassicJournal(e) && validJournalBGP(e)
	}
	return e.AzureBGPRecreationVersion == 0 || e.AzureBGPRecreationVersion == 1 && e.Allocation.ProfileID == AzureActiveActiveBGPProfile && e.ContractVersion == 3 && e.BGP != nil && len(e.RetainedGuardPredecessors) > 0
}
func sharedDisjointRemote(a, b []netip.Prefix) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	shared := false
	for _, p := range a {
		if !validGuardPrefix(p) {
			return false
		}
		for _, q := range b {
			if !validGuardPrefix(q) || p != q && p.Overlaps(q) {
				return false
			}
			shared = shared || p == q
		}
	}
	return shared
}
func sameAzureBGPRecreationDomain(a, b RuntimeJournalEntry) bool {
	if a.ContractVersion != 3 || b.ContractVersion != 3 || a.Allocation.ProfileID != AzureActiveActiveBGPProfile || b.Allocation.ProfileID != a.Allocation.ProfileID || a.Allocation.activeTunnelCount() != 2 || b.Allocation.activeTunnelCount() != 2 || !validJournalBGP(a) || !validJournalBGP(b) {
		return false
	}
	x, y := a.Engines[0].Binding, b.Engines[0].Binding
	if a.SiteID != b.SiteID || x.OrgID != y.OrgID || x.GatewayID != y.GatewayID || !exactHandoffPrefixes(a.Engines[0].LocalPrefixes, b.Engines[0].LocalPrefixes) || !sharedDisjointRemote(a.Engines[0].RemotePrefixes, b.Engines[0].RemotePrefixes) {
		return false
	}
	ac, bc := *a.BGP, *b.BGP
	ac.MaximumPrefixes = 0
	bc.MaximumPrefixes = 0
	if ac != bc {
		return false
	}
	for i := 0; i < 2; i++ {
		at, bt := a.Engines[i], b.Engines[i]
		ak, bk := a.Allocation.Tunnels[i], b.Allocation.Tunnels[i]
		if !exactHandoffPrefixes(at.LocalPrefixes, a.Engines[0].LocalPrefixes) || !exactHandoffPrefixes(bt.LocalPrefixes, b.Engines[0].LocalPrefixes) || !exactHandoffPrefixes(at.RemotePrefixes, a.Engines[0].RemotePrefixes) || !exactHandoffPrefixes(bt.RemotePrefixes, b.Engines[0].RemotePrefixes) || at.LocalIdentity != bt.LocalIdentity || at.RemoteIdentity != bt.RemoteIdentity || at.RemoteAddress != bt.RemoteAddress || ak.InsideAddress != bk.InsideAddress || !reflect.DeepEqual(ak.BGP, bk.BGP) {
			return false
		}
	}
	return true
}

// Derived denial only: historical entries and successor material remain exact.
// A disjoint former allowlist remains permanently refused after contraction.
func retainedRefusalPrefixes(entries, projected []RuntimeJournalEntry, retired []uuid.UUID) []netip.Prefix {
	hidden := map[uuid.UUID]bool{}
	for _, id := range retired {
		hidden[id] = true
	}
	seen := map[netip.Prefix]bool{}
	for _, old := range entries {
		if !hidden[old.Allocation.ConnectionID] || !IsAzureRuntimeProfile(old.Allocation.ProfileID) {
			continue
		}
		for _, p := range old.Engines[0].RemotePrefixes {
			covered := false
			for _, current := range projected {
				for _, q := range current.Engines[0].RemotePrefixes {
					covered = covered || p == q
				}
			}
			if !covered {
				seen[p] = true
			}
		}
	}
	for _, p := range retainedAzureTransportRefusals(entries, projected, retired) {
		seen[p] = true
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
func (c *RuntimeController) AzureBGPRecreationCapability() int {
	if c == nil {
		return 0
	}
	if c.BGPCapability() != 1 || c.RetainedGuardCapability() != 1 {
		return 0
	}
	return 1
}
func (c *RuntimeController) proveAzureBGPPredecessorAbsent(ctx context.Context, e RuntimeJournalEntry) error {
	return c.proveAzureBGPDutiesAbsent(ctx, e)
}
