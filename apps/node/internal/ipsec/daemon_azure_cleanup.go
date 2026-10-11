package ipsec

import (
	"context"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
)

// This negative-only seam is called by normal Cleanup after verified denial.
// Persisted allocation supplies exact inside addresses; no observed selector
// can authorize native Up, material adoption, or a new permit.
func (c *DaemonClient) removeAzureCleanupTunnel(ctx context.Context, entry RuntimeJournalEntry, slot int, namespace string) error {
	// The legacy detached wrapper intentionally cannot validate predecessor refs.
	return c.removeAzureCleanupTunnelJournal(ctx, entry, slot, namespace, runtimeJournalPayload{Version: 10, OwnerID: entry.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{entry}})
}

func (c *DaemonClient) removeAzureCleanupTunnelJournal(ctx context.Context, entry RuntimeJournalEntry, slot int, namespace string, journal runtimeJournalPayload) error {
	if ctx.Err() != nil || entry.Phase != RuntimeCleanupPending || entry.AbsenceOnly || entry.ContractVersion != 3 || !IsAzureBGPProfile(entry.Allocation.ProfileID) || namespace != entry.Allocation.Namespace || !validKernelAllocation(entry.Allocation) || !validJournalBGP(entry) || slot < 0 || slot >= entry.Allocation.activeTunnelCount() || journal.OwnerID != entry.Engines[0].Binding.GatewayID || !validJournalPayload(journal) {
		return ErrDaemonProtocol
	}
	found := false
	for _, current := range journal.Entries {
		if current.DeliveryID == entry.DeliveryID {
			if !reflect.DeepEqual(current, entry) {
				return ErrDaemonProtocol
			}
			found = true
		}
	}
	if !found {
		return ErrDaemonProtocol
	}
	return c.removeAzureNegativeTunnel(ctx, entry, slot)
}

// Only the controller's verified-denial Applied warm-stop path calls this.
// No cleanup ID, revision or receipt is manufactured.
func (c *DaemonClient) removeAzureQuiesceTunnel(ctx context.Context, entry RuntimeJournalEntry, slot int, namespace, boot string) error {
	if entry.Phase != RuntimeApplied || !IsAzureBGPProfile(entry.Allocation.ProfileID) || !validQuiescedEntry(entry) || !validKernelAllocation(entry.Allocation) || namespace != entry.Allocation.Namespace || boot != entry.Restoration.BootID || !validBootID(boot) || slot < 0 || slot >= entry.Allocation.activeTunnelCount() || entry.CleanupID != uuid.Nil || entry.CleanupDesiredRevision != 0 || entry.CoveredDeliveryRevision != 0 {
		return ErrDaemonProtocol
	}
	return c.removeAzureNegativeTunnel(ctx, entry, slot)
}

func (c *DaemonClient) removeAzureNegativeTunnel(ctx context.Context, entry RuntimeJournalEntry, slot int) error {
	t := entry.Engines[slot]
	allocation := entry.Allocation.Tunnels[slot]
	if t.ProfileID != entry.Allocation.ProfileID || !validEngineTunnel(t) || t.Binding != entry.Engines[0].Binding || t.Binding.ConnectionID != entry.Allocation.ConnectionID || !sameEnginePrefixes(t.RemotePrefixes, allocation.RemotePrefixes) || !t.BGP || t.ReqID == 0 || t.TunnelID != allocation.TunnelID || t.XFRMID != allocation.XFRMID || allocation.BGP == nil {
		return ErrDaemonProtocol
	}
	local := append([]netip.Prefix(nil), t.LocalPrefixes...)
	remote := append([]netip.Prefix(nil), t.RemotePrefixes...)
	local = append(local, netip.PrefixFrom(allocation.InsideAddress.Addr(), 32))
	remote = append(remote, netip.PrefixFrom(allocation.BGP.Peer, 32))
	return c.removeTunnelSelectors(ctx, t, func(child DaemonChild) bool {
		return azureCleanupSelectors(child.LocalPrefixes, local) && azureCleanupSelectors(child.RemotePrefixes, remote)
	})
}

func azureCleanupSelectors(observed, approved []netip.Prefix) bool {
	if len(observed) == 0 || len(observed) > 64 {
		return false
	}
	wide := netip.MustParsePrefix("0.0.0.0/0")
	if len(observed) == 1 && observed[0] == wide {
		return true
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range observed {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 || seen[p] {
			return false
		}
		seen[p] = true
		contained := false
		for _, a := range approved {
			if a.IsValid() && a.Addr().Is4() && a == a.Masked() && a.Bits() > 0 && p.Bits() >= a.Bits() && a.Contains(p.Addr()) {
				contained = true
			}
		}
		if !contained {
			return false
		}
	}
	return true
}
