package ipsec

import (
	"context"
	"net/netip"
	"sort"

	"github.com/google/uuid"
)

// Handoff references are ownership-hashed CP material, never customer grants.
// Deleted predecessor entries stay immutable. A successor replaces their exact
// refusal obligation only, and must obtain its own fresh lease and native proof.
func validRetainedGuardReferences(refs []RuntimeRetainedGuardPredecessor, connection, delivery uuid.UUID, bgp bool) bool {
	if len(refs) > 256 || (bgp && len(refs) > 0) {
		return false
	}
	prior := ""
	for _, ref := range refs {
		id := ref.DeliveryID.String()
		if ref.ConnectionID == uuid.Nil || ref.ConnectionID == connection || ref.DeliveryID == uuid.Nil || ref.DeliveryID == delivery || ref.CleanupDeliveryID == uuid.Nil || ref.CleanupDeliveryID == ref.DeliveryID || !validDigest(ref.OwnershipDigest) || (prior != "" && prior >= id) {
			return false
		}
		prior = id
	}
	return true
}
func exactHandoffPrefixes(a, b []netip.Prefix) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range a {
		if !validGuardPrefix(p) || seen[p] {
			return false
		}
		seen[p] = true
	}
	for _, p := range b {
		if !seen[p] {
			return false
		}
		delete(seen, p)
	}
	return len(seen) == 0
}
func sameHandoffDomain(a, b RuntimeJournalEntry) bool {
	x, y := a.Engines[0].Binding, b.Engines[0].Binding
	for _, e := range []RuntimeJournalEntry{a, b} {
		if e.Allocation.activeTunnelCount() == 2 && (!exactHandoffPrefixes(e.Engines[0].LocalPrefixes, e.Engines[1].LocalPrefixes) || !exactHandoffPrefixes(e.Engines[0].RemotePrefixes, e.Engines[1].RemotePrefixes)) {
			return false
		}
	}
	return a.ContractVersion != 3 && b.ContractVersion != 3 && a.BGP == nil && b.BGP == nil && a.SiteID == b.SiteID && x.OrgID == y.OrgID && x.GatewayID == y.GatewayID && exactHandoffPrefixes(a.Engines[0].LocalPrefixes, b.Engines[0].LocalPrefixes) && exactHandoffPrefixes(a.Engines[0].RemotePrefixes, b.Engines[0].RemotePrefixes)
}
func validRetainedGuardJournal(entries []RuntimeJournalEntry) bool {
	byID := map[uuid.UUID]RuntimeJournalEntry{}
	for _, e := range entries {
		byID[e.DeliveryID] = e
	}
	for _, e := range entries {
		if !validRetainedGuardReferences(e.RetainedGuardPredecessors, e.Allocation.ConnectionID, e.DeliveryID, e.ContractVersion == 3 || e.BGP != nil) {
			return false
		}
		refs := map[uuid.UUID]bool{}
		targets := map[uuid.UUID]bool{}
		for _, r := range e.RetainedGuardPredecessors {
			old, ok := byID[r.DeliveryID]
			if !ok || old.Phase != RuntimeRetainedRefusal || old.Allocation.ConnectionID != r.ConnectionID || old.CleanupID != r.CleanupDeliveryID || old.OwnershipDigest != r.OwnershipDigest || !sameHandoffDomain(e, old) {
				return false
			}
			refs[r.DeliveryID] = true
			targets[r.ConnectionID] = true
		}
		// All potentially installed lineage of a predecessor must be cleaned and
		// referenced. A partial list cannot conceal an uncleaned native obligation.
		for _, old := range entries {
			if targets[old.Allocation.ConnectionID] && (!refs[old.DeliveryID] || old.Phase != RuntimeRetainedRefusal) {
				return false
			}
		}
	}
	// Even a correctly checksummed hostile journal cannot form a cycle.
	state := map[uuid.UUID]int{}
	var visit func(uuid.UUID) bool
	visit = func(id uuid.UUID) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		state[id] = 1
		for _, r := range byID[id].RetainedGuardPredecessors {
			if !visit(r.DeliveryID) {
				return false
			}
		}
		state[id] = 2
		return true
	}
	for id := range byID {
		if !visit(id) {
			return false
		}
	}
	return true
}
func runtimeGuardProjection(entries []RuntimeJournalEntry) ([]RuntimeJournalEntry, []uuid.UUID, error) {
	if !validRetainedGuardJournal(entries) {
		return nil, nil, ErrRuntimeController
	}
	hidden := map[uuid.UUID]bool{}
	for _, e := range entries {
		for _, r := range e.RetainedGuardPredecessors {
			hidden[r.ConnectionID] = true
		}
	}
	var result []RuntimeJournalEntry
	for _, e := range entries {
		if !hidden[e.Allocation.ConnectionID] {
			result = append(result, e)
		}
	}
	for i, a := range result {
		for j := 0; j < i; j++ {
			b := result[j]
			if a.Allocation.ConnectionID == b.Allocation.ConnectionID {
				continue
			}
			for _, p := range a.Engines[0].RemotePrefixes {
				for _, q := range b.Engines[0].RemotePrefixes {
					if p.Overlaps(q) {
						return nil, nil, ErrRuntimeController
					}
				}
			}
		}
	}
	// The ordinary renderer still rejects ambiguous or partial overlap. Only the
	// exact persisted predecessor references can suppress duplicate refusals.
	retained := make([]uuid.UUID, 0, len(hidden))
	for id := range hidden {
		retained = append(retained, id)
	}
	sort.Slice(retained, func(i, j int) bool { return retained[i].String() < retained[j].String() })
	return result, retained, nil
}
func (c *RuntimeController) admitRetainedGuardHandoff(ctx context.Context, entries []RuntimeJournalEntry, successor RuntimeJournalEntry) error {
	proposed := append(append([]RuntimeJournalEntry(nil), entries...), successor)
	if _, _, err := runtimeGuardProjection(proposed); err != nil {
		return ErrRuntimeController
	}
	if len(successor.RetainedGuardPredecessors) == 0 {
		return nil
	}
	ns, err := c.namespace()
	if err != nil {
		return ErrRuntimeController
	}
	byID := map[uuid.UUID]RuntimeJournalEntry{}
	for _, e := range entries {
		byID[e.DeliveryID] = e
	}
	for _, ref := range successor.RetainedGuardPredecessors {
		old := byID[ref.DeliveryID]
		// Cleaned historical namespace proof never authorizes object adoption.
		// Inspect current exact IDs, names, aliases, inside addresses and all SA/routes.
		old.Allocation.Namespace = ns
		if c.proveAbsent(ctx, old) != nil {
			return ErrRuntimeController
		}
		for pass := 0; pass < 2; pass++ {
			links, e := runKernelCommand(ctx, c.config.IPPath, "-j", "-d", "-N", "link", "show")
			if e != nil {
				return ErrRuntimeController
			}
			addresses, e := runKernelCommand(ctx, c.config.IPPath, "-j", "-N", "-4", "address", "show")
			if e != nil || !resetExtraObjectsAbsent(old, links, addresses) {
				return ErrRuntimeController
			}
		}
	}
	if ctx.Err() != nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() {
		return ErrRuntimeController
	}
	return nil
}
func guardLeaseConnections(in GuardIntent) []GuardConnection {
	out := append([]GuardConnection(nil), in.Connections...)
	for _, id := range in.RetainedLeaseIDs {
		out = append(out, GuardConnection{ID: id})
	}
	return out
}

// RetainedGuardCapability is implemented by this exact runtime and requires the
// same current native qualification as ordinary IPsec activation.
func (c *RuntimeController) RetainedGuardCapability() int {
	if c == nil {
		return 0
	}
	return c.Capability()
}
