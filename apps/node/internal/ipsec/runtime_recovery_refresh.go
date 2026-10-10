package ipsec

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
)

// recoveryGuardDenied is a read-only denial proof, not a permit or cleanup
// receipt. Prior template subset matching alone allows live members; all three
// exact target sets must independently exist and be empty.
func (c *RuntimeController) recoveryGuardDenial(ctx context.Context, entry RuntimeJournalEntry) (bool, error) {
	denied, err := c.recoveryGuardDenials(ctx, []RuntimeJournalEntry{entry})
	return denied[entry.Allocation.ConnectionID], err
}

// All candidate sets are part of the same fully verified table snapshot. Reading
// that table once bounds inactive observation cost independently of provider count.
// Each candidate still needs all three exact empty sets and the final target proof.
func (c *RuntimeController) recoveryGuardDenials(ctx context.Context, entries []RuntimeJournalEntry) (map[uuid.UUID]bool, error) {
	if c.guard == nil || c.guard.reader == nil || c.journal == nil || c.guard.reader.run == nil || c.guard.reader.namespace == nil || c.guard.reader.interfaces == nil {
		return nil, ErrGuardReadback
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := c.guard.reader
	if len(entries) == 0 {
		return nil, ErrGuardReadback
	}
	expectedNS := entries[0].Allocation.Namespace
	names := map[string]uuid.UUID{}
	found := map[string]bool{}
	denied := map[uuid.UUID]bool{}
	for _, entry := range entries {
		id := entry.Allocation.ConnectionID
		if id == uuid.Nil || entry.Allocation.Namespace != expectedNS {
			return nil, ErrGuardReadback
		}
		if _, exists := denied[id]; exists {
			return nil, ErrGuardReadback
		}
		denied[id] = true
		for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
			if _, exists := names[name]; exists {
				return nil, ErrGuardReadback
			}
			names[name] = id
		}
	}
	before, e := r.namespace()
	if e != nil || before != expectedNS {
		return nil, ErrGuardReadback
	}
	links, e := r.interfaces()
	if e != nil {
		return nil, ErrGuardReadback
	}
	raw, e := r.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
	if e != nil || ctx.Err() != nil {
		return nil, ErrGuardReadback
	}
	templates, _, e := c.journal.guardTemplates()
	if e != nil || len(templates) != 1 {
		return nil, ErrGuardReadback
	}
	matched := false
	for _, g := range templates {
		if g.Namespace == before && VerifyGuardWithdrawal([]byte(g.ExpectedJSON), raw, links) == nil {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrGuardReadback
	}
	mapping := map[string]int{}
	for _, l := range links {
		mapping[l.Name] = l.Index
	}
	objects, ok := normalizedGuardObjectsWithInterfaces(raw, mapping)
	if !ok {
		return nil, ErrGuardReadback
	}
	for _, v := range objects {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, ErrGuardReadback
		}
		s, ok := obj["set"].(map[string]any)
		if !ok {
			continue
		}
		name, ok := s["name"].(string)
		if !ok {
			return nil, ErrGuardReadback
		}
		if id, wanted := names[name]; wanted {
			if found[name] {
				return nil, ErrGuardReadback
			}
			elems, exists := s["elem"]
			if exists {
				items, ok := elems.([]any)
				if !ok {
					return nil, ErrGuardReadback
				}
				if len(items) != 0 {
					denied[id] = false
				}
			}
			found[name] = true
		}
	}
	for name := range names {
		if !found[name] {
			return nil, ErrGuardReadback
		}
	}
	afterLinks, e := r.interfaces()
	if e != nil {
		return nil, ErrGuardReadback
	}
	after, e := r.namespace()
	if e != nil || after != before || ctx.Err() != nil {
		return nil, ErrGuardReadback
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Index < links[j].Index })
	sort.Slice(afterLinks, func(i, j int) bool { return afterLinks[i].Index < afterLinks[j].Index })
	if !reflect.DeepEqual(links, afterLinks) {
		return nil, ErrGuardReadback
	}
	return denied, nil
}

func (c *RuntimeController) recoveryGuardDenied(ctx context.Context, entry RuntimeJournalEntry) bool {
	denied, err := c.recoveryGuardDenial(ctx, entry)
	return err == nil && denied
}

// RefreshIPsecRecovery advances inactive recovery evidence only. The serial
// runtime owner invokes this between items; no material, secret, grant, route or
// permission is retained or installed. Fresh CP nonce authority must still
// agree with the existing epoch, and current target denial is proved twice.
func (c *RuntimeController) RefreshIPsecRecovery(ctx context.Context) error {
	if c == nil {
		return ErrRuntimeController
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || !c.started || c.closed || c.journal == nil || c.client == nil || c.config.Environment == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() {
		c.recoveryHistory = nil
		return ErrRuntimeController
	}
	entries, e := c.journal.Entries()
	if e != nil {
		c.recoveryHistory = nil
		return ErrRuntimeController
	}
	callbackStarted := c.recoveryNow()
	now := callbackStarted
	var chosen *RuntimeJournalEntry
	var history *recoveryDecision
	eligible := make([]RuntimeJournalEntry, 0, len(entries))
	for i := range entries {
		entry := &entries[i]
		h := c.recoveryHistory[entry.Allocation.ConnectionID]
		if h == nil || !h.seen {
			continue
		}
		if entry.Phase != RuntimeApplied || entry.ContractVersion != 2 || entry.AbsenceOnly || !validJournalRecovery(*entry) || entry.Recovery.Stage != "completed" {
			delete(c.recoveryHistory, entry.Allocation.ConnectionID)
			continue
		}
		epoch := recoveryEpoch{Binding: entry.Engines[0].Binding, PolicyHash: h.epoch.PolicyHash, DeliveryID: entry.DeliveryID, Namespace: entry.Allocation.Namespace, Tunnels: [2]uuid.UUID{entry.Engines[0].TunnelID, entry.Engines[1].TunnelID}}
		if entry.Engines[0].Binding.OrgID != c.config.OrgID || entry.Engines[0].Binding.GatewayID != c.config.GatewayID || !validRecoveryEpoch(epoch) || epoch != h.epoch || h.current != selectedRuntimeSlot(*entry) || now < h.lastNow {
			delete(c.recoveryHistory, entry.Allocation.ConnectionID)
			continue
		}
		if now-h.lastNow < 5*time.Second {
			continue
		}
		eligible = append(eligible, *entry)
	}
	if len(eligible) == 0 {
		return nil
	}
	denied, err := c.recoveryGuardDenials(ctx, eligible)
	if err != nil {
		for _, entry := range eligible {
			delete(c.recoveryHistory, entry.Allocation.ConnectionID)
		}
		return ErrRuntimeController
	}
	for i := range eligible {
		entry := &eligible[i]
		h := c.recoveryHistory[entry.Allocation.ConnectionID]
		if !denied[entry.Allocation.ConnectionID] {
			continue
		}
		if chosen == nil || h.lastNow < history.lastNow {
			chosen = entry
			history = h
		}
	}
	if ctx.Err() != nil {
		c.recoveryHistory = nil
		return ErrRuntimeController
	}
	if chosen == nil {
		return nil
	}
	entry := *chosen
	id := entry.Allocation.ConnectionID
	fail := func() error { delete(c.recoveryHistory, id); return ErrRuntimeController }
	ns, e := c.namespace()
	if e != nil || ns != entry.Allocation.Namespace {
		return fail()
	}
	prepared, ok := c.recoveryPrepared[entry.DeliveryID]
	if !ok {
		return fail()
	}
	env, e := c.config.Environment.Observe(ctx, entry.Allocation, entry.Engines)
	if e != nil || !reflect.DeepEqual(env, prepared) {
		return fail()
	}
	// The fully verified initial snapshot independently proved exact target denial.
	authority, identity, e := c.recoveryLease(ctx, entry, history.epoch.PolicyHash)
	if e != nil {
		return fail()
	}
	if _, e = authority.RemainingForApply(identity, 5*time.Second); e != nil {
		return fail()
	}
	started := c.recoveryNow()
	statuses := c.observeRecovery(ctx, entry)
	ended := c.recoveryNow()
	if ctx.Err() != nil || ended < started || ended-started > 5*time.Second || (statuses[0] != "up" && statuses[0] != "down") || (statuses[1] != "up" && statuses[1] != "down") || !c.config.DaemonAlive() || !c.qualification.current() {
		return fail()
	}
	if !c.recoveryGuardDenied(ctx, entry) {
		return fail()
	}
	after, e := c.config.Environment.Observe(ctx, entry.Allocation, entry.Engines)
	if e != nil || !reflect.DeepEqual(after, env) || ctx.Err() != nil {
		return fail()
	}
	if _, e = authority.RemainingForApply(identity, 5*time.Second); e != nil {
		return fail()
	}
	current, e := c.journal.Entries()
	if e != nil {
		return fail()
	}
	found := false
	for _, v := range current {
		if v.DeliveryID == entry.DeliveryID {
			if found || !reflect.DeepEqual(v, entry) {
				return fail()
			}
			found = true
		}
	}
	if !found {
		return fail()
	}
	afterNS, e := c.namespace()
	if e != nil || afterNS != ns || !c.config.DaemonAlive() || !c.qualification.current() || ctx.Err() != nil {
		return fail()
	}
	final := c.recoveryNow()
	if final < started || final-started > 5*time.Second || final < callbackStarted || final-callbackStarted > 5*time.Second {
		return fail()
	}
	history.observe(history.epoch, final, recoveryObservation{Epoch: history.epoch, Current: selectedRuntimeSlot(entry), Status: statuses, Authorized: true, At: started})
	return nil
}
