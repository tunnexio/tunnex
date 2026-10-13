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
func (c *RuntimeController) recoveryGuardDenials(ctx context.Context, entries []RuntimeJournalEntry) (denialResult map[uuid.UUID]bool, resultErr error) {
	stage := "input"
	startedDiagnostic := time.Now()
	connection := uuid.Nil
	if len(entries) == 1 {
		connection = entries[0].Allocation.ConnectionID
	}
	if c.guard == nil || c.guard.reader == nil || c.journal == nil || c.guard.reader.run == nil || c.guard.reader.namespace == nil || c.guard.reader.interfaces == nil {
		return nil, ErrGuardReadback
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	defer func() {
		if resultErr != nil {
			c.emitRuntimeDiagnostic(ctx, "recovery_guard_denial", stage, connection, startedDiagnostic, true)
		}
	}()
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
	stage = "guard_namespace"
	before, e := r.namespace()
	if e != nil || before != expectedNS {
		return nil, ErrGuardReadback
	}
	stage = "guard_interfaces"
	links, e := r.interfaces()
	if e != nil {
		return nil, ErrGuardReadback
	}
	stage = "guard_table_read"
	raw, e := r.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
	if e != nil || ctx.Err() != nil {
		return nil, ErrGuardReadback
	}
	stage = "journal_inventory"
	templates, _, e := c.journal.guardTemplates()
	if e != nil || len(templates) != 1 {
		return nil, ErrGuardReadback
	}
	stage = "guard_prior_ownership"
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
	stage = "guard_projection"
	objects, ok := normalizedGuardWithdrawalObjectsWithInterfaces(raw, mapping)
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
	stage = "guard_source_bracket"
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
	return c.refreshIPsecRecoveryLocked(ctx, 5*time.Second, false)
}

// Maintenance already owns c.mu. Pulse only inactive, due evidence between its
// bounded IO operations so a full multi-provider page cannot starve the unchanged
// three-observation/ten-second failover hold. This never publishes authority,
// changes a route or renews a guard member. A refused observation discards advice;
// each healthy owner still needs its independent original maintenance proofs.
func (c *RuntimeController) refreshMaintenanceRecovery(ctx context.Context) {
	now := c.recoveryNow()
	for id, h := range c.recoveryHistory {
		if _, active := c.active[id]; active || h == nil || !h.seen {
			continue
		}
		if now < h.lastNow || now-h.lastNow >= time.Second {
			_ = c.refreshIPsecRecoveryLocked(ctx, time.Second, true)
			return
		}
	}
}

func (c *RuntimeController) refreshIPsecRecoveryLocked(ctx context.Context, interval time.Duration, inactiveOnly bool) (resultErr error) {
	stage := "input"
	startedDiagnostic := time.Now()
	connection := uuid.Nil
	if c == nil {
		return ErrRuntimeController
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "recovery_refresh", stage, connection, startedDiagnostic, resultErr != nil)
	}()
	if ctx.Err() != nil || !c.started || c.closed || c.journal == nil || c.client == nil || c.config.Environment == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() {
		c.recoveryHistory = nil
		return ErrRuntimeController
	}
	stage = "journal_inventory"
	entries, e := c.journal.Entries()
	if e != nil {
		c.recoveryHistory = nil
		return ErrRuntimeController
	}
	callbackStarted := c.recoveryNow()
	now := callbackStarted
	var chosen *RuntimeJournalEntry
	var history *recoveryDecision
	stage = "inactive_history_inventory"
	eligible := make([]RuntimeJournalEntry, 0, len(entries))
	for i := range entries {
		entry := &entries[i]
		if _, active := c.active[entry.Allocation.ConnectionID]; inactiveOnly && active {
			continue
		}
		h := c.recoveryHistory[entry.Allocation.ConnectionID]
		if h == nil || !h.seen {
			continue
		}
		// Historical cleanup obligations can share this connection ID with the
		// current delivery. They cannot invalidate the current delivery's
		// process-local evidence; its own entry still passes every check below.
		if entry.DeliveryID != h.epoch.DeliveryID {
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
		if now-h.lastNow < interval {
			continue
		}
		eligible = append(eligible, *entry)
	}
	if len(eligible) == 0 {
		stage = "inactive_no_due_history"
		return nil
	}
	stage = "guard_denial_read"
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
		stage = "inactive_no_denied_candidate"
		return nil
	}
	entry := *chosen
	id := entry.Allocation.ConnectionID
	connection = id
	fail := func() error { delete(c.recoveryHistory, id); return ErrRuntimeController }
	stage = "guard_namespace"
	ns, e := c.namespace()
	if e != nil || ns != entry.Allocation.Namespace {
		return fail()
	}
	stage = "prepared_binding"
	prepared, ok := c.recoveryPrepared[entry.DeliveryID]
	if !ok {
		return fail()
	}
	stage = "environment"
	env, e := c.config.Environment.Observe(ctx, entry.Allocation, entry.Engines)
	if e != nil || !reflect.DeepEqual(env, prepared) {
		return fail()
	}
	// The fully verified initial snapshot independently proved exact target denial.
	stage = "permit_lease"
	authority, identity, e := c.recoveryLease(ctx, entry, history.epoch.PolicyHash)
	if e != nil {
		return fail()
	}
	stage = "remaining_authority"
	if _, e = authority.RemainingForApply(identity, 5*time.Second); e != nil {
		return fail()
	}
	started := c.recoveryNow()
	stage = "native_status"
	statuses := c.observeRecovery(ctx, entry)
	ended := c.recoveryNow()
	stage = "observation_window"
	if ctx.Err() != nil || ended < started || ended-started > 5*time.Second || (statuses[0] != "up" && statuses[0] != "down") || (statuses[1] != "up" && statuses[1] != "down") || !c.config.DaemonAlive() || !c.qualification.current() {
		return fail()
	}
	stage = "guard_denial_read"
	if !c.recoveryGuardDenied(ctx, entry) {
		return fail()
	}
	stage = "environment"
	after, e := c.config.Environment.Observe(ctx, entry.Allocation, entry.Engines)
	if e != nil || !reflect.DeepEqual(after, env) || ctx.Err() != nil {
		return fail()
	}
	stage = "remaining_authority"
	if _, e = authority.RemainingForApply(identity, 5*time.Second); e != nil {
		return fail()
	}
	stage = "journal_continuity"
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
	stage = "final_binding"
	afterNS, e := c.namespace()
	if e != nil || afterNS != ns || !c.config.DaemonAlive() || !c.qualification.current() || ctx.Err() != nil {
		return fail()
	}
	final := c.recoveryNow()
	if final < started || final-started > 5*time.Second || final < callbackStarted || final-callbackStarted > 5*time.Second {
		return fail()
	}
	stage = "recovery_advice"
	history.observe(history.epoch, final, recoveryObservation{Epoch: history.epoch, Current: selectedRuntimeSlot(entry), Status: statuses, Authorized: true, At: started})
	return nil
}
