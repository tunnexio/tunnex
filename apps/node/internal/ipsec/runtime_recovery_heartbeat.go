package ipsec

import (
	"context"
	"github.com/google/uuid"
	"reflect"
	"time"
)

// RuntimeRecoveryHeartbeat carries independent telemetry and no Apply acknowledgement.
// Its delivery is the original authenticated, secret-free Apply context.
type RuntimeRecoveryHeartbeat struct {
	ConnectionID uuid.UUID
	Delivery     RuntimeDelivery
	Report       RuntimeStatusReport
}

// RefreshIPsecActiveRecovery runs between serial reconciliation items. The new
// nonce lease qualifies evidence only: it is discarded and never replaces an
// active authority, changes a route, installs a permit or renews an NFT member.
// Full Apply remains the only consumer of a failover recommendation.
func (c *RuntimeController) RefreshIPsecActiveRecovery(ctx context.Context) ([]RuntimeRecoveryHeartbeat, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var reports []RuntimeRecoveryHeartbeat
	seen := map[uuid.UUID]bool{}
	// Each inner observation advances the exact target's sample clock. Drain all
	// currently due static connections once within one bounded serial callback.
	// Native reads of another provider can make an earlier provider due again;
	// resampling it would exhaust the shared deadline and discard all reports.
	for i := 0; i < 256; i++ {
		sampled, err := c.refreshIPsecActiveRecovery(ctx, seen)
		if err != nil {
			return nil, err
		}
		if len(sampled) == 0 {
			return reports, nil
		}
		for _, v := range sampled {
			// A same-sequence observation still consumed this provider's turn,
			// even though it cannot publish a new durable status receipt.
			seen[v.ConnectionID] = true
			if v.Report.SelectionSequence != nil {
				reports = append(reports, v)
			}
		}
	}
	return nil, ErrRuntimeController
}

func (c *RuntimeController) refreshIPsecActiveRecovery(ctx context.Context, seen map[uuid.UUID]bool) (reportsResult []RuntimeRecoveryHeartbeat, resultErr error) {
	stage := "input"
	startedDiagnostic := time.Now()
	connection := uuid.Nil
	if c == nil {
		return nil, ErrRuntimeController
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	defer func() {
		c.emitRuntimeDiagnostic(ctx, "heartbeat", stage, connection, startedDiagnostic, resultErr != nil)
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || !c.started || c.closed || c.journal == nil || c.client == nil || c.config.Environment == nil || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !c.qualification.current() {
		return nil, ErrRuntimeController
	}
	stage = "journal_inventory"
	entries, err := c.journal.Entries()
	if err != nil {
		return nil, ErrRuntimeController
	}
	now := c.recoveryNow()
	var selected *RuntimeJournalEntry
	var oldest *recoveryDecision
	for i := range entries {
		e := &entries[i]
		if seen[e.Allocation.ConnectionID] {
			continue
		}
		a, ok := c.active[e.Allocation.ConnectionID]
		h := c.recoveryHistory[e.Allocation.ConnectionID]
		if !ok || h == nil || !h.seen || e.Phase != RuntimeApplied || e.ContractVersion != 2 || e.AbsenceOnly || !validJournalRecovery(*e) || e.Recovery.Stage != "completed" || a.Delivery.ID != e.DeliveryID || a.Delivery.OwnershipDigest != e.OwnershipDigest || !reflect.DeepEqual(a.Entry, *e) {
			continue
		}
		epoch := recoveryEpoch{Binding: e.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash, DeliveryID: e.DeliveryID, Namespace: e.Allocation.Namespace, Tunnels: [2]uuid.UUID{e.Engines[0].TunnelID, e.Engines[1].TunnelID}}
		if epoch != h.epoch || !validRecoveryEpoch(epoch) || h.current != selectedRuntimeSlot(*e) || now < h.lastNow {
			delete(c.recoveryHistory, e.Allocation.ConnectionID)
			continue
		}
		// Fast serial items must not skip a useful pre-item sample: waiting5s
		// here can turn4s Validate +6s next provider into a >10s gap.
		// The reducer retains its independent3samples/10s hold.
		if now-h.lastNow < time.Second {
			continue
		}
		if selected == nil || h.lastNow < oldest.lastNow {
			selected = e
			oldest = h
		}
	}
	if selected == nil {
		return nil, nil
	}
	stage = "authority_binding"
	e := *selected
	id := e.Allocation.ConnectionID
	connection = id
	a := c.active[id]
	// Failure only withdraws. No cached healthy selection is published after a
	// revoked lease, expired native member, unknown inventory or source change.
	fail := func() ([]RuntimeRecoveryHeartbeat, error) {
		delete(c.recoveryHistory, id)
		delete(c.active, id)
		_, _ = c.refuse(ctx, entries)
		return nil, ErrRuntimeController
	}
	if a.Authority == nil || a.Identity.Binding != e.Engines[0].Binding || a.Identity.DeliveryID != e.DeliveryID || a.Delivery.DesiredRevision != e.Engines[0].Binding.DesiredRevision || a.Delivery.Manifest.ConfigurationRevision != e.Engines[0].Binding.ConfigurationRevision || a.Delivery.Manifest.RecoveryVersion == nil || *a.Delivery.Manifest.RecoveryVersion != 1 {
		return fail()
	}
	ns, err := c.namespace()
	if err != nil || ns != e.Allocation.Namespace {
		return fail()
	}
	stage = "remaining_authority"
	if _, err = a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
		return fail()
	}
	stage = "permit_lease"
	authority, identity, err := c.recoveryLease(ctx, e, oldest.epoch.PolicyHash)
	if err != nil {
		return fail()
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return fail()
	}
	stage = "environment"
	env, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
	if err != nil || !reflect.DeepEqual(env, a.Environment) {
		return fail()
	}
	started := c.recoveryNow()
	stage = "native_status"
	statuses := c.observeRecovery(ctx, e)
	for _, status := range statuses {
		if status != "up" && status != "down" {
			return fail()
		}
	}
	stage = "guard_denial_read"
	denied, err := c.recoveryGuardDenial(ctx, e)
	if err != nil {
		return fail()
	}
	var slot *int
	current := int(selectedRuntimeSlot(e)) - 1
	if statuses[current] == "up" {
		stage = "native_current_proof_and_guard"
		if denied || c.proveCurrent(ctx, e, env) != nil || !c.recoveryGuardPermits(ctx, e) {
			return fail()
		}
		value := current + 1
		slot = &value
	} else {
		// Native Down cannot be an installed active path, even while a previously
		// bounded guard member exists. Advice may accumulate but Apply must first
		// prove denial, fresh material and exact target readback before switching.
		after, err := c.config.Environment.Observe(ctx, e.Allocation, e.Engines)
		if err != nil || !reflect.DeepEqual(after, env) {
			return fail()
		}
	}
	stage = "final_binding"
	final := c.recoveryNow()
	afterNS, err := c.namespace()
	if err != nil || afterNS != ns || final < started || final-started > 5*time.Second || final < now || final-now > 5*time.Second || ctx.Err() != nil || !c.qualification.current() || !c.config.DaemonAlive() {
		return fail()
	}
	if _, err = a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
		return fail()
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		return fail()
	}
	// Reuse only a newer durable global sequence advanced by intervening normal
	// Apply/Validate commits. Equal sequence is an exact retry at the CP and
	// cannot refresh its observation time. Heartbeat adds no global fsync work.
	stage = "journal_sequence"
	_, seq, err := c.journal.guardTemplates()
	if err != nil || seq == 0 || seq > 9007199254740991 {
		return fail()
	}
	final = c.recoveryNow()
	if ctx.Err() != nil || final < started || final-started > 5*time.Second || final-now > 5*time.Second {
		return fail()
	}
	oldest.observe(oldest.epoch, final, recoveryObservation{Epoch: oldest.epoch, Current: selectedRuntimeSlot(e), Status: statuses, Authorized: true, At: started})
	if seq <= c.recoveryStatusSequence[e.DeliveryID] {
		return []RuntimeRecoveryHeartbeat{{ConnectionID: id, Delivery: a.Delivery}}, nil
	}
	if c.recoveryStatusSequence == nil {
		c.recoveryStatusSequence = map[uuid.UUID]uint64{}
	}
	c.recoveryStatusSequence[e.DeliveryID] = seq
	version := 1
	report := RuntimeStatusReport{DeliveryID: e.DeliveryID, DesiredRevision: e.Engines[0].Binding.DesiredRevision, ConfigurationRevision: e.Engines[0].Binding.ConfigurationRevision, RecoveryVersion: &version, SelectionSequence: &seq, ActiveSlot: slot}
	for i, t := range e.Engines {
		report.Tunnels[i] = RuntimeTunnelStatus{ID: t.TunnelID, Slot: i + 1, Status: statuses[i], Selected: a.Delivery.Manifest.Tunnels[i].Selected}
	}
	return []RuntimeRecoveryHeartbeat{{ConnectionID: id, Delivery: a.Delivery, Report: report}}, nil
}
