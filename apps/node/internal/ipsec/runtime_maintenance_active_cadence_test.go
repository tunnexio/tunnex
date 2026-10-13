package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

type recoveryObservedMaintenanceCore interface {
	maintainIPsecRuntimeRecoveryObserved(context.Context, []RuntimeMaterial, func() *PermitLeaseAuthority, func() bool, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, func(context.Context, RuntimeRecoveryHeartbeat) error) ([]RuntimeMaintenanceResult, error)
}

func runActiveCadenceMaintenance(r *renewalCycleRig, materials []RuntimeMaterial, publish func(context.Context, RuntimeDelivery, RuntimeStatusReport) error, publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error) ([]RuntimeMaintenanceResult, error) {
	if c, ok := any(r.c).(recoveryObservedMaintenanceCore); ok {
		return c.maintainIPsecRuntimeRecoveryObserved(context.Background(), materials, maintenanceAuthority(r), func() bool { return true }, publish, publishRecovery)
	}
	return r.c.maintainIPsecRuntimeObserved(context.Background(), materials, maintenanceAuthority(r), func() bool { return true }, publish)
}

func TestMaintainedActiveStatusGapIncludesPrecommitCollection(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	materials := maintenanceMaterials(r)
	target := materials[len(materials)-1].Manifest.ConnectionID
	if len(r.c.active) != 5 || r.c.active[target].Entry.ContractVersion != 2 {
		t.Fatal("no genuine static target/five-owner authority")
	}
	old := map[uuid.UUID]runtimeActive{}
	deadlines := map[uuid.UUID]time.Duration{}
	for id, a := range r.c.active {
		if a.Authority == nil || r.c.maintenanceGuard(context.Background(), a.Entry) != nil {
			t.Fatal("initial actual native authority absent", id)
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			t.Fatal("initial original authority expired", id, err)
		}
		old[id] = a
		deadlines[id] = a.Authority.deadline
	}
	r.charge("loop_start_due", time.Second)
	top, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(top) != 2 {
		t.Fatal("genuine loop-top heartbeat failed", len(top), err)
	}
	_, global, err := r.c.journal.guardTemplates()
	if err != nil {
		t.Fatal(err)
	}
	last := map[uuid.UUID]time.Duration{}
	sequences := map[uuid.UUID]uint64{}
	for _, out := range top {
		if out.Report.SelectionSequence == nil || *out.Report.SelectionSequence != global || r.c.recoveryStatusSequence[out.Delivery.ID] != global {
			t.Fatal("loop-top own sequence must equal current global")
		}
		last[out.ConnectionID] = *r.now
		sequences[out.Delivery.ID] = *out.Report.SelectionSequence
	}
	if _, ok := last[target]; !ok {
		t.Fatal("target loop-top observation missing")
	}
	r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		return viciMessage{}, nil, errors.New("honest native status unknown")
	}}
	r.c.config.IPPath = "/usr/bin/true"
	commitAt := time.Duration(0)
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		commitAt = *r.now
		return replace(ctx, in)
	}
	var targetArrival time.Duration
	maxGap := map[uuid.UUID]time.Duration{}
	recoveryPublished := 0
	record := func(id uuid.UUID) {
		if before, ok := last[id]; ok {
			gap := *r.now - before
			if gap > maxGap[id] {
				maxGap[id] = gap
			}
			last[id] = *r.now
		}
	}
	pageStarted := *r.now
	r.phase = "maintenance"
	results, err := runActiveCadenceMaintenance(r, materials, func(_ context.Context, d RuntimeDelivery, out RuntimeStatusReport) error {
		if out.DeliveryID != d.ID || out.Tunnels[0].Status != "unknown" || out.Tunnels[1].Status != "unknown" {
			t.Fatal("cached positive or wrong binding")
		}
		if last := sequences[d.ID]; last != 0 {
			if out.SelectionSequence == nil || *out.SelectionSequence <= last {
				t.Fatal("maintained report lost strict sequence ordering behind pulse")
			}
			sequences[d.ID] = *out.SelectionSequence
		}
		record(d.Manifest.ConnectionID)
		if d.Manifest.ConnectionID == target {
			targetArrival = *r.now
		}
		return nil
	}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
		a, ok := r.c.active[out.ConnectionID]
		if !ok || out.Report.SelectionSequence == nil || out.Report.ActiveSlot == nil || out.Report.Tunnels[0].Status != "up" || out.Report.Tunnels[1].Status != "up" || !reflect.DeepEqual(a.Delivery, out.Delivery) {
			t.Fatal("inactive/cached/unknown positive pulse")
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			t.Fatal("pulse without original authority", err)
		}
		if *out.Report.SelectionSequence <= sequences[out.Delivery.ID] {
			t.Fatal("repeated pulse reused older report sequence")
		}
		sequences[out.Delivery.ID] = *out.Report.SelectionSequence
		if commitAt == 0 && a.Authority != old[out.ConnectionID].Authority {
			t.Fatal("candidate authority published before combined commit")
		}
		recoveryPublished++
		record(out.ConnectionID)
		return nil
	})
	r.phase = ""
	if err != nil || len(results) != 5 || len(r.c.active) != 5 || targetArrival == 0 {
		t.Fatal("normal maintenance must be valid before cadence assertion", len(results), err)
	}
	for id, a := range old {
		if a.Authority.deadline != deadlines[id] || !reflect.DeepEqual(a.Entry, r.c.active[id].Entry) {
			t.Fatal("changed original authority/entry")
		}
	}
	oldReserve := time.Hour
	freshReserve := time.Hour
	for id, a := range old {
		left := a.Authority.deadline - commitAt
		if left < oldReserve {
			oldReserve = left
		}
		current := r.c.active[id]
		left = current.Authority.deadline - *r.now
		if left < freshReserve {
			freshReserve = left
		}
	}
	if oldReserve < 5*time.Second || freshReserve <= 0 {
		t.Fatal("finite bridge/final authority budget exhausted", oldReserve, freshReserve)
	}
	t.Logf("genuine initial5/target positive; top seq=%d; active pulses=%d; static maxgaps=%v; page duration=%s; old commit reserve=%s; fresh final reserve=%s; work=%v", global, recoveryPublished, maxGap, *r.now-pageStarted, oldReserve, freshReserve, r.charged)
	for id, gap := range maxGap {
		if gap > 10*time.Second {
			t.Fatalf("fresh static observation withheld across valid maintained collection: %s >10s owner=%s", gap, id)
		}
	}
}

func TestMaintenanceRepeatedFreshHeartbeatCannotPublishEqualGlobalSequence(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	r.charge("loop_start_due", time.Second)
	reports, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 2 {
		t.Fatal("initial heartbeat", len(reports), err)
	}
	_, seq, err := r.c.journal.guardTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range reports {
		if out.Report.SelectionSequence == nil || *out.Report.SelectionSequence != seq || r.c.recoveryStatusSequence[out.Delivery.ID] != seq {
			t.Fatal("own sequence does not equal global")
		}
	}
	nonces := r.telemetryNonces
	old := map[uuid.UUID]*PermitLeaseAuthority{}
	native := map[string]time.Duration{}
	for id, a := range r.c.active {
		old[id] = a.Authority
	}
	for name, deadline := range r.installed {
		native[name] = deadline
	}
	r.charge("next_due", time.Second)
	reports, err = r.c.RefreshIPsecActiveRecovery(context.Background())
	if err != nil || len(reports) != 0 || r.telemetryNonces-nonces != 2 {
		t.Fatal("fresh proof not completed or equal sequence became publishable", len(reports), err)
	}
	for id, a := range r.c.active {
		if a.Authority != old[id] {
			t.Fatal("evidence authority promoted")
		}
	}
	if !reflect.DeepEqual(native, r.installed) {
		t.Fatal("evidence pulse renewed native deadlines")
	}
	t.Log("two fresh nonce/native proofs completed; durable sequence unchanged; no report/CP freshness repair")
}

func TestMaintainedActivePulseFailureCannotRestoreStagedAuthority(t *testing.T) {
	for _, scenario := range []string{"expired_original", "native_lease_missing", "unknown_native", "canceled", "qualification", "source_changed", "epoch_changed", "callback_revoke", "callback_replace", "callback_expired", "callback_slow"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			materials := maintenanceMaterials(r)
			target := materials[len(materials)-1].Manifest.ConnectionID
			r.charge("due", 3*time.Second)
			for id, h := range r.c.recoveryHistory {
				if id != target {
					h.lastNow = *r.now
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "expired_original":
				r.c.active[target].Authority.Invalidate()
			case "native_lease_missing":
				r.installed[guardLeaseName(target)] = *r.now
			case "unknown_native":
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"unknown", "up"} }
			case "canceled":
				cancel()
			case "qualification":
				r.c.qualification.invalid = true
			case "source_changed":
				envs := r.c.config.Environment.(renewalCycleEnvironment)
				env := envs[target]
				env.Namespace = "net:[4026539999]"
				envs[target] = env
			case "epoch_changed":
				r.c.recoveryHistory[target].epoch.Namespace = "net:[4026539999]"
			}
			positiveCommits := 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if !g.PrefixOnly && len(g.Grants) > 0 {
						positiveCommits++
						break
					}
				}
				return replace(ctx, in)
			}
			callbacks := 0
			results, err := r.c.maintainIPsecRuntimeRecoveryObserved(ctx, materials, maintenanceAuthority(r), func() bool { return true }, func(context.Context, RuntimeDelivery, RuntimeStatusReport) error {
				t.Fatal("post-commit observation/ACK escaped failed pulse")
				return nil
			}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
				callbacks++
				if out.ConnectionID != target {
					t.Fatal("target not selected")
				}
				switch scenario {
				case "callback_revoke":
					r.c.active[target].Authority.Invalidate()
				case "callback_replace":
					delete(r.c.active, target)
				case "callback_expired":
					r.charge("callback", 61*time.Second)
				case "callback_slow":
					r.charge("callback", 6*time.Second)
				default:
					t.Fatal("invalid source published positive heartbeat", scenario)
				}
				return nil
			})
			expectedActive := 0
			// Initial input rejection keeps the original finite authority; a
			// failed pulse after staging must deny before any candidate commit.
			if scenario == "canceled" || scenario == "qualification" {
				expectedActive = 5
			}
			if err == nil || len(results) != 0 || positiveCommits != 0 || len(r.c.active) != expectedActive {
				t.Fatal("failed pulse reinstalled/ACKed staged authority", len(results), positiveCommits, len(r.c.active), err)
			}
			if scenario[:min(len(scenario), 8)] == "callback" && callbacks != 1 {
				t.Fatal("callback negative did not reach real fresh publication", callbacks)
			}
		})
	}
}

func TestMaintenanceActivePulseIsEvidenceOnlyAdvisory(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	materials := maintenanceMaterials(r)
	target := materials[len(materials)-1].Manifest.ConnectionID
	r.charge("due", 3*time.Second)
	for id, h := range r.c.recoveryHistory {
		if id != target {
			h.lastNow = *r.now
		}
	}
	r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"down", "up"} }
	before := r.c.active[target]
	native := map[string]time.Duration{}
	for name, end := range r.installed {
		native[name] = end
	}
	entries, err := r.c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	_, seq, err := r.c.journal.guardTemplates()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	r.c.mu.Lock()
	err = r.c.refreshMaintenanceActiveRecovery(context.Background(), map[uuid.UUID]bool{target: true}, func(_ context.Context, out RuntimeRecoveryHeartbeat) error {
		calls++
		if out.Report.ActiveSlot != nil || out.Report.Tunnels[0].Status != "down" || out.Report.Tunnels[1].Status != "up" || out.Report.SelectionSequence == nil || *out.Report.SelectionSequence <= seq {
			t.Fatal("advice became selected/UP or invented sequence")
		}
		return nil
	})
	r.c.mu.Unlock()
	afterEntries, readErr := r.c.journal.Entries()
	if err != nil || readErr != nil || calls != 1 || !reflect.DeepEqual(before, r.c.active[target]) || !reflect.DeepEqual(native, r.installed) || !reflect.DeepEqual(entries, afterEntries) {
		t.Fatal("advisory renewed permit/route/lease or changed entries", err, readErr, calls)
	}
}
