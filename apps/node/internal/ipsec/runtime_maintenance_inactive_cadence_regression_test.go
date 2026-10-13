package ipsec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This uses the real canonical five-owner maintenance/guard/lease/epoch seams.
// The virtual costs are the existing renewal rig's 250ms proof/800ms status
// costs and the existing publication fixture's 2300ms daemon status attempt.
// Native telemetry refusal remains Unknown; it never manufactures an Up report.
// This is a post-platform-qualification scheduling test, not native Linux or
// public Apply qualification, and recovery advice never installs a route/permit.
func TestMaintainedFiveProviderInactiveRecoveryCadence(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	c, ctx := r.c, context.Background()
	if len(c.active) != 5 || len(r.materials) != 5 {
		t.Fatal("initial canonical five-owner setup is not genuinely active")
	}
	oldAuthorities := map[*PermitLeaseAuthority]time.Duration{}
	for _, a := range c.active {
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			t.Fatal("initial authority", err)
		}
		if c.maintenanceGuard(ctx, a.Entry) != nil {
			t.Fatal("initial rendered native members are not positive")
		}
		oldAuthorities[a.Authority] = a.Authority.deadline
	}
	targetEntry := c.active[r.target].Entry
	prepared := c.active[r.target].Environment
	targetAuthority := c.active[r.target].Authority
	initialHistory := c.recoveryHistory[r.target]
	if initialHistory == nil || !initialHistory.seen || initialHistory.current != 1 {
		t.Fatal("initial exact static epoch is missing")
	}
	epoch := initialHistory.epoch
	activeHistories := map[*recoveryDecision]recoveryDecision{}
	for id, h := range c.recoveryHistory {
		if id != r.target {
			activeHistories[h] = *h
		}
	}
	siblingRenewals, inactiveNonces := 0, 0
	leaseClient := c.client
	c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
		if id == r.target {
			inactiveNonces++
		} else if r.phase == "maintenance" {
			siblingRenewals++
		}
		return leaseClient.RenewIPsecLease(ctx, id, q)
	})
	// Model the actual failed selected native path. Withdraw only the target
	// through the original combined guard installer; all four siblings stay Up.
	prove := c.prove
	c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		if e.Allocation.ConnectionID == r.target && selectedRuntimeSlot(e) == 1 {
			r.charge("failed_selected_proof", 250*time.Millisecond)
			return ErrRuntimeController
		}
		return prove(ctx, e, env)
	}
	var observations []time.Duration
	observe := c.recoveryObserve
	c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		if e.Allocation.ConnectionID == r.target {
			observations = append(observations, *r.now)
			r.charge("inactive_native_status", 800*time.Millisecond)
			return [2]string{"down", "up"}
		}
		return observe(ctx, e)
	}
	c.withdrawDNSOwnerView(r.target)
	delete(c.active, r.target)
	if err := c.installActive(ctx, r.entries); err != nil {
		t.Fatal("exact target denial installation", err)
	}
	if !c.recoveryGuardDenied(ctx, targetEntry) || len(c.active) != 4 {
		t.Fatal("target must have three verified empty sets with four positive owners")
	}
	beforeEntries, err := c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	*r.now += 6 * time.Second
	if err := c.RefreshIPsecRecovery(ctx); err != nil {
		t.Fatal("initial inactive sample", err)
	}
	if h := c.recoveryHistory[r.target]; h == nil || h.consecutive != 1 || h.epoch != epoch {
		t.Fatal("initial real fresh inactive observation did not enter exact epoch")
	}
	statusReads := 0
	c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		statusReads++
		r.charge("fresh_status_IO", 2300*time.Millisecond)
		return viciMessage{}, nil, errors.New("synthetic telemetry-native refusal")
	}}
	c.config.IPPath = "/usr/bin/true"
	var pageDurations []time.Duration
	for page := 0; page < 2; page++ {
		started := *r.now
		published := 0
		r.phase = "maintenance"
		c.mu.Lock() // Same serialized runtime owner as the exported boundary.
		results, err := c.maintainIPsecRuntimeObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, report RuntimeStatusReport) error {
			if d.Manifest.ConnectionID == r.target || report.DeliveryID != d.ID || report.Tunnels[0].Status != "unknown" || report.Tunnels[1].Status != "unknown" {
				t.Fatal("invalid maintained telemetry publication")
			}
			published++
			r.charge("report_HTTP", 600*time.Millisecond)
			return nil
		})
		c.mu.Unlock()
		r.phase = ""
		pageDurations = append(pageDurations, *r.now-started)
		if err != nil || len(results) != 4 || published != 4 || len(c.active) != 4 {
			t.Fatalf("page=%d results=%d publications=%d active=%d err=%v", page, len(results), published, len(c.active), err)
		}
		if _, ok := c.active[r.target]; ok || !c.recoveryGuardDenied(ctx, targetEntry) {
			t.Fatal("inactive advice authorized the failed target")
		}
		for id, a := range c.active {
			if id == r.target || c.maintenanceGuard(ctx, a.Entry) != nil {
				t.Fatal("healthy sibling native permit lost")
			}
		}
		// This is the original missing-owner fallback's one public refresh after
		// the full maintained page; it cannot fill a long intra-page evidence gap.
		if err := c.RefreshIPsecRecovery(ctx); err != nil {
			t.Fatal("fallback inactive refresh", err)
		}
		if !reflect.DeepEqual(c.recoveryPrepared[targetEntry.DeliveryID], prepared) {
			t.Fatal("inactive prepared environment changed")
		}
		for _, a := range c.active {
			oldAuthorities[a.Authority] = a.Authority.deadline
		}
	}
	afterEntries, err := c.journal.Entries()
	if err != nil || !reflect.DeepEqual(beforeEntries, afterEntries) {
		t.Fatal("observations changed durable entries/route selection")
	}
	for authority, deadline := range oldAuthorities {
		if authority.deadline != deadline {
			t.Fatal("original authority deadline was extended")
		}
	}
	for h, before := range activeHistories {
		if *h != before {
			t.Fatal("inactive pulse advanced a currently active owner's history")
		}
	}
	if targetAuthority.deadline != oldAuthorities[targetAuthority] || selectedRuntimeSlot(targetEntry) != 1 || !c.recoveryGuardDenied(ctx, targetEntry) {
		t.Fatal("inactive target authority, original route or denial changed")
	}
	for _, p := range c.bgpProcesses {
		if p.(*bgpSessionFixture).closed {
			t.Fatal("maintenance closed a healthy BGP process")
		}
	}
	maximumGap := time.Duration(0)
	for i := 1; i < len(observations); i++ {
		if gap := observations[i] - observations[i-1]; gap > maximumGap {
			maximumGap = gap
		}
	}
	h := c.recoveryHistory[r.target]
	t.Logf("real maintained page costs=%v target observations=%v maxgap=%s statusReads=%d siblingFreshNonces=%d inactiveAdviceNonces=%d work=%v history=%+v", pageDurations, observations, maximumGap, statusReads, siblingRenewals, inactiveNonces, r.charged, h)
	if statusReads != 8 || siblingRenewals != 8 || inactiveNonces != len(observations) || pageDurations[0] <= 10*time.Second {
		t.Fatal("slow real maintained page was not exercised")
	}
	if h == nil || h.epoch != epoch || h.current != 1 || h.consecutive < 3 || h.lastAt-h.firstDown < 10*time.Second || maximumGap > 10*time.Second {
		t.Fatal("inactive failover advice starved behind four slow maintained siblings")
	}
}

func TestMaintainedInactiveRecoveryPulseDiscardsUnsafeAdvice(t *testing.T) {
	for _, scenario := range []string{"CP_denied", "short_lease", "unknown_native"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			c, ctx := r.c, context.Background()
			target := c.active[r.target]
			deadline := target.Authority.deadline
			delete(c.active, r.target)
			c.withdrawDNSOwnerView(r.target)
			if err := c.installActive(ctx, r.entries); err != nil || !c.recoveryGuardDenied(ctx, target.Entry) || len(c.active) != 4 {
				t.Fatal("exact initial target denial/four-sibling setup", err)
			}
			entries, err := c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			*r.now += 6 * time.Second
			attempts := 0
			client := c.client
			c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				out, err := client.RenewIPsecLease(ctx, id, q)
				if id == r.target {
					attempts++
					if scenario == "CP_denied" {
						return RuntimeLease{}, ErrRuntimeController
					}
					if scenario == "short_lease" {
						out.TTLMS = 1
					}
				}
				return out, err
			})
			observe := c.recoveryObserve
			c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
				if e.Allocation.ConnectionID == r.target {
					r.charge("inactive_native_status", 800*time.Millisecond)
					if scenario == "unknown_native" {
						return [2]string{"unknown", "up"}
					}
					return [2]string{"down", "up"}
				}
				return observe(ctx, e)
			}
			r.phase = "maintenance"
			c.mu.Lock()
			results, err := c.maintainIPsecRuntimeObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil)
			c.mu.Unlock()
			r.phase = ""
			// The public reader must retain its original refusal semantics as well.
			_ = c.RefreshIPsecRecovery(ctx)
			if err != nil || len(results) != 4 || len(c.active) != 4 || attempts == 0 {
				t.Fatalf("unsafe advice affected healthy renewal: results=%d active=%d targetAttempts=%d err=%v", len(results), len(c.active), attempts, err)
			}
			if c.recoveryHistory[r.target] != nil || !c.recoveryGuardDenied(ctx, target.Entry) || target.Authority.deadline != deadline {
				t.Fatal("unsafe inactive evidence retained/authorized/extended")
			}
			after, err := c.journal.Entries()
			if err != nil || !reflect.DeepEqual(after, entries) {
				t.Fatal("unsafe advice mutated journal route intent")
			}
			for _, a := range c.active {
				if c.maintenanceGuard(ctx, a.Entry) != nil {
					t.Fatal("unsafe inactive advice withdrew a healthy sibling")
				}
			}
		})
	}
}
