package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Capture a real, newly sequenced native observation before its publication
// clock is remembered. No test helper creates a report or extends authority.
func pendingRecoveryFixture(t *testing.T) (*renewalCycleRig, *maintenancePulseDeferral, RuntimeRecoveryHeartbeat) {
	t.Helper()
	r, _, d := pulseDeferralFixture(t)
	r.charge("collection", 900*time.Millisecond)
	if !d.deferPulse(context.Background(), r.c) || !d.used {
		t.Fatal("real deferral missing")
	}
	var target uuid.UUID
	for id, before := range d.owners {
		if target == uuid.Nil || before.clock.returned < d.owners[target].clock.returned {
			target = id
		}
	}
	clock := r.c.recoveryReportClocks[target]
	r.charge("prior_report_9_5s", clock.returned+9500*time.Millisecond-*r.now)
	seen := map[uuid.UUID]bool{}
	for id := range r.c.active {
		seen[id] = id != target
	}
	r.c.mu.Lock()
	reports, err := r.c.refreshIPsecActiveRecoveryLockedQualified(context.Background(), seen, true, time.Now(), func() bool { return true })
	r.c.mu.Unlock()
	if err != nil || len(reports) != 1 || reports[0].ConnectionID != target || reports[0].Report.SelectionSequence == nil {
		t.Fatal("real fresh pending sample missing", err, len(reports))
	}
	if r.c.recoveryReportClocks[target] != clock || d.reportsCurrent(r.c) || !d.reportsCurrentForRecovery(context.Background(), r.c, reports[0]) {
		t.Fatal("fixture must cross only its old report age")
	}
	return r, d, reports[0]
}

func TestMaintenancePendingRecoveryProofReadOnly(t *testing.T) {
	r, d, out := pendingRecoveryFixture(t)
	clocks := map[uuid.UUID]runtimeRecoveryReportClock{}
	histories := map[uuid.UUID]recoveryDecision{}
	active := map[uuid.UUID]runtimeActive{}
	deadlines := map[*PermitLeaseAuthority]time.Duration{}
	native := map[string]time.Duration{}
	for id, a := range r.c.active {
		active[id] = cloneMaintenanceActive(a)
		deadlines[a.Authority] = a.Authority.deadline
	}
	for id, c := range r.c.recoveryReportClocks {
		clocks[id] = c
	}
	for id, h := range r.c.recoveryHistory {
		histories[id] = *h
	}
	for k, v := range r.installed {
		native[k] = v
	}
	for i := 0; i < 3; i++ {
		if !d.reportsCurrentForRecovery(context.Background(), r.c, out) {
			t.Fatal("same fresh pending proof refused")
		}
	}
	if !reflect.DeepEqual(clocks, r.c.recoveryReportClocks) || !reflect.DeepEqual(active, r.c.active) || !reflect.DeepEqual(native, r.installed) {
		t.Fatal("proof mutated clocks, authority, or native members")
	}
	for id, h := range histories {
		if *r.c.recoveryHistory[id] != h {
			t.Fatal("history mutated")
		}
	}
	for a, v := range deadlines {
		if a.deadline != v {
			t.Fatal("authority extended")
		}
	}
	if d.reportsCurrent(r.c) {
		t.Fatal("pending proof falsely stamped a returned report")
	}
}

func TestMaintenancePendingRecoveryRejectsHostileEvidence(t *testing.T) {
	cases := []string{"foreign_connection", "delivery", "equal_sequence", "future_sequence", "version", "tunnel_id", "tunnel_slot", "selected_flag", "unknown_tunnel", "selected_status_tamper", "hidden_bgp", "hidden_transport", "hidden_tunnel_count", "wrong_active_slot", "missing_active_slot", "missing_history", "history_epoch", "sample_before_return", "sample_future", "sample_clock_future", "sample_expired", "authority_expired", "authority_reserve", "other_owner_stale", "canceled", "qualification", "daemon"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			r, d, out := pendingRecoveryFixture(t)
			id := out.ConnectionID
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "foreign_connection":
				out.ConnectionID = uuid.New()
			case "delivery":
				out.Delivery.OwnershipDigest = "foreign"
			case "equal_sequence":
				v := r.c.recoveryReportClocks[id].sequence
				out.Report.SelectionSequence = &v
			case "future_sequence":
				v := *out.Report.SelectionSequence + 1
				out.Report.SelectionSequence = &v
			case "version":
				v := 2
				out.Report.RecoveryVersion = &v
			case "tunnel_id":
				out.Report.Tunnels[0].ID = uuid.New()
			case "tunnel_slot":
				out.Report.Tunnels[0].Slot = 2
			case "selected_flag":
				out.Report.Tunnels[0].Selected = !out.Report.Tunnels[0].Selected
			case "unknown_tunnel":
				out.Report.Tunnels[0].Status = "unknown"
			case "selected_status_tamper":
				out.Report.Tunnels[*out.Report.ActiveSlot-1].Status = "down"
			case "hidden_bgp":
				out.Report.BGP = &RuntimeBGPStatus{Version: 1}
			case "hidden_transport":
				v := 1
				out.Report.TransportVersion = &v
			case "hidden_tunnel_count":
				v := 2
				out.Report.TunnelCount = &v
			case "wrong_active_slot":
				v := 3 - *out.Report.ActiveSlot
				out.Report.ActiveSlot = &v
			case "missing_active_slot":
				out.Report.ActiveSlot = nil
			case "missing_history":
				delete(r.c.recoveryHistory, id)
			case "history_epoch":
				r.c.recoveryHistory[id].epoch.PolicyHash = "foreign"
			case "sample_before_return":
				r.c.recoveryHistory[id].lastAt = r.c.recoveryReportClocks[id].returned
			case "sample_future":
				r.c.recoveryHistory[id].lastAt = r.c.recoveryHistory[id].lastNow + time.Millisecond
			case "sample_clock_future":
				r.c.recoveryHistory[id].lastNow = *r.now + time.Millisecond
			case "sample_expired":
				r.charge("sample_age", 5*time.Second+time.Millisecond)
			case "authority_expired":
				r.c.active[id].Authority.Invalidate()
			case "authority_reserve":
				a := r.c.active[id].Authority
				a.mu.Lock()
				a.deadline = *r.now + 4999*time.Millisecond
				a.mu.Unlock()
			case "other_owner_stale":
				for other := range d.owners {
					if other != id {
						c := r.c.recoveryReportClocks[other]
						r.charge("other_report_age", c.returned+11*time.Second-*r.now)
					}
				}
				if *r.now-r.c.recoveryHistory[id].lastAt > 5*time.Second {
					t.Fatal("must isolate other-owner age")
				}
			case "canceled":
				cancel()
			case "qualification":
				r.c.qualification.invalid = true
			case "daemon":
				r.c.config.DaemonAlive = func() bool { return false }
			}
			before := r.c.recoveryReportClocks[id]
			if d.reportsCurrentForRecovery(ctx, r.c, out) {
				t.Fatal("hostile pending evidence accepted", mode)
			}
			if r.c.recoveryReportClocks[id] != before {
				t.Fatal("refusal mutated report clock")
			}
		})
	}
}

func TestMaintenancePendingRecoveryFailedPublicationDoesNotRemember(t *testing.T) {
	r, _, d := pulseDeferralFixture(t)
	r.charge("collection", 900*time.Millisecond)
	if !d.deferPulse(context.Background(), r.c) || !d.used {
		t.Fatal("deferral missing")
	}
	var target uuid.UUID
	for id, before := range d.owners {
		if target == uuid.Nil || before.clock.returned < d.owners[target].clock.returned {
			target = id
		}
	}
	before := r.c.recoveryReportClocks[target]
	deadline := r.c.active[target].Authority.deadline
	r.charge("prior_report_9_5s", before.returned+9500*time.Millisecond-*r.now)
	calls := 0
	err := r.c.refreshMaintenanceActiveRecovery(context.Background(), map[uuid.UUID]bool{target: true}, func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
		calls++
		if !d.reportsCurrentForRecovery(ctx, r.c, out) {
			t.Fatal("fresh pending report refused before injected callback failure")
		}
		return ErrRuntimeController
	})
	if err == nil || calls != 1 {
		t.Fatal("callback failure lost", err, calls)
	}
	if r.c.recoveryReportClocks[target] != before || r.c.active[target].Authority.deadline != deadline {
		t.Fatal("failed publication remembered evidence or extended lease")
	}
	if d.reportsCurrent(r.c) {
		t.Fatal("failure fabricated a fresh returned report")
	}
}
