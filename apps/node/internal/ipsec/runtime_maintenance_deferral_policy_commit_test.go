package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This drives the normal stale-page/409/fresh-material/finite-guard-commit path.
// A real fresh lease arrives within the one-second collection deferral while
// the prior returned report crosses its two-second due boundary.
type deferralPolicyCommitClient struct {
	*fqdnTurnoverClient
	rig     *renewalCycleRig
	crossed bool
	delay   time.Duration
}

func (c *deferralPolicyCommitClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	oldClock, known := c.rig.c.recoveryReportClock(c.rig.c.active[id])
	before := *c.rig.now
	out, err := c.fqdnTurnoverClient.RenewIPsecLease(ctx, id, q)
	if err == nil && id == c.target && q.PolicyHash == c.material.Policy.Hash && !c.crossed && pulseDeferralInCall("maintainIPsecRuntimeItemsAttempt") && !pulseDeferralInCall("refreshIPsecActiveRecoveryLockedQualified") {
		c.rig.charge("bounded_normal_lease_response", c.delay)
		c.crossed = known && before-oldClock.returned < 2*time.Second && *c.rig.now-oldClock.returned >= 2*time.Second && *c.rig.now-before < time.Second
	}
	return out, err
}

func TestMaintenanceDeferralSurvivesCommittedStaticExpiryRollover(t *testing.T) {
	for _, delay := range []time.Duration{0, 800 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			r, client := fqdnExpiryTurnoverRig(t, true)
			for id := range r.c.active {
				if id != r.target {
					delete(r.c.active, id)
					delete(r.c.recoveryHistory, id)
				}
			}
			if err := r.c.installActive(context.Background(), r.entries); err != nil {
				t.Fatal("single-owner native setup", err)
			}
			allowed := map[uuid.UUID]bool{r.target: true}
			record := func(context.Context, RuntimeRecoveryHeartbeat) error { return nil }
			r.charge("initial_actual_report_due", 2*time.Second)
			if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, record); err != nil {
				t.Fatal("initial actual report", err)
			}
			r.charge("prior_report_age", 1100*time.Millisecond)
			wrapped := &deferralPolicyCommitClient{fqdnTurnoverClient: client, rig: r, delay: delay}
			r.c.client = wrapped
			old := cloneMaintenanceActive(r.c.active[r.target])
			deadline := old.Authority.deadline
			page := staleFQDNPage(r, client)
			commitSeen, postCommitReports := false, 0
			var committedAt time.Duration
			captureCommit := func() bool {
				current := r.c.active[r.target]
				committed := current.Authority != old.Authority && current.Identity.PolicyHash == client.material.Policy.Hash
				if committed {
					if !commitSeen {
						committedAt = *r.now
					}
					commitSeen = true
					if !reflect.DeepEqual(current.Entry, old.Entry) || !reflect.DeepEqual(current.Delivery, old.Delivery) || old.Authority.deadline != deadline {
						t.Fatal("rollover changed transport/original deadline")
					}
					for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
						if r.installed[name] <= *r.now {
							t.Fatal("committed native authority absent", name)
						}
					}
					for _, g := range current.Grants {
						if g.FQDNManaged && r.installed[guardFQDNSetName(g)] <= *r.now {
							t.Fatal("committed FQDN authority absent")
						}
					}
				}
				return committed
			}
			publish := func(context.Context, RuntimeRecoveryHeartbeat) error {
				if captureCommit() {
					postCommitReports++
				}
				return nil
			}
			r.c.config.IPPath = "/usr/bin/true"
			r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
				captureCommit()
				// Advisory status is honestly unknown; the guard uses the separate
				// native fixture and its real rendered finite members above.
				return viciMessage{}, nil, ErrRuntimeController
			}}
			results, err := r.c.maintainIPsecRuntimeRecoveryObserved(context.Background(), []RuntimeMaterial{page}, maintenanceAuthority(r), func() bool { return true }, nil, publish)
			t.Logf("commit_seen=%t bounded_collection_crossing=%t fresh_material_fetches=%d lease_requests=%d post_commit_reports=%d result=%d err=%v", commitSeen, wrapped.crossed, client.fetched, len(client.requests), postCommitReports, len(results), err)
			if !commitSeen || (wrapped.crossed != (delay > 0)) || client.fetched < 1 {
				t.Fatal("fixture did not reach real bounded policy refresh")
			}
			if err != nil || !commitSeen || len(results) != 1 {
				t.Fatal("fresh committed static policy rejected by pre-commit deferral", err)
			}
			current := r.c.active[r.target]
			clock, known := r.c.recoveryReportClock(current)
			if !known || clock.epoch != recoveryReportEpoch(current) || clock.returned < committedAt || current.Identity.PolicyHash != client.material.Policy.Hash || old.Authority.deadline != deadline {
				t.Fatal("ACK omitted actual new-epoch report or altered old authority")
			}
		})
	}
}

// Intercept the existing native status producer after a real normal-page guard
// commit and before it remembers any new-epoch returned report.
func committedPulseTransferFixture(t *testing.T, check func(*renewalCycleRig, *maintenancePulseDeferral, map[uuid.UUID]runtimeActive, map[uuid.UUID]runtimeActive, map[uuid.UUID]runtimeActive)) (*renewalCycleRig, *maintenancePulseDeferral) {
	t.Helper()
	r, client := fqdnExpiryTurnoverRig(t, true)
	for id := range r.c.active {
		if id != r.target {
			delete(r.c.active, id)
			delete(r.c.recoveryHistory, id)
		}
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal(err)
	}
	allowed := map[uuid.UUID]bool{r.target: true}
	record := func(context.Context, RuntimeRecoveryHeartbeat) error { return nil }
	r.charge("actual_report_due", 2*time.Second)
	if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), allowed, record); err != nil {
		t.Fatal(err)
	}
	r.charge("known_report_age", 1200*time.Millisecond)
	d := r.c.beginMaintenancePulseDeferral(allowed, record)
	r.charge("bounded_collection", 900*time.Millisecond)
	if d == nil || !d.deferPulse(context.Background(), r.c) || !d.used {
		t.Fatal("used real deferral required")
	}
	prior := map[uuid.UUID]runtimeActive{r.target: cloneMaintenanceActive(r.c.active[r.target])}
	called := false
	r.c.config.IPPath = "/usr/bin/true"
	r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		if !called && r.c.active[r.target].Identity.PolicyHash == client.material.Policy.Hash {
			called = true
			candidates := map[uuid.UUID]runtimeActive{r.target: cloneMaintenanceActive(r.c.active[r.target])}
			staged := map[uuid.UUID]runtimeActive{r.target: cloneMaintenanceActive(r.c.active[r.target])}
			check(r, d, prior, candidates, staged)
		}
		return viciMessage{}, nil, ErrRuntimeController
	}}
	_, _ = r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{staleFQDNPage(r, client)}, maintenanceAuthority(r), func() bool { return true })
	if !called {
		t.Fatal("real guard commit interception missing")
	}
	return r, d
}

func TestMaintenanceCommittedTransferRequiresRealNewReport(t *testing.T) {
	r, d := committedPulseTransferFixture(t, func(r *renewalCycleRig, d *maintenancePulseDeferral, prior, candidates, staged map[uuid.UUID]runtimeActive) {
		beforeClock := r.c.recoveryReportClocks[r.target]
		beforeHistory := *r.c.recoveryHistory[r.target]
		oldDeadline := prior[r.target].Authority.deadline
		newDeadline := candidates[r.target].Authority.deadline
		if err := d.transferCommitted(context.Background(), r.c, prior, candidates, staged); err != nil {
			t.Fatal(err)
		}
		if len(d.owners) != 0 || len(d.committed) != 1 || r.c.recoveryReportClocks[r.target] != beforeClock || *r.c.recoveryHistory[r.target] != beforeHistory || prior[r.target].Authority.deadline != oldDeadline || candidates[r.target].Authority.deadline != newDeadline {
			t.Fatal("transfer mutated authority or fabricated report")
		}
		if d.committedReportsCurrent(context.Background(), r.c) {
			t.Fatal("missing new-epoch report passed ACK fence")
		}
	})
	// The interception occurs after the status producer reserves its sequence;
	// that in-progress sequence cannot satisfy a strictly newer report fence.
	if d.committedReportsCurrent(context.Background(), r.c) {
		t.Fatal("equal in-progress status sequence passed new-epoch fence")
	}
	r.charge("new_epoch_actual_sample", 2*time.Second)
	callback := func(ctx context.Context, out RuntimeRecoveryHeartbeat) error {
		if !d.reportsCurrentForRecovery(ctx, r.c, out) {
			t.Fatal("exact committed pending owner was rejected")
		}
		return nil
	}
	if err := r.c.refreshMaintenanceActiveRecovery(context.Background(), map[uuid.UUID]bool{r.target: true}, callback); err != nil {
		t.Fatal(err)
	}
	if !d.committedReportsCurrent(context.Background(), r.c) {
		t.Fatal("actual newer status producer did not satisfy new-epoch report fence")
	}
	a := r.c.active[r.target]
	a.Identity.PolicyHash = "wrong"
	r.c.active[r.target] = a
	if d.committedReportsCurrent(context.Background(), r.c) {
		t.Fatal("changed committed candidate passed ACK fence")
	}
}

func TestMaintenanceCommittedTransferRejectsInvalidBindingAtomically(t *testing.T) {
	for _, kind := range []string{"candidate", "current_set", "before", "transport", "same_authority", "expired_original", "history", "sequence", "later_owner", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			committedPulseTransferFixture(t, func(r *renewalCycleRig, d *maintenancePulseDeferral, prior, candidates, staged map[uuid.UUID]runtimeActive) {
				id := r.target
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch kind {
				case "candidate":
					a := candidates[id]
					a.Identity.PolicyHash = "wrong"
					candidates[id] = a
				case "current_set":
					delete(staged, id)
				case "before":
					a := prior[id]
					a.Identity.PolicyHash = "wrong"
					prior[id] = a
				case "transport":
					a := r.c.active[id]
					a.Environment.Namespace = "net:[4026533999]"
					r.c.active[id] = a
					candidates[id] = a
					staged[id] = a
				case "same_authority":
					a := r.c.active[id]
					a.Authority = prior[id].Authority
					r.c.active[id] = a
					candidates[id] = a
					staged[id] = a
				case "expired_original":
					prior[id].Authority.deadline = *r.now
				case "history":
					r.c.recoveryHistory[id].epoch.DeliveryID = uuid.New()
				case "sequence":
					r.c.recoveryStatusSequence[candidates[id].Entry.DeliveryID] = 0
				case "later_owner":
					d.owners[uuid.New()] = d.owners[id]
				case "canceled":
					cancel()
				}
				snapshots := map[uuid.UUID]maintenancePulseSnapshot{}
				for owner, s := range d.owners {
					snapshots[owner] = s
				}
				clock := r.c.recoveryReportClocks[id]
				if err := d.transferCommitted(ctx, r.c, prior, candidates, staged); err == nil {
					t.Fatal("invalid transfer accepted")
				}
				if !reflect.DeepEqual(d.owners, snapshots) || len(d.committed) != 0 || r.c.recoveryReportClocks[id] != clock {
					t.Fatal("failed transfer partially changed tracking or report clock")
				}
			})
		})
	}
}
