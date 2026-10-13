package ipsec

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

// Reuse the canonical five-owner postqualification/native guard fixture. Native
// status is the existing independent observation seam, not cached report data.
func maintainedMissingStandby(t *testing.T, slot int) (*renewalCycleRig, uuid.UUID) {
	t.Helper()
	r := newRenewalCycleRigInput(t, true)
	materials := maintenanceMaterials(r)
	target := materials[len(materials)-1].Manifest.ConnectionID
	for i, e := range r.entries {
		if e.Allocation.ConnectionID != target {
			continue
		}
		state := *e.Recovery
		if int(state.SelectedSlot) != slot {
			state.Sequence++
			state.Stage = "pending"
			state.PendingFrom, state.PendingTo = state.SelectedSlot, uint8(slot)
			e.Recovery = &state
			r.entries[i] = e
			if err := r.c.journal.Save(r.entries); err != nil {
				t.Fatal("fixture pending transition", err)
			}
			state.Stage = "completed"
			state.PendingFrom, state.PendingTo = 0, 0
		}
		state.SelectedSlot = uint8(slot)
		e.Recovery = &state
		r.entries[i] = e
		a := r.c.active[target]
		a.Entry = e
		r.c.active[target] = a
		h := r.c.recoveryHistory[target]
		h.current = uint8(slot)
	}
	if err := r.c.journal.Save(r.entries); err != nil {
		t.Fatal("fixture completed transition", err)
	}
	r.c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
		r.charge("native_status", 800*time.Millisecond)
		if e.Allocation.ConnectionID == target {
			s := [2]string{"down", "down"}
			s[slot-1] = "up"
			return s
		}
		return [2]string{"up", "up"}
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("fixture installed authority", err)
	}
	if len(r.c.active) != 5 {
		t.Fatal("missing genuine five-owner authority")
	}
	for _, a := range r.c.active {
		if r.c.maintenanceGuard(context.Background(), a.Entry) != nil {
			t.Fatal("initial positive native guard absent")
		}
		if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	r.c.config.Daemon = &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		return viciMessage{}, nil, errors.New("honest status telemetry unknown")
	}}
	r.c.config.IPPath = "/usr/bin/true"
	return r, target
}

func TestMaintainedMissingStandbyRestoration(t *testing.T) {
	for _, slot := range []int{1, 2} {
		t.Run(string(rune('0'+slot)), func(t *testing.T) {
			r, target := maintainedMissingStandby(t, slot)
			originals := map[*PermitLeaseAuthority]time.Duration{}
			for _, a := range r.c.active {
				originals[a.Authority] = a.Authority.deadline
			}
			attempts, commits := 0, 0
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) { commits++; return replace(ctx, in) }
			r.c.recoveryInitiate = func(ctx context.Context, tunnel EngineTunnel) error {
				attempts++
				a := r.c.active[target]
				if commits != 1 || selectedRuntimeSlot(a.Entry) != uint8(slot) || tunnel.TunnelID != a.Entry.Engines[2-slot].TunnelID {
					t.Fatal("retry changed selected path/owner or ran before commit")
				}
				if _, err := a.Authority.RemainingForApply(a.Identity, 2*time.Second); err != nil {
					t.Fatal("retry has no finite authority", err)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second {
					t.Fatal("unbounded standby initiation")
				}
				installed := map[string]time.Duration{}
				for k, v := range r.installed {
					installed[k] = v
				}
				candidateDeadline := a.Authority.deadline
				r.charge("standby_retry", 2*time.Second)
				if !reflect.DeepEqual(installed, r.installed) || a.Authority.deadline != candidateDeadline {
					t.Fatal("retry renewed permits/authority")
				}
				return errors.New("bounded attempt remains unobserved")
			}
			r.phase = "maintenance"
			results, err := r.c.maintainIPsecRuntimeObserved(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil)
			r.phase = ""
			if err != nil || len(results) != 5 || len(r.c.active) != 5 {
				t.Fatal("maintenance not qualified", len(results), err)
			}
			if attempts != 1 {
				t.Fatalf("missing configured spare did not get original bounded retry: attempts=%d", attempts)
			}
			if selectedRuntimeSlot(r.c.active[target].Entry) != uint8(slot) {
				t.Fatal("preempted healthy selection")
			}
			for a, d := range originals {
				if a.deadline != d {
					t.Fatal("extended original deadline")
				}
			}
			// The original per-delivery/tunnel30s backoff still gates another attempt.
			a := r.c.active[target]
			r.c.retryDownStandby(context.Background(), a.Entry, a.Authority, a.Identity)
			if attempts != 1 {
				t.Fatal("bypassed original backoff")
			}
			t.Logf("selected=%d attempts=%d page=%s remaining=%s work=%v", slot, attempts, *r.now, a.Authority.deadline-*r.now, r.charged)
		})
	}
}

func TestMaintainedStandbyInvalidInputsCannotInitiate(t *testing.T) {
	for _, scenario := range []string{"unknown", "already_up", "canceled", "qualification", "revoked", "expired", "wrong_owner"} {
		t.Run(scenario, func(t *testing.T) {
			r, target := maintainedMissingStandby(t, 2)
			attempts := 0
			r.c.recoveryInitiate = func(context.Context, EngineTunnel) error { attempts++; return nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := r.c.maintainIPsecRuntimeObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, func(_ context.Context, d RuntimeDelivery, _ RuntimeStatusReport) error {
				if d.Manifest.ConnectionID != target {
					return nil
				}
				switch scenario {
				case "unknown", "already_up":
					r.c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
						if e.Allocation.ConnectionID == target && scenario == "unknown" {
							return [2]string{"unknown", "up"}
						}
						return [2]string{"up", "up"}
					}
				case "canceled":
					cancel()
				case "qualification":
					r.c.qualification.invalid = true
				case "revoked":
					r.c.active[target].Authority.Invalidate()
				case "expired":
					r.charge("late_callback", 61*time.Second)
				case "wrong_owner":
					a := r.c.active[target]
					a.Entry.Allocation.ConnectionID = uuid.New()
					r.c.active[target] = a
				}
				return nil
			})
			if attempts != 0 {
				t.Fatal("invalid/healthy spare retried", scenario, attempts)
			}
			if scenario != "unknown" && scenario != "already_up" && (err == nil || len(result) != 0) {
				t.Fatal("invalid callback acknowledged", scenario)
			}
		})
	}
}

func TestMaintainedStandbyRetryCannotAcknowledgeExpiredCandidate(t *testing.T) {
	for _, scenario := range []string{"target_expiry", "earlier_owner_expiry", "canceled_during_retry"} {
		t.Run(scenario, func(t *testing.T) {
			r, target := maintainedMissingStandby(t, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempts := 0
			r.c.recoveryInitiate = func(context.Context, EngineTunnel) error {
				attempts++
				switch scenario {
				case "target_expiry":
					r.charge("retry_elapsed", 61*time.Second)
				case "earlier_owner_expiry":
					earliest := time.Duration(1<<63 - 1)
					for id, a := range r.c.active {
						if id != target && a.Authority.deadline < earliest {
							earliest = a.Authority.deadline
						}
					}
					*r.now = earliest + time.Millisecond
					a := r.c.active[target]
					if _, e := a.Authority.RemainingForApply(a.Identity, time.Millisecond); e != nil {
						t.Fatal("target must outlive earlier owner", e)
					}
				case "canceled_during_retry":
					cancel()
				}
				return nil
			}
			result, err := r.c.maintainIPsecRuntimeObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil)
			if attempts != 1 || err == nil || len(result) != 0 || len(r.c.active) != 0 {
				t.Fatal("retry latency escaped complete candidate validation", attempts, len(result), err, len(r.c.active))
			}
		})
	}
}
