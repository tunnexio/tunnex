package ipsec

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A canceled, read-only recovery observation discards process-local advice.
// The following ordinary renewal starts with a NEW live context and still
// proves every original journal/native/authority boundary. This is a local
// maintained-core reproduction, not native Linux or live AWS qualification.
func TestMaintenanceOptionalPulseSurvivesCanceledObservationCacheLoss(t *testing.T) {
	for _, pulse := range []bool{false, true} {
		name := "without_optional_pulse_control"
		if pulse {
			name = "with_optional_pulse_regression"
		}
		t.Run(name, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			c := r.c
			if len(c.active) != 5 || len(c.recoveryHistory) != 2 {
				t.Fatal("fixture lacks five owners/two genuine histories")
			}
			before, err := c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			authorities := map[uuid.UUID]*PermitLeaseAuthority{}
			for id, a := range c.active {
				authorities[id] = a.Authority
				if c.maintenanceGuard(context.Background(), a.Entry) != nil {
					t.Fatal("initial native guard not healthy", id)
				}
				if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
					t.Fatal("initial authority not healthy", id, err)
				}
				if a.Entry.ContractVersion == 2 && (!validJournalRecovery(a.Entry) || a.Entry.Recovery.Stage != "completed" || !validRecoveryEpoch(recoveryReportEpoch(a))) {
					t.Fatal("invalid trusted static epoch", id)
				}
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if c.RefreshIPsecRecovery(canceled) == nil {
				t.Fatal("canceled observation unexpectedly succeeded")
			}
			after, err := c.journal.Entries()
			if err != nil || !reflect.DeepEqual(before, after) || c.recoveryHistory != nil || len(c.active) != 5 {
				t.Fatal("cache-loss precondition changed trusted owners/journal", err)
			}
			for id, a := range c.active {
				if a.Authority != authorities[id] || c.maintenanceGuard(context.Background(), a.Entry) != nil {
					t.Fatal("canceled telemetry altered original authority/native guard", id)
				}
			}
			var events []RuntimeDiagnostic
			c.config.Diagnostic = func(e RuntimeDiagnostic) { events = append(events, e) }
			replace := c.replace
			positive, denial := 0, 0
			c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				permitting := false
				for _, g := range in.Connections {
					if !g.PrefixOnly && g.PermitFor > 0 && len(g.PermittedInterfaceIndices) > 0 {
						permitting = true
					}
				}
				if permitting {
					positive++
				} else {
					denial++
				}
				return replace(ctx, in)
			}
			var publishRecovery func(context.Context, RuntimeRecoveryHeartbeat) error
			pulses := 0
			if pulse {
				publishRecovery = func(context.Context, RuntimeRecoveryHeartbeat) error { pulses++; return nil }
			}
			r.phase = "maintenance"
			results, err := c.maintainIPsecRuntimeRecoveryObserved(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil, publishRecovery)
			r.phase = ""
			historyRefused := false
			for _, e := range events {
				if e.Operation == "maintenance_pulse" && e.Stage == "history" && e.Refused && e.ConnectionID == uuid.Nil && e.ContextState == "active" {
					historyRefused = true
				}
			}
			deniedOwners := 0
			for id := range authorities {
				if r.installed[guardLeaseName(id)] <= *r.now || r.installed[guardReplyLeaseName(id)] <= *r.now || r.installed[guardSALeaseName(id)] <= *r.now {
					deniedOwners++
				}
			}
			t.Logf("pulse=%t results=%d active=%d freshCP=%d positiveCommits=%d denialCommits=%d deniedOwners=%d pulseReports=%d historyRefused=%t elapsed=%s err=%v", pulse, len(results), len(c.active), r.leases, positive, denial, deniedOwners, pulses, historyRefused, *r.now, err)
			if err != nil || len(results) != 5 || len(c.active) != 5 || positive != 1 || denial != 0 || r.leases != 5 {
				t.Fatalf("optional observational cache loss must not stop independently validated five-owner renewal: results=%d active=%d freshCP=%d positive=%d denial=%d deniedOwners=%d historyRefused=%t err=%v", len(results), len(c.active), r.leases, positive, denial, deniedOwners, historyRefused, err)
			}
			for id, a := range c.active {
				if a.Authority == authorities[id] || c.maintenanceGuard(context.Background(), a.Entry) != nil {
					t.Fatal("successful renewal lacked fresh CP/native authority", id)
				}
			}
		})
	}
}
