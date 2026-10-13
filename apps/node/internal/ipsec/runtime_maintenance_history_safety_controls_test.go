package ipsec

import (
	"context"
	"github.com/google/uuid"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestMaintenanceOptionalPulseCacheLossSafetyControls(t *testing.T) {
	for _, kind := range []string{"journal_directory_not_private", "invalid_current_recovery", "known_stale_history", "known_history_backward_clock", "missing_history_known_report_backward_clock", "missing_history_expired_native", "missing_history_unknown_table", "fresh_context_canceled"} {
		t.Run(kind, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			c, target := r.c, r.target
			old := map[uuid.UUID]runtimeActive{}
			deadlines := map[uuid.UUID]time.Duration{}
			native := map[string]time.Duration{}
			for id, a := range c.active {
				old[id] = a
				deadlines[id] = a.Authority.deadline
			}
			for name, end := range r.installed {
				native[name] = end
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "journal_directory_not_private":
				if err := os.Chmod(c.journal.dir, 0755); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(c.journal.dir, 0700)
			case "invalid_current_recovery":
				a := c.active[target]
				a.Entry.Recovery = nil
				c.active[target] = a
				delete(c.recoveryHistory, target)
			case "known_stale_history":
				c.recoveryHistory[target].epoch.Namespace = "net:[4026539999]"
			case "known_history_backward_clock":
				c.recoveryHistory[target].lastNow = time.Second
			case "missing_history_known_report_backward_clock":
				a := c.active[target]
				delete(c.recoveryHistory, target)
				c.recoveryStatusSequence = map[uuid.UUID]uint64{a.Entry.DeliveryID: 1}
				c.recoveryReportClocks = map[uuid.UUID]runtimeRecoveryReportClock{target: {epoch: recoveryReportEpoch(a), digest: a.Entry.OwnershipDigest, current: selectedRuntimeSlot(a.Entry), sequence: 1, returned: time.Second}}
				if _, known := c.recoveryReportClock(a); !known {
					t.Fatal("fixture clock not authoritative for exact current owner")
				}
			case "missing_history_expired_native":
				c.recoveryHistory = nil
				for _, name := range []string{guardLeaseName(target), guardReplyLeaseName(target), guardSALeaseName(target)} {
					r.installed[name] = 0
				}
			case "missing_history_unknown_table":
				c.recoveryHistory = nil
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) { return nil, ErrGuardRead }
			case "fresh_context_canceled":
				c.recoveryHistory = nil
				cancel()
			}
			positive := 0
			replace := c.replace
			c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if g.ID == target && !g.PrefixOnly && g.PermitFor > 0 && len(g.PermittedInterfaceIndices) > 0 {
						positive++
					}
				}
				return replace(ctx, in)
			}
			r.phase = "maintenance"
			out, err := c.maintainIPsecRuntimeRecoveryObserved(ctx, maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true }, nil, func(context.Context, RuntimeRecoveryHeartbeat) error { return nil })
			r.phase = ""
			if positive != 0 {
				t.Fatal("unsafe target received positive guard commit", kind)
			}
			for _, o := range out {
				if o.Acknowledgement.DeliveryID == old[target].Entry.DeliveryID {
					t.Fatal("unsafe target ACKed", kind)
				}
			}
			if kind == "fresh_context_canceled" {
				if err == nil || len(out) != 0 || len(c.active) != 5 || !reflect.DeepEqual(native, r.installed) || r.leases != 0 {
					t.Fatal("canceled fresh caller changed finite authority", err, len(out), len(c.active))
				}
			} else if kind == "missing_history_expired_native" {
				if _, active := c.active[target]; active {
					t.Fatal("expired target retained", err)
				}
			} else if kind == "missing_history_unknown_table" {
				// Unchanged core may omit every ineligible owner, commit only
				// denial, and return nil/zero results. No error-class promise
				// grants permission: exact active/ACK/native absence is required.
				if len(out) != 0 || len(c.active) != 0 || r.leases != 0 {
					t.Fatal("unknown table retained or renewed an owner", err, len(out), len(c.active), r.leases)
				}
				for id := range old {
					for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
						if r.installed[name] > *r.now {
							t.Fatal("unknown table left positive native member", id, name)
						}
					}
				}
			} else if err == nil || len(out) != 0 || len(c.active) != 0 {
				t.Fatal("invalid trusted/source/known-clock state bypassed global refusal", kind, err, len(out), len(c.active))
			}
			for id, a := range old {
				if a.Authority.deadline != deadlines[id] {
					t.Fatal("extended old authority", id)
				}
			}
			t.Logf("kind=%s error=%v results=%d active=%d targetPositiveCommits=%d freshCP=%d", kind, err, len(out), len(c.active), positive, r.leases)
		})
	}
}
