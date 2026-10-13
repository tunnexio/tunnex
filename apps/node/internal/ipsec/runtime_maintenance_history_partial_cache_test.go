package ipsec

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestMaintenanceOptionalPulsePartialCacheStillSamplesValidOwner(t *testing.T) {
	for _, kind := range []string{"missing_one_history", "unseen_one_history"} {
		t.Run(kind, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			c, target := r.c, r.target
			other := uuid.Nil
			for id, a := range c.active {
				if a.Entry.ContractVersion == 2 && id != target {
					other = id
				}
			}
			if other == uuid.Nil {
				t.Fatal("missing second valid static owner")
			}
			if kind == "missing_one_history" {
				delete(c.recoveryHistory, target)
			} else {
				c.recoveryHistory[target] = &recoveryDecision{}
			}
			r.charge("due", 3*time.Second)
			for id, a := range c.active {
				if c.maintenanceGuard(context.Background(), a.Entry) != nil {
					t.Fatal("initial full5 native guard not positive", id)
				}
			}
			validPulses := 0
			// The shared fixture counts telemetry nonce requests as leases during
			// maintenance. Count the core renewal factory independently.
			freshApply := 0
			newAuthority := maintenanceAuthority(r)
			coreAuthority := func() *PermitLeaseAuthority {
				freshApply++
				return newAuthority()
			}
			r.phase = "maintenance"
			out, err := c.maintainIPsecRuntimeRecoveryObserved(context.Background(), maintenanceMaterials(r), coreAuthority, func() bool { return true }, nil, func(_ context.Context, h RuntimeRecoveryHeartbeat) error {
				if h.ConnectionID != other || h.Report.ActiveSlot == nil || *h.Report.ActiveSlot != int(selectedRuntimeSlot(c.active[other].Entry)) || h.Report.SelectionSequence == nil || h.Report.Tunnels[*h.Report.ActiveSlot-1].Status != "up" {
					t.Fatal("missing/unseen cache fabricated positive observation or blocked valid owner", h.ConnectionID)
				}
				validPulses++
				return nil
			})
			r.phase = ""
			if err != nil || len(out) != 5 || len(c.active) != 5 || freshApply != 5 || r.leases != freshApply+validPulses || validPulses == 0 {
				t.Fatal("partial advice absence blocked healthy core/other genuine pulse", kind, err, len(out), len(c.active), freshApply, r.leases, validPulses)
			}
			for id, a := range c.active {
				if c.maintenanceGuard(context.Background(), a.Entry) != nil {
					t.Fatal("finite final native permit lost", id)
				}
			}
			t.Logf("kind=%s active5 results=%d freshApply=%d totalCP=%d validOtherPulses=%d elapsed=%s", kind, len(out), freshApply, r.leases, validPulses, *r.now)
		})
	}
}
