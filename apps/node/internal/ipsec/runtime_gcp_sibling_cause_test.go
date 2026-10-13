package ipsec

import (
	"context"
	"crypto/sha256"
	"testing"
)

// Source-only modeled native/clock proof; no cloud cause attribution.
func TestGCPHACommitFreshnessChangeClassicSibling(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "stable", true: "HA_only_freshness_changes_after_eligibility"}[change], func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true, gcpMaintenancePair)
			classic := r.entries[1].Allocation.ConnectionID
			a := r.c.active[classic]
			a.StaticKeyDigest = sha256.Sum256([]byte(r.materials[1].Secrets[0].PSK))
			r.c.active[classic] = a
			r.phase = "maintenance"
			calls := 0
			out, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { calls++; return !change || calls <= 4 })
			if !change {
				if err != nil || len(out) != 2 || len(r.c.active) != 2 {
					t.Fatalf("stable pair rejected: outputs%d active%d err%v", len(out), len(r.c.active), err)
				}
				return
			}
			if err == nil || len(out) != 0 {
				t.Fatalf("HA freshness change was not refused: calls%d outputs%d err%v", calls, len(out), err)
			}
			if _, ok := r.c.active[classic]; ok {
				t.Fatal("expected current source global fail boundary to clear Classic")
			}
			if len(r.c.deniedClassicTransports) != 1 {
				t.Fatal("scoped late failure lost exact denied Classic transport")
			}
			t.Logf("HA-only post-eligibility freshness change reaches global fail; Classic active cleared; callback calls%d", calls)
		})
	}
}
