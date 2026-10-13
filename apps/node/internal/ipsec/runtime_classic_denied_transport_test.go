package ipsec

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeniedClassicTransportContainsNoAuthorityAndRejectsExpiredCapture(t *testing.T) {
	for _, expired := range []bool{false, true} {
		r := newRenewalCycleRigInput(t, true, gcpMaintenancePair)
		id := r.entries[1].Allocation.ConnectionID
		a := r.c.active[id]
		a.StaticKeyDigest = sha256.Sum256([]byte(r.materials[1].Secrets[0].PSK))
		if expired {
			a.Authority.Invalidate()
		}
		r.c.active[id] = a
		hints := r.c.rememberDeniedClassicTransports(r.entries)
		if expired {
			if len(hints) != 0 {
				t.Fatal("expired original authority retained continuity")
			}
			continue
		}
		if len(hints) != 1 {
			t.Fatal("exact committed Classic hint missing")
		}
		raw, err := json.Marshal(hints[id])
		if err != nil || strings.Contains(string(raw), "Authority") || strings.Contains(string(raw), r.materials[1].Secrets[0].PSK) {
			t.Fatal("hint retained authority or secret")
		}
		hints[id].Environment.LocalIngressIndices[0] = 999
		if r.c.active[id].Environment.LocalIngressIndices[0] == 999 {
			t.Fatal("hint aliases mutable published state")
		}
	}
}
func TestLateUnknownMaintenanceFailureDoesNotRetainTransport(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenancePair)
	id := r.entries[1].Allocation.ConnectionID
	a := r.c.active[id]
	a.StaticKeyDigest = sha256.Sum256([]byte(r.materials[1].Secrets[0].PSK))
	r.c.active[id] = a
	r.c.deniedClassicTransports = r.c.rememberDeniedClassicTransports(r.entries)
	bad := append([]RuntimeMaterial{}, r.materials...)
	bad[1].Secrets[1] = RuntimeSecret{PSK: "forbidden inactive credential"}
	if _, err := r.c.maintainIPsecRuntime(context.Background(), bad, maintenanceAuthority(r), func() bool { return true }); err == nil || len(r.c.deniedClassicTransports) != 0 {
		t.Fatal("unknown material failure retained transport recovery hint")
	}
}

func TestDeniedClassicTransportUnknownEarlyFailureClearsHint(t *testing.T) {
	for _, mode := range []string{"journal", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true, gcpMaintenancePair)
			id := r.entries[1].Allocation.ConnectionID
			a := r.c.active[id]
			a.StaticKeyDigest = sha256.Sum256([]byte(r.materials[1].Secrets[0].PSK))
			r.c.active[id] = a
			r.c.deniedClassicTransports = r.c.rememberDeniedClassicTransports(r.entries)
			ctx := context.Background()
			if mode == "journal" {
				r.c.journal.poisoned = true
			} else {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, err := r.c.maintainIPsecRuntime(ctx, r.materials, maintenanceAuthority(r), func() bool { return true }); err == nil || len(r.c.deniedClassicTransports) != 0 {
				t.Fatal("early unknown failure retained hint")
			}
		})
	}
}
