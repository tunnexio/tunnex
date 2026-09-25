package ipsec

import (
	"context"
	"testing"
	"time"
)

func TestRuntimeStandbyRetryDoesNotSelectOrGrantFromInitiation(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "down"}
	attempts := 0
	original := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		if !in.Connections[0].PrefixOnly {
			for _, index := range in.Connections[0].ReplyIngressIndices {
				if index == 11 {
					t.Fatal("initiation manufactured standby reply grant")
				}
			}
		}
		return original(ctx, in)
	}
	r.c.recoveryInitiate = func(ctx context.Context, tunnel EngineTunnel) error {
		attempts++
		if tunnel.TunnelID != r.m.Manifest.Tunnels[1].ID {
			t.Fatal("retried selected tunnel")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("unbounded retry")
		}
		return nil // This is not evidence of Up.
	}
	for _, at := range []time.Duration{0, 5 * time.Second, 10 * time.Second, 15 * time.Second, 20 * time.Second, 25 * time.Second, 30 * time.Second} {
		r.now = at
		if err := r.apply(); err != nil {
			t.Fatal(err)
		}
		if len(r.c.active) != 1 {
			t.Fatal("healthy selection withdrawn")
		}
		for _, a := range r.c.active {
			if selectedRuntimeSlot(a.Entry) != 1 {
				t.Fatal("standby retry selected route")
			}
		}
	}
	if attempts != 2 {
		t.Fatalf("expected bounded standby retries, got %d", attempts)
	}
	if r.switches > 1 {
		t.Fatal("standby retry switched selected route")
	}
}

func TestRuntimeStandbyRetryRejectsUncertainOrUnauthorizedPeer(t *testing.T) {
	for _, kind := range []string{"unknown", "selected-down", "lease"} {
		t.Run(kind, func(t *testing.T) {
			r := newRecoveryTestRig(t)
			r.status = [2]string{"up", "down"}
			attempts := 0
			r.c.recoveryInitiate = func(context.Context, EngineTunnel) error { attempts++; return nil }
			if kind == "unknown" {
				r.status[1] = "unknown"
			}
			if kind == "selected-down" {
				r.status = [2]string{"down", "up"}
			}
			if kind == "lease" {
				r.lease.deny = true
			}
			_ = r.apply()
			if attempts != 0 {
				t.Fatal("unsafe standby retry")
			}
		})
	}
}
