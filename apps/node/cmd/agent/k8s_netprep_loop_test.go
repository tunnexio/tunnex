package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestK8sNetPrepObservationWindowIsBoundedBelowFullEgressInterval(t *testing.T) {
	if observedReadyzWindow := k8sNetPrepPollInterval + readinessPollInterval; observedReadyzWindow > 5*time.Second {
		t.Fatalf("network-preparation readiness observation window=%s, want <=5s", observedReadyzWindow)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		k8sNetPrepLoop(ctx, 5*time.Millisecond, func(context.Context) error {
			if calls.Add(1) == 3 {
				cancel() // initial ready, observed loss, then self-heal
			}
			return nil
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("short network-preparation observer did not make progress")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("network-preparation observations=%d, want 3", got)
	}
}
