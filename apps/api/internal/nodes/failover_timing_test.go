package nodes

import (
	"testing"
	"time"
)

// SSI-11 D1: the served timing is the controller's own constants, in whole seconds. If someone retunes the
// controller, the dashboard follows without a second edit; if someone hard-codes a number here, this fails.
func TestFailoverTimingDerivesFromControllerConstants(t *testing.T) {
	got := FailoverTimings()
	if want := int(failoverStaleWindow / time.Second); got.StaleAfterSeconds != want {
		t.Fatalf("stale_after = %d, want %d", got.StaleAfterSeconds, want)
	}
	if want := failoverDemoteTicks * int(FailoverTickInterval/time.Second); got.DemoteAfterSeconds != want {
		t.Fatalf("demote_after = %d, want %d", got.DemoteAfterSeconds, want)
	}
	if want := failoverRestoreTicks * int(FailoverTickInterval/time.Second); got.RestoreAfterSeconds != want {
		t.Fatalf("restore_after = %d, want %d", got.RestoreAfterSeconds, want)
	}
	if got.RestoreAfterSeconds <= got.DemoteAfterSeconds {
		t.Fatalf("fail-back must be slower than fail-over: restore %d, demote %d", got.RestoreAfterSeconds, got.DemoteAfterSeconds)
	}
}
