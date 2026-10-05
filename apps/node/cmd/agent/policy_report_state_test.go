package main

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakePolicyReportOutcome struct {
	version      int
	hash         string
	failingSince time.Time
	applyErr     error
	refused      int
	flushFailing bool
	endpointsBad bool
}

func (f *fakePolicyReportOutcome) AppliedStatus() (int, string, time.Time, error) {
	return f.version, f.hash, f.failingSince, f.applyErr
}

func (f *fakePolicyReportOutcome) RefusedVersion() int         { return f.refused }
func (f *fakePolicyReportOutcome) ConntrackFlushFailing() bool { return f.flushFailing }
func (f *fakePolicyReportOutcome) EndpointsUnavailable() bool  { return f.endpointsBad }

func assertPolicyReportWake(t *testing.T, wake <-chan struct{}, want bool) {
	t.Helper()
	select {
	case <-wake:
		if !want {
			t.Fatal("unchanged reported outcome queued a wake")
		}
	default:
		if want {
			t.Fatal("changed reported outcome did not queue a wake")
		}
	}
	select {
	case <-wake:
		t.Fatal("one outcome change queued more than one wake")
	default:
	}
}

func TestPolicyReportWakeOnActualAppliedHashTransition(t *testing.T) {
	source := &fakePolicyReportOutcome{version: 1, hash: "old-applied-hash"}
	var nat, ipv6 atomic.Bool
	wake := make(chan struct{}, 1)
	err := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
		// A new policy can retain the same wire version while its applied hash changes.
		source.hash = "new-applied-hash"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyReportWake(t, wake, true)
}

func TestPolicyReportWakeOnFailedApplyKeepsActualHash(t *testing.T) {
	source := &fakePolicyReportOutcome{version: 1, hash: "last-successful-hash"}
	var nat, ipv6 atomic.Bool
	wake := make(chan struct{}, 1)
	applyErr := errors.New("replacement apply failed")
	onset := time.Date(2026, time.October, 5, 12, 0, 0, 0, time.UTC)
	got := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
		// Failed replacement changes diagnostics, leaving the last successful apply in force.
		source.applyErr, source.failingSince = applyErr, onset
		return applyErr
	})
	if got != applyErr {
		t.Fatalf("apply error = %v, want original error %v", got, applyErr)
	}
	assertPolicyReportWake(t, wake, true)
	state := snapshotPolicyReportState(source, &nat, &ipv6)
	if state.hash != "last-successful-hash" || state.version != 1 || state.applyError != applyErr.Error() || !state.failingSince.Equal(onset) {
		t.Fatalf("failed apply report lost actual status: %+v", state)
	}
	got = reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error { return applyErr })
	if got != applyErr {
		t.Fatalf("repeated apply error = %v, want %v", got, applyErr)
	}
	assertPolicyReportWake(t, wake, false)
}

func TestPolicyReportWakeSkipsNoOpAndEquivalentError(t *testing.T) {
	for _, withError := range []bool{false, true} {
		t.Run(fmt.Sprintf("with_error=%v", withError), func(t *testing.T) {
			source := &fakePolicyReportOutcome{version: 1, hash: "applied-hash"}
			var applyErr error
			if withError {
				source.applyErr = errors.New("same failure")
				applyErr = errors.New("same failure")
			}
			var nat, ipv6 atomic.Bool
			wake := make(chan struct{}, 1)
			calls := 0
			got := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
				calls++
				source.applyErr = applyErr
				return applyErr
			})
			if calls != 1 || got != applyErr {
				t.Fatalf("apply calls=%d error=%v, want one call and %v", calls, got, applyErr)
			}
			assertPolicyReportWake(t, wake, false)
		})
	}
}

func TestPolicyReportWakeSamplesRefusalBeforePolicyMutation(t *testing.T) {
	source := &fakePolicyReportOutcome{version: 1, hash: "last-successful-hash"}
	var nat, ipv6 atomic.Bool
	wake := make(chan struct{}, 1)
	if err := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
		// SetPolicy rejects the unsupported artifact before the apply phase.
		source.refused = 2
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertPolicyReportWake(t, wake, true)
	state := snapshotPolicyReportState(source, &nat, &ipv6)
	if state.refusedVersion != 2 || state.hash != "last-successful-hash" {
		t.Fatalf("refusal claimed a replacement apply: %+v", state)
	}
	if err := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertPolicyReportWake(t, wake, false)
}

func TestPolicyReportWakeOnOutcomeRecovery(t *testing.T) {
	for _, name := range []string{"apply error", "refusal", "conntrack flush", "endpoints", "egress NAT", "egress IPv6"} {
		t.Run(name, func(t *testing.T) {
			source := &fakePolicyReportOutcome{version: 1, hash: "applied-hash"}
			var nat, ipv6 atomic.Bool
			nat.Store(true)
			ipv6.Store(true)
			switch name {
			case "apply error":
				source.applyErr = errors.New("apply failed")
				source.failingSince = time.Date(2026, time.October, 5, 12, 0, 0, 0, time.UTC)
			case "refusal":
				source.refused = 2
			case "conntrack flush":
				source.flushFailing = true
			case "endpoints":
				source.endpointsBad = true
			case "egress NAT":
				nat.Store(false)
			case "egress IPv6":
				ipv6.Store(false)
			}
			wake := make(chan struct{}, 1)
			if err := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
				source.applyErr, source.failingSince = nil, time.Time{}
				source.refused, source.flushFailing, source.endpointsBad = 0, false, false
				nat.Store(true)
				ipv6.Store(true)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			assertPolicyReportWake(t, wake, true)
			if source.hash != "applied-hash" {
				t.Fatal("diagnostic recovery changed the actual applied hash")
			}
		})
	}
}

func TestPolicyReportWakeIgnoresErrorDifferencePastReportedBound(t *testing.T) {
	prefix := strings.Repeat("x", 300)
	source := &fakePolicyReportOutcome{version: 1, hash: "applied-hash", applyErr: errors.New(prefix + "first suffix")}
	var nat, ipv6 atomic.Bool
	wake := make(chan struct{}, 1)
	applyErr := errors.New(prefix + "different suffix")
	got := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
		source.applyErr = applyErr
		return applyErr
	})
	if got != applyErr {
		t.Fatalf("apply error = %v, want original error", got)
	}
	assertPolicyReportWake(t, wake, false)
	if got := snapshotPolicyReportState(source, &nat, &ipv6).applyError; got != prefix {
		t.Fatalf("reported error length=%d, want unchanged 300-byte prefix", len(got))
	}
}

func TestPolicyReportWakeCoalescesBufferedBurstWithoutBlocking(t *testing.T) {
	source := &fakePolicyReportOutcome{version: 1, hash: "initial-hash"}
	var nat, ipv6 atomic.Bool
	wake := make(chan struct{}, 1)
	wake <- struct{}{}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 16; i++ {
			if err := reconcileWithPolicyReportWake(source, &nat, &ipv6, wake, func() error {
				source.hash = fmt.Sprintf("applied-hash-%d", i)
				return nil
			}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("outcome changes blocked behind an already buffered wake")
	}
	assertPolicyReportWake(t, wake, true)
}
