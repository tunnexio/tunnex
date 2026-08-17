package agentruntime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollUntilReturnsOnChangeBeforeBound(t *testing.T) {
	var calls atomic.Int32
	start := time.Now()
	cfg, unchanged, err := pollUntil(context.Background(), time.Second, 5*time.Millisecond, func() (Config, bool, error) {
		if calls.Add(1) >= 3 {
			return Config{Revision: 2}, false, nil
		}
		return Config{}, true, nil
	})
	if err != nil || unchanged || cfg.Revision != 2 {
		t.Fatalf("change result = cfg=%+v unchanged=%v err=%v", cfg, unchanged, err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("change waited for full bound: %s", elapsed)
	}
}

func TestPollUntilNoChangeHoldsToBound(t *testing.T) {
	var calls atomic.Int32
	const wait = 40 * time.Millisecond
	start := time.Now()
	_, unchanged, err := pollUntil(context.Background(), wait, 5*time.Millisecond, func() (Config, bool, error) {
		calls.Add(1)
		return Config{}, true, nil
	})
	if err != nil || !unchanged {
		t.Fatalf("no-change result = unchanged=%v err=%v", unchanged, err)
	}
	if elapsed := time.Since(start); elapsed < wait {
		t.Fatalf("no-change returned before bound: %s < %s", elapsed, wait)
	}
	if calls.Load() < 2 {
		t.Fatalf("ticker did not recheck: calls=%d", calls.Load())
	}
}

func TestPollUntilCancellationReleasesWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(15*time.Millisecond, cancel)
	start := time.Now()
	_, _, err := pollUntil(ctx, time.Second, 5*time.Millisecond, func() (Config, bool, error) {
		return Config{}, true, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("cancellation did not release wait: %s", elapsed)
	}
}

func TestDeriveRuntimeHealthUsesReportFreshnessAndLastGood(t *testing.T) {
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	old := now.Add(-RuntimeFreshnessWindow - time.Second)
	applyFailed := "apply_failed"
	tests := []struct {
		name                 string
		seen                 *time.Time
		desired, applied     int64
		lastError            *string
		connectivity, health string
		stale                bool
	}{
		{name: "never reported", desired: 1, connectivity: "unknown", health: "inconclusive", stale: true},
		{name: "fresh current", seen: &fresh, desired: 1, applied: 1, connectivity: "connected", health: "ready"},
		{name: "fresh revision lag", seen: &fresh, desired: 2, applied: 1, connectivity: "connected", health: "last_good"},
		{name: "fresh apply error", seen: &fresh, desired: 2, applied: 1, lastError: &applyFailed, connectivity: "connected", health: "last_good"},
		{name: "silent applied", seen: &old, desired: 1, applied: 1, connectivity: "disconnected", health: "last_good", stale: true},
		{name: "silent unconfigured", seen: &old, desired: 1, connectivity: "disconnected", health: "inconclusive", stale: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connectivity, health, stale := deriveRuntimeHealth(now, tt.seen, tt.desired, tt.applied, tt.lastError)
			if connectivity != tt.connectivity || health != tt.health || stale != tt.stale {
				t.Fatalf("got connectivity=%q health=%q stale=%v", connectivity, health, stale)
			}
		})
	}
}
