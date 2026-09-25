package ipsec

import (
	"github.com/google/uuid"
	"sync"
	"testing"
	"time"
)

func TestRecoveryMetricsOnceAfterVerifiedCompletion(t *testing.T) {
	var m RecoveryMetrics
	id := uuid.New()
	start := time.Now()
	m.complete(id, 1, start)
	if m.Snapshot().Completed != 0 {
		t.Fatal("no observed attempt manufactured completion")
	}
	m.begin(id, 1, start)
	m.begin(id, 1, start.Add(time.Second))
	m.refuse(id, 1)
	m.refuse(id, 1)
	if got := m.Snapshot(); got.Attempts != 1 || got.Refused != 1 || got.Completed != 0 {
		t.Fatal(got)
	}
	m.complete(id, 1, start.Add(2*time.Second))
	m.complete(id, 1, start.Add(3*time.Second))
	m.refuse(id, 1)
	got := m.Snapshot()
	if got.Attempts != 1 || got.Refused != 1 || got.Completed != 1 || got.CompletedDuration != 2*time.Second {
		t.Fatal(got)
	}
	got.Attempts = 500
	if m.Snapshot().Attempts != 1 {
		t.Fatal("snapshot mutable")
	}
	m.begin(id, 2, start)
	m.complete(id, 1, start.Add(time.Second))
	m.complete(id, 2, start.Add(time.Second))
	if got := m.Snapshot(); got.Attempts != 2 || got.Completed != 2 {
		t.Fatal(got)
	}
}
func TestRecoveryMetricsBoundedAndConcurrent(t *testing.T) {
	var m RecoveryMetrics
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := uuid.New()
			m.begin(id, 1, start)
			m.complete(id, 1, start.Add(time.Second))
			_ = m.Snapshot()
		}()
	}
	wg.Wait()
	if got := m.Snapshot(); got.Attempts != 256 || got.Completed != 256 || got.CompletedDuration != 256*time.Second {
		t.Fatal(got)
	}
}
func TestRecoveryMetricsSaturatesAndRejectsClockRegression(t *testing.T) {
	var m RecoveryMetrics
	id := uuid.New()
	now := time.Now()
	m.begin(id, 1, now)
	m.complete(id, 1, now.Add(-time.Second))
	if m.Snapshot().CompletedDuration != 0 {
		t.Fatal("negative duration accumulated")
	}
	m.snapshot.Attempts = ^uint64(0)
	m.snapshot.CompletedDuration = time.Duration(1<<63 - 1)
	m.begin(id, 2, now)
	m.complete(id, 2, now.Add(time.Second))
	if got := m.Snapshot(); got.Attempts != ^uint64(0) || got.CompletedDuration != time.Duration(1<<63-1) {
		t.Fatal("overflow", got)
	}
}

func TestRecoveryMetricsControllerPermitFailureAndRetry(t *testing.T) {
	r := newRecoveryTestRig(t)
	_ = r.apply()
	r.now = 5 * time.Second
	_ = r.apply()
	if got := r.c.RecoveryMetricsSnapshot(); got.Attempts != 0 {
		t.Fatal("hold-down poll counted switch", got)
	}
	r.now = 10 * time.Second
	r.permitErr = true
	if r.apply() == nil {
		t.Fatal("permit refusal missing")
	}
	if got := r.c.RecoveryMetricsSnapshot(); got.Attempts != 1 || got.Refused != 1 || got.Completed != 0 {
		t.Fatal("completion preceded permit", got)
	}
	r.now = 15 * time.Second
	r.permitErr = false
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	r.now = 20 * time.Second
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	if got := r.c.RecoveryMetricsSnapshot(); got.Attempts != 1 || got.Refused != 1 || got.Completed != 1 {
		t.Fatal("retry or poll double counted", got)
	}
}
