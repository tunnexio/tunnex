package ipsec

import (
	"github.com/google/uuid"
	"sync"
	"time"
)

// RecoveryMetricsSnapshot is process-local observation, never runtime authority.
// No exporter or transport is registered. Refused counts attempts that suffered
// at least one refusal; a later successful retry may also count as completed.
type RecoveryMetricsSnapshot struct {
	Attempts          uint64
	Completed         uint64
	Refused           uint64
	CompletedDuration time.Duration
}

type recoveryMetricAttempt struct {
	sequence           uint64
	started            time.Time
	refused, completed bool
}

// RecoveryMetrics bounds internal deduplication by the journal's 256 delivery
// limit. Identifiers are never returned, labeled, logged or persisted.
type RecoveryMetrics struct {
	mu       sync.Mutex
	snapshot RecoveryMetricsSnapshot
	attempts map[uuid.UUID]recoveryMetricAttempt
}

func (m *RecoveryMetrics) begin(id uuid.UUID, sequence uint64, now time.Time) {
	if id == uuid.Nil || sequence == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.attempts[id]
	if ok && old.sequence >= sequence {
		return
	}
	if !ok && len(m.attempts) >= 256 {
		return
	}
	if m.attempts == nil {
		m.attempts = make(map[uuid.UUID]recoveryMetricAttempt)
	}
	m.attempts[id] = recoveryMetricAttempt{sequence: sequence, started: now}
	incrementRecoveryCounter(&m.snapshot.Attempts)
}
func (m *RecoveryMetrics) refuse(id uuid.UUID, sequence uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[id]
	if !ok || a.sequence != sequence || a.completed || a.refused {
		return
	}
	a.refused = true
	m.attempts[id] = a
	incrementRecoveryCounter(&m.snapshot.Refused)
}
func (m *RecoveryMetrics) complete(id uuid.UUID, sequence uint64, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[id]
	if !ok || a.sequence != sequence || a.completed {
		return
	}
	a.completed = true
	m.attempts[id] = a
	incrementRecoveryCounter(&m.snapshot.Completed)
	duration := now.Sub(a.started)
	if duration > 0 {
		const maxDuration = time.Duration(1<<63 - 1)
		if duration > maxDuration-m.snapshot.CompletedDuration {
			m.snapshot.CompletedDuration = maxDuration
		} else {
			m.snapshot.CompletedDuration += duration
		}
	}
}
func incrementRecoveryCounter(v *uint64) {
	if *v != ^uint64(0) {
		*v++
	}
}
func (m *RecoveryMetrics) Snapshot() RecoveryMetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot
}
func (c *RuntimeController) RecoveryMetricsSnapshot() RecoveryMetricsSnapshot {
	if c == nil {
		return RecoveryMetricsSnapshot{}
	}
	return c.recoveryMetrics.Snapshot()
}
