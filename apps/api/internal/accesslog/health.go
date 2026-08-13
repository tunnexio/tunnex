package accesslog

import (
	"sync"
	"time"
)

// Health is the LEGIBLE operational surface for the access-log subsystem (D3 retention
// legibility). The retention sweep records here so an operator has one place that shows
// "events were dropped for disk" / "the sweep is failing". Read by a health endpoint.
//
// NOTE (S7.5.1b): the JSONL source-of-truth write-failure signals lived here too; they were
// removed with the deferred JSONL writer rather than left as dead-always-green fields.
type Health struct {
	mu sync.Mutex

	// Retention: the drop-oldest sweep must alarm somewhere a human looks.
	retentionLastSweep time.Time
	retentionDropped   int64 // rows deleted by the last sweep (age + cap)
	retentionFailed    bool  // the last sweep ERRORED (partial/failed) — else a stale timestamp hides it
}

// Snapshot is a read-only view of Health for a health/admin endpoint.
type Snapshot struct {
	RetentionLastSweep time.Time `json:"retention_last_sweep,omitempty"`
	RetentionDropped   int64     `json:"retention_dropped"`
	RetentionFailed    bool      `json:"retention_failed"`
}

// NewHealth returns a zero-value Health (nothing degraded).
func NewHealth() *Health { return &Health{} }

// recordSweep records a retention sweep's result — ALWAYS called (even on a failed/partial
// sweep) so the surface never shows a stale healthy-looking timestamp while retention is broken.
func (h *Health) recordSweep(now time.Time, dropped int64, err error) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retentionLastSweep = now
	h.retentionDropped = dropped
	h.retentionFailed = err != nil
}

// Snapshot returns the current health for display.
func (h *Health) Snapshot() Snapshot {
	if h == nil {
		return Snapshot{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return Snapshot{
		RetentionLastSweep: h.retentionLastSweep,
		RetentionDropped:   h.retentionDropped,
		RetentionFailed:    h.retentionFailed,
	}
}
