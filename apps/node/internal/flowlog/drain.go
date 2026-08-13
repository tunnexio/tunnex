package flowlog

import (
	"context"
	"log/slog"
	"time"
)

// FlowReporter ships a drained batch to the control plane (control.Client satisfies it).
type FlowReporter interface {
	ReportFlows(ctx context.Context, events []Event, dropped int64) error
}

// DefaultDrainInterval is how often the drive drains the buffer and reports.
const DefaultDrainInterval = 5 * time.Second

// RunDrain periodically drains the pump and ships the batch. Best-effort + legibility-
// preserving: on a report FAILURE the drained events are NOT re-sent (no duplicate PG rows)
// — instead their count is CARRIED into the next report's `dropped`, so the CP writes a
// single "N events dropped" gap for the lost batch. Nothing here blocks enforcement; the
// pump keeps buffering (bounded) while reports fail. Returns when ctx is cancelled.
func RunDrain(ctx context.Context, pump *Pump, reporter FlowReporter, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = DefaultDrainInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var carried int64 // losses from prior failed reports, surfaced on the next one
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			events, dropped := pump.Drain()
			dropped += carried
			if len(events) == 0 && dropped == 0 {
				continue
			}
			if err := reporter.ReportFlows(ctx, events, dropped); err != nil {
				// The batch is lost; carry its size + the drop-count so the CP still writes a
				// gap next time. Do NOT re-buffer (would duplicate against a partially-ingested CP).
				carried = int64(len(events)) + dropped
				if logger != nil {
					logger.Warn("flowlog_report_failed", slog.String("error", err.Error()), slog.Int("events", len(events)), slog.Int64("carried_dropped", carried))
				}
				continue
			}
			carried = 0
		}
	}
}
