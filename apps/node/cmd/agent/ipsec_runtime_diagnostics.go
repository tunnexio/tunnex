package main

import (
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"log/slog"
)

// The owned-lab opt-in exposes only fixed DNS phase timings. Default logging
// and all other diagnostics retain their existing levels and fields.
func ipsecDiagnosticSink(logger *slog.Logger, dnsLabTiming bool) func(ipsec.RuntimeDiagnostic) {
	return func(event ipsec.RuntimeDiagnostic) {
		attrs := []any{"operation", event.Operation, "stage", event.Stage, "connection_id", event.ConnectionID.String(), "elapsed_ms", event.ElapsedMillis, "context_state", event.ContextState}
		if event.Refused {
			logger.Warn("ipsec_runtime_diagnostic_refused", attrs...)
		} else if dnsLabTiming && event.Operation == "dns_exchange" {
			logger.Info("ipsec_runtime_diagnostic_completed", attrs...)
		} else {
			logger.Debug("ipsec_runtime_diagnostic_completed", attrs...)
		}
	}
}
