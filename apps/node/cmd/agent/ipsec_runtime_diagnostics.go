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
		if event.DNSReadTiming != nil {
			attrs = []any{"operation", event.Operation, "stage", event.Stage, "elapsed_ms", event.ElapsedMillis, "context_state", event.ContextState}
			attrs = append(attrs, "guard_bracket_count", event.DNSReadTiming.GuardBracketCount, "guard_command_ms", event.DNSReadTiming.GuardCommandMillis, "guard_verification_ms", event.DNSReadTiming.GuardVerificationMillis, "guard_failure_class", event.DNSReadTiming.GuardFailureClass, "socket_ms", event.DNSReadTiming.SocketMillis, "socket_stage", event.DNSReadTiming.SocketStage, "guard_revalidation", event.DNSReadTiming.GuardRevalidation, "native_failure_class", event.DNSReadTiming.NativeFailureClass, "native_route_ms", event.DNSReadTiming.Native.RouteMillis, "native_recovery_ms", event.DNSReadTiming.Native.RecoveryMillis, "native_environment_ms", event.DNSReadTiming.Native.EnvironmentMillis, "native_elapsed_ms", event.DNSReadTiming.Native.ElapsedMillis, "native_remaining_at_entry_ms", event.DNSReadTiming.Native.RemainingAtEntryMillis, "native_environment_command_ms", event.DNSReadTiming.Native.Environment.CommandMillis, "native_environment_verification_ms", event.DNSReadTiming.Native.Environment.VerificationMillis, "native_environment_command_count", event.DNSReadTiming.Native.Environment.CommandCount)
		}
		if event.Refused {
			logger.Warn("ipsec_runtime_diagnostic_refused", attrs...)
		} else if dnsLabTiming && event.Operation == "dns_exchange" {
			logger.Info("ipsec_runtime_diagnostic_completed", attrs...)
		} else {
			logger.Debug("ipsec_runtime_diagnostic_completed", attrs...)
		}
	}
}
