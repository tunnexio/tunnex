package main

import "log/slog"

// Join IPsec withdrawal while WireGuard interface identities still exist. Even
// a refused/timed-out withdrawal must not leave WireGuard forwarding headless.
func shutdownDataplane(shutdownIPsec, shutdownWG func() error, logger *slog.Logger) {
	if err := shutdownIPsec(); err != nil {
		logger.Error("ipsec_runtime_shutdown_incomplete")
	}
	if shutdownWG != nil {
		if err := shutdownWG(); err != nil {
			logger.Error("agent_backend_shutdown_blocked", slog.String("error", err.Error()))
		}
	}
}
