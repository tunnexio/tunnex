package reconcile

import (
	"fmt"
	"log/slog"
)

// BackendOptions carries lifecycle ownership decided by the caller. A deep
// data-plane package must not infer Kubernetes ownership from process env.
type BackendOptions struct {
	PreserveInterfaceAlias string
	// WireGuardMTUCap only lowers a positive desired MTU; zero leaves it uncapped.
	WireGuardMTUCap int
}

// SelectBackend picks the data-plane backend. "wgctrl" uses the real WireGuard
// adapter (Linux, NET_ADMIN); anything else uses the in-memory backend. The real
// adapter is build-tagged so non-Linux builds still compile.
func SelectBackend(kind string, iface string, logger *slog.Logger) (WGBackend, error) {
	return SelectBackendWithOptions(kind, iface, logger, BackendOptions{})
}

// SelectBackendWithOptions selects a backend with an explicit host lifecycle
// contract. PreserveInterfaceAlias makes wgctrl adopt and preserve only the
// exact manager-owned interface instead of creating/deleting it itself.
func SelectBackendWithOptions(kind string, iface string, logger *slog.Logger, options BackendOptions) (WGBackend, error) {
	if options.WireGuardMTUCap != 0 && (options.WireGuardMTUCap < 1280 || options.WireGuardMTUCap > 1420) {
		return nil, fmt.Errorf("WireGuard MTU cap must be between 1280 and 1420, or zero when unset")
	}
	if kind == "wgctrl" {
		return newWGCtrlBackend(iface, logger, options)
	}
	return NewMemBackend(), nil
}
