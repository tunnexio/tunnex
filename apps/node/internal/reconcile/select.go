package reconcile

import "log/slog"

// BackendOptions carries lifecycle ownership decided by the caller. A deep
// data-plane package must not infer Kubernetes ownership from process env.
type BackendOptions struct {
	PreserveInterfaceAlias string
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
	if kind == "wgctrl" {
		return newWGCtrlBackend(iface, logger, options)
	}
	return NewMemBackend(), nil
}
