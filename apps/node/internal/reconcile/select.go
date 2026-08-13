package reconcile

import "log/slog"

// SelectBackend picks the data-plane backend. "wgctrl" uses the real WireGuard
// adapter (Linux, NET_ADMIN); anything else uses the in-memory backend. The real
// adapter is build-tagged so non-Linux builds still compile.
func SelectBackend(kind string, iface string, logger *slog.Logger) (WGBackend, error) {
	if kind == "wgctrl" {
		return newWGCtrlBackend(iface, logger)
	}
	return NewMemBackend(), nil
}
