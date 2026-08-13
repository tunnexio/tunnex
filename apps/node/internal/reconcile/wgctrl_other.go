//go:build !linux

package reconcile

import (
	"fmt"
	"log/slog"
	"runtime"
)

// newWGCtrlBackend is unavailable off Linux — the real WireGuard data plane
// needs kernel/userspace WG and NET_ADMIN, which only the Linux node image has.
// Non-Linux builds still compile (the mem backend remains available); selecting
// "wgctrl" here fails loudly rather than silently no-op'ing.
func newWGCtrlBackend(_ string, _ *slog.Logger) (WGBackend, error) {
	return nil, fmt.Errorf("wgctrl backend not supported on %s (Linux only)", runtime.GOOS)
}
