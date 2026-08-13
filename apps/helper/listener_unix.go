//go:build !windows

package helper

import (
	"net"
	"os"
	"path/filepath"
)

// DefaultSocketPath is the unix-domain socket the helper listens on (matches the
// TS helperSocketPath in apps/client).
func DefaultSocketPath() string { return "/var/run/tunnex/helper.sock" }

// NewListener creates the helper's local IPC endpoint. The helper runs as ROOT
// (a LaunchDaemon), but the desktop app connecting to it is UNPRIVILEGED — so the
// socket must be reachable by a normal user. It is therefore world-connectable
// (0666 in a traversable 0755 dir), and CALLER IDENTITY is enforced by the
// PeerResolver + CallerVerifier (LOCAL_PEERPID → exe-inside-install-dir), NOT by
// filesystem permissions. This mirrors the Windows model (the SDDL lets
// Authenticated Users connect; the caller-path check authorizes). Any local user
// can open the socket but is rejected unless their process is a trusted Tunnex
// binary; the connection cap bounds the flood surface. A stale socket is removed.
func NewListener(socketPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(socketPath) // clear a stale socket
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}
