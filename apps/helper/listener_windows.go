//go:build windows

package helper

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// DefaultSocketPath is the named pipe the helper listens on (matches the TS
// helperSocketPath in apps/client).
func DefaultSocketPath() string { return `\\.\pipe\tunnex-helper` }

// pipeSDDL is the security descriptor on the helper's named pipe.
//
// ENGLISH INTENT: SYSTEM (SY) and the local Administrators group (BA) get full
// control (GenericAll); any Authenticated User (AU) may CONNECT and read/write
// (GenericRead+GenericWrite) so the UNPRIVILEGED desktop app — running as the
// logged-in user, not admin — can reach the pipe at all. The DACL is Protected
// (P) so it does NOT inherit looser parent ACEs. Access alone is NOT authorization:
// which PROCESS may drive the helper is decided by the caller-path check
// (GetNamedPipeClientProcessId → image inside the install dir). So a non-Tunnex
// authenticated process CAN open the pipe but is refused with caller_untrusted —
// see the refused-client smoke step (PLAN "S6.3 Windows pipe SDDL").
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

// NewListener creates the SDDL-protected named-pipe listener.
func NewListener(pipePath string) (net.Listener, error) {
	return winio.ListenPipe(pipePath, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
}
