//go:build linux

package helper

import (
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerAuthKind marks this as the REAL resolver (surfaced by CallerAuthKind).
const peerAuthKind = "native"

// NewPeerResolver (Linux) authenticates the caller via SO_PEERCRED on the unix
// socket → the peer's pid → /proc/<pid>/exe. Linux is not a shipping target (the
// app runs on macOS/Windows), but this is the CI-testable reference for the
// getsockopt plumbing the other platforms mirror.
func NewPeerResolver() PeerResolver {
	return func(c net.Conn) (string, error) {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return "", &ProtocolError{Code: "peer_not_unix", Msg: "connection is not a unix socket"}
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return "", err
		}
		var cred *unix.Ucred
		var serr error
		if err := raw.Control(func(fd uintptr) {
			cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil {
			return "", err
		}
		if serr != nil {
			return "", serr
		}
		exe, err := os.Readlink("/proc/" + strconv.Itoa(int(cred.Pid)) + "/exe")
		if err != nil {
			return "", &ProtocolError{Code: "peer_path_unresolved", Msg: err.Error()}
		}
		return exe, nil
	}
}
