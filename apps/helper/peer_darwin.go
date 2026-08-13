//go:build darwin && cgo

package helper

/*
#include <libproc.h>
*/
import "C"

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// peerAuthKind marks this as the REAL cgo resolver (surfaced by CallerAuthKind).
const peerAuthKind = "native"

// NewPeerResolver (macOS) authenticates the caller via LOCAL_PEERPID on the unix
// socket → the peer's pid → proc_pidpath (libproc). cgo — verified in the macOS
// smoke, not the linux CI cross-compile (a no-cgo stub covers that build).
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
		var pid int
		var serr error
		if err := raw.Control(func(fd uintptr) {
			// LOCAL_PEERPID at level SOL_LOCAL (0) returns the peer's pid.
			pid, serr = unix.GetsockoptInt(int(fd), 0, unix.LOCAL_PEERPID)
		}); err != nil {
			return "", err
		}
		if serr != nil {
			return "", serr
		}
		buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
		n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
		if n <= 0 {
			return "", &ProtocolError{Code: "peer_path_unresolved", Msg: "proc_pidpath failed"}
		}
		return string(buf[:n]), nil
	}
}
