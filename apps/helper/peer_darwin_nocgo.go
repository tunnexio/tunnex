//go:build darwin && !cgo

package helper

import "net"

// peerAuthKind marks this build as the STUB (surfaced by CallerAuthKind so a
// non-cgo macOS build is immediately distinguishable, never silently shipped).
const peerAuthKind = "stub"

// NewPeerResolver (macOS, CGO disabled) — a FAIL-CLOSED stub (refuses every
// caller, same as the Windows/other stubs) so the CI cross-compile (CGO_ENABLED=0)
// compiles the darwin build. The REAL resolver (peer_darwin.go) needs cgo/libproc
// and is built + smoke-verified on a Mac (CGO_ENABLED=1).
func NewPeerResolver() PeerResolver {
	return func(net.Conn) (string, error) {
		return "", &ProtocolError{Code: "peer_resolution_needs_cgo", Msg: "macOS caller-path resolution requires a cgo build"}
	}
}
