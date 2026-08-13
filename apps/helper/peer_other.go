//go:build !linux && !darwin && !windows

package helper

import "net"

const peerAuthKind = "stub"

// NewPeerResolver fallback for unsupported platforms: FAIL CLOSED (refuse every
// caller). A helper that cannot identify its caller must trust no one.
func NewPeerResolver() PeerResolver {
	return func(net.Conn) (string, error) {
		return "", &ProtocolError{Code: "peer_resolution_unsupported", Msg: "caller-path resolution unsupported on this platform"}
	}
}
