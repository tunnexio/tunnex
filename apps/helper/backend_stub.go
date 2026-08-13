package helper

// StubBackend satisfies Backend without touching the network. It lets the helper
// binary build + serve the full protocol (auth, framing, fail-closed state) on any
// platform while the real wireguard-go (macOS) / wireguard-nt (Windows) backends —
// and their pre-arranged pf/WFP kill-switch — are implemented in build-tagged
// files. Every tunnel op reports not_implemented so nothing silently "succeeds".
type StubBackend struct{}

func (StubBackend) Up(*TunnelConfig) error {
	return &ProtocolError{Code: "not_implemented", Msg: "tunnel backend not implemented on this build"}
}
func (StubBackend) Down() error       { return nil }
func (StubBackend) FailClosed() error { return nil }
func (StubBackend) CleanStale() error { return nil }
func (StubBackend) SetAllowedIPs(string, []string) error {
	return &ProtocolError{Code: "not_implemented", Msg: "no tunnel backend on this platform"}
}
func (StubBackend) SetGatewayPeer(string, string) error {
	return &ProtocolError{Code: "not_implemented", Msg: "no tunnel backend on this platform"}
}
func (StubBackend) Stats() (TunnelStatus, error) {
	return TunnelStatus{}, &ProtocolError{Code: "not_implemented", Msg: "stats not implemented on this build"}
}
