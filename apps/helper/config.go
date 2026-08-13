package helper

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
)

// TunnelConfig is the STRUCTURED WireGuard config the app hands the helper over
// IPC. It is deliberately NOT a file path: passing a path to a root process
// invites TOCTOU + arbitrary-read; a validated struct closes both. Every field is
// checked by Validate BEFORE the helper touches the network, and malformed input
// is rejected with a stable code rather than best-effort'd.
type TunnelConfig struct {
	// PrivateKey is the interface's own WireGuard key: base64 of exactly 32 bytes.
	PrivateKey string `json:"private_key"`
	// PeerPublicKey is the server peer's public key: base64 of exactly 32 bytes.
	PeerPublicKey string `json:"peer_public_key"`
	// Endpoint is the server host:port (host may be IP or DNS name).
	Endpoint string `json:"endpoint"`
	// Address is the interface address as a single-host CIDR (e.g. 10.99.0.2/32).
	Address   string   `json:"address"`
	Addresses []string `json:"addresses,omitempty"`
	// AllowedIPs are the CIDRs routed INTO the tunnel (e.g. ["0.0.0.0/0","::/0"]
	// for full-tunnel, or specific subnets for split).
	AllowedIPs []string `json:"allowed_ips"`
	// FullTunnel declares INTENT: when true this is an all-traffic tunnel and
	// Validate REQUIRES both default routes (0.0.0.0/0 AND ::/0) present, so one
	// address family can't silently leak on its native default route. When false
	// (split tunnel) any valid CIDRs are accepted. The helper is the last gate
	// before routing, so the completeness check lives here.
	FullTunnel bool `json:"full_tunnel"`
	// DNS are resolver IPs applied while the tunnel is up (optional).
	DNS []string `json:"dns,omitempty"`
	// MTU is the interface MTU (0 = default; else 1280..1500).
	MTU int `json:"mtu,omitempty"`
	// PersistentKeepalive seconds (0 = off; else 1..65535).
	PersistentKeepalive int `json:"persistent_keepalive,omitempty"`
	// ControlPlaneEndpoint is the tenant API host:port (WF-A / D-WFA-4). When set on a FULL tunnel, the
	// kill-switch carves ONE named pass out to it (+ a host-route via the physical gateway) so the control
	// channel survives the tunnel going down — the device can still poll the CP to learn a re-home during a
	// hard hub death. The CP is already the TLS trust root; a pass to it widens nothing. Optional + additive
	// (an old client omits it → no carve-out → full-tunnel re-home unavailable, fail-static). Ignored for a
	// split tunnel (no kill-switch). host may be IP or DNS name, same safe-host rules as Endpoint.
	ControlPlaneEndpoint string `json:"control_plane_endpoint,omitempty"`
}

const wgKeyLen = 32

// Validate fails CLOSED on anything malformed. It returns a *ProtocolError whose
// Code is stable so the app can branch/telemetry on it. It does NOT mutate the
// config and it never logs key material.
func (c *TunnelConfig) Validate() error {
	if c == nil {
		return &ProtocolError{Code: "config_required", Msg: "config is nil"}
	}
	if err := validKey(c.PrivateKey); err != nil {
		return &ProtocolError{Code: "bad_private_key", Msg: err.Error()}
	}
	if err := validKey(c.PeerPublicKey); err != nil {
		return &ProtocolError{Code: "bad_peer_key", Msg: err.Error()}
	}
	if !validEndpoint(c.Endpoint) {
		return &ProtocolError{Code: "bad_endpoint", Msg: "endpoint must be host:port"}
	}
	if !validHostCIDR(c.Address) {
		return &ProtocolError{Code: "bad_address", Msg: "address must be a valid CIDR"}
	}
	for _, address := range c.Addresses {
		if !validHostCIDR(address) {
			return &ProtocolError{Code: "bad_address", Msg: "address must be a valid CIDR"}
		}
	}
	if len(c.AllowedIPs) == 0 {
		return &ProtocolError{Code: "bad_allowed_ips", Msg: "allowed_ips must not be empty"}
	}
	var haveV4Default bool
	for _, a := range c.AllowedIPs {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			return &ProtocolError{Code: "bad_allowed_ips", Msg: "invalid CIDR in allowed_ips: " + a}
		}
		if p.Bits() == 0 { // a default route
			if p.Addr().Is4() || p.Addr().Is4In6() {
				haveV4Default = true
			}
		}
	}
	// Full-tunnel always requires IPv4. IPv6 is optional: when absent, the
	// platform kill-switch blocks non-tunnel IPv6 so IPv4-only customers do not
	// leak traffic or get rejected solely because their network has no IPv6.
	if c.FullTunnel && !haveV4Default {
		return &ProtocolError{Code: "incomplete_full_tunnel", Msg: "full_tunnel requires 0.0.0.0/0 in allowed_ips"}
	}
	for _, d := range c.DNS {
		if _, err := netip.ParseAddr(strings.TrimSpace(d)); err != nil {
			return &ProtocolError{Code: "bad_dns", Msg: "invalid DNS IP: " + d}
		}
	}
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 1500) {
		return &ProtocolError{Code: "bad_mtu", Msg: "mtu must be 0 or 1280..1500"}
	}
	if c.PersistentKeepalive < 0 || c.PersistentKeepalive > 65535 {
		return &ProtocolError{Code: "bad_keepalive", Msg: "persistent_keepalive must be 0..65535"}
	}
	// The CP endpoint is validated as strictly as the WG endpoint (safe host:port — validEndpoint bars
	// loopback/link-local/metacharacters) so a bad value can't steer the pf carve-out. Empty = no carve-out.
	if c.ControlPlaneEndpoint != "" && !validEndpoint(c.ControlPlaneEndpoint) {
		return &ProtocolError{Code: "bad_control_plane_endpoint", Msg: "control_plane_endpoint must be host:port"}
	}
	return nil
}

// validKey requires standard base64 decoding to EXACTLY 32 bytes — the WireGuard
// key size. Rejects wrong length, non-base64, and empty.
func validKey(s string) error {
	if s == "" {
		return &ProtocolError{Code: "empty_key", Msg: "key is empty"}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return &ProtocolError{Code: "not_base64", Msg: "key is not valid base64"}
	}
	if len(raw) != wgKeyLen {
		return &ProtocolError{Code: "bad_key_len", Msg: "key must decode to 32 bytes"}
	}
	return nil
}

// validEndpoint requires host:port with a numeric port in 1..65535 and a SAFE
// host — either a literal IP that is a normal unicast global/private address, or
// a syntactically valid DNS name. The host is the one config field a backend may
// hand to a resolver or (worse) interpolate into a command, so it is validated as
// strictly as the rest: no spaces/metacharacters/control chars, and no
// loopback/link-local/multicast/unspecified literals (an attacker must not be able
// to steer where the root helper dials).
func validEndpoint(s string) bool {
	host, port, ok := splitHostPort(s)
	if !ok || host == "" {
		return false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	return validHost(host)
}

// validHost accepts a safe IP literal or a DNS hostname.
func validHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		// IP literal: reject the address classes an endpoint must never be.
		return !(addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
			addr.IsMulticast() || addr.IsUnspecified())
	}
	return validDNSName(host)
}

// validDNSName enforces RFC-1123-ish hostname syntax (letters/digits/hyphen dot-
// separated labels, 1..63 chars each, no leading/trailing hyphen, <=253 total).
// This rejects spaces, shell metacharacters, and control bytes outright.
func validDNSName(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	h = strings.TrimSuffix(h, ".") // a trailing root dot is legal
	for _, label := range strings.Split(h, ".") {
		n := len(label)
		if n == 0 || n > 63 || label[0] == '-' || label[n-1] == '-' {
			return false
		}
		for i := 0; i < n; i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// splitHostPort splits "host:port" handling bracketed IPv6 ("[::1]:51820"). It
// returns ok=false if there is no single trailing :port.
func splitHostPort(s string) (host, port string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if strings.HasPrefix(s, "[") { // [ipv6]:port
		end := strings.LastIndex(s, "]")
		if end < 0 || end+1 >= len(s) || s[end+1] != ':' {
			return "", "", false
		}
		return s[1:end], s[end+2:], true
	}
	i := strings.LastIndex(s, ":")
	if i < 0 || i == len(s)-1 || strings.Contains(s[:i], ":") {
		return "", "", false // no port, or a bare IPv6 without brackets
	}
	return s[:i], s[i+1:], true
}

// validHostCIDR requires a parseable CIDR (host or network form both fine).
func validHostCIDR(s string) bool {
	_, err := netip.ParsePrefix(strings.TrimSpace(s))
	return err == nil
}
