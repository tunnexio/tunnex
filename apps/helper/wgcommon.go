//go:build darwin || windows

package helper

// Shared wireguard-go helpers used by the REAL tunnel backends (macOS pf / Windows
// WFP). Platform-agnostic: uapi rendering, MTU, stats parsing, and the split-default
// route mapping. Excluded from the stub (linux) build, which needs no wireguard-go.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

// splitEndpoint splits host:port, unwrapping a bracketed IPv6 host.
func splitEndpoint(endpoint string) (host, port string) {
	if i := strings.LastIndex(endpoint, ":"); i > 0 {
		host, port = endpoint[:i], endpoint[i+1:]
	} else {
		host = endpoint
	}
	return strings.Trim(host, "[]"), port
}

// resolveEndpoint replaces a hostname endpoint with a SINGLE resolved IP so the pf/WFP
// pass rule, the endpoint host-route, AND wireguard-go all pin the SAME address. A
// multi-address DNS name resolved independently by each could otherwise pin/permit a
// different IP than the tunnel actually dials → the kill-switch would block the
// handshake (review #10). Already-IP endpoints pass through unchanged.
func resolveEndpoint(endpoint string) (string, error) {
	host, port := splitEndpoint(endpoint)
	if net.ParseIP(host) != nil {
		return endpoint, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", &ProtocolError{Code: "endpoint_unresolved", Msg: "cannot resolve WG endpoint " + host + ": " + err.Error()}
	}
	if len(ips) == 0 {
		return "", &ProtocolError{Code: "endpoint_unresolved", Msg: "no addresses for WG endpoint " + host}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

func deviceMTU(cfg *TunnelConfig) int {
	if cfg.MTU > 0 {
		return cfg.MTU
	}
	return device.DefaultMTU
}

// uapiConfig renders the wireguard-go IpcSet string. Keys are HEX in the uapi, so
// the base64 config keys are converted.
func uapiConfig(cfg *TunnelConfig) (string, error) {
	priv, err := b64ToHex(cfg.PrivateKey)
	if err != nil {
		return "", &ProtocolError{Code: "bad_private_key", Msg: err.Error()}
	}
	pub, err := b64ToHex(cfg.PeerPublicKey)
	if err != nil {
		return "", &ProtocolError{Code: "bad_peer_key", Msg: err.Error()}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", priv)
	fmt.Fprintf(&sb, "listen_port=0\n")
	fmt.Fprintf(&sb, "replace_peers=true\n")
	fmt.Fprintf(&sb, "public_key=%s\n", pub)
	fmt.Fprintf(&sb, "endpoint=%s\n", cfg.Endpoint)
	if cfg.PersistentKeepalive > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", cfg.PersistentKeepalive)
	}
	for _, aip := range cfg.AllowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", aip)
	}
	return sb.String(), nil
}

// allowedIPsUAPI renders a wireguard-go uapi string that LIVE-UPDATES one existing peer's AllowedIPs
// to exactly `allowedIPs` — no tunnel bounce (S8.5). It carries NEITHER private_key NOR replace_peers NOR
// endpoint, so the device's identity, the peer's keys, and the endpoint are all UNTOUCHED (the session +
// handshake survive). `update_only=true` means an ABSENT peer is NOT created — a typo can never conjure a
// phantom peer (the smuggle-class edge). `replace_allowed_ips=true` makes the given set the FULL sweep
// (removed ranges vanish). An empty set clears the peer's crypto-routing entirely.
func allowedIPsUAPI(peerPubKeyB64 string, allowedIPs []string) (string, error) {
	pub, err := b64ToHex(peerPubKeyB64)
	if err != nil {
		return "", &ProtocolError{Code: "bad_peer_key", Msg: err.Error()}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "public_key=%s\n", pub)
	fmt.Fprintf(&sb, "update_only=true\n")
	fmt.Fprintf(&sb, "replace_allowed_ips=true\n")
	for _, aip := range allowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", aip)
	}
	return sb.String(), nil
}

// gatewayPeerSwapUAPI renders a wireguard-go uapi string that RE-HOMES the tunnel onto a new gateway peer
// WITHOUT a bounce (WF-A). A re-home is a peer SWAP, not an endpoint edit: WireGuard identifies a peer by
// its PUBLIC KEY, and the active hub's key differs from the standby's, so the device must drop the old
// peer and adopt the new one. The uapi does exactly that, ADD-BEFORE-REMOVE so the crypto-routing for
// `allowedIPs` is never momentarily unowned:
//  1. add the NEW peer (public_key=new, endpoint=new, keepalive, replace_allowed_ips + the CURRENT set) —
//     the same allowed_ips the old peer carried, so routing coverage is preserved across the swap;
//  2. remove the OLD peer (public_key=old, remove=true) — WG would have stolen its allowed_ips to the new
//     peer anyway (a single crypto-routing trie), but we drop it explicitly so no inert peer lingers.
//
// It carries NO private_key and NO replace_peers, so the DEVICE IDENTITY (its own key), the interface
// address, and the kill-switch are ALL untouched — the session survives, no re-enrollment. The OS routes
// point at the INTERFACE, not the peer, so a split-tunnel swap needs no route reconcile (the endpoint
// host-route + kill-switch re-point that a FULL tunnel needs is the D-WFA-4 carve-out, a separate slice).
func gatewayPeerSwapUAPI(oldPubB64, newPubB64, endpoint string, keepalive int, allowedIPs []string) (string, error) {
	oldHex, err := b64ToHex(oldPubB64)
	if err != nil {
		return "", &ProtocolError{Code: "bad_peer_key", Msg: err.Error()}
	}
	newHex, err := b64ToHex(newPubB64)
	if err != nil {
		return "", &ProtocolError{Code: "bad_peer_key", Msg: err.Error()}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "public_key=%s\n", newHex)
	fmt.Fprintf(&sb, "endpoint=%s\n", endpoint)
	if keepalive > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", keepalive)
	}
	fmt.Fprintf(&sb, "replace_allowed_ips=true\n")
	for _, aip := range allowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", aip)
	}
	// Remove the OLD peer only when it actually differs — re-homing back to the same key (or a first
	// call where old==new) must not add-then-immediately-remove the peer we just installed.
	if oldHex != newHex {
		fmt.Fprintf(&sb, "public_key=%s\n", oldHex)
		fmt.Fprintf(&sb, "remove=true\n")
	}
	return sb.String(), nil
}

// routeSet expands AllowedIPs to the concrete OS route targets (routeTargets splits full-tunnel halves).
// Shared by both backends' S8.5 live route full-sweep diff.
func routeSet(allowedIPs []string) map[string]bool {
	m := map[string]bool{}
	for _, aip := range allowedIPs {
		for _, t := range routeTargets(aip) {
			m[t] = true
		}
	}
	return m
}

func b64ToHex(k string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// routeTargets maps a route destination to the actual OS routes to install. A
// full-tunnel default (0.0.0.0/0 or ::/0) is installed as the WG-standard PAIR of
// half-routes (0.0.0.0/1 + 128.0.0.0/1 ; ::/1 + 8000::/1): they cover all traffic and
// are MORE SPECIFIC than the physical default, so they take precedence WITHOUT
// destroying it. When the tunnel adapter disappears (Down, crash, kill -9), the halves
// vanish with the interface and the physical default resurfaces automatically — no
// capture/restore, no stranded host. Non-default destinations pass through unchanged.
func routeTargets(allowedIP string) []string {
	switch allowedIP {
	case "0.0.0.0/0":
		return []string{"0.0.0.0/1", "128.0.0.0/1"}
	case "::/0":
		return []string{"::/1", "8000::/1"}
	default:
		return []string{allowedIP}
	}
}

// parseStats pulls handshake + transfer counters out of a wireguard-go IpcGet dump.
func parseStats(get, ifname string) TunnelStatus {
	st := TunnelStatus{State: string(StateUp), Interface: ifname}
	for _, line := range strings.Split(get, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			fmt.Sscanf(v, "%d", &st.LastHandshakeSec)
		case "rx_bytes":
			fmt.Sscanf(v, "%d", &st.RxBytes)
		case "tx_bytes":
			fmt.Sscanf(v, "%d", &st.TxBytes)
		}
	}
	return st
}
