package ovpn

import (
	"fmt"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/ovpnca"
)

// BuildProfile assembles a standard `.ovpn` profile importable by the official OpenVPN clients
// (OpenVPN Connect / Tunnelblick / mobile — B3): client directives + INLINE ca/cert/key. The client
// private key is inlined here and delivered EXACTLY ONCE (the S3.4/D2 one-time ceremony, D-S9.2-1) —
// it is never stored server-side, so it cannot be re-fetched; a lost profile is re-MINTED, not
// re-served. `remote-cert-tls server` pins the server-auth EKU so a stolen CLIENT cert cannot
// impersonate the gateway (the role separation IssueServer/IssueClient enforces, Slice 4a).
func BuildProfile(caPEM string, p ovpnca.Profile, remotes []string, port int) string {
	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString("proto udp\n")
	// WF-OVPN-9 multi-remote: one `remote` per hub-set member in PRIORITY ORDER — OpenVPN's NATIVE
	// client-side failover (tries them top-down, connects to whichever gateway is up). Every listed member
	// hosts this device's CCD (the widened roster, same hub-set authority), so a fail-over target ACCEPTS
	// rather than refusing (ccd-exclusive). STATIC SNAPSHOT (like the WG routed-ranges bake): the list is
	// current-at-export — a hub-set change after export is not reflected in an already-downloaded .ovpn
	// (re-export after a topology change; the client-side failover across the listed remotes is what makes
	// it degrade gracefully meanwhile). A non-hub-set device gets exactly one remote (zero-config golden).
	for _, r := range remotes {
		fmt.Fprintf(&b, "remote %s %d\n", r, port)
	}
	// WF-OVPN-walk-4 (RTO): bound client-side failover. OpenVPN re-homes by WALKING its `remote`
	// list, and the default connect-timeout is 120s — so a dead PRIMARY strands the client for
	// minutes (the enterprise batch walk measured ~5 min) before it advances to the standby. That is
	// a bad number to ship beside WireGuard's seconds-scale, CP-driven peer-swap re-home. These are
	// dial attempts against a KNOWN gateway, not a flaky WAN: 10s is generous for a live gateway's
	// UDP+TLS handshake even cross-region (~420ms RTT = a few round-trips), while abandoning a DEAD
	// remote fast. Re-home is then bounded by connect-timeout x dead-remote count (~10-12s for a
	// 2-hub set — comparable to WireGuard). See docs/S9.1-decisions.md for the honest re-home note.
	b.WriteString("connect-timeout 10\n")
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("remote-cert-tls server\n") // verify the gateway presents a SERVER-auth cert (Slice 4a)
	b.WriteString("cipher AES-256-GCM\n")
	b.WriteString("auth SHA256\n")
	b.WriteString("verb 3\n")
	fmt.Fprintf(&b, "<ca>\n%s</ca>\n", ensureNL(caPEM))
	fmt.Fprintf(&b, "<cert>\n%s</cert>\n", ensureNL(p.CertPEM))
	fmt.Fprintf(&b, "<key>\n%s</key>\n", ensureNL(p.PrivateKeyPEM))
	return b.String()
}

func ensureNL(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
