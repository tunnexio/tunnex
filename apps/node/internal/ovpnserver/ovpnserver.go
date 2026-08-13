// Package ovpnserver is the agent-owned OpenVPN server lifecycle (S9.1 Slice 3). It is a PARALLEL
// data-plane manager (a sibling to egress + dnsforward, NOT part of the reconcile loop that owns
// wg0) — desired state pushed in via SetDesired on each control-plane fetch, converged on the
// reconcile tick, self-healed, never assumed-in-sync.
//
// Ownership boundaries (the reconcile-ownership + allocator tripwires):
//   - The reconcile loop owns wg0; THIS owns the openvpn process, its config, and its CCD dir. No
//     overlap — the tun interface name is pinned here (TunName) and threaded to egress as the ONE
//     truth (egress.SetOVPNTun). If the observed interface disagrees with the configured name, the
//     CONFIG is authoritative: reconcile re-asserts it (a differently-named interface is drift to be
//     corrected on the next process (re)start, never a truth to adopt).
//   - The address allocator (CP-side) is the SINGLE authority: OpenVPN self-allocation is DISABLED
//     (no `server` / `ifconfig-pool` directive) and every client's fixed /32 is pushed from its
//     CP-assigned address via client-config-dir. This package never mints an address — it renders
//     the one the control plane assigned, so an OVPN client's /32 is the SAME /32 that is its policy
//     subject in the compiled artifact (D-S9.1-3: indistinguishable from a WG device's /32, which is
//     what keeps B1 free).
package ovpnserver

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

// TunName is the OpenVPN server's tun interface — pinned in config, and the ONE truth threaded to
// the egress tunnel-ingress set (egress.SetOVPNTun(TunName)). Never re-derived or observed-then-adopted.
const TunName = "tunnex-ovpn"

// TransitCIDR is the OpenVPN server tun's OWN point-to-point subnet — deliberately NOT the device pool
// (WF-OVPN-2, the iroute ruling). tunnex-ovpn holds an address on ONLY this /30, so it installs a
// connected route for ONLY the transit range: wg0 stays the sole route for the pool /24, and each
// connected OVPN client's pool /32 is delivered via CCD (ifconfig-push + iroute) and routed to the tun
// by the learn-address hook — winning over wg0's /24 by longest-prefix ONLY while that client is
// connected. This is what lets an OVPN client SOURCE from its pool /32 (indistinguishable-/32, B1)
// without tunnex-ovpn and wg0 fighting over the /24 (the rc1-walk WF-OVPN-2 conflict).
//
// The range is RFC 6598 shared address space (100.64.0.0/10) — carrier-grade-NAT space intended for
// provider-internal use, never a customer-routable LAN — and is NEVER advertised: not a policy subject,
// not in any AllowedIPs, not pushed to any client. It is purely the local tun endpoint. THAT is why it
// is EXEMPT from the cross-org / cross-gateway disjointness validator (two gateways sharing it is
// harmless — neither ever sees the other's tun). The agent still GUARDS it LOCALLY every reconcile
// (transitConflicts: refuse with HealthTransitConflict if the pool or a pushed route overlaps it), so
// "an address nobody validated" is false — it is re-checked against the ranges THIS gateway routes.
const (
	TransitCIDR     = "100.127.255.0/30"
	transitServerIP = "100.127.255.1"
	transitMask     = "255.255.255.252"
)

// Client is one OpenVPN client's desired binding: its cert common name (device identity) and the
// CP-ASSIGNED pool /32 (the allocator is authoritative; this package never allocates).
type Client struct {
	CommonName string
	IP         string // the CP-assigned host address, e.g. "10.99.0.7"
	FullTunnel bool   // WF-OVPN-3: route ALL client traffic to the gateway (per-client redirect-gateway)
}

// fullTunnelDNS is pushed to a full-tunnel OVPN client so name resolution survives once its default
// route is the tunnel — mirroring the WireGuard full-tunnel behavior. DELIBERATELY duplicates
// devices.fullTunnelDNS: the two live in separate modules (api vs node) and cannot share a Go constant,
// exactly like the AES-256-GCM cipher that appears in both the client profile and this server config. A
// change to the product's full-tunnel resolver must touch BOTH sites.
const fullTunnelDNS = "1.1.1.1"

// Desired is the full desired state pushed on each control-plane fetch.
type Desired struct {
	PoolCIDR string   // the org device pool (for the CCD ifconfig-push netmask); "" => server idle
	Clients  []Client // the clients homed to this gateway
	// Routes (S9.1 Part-3 fold): the org's approved reachable ranges (site subnets etc.). Unlike a
	// WireGuard static config — which must BAKE routes because official apps do not poll — OpenVPN
	// PUSHES routes dynamically, so an OVPN client reaches site subnets WITHOUT a client-side edit:
	// the server emits `push "route <range>"` and the client installs them on connect. CIDR strings.
	Routes []string
	// DNS (S9.1 Part-3 fold): reachable cross-site DNS resolvers, pushed as `dhcp-option DNS` so name
	// resolution works on a standard OpenVPN client (the WG static-config DNS gap has no OVPN twin).
	DNS []string
}

// Health kinds surfaced to the control plane (D-S9.5-OPTIN c + 4d). These are SURFACED HEALTH, not
// logs: an operator who enables OpenVPN on a gateway missing its material sees WHY on the health
// surface, and the gateway keeps doing everything else correctly (the conntrack_flush_unavailable /
// D4 precedent). "" = healthy.
const (
	HealthOK              = ""
	HealthCertsAbsent     = "ovpn_certs_absent"     // enabled + roster, but ca/server cert/key not placed
	HealthBinaryAbsent    = "ovpn_binary_absent"    // enabled, but the openvpn binary is not on PATH
	HealthTransitConflict = "ovpn_transit_conflict" // the server tun transit range overlaps the pool or a pushed route
)

// Manager owns the openvpn process + its config/CCD. Process control + filesystem are injectable so
// the lifecycle is unit-testable without spawning openvpn or touching a shared FS.
type Manager struct {
	cfgDir  string
	ccdDir  string
	desired atomic.Pointer[Desired]
	health  atomic.Pointer[string]
	serving atomic.Bool // the tun is up (preconditions met + process asserted) — gates egress.SetOVPNTun

	// injectable seams (real implementations wired in New):
	ensureProc func(ctx context.Context, confPath string) error // (re)start the process if not running (self-heal)
	writeFile  func(path string, data []byte) error
	removeFile func(path string) error
	listCCD    func() ([]string, error)
	// PRECONDITION probes (preconditions-before-exec): the supervisor is structurally UNABLE to spawn
	// when either is false — refuse-loudly is a GUARD before ensureProc, never a post-failure handler.
	binaryPresent func() bool // the openvpn binary is on PATH (ships unconditionally, D-S9.5-OPTIN b)
	certsPresent  func() bool // ca.crt + server.crt + server.key are placed at cfgDir
}

// New builds a Manager rooted at cfgDir (server.conf + ccd/ live under it). Process control is a
// stub by default (wired to a real supervisor in main); the FS uses the real filesystem.
func New(cfgDir string) *Manager {
	m := &Manager{
		cfgDir: cfgDir,
		ccdDir: filepath.Join(cfgDir, "ccd"),
	}
	m.ensureProc = func(context.Context, string) error { return nil } // wired in main
	m.writeFile = func(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
	m.removeFile = os.Remove
	m.binaryPresent = func() bool { _, err := exec.LookPath("openvpn"); return err == nil }
	m.certsPresent = func() bool {
		// crl.pem is REQUIRED (S9.1 Slice 5): crl-verify is ALWAYS-ON, so a config referencing a missing
		// crl.pem is a server that won't start (the WF-OVPN-1 lesson). The CP always delivers a real-or-EMPTY
		// signed CRL when OVPN is enabled; until it lands, the server refuses-loudly (ovpn_certs_absent) — never
		// starts crl-verify-less (which would silently accept revoked certs).
		for _, f := range []string{"ca.crt", "server.crt", "server.key", "crl.pem"} {
			if _, err := os.Stat(filepath.Join(m.cfgDir, f)); err != nil {
				return false
			}
		}
		return true
	}
	m.listCCD = func() ([]string, error) {
		ents, err := os.ReadDir(m.ccdDir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		var names []string
		for _, e := range ents {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		return names, nil
	}
	return m
}

// TunName returns the pinned tun interface name — the ONE truth for egress.SetOVPNTun.
func (m *Manager) TunName() string { return TunName }

// SetDesired atomically swaps the desired state (called from the reconcile loop's OnPolicy each tick).
func (m *Manager) SetDesired(d Desired) { m.desired.Store(&d) }

// SetEnsureProc wires the real process supervisor (Supervisor.Ensure) — called only once preconditions
// pass, so the supervisor is structurally unable to crash-loop. Default is a no-op stub (tests).
func (m *Manager) SetEnsureProc(fn func(ctx context.Context, confPath string) error) {
	m.ensureProc = fn
}

// WriteServerMaterial writes the CP-delivered CA + server cert + server KEY + CRL to cfgDir (D-S9.6 +
// Slice 5). The key is 0600; the certs + CRL 0644 (public). The CRL is a valid signed CRL, possibly EMPTY
// (an org with zero revocations still gets a real CRL — crl-verify is always-on, never a missing file).
// Idempotent — re-asserted every tick, so a hand-deleted file heals on the next reconcile. This is what
// clears the ovpn_certs_absent precondition (which now REQUIRES crl.pem).
func (m *Manager) WriteServerMaterial(ca, cert, key, crl string) error {
	if err := os.MkdirAll(m.cfgDir, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		data string
		perm os.FileMode
	}{
		{"ca.crt", ca, 0o644},
		{"server.crt", cert, 0o644},
		{"server.key", key, 0o600}, // the private key — restrictive perms, never logged
		{"crl.pem", crl, 0o644},    // the revocation list (Slice 5) — public; empty is first-class
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(m.cfgDir, f.name), []byte(f.data), f.perm); err != nil {
			return err
		}
	}
	return nil
}

// SweepServerMaterial removes the server material (D-S9.6: disable means nothing exists on disk;
// the DB record survives, so re-enable re-delivers the same serial). Includes the CRL (Slice 5).
func (m *Manager) SweepServerMaterial() {
	for _, f := range []string{"ca.crt", "server.crt", "server.key", "crl.pem"} {
		_ = os.Remove(filepath.Join(m.cfgDir, f))
	}
}

// Health returns the surfaced health kind ("" ok, or ovpn_certs_absent / ovpn_binary_absent) — the
// agent reports it so an operator sees WHY an enabled gateway is not serving (surfaced, not logged).
func (m *Manager) Health() string {
	if h := m.health.Load(); h != nil {
		return *h
	}
	return HealthOK
}

func ptr(s string) *string { return &s }

// serverConfig renders the openvpn server.conf. Two invariants ride here:
//
//	WF-OVPN-1 (server-mode completeness): the config is a COMPLETE, RUNNABLE TLS server — `mode server`
//	+ `tls-server` + proto/port + `ifconfig` + `dh none` + `keepalive`. The rc1 walk found the prior
//	config omitted ALL of these, so openvpn started in point-to-point mode and never brought up the tun.
//
//	WF-OVPN-2 (no pool-/24 claim): the tun's own address is on the TRANSIT /30 (ifconfig transitServerIP),
//	NEVER the pool — so tunnex-ovpn and wg0 never fight over the pool /24. Client /32s arrive via the CCD
//	(ifconfig-push + iroute) and are routed to the tun per-client by the learn-address hook.
//
// SELF-ALLOCATION STAYS DISABLED (the allocator tripwire): still NO `server` / `ifconfig-pool` directive
// — every client's address comes from its per-client CCD ifconfig-push (the CP-assigned /32). The tun
// name is pinned (dev TunName) so egress' tunnel-ingress set matches.
func (m *Manager) serverConfig(gwIP string, routes, dns []string) string {
	var b strings.Builder
	// Server mode (WF-OVPN-1): make this a listening TLS server. Without mode server + tls-server,
	// openvpn is a point-to-point peer and never serves — the rc1-walk finding.
	b.WriteString("mode server\n")
	b.WriteString("tls-server\n")
	b.WriteString("proto udp\n")
	b.WriteString("port 1194\n")
	fmt.Fprintf(&b, "dev %s\n", TunName)
	b.WriteString("dev-type tun\n")
	b.WriteString("topology subnet\n")
	// The tun's OWN address is on the TRANSIT /30, NEVER the pool (WF-OVPN-2): tunnex-ovpn installs a
	// connected route for ONLY the transit range, so wg0 remains the sole route for the pool /24. NO
	// `server`/`ifconfig-pool` and NO `route <pool>`: self-allocation stays off (CP allocator is sole),
	// and the pool /24 is never claimed here — connected clients' /32s win by longest-prefix instead.
	fmt.Fprintf(&b, "ifconfig %s %s\n", transitServerIP, transitMask)
	b.WriteString("dh none\n") // ECDHE-RSA (the server cert is RSA) needs no DH params file
	b.WriteString("data-ciphers AES-256-GCM\n")
	b.WriteString("cipher AES-256-GCM\n") // matches the client profile's pinned cipher
	b.WriteString("auth SHA256\n")
	b.WriteString("keepalive 10 60\n")
	// reneg-sec 60 (S9.1 Slice 5, D-S9.5-3): the TLS renegotiation interval bounds revocation latency —
	// crl-verify is re-checked at each reneg, so a revoked client's live session dies within one interval.
	// 60s (not the 3600s default) trades a little handshake overhead for near-immediate revocation, matching
	// "WireGuard revocation is immediate; OpenVPN revocation takes effect within one renegotiation interval
	// (60s)." These are hub gateways, not battery-constrained clients — the low end is right.
	b.WriteString("reneg-sec 60\n")
	// Diagnosability (WF-OVPN walk gap): the supervisor spawns openvpn detached and does NOT capture its
	// stdout/stderr, so auth/TLS failures were invisible on the box. openvpn writes its own log here at a
	// modest verbosity (3 — connection + TLS + auth lines, NO key material). log-append keeps history
	// across the per-tick self-heal respawns. `docker exec tunnex-node cat <cfgDir>/ovpn.log` reads it.
	b.WriteString("verb 3\n")
	fmt.Fprintf(&b, "log-append %s\n", filepath.Join(m.cfgDir, "ovpn.log"))
	fmt.Fprintf(&b, "client-config-dir %s\n", m.ccdDir)
	b.WriteString("ccd-exclusive\n") // a client with NO CCD entry is REFUSED — belt-and-suspenders on the single-authority rule
	// learn-address hook (WF-OVPN-2): openvpn calls it as it learns/forgets each client's iroute'd /32,
	// so the kernel gets a per-client /32 route to the tun (and drops it on disconnect). This is the
	// mechanism that keeps tunnex-ovpn off the pool /24 while still delivering replies to connected clients.
	b.WriteString("script-security 2\n")
	fmt.Fprintf(&b, "learn-address %s\n", filepath.Join(m.cfgDir, "learn-address.sh"))
	// Trust material (placed by the enrollment/export path; referenced by fixed name here).
	fmt.Fprintf(&b, "ca %s\n", filepath.Join(m.cfgDir, "ca.crt"))
	fmt.Fprintf(&b, "cert %s\n", filepath.Join(m.cfgDir, "server.crt"))
	fmt.Fprintf(&b, "key %s\n", filepath.Join(m.cfgDir, "server.key"))
	// crl-verify ALWAYS-ON (S9.1 Slice 5, D-S9.5-2): the CP always delivers a real-or-EMPTY signed CRL when
	// OVPN is enabled, and certsPresent REQUIRES crl.pem — so the server never runs crl-verify-less (which
	// would silently accept a revoked cert). An empty CRL revokes nothing but keeps the check wired.
	fmt.Fprintf(&b, "crl-verify %s\n", filepath.Join(m.cfgDir, "crl.pem"))
	// PUSH the topology + gateway to the client (WF-OVPN-7, 4e-walk finding). Because this server uses
	// manual `mode server` (not the `--server` helper), the topology is NOT auto-pushed — the client
	// defaults to net30 and REJECTS the /24 ifconfig-push ("ifconfig addresses are not in the same /30
	// subnet"). Push subnet topology; and push the POOL gateway as route-gateway — an IN-SUBNET address
	// the client accepts — because the server tun sits on the OFF-pool transit /30 (WF-OVPN-2), so its own
	// address would be an invalid off-subnet gateway for the client. On a p2p tun the client sends via this
	// gateway into the tunnel; the gateway host owns it on wg0 and forwards.
	b.WriteString("push \"topology subnet\"\n")
	if gwIP != "" {
		fmt.Fprintf(&b, "push \"route-gateway %s\"\n", gwIP)
	}
	b.WriteString("persist-tun\n")
	// S9.1 Part-3 fold: PUSH the org's approved ranges + DNS. OpenVPN installs these on the client at
	// connect (dynamic, server-side) — so a standard OpenVPN client reaches site subnets + resolves
	// cross-site names WITHOUT the client-side edit a static WireGuard config would need. Ranges are
	// canonically re-emitted (net + dotted mask) so nothing injects config directives.
	for _, c := range routes {
		if net, mask, ok := routeNetMask(c); ok {
			fmt.Fprintf(&b, "push \"route %s %s\"\n", net, mask)
		}
	}
	for _, d := range dns {
		if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
			fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", a.String())
		}
	}
	return b.String()
}

// routeNetMask converts a CIDR to OpenVPN's `route <network> <netmask>` form (dotted mask, not /bits).
func routeNetMask(cidr string) (net, mask string, ok bool) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return "", "", false
	}
	m, err := poolMask(cidr) // dotted mask from the prefix length
	if err != nil {
		return "", "", false
	}
	return p.Masked().Addr().String(), m, true
}

// ccdEntry renders one client's CCD file (WF-OVPN-2, iroute model):
//
//	ifconfig-push <ip> <pool-mask> — the client's tun IP is its CP-assigned pool /32 with the POOL mask,
//	    so the client treats the whole pool /24 as on-link (reaches other devices) and SOURCES from its
//	    pool /32 — the indistinguishable-/32 that makes B1 free (never an allocated address).
//	iroute <ip> /32 — the server-side demux that makes an address OUTSIDE the tun's transit subnet
//	    routable to THIS client. Paired with the learn-address kernel /32 route, it lets the client hold a
//	    pool /32 while tunnex-ovpn owns only the transit /30 (so wg0 keeps the pool /24, no route fight).
func ccdEntry(ip, mask string, fullTunnel bool) string {
	e := fmt.Sprintf("ifconfig-push %s %s\niroute %s 255.255.255.255\n", ip, mask, ip)
	// WF-OVPN-3: a full-tunnel client redirects its DEFAULT route through the gateway (bypass-dhcp keeps
	// the local DHCP path off the tunnel) — the OpenVPN twin of WireGuard's full_tunnel flag, per-DEVICE
	// via the CCD (never server-wide). A full-tunnel client also needs a resolver once its default route
	// is the tunnel, so DNS is pushed too (mirroring the WG full-tunnel DNS). Split-tunnel (the default)
	// emits neither — its routes come from the Part-3 server pushes.
	if fullTunnel {
		e += "push \"redirect-gateway def1 bypass-dhcp\"\n"
		e += fmt.Sprintf("push \"dhcp-option DNS %s\"\n", fullTunnelDNS)
	}
	return e
}

// transitConflicts is the LOCAL disjointness guard for the exempt transit range (see TransitCIDR): the
// transit /30 is never advertised, so it is exempt from the CP validator — but the agent still refuses
// to serve if the pool or any pushed route overlaps it on THIS gateway, so the tun address is never
// "validated by nobody".
func transitConflicts(pool string, routes []string) bool {
	tp, err := netip.ParsePrefix(TransitCIDR)
	if err != nil {
		return false
	}
	for _, c := range append([]string{pool}, routes...) {
		if c == "" {
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil && p.Overlaps(tp) {
			return true
		}
	}
	return false
}

// writeLearnAddressScript writes the learn-address hook (WF-OVPN-2) — root-owned, 0700. $2 (the
// address) is the CP-assigned roster /32, not attacker input; it is validated as IPv4 in the script
// before it touches `ip route` (defense-in-depth on the one-time-secret/injection hygiene law).
func (m *Manager) writeLearnAddressScript() error {
	script := fmt.Sprintf(`#!/bin/sh
# OpenVPN learn-address hook (WF-OVPN-2, iroute model): keep a /32 kernel route to the OVPN tun for each
# connected client's CP-assigned pool address, so replies reach the right tunnel WITHOUT tunnex-ovpn
# claiming the pool /24 (wg0 keeps the /24; these /32s win by longest-prefix only while connected).
# Args from openvpn: $1=op(add|update|delete) $2=address $3=common_name. $2 is the roster /32 (not
# attacker input); validated as IPv4 here for defense-in-depth before it touches ip route.
op="$1"; addr="$2"
case "$addr" in ""|*[!0-9.]*) exit 0 ;; esac
case "$op" in
  add|update) exec ip route replace "$addr/32" dev %s ;;
  delete) ip route del "$addr/32" dev %s 2>/dev/null; exit 0 ;;
esac
`, TunName, TunName)
	return os.WriteFile(filepath.Join(m.cfgDir, "learn-address.sh"), []byte(script), 0o700)
}

// Reconcile converges the openvpn server toward desired state: writes the server config, reconciles
// the CCD dir (write desired clients, SWEEP departed ones — no orphans), and self-heals the process.
// Idempotent; safe to call every tick. When the desired state is idle (no pool), it is a no-op (the
// server stays down, egress sees no tun → the zero-config golden holds).
func (m *Manager) Reconcile(ctx context.Context) error {
	d := m.desired.Load()
	if d == nil || d.PoolCIDR == "" {
		m.health.Store(ptr(HealthOK)) // idle / not opted-in on this gateway — nothing to be unhealthy about
		m.serving.Store(false)        // no tun up when idle
		return nil                    // not configured / no pool yet — stay idle
	}
	// PRECONDITIONS BEFORE EXEC (4d, ruled): the supervisor is structurally unable to spawn when the
	// binary or certs are missing — these guards run BEFORE ensureProc, refuse LOUDLY via the health
	// surface (not a log, not a post-failure handler), and the gateway keeps doing everything else.
	// Binary first (nothing to serve without it), then certs.
	if !m.binaryPresent() {
		m.health.Store(ptr(HealthBinaryAbsent))
		m.serving.Store(false) // the tun is NOT up → the agent publishes SetOVPNTun("") → Slice-3 sweep
		return nil
	}
	if !m.certsPresent() {
		m.health.Store(ptr(HealthCertsAbsent))
		m.serving.Store(false)
		return nil
	}
	// LOCAL transit guard (WF-OVPN-2): refuse-loudly if the exempt transit /30 overlaps the pool or a
	// pushed route on THIS gateway — the tun address is never validated-by-nobody.
	if transitConflicts(d.PoolCIDR, d.Routes) {
		m.health.Store(ptr(HealthTransitConflict))
		m.serving.Store(false)
		return nil
	}
	m.health.Store(ptr(HealthOK)) // preconditions met — clears any prior refusal on recovery
	mask, err := poolMask(d.PoolCIDR)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.ccdDir, 0o700); err != nil {
		return err
	}
	// learn-address hook (WF-OVPN-2): written before the config references it, root-owned 0700.
	if err := m.writeLearnAddressScript(); err != nil {
		return err
	}
	// The pool gateway IP (the host part of PoolCIDR, e.g. "10.99.0.1") — pushed to OVPN clients as their
	// in-subnet route-gateway (WF-OVPN-7). PoolCIDR carries the gateway CIDR ("10.99.0.1/24").
	gwIP := ""
	if p, perr := netip.ParsePrefix(d.PoolCIDR); perr == nil {
		gwIP = p.Addr().String()
	}
	// Server config (idempotent write).
	if err := m.writeFile(filepath.Join(m.cfgDir, "server.conf"), []byte(m.serverConfig(gwIP, d.Routes, d.DNS))); err != nil {
		return err
	}
	// CCD: desired set, keyed by common name.
	want := map[string]string{} // CN -> rendered CCD body
	for _, c := range d.Clients {
		if c.CommonName == "" || c.IP == "" {
			continue // fail-static: skip a malformed client rather than write a bad ifconfig-push
		}
		want[c.CommonName] = ccdEntry(c.IP, mask, c.FullTunnel)
	}
	// Write/refresh desired CCD files.
	names := make([]string, 0, len(want))
	for cn := range want {
		names = append(names, cn)
	}
	sort.Strings(names) // deterministic write order (steady-state reconcile is byte-stable)
	for _, cn := range names {
		if err := m.writeFile(filepath.Join(m.ccdDir, cn), []byte(want[cn])); err != nil {
			return err
		}
	}
	// FULL-SWEEP: remove CCD files for clients no longer desired (a departed client leaves — no orphan
	// grant-by-address in the server). Mirrors the DOCKER-USER + peer sweep discipline.
	existing, err := m.listCCD()
	if err != nil {
		return err
	}
	for _, name := range existing {
		if _, keep := want[name]; !keep {
			if err := m.removeFile(filepath.Join(m.ccdDir, name)); err != nil {
				return err
			}
		}
	}
	// Self-heal: (re)start the process if it isn't running.
	if err := m.ensureProc(ctx, filepath.Join(m.cfgDir, "server.conf")); err != nil {
		m.serving.Store(false) // spawn failed — the tun is not up
		return err
	}
	m.serving.Store(true) // the process is asserted → the tun is up → the agent may publish SetOVPNTun
	return nil
}

// TunActive reports whether the OpenVPN tun is up (preconditions met + the process asserted). The
// agent publishes egress.SetOVPNTun(TunName) ONLY when this is true — a tunnelIfaces() entry for a
// tun that isn't up would render forward accepts for a non-existent ingress. When the server later
// DIES (TunActive → false), the agent publishes SetOVPNTun("") and the Slice-3 sweep-on-departed-tun
// path removes the tun's egress rules. Cross-slice: ovpnserver liveness drives egress' tunnel set.
func (m *Manager) TunActive() bool { return m.serving.Load() }

// poolMask returns the dotted-decimal netmask for a pool CIDR (topology subnet's ifconfig-push needs it).
func poolMask(cidr string) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return "", fmt.Errorf("ovpnserver: pool CIDR must be IPv4, got %q", cidr)
	}
	bits := p.Bits()
	var mask [4]byte
	for i := 0; i < 4; i++ {
		n := bits - i*8
		switch {
		case n >= 8:
			mask[i] = 0xff
		case n <= 0:
			mask[i] = 0x00
		default:
			mask[i] = byte(0xff << (8 - n))
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]), nil
}
