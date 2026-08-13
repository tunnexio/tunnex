//go:build linux

package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// wgctrlBackend is the real WireGuard data-plane adapter. It drives the standard
// tools (ip / wg / wireguard-go), so it works with kernel WireGuard or the
// userspace implementation. Peer convergence uses `wg syncconf`, which removes
// absent peers and leaves unchanged peers UNTOUCHED (no handshake reset) —
// idempotent against a dirty device.
type wgctrlBackend struct {
	iface  string
	logger *slog.Logger
	// Cached from the last Configure so ApplyPeers' `wg syncconf` can echo them in
	// its [Interface] section. An EMPTY [Interface] makes syncconf CLEAR the
	// private key (→ "(none)") and reset the listen port to a random value —
	// silently breaking every tunnel on the next reconcile (POC-surfaced bug).
	privKey    string
	listenPort int
	// interfacePrefixes is the canonical subnet of every address configured on
	// wg0. ApplyRoutes uses only the desired-route intersection to own the
	// device-pool return rule ahead of provider CNI source rules.
	interfacePrefixes []netip.Prefix
	// runFn shells `ip`/`wg` (defaults to the package run). Overridable in tests to inject a route-
	// enumeration fault, proving ApplyRoutes surfaces a -4 error (F3).
	runFn func(context.Context, string, ...string) (string, error)
}

func newWGCtrlBackend(iface string, logger *slog.Logger) (WGBackend, error) {
	return &wgctrlBackend{iface: iface, logger: logger, runFn: run}, nil
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Configure idempotently ensures the interface exists and has the given key,
// port, address, and MTU. It is DIRTY-CHECKED: it reads current device state and
// only applies what differs, so a steady-state reconcile touches nothing — in
// particular it never re-issues `wg set private-key` on an unchanged key, which
// would needlessly churn the interface. Diagnosable errors bubble up (agent
// readiness reflects them) rather than pretending success.
func (b *wgctrlBackend) Configure(ctx context.Context, cfg InterfaceConfig) error {
	if err := b.ensureDevice(ctx); err != nil {
		return err
	}
	// Cache for ApplyPeers' syncconf so it echoes (never clears) the key + port.
	b.privKey, b.listenPort = cfg.PrivateKey, cfg.ListenPort
	curPub, curPort := b.currentWGInterface(ctx)

	// (Re)set the private key only when the interface's PUBLIC key doesn't already
	// match ours. Comparing public keys is clamp-invariant: WireGuard clamps the
	// stored private key, so the raw private bytes always differ, but the public
	// key is stable — so this fires exactly once (or on a real re-key), never on
	// every reconcile. Done as its own `wg set` so it can't disturb the port.
	if cfg.PrivateKey != "" && (cfg.PublicKey == "" || cfg.PublicKey != curPub) {
		keyFile, err := os.CreateTemp("", "wgkey")
		if err != nil {
			return err
		}
		defer os.Remove(keyFile.Name())
		_ = os.Chmod(keyFile.Name(), 0o600)
		if _, err := keyFile.WriteString(cfg.PrivateKey); err != nil {
			_ = keyFile.Close()
			return err
		}
		_ = keyFile.Close()
		if _, err := run(ctx, "wg", "set", b.iface, "private-key", keyFile.Name()); err != nil {
			return err
		}
	}
	// Set the listen port only when it differs — re-setting it to the current
	// value fails with "Address in use". A zero desired port would make wg pick a
	// random port, so refuse it.
	if cfg.ListenPort > 0 && cfg.ListenPort != curPort {
		if _, err := run(ctx, "wg", "set", b.iface, "listen-port", strconv.Itoa(cfg.ListenPort)); err != nil {
			return err
		}
	}

	var interfacePrefixes []netip.Prefix
	for _, addr := range strings.Split(cfg.Address, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if p, err := netip.ParsePrefix(addr); err == nil {
			interfacePrefixes = append(interfacePrefixes, p.Masked())
		}
		if b.hasAddress(ctx, addr) {
			continue
		}
		if _, err := b.runFn(ctx, "ip", "address", "replace", addr, "dev", b.iface); err != nil {
			return err
		}
	}
	b.interfacePrefixes = interfacePrefixes
	return b.ensureLinkUp(ctx, cfg.MTU)
}

func (b *wgctrlBackend) ensureDevice(ctx context.Context) error {
	if _, err := run(ctx, "ip", "link", "show", b.iface); err == nil {
		return nil // already exists
	}
	// Kernel WireGuard (present on most modern kernels incl. Docker's LinuxKit
	// VM). Userspace wireguard-go is tried only if the binary is installed; a
	// clear error otherwise so readiness failure is diagnosable.
	if _, err := run(ctx, "ip", "link", "add", "dev", b.iface, "type", "wireguard"); err == nil {
		return nil
	}
	if _, err := exec.LookPath("wireguard-go"); err == nil {
		if _, err := run(ctx, "wireguard-go", b.iface); err == nil {
			return nil
		}
	}
	return fmt.Errorf("cannot create wg device %q: kernel WireGuard module unavailable and no wireguard-go binary (need NET_ADMIN + WG kernel module or wireguard-go)", b.iface)
}

// currentWGInterface returns the interface's current PUBLIC key and listen port
// from `wg show <iface> dump` (line 0: private-key, public-key, listen-port,
// fwmark). The public key is used for the clamp-safe key-set check. Returns
// ("", 0) if unreadable.
func (b *wgctrlBackend) currentWGInterface(ctx context.Context) (pubKey string, listenPort int) {
	out, err := run(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		return "", 0
	}
	return parseWGInterface(out)
}

// parseWGInterface parses the interface (first) line of `wg show <iface> dump`
// (private-key, PUBLIC-key, listen-port, fwmark), returning the public key and
// port. We compare the PUBLIC key (field 1), not the private key (field 0):
// WireGuard clamps the stored private key, so its raw bytes differ from what the
// agent generated, but the derived public key is stable. Returns ("", 0) if the
// line is malformed or the interface has no key yet ("(none)").
func parseWGInterface(dump string) (pubKey string, listenPort int) {
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", 0
	}
	f := strings.Split(lines[0], "\t")
	if len(f) < 3 {
		return "", 0
	}
	pub := f[1]
	if pub == "(none)" {
		pub = ""
	}
	port, _ := strconv.Atoi(f[2])
	return pub, port
}

// hasAddress reports whether addr (e.g. "10.99.0.1/32") is already on the device.
func (b *wgctrlBackend) hasAddress(ctx context.Context, addr string) bool {
	out, err := run(ctx, "ip", "-o", "addr", "show", "dev", b.iface)
	if err != nil {
		return false
	}
	return strings.Contains(out, addr)
}

// ensureLinkUp sets MTU + brings the link up only if it is not already at the
// desired MTU and up.
func (b *wgctrlBackend) ensureLinkUp(ctx context.Context, mtu int) error {
	out, err := run(ctx, "ip", "link", "show", b.iface)
	if err == nil {
		hasMTU := mtu <= 0 || strings.Contains(out, "mtu "+strconv.Itoa(mtu))
		isUp := strings.Contains(out, "state UP") || strings.Contains(out, "state UNKNOWN") ||
			strings.Contains(out, ",UP,") || strings.Contains(out, "<UP")
		if hasMTU && isUp {
			return nil
		}
	}
	setArgs := []string{"link", "set", "dev", b.iface}
	if mtu > 0 {
		setArgs = append(setArgs, "mtu", strconv.Itoa(mtu))
	}
	setArgs = append(setArgs, "up")
	_, err = run(ctx, "ip", setArgs...)
	return err
}

// Peers reads the current peer set from the device.
func (b *wgctrlBackend) Peers(ctx context.Context) ([]Peer, error) {
	out, err := run(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseWGDump(out), nil
}

// Stats parses per-peer live telemetry from `wg show <iface> dump`.
func (b *wgctrlBackend) Stats(ctx context.Context) ([]PeerStat, error) {
	out, err := run(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseWGStats(out), nil
}

// Close deletes the WG interface on agent shutdown (WF-C Layer 1) — the symmetric destroy for
// ensureDevice's `ip link add`. Without it, `--network host` wg0 outlives the container on a graceful
// stop and forwards headless (zombie hub). IDEMPOTENT: if the interface is already gone (never created,
// or a prior Close), `ip link del` errors "Cannot find device" — treated as success (nothing to tear down).
func (b *wgctrlBackend) Close(ctx context.Context) error {
	if _, err := b.runFn(ctx, "ip", "link", "show", b.iface); err != nil {
		return nil // already absent → nothing to delete (idempotent)
	}
	_, err := b.runFn(ctx, "ip", "link", "del", b.iface)
	return err
}

// parseWGStats parses the peer lines of a dump into telemetry. Peer fields:
// pubkey, psk, endpoint, allowed-ips, latest-handshake(unix), rx, tx, keepalive.
func parseWGStats(out string) []PeerStat {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var stats []PeerStat
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		s := PeerStat{PublicKey: f[0]}
		if f[2] != "(none)" && f[2] != "" {
			s.Endpoint = f[2]
		}
		s.LastHandshake, _ = strconv.ParseInt(f[4], 10, 64)
		s.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
		s.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		stats = append(stats, s)
	}
	return stats
}

// parseWGDump parses `wg show <iface> dump` output into peers. The first line is
// the interface itself (skipped); each subsequent tab-separated line is a peer:
// pubkey, preshared-key, endpoint, allowed-ips, ...
func parseWGDump(out string) []Peer {
	var peers []Peer
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		p := Peer{PublicKey: f[0]}
		if f[2] != "(none)" && f[2] != "" {
			p.Endpoint = f[2]
		}
		if f[3] != "(none)" && f[3] != "" {
			p.AllowedIPs = strings.Split(f[3], ",")
		}
		// Persistent-keepalive is the last dump field (f[7]): an interval in seconds, or "off". Parsing it
		// (S8.3 CK) makes the actual side carry keepalive so peersEqual converges on it for site-link peers
		// instead of churning (the R2 fixture-fidelity discipline: the kernel reports it, so we read it).
		if len(f) >= 8 && f[7] != "off" && f[7] != "(none)" {
			if ka, err := strconv.Atoi(f[7]); err == nil {
				p.PersistentKeepalive = ka
			}
		}
		peers = append(peers, p)
	}
	return peers
}

// buildSyncConf renders a wg config containing only [Peer] sections, for
// `wg syncconf` (converges to this peer set; unchanged peers keep their session).
func buildSyncConf(privKey string, listenPort int, peers []Peer) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	// Echo the key + port: `wg syncconf` CLEARS anything ABSENT from [Interface]
	// (an empty section wipes the private key + randomizes the listen port). Writing
	// them makes syncconf idempotent on the interface instead of destructive.
	if privKey != "" {
		sb.WriteString("PrivateKey = " + privKey + "\n")
	}
	if listenPort > 0 {
		sb.WriteString("ListenPort = " + strconv.Itoa(listenPort) + "\n")
	}
	for _, p := range peers {
		// WF-OVPN-10 boundary guard (the WF-OVPN-1 lesson: a config that meets an external tool must be one
		// that tool ACCEPTS). A peer with an EMPTY PublicKey renders `PublicKey = ` and makes `wg syncconf`
		// reject the ENTIRE file — one bad peer bricks the whole interface (its blast radius is what made
		// WF-OVPN-10 merge-blocking). The control plane already excludes keyless (OpenVPN) devices at the
		// source (ListActiveWireGuardPeersForNode); this is the last-line guarantee that no peer set can
		// brick wg here, whatever the CP sends.
		if p.PublicKey == "" {
			continue
		}
		sb.WriteString("\n[Peer]\nPublicKey = " + p.PublicKey + "\n")
		if len(p.AllowedIPs) > 0 {
			sb.WriteString("AllowedIPs = " + strings.Join(p.AllowedIPs, ",") + "\n")
		}
		if p.Endpoint != "" {
			sb.WriteString("Endpoint = " + p.Endpoint + "\n")
		}
		if p.PersistentKeepalive > 0 {
			sb.WriteString("PersistentKeepalive = " + strconv.Itoa(p.PersistentKeepalive) + "\n")
		}
	}
	return sb.String()
}

// ApplyPeers converges the peer set via `wg syncconf` (idempotent; unchanged
// peers keep their sessions, absent peers are removed).
func (b *wgctrlBackend) ApplyPeers(ctx context.Context, peers []Peer) error {
	f, err := os.CreateTemp("", "wgconf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(buildSyncConf(b.privKey, b.listenPort, peers)); err != nil {
		return err
	}
	_ = f.Close()
	_, err = run(ctx, "wg", "syncconf", b.iface, f.Name())
	return err
}

// siteRouteMetric tags every S8.2 kernel route we own. The prune enumerates + deletes ONLY routes
// carrying BOTH `proto static` AND this metric, so an operator's / routing-daemon's own static route on
// wg0 (any other metric, or none) is NEVER touched (review #2). We picked a distinct metric over a
// dedicated routing table: a table needs an `ip rule` to steer forwarding into it (policy routing on the
// data path); a metric scopes ownership without touching how packets are routed (a lone route to a
// prefix is selected regardless of metric).
const siteRouteMetric = 8021

// returnRulePriority is reserved by Tunnex for device-pool return routing. It
// must run before provider CNI source rules (EKS VPC CNI uses priorities 512+)
// while leaving the local rule at priority 0 authoritative.
const returnRulePriority = 100

// parseRouteDst canonicalizes a route destination token to a netip.Prefix. `ip route show` prints a host
// route as a BARE address (no /32), so a desired "10.1.0.5/32" must compare equal to an enumerated
// "10.1.0.5" (review #3: string compare churned /32 routes install→delete every tick). A bare address
// becomes a full-length prefix.
func parseRouteDst(tok string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// routesToPrune is the PURE prune decision: enumerated route-destination tokens minus the desired set,
// compared as canonical prefixes (so /32 host-route normalization can't cause a spurious prune). Unknown
// tokens are skipped (never guessed into a delete).
func routesToPrune(enumerated []string, desired map[netip.Prefix]bool) []netip.Prefix {
	var del []netip.Prefix
	for _, tok := range enumerated {
		p, ok := parseRouteDst(tok)
		if !ok || desired[p] {
			continue
		}
		del = append(del, p)
	}
	return del
}

// returnRules parses only the exact rule shape owned by Tunnex:
//
//	100: from all to 10.99.0.0/24 lookup main
//
// Unrelated rules, including other shapes at priority 100, are ignored.
func returnRules(listing string) map[netip.Prefix]bool {
	out := make(map[netip.Prefix]bool)
	for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || strings.TrimSuffix(f[0], ":") != strconv.Itoa(returnRulePriority) {
			continue
		}
		var to, lookup string
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "to":
				to = f[i+1]
			case "lookup":
				lookup = f[i+1]
			}
		}
		p, ok := parseRouteDst(to)
		if ok && lookup == "main" {
			out[p] = true
		}
	}
	return out
}

func (b *wgctrlBackend) reconcileReturnRules(ctx context.Context, desiredRoutes map[netip.Prefix]bool) error {
	desired := make(map[netip.Prefix]bool)
	for _, p := range b.interfacePrefixes {
		if desiredRoutes[p] {
			desired[p] = true
		}
	}
	priority := strconv.Itoa(returnRulePriority)
	for _, fam := range []string{"-4", "-6"} {
		listing, err := b.runFn(ctx, "ip", fam, "rule", "show", "pref", priority)
		if err != nil {
			if fam == "-6" {
				continue
			}
			return err
		}
		current := returnRules(listing)
		for p := range desired {
			if (fam == "-4") != p.Addr().Is4() || current[p] {
				continue
			}
			if _, err := b.runFn(ctx, "ip", fam, "rule", "add", "pref", priority, "to", p.String(), "lookup", "main"); err != nil {
				return err
			}
		}
		for p := range current {
			if desired[p] {
				continue
			}
			slog.Info("tunnex_return_rule_pruned", "dst", p.String(), "priority", returnRulePriority)
			if _, err := b.runFn(ctx, "ip", fam, "rule", "del", "pref", priority, "to", p.String(), "lookup", "main"); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyRoutes reconciles the S8.2 site-to-site kernel routes on the tunnel iface. It installs each
// desired remote-subnet route (proto static + our metric; idempotent replace heals a flushed route) and
// PRUNES only OUR routes (proto static + siteRouteMetric) no longer desired — the full-sweep contract.
// Enumerates BOTH families (review #4: v6 inputs are refused today, but the prune must not silently miss
// a family if S8.4 admits v6 subnets).
func (b *wgctrlBackend) ApplyRoutes(ctx context.Context, cidrs []string, srcHint string) error {
	metric := strconv.Itoa(siteRouteMetric)
	desired := make(map[netip.Prefix]bool, len(cidrs))
	for _, c := range cidrs {
		p, ok := parseRouteDst(c)
		if !ok {
			continue // malformed CP input — never install a bad route
		}
		desired[p] = true
		args := []string{"route", "replace", p.String(), "dev", b.iface, "proto", "static", "metric", metric}
		if srcHint != "" {
			args = append(args, "src", srcHint) // D2 src-hint (reconcile-derived) — re-applied every tick, survives clobber
		}
		if _, err := b.runFn(ctx, "ip", args...); err != nil {
			return err
		}
	}
	// A host-network Kubernetes connector shares the host RPDB with its CNI.
	// Provider source rules can otherwise capture a pod-sourced SYN-ACK before
	// conntrack restores the VIP source. Reconcile only the configured wg subnet
	// that is also an explicit desired route; ordinary site routes are unchanged.
	if err := b.reconcileReturnRules(ctx, desired); err != nil {
		return err
	}
	for _, fam := range []string{"-4", "-6"} {
		out, err := b.runFn(ctx, "ip", fam, "route", "show", "dev", b.iface, "proto", "static", "metric", metric)
		if err != nil {
			// -6 is tolerated always (may be ipv6.disable=1; site subnets are v4-only today). -4 ALWAYS
			// SURFACES (F3 terminal): we cannot know whether a stale route needs pruning without
			// enumerating, so swallowing a -4 error would skip the full-sweep prune on the exact
			// UNBOUND-gateway transition where it is owed (stale route blackholing while green). Under
			// fail-static, a gateway whose `ip -4 route show` errors IS unhealthy — surfacing it is
			// correct, not a false alarm (the tolerate-when-no-desired-routes convenience was refused: it
			// could not distinguish never-had-routes from just-unbound, and the latter owes the sweep).
			if fam == "-6" {
				slog.Debug("site_route_enumerate_v6_skipped", "iface", b.iface, "error", err.Error())
				continue
			}
			return err
		}
		var toks []string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				toks = append(toks, f[0])
			}
		}
		for _, p := range routesToPrune(toks, desired) {
			// P8: log every deletion naming the route — our routes carry metric 8021, but a foreign route
			// that happens to share it is indistinguishable here, so the deletion must be LEGIBLE (the
			// metric-collision residual limitation made visible, not silent).
			slog.Info("site_route_pruned", "dst", p.String(), "iface", b.iface, "metric", siteRouteMetric)
			if _, err := b.runFn(ctx, "ip", "route", "del", p.String(), "dev", b.iface, "proto", "static", "metric", metric); err != nil {
				return err
			}
		}
	}
	return nil
}
