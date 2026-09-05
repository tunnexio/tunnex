//go:build linux

package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// wgctrlBackend is the real WireGuard data-plane adapter. It drives the standard
// tools (ip / wg / wireguard-go), so it works with kernel WireGuard or the
// userspace implementation. Peer convergence uses `wg syncconf`, which removes
// absent peers and leaves unchanged peers UNTOUCHED (no handshake reset) —
// idempotent against a dirty device.
type wgctrlBackend struct {
	iface                  string
	logger                 *slog.Logger
	preserveInterfaceAlias string
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
	// interfaceAddresses is the exact unmasked address set this process placed.
	// Kubernetes graceful shutdown removes these while preserving the manager's
	// alias-owned interface shell.
	interfaceAddresses []netip.Prefix
	// runFn shells `ip`/`wg` (defaults to the package run). Overridable in tests to inject a route-
	// enumeration fault, proving ApplyRoutes surfaces a -4 error (F3).
	runFn func(context.Context, string, ...string) (string, error)
}

func newWGCtrlBackend(iface string, logger *slog.Logger, options BackendOptions) (WGBackend, error) {
	return &wgctrlBackend{iface: iface, logger: logger, preserveInterfaceAlias: options.PreserveInterfaceAlias, runFn: run}, nil
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (b *wgctrlBackend) runCommand(ctx context.Context, name string, args ...string) (string, error) {
	if b.runFn != nil {
		return b.runFn(ctx, name, args...)
	}
	return run(ctx, name, args...)
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
		if _, err := b.runCommand(ctx, "wg", "set", b.iface, "private-key", keyFile.Name()); err != nil {
			return err
		}
	}
	// Set the listen port only when it differs — re-setting it to the current
	// value fails with "Address in use". A zero desired port would make wg pick a
	// random port, so refuse it.
	if cfg.ListenPort > 0 && cfg.ListenPort != curPort {
		if _, err := b.runCommand(ctx, "wg", "set", b.iface, "listen-port", strconv.Itoa(cfg.ListenPort)); err != nil {
			return err
		}
	}

	var interfacePrefixes, interfaceAddresses []netip.Prefix
	for _, addr := range strings.Split(cfg.Address, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return fmt.Errorf("invalid WireGuard interface address %q: %w", addr, err)
		}
		interfacePrefixes = append(interfacePrefixes, p.Masked())
		interfaceAddresses = append(interfaceAddresses, p)
	}
	// Publish ownership before mutation so a later address write failure still
	// leaves Close with the exact set it may safely withdraw.
	b.interfacePrefixes = interfacePrefixes
	b.interfaceAddresses = interfaceAddresses
	for _, prefix := range interfaceAddresses {
		addr := prefix.String()
		if b.hasAddress(ctx, addr) {
			continue
		}
		if _, err := b.runFn(ctx, "ip", "address", "replace", addr, "dev", b.iface); err != nil {
			return err
		}
	}
	return b.ensureLinkUp(ctx, cfg.MTU)
}

func (b *wgctrlBackend) ensureDevice(ctx context.Context) error {
	if b.preserveInterfaceAlias != "" {
		link, present, err := b.inspectOwnedInterface(ctx)
		if err != nil {
			return fmt.Errorf("inspect host-posture WireGuard interface: %w", err)
		}
		if !present {
			return fmt.Errorf("host-posture WireGuard interface %q is absent", b.iface)
		}
		if link.Name != b.iface || link.Kind != "wireguard" || link.Alias != b.preserveInterfaceAlias || link.IfIndex < 1 {
			return fmt.Errorf("refuse ambiguous host-posture WireGuard interface %q", b.iface)
		}
		return nil
	}
	if _, err := b.runCommand(ctx, "ip", "link", "show", b.iface); err == nil {
		return nil // already exists
	}
	// Kernel WireGuard (present on most modern kernels incl. Docker's LinuxKit
	// VM). Userspace wireguard-go is tried only if the binary is installed; a
	// clear error otherwise so readiness failure is diagnosable.
	if _, err := b.runCommand(ctx, "ip", "link", "add", "dev", b.iface, "type", "wireguard"); err == nil {
		return nil
	}
	if _, err := exec.LookPath("wireguard-go"); err == nil {
		if _, err := b.runCommand(ctx, "wireguard-go", b.iface); err == nil {
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
	out, err := b.runCommand(ctx, "wg", "show", b.iface, "dump")
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
	out, err := b.runCommand(ctx, "ip", "-o", "addr", "show", "dev", b.iface)
	if err != nil {
		return false
	}
	return strings.Contains(out, addr)
}

// ensureLinkUp sets MTU + brings the link up only if it is not already at the
// desired MTU and up.
func (b *wgctrlBackend) ensureLinkUp(ctx context.Context, mtu int) error {
	out, err := b.runCommand(ctx, "ip", "link", "show", b.iface)
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
	_, err = b.runCommand(ctx, "ip", setArgs...)
	return err
}

// Peers reads the current peer set from the device.
func (b *wgctrlBackend) Peers(ctx context.Context) ([]Peer, error) {
	out, err := b.runCommand(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		if interfaceAbsent(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseWGDump(out), nil
}

// Readback observes every effective WireGuard peer and only the route/rule
// shapes this backend owns. It deliberately reads the OS after apply; cached
// desired input is never accepted as proof of convergence.
func (b *wgctrlBackend) Readback(ctx context.Context) (WGBackendReadback, error) {
	peers, err := b.Peers(ctx)
	if err != nil {
		return WGBackendReadback{}, b.classifyReadbackError(err)
	}
	routeDetails, err := b.agentOwnedRouteDetails(ctx)
	if err != nil {
		return WGBackendReadback{}, b.classifyReadbackError(err)
	}
	rules, err := b.agentOwnedReturnRules(ctx)
	if err != nil {
		return WGBackendReadback{}, b.classifyReadbackError(err)
	}
	return WGBackendReadback{
		Peers:        peers,
		Routes:       routeDestinations(routeDetails),
		RouteDetails: routeDetails,
		ReturnRules:  sortedReturnRules(rules),
	}, nil
}

func (b *wgctrlBackend) classifyReadbackError(err error) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, strings.ToLower(b.iface)) &&
		(strings.Contains(message, "does not exist") || strings.Contains(message, "cannot find device") || strings.Contains(message, "unable to access interface")) {
		return fmt.Errorf("%w: %v", ErrWGInterfaceAbsent, err)
	}
	return err
}

// Stats parses per-peer live telemetry from `wg show <iface> dump`.
func (b *wgctrlBackend) Stats(ctx context.Context) ([]PeerStat, error) {
	out, err := b.runCommand(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseWGStats(out), nil
}

// Close deletes a legacy gateway-owned interface. With explicit host-posture
// ownership it instead downs and drains the exact alias-owned shell (keys,
// peers, addresses, owned routes/rules) while preserving alias+ifindex for the
// per-node manager and next gateway process.
func (b *wgctrlBackend) Close(ctx context.Context) error {
	if b.preserveInterfaceAlias != "" {
		link, present, err := b.inspectOwnedInterface(ctx)
		if err != nil {
			return fmt.Errorf("inspect preserved host-posture WireGuard interface: %w", err)
		}
		if !present {
			return nil
		}
		if link.Name != b.iface || link.Kind != "wireguard" || link.Alias != b.preserveInterfaceAlias || link.IfIndex < 1 {
			return fmt.Errorf("refuse ambiguous host-posture WireGuard shutdown for %q", b.iface)
		}
		return b.drainPreservedInterface(ctx, link)
	}
	if _, err := b.runFn(ctx, "ip", "link", "show", b.iface); err != nil {
		return nil // already absent → nothing to delete (idempotent)
	}
	_, err := b.runFn(ctx, "ip", "link", "del", b.iface)
	return err
}

type wireGuardDrainState struct {
	PrivateKey string
	PublicKey  string
	ListenPort int
	Peers      []string
}

func parseWireGuardDrainState(out string) (wireGuardDrainState, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return wireGuardDrainState{}, fmt.Errorf("WireGuard dump is empty")
	}
	fields := strings.Split(lines[0], "\t")
	if len(fields) != 4 {
		return wireGuardDrainState{}, fmt.Errorf("WireGuard interface dump is malformed")
	}
	port, err := strconv.Atoi(fields[2])
	if err != nil || port < 0 || port > 65535 {
		return wireGuardDrainState{}, fmt.Errorf("WireGuard listen port readback is invalid")
	}
	state := wireGuardDrainState{PrivateKey: fields[0], PublicKey: fields[1], ListenPort: port}
	seen := map[string]struct{}{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		peer := strings.Split(line, "\t")
		if len(peer) != 8 || peer[0] == "" || peer[0] == "(none)" || len(peer[0]) > 128 || strings.ContainsAny(peer[0], " \r\n\t") {
			return wireGuardDrainState{}, fmt.Errorf("WireGuard peer dump is malformed")
		}
		if _, duplicate := seen[peer[0]]; duplicate {
			return wireGuardDrainState{}, fmt.Errorf("WireGuard peer dump contains a duplicate key")
		}
		seen[peer[0]] = struct{}{}
		state.Peers = append(state.Peers, peer[0])
	}
	sort.Strings(state.Peers)
	return state, nil
}

func (b *wgctrlBackend) drainPreservedInterface(ctx context.Context, original ownedInterfaceLink) error {
	// First make packet processing impossible. Even if a later exact-state
	// enumeration fails, the alias-owned shell remains down rather than becoming
	// a headless tunnel after the egress hooks are reduced to marker-only state.
	if _, err := b.runCommand(ctx, "ip", "link", "set", "dev", b.iface, "down"); err != nil {
		return fmt.Errorf("bring preserved WireGuard shell down: %w", err)
	}
	wgDump, err := b.runCommand(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		return fmt.Errorf("read WireGuard state before shutdown: %w", err)
	}
	wgState, err := parseWireGuardDrainState(wgDump)
	if err != nil {
		return err
	}
	routes, err := b.agentOwnedRouteDetails(ctx)
	if err != nil {
		return fmt.Errorf("read owned routes before shutdown: %w", err)
	}
	rules, err := b.agentOwnedReturnRules(ctx)
	if err != nil {
		return fmt.Errorf("read owned return rules before shutdown: %w", err)
	}

	// Removing the private key is the cryptographic fail-closed boundary. A zero
	// listen port is retained only as a down-interface configuration; wg chooses
	// a port again only after the next gateway explicitly configures and raises it.
	if _, err := b.runCommand(ctx, "wg", "set", b.iface, "private-key", "/dev/null"); err != nil {
		return fmt.Errorf("remove WireGuard private key: %w", err)
	}
	if _, err := b.runCommand(ctx, "wg", "set", b.iface, "listen-port", "0"); err != nil {
		return fmt.Errorf("clear WireGuard listen port: %w", err)
	}
	for _, peer := range wgState.Peers {
		if _, err := b.runCommand(ctx, "wg", "set", b.iface, "peer", peer, "remove"); err != nil {
			return fmt.Errorf("remove WireGuard peer during shutdown: %w", err)
		}
	}
	for _, prefix := range b.interfaceAddresses {
		if _, err := b.runCommand(ctx, "ip", "address", "del", prefix.String(), "dev", b.iface); err != nil {
			return fmt.Errorf("remove owned WireGuard address %s: %w", prefix, err)
		}
	}
	for _, route := range routes {
		family := "-6"
		if route.Family == "ipv4" {
			family = "-4"
		} else if route.Family != "ipv6" {
			return fmt.Errorf("owned route family %q is ambiguous", route.Family)
		}
		args := []string{family, "route", "del", route.Destination, "dev", b.iface, "proto", "static", "metric", strconv.Itoa(siteRouteMetric)}
		if route.Source != "" {
			args = append(args, "src", route.Source)
		}
		if _, err := b.runCommand(ctx, "ip", args...); err != nil {
			return fmt.Errorf("remove owned route %s: %w", route.Destination, err)
		}
	}
	for _, prefix := range sortedPrefixStrings(rules) {
		parsed, parseErr := netip.ParsePrefix(prefix)
		if parseErr != nil {
			return fmt.Errorf("owned return-rule prefix %q became invalid", prefix)
		}
		family := "-6"
		if parsed.Addr().Is4() {
			family = "-4"
		}
		if _, err := b.runCommand(ctx, "ip", family, "rule", "del", "pref", strconv.Itoa(returnRulePriority), "to", prefix, "lookup", "main"); err != nil {
			return fmt.Errorf("remove owned return rule %s: %w", prefix, err)
		}
	}

	finalDump, err := b.runCommand(ctx, "wg", "show", b.iface, "dump")
	if err != nil {
		return fmt.Errorf("read WireGuard state after shutdown: %w", err)
	}
	finalWG, err := parseWireGuardDrainState(finalDump)
	if err != nil || len(finalWG.Peers) != 0 || finalWG.PrivateKey != "(none)" || finalWG.PublicKey != "(none)" || finalWG.ListenPort != 0 {
		return fmt.Errorf("WireGuard shutdown readback is not a keyless peerless closed shell")
	}
	if remaining, err := b.agentOwnedRouteDetails(ctx); err != nil || len(remaining) != 0 {
		if err != nil {
			return fmt.Errorf("read owned routes after shutdown: %w", err)
		}
		return fmt.Errorf("owned route shutdown readback is not empty")
	}
	if remaining, err := b.agentOwnedReturnRules(ctx); err != nil || len(remaining) != 0 {
		if err != nil {
			return fmt.Errorf("read owned return rules after shutdown: %w", err)
		}
		return fmt.Errorf("owned return-rule shutdown readback is not empty")
	}
	liveAddresses, err := b.liveInterfaceAddresses(ctx)
	if err != nil {
		return fmt.Errorf("read WireGuard addresses after shutdown: %w", err)
	}
	for _, prefix := range b.interfaceAddresses {
		if liveAddresses[prefix] {
			return fmt.Errorf("owned WireGuard address %s remains after shutdown", prefix)
		}
	}
	link, present, err := b.inspectOwnedInterface(ctx)
	if err != nil {
		return fmt.Errorf("read manager-owned WireGuard shell after shutdown: %w", err)
	}
	if !present || link != original {
		return fmt.Errorf("manager-owned WireGuard shell identity changed during shutdown")
	}
	b.privKey, b.listenPort = "", 0
	b.interfacePrefixes = nil
	b.interfaceAddresses = nil
	return nil
}

func (b *wgctrlBackend) liveInterfaceAddresses(ctx context.Context) (map[netip.Prefix]bool, error) {
	out, err := b.runCommand(ctx, "ip", "-j", "address", "show", "dev", b.iface)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		IfName   string `json:"ifname"`
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 || rows[0].IfName != b.iface {
		return nil, fmt.Errorf("address readback is malformed or ambiguous")
	}
	addresses := make(map[netip.Prefix]bool, len(rows[0].AddrInfo))
	for _, info := range rows[0].AddrInfo {
		address, err := netip.ParseAddr(info.Local)
		if err != nil || info.PrefixLen < 0 || info.PrefixLen > address.BitLen() ||
			(info.Family == "inet") != address.Is4() || (info.Family != "inet" && info.Family != "inet6") {
			return nil, fmt.Errorf("address readback contains an invalid entry")
		}
		addresses[netip.PrefixFrom(address, info.PrefixLen)] = true
	}
	return addresses, nil
}

type ownedInterfaceLink struct {
	Name    string
	Alias   string
	Kind    string
	IfIndex int
}

func (b *wgctrlBackend) inspectOwnedInterface(ctx context.Context) (ownedInterfaceLink, bool, error) {
	out, err := b.runCommand(ctx, "ip", "-j", "-d", "link", "show", "dev", b.iface)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "does not exist") || strings.Contains(message, "cannot find device") {
			return ownedInterfaceLink{}, false, nil
		}
		return ownedInterfaceLink{}, false, err
	}
	var rows []struct {
		IfIndex  int    `json:"ifindex"`
		IfName   string `json:"ifname"`
		IfAlias  string `json:"ifalias"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		return ownedInterfaceLink{}, false, fmt.Errorf("link readback is malformed or ambiguous")
	}
	row := rows[0]
	return ownedInterfaceLink{Name: row.IfName, Alias: row.IfAlias, Kind: row.LinkInfo.Kind, IfIndex: row.IfIndex}, true, nil
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
	// A graceful shutdown deletes wg0. On the next process start, the ownership
	// emergency sweep runs before ordinary desired state recreates it. Applying
	// an empty peer set to an absent interface is already fully withdrawn; do not
	// turn that safe zero state into a restart loop. Non-empty desired peers still
	// fail loudly so an absent data plane can never be mistaken for convergence.
	if len(peers) == 0 {
		if _, err := b.runCommand(ctx, "wg", "show", b.iface, "dump"); err != nil {
			if interfaceAbsent(err) {
				return nil
			}
			return err
		}
	}
	f, err := os.CreateTemp("", "wgconf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(buildSyncConf(b.privKey, b.listenPort, peers)); err != nil {
		return err
	}
	_ = f.Close()
	_, err = b.runCommand(ctx, "wg", "syncconf", b.iface, f.Name())
	return err
}

// interfaceAbsent recognizes only the operating-system errors that prove the
// requested link is not present. Permission failures, missing binaries, and
// every other readback failure remain fatal because they cannot prove a
// withdrawn data plane.
func interfaceAbsent(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such device") ||
		(strings.Contains(message, "device") && strings.Contains(message, "does not exist")) ||
		strings.Contains(message, "cannot find device")
}

// siteRouteMetric tags every S8.2 kernel route we own. The prune enumerates + deletes ONLY routes
// carrying BOTH `proto static` AND this metric, so an operator's / routing-daemon's own static route on
// wg0 (any other metric, or none) is NEVER touched (review #2). We picked a distinct metric over a
// dedicated routing table: a table needs an `ip rule` to steer forwarding into it (policy routing on the
// data path); a metric scopes ownership without touching how packets are routed (a lone route to a
// prefix is selected regardless of metric).
// parseRouteDst canonicalizes a route destination token to a netip.Prefix. `ip route show` prints a host
// route as a BARE address (no /32), so a desired "10.1.0.5/32" must compare equal to an enumerated
// "10.1.0.5" (review #3: string compare churned /32 routes install→delete every tick). A bare address
// becomes a full-length prefix.
func parseRouteDst(tok string) (netip.Prefix, bool) {
	return canonicalRoutePrefix(tok)
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

// agentOwnedRoutes enumerates routes and retains the exact shape ApplyRoutes
// owns. We cannot ask iproute2 to filter by the tunnel interface or ownership
// attributes: on a host-network Kubernetes connector its filtered rendering
// can omit the dev, proto, or metric fields. IPv4
// enumeration errors are fatal because a complete full-sweep/readback is then
// impossible; IPv6 remains optional while the product admits IPv4 site ranges.
func (b *wgctrlBackend) agentOwnedRoutes(ctx context.Context) (map[netip.Prefix]bool, error) {
	details, err := b.agentOwnedRouteDetails(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Prefix]bool, len(details))
	for _, route := range details {
		prefix, _ := canonicalRoutePrefix(route.Destination)
		out[prefix] = true
	}
	return out, nil
}

func (b *wgctrlBackend) agentOwnedRouteDetails(ctx context.Context) ([]OwnedRoute, error) {
	metric := strconv.Itoa(siteRouteMetric)
	var out []OwnedRoute
	for _, family := range []string{"-4", "-6"} {
		listing, err := b.runCommand(ctx, "ip", family, "route", "show")
		if err != nil {
			if interfaceAbsent(err) {
				continue
			}
			if family == "-6" {
				slog.Debug("site_route_enumerate_v6_skipped", "iface", b.iface, "error", err.Error())
				continue
			}
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if !hasOwnedRouteAttributes(line, b.iface, metric) {
				continue
			}
			route, err := parseOwnedRoute(line, family, b.iface)
			if err != nil {
				return nil, err
			}
			out = append(out, route)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Destination != out[j].Destination {
			return out[i].Destination < out[j].Destination
		}
		return out[i].Family < out[j].Family
	})
	return out, nil
}

// hasOwnedRouteAttributes is the narrow classifier for the broad route
// readback. A kernel-created connected route on wg0 is foreign state; only the
// exact proto+metric pair installed by ApplyRoutes is eligible for parsing or
// pruning.
func hasOwnedRouteAttributes(line, iface, metric string) bool {
	fields := strings.Fields(line)
	var device, protocol, routeMetric string
	for i := 1; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			device = fields[i+1]
			i++
		case "proto":
			protocol = fields[i+1]
			i++
		case "metric":
			routeMetric = fields[i+1]
			i++
		}
	}
	return device == iface && protocol == "static" && routeMetric == metric
}

func parseOwnedRoute(line, familyFlag, iface string) (OwnedRoute, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return OwnedRoute{}, fmt.Errorf("empty agent-owned route line")
	}
	prefix, ok := parseRouteDst(fields[0])
	if !ok || (familyFlag == "-4") != prefix.Addr().Is4() {
		return OwnedRoute{}, fmt.Errorf("invalid agent-owned route destination %q", fields[0])
	}
	route := OwnedRoute{Destination: prefix.String(), Family: "ipv6"}
	if prefix.Addr().Is4() {
		route.Family = "ipv4"
	}
	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "dev", "proto", "metric", "src":
			if i+1 >= len(fields) {
				return OwnedRoute{}, fmt.Errorf("missing %s value in agent-owned route %q", fields[i], line)
			}
			value := fields[i+1]
			i++
			switch fields[i-1] {
			case "dev":
				route.Device = value
			case "proto":
				route.Protocol = value
			case "metric":
				parsed, err := strconv.Atoi(value)
				if err != nil {
					return OwnedRoute{}, fmt.Errorf("invalid agent-owned route metric %q", value)
				}
				route.Metric = parsed
			case "src":
				addr, err := netip.ParseAddr(value)
				if err != nil || addr.Is4() != prefix.Addr().Is4() || addr.String() != value {
					return OwnedRoute{}, fmt.Errorf("invalid agent-owned route source %q", value)
				}
				route.Source = value
			}
		}
	}
	if route.Device != iface || route.Protocol != "static" || route.Metric != siteRouteMetric {
		return OwnedRoute{}, fmt.Errorf("route does not carry Tunnex ownership attributes: %q", line)
	}
	return route, nil
}

func routeDestinations(routes []OwnedRoute) []string {
	out := make([]string, len(routes))
	for i, route := range routes {
		out[i] = route.Destination
	}
	sort.Strings(out)
	return out
}

// agentOwnedReturnRules enumerates and parses only the exact Tunnex priority,
// destination and lookup-main shape. Other rules at the same priority remain
// foreign and invisible to both reconcile and readback.
func (b *wgctrlBackend) agentOwnedReturnRules(ctx context.Context) (map[netip.Prefix]bool, error) {
	out := make(map[netip.Prefix]bool)
	for _, family := range []string{"-4", "-6"} {
		current, err := b.agentOwnedReturnRulesForFamily(ctx, family)
		if err != nil {
			if family == "-6" {
				continue
			}
			return nil, err
		}
		for prefix := range current {
			out[prefix] = true
		}
	}
	return out, nil
}

func (b *wgctrlBackend) agentOwnedReturnRulesForFamily(ctx context.Context, family string) (map[netip.Prefix]bool, error) {
	listing, err := b.runCommand(ctx, "ip", family, "rule", "show", "pref", strconv.Itoa(returnRulePriority))
	if err != nil {
		return nil, err
	}
	return returnRules(listing), nil
}

func sortedPrefixStrings(prefixes map[netip.Prefix]bool) []string {
	out := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		out = append(out, prefix.String())
	}
	sort.Strings(out)
	return out
}

func sortedReturnRules(prefixes map[netip.Prefix]bool) []ReturnRule {
	routes := sortedPrefixStrings(prefixes)
	out := make([]ReturnRule, len(routes))
	for i, route := range routes {
		out[i] = ReturnRule{Priority: returnRulePriority, Destination: route, Lookup: "main"}
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
		current, err := b.agentOwnedReturnRulesForFamily(ctx, fam)
		if err != nil {
			if fam == "-6" {
				continue
			}
			return err
		}
		for p := range desired {
			if (fam == "-4") != p.Addr().Is4() || current[p] {
				continue
			}
			if _, err := b.runCommand(ctx, "ip", fam, "rule", "add", "pref", priority, "to", p.String(), "lookup", "main"); err != nil {
				return err
			}
		}
		for p := range current {
			if (fam == "-4") != p.Addr().Is4() || desired[p] {
				continue
			}
			slog.Info("tunnex_return_rule_pruned", "dst", p.String(), "priority", returnRulePriority)
			if _, err := b.runCommand(ctx, "ip", fam, "rule", "del", "pref", priority, "to", p.String(), "lookup", "main"); err != nil {
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
	current, err := b.agentOwnedRoutes(ctx)
	if err != nil {
		return err
	}
	for _, p := range routesToPrune(sortedPrefixStrings(current), desired) {
		// P8: log every deletion naming the route — our routes carry metric 8021, but a foreign route
		// that happens to share it is indistinguishable here, so the deletion must be LEGIBLE (the
		// metric-collision residual limitation made visible, not silent).
		slog.Info("site_route_pruned", "dst", p.String(), "iface", b.iface, "metric", siteRouteMetric)
		if _, err := b.runCommand(ctx, "ip", "route", "del", p.String(), "dev", b.iface, "proto", "static", "metric", metric); err != nil {
			return err
		}
	}
	return nil
}
