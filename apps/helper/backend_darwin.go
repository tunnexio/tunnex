//go:build darwin

package helper

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// pfAnchor is the pf anchor name the kill-switch rules load into. It is
// kernel-resident: it persists if the helper dies (fail-closed). It is released by
// a graceful Down, the dead-man timeout, OR — if the process died abnormally — the
// next helper's startup CleanStale. See the S6.3 KILL-SWITCH DESIGN in PLAN.
const pfAnchor = "tunnex"

// pfTokenPath persists the `pfctl -E` enable-reference token so that a FRESH helper
// process (after a crash / kill -9 lost the in-memory copy) can release the exact
// reference on startup instead of force-disabling pf for the whole system. Root-only.
const pfTokenPath = "/var/run/tunnex/pf.token"

// dnsBackupPath persists each network service's PRIOR DNS setting while a full tunnel
// has hijacked the system resolver, so Down (or a crashed-then-restarted helper's
// CleanStale) can restore it. Same crash-safe pattern as pfTokenPath. Root-only.
const dnsBackupPath = "/var/run/tunnex/dns.json"

// darwinBackend implements Backend on macOS with wireguard-go (userspace WG over a
// utun) + a pf kill-switch + ifconfig/route for addressing. Ordering invariant:
// Up arms the pf backstop BEFORE moving routes; Down restores routing then flushes
// pf LAST.
type darwinBackend struct {
	mu      sync.Mutex
	dev     *device.Device
	tunDev  tun.Device
	ifname  string
	pfToken string // reference-counted `pfctl -E` token, released (not -d) on Down
	// endpointHost is the WG endpoint IP for which a full tunnel pins a host route
	// via the PHYSICAL gateway (so WG's own encrypted packets don't loop back into
	// the tunnel). endpointFam is "-inet"/"-inet6" so Down deletes it correctly.
	endpointHost string
	endpointFam  string
	// applied is the per-session BELIEF CACHE (S8.5 reduce) of the OS route-targets we believe are in the
	// kernel — set on Up (baked base), reconciled by SetAllowedIPs, cleared on Down. NEVER persisted. Keys
	// are canonical route-targets (routeSet form). See reconcileRoutes for the belief-drift stance.
	applied map[string]bool
	// peer* track the CURRENT gateway peer so a WF-A re-home (SetGatewayPeer) knows which key to remove and
	// which allowed_ips/keepalive to preserve onto the new peer. peerPubKey seeds on Up and advances on each
	// re-home (the config's PeerPublicKey goes stale after the first swap); peerAllowedIPs seeds on Up and
	// advances on every SetAllowedIPs route push (so a re-home carries the LIVE crypto-routing, not the
	// baked set). Cleared on Down.
	peerPubKey     string
	peerAllowedIPs []string
	peerKeepalive  int
	// fullTunnel records whether the live tunnel is full (kill-switch armed). A WF-A re-home of a FULL
	// tunnel must re-point the pf carve-out + WG host-route (D-WFA-4); a split re-home is a bare peer swap.
	fullTunnel bool
	// cpEndpoint is the resolved CP host:port the full-tunnel kill-switch carves ONE pass out to (D-WFA-4),
	// so the control channel survives the tunnel going down. Empty = no carve-out (split tunnel, or a
	// full tunnel whose client sent no control_plane_endpoint / a CP that would not resolve) → full-tunnel
	// re-home is refused. cpHost/cpFam are the pinned host-route for Down cleanup.
	cpEndpoint string
	cpHost     string
	cpFam      string
	// physGwV4/physGwV6 are the PHYSICAL default gateway per family, captured at Up (WF-A-FT-1) BEFORE the
	// full-tunnel default is installed. A re-home (SetGatewayPeer) pins the new WG endpoint's host-route via
	// THIS stored value — NOT gatewayFor(), which at re-home time returns the TUNNEL next-hop (the tunnel
	// 0.0.0.0/1 half is more specific than the physical 0.0.0.0/0, so a route-get for a new endpoint resolves
	// into the tunnel → the new gateway's outer packets loop into the dead tunnel and the handshake never
	// completes: the exact WF-A-FT-1 stuck-on-connecting failure the walk found).
	//
	// STALENESS (v1 stance, named seam): if the physical network CHANGES mid-session (Wi-Fi→Ethernet, a DHCP
	// renew moving the router), this stored value goes stale. A re-home pin against a stale gateway then FAILS
	// VISIBLY — the handshake doesn't complete — the SAME surface as a genuine network change, NOT a silent
	// self-inflicted loop. WG socket rebinding handles real roaming; a future roaming story owns re-deriving
	// this (it inherits this seam). The RR2-family alternative (re-derive with the tunnel routes temporarily
	// excluded) is more machinery on the kill-switch path for an edge this stance already covers — refused
	// unless store-at-Up proves unworkable.
	physGwV4 string
	physGwV6 string
	// routeRun is the `route` exec seam (nil → the real `route` CLI) so the re-home pin's chosen next-hop is
	// assertable in a test without a live routing table.
	routeRun func(args ...string) error
	// ifconfigRun is the address-setup seam; it keeps family-specific command
	// construction testable without mutating a real utun interface.
	ifconfigRun func(args ...string) error
}

// rr runs the `route` CLI (via the routeRun seam when set — tests capture the args).
func (b *darwinBackend) rr(args ...string) error {
	if b.routeRun != nil {
		return b.routeRun(args...)
	}
	return run("route", args...)
}

// physGatewayFor selects the stored physical gateway for `host`'s family (WF-A-FT-1) — v6 host → v6 gateway,
// else v4. Pure; the per-family guard (fold #2) applied to the re-home pin.
func physGatewayFor(host, v4, v6 string) string {
	if strings.Contains(host, ":") {
		return v6
	}
	return v4
}

// NewBackend returns the macOS tunnel backend.
func NewBackend() Backend { return &darwinBackend{} }

func (b *darwinBackend) Up(cfg *TunnelConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Resolve a hostname endpoint to ONE IP up front so the pf pass rule, the endpoint
	// host-route, and wireguard-go all pin the same address (review #10).
	ep, err := resolveEndpoint(cfg.Endpoint)
	if err != nil {
		return err
	}
	cfg.Endpoint = ep

	b.fullTunnel = cfg.FullTunnel
	// D-WFA-4: for a FULL tunnel, resolve the CP endpoint to ONE IP up front (best-effort) so the pf
	// carve-out below (armPF reads b.cpEndpoint) permits + pins exactly it. A CP that will not resolve =
	// NO carve-out: the tunnel still comes up, but full-tunnel re-home is then unavailable (SetGatewayPeer
	// refuses, the client fail-statics) — an honest degrade, never a broadened block.
	b.cpEndpoint = ""
	if cfg.FullTunnel && cfg.ControlPlaneEndpoint != "" {
		if cpEp, e := resolveEndpoint(cfg.ControlPlaneEndpoint); e == nil {
			b.cpEndpoint = cpEp
		}
	}
	// WF-A-FT-1: capture the PHYSICAL default gateway per family NOW (before the tunnel default is installed
	// below), so a later full-tunnel re-home pins the new WG endpoint via this stored next-hop instead of
	// re-deriving it through the tunnel-polluted route table. Only meaningful for a full tunnel (a split
	// tunnel has no kill-switch / endpoint host-route to move). Empty when there is no physical default.
	b.physGwV4, b.physGwV6 = "", ""
	if cfg.FullTunnel {
		b.physGwV4 = gatewayFor("default", "-inet")
		b.physGwV6 = gatewayFor("default", "-inet6")
	}

	// 0) CLEAN stale kill-switch state from a prior FailClosed/crash before (re)arming.
	//    A SPLIT tunnel must NOT inherit a full tunnel's block-all (it wants cleartext
	//    routing) — release it. (Full-tunnel re-arm below is idempotent; the stale
	//    endpoint route is cleared idempotently at the add site in step 3a.)
	if !cfg.FullTunnel {
		_ = b.releasePF()
	}

	// 1) ARM the kill-switch FIRST — but ONLY for a FULL tunnel. A split tunnel
	//    routes just its allowed-IPs and leaves the rest of the user's traffic on
	//    the normal cleartext default route BY DESIGN, so there is nothing to
	//    kill-switch (block-all would wrongly kill the user's internet). Full
	//    tunnel: block everything except the WG endpoint + loopback + DHCP/NDP,
	//    before any route moves.
	if cfg.FullTunnel {
		if err := b.armPF(cfg.Endpoint, ""); err != nil {
			return fmt.Errorf("arm kill-switch: %w", err)
		}
	}

	// 2) Create the utun + wireguard-go device, configure it.
	tdev, err := tun.CreateTUN("utun", deviceMTU(cfg))
	if err != nil {
		return fmt.Errorf("create utun: %w", err)
	}
	name, _ := tdev.Name()
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "tunnex-helper: "))
	uapi, err := uapiConfig(cfg)
	if err != nil {
		_ = tdev.Close()
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		_ = tdev.Close()
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		_ = tdev.Close()
		return fmt.Errorf("device up: %w", err)
	}

	// 2b) Full tunnel: reload the anchor now that the tunnel exists so traffic may
	//     leave on it (still BEFORE routes — a failure here keeps everything blocked).
	if cfg.FullTunnel {
		if err := b.armPF(cfg.Endpoint, name); err != nil {
			dev.Close()
			return fmt.Errorf("allow tunnel in kill-switch: %w", err)
		}
	}

	// 3) ONLY NOW move routes onto the tunnel (address + allowed-IPs).
	if err := b.assignAddresses(name, cfg.Addresses, cfg.Address); err != nil {
		dev.Close()
		return err
	}
	// 3a) FULL TUNNEL: pin a /32 host route for the WG endpoint via the CURRENT
	//     physical default gateway, BEFORE the default moves onto utun. Without this,
	//     wireguard-go's own OUTER (encrypted) packets to the gateway match the
	//     0.0.0.0/1 tunnel route and loop back into the tunnel — tx explodes, nothing
	//     egresses (what `wg-quick` calls the endpoint route).
	if cfg.FullTunnel {
		if epHost, _ := splitEndpoint(cfg.Endpoint); epHost != "" {
			fam, perr := b.pinPhysHostRoute(epHost)
			if perr != nil {
				dev.Close()
				return perr
			}
			if fam != "" {
				b.endpointHost, b.endpointFam = epHost, fam
			}
		}
	}
	// 3b) FULL TUNNEL + D-WFA-4: pin the CP endpoint host-route via the physical gateway too — same reason
	//     as the WG endpoint: the control channel's TLS must egress PHYSICALLY (not loop into the tunnel),
	//     so it survives the tunnel going down and the re-home poll works during a hard hub death. The pf
	//     pass alone (armed above) is not enough — without the route the CP IP matches the 0.0.0.0/1 tunnel
	//     half. Hard fail like the WG pin: a half carve-out (pass, no route) must never persist.
	if cfg.FullTunnel && b.cpEndpoint != "" {
		if cpHost, _ := splitEndpoint(b.cpEndpoint); cpHost != "" {
			fam, perr := b.pinPhysHostRoute(cpHost)
			if perr != nil {
				dev.Close()
				return perr
			}
			// Guard fam like the WG-endpoint pin above (review #2): an on-link CP (gatewayFor "" → fam "")
			// pins NO route and needs none (its connected route is more specific than the tunnel half), so
			// don't record cpHost with an empty fam — Down would else run `route delete` with a blank family.
			if fam != "" {
				b.cpHost, b.cpFam = cpHost, fam
			}
		}
	}
	// Baked routes go through the ONE reconciler (S8.5 reduce, #9) — same delete-before-add + per-route
	// discipline as the pushed ranges. ifname must be set first (routeCmd reads it).
	b.ifname = name
	b.applied = map[string]bool{}
	if err := reconcileRoutes(b.applied, routeSet(cfg.AllowedIPs), b.routeCmd); err != nil {
		b.ifname = ""
		b.applied = nil
		dev.Close()
		return err
	}

	// 4) FULL TUNNEL: move the system resolver onto the tunnel. Full-tunnel captures
	//    ALL traffic (0.0.0.0/0) AND the kill-switch blocks every non-tunnel egress —
	//    so the machine's existing DHCP/LAN resolver is now UNREACHABLE and name
	//    resolution would die (ping-by-IP works, everything by-name fails). Point every
	//    network service at the config's DNS (reachable through the tunnel), saving the
	//    prior setting so Down/CleanStale restores it. Split tunnel keeps its own DNS
	//    (cfg.DNS is empty there — config.go dnsFor), so this is scoped to full-tunnel.
	if cfg.FullTunnel && len(cfg.DNS) > 0 {
		applyDNS(cfg.DNS)
	}

	b.dev, b.tunDev, b.ifname = dev, tdev, name
	// Seed the current-peer cache for a WF-A re-home (SetGatewayPeer): the key to swap out, and the
	// allowed_ips/keepalive to carry onto the new peer.
	b.peerPubKey, b.peerAllowedIPs, b.peerKeepalive = cfg.PeerPublicKey, append([]string(nil), cfg.AllowedIPs...), cfg.PersistentKeepalive
	return nil
}

// assignAddresses applies each interface address with the syntax required by
// its address family. macOS rejects an IPv6 address passed to `inet` (the old
// code produced `bad value`), and inet6 takes an explicit prefix length rather
// than the IPv4 point-to-point destination form.
func (b *darwinBackend) assignAddresses(ifname string, addresses []string, fallback string) error {
	if len(addresses) == 0 {
		addresses = []string{fallback}
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return fmt.Errorf("parse address: %w", err)
		}
		var args []string
		if prefix.Addr().Is6() {
			args = []string{ifname, "inet6", prefix.Addr().String(), "prefixlen", fmt.Sprint(prefix.Bits()), "up"}
		} else {
			args = []string{ifname, "inet", prefix.Addr().String(), prefix.Addr().String(), "up"}
		}
		runIfconfig := b.ifconfigRun
		if runIfconfig == nil {
			runIfconfig = func(a ...string) error { return run("ifconfig", a...) }
		}
		if err := runIfconfig(args...); err != nil {
			return fmt.Errorf("assign address: %w", err)
		}
	}
	return nil
}

// SetAllowedIPs live-updates the peer's AllowedIPs (S8.5): a uapi update (no handshake reset) + an
// OS-route full-sweep (add new, delete gone). Never touches the device identity, the peer's keys, the
// endpoint, or the pf kill-switch. b.mu serializes against Up/Down.
func (b *darwinBackend) SetAllowedIPs(peerPubKey string, allowedIPs []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		return &ProtocolError{Code: "not_up", Msg: "no active tunnel device"}
	}
	uapi, err := allowedIPsUAPI(peerPubKey, allowedIPs)
	if err != nil {
		return err
	}
	if err := b.dev.IpcSet(uapi); err != nil {
		return &ProtocolError{Code: "allowed_ips_apply_failed", Msg: err.Error()}
	}
	// Advance the peer cache so a subsequent WF-A re-home carries the LIVE routing, not the baked set.
	// (review #5 — no-change rationale, recorded: advancing BEFORE reconcileRoutes is correct. The cache
	// feeds only the re-home's crypto allowed_ips, and a re-home NEVER touches OS routes — they ride the
	// interface, not the peer. So a reconcile failure here can't make a later re-home lose routes; any
	// crypto-vs-route skew is this SetAllowedIPs' own reconcile-fail, self-healing on the monitor's retry.)
	b.peerAllowedIPs = append([]string(nil), allowedIPs...)
	// OS-route full-sweep through the ONE reconciler (S8.5 reduce): delete-before-add, delete-stale-first,
	// per-route advance against the belief cache. The crypto (replace_allowed_ips) already converged above.
	return reconcileRoutes(b.applied, routeSet(allowedIPs), b.routeCmd)
}

// SetGatewayPeer live re-homes the tunnel onto a new gateway peer (WF-A) — a peer SWAP with the CURRENT
// peer's allowed_ips/keepalive preserved, no bounce, no handshake reset on the surviving interface. The
// device identity (own key) and the interface address are UNTOUCHED.
//   - SPLIT tunnel: a bare peer swap — the OS routes point at the interface, not the peer, so no route
//     reconcile is needed, and there is no kill-switch.
//   - FULL tunnel (D-WFA-4): after the swap, RE-POINT the kill-switch to the NEW gateway — re-arm pf with
//     the new WG endpoint (re-emitting the CP carve-out) + move the WG endpoint host-route — or the new
//     gateway's handshake is block-dropped + route-looped. REQUIRES the CP carve-out (b.cpEndpoint): without
//     it a full-tunnel device could never have polled a re-home in the first place, so refuse honestly.
func (b *darwinBackend) SetGatewayPeer(newPubKey, newEndpoint string) error {
	// Resolve to ONE IP BEFORE taking b.mu (review #1): a DNS lookup's latency must NEVER hold a lock the
	// fail-closed path needs. b.mu is also taken by the dead-man's FailClosed — a slow re-home resolve
	// blocking it would delay kill-switch enforcement during a failover, exactly when it matters most (the
	// kill-switch-no-unbounded-I/O law; the RR2 FS-I/O-outside-the-lock lesson recurring at the DNS tier).
	ep, err := resolveEndpoint(newEndpoint)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		return &ProtocolError{Code: "not_up", Msg: "no active tunnel device"}
	}
	if b.fullTunnel && b.cpEndpoint == "" {
		// A full tunnel with no CP carve-out cannot safely re-home (its handshake to the new gateway would
		// be block-dropped, and it never had a tunnel-independent control path). The honest failure seam.
		return &ProtocolError{Code: "rehome_full_tunnel_unsupported", Msg: "full-tunnel re-home requires the CP carve-out (control_plane_endpoint)"}
	}
	uapi, err := gatewayPeerSwapUAPI(b.peerPubKey, newPubKey, ep, b.peerKeepalive, b.peerAllowedIPs)
	if err != nil {
		return err
	}
	// Swap the crypto peer FIRST (swap-first is recoverable: if the pf re-point below fails, the client
	// fail-statics and retries; a pf-first order could strand the OLD tunnel if the swap then failed).
	if err := b.dev.IpcSet(uapi); err != nil {
		return &ProtocolError{Code: "gateway_peer_apply_failed", Msg: err.Error()}
	}
	// WF-A-obs-1: log the successful swap (pubkeys are public; no secrets). Without this a re-home that
	// SUCCEEDS and one that silently loops (the WF-A-FT-1 class) look identical in the logs — this line is
	// the breadcrumb that turns the next such diagnosis into a log-read instead of a source-trace.
	log.Printf("gateway_peer_swapped: pubkey %s -> %s, endpoint -> %s, full_tunnel=%v (no bounce)", b.peerPubKey, newPubKey, ep, b.fullTunnel)
	b.peerPubKey = newPubKey // the new peer is now current; a later re-home swaps IT out

	if b.fullTunnel {
		// Re-arm pf with the NEW WG endpoint (buildPFRules re-emits the CP pass from b.cpEndpoint), so the
		// new gateway's encrypted UDP is permitted and the old endpoint no longer is.
		if err := b.armPF(ep, b.ifname); err != nil {
			return &ProtocolError{Code: "gateway_peer_pf_failed", Msg: err.Error()}
		}
		// Move the WG endpoint host-route: delete the OLD pin, add the NEW (so the new gateway's outer
		// packets egress physically instead of looping into the tunnel).
		newHost, _ := splitEndpoint(ep)
		if b.endpointHost != "" && b.endpointHost != newHost {
			_ = run("route", "-q", "delete", b.endpointFam, "-host", b.endpointHost)
			b.endpointHost, b.endpointFam = "", ""
		}
		if newHost != "" {
			// WF-A-FT-1: pin via the STORED physical gateway (captured at Up), NOT gatewayFor — by re-home
			// time the tunnel default is installed, so gatewayFor would return the tunnel next-hop and loop
			// the new gateway's handshake (the stuck-on-connecting bug the walk found).
			fam, perr := b.pinHostRouteVia(newHost, physGatewayFor(newHost, b.physGwV4, b.physGwV6))
			if perr != nil {
				return &ProtocolError{Code: "gateway_peer_route_failed", Msg: perr.Error()}
			}
			if fam != "" {
				b.endpointHost, b.endpointFam = newHost, fam
			}
		}
	}
	return nil
}

// pinPhysHostRoute pins a /32 (or /128) host route for `host` via the CURRENT physical default gateway, so
// a packet to that host egresses on the physical NIC instead of matching the 0.0.0.0/1 tunnel half and
// looping (the WG endpoint + the D-WFA-4 CP carve-out both need this). Idempotent (delete-before-add, so a
// prior FailClosed/crash's leftover physical-gateway route can't fail the re-add "File exists"). Returns the
// family flag ("-inet"/"-inet6") pinned, or "" when the host is on-link/unresolved (nothing to pin — not an
// error). b.mu is held by every caller (Up / SetGatewayPeer).
// pinPhysHostRoute derives the physical next-hop via gatewayFor (VALID only PRE-tunnel-default — i.e. at Up,
// where 0.0.0.0/0 is still the most specific default) then pins. Used by Up's WG + CP endpoint pins.
// A re-home must NOT use this (gatewayFor is polluted by the tunnel default) — it uses pinHostRouteVia with
// the stored physical gateway (WF-A-FT-1).
func (b *darwinBackend) pinPhysHostRoute(host string) (fam string, err error) {
	famFlag := "-inet"
	if strings.Contains(host, ":") {
		famFlag = "-inet6"
	}
	return b.pinHostRouteVia(host, gatewayFor(host, famFlag))
}

// pinHostRouteVia pins a /32|/128 host-route for `host` via an EXPLICIT gateway `gw` (delete-before-add,
// idempotent). Empty gw → nothing pinned, fam="" (on-link, or no stored physical gateway). The re-home path
// passes the STORED physical gateway (WF-A-FT-1); Up passes gatewayFor's pre-tunnel result. Because gw is a
// PARAMETER, this path structurally cannot re-derive the tunnel next-hop — the loop bug can't recur here.
func (b *darwinBackend) pinHostRouteVia(host, gw string) (fam string, err error) {
	fam = "-inet"
	if strings.Contains(host, ":") {
		fam = "-inet6"
	}
	if gw == "" {
		return "", nil // on-link / no stored next-hop → nothing to pin
	}
	_ = b.rr("-q", "delete", fam, "-host", host)
	if err := b.rr("-q", "add", fam, "-host", host, gw); err != nil {
		return "", fmt.Errorf("pin host route %s via %s: %w", host, gw, err)
	}
	return fam, nil
}

// routeCmd is the darwin per-target route seam for reconcileRoutes: add|delete a `-net <target>` route on
// the tunnel interface (v4/v6 by target form). #9/#10 reduce — Up's baked routes AND SetAllowedIPs' pushed
// ranges go through this ONE path, so a route-flag change can never drift baked vs pushed.
func (b *darwinBackend) routeCmd(add bool, target string) error {
	op := "delete"
	if add {
		op = "add"
	}
	args := []string{"-q", op}
	if strings.Contains(target, ":") {
		args = append(args, "-inet6")
	}
	args = append(args, "-net", target, "-interface", b.ifname)
	if err := run("route", args...); err != nil {
		return fmt.Errorf("route %s %s: %w", op, target, err)
	}
	return nil
}

func (b *darwinBackend) Down() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Graceful: restore routing (device close drops the utun + its routes), THEN
	// flush the pf backstop LAST so no window reverts to cleartext with the block
	// already gone.
	if b.dev != nil {
		b.dev.Close()
	}
	b.dev, b.tunDev, b.ifname = nil, nil, ""
	b.peerPubKey, b.peerAllowedIPs, b.peerKeepalive = "", nil, 0 // drop the current-peer cache with the device
	b.applied = nil                                              // device closed drops its utun routes; belief cleared (drift-heal c). A home-LAN range
	// whose connected route we deleted-before-add re-derives on the next network event (verify: walk's
	// home-LAN-collision leg — not unit-reachable).
	if b.endpointHost != "" {
		_ = run("route", "-q", "delete", b.endpointFam, "-host", b.endpointHost)
		b.endpointHost, b.endpointFam = "", ""
	}
	// D-WFA-4: drop the CP carve-out host-route + state with the tunnel (the pf anchor is flushed by
	// releasePF below, taking its CP pass with it).
	if b.cpHost != "" {
		_ = run("route", "-q", "delete", b.cpFam, "-host", b.cpHost)
		b.cpHost, b.cpFam = "", ""
	}
	b.cpEndpoint, b.fullTunnel = "", false
	b.physGwV4, b.physGwV6 = "", "" // WF-A-FT-1: session-scoped — the stored physical gateway clears with the tunnel
	// Restore the system resolver a full tunnel hijacked (no-op if none was saved).
	restoreDNS()
	return b.releasePF()
}

// gatewayFor returns the physical next-hop for reaching a SPECIFIC address (v4 or v6
// via fam "-inet"/"-inet6"), read BEFORE the tunnel default is installed. Using the
// route to the endpoint itself (not the default) handles an endpoint reached via a
// non-default route. Empty if on-link / unresolved (then no host route is pinned).
func gatewayFor(ip, fam string) string {
	out, err := exec.Command("route", "-n", "get", fam, ip).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" {
			return f[1]
		}
	}
	return ""
}

func (b *darwinBackend) FailClosed() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Alive-process fast path: tear the tun; the pf backstop stays (it was armed at
	// Up and outlives this process anyway). Re-assert it in case Up failed early.
	if b.dev != nil {
		b.dev.Close()
		b.dev, b.tunDev, b.ifname = nil, nil, ""
	}
	// UNCONDITIONAL (S8.5 #3): the belief map is cleared on EVERY terminal transition, even when Up failed
	// LATE (after the route reconcile seeded `applied` but before b.dev was assigned) — a conditional clear
	// is how a belief cache rots. Cheap + dumb beats a platform-specific patch path.
	b.applied = nil
	return nil
}

func (b *darwinBackend) Stats() (TunnelStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		return TunnelStatus{State: string(StateDown)}, nil
	}
	get, err := b.dev.IpcGet()
	if err != nil {
		return TunnelStatus{Interface: b.ifname}, err
	}
	return parseStats(get, b.ifname), nil
}

// --- helpers (shared uapi/MTU/stats/routeTargets live in wgcommon.go) ---

// buildPFRules is the kill-switch ruleset loaded into the anchor. Requirements:
//   - (2) loopback is EXEMPT (pass quick on lo0) — also protects the app's own
//     127.0.0.1 loopback callback flow. (pass quick, NOT set skip — see below.)
//   - (4) `block drop out all` covers BOTH inet and inet6 (unqualified = all AFs);
//     NDP is explicitly passed for v6.
//   - the WG endpoint passes (so handshakes/data reach the gateway); once the
//     tunnel exists, its interface is passed quick so user traffic may leave on it.
//   - (3) DHCP/NDP pass — a DELIBERATE, threat-model-argued exception so long
//     sessions don't lose their lease/neighbor state. Risk: these are local-link
//     UDP/ICMPv6 protocols; the exposure is a local attacker on the same segment
//     spoofing DHCP/RA, which is out of scope for a VPN egress kill-switch (and
//     already a risk pre-VPN). Worth it to avoid the tunnel silently dying on a
//     DHCP renew.
func buildPFRules(endpoint, ifname, cpEndpoint string) string {
	host, port := splitEndpoint(endpoint)
	var b strings.Builder
	// `set skip on <iface>` is REJECTED inside a pf anchor — `set` options are
	// main-ruleset-only, so pfctl silently DROPS these lines when we load them via
	// `pfctl -a tunnex -f -`. The interface is then NOT skipped: every packet the
	// kernel routes onto utun (i.e. ALL of the user's tunnelled traffic) falls through
	// to `block drop out all` and is dropped BEFORE wireguard-go can read+encrypt it —
	// the tunnel handshakes (that's the outer socket on the physical iface hitting the
	// endpoint pass) but carries no data. Use `pass quick` instead: quick short-circuits
	// ABOVE the block, giving loopback + the tunnel interface the exact bypass that
	// `set skip` was meant to, but in a form an anchor honors.
	b.WriteString("pass quick on lo0 all\n")
	if ifname != "" {
		fmt.Fprintf(&b, "pass quick on %s all\n", ifname)
	}
	b.WriteString("block drop out all\n")
	fmt.Fprintf(&b, "pass out proto udp to %s port %s\n", host, port)
	// D-WFA-4: the ONE named carve-out — permit the control channel's TLS to the CP endpoint EXACTLY, so
	// the device can still poll the CP (to learn a re-home) when the tunnel is down. The CP is already the
	// TLS trust root; a pass to it widens nothing. Only present for a full tunnel that supplied a CP endpoint.
	if cpEndpoint != "" {
		cpHost, cpPort := splitEndpoint(cpEndpoint)
		fmt.Fprintf(&b, "pass out proto tcp to %s port %s\n", cpHost, cpPort)
	}
	b.WriteString("pass out proto udp from any port 68 to any port 67\n")   // DHCPv4
	b.WriteString("pass out proto udp from any port 546 to any port 547\n") // DHCPv6
	b.WriteString("pass out inet6 proto icmp6 all\n")                       // NDP
	return b.String()
}

// armPF loads the ruleset into the anchor and enables pf with a REFERENCE-COUNTED
// token (`pfctl -E`), captured once so Down can RELEASE it (`pfctl -X <token>`)
// rather than force-disabling pf for the whole system.
//
// NOTE (lifecycle): a named anchor is only evaluated if the main ruleset
// references it (`anchor "tunnex"` in pf.conf). The SMAppService/installer adds
// that reference (removed on uninstall). The smoke asserts ENFORCEMENT (a blocked
// ping), not rule presence — so a non-referenced anchor is caught.
func (b *darwinBackend) armPF(endpoint, ifname string) error {
	if err := runStdin(buildPFRules(endpoint, ifname, b.cpEndpoint), "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	if b.pfToken == "" {
		out, _ := exec.Command("pfctl", "-E").CombinedOutput() // "Token : NNN" (stderr)
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Token") {
				f := strings.Fields(line)
				if len(f) > 0 {
					b.pfToken = f[len(f)-1]
				}
			}
		}
		// Persist the token so a crashed-then-restarted helper can release THIS exact
		// enable-reference (CleanStale) instead of leaking it or force-disabling pf.
		if b.pfToken != "" {
			_ = os.MkdirAll("/var/run/tunnex", 0o755)
			_ = os.WriteFile(pfTokenPath, []byte(b.pfToken), 0o600)
		}
	}
	return nil
}

// releasePF flushes our anchor rules and releases the pf enable reference (both the
// in-memory token and any persisted copy).
func (b *darwinBackend) releasePF() error {
	err := run("pfctl", "-a", pfAnchor, "-F", "all")
	if b.pfToken != "" {
		_ = exec.Command("pfctl", "-X", b.pfToken).Run()
		b.pfToken = ""
	}
	_ = os.Remove(pfTokenPath)
	return err
}

// CleanStale releases a kill-switch stranded by a prior process that exited without
// a graceful Down (crash / kill -9). The crux — flushing the anchor rules — removes
// the block even if the enable-reference can't be identified; releasing the persisted
// token additionally restores pf's prior enable state. Idempotent: a missing token /
// empty anchor is a no-op. This is what un-strands a host after an abnormal exit.
func (b *darwinBackend) CleanStale() error {
	// Flush the block rules FIRST — this is the un-strand. Ignore errors (anchor may
	// be empty / pf disabled — both fine).
	_ = run("pfctl", "-a", pfAnchor, "-F", "all")
	// Release the persisted enable-reference if one survived the crash.
	if tok, err := os.ReadFile(pfTokenPath); err == nil {
		if t := strings.TrimSpace(string(tok)); t != "" {
			_ = exec.Command("pfctl", "-X", t).Run()
		}
		_ = os.Remove(pfTokenPath)
	}
	// Restore the system resolver if a crashed full tunnel left it pointed at the
	// tunnel DNS (same un-strand intent as flushing the pf block above).
	restoreDNS()
	return nil
}

// networkServices returns the ENABLED macOS network services (Wi-Fi, Ethernet, …).
// networksetup's first output line is a header; disabled services are '*'-prefixed.
func networkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var svcs []string
	for i, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue // header, blank, or disabled service
		}
		svcs = append(svcs, line)
	}
	return svcs
}

// currentDNS returns the EXPLICIT DNS servers set on a service, or nil when it is on
// automatic/DHCP ("There aren't any DNS Servers set on <svc>."). nil is meaningful:
// restoreDNS maps it back to `-setdnsservers <svc> empty` (return to automatic).
func currentDNS(svc string) []string {
	out, err := exec.Command("networksetup", "-getdnsservers", svc).Output()
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if ip := strings.TrimSpace(line); net.ParseIP(ip) != nil {
			servers = append(servers, ip)
		}
	}
	return servers
}

// applyDNS points EVERY enabled network service at the tunnel resolver, first saving
// each service's prior setting to dnsBackupPath so Down/CleanStale can restore it. The
// backup is written BEFORE any mutation, so a crash mid-apply is still recoverable.
// macOS resolves via the primary service's configured DNS regardless of the utun
// default route, so the resolver must be set on the real services, not the utun.
func applyDNS(servers []string) {
	svcs := networkServices()
	if len(svcs) == 0 {
		return
	}
	backup := make(map[string][]string, len(svcs))
	for _, svc := range svcs {
		backup[svc] = currentDNS(svc) // nil = was automatic/DHCP
	}
	if data, err := json.Marshal(backup); err == nil {
		_ = os.MkdirAll("/var/run/tunnex", 0o755)
		_ = os.WriteFile(dnsBackupPath, data, 0o600)
	}
	for _, svc := range svcs {
		_ = run("networksetup", append([]string{"-setdnsservers", svc}, servers...)...)
	}
}

// restoreDNS puts every service's DNS back to what applyDNS saved (automatic when the
// prior list was empty), then removes the backup. Idempotent: no backup = no-op.
func restoreDNS() {
	data, err := os.ReadFile(dnsBackupPath)
	if err != nil {
		return
	}
	var backup map[string][]string
	if json.Unmarshal(data, &backup) == nil {
		for svc, servers := range backup {
			args := []string{"-setdnsservers", svc}
			if len(servers) == 0 {
				args = append(args, "empty") // back to automatic/DHCP
			} else {
				args = append(args, servers...)
			}
			_ = run("networksetup", args...)
		}
	}
	_ = os.Remove(dnsBackupPath)
}

func ipOnly(cidr string) string {
	if i := strings.Index(cidr, "/"); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runStdin(stdin, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
