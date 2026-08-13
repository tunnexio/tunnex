//go:build windows

package helper

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"github.com/tunnexio/tunnex/apps/helper/internal/wfp"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// wintunAdapter is the wintun adapter name the client tunnel uses.
const wintunAdapter = "tunnex"

// dnsAddrs parses the config DNS strings into netip.Addr, split by family (v4/v6) plus a
// combined list. Invalid entries are skipped (Validate already accepted the config).
func dnsAddrs(dns []string) (v4, v6, all []netip.Addr) {
	for _, s := range dns {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		all = append(all, a)
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return
}

// hasV6Default reports whether ::/0 is among the AllowedIPs (full v6 tunnel).
func hasV6Default(allowedIPs []string) bool {
	for _, a := range allowedIPs {
		if strings.TrimSpace(a) == "::/0" {
			return true
		}
	}
	return false
}

// windowsBackend implements Backend on Windows: wireguard-go over a wintun adapter, a WFP
// kill-switch (the vendored internal/wfp — the wireguard-windows filter set on a S6.7 PERSISTENT
// non-dynamic session + fixed provider GUID, so the block genuinely survives process death), and
// winipcfg for addressing/routes. It mirrors backend_darwin's ordering and the BOUNDED
// fail-closed model: the WFP objects are KERNEL-RESIDENT and outlive the process; Down / CleanStale
// / `tunnex-helper --wfp-clean` remove them by enumerate-and-delete under our fixed provider GUID
// (idempotent, no persisted token — the GUID IS the durable key); the Supervisor's dead-man + the
// auto-start service's startup CleanStale + reboot bound an un-recovered crash.
type windowsBackend struct {
	mu     sync.Mutex
	dev    *device.Device
	tunDev tun.Device
	luid   uint64
	armed  bool // WFP kill-switch installed (kernel-resident)
	// Endpoint host-route pinned on the PHYSICAL interface (so WG's own encrypted
	// packets don't loop into the tunnel); removed on Down.
	epDest   netip.Prefix
	epLUID   winipcfg.LUID
	epNH     netip.Addr
	epPinned bool
	// applied is the per-session BELIEF CACHE (S8.5 reduce) of the OS route-targets we believe are in the
	// kernel — set on Up, reconciled by SetAllowedIPs, cleared on Down. NEVER persisted. See reconcileRoutes.
	applied map[string]bool
	// peer* track the CURRENT gateway peer for a WF-A re-home (SetGatewayPeer) — the key to swap out plus
	// the allowed_ips/keepalive to preserve onto the new peer. Mirrors backend_darwin: peerPubKey seeds on
	// Up + advances on each re-home; peerAllowedIPs seeds on Up + advances on every SetAllowedIPs push.
	peerPubKey     string
	peerAllowedIPs []string
	peerKeepalive  int
	// fullTunnel records whether the live tunnel is full (WFP kill-switch armed). A full-tunnel WF-A re-home
	// needs a WFP CP carve-out (D-WFA-4) that is DEFERRED on Windows (S8.6b-win-carveout) — so SetGatewayPeer
	// refuses full-tunnel here; split-tunnel re-home is a bare peer swap and works.
	fullTunnel bool
}

// NewBackend returns the Windows tunnel backend.
func NewBackend() Backend { return &windowsBackend{} }

func (b *windowsBackend) Up(cfg *TunnelConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Full tunnel is supported on Windows (S6.7): the WFP kill-switch is a PERSISTENT block
	// that survives process death — proven live (taskkill /F mid-tunnel → zero cleartext
	// egress v4+v6 on a physical-NIC pcap → recovery restores). The S6.9 guard + both dev
	// bypass flags were removed together when that gate passed.

	// Parse the tunnel DNS UP FRONT (before creating any adapter/WFP state, so an invalid
	// config fails cleanly). Used for BOTH EnableFirewall's restrictToDNSServers (blockDNS)
	// and the adapter SetDNS below. useV6DNS gates the v6 SetDNS AND the v6 WFP-permit
	// together, so the permitted resolver set exactly matches what the adapter uses (no v6
	// resolver permitted-but-never-set); v6 DNS only when v6 is tunnelled.
	dnsV4, dnsV6, _ := dnsAddrs(cfg.DNS)
	useV6DNS := len(dnsV6) > 0 && hasV6Default(cfg.AllowedIPs)
	dnsRestrict := append([]netip.Addr{}, dnsV4...)
	if useV6DNS {
		dnsRestrict = append(dnsRestrict, dnsV6...)
	}
	// A full tunnel with NO usable DNS server would block ALL DNS (the base WFP block drops
	// port 53) with no tunnel resolver set → a silent, total resolution outage. Refuse up
	// front. config.go always supplies one; this guards the invariant so a future or
	// hand-crafted empty-DNS full-tunnel config can't blackhole resolution (review).
	if cfg.FullTunnel && len(dnsRestrict) == 0 {
		return &ProtocolError{Code: "full_tunnel_requires_dns", Msg: "full tunnel requires a DNS server"}
	}

	// Resolve a hostname endpoint to ONE IP so the WFP pass, the endpoint route, and
	// wireguard-go all pin the same address (review #10).
	ep, err := resolveEndpoint(cfg.Endpoint)
	if err != nil {
		return err
	}
	cfg.Endpoint = ep

	// CLEAN any stale Tunnex WFP kill-switch (S6.7: PERSISTENT — survives a prior crash) before
	// (re)arming: a re-arm with our fixed GUID would else fail ALREADY_EXISTS, and a stale
	// full-tunnel block must not persist under a new SPLIT tunnel. Idempotent enumerate-and-delete.
	wfp.DisableFirewall()
	b.armed = false

	tdev, err := tun.CreateTUN(wintunAdapter, deviceMTU(cfg))
	if err != nil {
		return fmt.Errorf("create wintun adapter: %w", err)
	}
	nt, ok := tdev.(*tun.NativeTun)
	if !ok {
		_ = tdev.Close()
		return fmt.Errorf("wintun: unexpected tun device type %T", tdev)
	}
	luid := nt.LUID()

	// ARM the kill-switch FIRST (before any routing) — ONLY for a full tunnel (a
	// split tunnel leaves the rest of the user's traffic on the cleartext default BY
	// DESIGN). EnableFirewall permits the tunnel adapter, loopback, DHCP/NDP, and THIS
	// process, and blocks everything else. NOTE: the WFP permit lets our encrypted
	// packets PASS the filter, but it does NOT stop the routing table from sending them
	// into the tunnel — so a full tunnel STILL needs the physical endpoint route pinned
	// below (review #1). The filters are kernel-resident and survive process death; removed by
	// wfp.DisableFirewall (Down / CleanStale / --wfp-clean) by enumerate-and-delete under our
	// fixed provider GUID. dnsRestrict (parsed up front) is EnableFirewall's restrictToDNSServers
	// so blockDNS forces DNS to the tunnel resolver only; the 2nd param STAYS false (doNotRestrict
	// — true would disarm the whole kill-switch).
	if cfg.FullTunnel {
		if err := wfp.EnableFirewall(luid, false, dnsRestrict); err != nil {
			_ = tdev.Close()
			// The kill-switch DID NOT arm → NOTHING is blocking (EnableFirewall's transaction
			// aborts on failure, so there's no partial block). This must NOT be reported as
			// fail-closed: FailClosed() here would be a no-op (b.dev is unset) and the Supervisor
			// would set StateFailed = "kill-switch installed" while the box is on cleartext
			// routing (review — false fail-closed). Surface a CLEAN pre-arm code so the Supervisor
			// stays Down and the UI honestly says "not connected", not "protected".
			return &ProtocolError{Code: "wfp_arm_failed", Msg: fmt.Sprintf("could not arm the Windows kill-switch: %v", err)}
		}
		b.armed = true
	}

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "tunnex-helper: "))
	uapi, err := uapiConfig(cfg)
	if err != nil {
		dev.Close() // keeps the WFP block armed (fail-closed); the Supervisor → FailClosed
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("device up: %w", err)
	}

	// Address + routes on the adapter. Split-default for full-tunnel so the physical
	// default is NEVER destroyed (auto-recovers on teardown/crash). On-link via the
	// adapter (next-hop unspecified).
	wl := winipcfg.LUID(luid)
	addresses := cfg.Addresses
	if len(addresses) == 0 {
		addresses = []string{cfg.Address}
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			dev.Close()
			return fmt.Errorf("parse address %q: %w", address, err)
		}
		prefixes = append(prefixes, prefix)
	}
	if err := wl.SetIPAddresses(prefixes); err != nil {
		dev.Close()
		return fmt.Errorf("set address: %w", err)
	}
	// Baked routes go through the ONE reconciler (S8.5 reduce, #9/#10) — same delete-before-add + per-route
	// discipline + single next-hop derivation as the pushed ranges. luid must be set first (routeCmd reads it).
	b.luid = luid
	b.applied = map[string]bool{}
	if err := reconcileRoutes(b.applied, routeSet(cfg.AllowedIPs), b.routeCmd); err != nil {
		b.luid = 0
		b.applied = nil
		dev.Close()
		return err
	}

	// Pin the endpoint route on the PHYSICAL interface (review #1): with 0.0.0.0/1 on
	// the tunnel, wireguard-go's own encrypted packets to the endpoint would otherwise
	// match the tunnel route and loop — conn.NewDefaultBind() does NOT bind the socket
	// to the physical NIC, so the loop is real, not merely theoretical.
	if cfg.FullTunnel {
		if epHost, _ := splitEndpoint(cfg.Endpoint); epHost != "" {
			if ip, perr := netip.ParseAddr(epHost); perr == nil {
				if err := b.pinEndpointRoute(ip, luid); err != nil {
					dev.Close()
					return err
				}
			}
		}
	}

	// FULL TUNNEL: point the system resolver at the tunnel DNS ON THE WINTUN ADAPTER
	// (Story A). Adapter-scoped, so it AUTO-VANISHES when the adapter is torn down (Down /
	// crash) — no backup/restore/strand, unlike macOS's per-service networksetup. Without
	// this the OS keeps resolving via the (now WFP-blocked) LAN DNS and names don't
	// resolve. v6 DNS only when a v6 default is tunnelled (else v6 stays dropped — no
	// NAT66, matching macOS). domains=nil (full tunnel = all DNS to the resolver).
	if cfg.FullTunnel {
		if len(dnsV4) > 0 {
			if err := wl.SetDNS(winipcfg.AddressFamily(windows.AF_INET), dnsV4, nil); err != nil {
				dev.Close()
				return fmt.Errorf("set tunnel DNS (v4): %w", err)
			}
		}
		if useV6DNS {
			if err := wl.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), dnsV6, nil); err != nil {
				dev.Close()
				return fmt.Errorf("set tunnel DNS (v6): %w", err)
			}
		}
	}

	b.dev, b.tunDev, b.luid = dev, tdev, luid
	b.fullTunnel = cfg.FullTunnel
	// Seed the current-peer cache for a WF-A re-home (SetGatewayPeer): the key to swap out, and the
	// allowed_ips/keepalive to carry onto the new peer.
	b.peerPubKey, b.peerAllowedIPs, b.peerKeepalive = cfg.PeerPublicKey, append([]string(nil), cfg.AllowedIPs...), cfg.PersistentKeepalive
	return nil
}

// SetAllowedIPs live-updates the peer's AllowedIPs (S8.5): the SAME uapi update as macOS (dev.IpcSet,
// no handshake reset) — the crypto-route path is platform-identical. The OS-route full-sweep DIFFERS by
// platform: Windows reconciles via winipcfg AddRoute/DeleteRoute on the tunnel LUID (macOS uses the
// `route` CLI). Never touches the device identity, the peer's keys/endpoint, or the WFP kill-switch.
func (b *windowsBackend) SetAllowedIPs(peerPubKey string, allowedIPs []string) error {
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
	// (review #5 — advancing before reconcileRoutes is correct: the cache feeds only the re-home crypto
	// allowed_ips, and a re-home never touches OS routes. See the darwin SetAllowedIPs note.)
	b.peerAllowedIPs = append([]string(nil), allowedIPs...)
	// OS-route full-sweep through the ONE reconciler (S8.5 reduce): delete-before-add, delete-stale-first,
	// per-route advance against the belief cache. The crypto (replace_allowed_ips) already converged above.
	return reconcileRoutes(b.applied, routeSet(allowedIPs), b.routeCmd)
}

// SetGatewayPeer live re-homes the tunnel onto a new gateway peer (WF-A) — a peer SWAP (the SAME uapi
// swap as macOS: add-new-before-remove-old, no handshake reset) with the current peer's allowed_ips/
// keepalive preserved. The device identity and the interface address are UNTOUCHED. OS routes point at the
// LUID, not the peer, so a split-tunnel swap needs NO route reconcile. FULL-TUNNEL is REFUSED
// (rehome_full_tunnel_unsupported): the WFP CP carve-out that a full-tunnel re-home needs (D-WFA-4, so the
// control channel + the new gateway are permitted) is DEFERRED on Windows (S8.6b-win-carveout) — until then
// a Windows full-tunnel device stranded on a dead hub needs a manual reconnect. Split-tunnel is unaffected.
func (b *windowsBackend) SetGatewayPeer(newPubKey, newEndpoint string) error {
	// Resolve BEFORE taking b.mu (review #1): DNS latency must never hold a lock the fail-closed path needs
	// (the kill-switch-no-unbounded-I/O law — see the darwin backend's SetGatewayPeer note).
	ep, err := resolveEndpoint(newEndpoint)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		return &ProtocolError{Code: "not_up", Msg: "no active tunnel device"}
	}
	if b.fullTunnel {
		return &ProtocolError{Code: "rehome_full_tunnel_unsupported", Msg: "full-tunnel re-home is not supported on Windows yet (WFP CP carve-out deferred)"}
	}
	uapi, err := gatewayPeerSwapUAPI(b.peerPubKey, newPubKey, ep, b.peerKeepalive, b.peerAllowedIPs)
	if err != nil {
		return err
	}
	if err := b.dev.IpcSet(uapi); err != nil {
		return &ProtocolError{Code: "gateway_peer_apply_failed", Msg: err.Error()}
	}
	// WF-A-obs-1: breadcrumb for a successful swap (pubkeys are public) — a succeeded vs a silently-looped
	// re-home must be distinguishable in the logs.
	log.Printf("gateway_peer_swapped: pubkey %s -> %s, endpoint -> %s, full_tunnel=%v (no bounce)", b.peerPubKey, newPubKey, ep, b.fullTunnel)
	b.peerPubKey = newPubKey
	return nil
}

// routeCmd is the windows per-target route seam for reconcileRoutes: add|delete a route on the tunnel LUID
// (winipcfg). The next-hop family (unspecified on-link, v4/v6 by target) is derived HERE ONCE — #10 reduce
// (it was copy-pasted across Up's loop + SetAllowedIPs' add + delete). #9/#10: Up's baked routes AND the
// pushed ranges go through this ONE path, so they can never install with different attributes.
func (b *windowsBackend) routeCmd(add bool, target string) error {
	dest, err := netip.ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("parse route %q: %w", target, err)
	}
	nh := netip.IPv4Unspecified()
	if dest.Addr().Is6() {
		nh = netip.IPv6Unspecified()
	}
	wl := winipcfg.LUID(b.luid)
	if add {
		if err := wl.AddRoute(dest, nh, 0); err != nil {
			return fmt.Errorf("route add %s: %w", target, err)
		}
		return nil
	}
	if err := wl.DeleteRoute(dest, nh); err != nil {
		return fmt.Errorf("route delete %s: %w", target, err)
	}
	return nil
}

// pinEndpointRoute installs a host route for the endpoint via the PHYSICAL default
// next-hop (the lowest-metric default route NOT on the tunnel adapter), so WG's own
// encrypted packets egress physically instead of matching the tunnel's split-default.
// Idempotent (a prior FailClosed/crash may have left it — the route is on the physical
// interface and survives the wintun teardown, like the macOS endpoint route).
func (b *windowsBackend) pinEndpointRoute(ep netip.Addr, tunnelLUID uint64) error {
	fam := winipcfg.AddressFamily(windows.AF_INET)
	bits := 32
	if ep.Is6() {
		fam = winipcfg.AddressFamily(windows.AF_INET6)
		bits = 128
	}
	rows, err := winipcfg.GetIPForwardTable2(fam)
	if err != nil {
		return fmt.Errorf("read routing table: %w", err)
	}
	candidates := make([]physicalDefaultRoute, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || uint64(r.InterfaceLUID) == tunnelLUID {
			continue // default routes NOT on the tunnel adapter
		}
		ifrow, err := r.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		iface, err := r.InterfaceLUID.IPInterface(fam)
		if err != nil {
			continue
		}
		// Windows route priority is the route metric plus its interface metric;
		// comparing r.Metric alone can choose the wrong NIC on a multi-homed host.
		candidates = append(candidates, physicalDefaultRoute{
			EffectiveMetric: uint64(r.Metric) + uint64(iface.Metric),
			LUID:            uint64(r.InterfaceLUID),
			NextHop:         r.NextHop.Addr(),
			Up:              true,
		})
	}
	selected, found := selectPhysicalDefaultRoute(candidates)
	if !found {
		return nil // no physical default — nothing to loop through
	}
	luid := winipcfg.LUID(selected.LUID)
	nh := selected.NextHop
	dest := netip.PrefixFrom(ep, bits)
	_ = luid.DeleteRoute(dest, nh) // idempotent
	if err := luid.AddRoute(dest, nh, 0); err != nil {
		return fmt.Errorf("pin endpoint route %s: %w", dest, err)
	}
	b.epDest, b.epLUID, b.epNH, b.epPinned = dest, luid, nh, true
	return nil
}

func (b *windowsBackend) Down() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Graceful: closing the adapter drops its addresses + routes (the physical default
	// was never destroyed → normal routing returns), THEN remove the WFP block LAST so
	// no window reverts to cleartext with the block already gone.
	if b.dev != nil {
		b.dev.Close()
	}
	b.dev, b.tunDev, b.luid = nil, nil, 0
	b.peerPubKey, b.peerAllowedIPs, b.peerKeepalive = "", nil, 0 // drop the current-peer cache with the device
	b.fullTunnel = false
	b.applied = nil // device closed drops its routes; belief cleared (drift-heal c)
	if b.epPinned {
		_ = b.epLUID.DeleteRoute(b.epDest, b.epNH) // on the physical iface → not auto-removed
		b.epPinned = false
	}
	if b.armed {
		// SURFACE a cleanup failure (review): the persistent block does NOT auto-release with a
		// session anymore, so if enumerate-and-delete fails the block stays armed and the host
		// has zero egress while the UI shows "Disconnected". Report it (with the recovery hint)
		// instead of a silent strand; keep b.armed=true so a later CleanStale/reboot still targets it.
		if err := wfp.Clean(); err != nil {
			return fmt.Errorf("removing the kill-switch failed — networking may be blocked; recover with `tunnex-helper --wfp-clean` (or reboot): %w", err)
		}
		b.armed = false
	}
	return nil
}

func (b *windowsBackend) FailClosed() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Alive-process fast path: tear the adapter; the WFP block STAYS armed (it was
	// installed at Up and outlives this process). On kill -9 this never runs; the
	// kernel-resident filters hold the line until the next start's CleanStale or the
	// dead-man releases them.
	if b.dev != nil {
		b.dev.Close()
		b.dev, b.tunDev = nil, nil
	}
	// UNCONDITIONAL (S8.5 #3): clear luid + the belief map on EVERY terminal transition, even when Up failed
	// LATE (pinEndpointRoute/SetDNS after the route reconcile seeded `applied`, before b.dev was assigned) —
	// FailClosed's `if b.dev != nil` guard would otherwise leave a populated map for a destroyed adapter.
	b.luid, b.applied = 0, nil
	return nil
}

func (b *windowsBackend) CleanStale() error {
	// Release a PERSISTENT Tunnex WFP block stranded by a PRIOR process that exited without a
	// graceful Down (crash / kill). wfp.Clean enumerate-and-deletes every object under our fixed
	// provider GUID — idempotent (not-found = success). This is the reboot/startup RECOVERY: the
	// service is auto-start, so a boot runs it before serving and un-wedges the host (same code
	// path as --wfp-clean). RETURN the error — a boot-time self-heal that FAILS must not be
	// silent; the Supervisor's SelfHeal logs it (main.go), so a wedged host is diagnosable.
	b.mu.Lock()
	defer b.mu.Unlock()
	err := wfp.Clean()
	b.armed = false
	return err
}

func (b *windowsBackend) Stats() (TunnelStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		return TunnelStatus{State: string(StateDown)}, nil
	}
	get, err := b.dev.IpcGet()
	if err != nil {
		return TunnelStatus{Interface: wintunAdapter}, err
	}
	return parseStats(get, wintunAdapter), nil
}
