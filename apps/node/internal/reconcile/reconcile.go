// Package reconcile converges the local WireGuard interface toward the
// control-plane desired state. The logic is backend-agnostic (WGBackend) so it
// unit-tests against a fake — only a thin adapter touches real wgctrl.
package reconcile

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Peer mirrors the control plane's peer shape (JSON contract).
type Peer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
	// SiteLink (S8.2) marks a gateway-DIALED site-link peer whose Endpoint is control-plane-managed
	// (static). The dirty-check compares Endpoint for these (B4) so a hub endpoint change re-dials; device
	// peers roam → SiteLink=false → endpoint-blind (TestReconcileIgnoresRoamedEndpoint stays armed).
	SiteLink bool `json:"site_link,omitempty"`
	// PersistentKeepalive (S8.3 CK, seconds) — CP-managed on site-link peers only; keeps a NAT'd link warm
	// so it doesn't false-stale (H5). The kernel DOES report it (`wg show dump` last field), so it is
	// compared for SiteLink peers in peersEqual (like Endpoint) — converges without churn, and catches a
	// peer that gained keepalive (first application). Roaming device peers carry 0.
	PersistentKeepalive int `json:"persistent_keepalive,omitempty"`
}

// DesiredState is the control-plane response the agent reconciles toward.
type DesiredState struct {
	ProtocolVersion  int    `json:"protocol_version"`
	NodeID           string `json:"node_id"`
	InterfaceAddress string `json:"interface_address"`
	MTU              int    `json:"mtu"`
	ListenPort       int    `json:"listen_port"`
	// Version is the control plane's change-version at fetch time; echoed on the
	// next Watch so a change during the fetch/apply gap is not missed.
	Version uint64 `json:"version"`
	Peers   []Peer `json:"peers"`
	// Policy is the compiled Zero Trust policy (S7.2). ABSENT/NULL => nil => the
	// agent keeps the legacy blanket MESH — so an open-build control plane (which
	// never sends the field) or an older control plane mid-upgrade can never make
	// a newer agent accidentally enforce OR open by omission. This decode default
	// is ASSERTED by TestAbsentPolicyDecodesToMesh; don't change it casually.
	Policy *nodepolicy.Compiled `json:"policy,omitempty"`
	// OVPNEnabled + OVPNClients (S9.1 4c/4d): whether this gateway runs the OpenVPN server (D-S9.5-OPTIN
	// org opt-in) and the roster homed to it (cert CommonName + CP-assigned /32). Out-of-hash plumbing;
	// absent → OVPN idle. Decoded straight from the CP's DesiredState JSON.
	OVPNEnabled bool         `json:"ovpn_enabled,omitempty"`
	OVPNClients []OVPNClient `json:"ovpn_clients,omitempty"`
	// OVPNServer (D-S9.6): the gateway's server material to write at cfgDir (ca/cert/key). nil → sweep
	// the files. The key crosses the mTLS control channel (no new trust); the agent writes it 0600.
	OVPNServer *OVPNServerMaterial `json:"ovpn_server,omitempty"`
}

// OVPNPushRoutes is the range set an OpenVPN server PUSHES to its clients: the UNION of the org's remote
// site Routes AND this gateway's OWN LocalSubnets — i.e. `Routes ∪ LocalSubnets`. This is EXACTLY the same
// reachable set a WireGuard client assembles from the routed-ranges poll (sites.ListRoutedRanges): ONE
// truth — the org's approved site subnets — delivered TWO ways (WG polls the control plane; OVPN pushes at
// connect). WF-OVPN-11 (WF-4-local's OpenVPN twin): without LocalSubnets an OVPN client reaches REMOTE
// sites but NOT the LAN behind its OWN gateway — the primary VPN use case ("dial in, reach the office file
// server"), never peripheral. nil policy → nil (the zero-config golden: a gateway with no ranges pushes
// nothing, byte-identical to pre-fold).
func OVPNPushRoutes(p *nodepolicy.Compiled) []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Routes)+len(p.LocalSubnets)+len(p.VIPMappings)+len(p.K8sDNSZones))
	for _, rt := range p.Routes {
		out = append(out, rt.DstCIDR) // remote site subnets (reached over the site links)
	}
	out = append(out, p.LocalSubnets...) // this gateway's own approved LAN (the WF-OVPN-11 half)
	// S10.3 fork-1 — the K8s half of the SAME asymmetry WF-OVPN-11 fixed for site LANs: an OVPN client must
	// reach the exposed Services of the cluster THIS gateway fronts, else OpenVPN inherits the client gap the
	// moment WireGuard's is closed. Push each exposed Service VIP + the reserved DNS VIP as a /32 route — the
	// SAME artifact data the DNAT + DNS answer already use (reuse rails, no new field). /32-per-exposed-VIP is
	// functionally complete (an unexposed VIP has no DNAT, so routing the whole range would add only dead
	// space) and tighter than routing the range. The DNS VIP push (dhcp-option DNS) is the serverConfig half.
	for _, vm := range p.VIPMappings {
		if vm.VIP != "" {
			out = append(out, vm.VIP+"/32")
		}
	}
	for _, z := range p.K8sDNSZones {
		if z.ListenVIP != "" {
			out = append(out, z.ListenVIP+"/32") // route the DNS VIP so the client can reach the resolver
		}
	}
	return out
}

// OVPNClient is one OpenVPN client's wire binding (mirror of the CP's nodes.OVPNClient).
type OVPNClient struct {
	CommonName string `json:"cn"`
	IP         string `json:"ip"`
	FullTunnel bool   `json:"ft,omitempty"` // WF-OVPN-3: per-device full-tunnel (redirect-gateway via CCD)
}

// OVPNServerMaterial is the gateway's OpenVPN server PKI (mirror of the CP's nodes.OVPNServerMaterial).
type OVPNServerMaterial struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
	CRL  string `json:"crl,omitempty"` // S9.1 Slice 5: the org's signed CRL (real-or-empty); crl-verify always-on
}

// InterfaceConfig is the device-level configuration. The PrivateKey is supplied
// by the AGENT (generated locally, never from the control plane). PublicKey is
// the key's public half — the adapter compares it against the device's current
// public key to decide if the private key needs (re)setting, which is robust to
// WireGuard clamping the stored private key (the raw private bytes differ after
// clamping, but the public key does not).
type InterfaceConfig struct {
	PrivateKey string
	PublicKey  string
	ListenPort int
	Address    string
	MTU        int
}

// PeerStat is per-peer live telemetry read from the device: last handshake (unix
// seconds, 0 = never), raw byte gauges (reset on interface restart), and current
// source endpoint. Reported to the control plane for the connection-status view.
type PeerStat struct {
	PublicKey     string `json:"public_key"`
	LastHandshake int64  `json:"last_handshake"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	Endpoint      string `json:"endpoint,omitempty"`
}

// WGBackend abstracts the WireGuard data plane. The real adapter wraps wgctrl;
// the fake drives unit tests.
type WGBackend interface {
	// Configure idempotently ensures the interface exists with this key/port/
	// address/MTU (converging a dirty device without flapping correct peers).
	Configure(ctx context.Context, cfg InterfaceConfig) error
	Peers(ctx context.Context) ([]Peer, error)
	ApplyPeers(ctx context.Context, peers []Peer) error
	// ApplyRoutes reconciles the kernel routes to remote SITE subnets (S8.2): install each desired
	// route via the tunnel iface (idempotent — heals a flushed route next tick) and PRUNE our routes
	// no longer desired (the full-sweep contract: a site unbind/subnet removal drops the route). Only
	// agent-owned routes are touched; the interface's own on-link route is never pruned. srcHint (S8.2c D2,
	// "" = none) is the gateway's site-LAN source address the RECONCILE loop derived (one host-addr snapshot
	// shared with the D3 signal) — applied to each route so gateway-host-originated site traffic sources
	// from the site LAN, not the overlay.
	ApplyRoutes(ctx context.Context, cidrs []string, srcHint string) error
	// Stats reports per-peer live telemetry (handshake/bytes/endpoint).
	Stats(ctx context.Context) ([]PeerStat, error)
	// Close tears the WG interface DOWN on agent shutdown (WF-C Layer 1). Configure CREATES the interface
	// (ensureDevice: `ip link add … type wireguard`); Close is its symmetric destroy — `ip link del`. With
	// `--network host` wg0 lives in the HOST netns and OUTLIVES the container, so without this a graceful
	// `docker stop` leaves the data plane FORWARDING HEADLESS (the zombie-hub / failover-blind class).
	// IDEMPOTENT: an already-absent interface is not an error. (A hard SIGKILL skips this — that residue
	// is WF-C Layer 2, the liveness-model question, a separate paper.)
	Close(ctx context.Context) error
}

// ControlClient is the agent's view of the control plane.
type ControlClient interface {
	// FetchDesired returns the full desired state (a full resync, not a diff).
	FetchDesired(ctx context.Context) (DesiredState, error)
	// Watch blocks until the control plane signals a change (push) or returns an
	// error/ctx cancellation. It carries the version from the last fetch so a
	// change during the fetch gap makes Watch return immediately (no lost wakeup).
	Watch(ctx context.Context, since uint64) error
}

// Reconciler converges a backend toward desired state. It holds the node's
// locally-generated interface private key (never sourced from the control plane).
type Reconciler struct {
	backend    WGBackend
	privateKey string
	publicKey  string
	logger     *slog.Logger
	healthy    atomic.Bool
	version    atomic.Uint64 // last desired-state version, echoed on Watch
	// onPolicy (optional) receives the compiled Zero Trust policy from EVERY
	// desired-state fetch — including nil (absent => legacy mesh). main wires it
	// to egress.Manager.SetPolicy + an immediate egress kick, so a pushed policy
	// change reaches the forward chain on the push path (<5s), not the next
	// egress tick.
	onPolicy func(*nodepolicy.Compiled)
	// onOVPN (optional, S9.1 4d) receives the FULL desired state each fetch so the agent can build the
	// OpenVPN server desired (enabled + roster + pool + policy Routes/DNS). nil in a WG-only agent.
	onOVPN func(DesiredState)
	// siteLinkStale (S8.2 H5) is an optional sink: each reconcile, the agent checks its SITE-LINK peers'
	// WG handshakes and stores whether any is stale/absent, so the report loop can surface site_link_down.
	// nil when not wired (e.g. tests) → the check is skipped.
	siteLinkStale *atomic.Bool
	lastStatsOK   time.Time // F2: last successful backend.Stats read — the one timestamp for three-state staleness
	// brickedLogged (S11 WF-S11-6) latches the once-only ERROR for a terminal, unrecoverable condition — an
	// expired agent certificate. Latched rather than rate-limited because the state never clears on its own.
	brickedLogged atomic.Bool
	// siteSubnetUnreachable (S8.2c D3) is an optional sink: each reconcile, if the CP advertised local site
	// subnets (LocalSubnets) but NO host address is inside any of them, the gateway is fronting a subnet it
	// isn't on (bridge-trapped wg0, or a misconfigured advertisement). Surfaced as site_subnet_unreachable
	// so the "reassuring-green" shape (wg0 alive + handshake fresh, LAN unreachable) is never silently OK.
	siteSubnetUnreachable *atomic.Bool
	// hostAddrsFn returns the host's IPv4 addresses (defaults to hostIPv4Addrs; seam for tests). Enumerated
	// ONCE per reconcile and used for BOTH the D2 route src-hint and the D3 unreachable signal, so the two
	// read the SAME snapshot (review: a src from one view + an alarm from another is a reassuring-green gen).
	hostAddrsFn func() []netip.Addr
	// noSrcLogged throttles the site_route_src_unresolved onset warning to once per onset (not per tick).
	noSrcLogged bool
	// forwardBlockedFn (WF-4 / D-WF4-d) optionally reports the egress manager's Docker-FORWARD-blocked
	// condition: a Docker host whose FORWARD DROP swallows forwarded site traffic the agent couldn't
	// clear. OR'd into siteSubnetUnreachable so a can't-forward gateway surfaces LOUD, never green.
	forwardBlockedFn func() bool
}

// SetForwardBlockedFn wires the egress Docker-FORWARD-blocked probe into the D3 signal (WF-4). Optional.
func (r *Reconciler) SetForwardBlockedFn(f func() bool) { r.forwardBlockedFn = f }

// SetSiteSubnetUnreachableSink wires the D3 unreachable-advertised-subnet sink (read by the report loop).
// Call before Run. Also arms hostAddrsFn to the real enumerator if unset.
func (r *Reconciler) SetSiteSubnetUnreachableSink(b *atomic.Bool) {
	r.siteSubnetUnreachable = b
	if r.hostAddrsFn == nil {
		r.hostAddrsFn = hostIPv4Addrs
	}
}

// SetSiteLinkStaleSink wires the H5 site-link-staleness sink (read by the report loop). Call before Run.
func (r *Reconciler) SetSiteLinkStaleSink(b *atomic.Bool) { r.siteLinkStale = b }

// siteLinkStaleWindow: a site-link peer with no handshake within this window (or never) is stale. Errs
// toward over-reporting (a false site_link_down is an annoyance; a false-healthy dead bridge is the
// blackhole class). Comfortably above WireGuard's ~2-min rehandshake/keepalive cadence.
const siteLinkStaleWindow = 180 * time.Second

// updateSiteLinkStale checks the desired SITE-LINK peers' handshakes and stores staleness in the sink.
func (r *Reconciler) updateSiteLinkStale(ctx context.Context, desired []Peer) {
	var sitePubs []string
	for _, p := range desired {
		if p.SiteLink {
			sitePubs = append(sitePubs, p.PublicKey)
		}
	}
	if len(sitePubs) == 0 {
		r.siteLinkStale.Store(false) // no site links on this gateway → nothing to be stale
		return
	}
	stats, err := r.backend.Stats(ctx)
	if err != nil {
		// THREE-STATE on a Stats error (F2/R4), one timestamp, no debounce machinery: (1) cold start —
		// never a good reading — report STALE (over-report once; a maybe-dead link reads dead). (2) a
		// TRANSIENT error within the staleness window of the last good read — KEEP the last value (kills
		// the flap: a genuinely-up link doesn't oscillate on an intermittent wg-dump hiccup). (3) an error
		// PERSISTING past the window — report STALE (can no longer vouch the link is up).
		if r.lastStatsOK.IsZero() || time.Since(r.lastStatsOK) > siteLinkStaleWindow {
			r.siteLinkStale.Store(true)
		}
		return // else: keep last value
	}
	r.lastStatsOK = time.Now()
	hs := make(map[string]int64, len(stats))
	for _, s := range stats {
		hs[s.PublicKey] = s.LastHandshake
	}
	now := time.Now().Unix()
	stale := false
	for _, pub := range sitePubs {
		h, ok := hs[pub]
		if !ok || h == 0 || now-h > int64(siteLinkStaleWindow.Seconds()) {
			stale = true
			break
		}
	}
	r.siteLinkStale.Store(stale)
}

// OnPolicy registers the policy sink. Call before Run (not synchronized).
func (r *Reconciler) OnPolicy(fn func(*nodepolicy.Compiled)) { r.onPolicy = fn }

// OnOVPN registers the OpenVPN desired-state sink (S9.1 4d). Call before Run.
func (r *Reconciler) OnOVPN(fn func(DesiredState)) { r.onOVPN = fn }

// New builds a Reconciler with the node's WireGuard key pair (public key is used
// only for the clamp-safe "is the interface key already set" check).
func New(backend WGBackend, privateKey, publicKey string, logger *slog.Logger) *Reconciler {
	return &Reconciler{backend: backend, privateKey: privateKey, publicKey: publicKey, logger: logger, hostAddrsFn: hostIPv4Addrs}
}

// Healthy reports whether the last reconcile fully succeeded (control plane
// reachable AND the backend converged). Agent readiness reflects this, so a
// backend failure — NET_ADMIN missing, port bound, device collision — surfaces
// as not-ready and diagnosable, never a silent success or crash-loop.
func (r *Reconciler) Healthy() bool { return r.healthy.Load() }

// Reconcile converges the backend to the desired peer set. It applies the FULL
// set (a resync), so a long-disconnected agent recovers correctly. Returns
// whether anything changed.
func (r *Reconciler) Reconcile(ctx context.Context, desired []Peer) (bool, error) {
	actual, err := r.backend.Peers(ctx)
	if err != nil {
		return false, err
	}
	if peersEqual(actual, desired) {
		return false, nil
	}
	if err := r.backend.ApplyPeers(ctx, desired); err != nil {
		return false, err
	}
	return true, nil
}

// runOnce fetches desired state and reconciles. A fetch error is returned
// WITHOUT touching the backend — data-plane independence: a control-plane outage
// never flushes live peers.
func (r *Reconciler) runOnce(ctx context.Context, client ControlClient) (bool, error) {
	ds, err := client.FetchDesired(ctx)
	if err != nil {
		r.healthy.Store(false)
		return false, err
	}
	r.version.Store(ds.Version) // echoed on the next Watch to close the fetch-gap
	// Deliver the compiled policy BEFORE the WG converge (and regardless of its
	// outcome): enforcement is orthogonal to interface config, and a policy pushed
	// for revocation must not wait on an unrelated backend failure. nil (absent
	// field) is delivered too — it means "legacy mesh" and must be able to unset a
	// previous policy (mode enforcing -> off recovery path).
	if r.onPolicy != nil {
		r.onPolicy(ds.Policy)
	}
	if r.onOVPN != nil {
		r.onOVPN(ds)
	}
	// Idempotently ensure the interface config, then converge peers.
	if err := r.backend.Configure(ctx, InterfaceConfig{
		PrivateKey: r.privateKey, PublicKey: r.publicKey,
		ListenPort: ds.ListenPort, Address: ds.InterfaceAddress, MTU: ds.MTU,
	}); err != nil {
		r.healthy.Store(false)
		return false, err
	}
	changed, err := r.Reconcile(ctx, ds.Peers)
	if err != nil {
		r.healthy.Store(false)
		return false, err
	}
	// S8.2: converge the site-to-site kernel routes (from Policy.Routes — explicit intent, never
	// inferred from a peer's AllowedIPs). After peers so the interface + crypto-routing exist.
	var routes, localSubnets []string
	if ds.Policy != nil {
		for _, rt := range ds.Policy.Routes {
			routes = append(routes, rt.DstCIDR)
		}
		localSubnets = ds.Policy.LocalSubnets // D2: the gateway's own approved subnets → route src-hint
	}
	// D2 + D3, ONE host-addr snapshot per tick (review #6): derive the route src-hint AND the
	// unreachable-subnet signal from the SAME view. srcOK → src-hint (D2). hadSubnets && !srcOK → the
	// gateway fronts a subnet it isn't on (bridge-trapped wg0 / misconfig) → D3 site_subnet_unreachable
	// (loud even when the link handshake is fresh — the reassuring-green trap) + a throttled onset log.
	// Enumerate host addrs ONLY when a subnet is advertised (re-review #5): the common non-site node has no
	// LocalSubnets, and siteRouteSrc discards the addrs there anyway — skip the net.InterfaceAddrs syscall.
	var hostAddrs []netip.Addr
	if len(localSubnets) > 0 {
		hostAddrs = r.hostAddrsFn()
	}
	src, srcOK, hadSubnets := siteRouteSrc(localSubnets, hostAddrs)
	if r.siteSubnetUnreachable != nil {
		// D3 (host not on the advertised subnet) OR WF-4 (Docker FORWARD DROP swallows the forward) —
		// both mean "this gateway can't actually deliver its advertised site subnet". Surface either LOUD.
		fwdBlocked := r.forwardBlockedFn != nil && r.forwardBlockedFn()
		r.siteSubnetUnreachable.Store((hadSubnets && !srcOK) || fwdBlocked)
	}
	if hadSubnets && !srcOK {
		if !r.noSrcLogged {
			r.logger.Warn("site_route_src_unresolved", "local_subnets", strings.Join(localSubnets, ","))
			r.noSrcLogged = true // onset-only: reset when a src resolves or nothing is advertised
		}
	} else {
		r.noSrcLogged = false
	}
	srcHint := ""
	if srcOK {
		srcHint = src.String()
	}
	if err := r.backend.ApplyRoutes(ctx, routes, srcHint); err != nil {
		r.healthy.Store(false)
		return false, err
	}
	// H5: refresh the site-link-staleness signal (best-effort; never fails the reconcile).
	if r.siteLinkStale != nil {
		r.updateSiteLinkStale(ctx, ds.Peers)
	}
	r.healthy.Store(true)
	return changed, nil
}

// Run drives reconciliation from two independent triggers: Watch (push, low
// latency) and a ticker (safety net that converges even if push is broken). On
// any control-plane error it backs off and leaves the data plane untouched.
func (r *Reconciler) Run(ctx context.Context, client ControlClient, interval, backoff time.Duration) {
	// Initial resync.
	if _, err := r.runOnce(ctx, client); err != nil {
		r.logger.Warn("reconcile_initial_failed", slog.String("error", err.Error()))
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// Push path: block until the control plane signals a change. Echo the last
		// fetched version so a change during the previous fetch/apply returns now.
		watchCh := make(chan error, 1)
		go func() { watchCh <- client.Watch(ctx, r.version.Load()) }()

		select {
		case <-ctx.Done():
			return
		case err := <-watchCh:
			if err != nil {
				r.logBrickedOnce(err)
				r.logger.Warn("watch_failed_backing_off", slog.String("error", err.Error()))
				if !sleep(ctx, backoff) {
					return
				}
				continue // the ticker keeps converging regardless (safety net)
			}
			if _, err := r.runOnce(ctx, client); err != nil {
				r.logger.Warn("reconcile_after_push_failed", slog.String("error", err.Error()))
			}
		case <-ticker.C:
			if _, err := r.runOnce(ctx, client); err != nil {
				r.logBrickedOnce(err)
				r.logger.Warn("reconcile_interval_failed", slog.String("error", err.Error()))
			}
		}
	}
}

// logBrickedOnce raises the unrecoverable case to ERROR exactly once (S11 WF-S11-6). ONCE is the point: the
// retry loop runs every few seconds, so repeating the remedy would bury it in the same wall of text it exists to
// cut through — and the WARN backoff lines still show the loop is alive. The condition is terminal, so one loud
// line at the moment it is first detected is the whole signal.
func (r *Reconciler) logBrickedOnce(err error) {
	if msg, ok := CertExpiredRemedy(err); ok && r.brickedLogged.CompareAndSwap(false, true) {
		r.logger.Error("agent_cert_expired_cannot_reconnect", slog.String("remedy", msg))
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// peersEqual compares the ACTUAL peer set (from the kernel/wg dump) against the DESIRED set (from the
// control plane). OUTER structure is the sorted-MULTISET compare (F4/R2 restore) — canon both, sort,
// pairwise — so a duplicate-pubkey desired set can't hide an unpruned actual peer (a map-keyed compare
// dropped that). The per-peer Endpoint conditionality lives INSIDE the comparator: after sorting on
// canon (pubkey + sorted allowed-ips, endpoint-BLIND), aligned pairs share pubkey+ips, so the DESIRED
// peer's SiteLink flag decides whether the static Endpoint must match (B4). Only the desired side ever
// carries SiteLink (CP intent); the kernel read path never does — keying canon on SiteLink was the R2
// perpetual-dirty bug.
func peersEqual(actual, desired []Peer) bool {
	if len(actual) != len(desired) {
		return false
	}
	a := append([]Peer(nil), actual...)
	d := append([]Peer(nil), desired...)
	sort.Slice(a, func(i, j int) bool { return canon(a[i]) < canon(a[j]) })
	sort.Slice(d, func(i, j int) bool { return canon(d[i]) < canon(d[j]) })
	for i := range a {
		if canon(a[i]) != canon(d[i]) { // pubkey + allowed-ips (multiset-exact)
			return false
		}
		// B4 static-endpoint compare — but ONLY when the desired peer HAS a static endpoint. A hub's view
		// of a NAT'd spoke has desired Endpoint="" by construction (the spoke dials the hub, not vice
		// versa), so the kernel-learned ROAMED src endpoint is the only truth — comparing it would churn
		// forever (the endpoint-blind canon, exactly like a roaming device peer). The keepalive made that
		// spoke always-connected, so an empty-desired compare would be perpetual-dirty. So: compare the
		// endpoint only for the spoke→hub direction (desired endpoint present), stay blind for hub→spoke.
		if d[i].SiteLink && d[i].Endpoint != "" && a[i].Endpoint != d[i].Endpoint {
			return false
		}
		if d[i].SiteLink && a[i].PersistentKeepalive != d[i].PersistentKeepalive { // site-link keepalive (CK)
			return false
		}
	}
	return true
}

// canon keys a peer by its STABLE IDENTITY (public key + allowed-ips) for the
// dirty-check. It deliberately EXCLUDES the endpoint: a roaming client's observed
// endpoint (NAT source port) changes constantly, so including it made peersEqual
// perpetually false, firing ApplyPeers on every reconcile (and, with the old
// empty-[Interface] syncconf, wiping the interface each time). WireGuard tracks
// roaming endpoints itself, so the desired->actual convergence must not treat the
// observed endpoint as a diff.
//
// BOUNDARY / EPIC 8: this means a legitimate desired ENDPOINT change is not caught
// by the dirty-check. Today no desired peer carries a meaningful static endpoint
// (clients roam). When EPIC 8 (site-to-site) adds gateway-DIALED peers whose
// static endpoint IS control-plane-managed, the dirty-check must distinguish a
// gateway peer's static endpoint (compare it) from a client's roaming one (ignore
// it) — e.g. a per-peer "static endpoint" flag. Ledger marker: EPIC 8 site-to-site.
func canon(p Peer) string {
	ips := append([]string(nil), p.AllowedIPs...)
	sort.Strings(ips)
	return p.PublicKey + "|" + strings.Join(ips, ",") // endpoint-blind; peersEqual compares endpoints per SiteLink (B4/R2)
}
