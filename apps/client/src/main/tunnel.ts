import { HelperConnection, PROTOCOL_VERSION, type HelperResponse, type PostureStatus, type ResolverForward, type TunnelConfig, type TunnelStatus } from "./helperclient";

// helperSocketPath is the local endpoint the privileged helper listens on. It is
// platform-specific (a unix socket on macOS, a named pipe on Windows). The helper
// creates it with an owner-only ACL; the app connects and its caller identity is
// verified helper-side (path-check now, code-signing at S6.5b).
export function helperSocketPath(platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") return "\\\\.\\pipe\\tunnex-helper";
  return "/var/run/tunnex/helper.sock";
}

// ConfigProvider yields the WireGuard TunnelConfig for the current device. It runs
// in MAIN and fetches via the bearer-injected API — so the WG PRIVATE KEY, like
// the bearer token, never enters the renderer. (D2: the client OWNS device
// creation and never re-fetches; see PLAN S6.3 ConfigProvider decisions.)
export type ConfigProvider = () => Promise<TunnelConfig>;

type TunnelOwnership =
  | { readonly kind: "inactive" }
  | { readonly kind: "up"; readonly generation: number }
  | { readonly kind: "cleanup-required"; readonly generation: number };

// These replies are guaranteed to occur before the helper arms an interface,
// route, resolver, or kill-switch. Every unknown/new failure is ambiguous and
// therefore remains cleanup-required until an explicit tunnel_down succeeds.
const CLEAN_PREARM_UP_CODES = new Set([
  "config_required",
  "bad_private_key",
  "bad_peer_key",
  "bad_endpoint",
  "bad_address",
  "bad_allowed_ips",
  "incomplete_full_tunnel",
  "bad_dns",
  "bad_mtu",
  "bad_keepalive",
  "bad_control_plane_endpoint",
  "endpoint_unresolved",
  "full_tunnel_requires_dns",
  "wfp_arm_failed",
  "pf_arm_failed",
]);

// HEARTBEAT_MS must stay well under the helper's read deadline (30s): the app holds
// ONE persistent connection open and this heartbeat is what keeps it the live
// "owner" (and feeds the UI live stats). Miss enough heartbeats and the helper
// drops the owner connection and fails the tunnel closed.
const HEARTBEAT_MS = 10_000;

// TunnelController is MAIN's tunnel control. It holds a PERSISTENT helper
// connection for the tunnel's lifetime (the liveness signal), builds the typed
// requests, and heartbeats while up. onStatus lets main forward live status /
// a fail-closed event to the renderer.
export class TunnelController {
  private readonly conn: HelperConnection;
  private heartbeat: ReturnType<typeof setInterval> | null = null;
  private upInFlight = false;
  private sessionGeneration = 0;
  private connectionGeneration = 0;
  private ownership: TunnelOwnership = { kind: "inactive" };
  private failedPublishedGeneration: number | null = null;
  // The active device's tunnel address, cached from the config on `up`. The helper
  // reports runtime stats (rx/tx/handshake) but not the address (it's config), so
  // main attaches it to every status it forwards. Cleared on down / fail-closed.
  private address?: string;
  // resolversActive tracks whether we have installed any domain-scoped resolvers so
  // the inert path (no forwards, none ever set) makes ZERO wire calls. S8.4.
  private resolversActive = false;

  // withAddress decorates a helper status with the cached tunnel address so the UI
  // can show "Your IP" without the address ever needing to round-trip the helper.
  private withAddress(s: TunnelStatus): TunnelStatus {
    return this.address ? { ...s, address: this.address } : s;
  }

  constructor(
    socketPath: string,
    private readonly onStatus?: (s: TunnelStatus) => void,
  ) {
    this.conn = new HelperConnection(socketPath, () => this.onLost(this.connectionGeneration));
  }

  // baseAllowed caches the session's BAKED-STABLE AllowedIPs (the pool for split, 0.0.0.0/0 + ::/0 for
  // full) so the RoutedRangesMonitor can merge base ∪ ranges without re-fetching the config (identity is
  // never re-fetched — D2). Refreshed each up(); a mode change re-mints, so a fresh session's monitor
  // reads the fresh base.
  private baseAllowed: string[] = [];

  // baseAllowedIPs returns the session's baked-stable AllowedIPs — the routes the monitor must always
  // re-include (the stable core the routed-ranges push never drops).
  baseAllowedIPs(): string[] {
    return [...this.baseAllowed];
  }

  async up(resolveConfig: ConfigProvider): Promise<TunnelStatus> {
    if (this.upInFlight) throw new Error("tunnel_up_in_progress");
    if (this.ownership.kind !== "inactive") throw new Error("tunnel_cleanup_required");
    this.upInFlight = true;
    const generation = this.nextSessionGeneration();
    this.connectionGeneration = generation;
    this.failedPublishedGeneration = null;
    try {
      const config = await resolveConfig();
      this.address = config.address;
      this.baseAllowed = [...(config.allowed_ips ?? [])];
      // Once tunnel_up is on the wire, absence of a reply cannot prove that the
      // helper armed nothing. Cleanup-required is the provisional state; only a
      // typed pre-arm refusal may return it to inactive.
      this.ownership = { kind: "cleanup-required", generation };
      let r: HelperResponse;
      try {
        r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "tunnel_up", config });
      } catch (error) {
        this.clearPublishedTunnelState();
        this.publishFailedOnce(generation);
        throw error;
      }
      if (!r.ok) {
        this.clearPublishedTunnelState();
        if (r.code && CLEAN_PREARM_UP_CODES.has(r.code)) {
          this.ownership = { kind: "inactive" };
        } else {
          this.publishFailedOnce(generation);
        }
        throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "tunnel up failed"));
      }
      this.ownership = { kind: "up", generation };
      await this.applyResolvers(config.dns_forwards ?? []);
      // tunnel_up may have succeeded immediately before the owner socket died
      // during resolver setup. onLost requires cleanup; never publish the
      // stale success or arm a heartbeat on a replacement/status-only socket.
      if (!this.owns("up", generation) || this.sessionGeneration !== generation) {
        throw new Error("tunnel_owner_lost_during_up");
      }
      this.startHeartbeat(generation);
      return this.withAddress(r.status ?? { state: "up" });
    } finally {
      this.upInFlight = false;
    }
  }

  // resolverApply is the ONE set_resolvers path + the ONE resolversActive latch (S8.5 #6 — the F5 strand
  // invariant lives here, not in two copies). Marks active the moment we ATTEMPT a non-empty install —
  // NOT only on success — so a partial helper failure that left owned files can't strand them past a
  // down() sweep (F5). `resolvers_unsupported` (Windows stub) means nothing was installed → clear. A
  // genuine failure LEAVES the latch true so down() still sweeps once. Returns the raw response; the two
  // callers apply their error posture (up/down swallow, the monitor throws).
  private async resolverApply(fwds: ResolverForward[]): Promise<{ ok: boolean; code?: string; error?: string }> {
    if (fwds.length > 0) this.resolversActive = true;
    // Once the request is on the FIFO socket, a throw/refusal cannot prove the
    // helper applied none of it. Mark unknown before the wire and restore exact
    // knowledge only from a definitive response.
    const r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "set_resolvers", resolvers: fwds });
    if (r.ok) {
      this.resolversActive = fwds.length > 0; // installed n, or swept to 0
    } else if (r.code === "resolvers_unsupported") {
      this.resolversActive = false; // platform stub: nothing installed
    }
    return r;
  }

  // applyResolvers is the up()/down() best-effort / fail-STATIC wrapper: a set failure must NEVER fail the
  // tunnel — cross-site names just don't resolve. Inert when there is nothing to set and nothing was set
  // before (zero wire calls — the S8.4 inert red).
  private async applyResolvers(fwds: ResolverForward[]): Promise<void> {
    if (fwds.length === 0 && !this.resolversActive) return;
    try {
      await this.resolverApply(fwds);
    } catch {
      /* fail-static: leave the tunnel up; resolversActive stays as attempted so a down still tries once */
    }
  }

  // setAllowedIPs live-updates the tunnel peer's AllowedIPs to the full desired set (S8.5 routed-subnets
  // push) via the helper. Unlike applyResolvers (one-shot, swallow), this is driven by a POLL, so it
  // THROWS on failure — the RoutedRangesMonitor catches it, keeps its last-applied set (fail-static),
  // and retries with backoff. A refusal (old helper unknown_verb) or a wire error both throw.
  async setAllowedIPs(allowedIPs: string[]): Promise<void> {
    const r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "set_allowed_ips", allowed_ips: allowedIPs });
    if (!r.ok) throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "set_allowed_ips failed"));
  }

  // setResolvers is the POLL-DRIVEN resolver apply (S8.5 Slice 3): the RoutedRangesMonitor hands the FULL
  // desired forward set (server-gated to reachable resolvers) each time it changes — forwards are VOLATILE,
  // same lifecycle as routes, so they ride the poll, not the baked config. Full-sweep + reconcile are
  // helper-side (S8.4 set_resolvers). Unlike up()'s one-shot applyResolvers this THROWS on a genuine
  // failure so the monitor keeps its last-applied set (fail-static) and retries — EXCEPT
  // resolvers_unsupported (Windows: the resolver verb is a stub until Slice 4's NRPT), which returns
  // cleanly (nothing to retry; the slice is macOS-live, Windows-dark, and skips WITHOUT erroring).
  // Latches resolversActive on any non-empty attempt so down()'s sweep can never STRAND monitor-installed
  // resolver files — the monitor is a SECOND writer to the same helper resolver state (the F5 strand class).
  async setResolvers(fwds: ResolverForward[]): Promise<void> {
    const r = await this.resolverApply(fwds); // the ONE set_resolvers path + latch (#6)
    if (r.ok || r.code === "resolvers_unsupported") return; // unsupported = Windows stub: clean skip, no thrash
    throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "set_resolvers failed"));
  }

  // setGatewayPeer re-homes the tunnel onto a new active-hub peer (WF-A) via the helper's peer SWAP — the
  // device's own key/address/kill-switch are untouched, so the session survives without re-enrollment.
  // POLL-driven like setAllowedIPs, so it THROWS on failure: the RoutedRangesMonitor's dial tier catches
  // it, keeps its last-applied dial (fail-static), and retries with backoff. A refusal (old helper
  // unknown_verb, or the full-tunnel carve-out rehome_full_tunnel_unsupported) and a wire error both throw.
  async setGatewayPeer(peerPublicKey: string, endpoint: string): Promise<void> {
    const r = await this.conn.request({
      version: PROTOCOL_VERSION,
      auth_mode: "path_check",
      verb: "set_gateway_peer",
      gateway_peer: { peer_public_key: peerPublicKey, endpoint },
    });
    if (!r.ok) throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "set_gateway_peer failed"));
  }

  async down(): Promise<void> {
    this.stopHeartbeat();
    // First-login replacement and repeated disconnects have no tunnel to tear
    // down. Do not create a helper socket merely to ask an already-down helper.
    if (this.ownership.kind === "inactive") {
      this.clearPublishedTunnelState();
      return;
    }

    const teardownGeneration = this.nextSessionGeneration();
    this.connectionGeneration = teardownGeneration;
    this.failedPublishedGeneration = null;
    // Both an up tunnel and an earlier ambiguous/partial failure require the
    // same explicit cleanup wire call. Never downgrade to inactive on inference.
    this.ownership = { kind: "cleanup-required", generation: teardownGeneration };
    try {
      // Sweep any installed resolvers BEFORE dropping the connection (while it's alive).
      if (this.resolversActive) {
        try {
          await this.resolverApply([]);
        } catch {
          // The backend's Down is still the authoritative full cleanup attempt.
          // Continue on a fresh helper socket if this FIFO socket was poisoned.
        }
      }
      const r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "tunnel_down" });
      if (!r.ok) {
        this.clearPublishedTunnelState();
        this.resolversActive = true;
        this.publishFailedOnce(teardownGeneration);
        throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "tunnel down failed"));
      }
    } catch (error) {
      // !ok and wire loss are both cleanup-required. A later down must reconnect
      // and retry the real helper cleanup rather than becoming a zero-wire no-op.
      this.clearPublishedTunnelState();
      this.publishFailedOnce(teardownGeneration);
      throw error;
    }

    this.ownership = { kind: "inactive" };
    this.failedPublishedGeneration = null;
    this.clearPublishedTunnelState();
    this.resolversActive = false;
    // Graceful: the down told the helper to restore routing, so closing the owner
    // connection now is expected (won't trip fail-closed).
    this.conn.close();
  }

  // Terminal server verdicts cannot keep using a locally restored owner after
  // tunnel_down refuses. Close the owner socket so the helper's existing
  // fail-closed contract becomes the network truth before main reports failure.
  // This is intentionally main-process-only; the renderer never receives a
  // force-close verb.
  failClosed(): void {
    if (this.ownership.kind === "inactive") return;
    const generation = this.ownership.generation;
    this.ownership = { kind: "cleanup-required", generation };
    this.stopHeartbeat();
    this.clearPublishedTunnelState();
    this.resolversActive = true;
    // Intentional close suppresses HelperConnection.onLost; publish once here.
    this.conn.close();
    this.publishFailedOnce(generation);
  }

  async status(): Promise<TunnelStatus> {
    const r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" });
    if (!r.ok) throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "tunnel status failed"));
    const status = r.status ?? { state: "down" };
    // Preserve the historical display fallback, but never use an absent payload
    // as authoritative Down truth that could erase a real cleanup obligation.
    if (r.status) this.reconcileSuccessfulStatus(r.status);
    return this.withAddress(status);
  }

  // posture reads local posture facts via the helper (S7.5.3) — read-only, never
  // touches tunnel state or connection ownership. Throws on refusal (incl. an
  // OLD helper's unknown_verb); the caller treats any throw as "facts
  // indeterminate" and reports them ABSENT, never guessed.
  async posture(): Promise<PostureStatus> {
    const r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "posture_status" });
    if (!r.ok) throw new Error(r.code ? `${r.code}: ${r.error ?? ""}` : (r.error ?? "posture status failed"));
    return r.posture ?? {};
  }

  private startHeartbeat(generation: number): void {
    this.stopHeartbeat();
    this.heartbeat = setInterval(async () => {
      try {
        const r = await this.conn.request({ version: PROTOCOL_VERSION, auth_mode: "path_check", verb: "status" });
        if (generation !== this.sessionGeneration || !this.owns("up", generation)) return;
        if (r.ok && r.status) {
          this.reconcileSuccessfulStatus(r.status);
          if (r.status.state === "failed") {
            this.publishFailedOnce(generation);
          } else {
            this.onStatus?.(this.withAddress(r.status));
          }
        }
      } catch {
        /* a dropped connection surfaces via onLost */
      }
    }, HEARTBEAT_MS);
    this.heartbeat.unref?.();
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  // A controller is app-lifetime, while the privileged helper can outlive and
  // predate it. A successful helper read is therefore also ownership truth: a
  // fresh controller that observes Up/Failed must retain a real cleanup handle
  // so the next down cannot become an inactive zero-wire no-op. Read failures do
  // not enter here and remain inconclusive; they never invent ownership.
  private reconcileSuccessfulStatus(status: TunnelStatus): void {
    if (status.state === "down") {
      if (this.ownership.kind !== "inactive") this.stopHeartbeat();
      this.ownership = { kind: "inactive" };
      this.failedPublishedGeneration = null;
      this.clearPublishedTunnelState();
      this.resolversActive = false;
      return;
    }

    if (status.state !== "up" && status.state !== "failed") return;

    let generation: number;
    if (this.ownership.kind === "inactive") {
      generation = this.nextSessionGeneration();
      this.connectionGeneration = generation;
      this.failedPublishedGeneration = null;
      // A status connection proves non-down helper state, but it did not perform
      // this controller's tunnel_up. Treat that state as cleanup-only ownership.
      this.ownership = { kind: "cleanup-required", generation };
      this.clearPublishedTunnelState();
      this.resolversActive = true;
    } else {
      generation = this.ownership.generation;
    }

    if (status.state === "failed") {
      this.ownership = { kind: "cleanup-required", generation };
      this.stopHeartbeat();
      this.clearPublishedTunnelState();
      this.resolversActive = true;
    }
  }

  // onLost fires when the persistent connection drops unexpectedly (helper died):
  // stop heartbeating and surface a fail-closed status to the UI.
  private onLost(generation: number): void {
    // A read-only status/posture socket is not tunnel ownership. Its timeout or
    // loss may reject that read, but must not manufacture a fail-closed tunnel
    // transition when this controller has no active generation.
    if (this.ownership.kind === "inactive"
      || this.ownership.generation !== generation
      || generation !== this.sessionGeneration) return;
    this.ownership = { kind: "cleanup-required", generation };
    this.stopHeartbeat();
    this.clearPublishedTunnelState();
    this.resolversActive = true;
    this.publishFailedOnce(generation);
  }

  private owns(kind: Exclude<TunnelOwnership["kind"], "inactive">, generation: number): boolean {
    return this.ownership.kind === kind && this.ownership.generation === generation;
  }

  private clearPublishedTunnelState(): void {
    this.address = undefined;
    this.baseAllowed = [];
  }

  private publishFailedOnce(generation: number): void {
    if (this.failedPublishedGeneration === generation) return;
    this.failedPublishedGeneration = generation;
    this.onStatus?.({ state: "failed" });
  }

  private nextSessionGeneration(): number {
    if (this.sessionGeneration === Number.MAX_SAFE_INTEGER) {
      throw new Error("tunnel session generation exhausted");
    }
    this.sessionGeneration += 1;
    return this.sessionGeneration;
  }
}
