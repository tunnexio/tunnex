import type { DeviceApi, DialTarget } from "./deviceconfig";
import type { ResolverForward } from "./helperclient";
import { PollMonitor } from "./pollmonitor";
import { REVOKE_POLL_MS, REVOKE_BACKOFF_MAX_MS } from "./revocation";

// canonRanges dedups + sorts a CIDR list into a stable canonical form for change-compare. The server
// already returns its ranges canonical + sorted (S8.5 2b); we merge in the baked base and re-sort so the
// compare is order-free (the peersEqual lesson at the client tier — compare canonical, never raw).
export function canonRanges(cidrs: string[]): string[] {
  return Array.from(new Set(cidrs.map((c) => c.trim()).filter((c) => c.length > 0))).sort();
}

// canonForwards folds the forward set into a stable string for change-compare (S8.5 Slice 3). Normalized
// (lowercased domain, trimmed) + deduped by the domain=resolver pair + sorted — so a reordered or
// case-shuffled server response is NOT a change and emits ZERO helper calls (the DNS tier's no-churn half).
export function canonForwards(fwds: ResolverForward[]): string {
  return Array.from(
    new Set(fwds.map((f) => `${f.domain.trim().toLowerCase()}=${f.resolver_ip.trim()}`)),
  )
    .sort()
    .join(",");
}

// canonDial folds a dial target into a stable string for change-compare (WF-A). A null dial (server derived
// none) folds to "" — the SAME as an unchanged seed, so it never reads as a change and drives ZERO helper
// calls. endpoint|pubkey is the identity of a gateway peer; a matching pair is not a re-home.
export function canonDial(d: DialTarget | null): string {
  return d ? `${d.endpoint.trim()}|${d.pubkey.trim()}` : "";
}

export type RangesOutcome = "skipped" | "applied" | "unchanged" | "inconclusive";

// RoutedRangesMonitor is the S8.5 volatile-config poll — the RevocationMonitor's sibling (same cadence,
// self-scheduling lifecycle, error posture). While a SPLIT-tunnel session is up it fetches the org's
// declared ranges AND reachable DNS forwards in ONE poll, and live-applies each tier via the helper ONLY
// when it changes: ranges → set_allowed_ips (base ∪ ranges), forwards → set_resolvers (the full gated set).
// It is NOT constructed for a full-tunnel session (0.0.0.0/0 subsumes every range and the DNS is the
// full-tunnel resolver — the CLIENT layer skips, so no pointless privileged call; ipc.ts owns that gate).
//
// Discipline (BOTH tiers, independently):
//   - fail-STATIC: a poll THROW (or an apply THROW) keeps that tier's last-applied set — a CP blip never
//     un-routes the office LAN nor drops its DNS. Backoff lengthens the next probe.
//   - no-CHURN: canonical compare → apply only on change. N identical polls = ZERO helper calls.
//   - full-SWEEP: ranges = base ∪ current-ranges (never accumulated); forwards = the full current gated
//     set (helper reconciles owned files) — a removed range/forward vanishes on the next differing poll.
// The two tiers are INDEPENDENT: a set_resolvers failure never blocks a routes apply, and vice-versa —
// DNS and routing degrade separately (a resolver-write refusal must not strand the office-LAN route).
export class RoutedRangesMonitor extends PollMonitor {
  // lastRanges = the canonical join of the AllowedIPs the helper currently holds. Seeded to the BAKED
  // BASE: tunnel_up already applied it, so an empty-ranges org yields "unchanged" on the ranges tier —
  // zero client work (the D5 empty-channel golden's client half).
  private lastRanges: string;
  // lastForwards = the canonical fold of the resolvers the helper currently holds. Seeded EMPTY: up()
  // applies dns_forwards=[] (forwards are volatile, never baked), so an empty-forwards org is "unchanged".
  private lastForwards = "";
  // lastDial = the canonical fold (endpoint|pubkey) of the gateway peer the helper currently dials (WF-A).
  // Seeded from the MINTED peer (currentDial), so the first poll returning that same active hub is
  // "unchanged" — zero helper calls until the active primary actually moves (failover).
  private lastDial: string;

  constructor(
    private readonly orgId: string,
    private readonly base: string[], // the baked-stable AllowedIPs (split-tunnel = [pool]) — never dropped
    private readonly api: Pick<DeviceApi, "routedConfig">,
    private readonly applyRanges: (allowedIPs: string[]) => Promise<void>, // TunnelController.setAllowedIPs
    private readonly applyForwards: (fwds: ResolverForward[]) => Promise<void>, // TunnelController.setResolvers
    baseMs: number = REVOKE_POLL_MS, // reuse the revocation cadence (config changes rarely)
    maxMs: number = REVOKE_BACKOFF_MAX_MS,
    setTimer?: (cb: () => void, ms: number) => ReturnType<typeof setTimeout>,
    clearTimer?: (t: ReturnType<typeof setTimeout>) => void,
    // S8.5 #5: whether to apply the ROUTES tier. FALSE for a full-tunnel session — 0.0.0.0/0 already
    // subsumes every routed range, so pushing them is a no-op; the RESOLVER tier ALWAYS runs (full-tunnel's
    // baked DNS can't answer internal cross-site zones, so it needs the forwards). The mode ruling that once
    // skipped the whole monitor for full-tunnel lapsed when Slice 3 grew the payload past routes.
    private readonly routesEnabled: boolean = true,
    // WF-A: the device id whose active-hub dial the poll should fetch (scopes the dial to THIS device on the
    // server). Absent → the dial is never requested and the dial tier is inert (the monitor pre-dates WF-A).
    private readonly deviceId?: string,
    // WF-A: apply a dial change by re-homing the gateway peer (TunnelController.setGatewayPeer). Absent →
    // the dial tier is inert (no re-home wiring).
    private readonly applyDial?: (endpoint: string, pubkey: string) => Promise<void>,
    // WF-A: whether to apply the DIAL tier. FALSE for a full-tunnel session in v1 — a full tunnel's endpoint
    // host-route + kill-switch pass rule must move WITH the peer, which is the D-WFA-4 carve-out (a separate
    // slice); until then a full-tunnel re-home is refused, so we do not drive it.
    private readonly dialEnabled: boolean = false,
    // WF-A: the MINTED gateway peer, to seed lastDial so the first poll matching it is a no-op.
    currentDial: DialTarget | null = null,
  ) {
    super(baseMs, maxMs, setTimer, clearTimer);
    this.lastRanges = canonRanges(base).join(",");
    this.lastDial = canonDial(currentDial);
  }

  // IMMEDIATE first poll (the mint-ruling-A condition): a NEW device gets its ranges + forwards within
  // SECONDS of connecting, not after a full 30s interval — shrinking the new-device gap so ruling A's
  // "poll covers new devices" trade is nearly free. loop() runs checkOnce NOW, then reschedules at cadence.
  protected override firstTick(): void {
    void this.loop();
  }

  // checkOnce runs a single poll then applies BOTH tiers, each on change only, each fail-static. Exposed
  // for tests.
  async checkOnce(): Promise<RangesOutcome> {
    if (this.stopped || this.inFlight) return "skipped";
    this.inFlight = true;
    try {
      const cfg = await this.api.routedConfig(this.orgId, this.deviceId);
      if (this.stopped) return "skipped"; // disconnecting — abandon the result
      const merged = canonRanges([...this.base, ...cfg.ranges]);
      const rangesKey = merged.join(",");
      const forwardsKey = canonForwards(cfg.forwards);
      const dialKey = canonDial(cfg.dial);

      let changed = false;
      let failed = false;
      // RANGES tier — apply base ∪ ranges via set_allowed_ips on change; fail-static (keep lastRanges).
      // Skipped entirely for a full-tunnel session (#5): 0.0.0.0/0 subsumes every range (no route calls).
      if (this.routesEnabled && rangesKey !== this.lastRanges) {
        try {
          await this.applyRanges(merged);
          this.lastRanges = rangesKey;
          changed = true;
        } catch {
          failed = true;
        }
      }
      // FORWARDS tier — apply the full gated set via set_resolvers on change; INDEPENDENT fail-static.
      if (forwardsKey !== this.lastForwards) {
        try {
          await this.applyForwards(cfg.forwards);
          this.lastForwards = forwardsKey;
          changed = true;
        } catch {
          failed = true;
        }
      }
      // DIAL tier (WF-A) — re-home the gateway peer via set_gateway_peer when the active hub moved.
      // INDEPENDENT fail-static, same as the other tiers. A NULL dial folds to "" and — because we only act
      // on a DIFFERING non-empty key — never swaps the peer away (a single-gateway org or a server blip that
      // returns no dial keeps the current peer). Gated OFF for full-tunnel in v1 (D-WFA-4 carve-out).
      if (this.dialEnabled && this.applyDial && cfg.dial && dialKey !== this.lastDial) {
        try {
          await this.applyDial(cfg.dial.endpoint, cfg.dial.pubkey);
          this.lastDial = dialKey;
          changed = true;
        } catch {
          failed = true;
        }
      }

      if (failed) {
        // At least one tier's apply threw: KEEP its last-applied set, lengthen the next probe. The other
        // tier (if it succeeded) already advanced its key, so it won't re-apply — no thrash.
        this.bumpBackoff();
        return "inconclusive";
      }
      this.resetBackoff();
      return changed ? "applied" : "unchanged";
    } catch {
      // Poll read error: KEEP both last-applied sets, lengthen the next probe (fail-static, both tiers).
      this.bumpBackoff();
      return "inconclusive";
    } finally {
      this.inFlight = false;
    }
  }
}
