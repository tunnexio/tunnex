import { relativeAge } from "./format";
import type { HubSet } from "./api";

// S8.6 Slice 6b — the hub-set (HA) view-model. PURE projection of the served HubSet (S8.6 GET /hub-set)
// into render-ready rows. Render-floor: it can only claim what a row attests — a member with metrics shows
// them (rx/tx = 0 is an honest idle link); a NOT-reporting member shows "n/a" (absent, NEVER 0).
//
// ⛔ S14.5: THE ABSENT MARKER WAS "—" AND IS NOW "n/a". Two reasons, and the second is the real one.
// (1) The em-dash rule bans it as a placeholder glyph outright. (2) An em-dash is not READ as "we have no
// value" by anyone who has not been told it means that -- it reads as a dash, or as a minus, or as nothing
// at all to a screen reader. "n/a" says the thing.

// HUB_STALE_MS — a member not handshook within this reads STALE (mirrors GATEWAY_OFFLINE_MS, one clock).
export const HUB_STALE_MS = 90_000;

// formatBytes renders a RAW gauge (display only, never summed as monotonic — S11.1). Absent → the caller
// substitutes "n/a"; this only formats a real number.
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export interface HubMemberRow {
  nodeId: string;
  role: "primary" | "standby";
  reporting: boolean; // true if metrics are reporting; false if absent
  handshakeAge: string; // relativeAge(last_handshake_at) or "n/a" (not reporting)
  rx: string; // formatBytes(rx_bytes) or "n/a"
  tx: string;
  warm: boolean | null; // fresh handshake? null when NOT reporting (unknown ≠ cold)
  demoted: boolean; // the CONFIGURED primary (lowest hub_priority) but NOT the acting primary → a failover
}

export interface HubSetViewModel {
  generation: number;
  members: HubMemberRow[];
  promotionInEffect: boolean; // the active primary (members[0]) ≠ the configured primary (lowest pin)
}

// hubSetView projects the served HubSet into rows. null when there is no HA hub set (unpinned org — the
// zero-config case: no HA surface at all). The CONFIGURED order is read from the members' hub_priority (the
// pins); the ACTIVE order is the served member order. When they diverge, a promotion is in effect and the
// configured-primary member renders as demoted.
export function hubSetView(
  hs: HubSet | null | undefined,
  nowMs: number,
): HubSetViewModel | null {
  if (!hs || hs.members.length === 0) return null;
  let configuredPrimary: string | null = null;
  let bestPrio = Infinity;
  for (const m of hs.members) {
    if (m.hub_priority != null && m.hub_priority < bestPrio) {
      bestPrio = m.hub_priority;
      configuredPrimary = m.node_id;
    }
  }
  const activePrimary = hs.members[0].node_id;
  const promotionInEffect =
    configuredPrimary != null && configuredPrimary !== activePrimary;
  const members = hs.members.map((m): HubMemberRow => {
    const met = m.metrics;
    const reporting = met != null;
    const t = reporting ? Date.parse(met!.last_handshake_at) : NaN;
    return {
      nodeId: m.node_id,
      role: m.role,
      reporting,
      handshakeAge: reporting ? relativeAge(met!.last_handshake_at) : "n/a",
      rx: reporting ? formatBytes(met!.rx_bytes) : "n/a",
      tx: reporting ? formatBytes(met!.tx_bytes) : "n/a",
      warm: reporting ? !Number.isNaN(t) && nowMs - t < HUB_STALE_MS : null,
      demoted: promotionInEffect && m.node_id === configuredPrimary,
    };
  });
  return { generation: hs.generation, members, promotionInEffect };
}

// ── SSI-9: who can see a hub fail ────────────────────────────────────────────────────────────────────────
//
// The failover controller demotes a hub only on testimony: ANOTHER gateway reporting a stale handshake with
// it. A hub's own report proves it reaches the control plane, never that its data plane serves. Gateways of
// the SAME network do not peer with each other, so a primary and standby that share a network cannot
// observe one another. With no gateway in any other network, nobody is watching, the controller holds its
// counters ("no witness, no ruling") and a dead primary is never demoted — while this tab shows a tidy pair.
//
// PURE. It answers from the topology the page already has; it does not claim anyone IS observing right now
// (the Handshake column is that), only whether anyone COULD.

export interface ObserverSite {
  id: string;
  /** ACTIVE gateways bound to this network. */
  gatewayIds: string[];
  /** APPROVED ranges on this network: with none, other networks' gateways have nothing to dial it for. */
  approvedRanges: number;
}

/**
 * unobservedHubs returns the hub members that NO gateway in another network can observe, in member order.
 * A member is observable when its own network has an approved range (so others peer with it) and at least
 * one other network has an active gateway.
 */
export function unobservedHubs(memberIds: string[], sites: ObserverSite[]): string[] {
  const siteOf = new Map<string, ObserverSite>();
  for (const site of sites) for (const id of site.gatewayIds) siteOf.set(id, site);
  return memberIds.filter((member) => {
    const home = siteOf.get(member);
    if (!home) return true; // a hub bound to no network peers with nobody
    if (home.approvedRanges === 0) return true;
    return !sites.some((other) => other.id !== home.id && other.gatewayIds.length > 0);
  });
}
