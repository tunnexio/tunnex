import type { Loaded } from "./api";
import type { NavCount } from "./navcounts";
import { FAILED, LOADING, ok } from "./navcounts";

// S14.4 — the Overview's PURE decisions, extracted so the tier tests them without a DOM and the screen has
// nothing to decide beyond rendering.

/**
 * A stat card's state, reusing the nav-count union deliberately.
 *
 * SAME PROBLEM, SAME TYPE: "we have not learned this yet", "we failed to learn it", and "the answer is a
 * number" are the three states everywhere in this product, and `number | null` collapses the first two into a
 * value the caller can `?? 0` away in one keystroke.
 */
export type StatState = NavCount;

/** Lift a `Loaded<T>` plus a projection into a stat state. `null` load = still loading. */
export function statFrom<T>(
  res: Loaded<T> | null,
  project: (t: T) => number,
): StatState {
  if (res === null) return LOADING;
  return res.ok ? ok(project(res.data)) : FAILED;
}

/** What a stat card renders. `null` = render the unavailable/loading treatment, NEVER a number. */
export function statText(s: StatState): string | null {
  return s.state === "ok" ? String(s.value) : null;
}

/**
 * ⛔ IS THIS A FRESH ORG, OR DID WE FAIL TO FIND OUT?
 *
 * The get-started empty state is only honest when we KNOW the org is empty. Showing it because a fetch failed
 * would tell a founder with a working fleet that they have nothing — the reassuring-empty defect wearing an
 * onboarding hat, and considerably more alarming than a blank panel.
 */
export function isFreshOrg(
  nodes: StatState,
  devices: StatState,
  members: StatState,
): boolean {
  return (
    nodes.state === "ok" &&
    devices.state === "ok" &&
    members.state === "ok" &&
    nodes.value === 0 &&
    devices.value === 0
  );
}

export interface GatewayRow {
  id: string;
  name: string;
  /** The badge label from the ONE health interpreter — never a second copy of the vocabulary. */
  label: string;
  tone: "ok" | "warn" | "danger" | "neutral";
  /**
   * S15.2 / D25(C) — the attribution badge, INDEPENDENT of the health verdict above.
   *
   * ⛔ A SEPARATE FIELD RATHER THAN ANOTHER TONE, because a gateway can be healthy AND unattributable.
   * Merging them would make one of the two facts unreportable whenever the other was present.
   */
  attribution?: string | null;
  attributionDetail?: string | null;
}

/**
 * Sort order for the gateway health list: UNHEALTHY FIRST, then by name.
 *
 * The list shows ALL gateways, not only unhealthy ones (ruled). "Nothing is wrong" and "we have no gateways"
 * must not render identically — and a list that hides healthy rows makes the empty case ambiguous, which is
 * the same defect one level up from the one this screen is built to avoid.
 */
export function sortGateways(rows: GatewayRow[]): GatewayRow[] {
  const rank = { danger: 0, warn: 1, neutral: 2, ok: 3 } as const;
  return [...rows].sort(
    (a, b) => rank[a.tone] - rank[b.tone] || a.name.localeCompare(b.name),
  );
}

// ── S14.4 corrected audit — panels whose data DOES exist ────────────────────────────────────────────────────
//
// ⚠ THESE WERE CUT ON A WRONG MEASUREMENT. The cut list said "no hub, generation, pin or handshake-age field
// exists on Site" — true, and irrelevant: the hub set is its OWN endpoint (`/hub-set`) and its OWN schema
// (`HubSet{generation, members[]}`), with `hubsetview.ts` already projecting it. Device posture was cut as
// "deferred", while `Device` carries health_state / health_blocked / health_reported_at today.
//
// THIRD INSTANCE IN ONE DAY OF AN ABSENCE FOUND BY LOOKING IN ONE PLACE — and the first the founder caught
// rather than the assistant (docs/laws.md).

import type { Device } from "./api";

export interface PeerSlice {
  label: string;
  value: number;
  tone: "ok" | "warn" | "danger" | "neutral";
  /**
   * S15.2 / D25(C) — the attribution badge, INDEPENDENT of the health verdict above.
   *
   * ⛔ A SEPARATE FIELD RATHER THAN ANOTHER TONE, because a gateway can be healthy AND unattributable.
   * Merging them would make one of the two facts unreportable whenever the other was present.
   */
  attribution?: string | null;
  attributionDetail?: string | null;
}

/**
 * The device donut the design actually shows: "129 devices", split Connected / Idle / Posture-blocked /
 * Revoked-offline.
 *
 * ⚠ RE-SOURCED. The first build counted GATEWAYS, which is a different population and a smaller one — the
 * panel is titled "Peer Connection Status" and peers are devices. A chart can be perfectly honest about the
 * wrong denominator.
 *
 * The four buckets are DISJOINT and ordered by precedence, so every device lands in exactly one: revoked
 * first (a revoked device is not "idle"), then posture-blocked (blocked is not "connected"), then liveness.
 */
export function peerSlices(devices: Device[]): PeerSlice[] {
  let revoked = 0,
    blocked = 0,
    connected = 0,
    idle = 0;
  for (const d of devices) {
    if (d.status === "revoked") revoked++;
    else if (d.health_blocked) blocked++;
    else if (d.online) connected++;
    else idle++;
  }
  return [
    { label: "Connected", value: connected, tone: "ok" },
    { label: "Idle", value: idle, tone: "neutral" },
    { label: "Posture-blocked", value: blocked, tone: "warn" },
    { label: "Revoked / offline", value: revoked, tone: "danger" },
  ];
}

export interface PostureSplit {
  compliant: number;
  blocked: number;
  unknown: number;
  /** Percent compliant of those that HAVE reported. `null` when nothing has reported at all. */
  percent: number | null;
}

/**
 * Device posture, from the fields `Device` already carries.
 *
 * ⛔ UNKNOWN IS ITS OWN STATE, and the percentage EXCLUDES it. Counting never-reported devices as compliant
 * would be the reassuring-empty defect with a denominator; counting them as blocked would invent a failure.
 * The design says it in its own caption: "Absence ≠ compliance — unknown is its own state."
 */
export function postureSplit(devices: Device[]): PostureSplit {
  let compliant = 0,
    blocked = 0,
    unknown = 0;
  for (const d of devices) {
    if (d.status === "revoked") continue; // a revoked device has no posture worth reporting
    if (d.health_state === undefined || d.health_state === null) unknown++;
    else if (d.health_blocked) blocked++;
    else compliant++;
  }
  const reported = compliant + blocked;
  return {
    compliant,
    blocked,
    unknown,
    percent: reported === 0 ? null : Math.round((compliant / reported) * 100),
  };
}
