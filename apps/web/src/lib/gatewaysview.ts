import type { Node } from "./api";
import { policyHealthBadge, type HealthBadge } from "./healthview";
import { gatewayLiveness } from "./sitesview";

// gatewaysview — PURE view-models for the Gateways screen (S14.6 slice 2). Electron-free, no React.
//
// ⛔ THE HEALTH GROUPING IS THE SCREEN'S CONTENT, and it exists because `Fleet risk` was CUT.
//
// The handoff's left column is a bubble plot: agent version × peer load, bubble size = peers, colour =
// health. It was ruled out at epic open — *"risk scoring is an unbuilt Tier-3 name in the competitive
// ledger. Replaced by a HEALTH-GROUPED GATEWAY LIST — same information, legible at a glance."*
//
// This is that replacement, and the ruling is right for a reason worth restating: a scatter plot answers
// "which gateway is an outlier"; an operator at 3am is asking "WHAT IS BROKEN". Grouping answers the second
// directly, scales to a 200-gateway fleet, and needs no axis nobody calibrated.

export type GatewayGroupKey = "degraded" | "healthy" | "revoked";

export interface GatewayRow {
  id: string;
  name: string;
  status: Node["status"];
  health: HealthBadge | null;
  /** The OpenVPN refuse-loudly kind — a DIFFERENT axis from policy health (S9.1 4d). */
  ovpnHealth: string | null;
  /** Verified internet egress mode used by newly generated full-tunnel profiles. */
  egressMode: Node["egress_mode"];
  agentVersion: string;
  siteId: string | null;
  /** The bound site's NAME, when the caller knows it. `null` = unbound, or the caller did not load sites. */
  siteName: string | null;
  isHub: boolean;
  lastSeenAt: string | null;
}

export interface GatewayGroup {
  key: GatewayGroupKey;
  rows: GatewayRow[];
}

/**
 * Project nodes into rows.
 *
 * ⛔ A REVOKED GATEWAY CARRIES NO HEALTH BADGE. `revoked` IS its state, and a degradation badge beside it
 * would have the row asserting two things at once — the WF-S11-10 finding, preserved here rather than
 * re-derived. `policyHealthBadge` is only consulted for an active node.
 */
export function toGatewayRow(
  n: Node,
  siteNames?: Record<string, string>,
  nowMs = Date.now(),
): GatewayRow {
  const policyHealth = policyHealthBadge(n);
  // A policy-clean gateway is not healthy if its liveness report is stale. Keep
  // the no-last-seen case neutral for a just-enrolled gateway that has not yet
  // produced its first report.
  const liveness = n.last_seen_at
    ? gatewayLiveness(n.last_seen_at, nowMs)
    : null;
  return {
    id: n.id,
    name: n.name,
    status: n.status,
    // S14.21: guard moved into policyHealthBadge — this line was the second copy of it.
    health:
      policyHealth ??
      (liveness?.offline
        ? { label: "offline", tone: "danger" }
        : null),
    ovpnHealth: n.status === "revoked" ? null : (n.ovpn_health ?? null),
    egressMode: n.egress_mode ?? null,
    agentVersion: n.agent_version,
    siteId: n.site_id ?? null,
    siteName: n.site_id ? (siteNames?.[n.site_id] ?? null) : null,
    isHub: n.is_site_hub === true,
    lastSeenAt: n.last_seen_at ?? null,
  };
}

/**
 * Group into DEGRADED → HEALTHY → REVOKED, in that order.
 *
 * ⛔ DEGRADED FIRST, ALWAYS. The epic's own rule for an ACTING surface: *"the primary action and the thing
 * that is wrong come first."* A fleet list sorted by name makes an operator scan for the problem; a fleet
 * list that leads with the problem has already answered them.
 *
 * ⚠ AND A GATEWAY WITH AN OVPN FAULT COUNTS AS DEGRADED even when its POLICY health is clean. They are
 * different axes (S9.1 4d) and an opted-in gateway that is not serving must not sit in the healthy group
 * because the other axis happens to be fine. Reading only `health` here would put it there.
 */
export function groupGateways(
  nodes: Node[],
  siteNames?: Record<string, string>,
  nowMs = Date.now(),
): GatewayGroup[] {
  const rows = nodes.map((n) => toGatewayRow(n, siteNames, nowMs));
  const degraded = rows.filter(
    (r) =>
      r.status !== "revoked" && (r.health !== null || r.ovpnHealth !== null),
  );
  const healthy = rows.filter(
    (r) => r.status !== "revoked" && r.health === null && r.ovpnHealth === null,
  );
  const revoked = rows.filter((r) => r.status === "revoked");
  return [
    { key: "degraded", rows: degraded },
    { key: "healthy", rows: healthy },
    { key: "revoked", rows: revoked },
  ];
}

export type GatewayFilter = "all" | "healthy" | "degraded";

/**
 * The header's filter chips, with their counts.
 *
 * ⛔ THE COUNTS ARE DERIVED FROM THE SAME GROUPING THE TABLE RENDERS. The handoff shows `All (7)`,
 * `Healthy (3)`, `Degraded (4)` — three numbers that must add up, and would not if the chips counted one way
 * and the list grouped another. ONE derivation, two renderings.
 *
 * ⚠ `all` INCLUDES REVOKED and the other two do not, which is why `healthy + degraded` can be less than
 * `all`. That is honest — a revoked gateway is neither — but it looks like an arithmetic bug unless the
 * screen says so, so the chip row carries the revoked count separately when there is one.
 */
export function gatewayFilterCounts(nodes: Node[]): {
  all: number;
  healthy: number;
  degraded: number;
  revoked: number;
} {
  const g = groupGateways(nodes);
  const by = (k: GatewayGroupKey) =>
    g.find((x) => x.key === k)?.rows.length ?? 0;
  return {
    all: nodes.length,
    healthy: by("healthy"),
    degraded: by("degraded"),
    revoked: by("revoked"),
  };
}

/** Apply a filter chip. `all` keeps revoked rows; the other two never contain them by construction. */
export function applyGatewayFilter(
  groups: GatewayGroup[],
  filter: GatewayFilter,
): GatewayGroup[] {
  // ⛔ UNDER "ALL", AN EMPTY GROUP IS NOT A SECTION — IT IS A HEADING AND A SENTENCE SAYING NOTHING IS HERE,
  // and it cost a full screen of scrolling between the two groups that did have rows. The CHIP already
  // reports "Healthy (0)": the count is the answer, and rendering a card to repeat it is the answer twice,
  // the second time in the space where content should be.
  //
  // ⚠ THE EXCEPTION IS THE WHOLE REASON THIS IS NOT A ONE-LINE FILTER. When the operator SELECTS a group,
  // its emptiness is the answer to the question they just asked, and it must render — an explicitly chosen
  // filter that produces a blank page is indistinguishable from a page that failed to load.
  if (filter === "all") return groups.filter((g) => g.rows.length > 0);
  return groups.filter((g) => g.key === filter);
}

// ── THE NOTES — the epic's KEEP list, rendered ONCE PER GROUP (S14.6, founder-ruled) ────────────────────
//
// ⛔ THE COPY IS THE POINT. The epic's KEEP list names these as its examples of the copy to carry VERBATIM:
// *"THE COPY — carried VERBATIM. It states the product's laws in the interface."* The BADGE names the state;
// THE NOTE SAYS WHAT IT MEANS AND WHAT IT IMPLIES, and losing it was the biggest gap on this screen.
//
// ⛔ AND THEY RENDER PER GROUP, NOT PER ROW. The note is a property of the health KIND, not of the gateway —
// four `site link down` rows would carry four copies of one sentence, which the placement test forbids
// (*is it identical on every row? then it renders once*). Under health grouping the header is that "once".
//
// Keyed by the badge LABEL because that is what `policyHealthBadge` returns and what the row renders — one
// vocabulary, not a second enum to keep in sync with the first.
const KIND_NOTES: Record<string, string> = {
  "site link down":
    "No fresh handshake to the hub. A down site bridge is never shown as green.",
  "site hub unreachable":
    "No public-endpoint carrier for transit. The hub outranks a single spoke link being down.",
  "site subnet unreachable":
    "The gateway advertises a local subnet but no host address sits inside it, so forwarded traffic cannot be sourced onto the LAN.",
  "apply failing":
    "An enforcing apply is currently failing. This errs toward over-reporting: never green while broken.",
  "silent desync":
    "Pushed and applied policy differ, past the debounce, with fresh reports. The gateway is stuck.",
  "health unknown":
    "Cannot determine: the compile hash is unavailable or the gateway stopped reporting. Unknown is its own state, never healthy.",
  "syncing…":
    "A normal push settling. Under the report cadence, so it does not alarm.",
  "agent too old":
    "The agent refused the compiled policy because its version exceeds what the agent can apply, and went deny-all. The remedy is operator-side: upgrade the agent.",
  "enforcing a disabled policy": "Enforcing a policy it cannot swap out.",
  "certificate expired, re-enroll this gateway":
    "The client certificate lapsed, so the mTLS channel itself is blocked. Only re-enrolment recovers this.",
  "agent down, still forwarding (restart agent)":
    "The wire is warm and the brain is dead: wg0 keeps forwarding while the agent is silent, so a since-revoked device is still enforced from a frozen artifact.",
  "expiry-flush degraded":
    "Conntrack flush is unavailable, so an expired grant may keep an established flow alive.",
  "no Kubernetes endpoint view (check API access + RBAC)":
    "The VIP DNAT cannot see its backing endpoints.",
  degraded:
    "Policy enforcement is degraded. See the gateway's kind for which axis.",
};

/**
 * The distinct notes for the kinds present in a group, in the order the rows appear.
 *
 * ⚠ A GROUP CAN MIX KINDS, so this returns a LIST rather than one string. Collapsing a mixed group to a
 * single note would attach one kind's explanation to another kind's row — the badge stays the per-row truth
 * and the header explains only the kinds actually present.
 */
export function groupNotes(rows: GatewayRow[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of rows) {
    const label = r.health?.label;
    if (!label) continue;
    const note = KIND_NOTES[label];
    if (note && !seen.has(note)) {
      seen.add(note);
      out.push(note);
    }
  }
  return out;
}

/**
 * revokeConsequence states what revoking THIS gateway costs, for the two-step confirm.
 *
 * ⛔ ONE CLAUSE OF THIS CHANGED THE DAY TRANSFER SHIPPED, AND THAT IS WHY IT WAS NOT REWRITTEN EARLIER.
 *
 * The previous version said the devices homed here "stop connecting immediately", which was TRUE: revoke
 * cascaded to them in the same transaction. It stopped being true in the commit that added the transfer
 * step and the revoke refusal, and it was changed in that commit and not one earlier — copy describing a
 * flow the product does not have is the defect recorded twice in docs/laws.md this cycle.
 *
 * WHAT IT SAYS NOW, and the split is the point:
 *
 *   n > 0  — the revoke will be REFUSED. So the sentence is not a warning about a cost, it is an
 *            instruction: move them first. The server refuses with `devices_still_homed` and names the same
 *            count, so the screen and the API tell one story.
 *   n === 0 — the permanence, which is a fact about the GATEWAY and true whether or not anyone is homed
 *            here. It stays at zero devices; only the count falls silent, because a caution that fires on
 *            the harmless case is a caution nobody reads on the dangerous one.
 *
 * ⚠ AND AN UNREADABLE COUNT IS NOT ZERO. `counts === null` means the devices list failed to load. A silent
 * all-clear manufactured by a failure is the worst possible output for the one sentence whose job is to
 * stop a destructive click — and here it would also promise a revoke the server may well refuse.
 */
export function revokeConsequence(
  counts: Record<string, number> | null,
  nodeId: string,
): string {
  const permanent =
    "This cannot be undone \u2014 a revoked gateway is never active again.";
  if (counts === null)
    return (
      `${permanent} The devices homed here could not be counted \u2014 if any are, ` +
      `the revoke will be refused until they are moved to another gateway.`
    );
  const n = counts[nodeId] ?? 0;
  if (n === 0) return permanent;
  return (
    `${n} ${n === 1 ? "device is" : "devices are"} homed here, so this gateway cannot be ` +
    `retired yet: move ${n === 1 ? "it" : "them"} to another gateway first. ${permanent}`
  );
}

/**
 * transferConsequence states what MOVING these devices costs — the sentence beside the destination picker.
 *
 * ⛔ IT LEADS WITH THE RE-IMPORT, BECAUSE THAT IS THE PART THE OPERATOR MUST PLAN FOR. Moving the row is
 * the easy half; every issued config bakes its gateway's endpoint and public key, so a moved device holds a
 * config naming a gateway that will not serve it. The server reports which devices need a fresh profile
 * (`needs_reissue`), and this says so before the click rather than after it.
 *
 * ⛔ AND THE CROSS-SITE CLAUSE IS NOT A NICETY (D5). Site-scoped policy is evaluated against the device's
 * GATEWAY'S SITE, so moving a device to a gateway in a different site changes WHICH RULES APPLY TO IT. That
 * is a grant or a revocation, arriving as a side effect of maintenance. A move between sites that does not
 * say so is a silent access change wearing a maintenance label, which is the one thing this surface must
 * not be.
 *
 * ⚠ IT IS DELIBERATELY VAGUE ABOUT THE DIRECTION — "may widen or narrow" — because the screen genuinely
 * does not know. Computing it would mean evaluating the org's whole rule set per device, and a confident
 * wrong answer here is worse than an honest uncertain one: an operator told "nothing changes" will not
 * check, and an operator told "this may change what they reach" will.
 */
export function transferConsequence(
  count: number,
  crossSite: boolean,
): string {
  const base =
    `${count} ${count === 1 ? "device" : "devices"} will move. ` +
    `${count === 1 ? "Its" : "Their"} current configuration names this gateway, so ` +
    `${count === 1 ? "its owner" : "their owners"} must re-import ` +
    `${count === 1 ? "a new profile" : "new profiles"} before reconnecting.`;
  if (!crossSite) return base;
  return (
    `${base} The destination is in a DIFFERENT SITE, and site-scoped policy is evaluated against a ` +
    `device's gateway \u2014 so the rules that apply to ${count === 1 ? "this device" : "these devices"} ` +
    `will change, and what ${count === 1 ? "it" : "they"} can reach may widen or narrow.`
  );
}
