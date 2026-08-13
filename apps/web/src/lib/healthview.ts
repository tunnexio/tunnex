import type { Node } from "./api";

// policyHealthBadge — the S7.4b differentiated gateway-health badge, a PURE projection.
// The `policy_degraded` BOOL is PRIMARY: not degraded → no badge (healthy). When degraded, the
// KIND refines the label + tone, but the badge is NEVER less alarmed than the bool (never an
// "ok" tone, never null, while degraded). `converging` is a normal push settling → a subtle
// "syncing", not a loud alarm; `silent_desync` is the stuck, actionable case; `desync_unknown`
import type { BadgeTone } from "../components/ui";

export type { BadgeTone };

export interface HealthBadge {
  label: string;
  tone: BadgeTone;
}

// ⛔ THE EXHAUSTIVENESS GUARD — REGISTERED AT S11, TRIGGER "next health-kind addition or S14.7 pre-flight",
// DISCHARGED HERE. It replaces a `switch` whose `default` was fail-safe in the wrong dimension.
//
// The old default returned `{label: "degraded", tone: "warn"}` for any unrecognised kind, so it never
// under-alarmed — the bool was still honoured. But A NEW KIND ADDED TO THE SPEC FELL THROUGH TO IT SILENTLY,
// losing the one thing the kind exists to carry: its NAMED REMEDY.
//
// THAT IS NOT HYPOTHETICAL. `k8s_endpoints_unavailable` shipped in the Go enum and in the metrics, never
// reached this renderer, and rendered as the generic "degraded" badge in the product — found only by the S11
// mirror-surface census (WF-S11-7), a whole story later.
//
// A `Record` keyed by the generated union makes the same mistake a COMPILE ERROR NAMING THE MISSING KIND.
// `make generate` updates the union from the spec; this table then fails to typecheck until someone decides
// what the new kind should say.
type PolicyDegradedKind = NonNullable<Node["policy_degraded_kind"]>;

/** Every kind except `healthy` — the ones that must have a badge. */
export type NonHealthyPolicyDegradedKind = Exclude<
  PolicyDegradedKind,
  "healthy"
>;

const DEGRADED_BADGE: Record<NonHealthyPolicyDegradedKind, HealthBadge> = {
  // `converging` is a normal push settling — a subtle "syncing", not a loud alarm.
  converging: { label: "syncing…", tone: "warn" },
  apply_failing: { label: "apply failing", tone: "warn" },
  stuck_enforcing: { label: "enforcing a disabled policy", tone: "danger" },
  silent_desync: { label: "silent desync", tone: "danger" },
  // The honest can't-determine. Never rendered as healthy.
  desync_unknown: { label: "health unknown", tone: "unknown" },
  // Refused the artifact -> deny-all; remedy: upgrade.
  unsupported_policy_version: { label: "agent too old", tone: "danger" },
  // S8.2: no carrier for site-to-site traffic.
  site_hub_down: { label: "site hub unreachable", tone: "danger" },
  // S8.2: a site-to-site tunnel has no fresh handshake.
  site_link_down: { label: "site link down", tone: "danger" },
  // S8.2c: advertises a LAN the gateway isn't on (bridge-trapped).
  site_subnet_unreachable: { label: "site subnet unreachable", tone: "danger" },
  // S8.7: can't tear down expired-grant flows (CAP_NET_ADMIN?) — revoked flows may linger.
  conntrack_flush_unavailable: { label: "expiry-flush degraded", tone: "warn" },
  // S11 WF-S11-6: the cert expired, so the agent cannot authenticate to the CP — including the renewal
  // endpoint, which needs the cert that expired. The label carries the REMEDY because no other kind's remedy
  // applies and waiting is actively wrong: this never self-heals.
  cert_expired_cannot_reconnect: {
    label: "certificate expired, re-enroll this gateway",
    tone: "danger",
  },
  // S10.3 WF-K5 — THE KIND THIS GUARD EXISTS BECAUSE OF. Add a kind to the spec and forget this table, and
  // the compiler now says so by name instead of the product quietly saying "degraded".
  k8s_endpoints_unavailable: {
    label: "no Kubernetes endpoint view (check API access + RBAC)",
    tone: "danger",
  },
  // WF-C L2: zombie hub — wire fresh, agent dead. The label names BOTH halves so it lies in neither
  // direction (not "offline" — it forwards; not "healthy" — it's stale).
  hub_forwarding_not_reconciling: {
    label: "agent down, still forwarding (restart agent)",
    tone: "danger",
  },
};

/** Degraded, but we have nothing more specific to say. Never null while the bool is true. */
const GENERIC_DEGRADED: HealthBadge = { label: "degraded", tone: "warn" };

/**
 * ⛔ `status` IS REQUIRED, AND THAT IS THE WHOLE FIX (S14.21).
 *
 * This took `Pick<Node, "policy_degraded" | "policy_degraded_kind">`. That did not merely FAIL to check
 * `status` — it made checking IMPOSSIBLE: a caller could not pass one, and the compiler was satisfied by an
 * object that had none. **The function was structurally forbidden from forming the verdict it is named for**,
 * so the guard ended up OUTSIDE it, in the callers, where it was inherited by whoever remembered.
 *
 * The census that produced this change: SEVEN sites form a health verdict about a gateway. Four guarded
 * `revoked`, three did not — and the three that did carried the SAME LINE COPY-PASTED, which is the tell. A
 * rule restated at each site is not enforced, it is remembered. On the deployed dashboard a revoked gateway
 * rendered the literal word **"healthy"**, in green.
 *
 * Third time this defect was fixed — `Gateways.tsx` at EPIC 11, `sitesview.ts` at S13.1. Both fixed the site
 * where the bug was SEEN. This fixes the place the verdict is FORMED, and requires `status` so a caller that
 * forgets does not compile.
 *
 * ⚠ WHAT THIS DOES NOT CLOSE: a raw `.filter(n => n.policy_degraded)` bypasses this function entirely. The
 * signature ENABLES correct sourcing; it cannot FORCE it. Two such reads existed and are re-sourced in the
 * same change — but the class stays open by construction, because the field remains readable.
 */
export function policyHealthBadge(
  node: Pick<Node, "status" | "policy_degraded" | "policy_degraded_kind">,
): HealthBadge | null {
  // ⛔ REVOKED IS THE STATE. A degradation badge beside it describes a gateway that is no longer meant to
  // work, and "site link down" on a deliberately-revoked node instructs an operator to go repair something
  // that was decommissioned on purpose. No health verdict at all — not a healthy one, not a degraded one.
  if (node.status === "revoked") return null;
  if (!node.policy_degraded) return null; // bool primary — not degraded → no badge
  const kind = node.policy_degraded_kind;
  // Degraded per the authoritative bool but the kind is absent or says `healthy`. STILL A BADGE: the badge is
  // never less alarmed than the bool. This arm is for a MISSING kind, not an unknown one — an unknown kind is
  // now impossible, because the table above would not compile without it.
  if (kind === undefined || kind === null || kind === "healthy")
    return GENERIC_DEGRADED;
  // ⛔ `??` IS NOT BELT-AND-BRACES — IT GUARDS A DIFFERENT FAILURE THAN THE `Record` DOES, and replacing the
  // switch's default with the table alone silently removed it. The component test caught it immediately.
  //
  //   THE RECORD guards COMPILE time: a kind in OUR spec with no badge is a build error.
  //   THE `??`   guards RUN time: a kind the SERVER has and our generated union does not — a control plane
  //              ahead of a cached bundle. TypeScript cannot see that value; the lookup yields `undefined`,
  //              and an undefined badge renders NOTHING while `policy_degraded` is true.
  //
  // Losing it would make the client LESS ALARMED THAN THE BOOL for exactly the kind nobody has taught it
  // about yet, which is the one most likely to matter.
  return DEGRADED_BADGE[kind] ?? GENERIC_DEGRADED;
}

// SiteLinkNote — WF-B: the SUBORDINATE site-link line, INDEPENDENT of the headline badge
// (policyHealthBadge). A DEMOTED hub member whose link is dead WHILE org transit rides the active
// primary (healthy): the site's headline stays its real state and this names the demoted-dead peer as a
// distinct line ("site link down: aws-gw-1 (demoted)"). The `(demoted)` qualifier tells the operator
// "expected — this member was failed-over-past" vs a live peer's real outage. NEVER accompanies a
// `site_link_down` HEADLINE (the CP never sets the note then — the inverse-red guard).
export interface SiteLinkNote {
  peer: string;
  demoted: boolean;
}

export function siteLinkNote(
  node: Pick<Node, "site_link_note_peer" | "site_link_note_demoted">,
): SiteLinkNote | null {
  if (!node.site_link_note_peer) return null; // render-floor: the field it consumes, present ⇒ a note
  return {
    peer: node.site_link_note_peer,
    demoted: node.site_link_note_demoted ?? false,
  };
}

/**
 * ⛔ A PILL, NOT BARE TEXT — corrected S14.6, founder-caught, and it was product-wide.
 *
 * This returned COLOUR ONLY: `text-amber-400` / `text-rose-400`. So on every surface that renders health
 * beside other states, a DEGRADED gateway showed as bare coloured text while its `healthy` and `revoked`
 * siblings showed as bordered pills — one state styled as a different KIND of thing from the others.
 *
 * The name said badge and the function returned a colour. Four call sites inherited that, and the wireframe
 * badges every state uniformly (`HEALTHY`, `APPLY_FAILING`, `DESYNC_UNKNOWN`, `SITE_LINK_DOWN`,
 * `UNSUPPORTED_VER` are all pills).
 *
 * ⚠ FIXED IN THE HELPER RATHER THAN AT THE CALL SITE, deliberately: a fix at one call site does not reach
 * the call sites beside it — the missing-primitive law, which this repo has now paid for several times.
 * Matches `Badge`'s recipe so the two cannot drift.
 */
export function badgeClass(tone: BadgeTone): string {
  const colour: Record<BadgeTone, string> = {
    ok: "border-emerald-500/40 text-emerald-400",
    warn: "border-warn/40 text-warn",
    danger: "border-danger/40 text-danger",
    neutral: "border-white/10 text-slate-400",
    unknown: "border-white/10 text-slate-400",
  };
  return `inline-flex items-center rounded-full border px-2 py-0.5 text-micro ${colour[tone]}`;
}

/**
 * The gateway ROW verdict — label and tone together, for any list that shows one line per gateway.
 *
 * ⛔ THE PANEL WAS FORMING THIS ITSELF, AND THAT WAS THE LAST VERDICT OUTSIDE THIS MODULE. It read
 * `b ? b.label : "healthy"` — turning "no badge" into the CLAIM "healthy". Those are different things and
 * they differ for exactly one reason: a revoked gateway has no verdict at all, and calling that healthy is
 * how a decommissioned machine ended up green on the deployed dashboard.
 *
 * Widening `policyHealthBadge` to require `status` stopped it returning a WRONG verdict. It could not stop a
 * caller INVENTING one from the absence — only moving the decision here does that.
 */
export function gatewayHealthRow(
  node: Pick<Node, "status" | "policy_degraded" | "policy_degraded_kind">,
): { label: string; tone: "ok" | "warn" | "danger" | "neutral" } {
  if (node.status === "revoked") return { label: "revoked", tone: "neutral" };
  const b = policyHealthBadge(node);
  if (!b) return { label: "healthy", tone: "ok" };
  return { label: b.label, tone: b.tone === "unknown" ? "neutral" : b.tone };
}

/**
 * The attribution badge — S15.2 / D25(C): **degrade, do not refuse.**
 *
 * ⛔ SEPARATE FROM `gatewayHealthRow`, AND NOT FOLDED INTO IT. Policy health answers *is this gateway
 * enforcing what the control plane believes it is enforcing*. Attribution answers *can we say who
 * authorised it into the org*. **A gateway can be perfectly healthy and unattributable at the same time**,
 * and collapsing the two into one badge would force a choice between reporting an enforcement problem and
 * reporting an accountability one.
 *
 * ⚠ TONE IS `warn`, NOT `danger`, AND THE DISTINCTION IS THE RULING. An unattributable tunnel is a LOGGING
 * failure, not an access-control one — the policy engine still enforces every rule. Painting it red would
 * claim a security failure that has not occurred, and this repo has already paid for a badge that alarmed
 * less than the bool beside it; alarming MORE than the truth is the same defect facing the other way.
 */
export function attributionBadge(
  node: Pick<Node, "unattributable">,
): { label: string; tone: "warn"; detail: string } | null {
  if (!node.unattributable) return null;
  return {
    label: "unattributable",
    tone: "warn",
    detail:
      "No owner is recorded for this gateway, so its activity cannot be attributed to a person. It keeps running and enforcing policy — this is a gap in the audit trail, not in access control.",
  };
}
