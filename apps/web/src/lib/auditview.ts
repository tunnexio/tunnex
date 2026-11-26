// Audit log — the actor, resolved honestly.
//
// ⛔ "system" MEANT TWO DIFFERENT THINGS ON THE SAME SCREEN.
//
// `AuditLog.tsx` rendered `a.actor_id ? actorName(members, a.actor_id) : "system"`. MEASURED
// across 100 served rows on the enterprise stack:
//
//   40 rows carry `actor_id`      -> a member's name          ✅
//   26 rows carry `actor_system`  -> rendered "system"        the NAME was discarded
//   34 rows carry NEITHER         -> rendered "system"        identical to the above
//
// So the same word answered *a named subsystem did this* and *nobody recorded who did this*, and
// **an attribution gap was invisible** — the fallback word for "unknown" was the word already in
// use for "known, and here is its name".
//
// The registered finding was "the Audit Log discards every named actor_system". True, and the
// smaller half. The larger half is what discarding it CONCEALS.

import type { Member } from "./api";
import { beamActionLabel } from "./beam";
import { k8sApiLabel, ruleCountPhrase } from "./k8sapiaccess";

export type AuditRow = {
  actor_id?: string | null;
  actor_system?: string | null;
  action: string;
  /** Event metadata. Carries the actor's identity when the roster cannot supply it (see below). */
  details?: Record<string, unknown> | null;
};

/**
 * Four arms, because the server can express four things and the screen could express two.
 *
 * `unattributed` is FIRST-CLASS and deliberately not folded into `system`: it is the state that
 * says *the server never recorded who did this*, which is a defect to be surfaced rather than a
 * category of actor. Four server actions currently land here — `hub_set.promotion`,
 * `hub_set.failback`, `hub_set.membership`, `node.enrolled` — all system-initiated, all using the
 * human insert path with a NULL actor instead of `InsertSystemAuditLog`. Registered separately;
 * this screen must not hide it while it is unfixed.
 */
export type ActorKind =
  | "human"
  | "system"
  | "unknown_human"
  | "unattributed"
  /**
   * ⛔ A FIFTH ARM, BECAUSE THE FOURTH WOULD HAVE LIED ABOUT A REAL PERSON.
   *
   * S12.11 gave deployment administrators the power to change a role in ANY organization. They are
   * typically a member of NONE of them — so their `actor_id` is not on the roster this screen
   * resolves against, and the existing arms would have rendered *"former member 019fc421"*: a
   * confident false claim about somebody who was never a member at all, attached to the one event
   * class an org's owners most need to read correctly.
   *
   * The row names them (`actor_email` + `actor_kind` in the metadata) precisely because the roster
   * cannot.
   */
  | "cp_admin";

export type ResolvedActor = {
  kind: ActorKind;
  label: string;
  /** True when the row cannot say who acted — rendered as a warning, not as metadata. */
  gap: boolean;
};

/**
 * ⛔ `rosterKnown` EXISTS BECAUSE "NOT ON THE ROSTER" AND "NO ROSTER" ARE DIFFERENT FACTS.
 *
 * With an empty roster every human actor resolved to *"former member 019fc421"* — a FALSE
 * STATEMENT ABOUT A PERSON, asserted confidently, about someone who may be a current member
 * sitting in the next room. The Overview feed hits this exactly: `/overview` serves `members` as a
 * COUNT, so the roster is a separate second-class read that can be slow or fail.
 *
 * A missing lookup table is OUR ignorance, not a fact about the actor. When the roster is not
 * known, a human reads as an unnamed human and nothing is claimed about their membership.
 */
export function resolveActor(
  row: AuditRow,
  members: Member[],
  rosterKnown = true,
): ResolvedActor {
  // ⛔ NAMED SYSTEM ACTOR FIRST. A row carrying `actor_system` is fully attributed — it is not a
  // fallback and must never render as the generic word.
  if (row.actor_system && row.actor_system.trim() !== "") {
    return { kind: "system", label: row.actor_system.trim(), gap: false };
  }
  // ⛔ BEFORE THE ROSTER LOOKUP, because the roster is the thing that cannot answer here. A
  // deployment administrator acting inside a tenant they do not belong to is FULLY attributed — the
  // row carries who they are — and must not be resolved by absence from a list they were never on.
  const kind = row.details?.["actor_kind"];
  if (kind === "cp_admin") {
    const email = row.details?.["actor_email"];
    const who = typeof email === "string" && email !== "" ? email : "unnamed";
    return { kind: "cp_admin", label: `${who} (deployment admin)`, gap: false };
  }
  if (row.actor_id && row.actor_id.trim() !== "") {
    const m = members.find((mm) => mm.user_id === row.actor_id);
    // A human who has left the roster is still ATTRIBUTED — we know who, we just cannot name
    // them. That is a different state from "nobody recorded it", so it keeps its own kind and
    // does NOT set `gap`.
    if (m) return { kind: "human", label: m.name || m.email, gap: false };
    return {
      kind: "unknown_human",
      // Says only what is true in each case. "former member" is a CLAIM — it is made only when we
      // actually looked at the roster and they were not on it.
      label: rosterKnown
        ? `former member ${row.actor_id.slice(0, 8)}`
        : `member ${row.actor_id.slice(0, 8)}`,
      gap: false,
    };
  }
  // ⛔ THE HONEST ANSWER, AND THE ONE THE OLD CODE HID.
  return { kind: "unattributed", label: "not recorded", gap: true };
}

/**
 * ⛔ THE SCREEN MUST NOT LAUNDER A SERVER DEFECT INTO A CATEGORY.
 *
 * "not recorded" reads as a property of the event; it is a property of OUR WRITE PATH. The note
 * says so, so that an operator reading an unattributed security-relevant row knows the gap is
 * ours and does not go looking for a person who was never recorded.
 */
export const UNATTRIBUTED_NOTE =
  "Some events were written without an actor. That is a gap in how we record them, not evidence that nobody acted, these are system-initiated events whose writer did not name itself.";

/** The known system actors, for the filter. Derived from rows, never hardcoded. */
export function systemActors(rows: AuditRow[]): string[] {
  const seen = new Set<string>();
  for (const r of rows) {
    if (r.actor_system && r.actor_system.trim() !== "")
      seen.add(r.actor_system.trim());
  }
  return [...seen].sort();
}

/** How many rows on this page cannot say who acted. Counted, never estimated. */
export function unattributedCount(rows: AuditRow[]): number {
  return rows.filter((r) => resolveActor(r, []).gap).length;
}

// ── what changed ─────────────────────────────────────────────────────────────────────────

type AuditChange = Pick<AuditRow, "action" | "details">;

function detailText(row: AuditChange, key: string): string | null {
  const value = row.details?.[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function detailCount(row: AuditChange, key: string): number | null {
  const value = row.details?.[key];
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

/** The action's last segment as words: "policy.rule_created" reads "Rule created". */
function actionWords(action: string): string {
  const leaf = action.split(".").at(-1) ?? action;
  const words = leaf.replace(/[_-]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// The rule actions that carry their destination in the metadata when it is a cluster's Kubernetes API.
const RULE_ACTIONS = new Set([
  "policy.rule_created",
  "policy.rule_deleted",
  "policy.rule_enabled",
  "policy.rule_disabled",
  "policy.grant_expired",
]);

/**
 * The destination a rule event names, when the row says it is a cluster's Kubernetes API (K8N-3).
 * Read from the row's own metadata, never looked up: the cluster may be gone by the time this is read.
 */
export function auditK8sApiDestination(row: AuditChange): string | null {
  if (!RULE_ACTIONS.has(row.action)) return null;
  const cluster = detailText(row, "dst_k8s_api_cluster");
  if (cluster) return k8sApiLabel(cluster);
  return row.details?.["dst_kind"] === "k8s_api" ? k8sApiLabel("a cluster whose name was not recorded") : null;
}

// ── Vault (VAULT-UX-1 V3) ─────────────────────────────────────────────────────────────────

const VAULT_ACTION_LABELS: Record<string, string> = {
  "vault.created": "Credential added",
  "vault.quick_created": "Password generated and saved",
  "vault.configured": "Credential details added",
  "vault.updated": "New secret version saved",
  "vault.details_changed": "Credential details changed",
  "vault.revealed": "Secret revealed",
  "vault.copied": "Secret copied",
  "vault.deleted": "Credential deleted",
  "vault.service_created": "Vault service added",
  "vault.personal_entries_purged": "Personal credentials removed with the membership",
};

/** Every Vault action, for the audit filter's suggestions. */
export const VAULT_AUDIT_ACTIONS = Object.keys(VAULT_ACTION_LABELS);

// VAULT-UX-2 W1: "family.*" in the Action filter is a whole action family, sent as action_prefix, so a
// family filter can never miss an action because it lives on another target type.
const ACTION_FAMILY = /^((?:[a-z][a-z0-9_]*\.)+)\*$/;
const FAMILY_LABELS: Record<string, string> = { "vault.": "All Vault activity", "beam.": "All Local Sharing activity" };
/** The Vault family filter, as the Action field shows it. */
export const VAULT_ACTION_FAMILY = "vault.*";
/** LS-UX-4 P26: every Local Sharing action, including policy, project and server changes on other target types. */
export const BEAM_ACTION_FAMILY = "beam.*";

/** The audit query for what the Action field holds: an exact action, or a family as action_prefix. */
export function auditActionQuery(action: string): { action?: string; action_prefix?: string } {
  const value = action.trim();
  if (!value) return {};
  const family = ACTION_FAMILY.exec(value);
  return family && family[1].length <= 64 ? { action_prefix: family[1] } : { action: value };
}

const VAULT_DETAIL_KEYS = new Set(["title", "service", "visibility", "kind", "version", "recipient", "recipient_kind", "recipient_from", "fields", "entries", "reason"]);

/** Vault evidence through an allowlist, like Local Sharing's: labels and counts only, never anything else. */
export function vaultAuditDetails(details: Record<string, unknown>): [string, string | number | boolean][] {
  const out: [string, string | number | boolean][] = [];
  for (const [key, value] of Object.entries(details)) {
    if (!VAULT_DETAIL_KEYS.has(key)) continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") out.push([key, value]);
    else if (Array.isArray(value) && value.every(item => typeof item === "string")) out.push([key, value.join(", ")]);
  }
  return out;
}

/**
 * An action as words where there is no event to read, such as the action filter's suggestions. It names
 * no cluster, because none is involved yet.
 */
export function auditActionLabel(action: string): string {
  const family = ACTION_FAMILY.exec(action);
  if (family) return FAMILY_LABELS[family[1]] ?? `All ${family[1].slice(0, -1)} activity`;
  if (VAULT_ACTION_LABELS[action]) return VAULT_ACTION_LABELS[action];
  if (action.startsWith("beam.")) return beamActionLabel(action);
  if (action === "k8s.api_access_enabled") return "Kubernetes API access turned on";
  if (action === "k8s.api_access_disabled") return "Kubernetes API access turned off";
  return actionWords(action);
}

/**
 * What changed, in words. Every action reads as its own last segment, as before; the two API access
 * actions name the cluster, and a rule event whose destination is a cluster's Kubernetes API says so.
 */
export function auditChangeLabel(row: AuditChange): string {
  if (row.action === "k8s.api_access_enabled" || row.action === "k8s.api_access_disabled") {
    const cluster = detailText(row, "cluster") ?? "a cluster whose name was not recorded";
    return `${auditActionLabel(row.action)} for ${cluster}`;
  }
  if (row.action.startsWith("vault.") && VAULT_ACTION_LABELS[row.action]) {
    // Assigned credentials carry their title; personal ones are recorded without one (VAULT-UX-1 V3).
    const title = detailText(row, "title");
    if (title) return `${VAULT_ACTION_LABELS[row.action]} · ${title}`;
    if (detailText(row, "visibility") === "personal") return `${VAULT_ACTION_LABELS[row.action]} · personal credential`;
    return VAULT_ACTION_LABELS[row.action];
  }
  const destination = auditK8sApiDestination(row);
  return destination ? `${actionWords(row.action)} · ${destination}` : actionWords(row.action);
}

/** One sentence of consequence for the detail view, from the recorded counts. null when there is none. */
export function auditChangeConsequence(row: AuditChange): string | null {
  if (row.action === "k8s.api_access_enabled") {
    const n = detailCount(row, "rules_taking_effect");
    if (n === null) return null;
    return n === 0 ? "No access rule named this cluster's API, so nobody could reach it yet."
      : `${ruleCountPhrase(n)} that already named this cluster's API took effect again.`;
  }
  if (row.action === "k8s.api_access_disabled") {
    const n = detailCount(row, "rules_kept");
    if (n === null) return null;
    return n === 0 ? "No access rule named this cluster's API."
      : `${ruleCountPhrase(n)} that named this cluster's API ${n === 1 ? "was" : "were"} kept and allow${n === 1 ? "s" : ""} nothing until API access is turned on again.`;
  }
  return null;
}
