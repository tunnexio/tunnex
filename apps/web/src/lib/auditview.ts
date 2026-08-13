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
  "Some events were written without an actor. That is a gap in how we record them, not evidence that nobody acted — these are system-initiated events whose writer did not name itself.";

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
