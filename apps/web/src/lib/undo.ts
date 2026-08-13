// S14.3 SLICE B — WHAT MAY CARRY AN UNDO, AS DATA.
//
// THE DECIDE-ITEM, IN THE FOUNDER'S WORDS: "an undo on a destructive verb that the server already committed is
// a lie." So the question was made MEASURABLE rather than argued: for which actions can the server return the
// SAME OBJECT to its PRIOR STATE?
//
// MEASURED FROM THE PRODUCT, not from taste: 16 `DELETE` paths in openapi.yaml, 51 audit actions at call
// sites, 9 inverse-verb pairs in the audit vocabulary.
//
// ⛔ AN INVERSE VERB EXISTING IS NOT SUFFICIENT, and this is the sharp part. `policy.rule_created` and
// `policy.rule_deleted` are a pair — but RE-CREATING A DELETED RULE PRODUCES A NEW RULE ID. That is a
// different object, audited as a creation. It is not an undo; it is A NEW GRANT THAT HAPPENS TO LOOK LIKE THE
// OLD ONE, and on an access-control surface those are not the same thing.
//
//   THE CRITERION — BOTH CONDITIONS REQUIRED:
//     1. an inverse operation exists in the API, AND
//     2. it returns the SAME OBJECT IDENTITY to its prior state.
//
// EVERYTHING ELSE GETS A CONFIRM, NEVER AN UNDO. Where an act cannot be reversed the honest affordance is
// BEFORE, not after — a second chance that does not exist is worse than no second chance, because the user
// stops being careful.

/** An action a toast may offer to reverse. Keyed by the AUDIT ACTION the original act emits. */
export interface UndoableAction {
  /** The audit action of the ORIGINAL act. */
  action: string;
  /** The audit action the undo itself emits — its own act, with its own actor and timestamp. */
  inverse: string;
  /** Why the identity is preserved. Recorded so a future reader can check the claim rather than trust it. */
  sameIdentity: string;
}

/**
 * THE ALLOW-LIST. Six actions, every one a STATE TOGGLE on an object that keeps its identity.
 *
 * It is data, and asserted, for the same reason the `ok` colour reservation is: a criterion that lives only in
 * prose gets widened by whoever builds the next screen, in good faith, one plausible case at a time.
 */
export const UNDOABLE_ACTIONS: UndoableAction[] = [
  {
    action: "policy.rule_disabled",
    inverse: "policy.rule_enabled",
    sameIdentity:
      "PATCH /policies/{ruleId} — the same ruleId is re-enabled; no row is created",
  },
  {
    action: "policy.rule_enabled",
    inverse: "policy.rule_disabled",
    sameIdentity: "PATCH /policies/{ruleId} — same ruleId",
  },
  {
    action: "org.zero_trust_enabled",
    inverse: "org.zero_trust_disabled",
    sameIdentity: "org setting on the same org row",
  },
  {
    action: "org.zero_trust_disabled",
    inverse: "org.zero_trust_enabled",
    sameIdentity: "org setting on the same org row",
  },
  {
    action: "org.device_approval_enabled",
    inverse: "org.device_approval_disabled",
    sameIdentity: "org setting on the same org row",
  },
  {
    action: "org.device_approval_disabled",
    inverse: "org.device_approval_enabled",
    sameIdentity: "org setting on the same org row",
  },
];

/**
 * EXCLUDED, WITH THE REASON — kept in the source so the criterion can be CHECKED rather than re-derived.
 *
 * An absent entry proves nothing; an entry that names its reason can be argued with.
 */
export const NOT_UNDOABLE: Array<{ action: string; why: string }> = [
  {
    action: "policy.rule_created",
    why: "re-creating yields a NEW rule id — a new grant, not the old one back",
  },
  { action: "resource.created", why: "re-creating yields a NEW resource id" },
  { action: "group.created", why: "re-creating yields a NEW group id" },
  {
    action: "machine.credential_issued",
    why: "re-issuing mints a NEW secret; the old one is gone",
  },
  {
    action: "device.revoked",
    why: "revocation is a FULL SWEEP — peer slot, pool address and telemetry",
  },
  { action: "org.deleted", why: "no inverse exists at all" },
  {
    action: "group.member_added",
    // The second, different reason — and the sharper half of the ruling.
    why:
      "for an IdP-SYNCED group the reconciler is fail-static and AUTHORITATIVE, so an undo would be REVERTED " +
      "by the next sync. AN UNDO THE SYSTEM WILL FIGHT IS WORSE THAN NO UNDO: the user sees a success, then " +
      "watches it disappear, and learns the interface cannot be trusted about the thing it just confirmed.",
  },
  {
    action: "group.member_removed",
    why: "same — the sync reconciler is authoritative for synced groups",
  },
];

/** May this action carry an undo? The allow-list is the criterion; membership is not a judgement call. */
export function isUndoable(action: string): boolean {
  return UNDOABLE_ACTIONS.some((a) => a.action === action);
}

export function inverseOf(action: string): string | undefined {
  return UNDOABLE_ACTIONS.find((a) => a.action === action)?.inverse;
}
