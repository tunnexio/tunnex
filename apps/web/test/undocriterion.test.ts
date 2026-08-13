import { describe, expect, it } from "vitest";
import {
  UNDOABLE_ACTIONS,
  NOT_UNDOABLE,
  isUndoable,
  inverseOf,
} from "../src/lib/undo";

// S14.3 SLICE B — THE UNDO CRITERION, ASSERTED RATHER THAN REMEMBERED.
//
// THE DECIDE-ITEM: "an undo on a destructive verb that the server already committed is a lie." The answer was
// MEASURED, not argued — 16 DELETE paths, 51 audit actions at call sites, 9 inverse-verb pairs — and reduced
// to a criterion with two conditions:
//
//   1. an inverse operation exists in the API, AND
//   2. it returns the SAME OBJECT IDENTITY to its prior state.
//
// The list is data and asserted for the same reason the `ok` colour reservation is: a criterion that lives
// only in prose gets widened by whoever builds the next screen, in good faith, one plausible case at a time.

describe("the criterion: an inverse verb is NOT sufficient", () => {
  it("every undoable action is a STATE TOGGLE, never a create/delete pair", () => {
    // `policy.rule_created` ↔ `policy.rule_deleted` IS an inverse pair in the audit vocabulary — and
    // re-creating a deleted rule produces a NEW rule id. A different object, audited as a creation. On an
    // access-control surface, "a new grant that looks like the old one" is not "the old one back".
    for (const a of UNDOABLE_ACTIONS) {
      expect(
        a.action,
        `${a.action} looks like a creation/deletion`,
      ).not.toMatch(/_created$|_deleted$|_issued$|_revoked$/);
    }
  });

  it("every undoable action records WHY identity is preserved — a claim a reader can check", () => {
    for (const a of UNDOABLE_ACTIONS) {
      expect(a.sameIdentity.length, a.action).toBeGreaterThan(20);
    }
  });

  it("the inverse of an undoable action is itself known", () => {
    for (const a of UNDOABLE_ACTIONS)
      expect(inverseOf(a.action)).toBe(a.inverse);
  });

  it("no action is BOTH undoable and excluded — the two lists cannot contradict each other", () => {
    const un = new Set(UNDOABLE_ACTIONS.map((a) => a.action));
    const overlap = NOT_UNDOABLE.filter((n) => un.has(n.action)).map(
      (n) => n.action,
    );
    expect(
      overlap,
      `both undoable and excluded: ${overlap.join(", ")}`,
    ).toEqual([]);
  });
});

describe("the EXCLUSIONS, asserted so the criterion cannot be quietly widened", () => {
  // These are the cases someone will be tempted by. Each is named with its reason in the source, so a future
  // author has to ARGUE with a recorded rationale rather than fill a silence.
  const mustBeExcluded = [
    "policy.rule_created",
    "resource.created",
    "group.created",
    "machine.credential_issued",
    "device.revoked",
    "org.deleted",
    "group.member_added",
    "group.member_removed",
  ];
  for (const a of mustBeExcluded) {
    it(`${a} offers NO undo`, () => expect(isUndoable(a)).toBe(false));
  }

  it("every exclusion states a reason", () => {
    for (const n of NOT_UNDOABLE)
      expect(n.why.length, n.action).toBeGreaterThan(20);
  });

  it("the IdP-sync exclusion is recorded in the terms that make it different from the others", () => {
    // The sharper half of the ruling, and a DIFFERENT reason from all the rest: membership in a synced group
    // CAN be restored — the identity survives. It is excluded because the fail-static reconciler is
    // AUTHORITATIVE and would revert it. AN UNDO THE SYSTEM WILL FIGHT IS WORSE THAN NO UNDO: the user sees a
    // success, watches it disappear, and learns the interface cannot be trusted about what it just confirmed.
    const m = NOT_UNDOABLE.find((n) => n.action === "group.member_added")!;
    expect(m.why).toMatch(/fail-static|authoritative/i);
    expect(m.why).toMatch(/revert/i);
  });
});

describe("isUndoable is the gate, and it is not empty", () => {
  it("recognises the measured toggles", () => {
    expect(isUndoable("policy.rule_disabled")).toBe(true);
    expect(isUndoable("org.zero_trust_disabled")).toBe(true);
  });

  it("refuses an action it has never heard of — the default is NO", () => {
    expect(isUndoable("something.invented")).toBe(false);
  });

  it("the allow-list is non-trivial and the exclusion list is non-trivial", () => {
    // Vacuity guard both ways: an empty allow-list would make every "offers no undo" assertion pass for the
    // wrong reason, and an empty exclusion list would make the reason assertions vacuous.
    expect(UNDOABLE_ACTIONS.length).toBeGreaterThanOrEqual(6);
    expect(NOT_UNDOABLE.length).toBeGreaterThanOrEqual(6);
  });
});
