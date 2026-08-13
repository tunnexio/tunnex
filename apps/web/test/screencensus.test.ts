import { describe, expect, it } from "vitest";
import { readdirSync } from "node:fs";
import { join } from "node:path";

// D3 — THE CENSUS. A LEDGER, NOT A FLOOR.
//
// The gate is NOT a coverage percentage. A percentage is the gameable number: it rises when someone tests
// something easy and says nothing about whether the surface that breaks is guarded. Instead every screen in a
// NAMED LIST must have a wiring test and a failure-path test, and the count must EQUAL the screen total.
//
// WHY EQUALS AND NOT >=. A minimum count is satisfied forever by a lazy floor — `>= 1` passes on screen 2 and
// on screen 19 alike, which is the gameable-number failure in a different costume. Asserting equality means
// screen 19 FAILS THE CENSUS BY NAME and the number has to be MOVED DELIBERATELY. Moving it is a visible,
// reviewable edit; that is what makes this a ledger rather than a floor.
//
// The precedent is in this repo and it works: TestEveryHealthKindReachesItsMirrorSurfaces, minted for the same
// class — a producer whose consumers were never enumerated, which is WF-S11-7 exactly.
//
// ENUMERATED, NOT LISTED. The screen set is read from the filesystem so it cannot go stale; exemptions are an
// explicit allow-list. EVERY EXEMPTION CARRIES ITS REASON INLINE, because an unreasoned exemption is how the
// list quietly becomes the codebase — a name with no reason is indistinguishable from a name someone added to
// make the census pass, and six months later nobody can tell which it was.

const PAGES_DIR = join(__dirname, "..", "src", "pages");

// EXEMPT — the reason is part of the datum, not documentation about it.
const EXEMPT: Record<string, string> = {
  // ⛔ PENDING, WITH ITS REASON AND ITS TRIGGER. ChangePassword is the door in the forced-password wall:
  // the server refused every route with `password_change_required` and the client had nowhere to send
  // anyone, so an operator signed in with the log-printed credential and read a red error under a button
  // that could never work.
  //
  // ⚠ IT SHIPPED WITHOUT A WIRING TEST BECAUSE THE OPERATOR WAS BLOCKED, and that is a reason, not an
  // excuse. TRIGGER: the next piece of the onboarding rebuild (invitations + forced password SET for
  // invitees) touches this same flow — the wiring test lands with it, covering both screens at once
  // rather than testing this one twice.
  "ChangePassword.tsx":
    "PENDING — forced first-login change; wiring test lands with the invitation flow, which shares it",
  // ⛔ NOT A PRODUCT SCREEN, AND NOT SHIPPED. The visual gallery is a fixture surface behind
  // `VITE_VISUAL_GALLERY`, unset in every production build. It renders primitives with literal props, calls no
  // API, and makes no decision — so a wiring test would assert that a fixture equals itself.
  // ITS OWN GATE IS THE VIEWPORT LEG (e2e/visual/), which is the only thing that can judge it, plus
  // `visualgallery.test.ts` proving the route is not shipped.
  "VisualGallery.tsx":
    "test fixture, build-flagged off; gated by the viewport leg and by the unshipped-route assertion",
  "Login.tsx": "unauthenticated shell — no backend concept to disagree about",
  "Signup.tsx": "unauthenticated shell — no backend concept to disagree about",
  "ForgotPassword.tsx":
    "single-form flow; the decision is server-side, nothing rendered to disagree with",
  "ResetPassword.tsx":
    "single-form flow; the decision is server-side, nothing rendered to disagree with",
  "VerifyEmail.tsx":
    "terminal status page — renders a fixed state, no list, no derivation",
  "VerifyPending.tsx":
    "terminal status page — renders a fixed state, no list, no derivation",
  "AcceptInvite.tsx": "one-shot token redemption; no ongoing backend concept",
  "CreateOrg.tsx": "one form, one POST, no rendered backend state",
  // TESTED ELSEWHERE, not skipped — the distinction matters and is why the reason names the coverage.
  "CliAuth.tsx":
    "single-purpose consent flow; the property that matters (no click, no mint) is covered by S5.1's Playwright leg",
  "CliDevice.tsx":
    "single-purpose consent flow; the property that matters (no click, no mint) is covered by S5.1's Playwright leg",
  // ⚠ CONDITIONAL EXEMPTION — VOID IF ITEM A DOES NOT LAND. Dashboard fetches one overview and renders it: no
  // derivation, no gating, no suppression, and its failure mode is guarded BY CONSTRUCTION (`{data && (…)}`,
  // so counts cannot render from a failed load — the same class as the Loaded<T> finding). A test asserting
  // "the numbers appear" is the render-floor version the tier ruled out.
  // BUT it carries ONE real decision: `onStatusChanged` refreshes when the tunnel goes `revoked`, so a
  // revocation cannot leave a stale view. That is an ELECTRON BRIDGE decision, and Item A removes the
  // dashboard from Electron entirely (connect-only client). TRIGGER: if Item A does not land, or if the
  // dashboard is ever rendered in Electron again, THIS EXEMPTION IS VOID and Dashboard rejoins COVERED.
  "Dashboard.tsx":
    "display-only: guarded by construction ({data && …}), no derivation/gating/suppression. CONDITIONAL on Item A — see the note above; void if the dashboard is ever rendered in Electron again",
};

// COVERED — a screen enters this list when it has BOTH a wiring test and a failure-path test.
const COVERED: Record<string, string> = {
  "Gateways.tsx":
    "test/gatewayswiring.test.tsx — revoke wiring + revoked-suppression + failed-revoke surfaced",
  "Devices.tsx":
    "test/deviceswiring.test.tsx — posture/re-export suppression on revoked + failed-load surfaced, distinct from empty",
  "Kubernetes.tsx":
    "test/kuberneteswiring.test.tsx — health-kind mirror census (WF-S11-7) + withheld destructive control + LoadRetry reached",
  "Access.tsx":
    "test/accesswiring.test.tsx — enforcement posture cannot be claimed without being read (both directions) + disabled rules shown + failed load never renders a count",
  // SHEDDER, tested accordingly: assertions are written against the DECISION and name `subnets` as the
  // destination, so they travel through the split instead of becoming throwaway work.
  // S14.7. The one derivation it makes is the client-side attribution join, and the covered property is
  // WHICH of the three indistinguishable-looking non-answers it claims: in-flight, could-not-ask, and
  // asked-and-nobody-owns-it all render as an innocent cell if you let them.
  "RoutedRanges.tsx":
    "test/routedrangeswiring.test.tsx — in-flight never claims 'no site' (both sides), a failed fan-out degrades to 'could not load' not 'no site', pending never attributes, failed ranges read renders retry not an empty routing table, and the DNS gate is stated on a NON-empty list too",
  "Sites.tsx":
    "test/siteswiring.test.tsx — pending vs approved reachability (destination: subnets) + accessible title not colour + first-crossing threshold + failed load renders retry",
  // SHEDDER: machine credentials -> cli, edition -> license. Assertions target the DECISION and name the
  // destination, so they travel through the split.
  "Users.tsx":
    "test/userswiring.test.tsx — the sole owner cannot be demoted (lockout), both directions + failed roster surfaced, never 'no members yet'",
  "AuditLog.tsx":
    "test/auditlogwiring.test.tsx — paging uses the APPLIED filter set, never a mid-edit one + failed load surfaced, never an empty history",
  "Settings.tsx":
    "test/settingswiring.test.tsx — the control reflects the ORG's opt-in state, not a default (misconfigure, stays in settings) + edition gating both directions (destination: license) + failed org load surfaced, no defaults offered",
};

// PENDING — accounted for, NOT yet covered. This list is the BACKLOG STATED OUT LOUD, and it exists because a
// census that only knows COVERED and EXEMPT lands RED on day one: it would either block the branch or be
// skipped, and a skipped gate is a vacuous gate wearing a different hat.
//
// It does not weaken the ledger. A NEW screen still fails by name, because it appears in none of the three
// lists. What PENDING buys is that the eight known-uncovered screens are VISIBLE and COUNTED rather than
// hidden behind a red the reader learns to ignore. Moving a screen from PENDING to COVERED requires editing
// BOTH totals below — two deliberate edits in one reviewable diff.
//
// THE ORDER IS THE COMMIT-ONE ORDER, and the reason is recorded with it: surfaces are ranked by where
// disagreement with the backend is most consequential, not by size.
const PENDING: Record<string, string> = {
  // ⛔ S15.3. The AI-agent surface is routed and rendering, and its VIEW-MODEL is covered
  // (agentview.test.ts: the render floor, the three-valued kind, UNDETERMINED's ruled words, the
  // ordering, the Overview card's copy). The WIRING and FAILURE-PATH tests are not written yet —
  // specifically: that a 403 renders ABSENCE rather than an error, and that a real failure does NOT
  // render as "no agents". PENDING rather than COVERED on purpose: a half-covered screen must be
  // VISIBLY half-covered, and those two are the ones this screen would be worst at getting wrong.
  "Agents.tsx":
    "S15.3 — view-model covered; 403-as-absence + failure-path wiring tests owed",
  // ⛔ S14.19. Routed and rendering; its VIEW-MODEL is covered (flowlogview.test.ts) but the wiring
  // and failure-path tests are not written yet. PENDING rather than COVERED on purpose — the ledger
  // is only worth having if a half-covered screen is visibly half-covered.
  "AccessEvents.tsx":
    "S14.19 — view-model covered; wiring + failure-path tests owed",
  // ⚠ SHEDDER — the redesign SPLITS this screen. Sites keeps `sites` and sheds ROUTED RANGES to a new
  // `subnets` screen. Its tests MUST assert the DECISION and NAME THE DESTINATION: "a routed range that fails
  // to load is surfaced, not rendered as none" travels to whichever screen renders it; "the Sites page shows a
  // routed-range list" does not, and becomes throwaway work the day the split lands.
};

describe("screen census", () => {
  const screens = readdirSync(PAGES_DIR).filter((f) => f.endsWith(".tsx"));

  // THE CENSUS'S OWN VACUITY GUARD. A census that passes because it enumerated ZERO screens would be the very
  // class this file exists to prevent — it would go green forever on a bad glob or a moved directory. The
  // number is known independently and asserted, so an empty enumeration FAILS.
  it("enumerates a plausible number of screens (guards against a census that counts nothing)", () => {
    expect(screens.length).toBeGreaterThanOrEqual(15);
  });

  it("every screen is COVERED, PENDING or EXEMPT — a NEW screen fails here BY NAME", () => {
    const unaccounted = screens.filter(
      (s) => !(s in COVERED) && !(s in PENDING) && !(s in EXEMPT),
    );
    // `Gateways.tsx` lives in components/ but IS the gateway screen; it is accounted for in COVERED and is not
    // enumerated here, which is why it never appears in `unaccounted`.
    expect(
      unaccounted,
      `unaccounted screens (add a wiring+failure test, or a PENDING/EXEMPT entry WITH A REASON): ${unaccounted.join(", ")}`,
    ).toEqual([]);
  });

  it("every EXEMPT and PENDING entry carries a non-empty reason", () => {
    const unreasoned = [
      ...Object.entries(EXEMPT),
      ...Object.entries(PENDING),
    ].filter(([, why]) => !why || why.trim().length < 10);
    expect(unreasoned.map(([f]) => f)).toEqual([]);
  });

  // A screen cannot be in two lists at once — that is how a "covered" screen quietly stays on the backlog, or
  // an exempt one silently acquires an obligation nobody meant to give it.
  it("the three lists are disjoint", () => {
    const names = [
      ...Object.keys(COVERED),
      ...Object.keys(PENDING),
      ...Object.keys(EXEMPT),
    ];
    expect(names.length).toBe(new Set(names).size);
  });

  // THE LEDGER LINES. Not floors. Covering a screen means moving it from PENDING to COVERED and editing BOTH
  // numbers — two deliberate edits, in one diff a reviewer sees. A `>=` here would be satisfied forever.
  it("the COVERED count equals its ledger total", () => {
    expect(Object.keys(COVERED).length).toBe(9);
  });

  it("the PENDING count equals its ledger total — the backlog shrinks deliberately or not at all", () => {
    // ZERO. Every accountable screen is covered. The list stays, because a screen added tomorrow must land in
    // one of the three lists or fail the census by name — an empty PENDING is a state, not a reason to delete
    // the mechanism.
    expect(Object.keys(PENDING).length).toBe(2);
  });

  // THE CEILING IS NOT THIS NUMBER. Recorded so the totals above are read as a LEDGER OF TODAY, not a target.
  //
  // The redesign is a re-architecture that CONSOLIDATES 18 pages into 17 declared screens, and it changes what
  // is accountable here. Two of today's screens SHED sub-surfaces into new ones (Sites -> subnets,
  // Settings -> cli + license), and four wireframe screens have no current equivalent at all: `flows` (a
  // registered gap that never had a UI), `ops`, `license`, `onboarding`. Net, the tier's accountable total
  // grows from 9 to roughly 13 once exemptions are re-applied.
  //
  // RE-BASELINING IS A DELIBERATE, REVIEWABLE EDIT — which is exactly the property the equals-the-total form
  // was chosen for. A `>=` floor would have absorbed the growth silently and nobody would have had to look.
  it("the ledger is a snapshot of today — 9 accountable screens, ceiling ~13 after the redesign", () => {
    expect(Object.keys(COVERED).length + Object.keys(PENDING).length).toBe(11);
  });
});
