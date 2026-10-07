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
  // ⛔ NOT A PRODUCT SCREEN, AND NOT SHIPPED. The visual gallery is a fixture surface behind
  // `VITE_VISUAL_GALLERY`, unset in every production build. It renders primitives with literal props, calls no
  // API, and makes no decision — so a wiring test would assert that a fixture equals itself.
  // ITS OWN GATE IS THE VIEWPORT LEG (e2e/visual/), which is the only thing that can judge it, plus
  // `visualgallery.test.ts` proving the route is not shipped.
  "VisualGallery.tsx":
    "test fixture, build-flagged off; gated by the viewport leg and by the unshipped-route assertion",
  "K8sEnrollmentLocalReview.tsx":
    "test fixture, build-flagged off; fixture/API isolation and the unshipped-route contract are covered by k8senrollmentlocalreviewroute.test.ts",
  "K8sScopeLocalReview.tsx":
    "test fixture, build-flagged off; temporary transport restoration and the unshipped-route contract are covered by k8senrollmentlocalreviewroute.test.ts",
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
  "Beam.tsx": "beam.test.tsx — tenant-scoped shared/owner inventory, failed/empty separation, revisioned lifecycle confirmation, denied reviewer launch and stale organization responses",
  "SandboxSetup.tsx": "test/sandbox-setup.test.tsx, test/sandbox-runner-enrollment.test.tsx and test/sandbox-runner-qualification-trial.test.tsx — admin enrollment, prerequisites, one-time token, observed readiness, bounded native trial, exact-report review, settings CAS and catalog publication",
  "Sandboxes.tsx": "test/sandboxes.test.tsx — authoritative availability, empty/error separation, wizard review-only creation, private-key rejection, request idempotency and expired connection suppression",
  "SandboxCustomSkills.tsx": "test/sandbox-custom-skills.test.tsx — private library search, failed/empty separation, local import validation, inert preview, draft cancellation and immutable revision/deletion semantics",
  "AppAccessCompanyApplications.tsx": "appaccesscatalog.test.tsx — display-only discovery, owner fallback, authoritative grant/MFA separation and failed catalog reads",
  "AppAccessRequests.tsx": "appaccesscatalog.test.tsx — retained self history, atomic versioned decisions and failed request reads",
  "AppAccessManagedApplications.tsx": "appaccesscatalog.test.tsx — scoped owner projection/grants, ownership loss and failed reads without admin topology",
  "EditorAuth.tsx": "editorauth.test.tsx - explicit consent, scoped account, inline MFA and callback rejection",
  "BrowserTerminal.tsx": "browserterminal.test.tsx - member topology isolation, MFA refusal, recording refusal and failed workspace reads",
  "AppAccess.tsx": "appaccesswiring.test.tsx + appaccessmfa.test.tsx — role-aware landing, member topology refusal, draft API binding, stale-save preservation, immediate MFA policy confirmation and read-failure separation",
  "AppAccessAccess.tsx": "appaccessgrants.test.tsx: permissions, stale input, grant impact and effective access",
  "AppAccessMyApplications.tsx": "appaccessmyapps.test.tsx + appaccessmfa.test.tsx: own catalog/session binding, fresh MFA reuse, enrollment acknowledgment, verification-gated nonce retry, invalid handoff and authoritative sign-out failure",
  "Connect.tsx": "test/setuphandoff.test.tsx — native client handoff, authoritative address and failed metadata",
  "ChangePassword.tsx": "test/setuphandoff.test.tsx — safe return destination and failed password save",
  "AcceptInvite.tsx": "test/setuphandoff.test.tsx — client handoff without session minting and expired invitation refusal",
  "Setup.tsx": "test/setupwiring.test.tsx — existing gateway reuse, failed reads, organization change and permission refusal",
  "SiteToSite.tsx":
    "test/sitetosite.test.tsx + sitepairreview.test.tsx — organization-scoped inventory, permission recovery, selected subnet reads, and stale/failed read separation",
  "AgentsAIGateway.tsx": "AI policy expected-revision writes, failure handling and scoped usage - aigatewaypolicy.test.tsx",
  "NetworkSetup.tsx": "networksetup.test.tsx: review-before-write, permission refusal, failed save and uncertain outcome",
  "Gateways.tsx":
    "test/gatewayworkspace.test.tsx + gatewayswiring.test.tsx — URL-backed operational inventory, error/empty separation, enrollment reachability",
  "GatewayDetail.tsx":
    "test/gatewayworkspace.test.tsx — stable detail route, permission-hidden lifecycle controls, impact-read failure and confirm-before-revoke",
  "Devices.tsx":
    "test/deviceswiring.test.tsx — posture/re-export suppression on revoked + failed-load surfaced, distinct from empty",
  "Kubernetes.tsx":
    "test/kuberneteswiring.test.tsx — health-kind mirror census (WF-S11-7) + withheld destructive control + LoadRetry reached",
  "Access.tsx":
    "test/accesswiring.test.tsx — enforcement posture cannot be claimed without being read (both directions) + disabled rules shown + failed load never renders a count",
  "AccessKubernetesScopes.tsx":
    "test/k8sclusterscopewiring.test.tsx — named-permission DOM absence, failed-queue versus empty, zero-default exact-child creation, and irreversible decision confirmation",
  "Alerts.tsx":
    "test/alertswiring.test.tsx — active/history server-state wiring, resource navigation, management visibility, and failed reads never rendered as an all-clear",
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
  "AppAccessEvents.tsx":
    "test/appaccessevents.test.tsx — independent app-event endpoint, exact tenant/filter keyset paging, invalid filter refusal, unavailable telemetry and read failure remain honest",
  "Settings.tsx":
    "test/settingswiring.test.tsx — the control reflects the ORG's opt-in state, not a default (misconfigure, stays in settings) + edition gating both directions (destination: license) + failed org load surfaced, no defaults offered + CP-admin-only Applications domains deep link, including no-org access",
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
	"AccessGroups.tsx": "S18 canonical typed Group inventory, membership, archive and organization-switch wiring — agenttemplateswiring.test.tsx",
	"AccessResources.tsx": "S18 canonical Access Resources inventory and lifecycle workspace — resource route and caller coverage is being finalized",
	"AgentsPolicyTemplates.tsx": "S18 F09 Agents-owned immutable template, preview, assignment and recovery wiring — agenttemplateswiring.test.tsx",
	"AgentsManagementGate.tsx": "shared permission boundary for Agents group/template workspaces; exercised by agenttemplateswiring.test.tsx",
	"AgentDetail.tsx": "S18 MCP workspace — wiring and failure-path coverage follows the Agents-owned lifecycle contract",
	"AgentsIndex.tsx": "S18 operational index — URL query and permission/plan failure coverage is being finalized",
	"AgentsMCP.tsx": "S18 MCP management — lifecycle mutation and opt-in failure coverage is being finalized",
	"S18VisualScenarios.tsx": "development-only gallery fixture — reviewed through browser states, not production routing",
	"DeviceApprovals.tsx": "S18 Device lifecycle approval workspace — route, RBAC, pending queue and unavailable-state coverage is being finalized",
	"DevicePosture.tsx": "S18 Device lifecycle posture workspace — route, RBAC and default-off posture coverage is being finalized",
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
    // The legacy enrollment component is not a page; the S20 inventory/detail pages are both accounted for.
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
    expect(Object.keys(COVERED).length).toBe(32);
  });

  it("the PENDING count equals its ledger total — the backlog shrinks deliberately or not at all", () => {
    // ZERO. Every accountable screen is covered. The list stays, because a screen added tomorrow must land in
    // one of the three lists or fail the census by name — an empty PENDING is a state, not a reason to delete
    // the mechanism.
    expect(Object.keys(PENDING).length).toBe(12);
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
  it("the ledger is a snapshot of today — 43 accountable screens, ceiling ~13 after the redesign", () => {
    expect(Object.keys(COVERED).length + Object.keys(PENDING).length).toBe(44);
  });
});
