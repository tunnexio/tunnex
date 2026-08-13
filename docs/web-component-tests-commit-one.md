# ⛔ HANDOFF — READ THIS BEFORE OPENING THE REDESIGN BRANCH

**The component test tier is COMPLETE and CI-GREEN. This section is the contract it hands forward.** Everything
below binds the redesign; the rest of this paper is how it was decided.

## CI GREEN AT `00a736d` (PR #44, 2026-08-01)

**Recorded with the sha and every job, because "gate green" without a sha is the class this project has already
ruled against** (`GATE-REPORT-NEEDS-SHA`).

| workflow | jobs | conclusion |
|---|---|---|
| **CI** | `gates` · `client (macos-latest)` · `client (windows-latest)` · `e2e` · `e2e-enterprise` | **all success** |
| **Security** | `gofmt + vet parity` · `govulncheck` ×5 (api·node·cli·helper·operator) · `CodeQL` ×2 (go·js-ts) · `Trivy` | **all success** |

**Re-earned by any further commit.** And note *why* the PR exists at all: `ci.yml` fires on `pull_request` only
(WF-S13-11), so a story branch has **no CI signal** until one is opened. `make web-gate` (typecheck + vitest + build — NOT Playwright; e2e runs in CI only) passing locally is
**not** the gate.

## ⚠ CORRECTION — AND THE CORRECTION IS THE SHA DISCIPLINE WORKING, NOT A NUMBER BEING AMENDED

**The table above is TRUE AT `00a736d` AND IS NOT TRUE AT THE BRANCH HEAD.** Commits landed afterward — the
wireframe artifact at `5b2f4f7` — and the plain `CodeQL` code-scanning aggregate **went red** on five alerts
raised against that file (1 high `js/xss-through-dom`, 4 medium `js/cross-window-information-leak`). It was
found while diagnosing the same red on the stacked PR #46.

**STATE THE POINT, NOT JUST THE NUMBER.** A claim of "CI green" with no sha would have been **unfalsifiable** —
it would have quietly meant "green at some moment", stayed on the page, and been read as a property of the
branch forever. **Because the claim was DATED, it was CHECKABLE, and it got checked.** The report did not decay
into a lie; it decayed into a *stale fact with a timestamp*, which is exactly what `GATE-REPORT-NEEDS-SHA` was
minted to produce.

**So this is not an erratum. It is the mechanism doing the one thing it exists to do.** The rule earns its
keep at the moment a green goes stale — and the only way to notice that moment is for the green to have carried
a sha in the first place.

**DISPOSITION:** founder-ruled — the wireframe was **renamed** to `.html.txt` (CodeQL classifies by extension),
not path-excluded and not dismissed. See `docs/UI-REDESIGN-registration.md`.

### RE-ASSERTED — CI GREEN AT `598f133` (2026-08-01)

**Every check on the PR passes, `CodeQL` aggregate included.** Verified by the alert list rather than the check
colour: `code-scanning/alerts?ref=refs/pull/44/merge&tool_name=CodeQL` returns **ZERO** where it previously
returned five. **The rename cleared it; the pre-committed fallback to per-alert dismissal was not needed.**

| workflow | jobs | conclusion |
|---|---|---|
| **CI** | `gates` · `client (macos-latest)` · `client (windows-latest)` · `e2e` · `e2e-enterprise` | **all pass** |
| **Security** | `gofmt + vet parity` · `govulncheck` ×5 · `CodeQL` ×2 blocking · **`CodeQL` aggregate** · `Trivy` ×2 | **all pass** |

**Re-earned by any further commit** — which is the whole point of the paragraph above.

## 1. THE FIVE QUERY RULES — the binding contract

1. **QUERY BY ROLE + ACCESSIBLE NAME.** Never test-ids, class names, or DOM structure. **A redesign that breaks
   these has broken accessibility too — a finding, not test debt.**
2. **MOCK AT THE NETWORK BOUNDARY** (`api.GET`/`api.POST`), never the component boundary. That layer does not
   change in a redesign.
3. **ASSERT DECISIONS, NOT RENDERING.**
4. **NO TEST MAY ASSUME A VIEWPORT** — no dependence on layout, column order, or width-conditional visibility.
   The responsive item introduces five widths.
5. **A `waitFor` MUST COVER EVERY ELEMENT THE ASSERTIONS TOUCH** — never the first that appears. *Two tests over
   the same elements disagreeing is the tell.*

**`getByText` is permitted ONLY for content carrying no role today, and every such use is a MARKER that the
element should gain `role="status"`/`role="alert"` in the redesign** — a finding-generator, not an exemption.

## 2. THE CENSUS — `COVERED 8 · EXEMPT 11 · PENDING 0`, accountable total **8**

`test/screencensus.test.ts`. **Enumerated from `src/pages/*.tsx`** so it cannot go stale; exemptions are an
explicit allow-list and **every one carries its reason inline** — an unreasoned exemption is how the list
quietly becomes the codebase.

**Asserted with `toBe`, never `>=`.** A floor is satisfied forever from screen 2 onward. **Equality means screen
19 fails the census BY NAME and the number must be MOVED DELIBERATELY** — a visible, reviewable edit. That is
what makes it a ledger rather than a floor.

**PENDING stays at zero rather than being deleted:** an empty backlog is a state, not a reason to remove the
mechanism.

## 3. THE CEILING — the number is a LEDGER OF TODAY, not a target

**~13 accountable screens after the redesign.** Six wireframe screens have no current equivalent:
`subnets` · `cli` (both extractions) · `flows` (a registered gap that never had a UI) · `ops` · `license` ·
`onboarding`. **Re-baselining the totals is a deliberate reviewable edit — the property the equals-the-total
form was chosen for.** A `>=` floor would have absorbed the growth silently.

## 4. THE SHEDDER CONSTRAINTS

| screen | keeps | sheds to |
|---|---|---|
| **`Sites.tsx`** | `sites` | **`subnets`** (routed ranges) |
| **`Settings.tsx`** | `settings` | **`cli`** (machine credentials) · **`license`** (edition) |

**Their tests assert the DECISION and NAME THE DESTINATION**, so they travel through the split.
*"A routed range that fails to load is surfaced, not rendered as none"* travels. *"The Sites page shows a
routed-range list"* does not.

## 5. ⛔ THE TIER'S PURPOSE — THE REDESIGN IS A REFACTOR UNDER A GREEN SUITE

**Perform the redesign with these tests PASSING THROUGHOUT. Do not rewrite them and re-test afterwards.**

The tier then proves the redesign **did not change BEHAVIOUR while changing everything else.**

> **A TEST THAT HAS TO BE REWRITTEN TO PASS IS A SIGNAL THAT THE REDESIGN CHANGED A DECISION** — either a bug,
> or a deliberate change that must be RECORDED. **It is not test debt.** Rewriting it destroys the only signal
> that says so.

**This inverts the tier's value:** it is not insurance against breakage. It is the instrument that makes a
re-architecture **reviewable at all.**

## 6. THE `Loaded<T>` CONTRACT — and what widening it costs silently

`src/lib/loadedcontract.ts` asserts at the type level that `Loaded<T>` discriminates, that the error branch
carries **no `data` key**, and that `data` is **required** on the success branch.

**`Loaded<T> = { ok: true; data: T } | { ok: false; error: string }` makes the `loadOne` law unwritable to
violate:** `.data` is unreachable without narrowing `.ok`, so the naive mutation produces a **compile error**,
not a wrong render.

**WIDENING IT TO `{ ok: boolean; data?: T; error?: string }` — the shape a hurried refactor reaches for because
it is easier to construct — CONVERTS A COMPILE-TIME GUARANTEE INTO A DISCIPLINE NOBODY AUDITS.** Nothing fails.
No test goes red. The guard simply stops existing, and its absence looks like ordinary code. **The redesign
touches every load path. Do not loosen it.** (The contract lives in `src/` deliberately: `tsconfig` now includes
`test`, but a contract placed there would once have been a check that cannot fail.)

## 7. TWO FINDINGS THIS BRANCH PRODUCED

| finding | status |
|---|---|
| **Sites revoked-badge** — `GatewayRow` rendered health badges on revoked rows; WF-S11-10's **third surface** | **FIXED**, under the branch's ONE named product exception. One line restoring a guard `Devices.tsx` already had |
| **SSO failed load** — `SsoConfig.load()` collapses **every** error to `setConfigured(false)`, so a transient 500 on an org that HAS SSO renders *"Configure"* with the config hidden and no failure shown | **REGISTERED, NOT FIXED. Ranked ABOVE the Sites finding.** It is **DESTRUCTIVE, not misinforming**: an admin who reconfigures from scratch against a live IdP may **overwrite a working SSO configuration**. `loadOne`'s sharpest instance — the law was minted for reassuring-empty **lists**; this is reassuring-empty **config on the auth surface**. Structurally present, unconfirmed on the wire. **The decision owed:** what the panel does on a non-404 failure |

---

# `story/web-component-tests` — COMMIT-ONE

**PAPER. NOTHING BUILT.** Branch cut from `main`, component test tier ONLY, no redesign.

**It is slice one of the UI redesign** (`docs/UI-REDESIGN-registration.md`, Item B decide-item 2: *the component
test tier lands FIRST or in the same story, never after*), pulled forward onto the EXISTING web app so the
redesign lands on a guarded surface rather than creating one.

**No conflict with EPIC 13:** this touches only `apps/web`, and specifically **not** `openapi/openapi.yaml`,
which is where S13.1's change lives. It cannot collide with a future redesign branch either — it adds test
files rather than changing components.

---

# TWO PREMISE CORRECTIONS, STATED BEFORE THE DECISIONS

## 1. THE RUNNER DECISION IS INHERITED, NOT OPEN

`apps/web/package.json` already carries **`vitest` + `@testing-library/react` + `jsdom`**, with a `test` script
already wired into the gate set (`pnpm --filter @tunnex/web test`, CLAUDE.md). **Commit-one does not choose a
runner. It inherits one.** Re-opening that choice would be work with no finding behind it.

## 2. "ZERO COMPONENT COVERAGE" WAS WRONG — IT IS ONE FOOTHOLD AND EIGHTEEN SCREENS

**The registration's wording was the founder's and it was imprecise; corrected here rather than carried
forward.** `apps/web/test/` holds **11 files, 190 tests, all passing**:

| tier | files | what they are |
|---|---|---|
| **pure view-model** | 10 | `nodepick` · `healthview` · `policyview` · `postureview` · `sitesview` · `hubsetview` · `k8sview` · `authroute` · `deviceexport` · `enrollcommand` |
| **component (renders)** | **1** | `devicespage.test.tsx` |

`src/pages/` holds **18 screens**. So the accurate statement is **one foothold and eighteen screens** — and the
foothold's own header already says it is *"the foothold for the registered component-test-tier ledger item, not
a retroactive suite for the whole app."*

**Why the distinction matters:** the pure tier is real coverage of the RULES. What is missing is coverage of
whether the screens USE them — which is exactly the gap the foothold was written to close.

---

# D1 — WHAT "COVERED" MEANS: **THE WIRING, PLUS THE FAILURE PATH**

## D1(a) — the wiring, not the rendering

**A screen is covered when a test asserts that the decision the USER GETS matches the rule the pure tier
tests.**

The argument is the foothold's own justification, quoted because it is the whole case:

> *"Slice 3 extracted `defaultDeviceNode` into `src/lib`, which made the RULE testable. But a pure test of the
> rule passes just as happily while the page still reads `nodes[0]` — nothing asserted that the component uses
> the fix. That is the vacuous-check trap one tier up: the guard tests the extracted decision, not the decision
> the user actually gets."*

**EXPLICITLY NOT COVERAGE:** snapshot tests · `expect(render(<X/>)).toBeTruthy()` · "renders without crashing".
**Those are the render-floor version of a vacuous check** — they cannot fail for the reason the surface actually
breaks, which puts them in `docs/laws.md`'s existing family rather than outside it.

**The shape, from the foothold:** fleet state in → assert the *outbound call* carries the right value. Given a
fleet whose oldest gateway is revoked, the POST that creates a device must carry the ACTIVE gateway's id.

## D1(b) — **AND ITS FAILURE PATH** (founder-added clause)

**A screen is also covered when its FAILURE path is asserted.**

**The `loadOne` law is web-specific, and its violation mode is a REASSURING EMPTY STATE** — a screen that
renders perfectly and tells the user nothing. A wiring test that only walks the happy path **misses the exact
defect class this surface produces.**

So each covered screen asserts **both**:

1. **wiring** — the right value reaches the outbound call
2. **failure** — a failed load renders the failed-load triad, **NOT an empty list that reads as "you have none"**

**This clause is what makes the tier worth gating.** Happy-path-only wiring tests would pass on a screen that
silently swallows every error, which is the defect the redesign is most likely to reintroduce while moving
components around.

---

# D2 — WHICH SCREENS FIRST: ORDERED BY **DISAGREEMENT WITH THE BACKEND**

## THE FOUR WEB-SIDE WALK FINDINGS — VERIFIED AGAINST `walk-artifacts/S11/walk-record.md`, NOT ASSUMED

The founder's expectation was recorded as *"to be VERIFIED not accepted."* Verified:

| finding | what it was | web-side? |
|---|---|---|
| **WF-S11-7** | an **unrendered health kind** — a producer with no consumer. Cited across `docs/S13.1-decisions.md` as the canonical *"a surface added without censusing its consumers"* instance | **YES** — the UI never rendered a kind the backend emitted |
| **WF-S11-9** | *"gateway revoke exists in the API and never existed in the UI"* — fold landed in `apps/web/src/components/Gateways.tsx` | **YES** |
| **WF-S11-10** | a **revoked** gateway badged *"certificate expired — re-enroll this gateway"*. Root: `Gateways.tsx` **never suppressed health badges for revoked rows the way `Devices.tsx` always has** (`d.status !== "revoked" && …`) | **YES** — two web components disagreeing with each other |
| **WF-S11-10b** | the label was fixed, the **presence** was not: kinds summed to **4 on a fleet of 3**, because `FleetHealthCounts` walks `ListNodes` (`SELECT * FROM nodes WHERE org_id = $1`, no `revoked_at` filter) while *preflight's* query does filter | **YES** — the UI counted rows the backend did not consider live |

**The founder's expectation was correct on all four.**

## WHAT THEY SHARE — and it drives the order

**None of these is a rendering bug. Every one is a surface DISAGREEING WITH THE BACKEND about what exists or
what counts.**

- WF-S11-7 — the backend says a kind exists; the UI does not know it
- WF-S11-9 — the backend offers an action; the UI does not
- WF-S11-10 — one component thinks revoked rows count; its sibling does not
- WF-S11-10b — the UI counts four things where three exist

**So the order is by WHERE DISAGREEMENT IS MOST CONSEQUENTIAL, not by screen size or traffic:**

| # | screen | why here |
|---|---|---|
| **1** | **Gateways** (within `Sites.tsx` / `Gateways.tsx`) | **three of the four findings landed here.** Revoked-vs-active is the disagreement axis, and it is the one that produced a *confident wrong instruction* to undo a security action |
| **2** | **Devices** | already has the foothold — **extend it to the failure path**, which it does not yet cover. Also the sibling that got revoked-suppression RIGHT, so it is the reference implementation for screen 1's rule |
| **3** | **Access** | policy rules disagreeing with the compiled artifact is the highest-consequence disagreement in the product: a rule shown as active but not compiled is a silent authorization gap |
| **4** | **Kubernetes** | WF-S11-7's own territory — the unrendered health kind. The census in D3 is what stops it recurring |

**Users / Audit / Settings and the rest follow, ordered the same way, at the paper's discretion.**

**ORDER ACCEPTED 2026-08-01 with its reasoning recorded:** Gateways first because **three of the four findings
landed there**; Devices second because it is **the sibling that got revoked-suppression RIGHT**, which makes it
screen 1's reference implementation — and D4's first sibling assertion is exactly that pair.

---

# D3 — GATING: **A CENSUS, NEVER A PERCENTAGE**

**A coverage percentage is the gameable number.** It rises when someone tests something easy and says nothing
about whether the surface that breaks is guarded.

**Instead: assert that EVERY SCREEN IN A NAMED LIST HAS A WIRING TEST AND A FAILURE-PATH TEST.**

**The precedent is in this repo and it works:** `TestEveryHealthKindReachesItsMirrorSurfaces` — the same census
shape, minted for the same class of defect (a producer whose consumers were never enumerated), which is
WF-S11-7 exactly.

```
screen 19 is added  →  the census fails BY NAME  →  nobody has to remember
```

**THE LIST IS THE ARTIFACT.** Adding a screen without a test is a **red**, not a lint warning and not a drop in
a number.

## ✅ D3(a) RULED — **ENUMERATE `src/pages/*.tsx` + A PRINTED ALLOW-LIST, AND EVERY EXEMPTION CARRIES A REASON**

Enumeration **cannot go stale**. The allow-list makes exemptions **visible**.

**EVERY ALLOW-LIST ENTRY CARRIES ITS REASON INLINE.** Not in a comment above the list, not in this paper — in
the entry itself, printed by the census when it runs.

```ts
// Shape, not final content. The REASON is part of the datum, not documentation about it.
const EXEMPT: Record<string, string> = {
  "Login.tsx":  "unauthenticated shell — no backend concept to disagree about",
  "Signup.tsx": "unauthenticated shell — no backend concept to disagree about",
  // …
}
```

**An unreasoned exemption is how the list quietly becomes the codebase.** A name with no reason is
indistinguishable from a name someone added to make the census pass, and six months later nobody can tell which
it was.

## ✅ D3(b) RULED — **THE COUNT MUST EQUAL THE SCREEN TOTAL. A LEDGER, NOT A FLOOR.**

**Rejected: `expect(covered).toBeGreaterThanOrEqual(1)`.** A minimum count is **satisfied forever by a lazy
floor** — it passes on screen 2 and on screen 19 alike, which is the gameable-number failure in a different
costume.

**Ruled: assert the covered count EQUALS the current screen total.**

```
screen 19 is added  →  the census fails BY NAME  →  the number must be MOVED DELIBERATELY
```

Moving the number is a visible, reviewable edit. **That is what makes it a ledger rather than a floor:** the
artifact records what is covered *now*, and growing it is an act, not a drift.

### THIS IS THE DETECTOR'S THIRD PROSPECTIVE APPLICATION — recorded as such

| # | instance | when caught |
|---|---|---|
| 1 | B2's 7-second poller vs a ~272ms window | **after** twelve green samples |
| 2 | `TestExpiryWhileRUNNING…` waiting on `issued` | **after** CI went red |
| 3 | the restore-window poller for an event `restore.go` cannot produce | **before** it was written |
| **4** | **this census, had it been written with a `>= 1` floor** | **before it was written** |

The question that catches all four is the same one: ***can this check fail for the reason it exists?*** A `>= 1`
floor cannot, from screen 2 onward.

---

# D4 — **SIBLING-CONSISTENCY**, from WF-S11-10's own shape (founder-added)

## THE GAP THE PER-SCREEN CENSUS CANNOT SEE, BY CONSTRUCTION

WF-S11-10's root was **`Gateways.tsx` never suppressing health badges for revoked rows THE WAY `Devices.tsx`
ALWAYS HAS** (`d.status !== "revoked" && …`).

**Two components disagreeing with each other about the same backend concept.**

**A per-screen wiring test passes on BOTH while they disagree.** Each screen is internally consistent; each
renders what it believes; neither test has any reason to mention the other. **The census counts two covered
screens and the defect survives** — which is the shared-territory version of the vacuous check.

## THE RULE

**For each backend concept rendered by MORE THAN ONE surface, one assertion that the surfaces AGREE.**

**Known instance: revoked-row suppression** — `Gateways.tsx` vs `Devices.tsx`.

**The paper must ENUMERATE the others before writing any of them.** Candidates to check, not to assume:
health-kind badging · online/liveness derivation · edition gating · the failed-load triad itself.

## SCOPE — CONCEPTS THAT ALREADY EXIST. DO NOT INVENT A FRAMEWORK.

**This is an enumeration of what is already rendered twice, not an abstraction layer for what might be.** If a
concept has one surface, it has no sibling test. If the enumeration finds only one genuine instance, **the
correct outcome is one assertion**, not a framework with one user.

---

# WHAT THE PAPER OWES BEFORE ANY CODE

1. **The named list**, with exemptions stated and justified.
2. **A worked example of each half** — one wiring test, one failure-path test — as the pattern the rest copy.
3. **The census's own red** — prove it fails when a screen is added without a test. **`scripts/mutate.sh` now
   has a working self-test and can enforce this** (it was dead on arrival until 2026-08-01; see `docs/laws.md`).
4. **The gate's placement** — the existing `pnpm --filter @tunnex/web test` already runs in CI, so the census
   rides an existing gate rather than adding one. **Confirm that is still true when the census lands.**

# WHAT THIS BRANCH DOES NOT DO

- **No redesign.** No new components, no token extraction, no visual change.
- **No `openapi/openapi.yaml` change.** That is S13.1's file until EPIC 13 merges.
- **No `apps/client` work.** Item A ruled the client gets its own components; its test tier is that story's
  problem, not this one's.

---

# NAMED EXCEPTION — THIS TESTS-ONLY BRANCH MAKES ONE PRODUCT FIX (founder-ruled 2026-08-01)

**Tests-only is the right default. This is the exception, and it is named so the branch cannot drift into a fix
branch without anyone noticing.**

**THE FIX:** `Sites.tsx`'s `GatewayRow` gains the revoked-suppression guard on the health badge —
`{g.status !== "revoked" && g.health && …}`.

**WHY IT BELONGS HERE:** this branch exists **because untested surfaces disagree with each other**, and this is
that disagreement sitting in the file. The fix is one guard; the test is D4's three-way assertion, **which was
already owed**. Splitting them means a second branch touching `Sites.tsx` for a one-line change.

**A SECOND CHANGE, DISCLOSED:** `GatewayRow` is now `export`ed. It is not a behaviour change — the assertion
has to reach the row, and a per-screen test cannot see a cross-surface disagreement by construction. Recorded
rather than slipped in.

**⛔ IF A SECOND PRODUCT FIX APPEARS, STOP AND ASK.** A tests-only branch making one named product fix is fine.
A tests-only branch that quietly becomes a fix branch is not.

## THE FINDING'S STATUS AND ITS SHAPE

**STRUCTURALLY PRESENT, UNCONFIRMED ON THE WIRE.** Not a sighting. `policyHealthBadge` keys only on
`policy_degraded` + kind, and neither `GatewayRow` nor `sitesview.ts` filtered revoked — so a revoked degraded
gateway would render *"revoked"* beside *"certificate expired — re-enroll this gateway"*. **§C's fleet would
confirm it for free if a revoked gateway there carries degraded health — but nothing waits for that.**

**THE SHAPE, which is the argument for D4 in one sentence: WF-S11-10 was fixed on ONE surface while a THIRD
rendered the same concept with the same defect — and it was found by asking WHO ELSE RENDERS THIS, not by
walking the UI.**

# THE CENSUS GAINED A THIRD LIST — PENDING — AND THE REASON IS A DEFECT IN THE FIRST DESIGN

**Running it revealed the flaw immediately:** a census that knows only COVERED and EXEMPT **lands RED on day
one**, naming all eight uncovered screens. It would then either block the branch or be skipped — **and a
skipped gate is a vacuous gate wearing a different hat.**

**PENDING is the backlog stated out loud.** It does not weaken the ledger:

- a **NEW** screen still fails **by name** — it is in none of the three lists
- the eight known-uncovered screens are **visible and counted**, not hidden behind a red the reader learns to ignore
- **both totals are asserted with `toBe`**, so covering a screen means moving it between lists **and editing two
  numbers** — one reviewable diff, no drift
- the lists are asserted **disjoint**, so a screen cannot be quietly covered and pending at once

**Proven to bite:** creating `src/pages/NewThing.tsx` fails the census by name; removing it restores green.

---

# CENSUS × WIREFRAME MAPPING — done BEFORE writing the next screen (founder-ruled 2026-08-01)

**The redesign is a RE-ARCHITECTURE that consolidates. A wiring test for a screen that gets absorbed is
throwaway work, so the mapping runs first.** Extracted from `docs/design/TUNNEX-wireframe-v2.html.txt` by
measurement — the nav is declared as `{ id, icon, label, admin }` objects and was read with a bounded `grep -o`,
never by loading the file into context.

## CORRECTION: THE WIREFRAME DECLARES **17** SCREENS, NOT 12

The "12 screens" figure is the MAIN NAV minus one. The declaration carries **13 main-nav entries** plus a
separate **`OTHER SCREENS`** group of four.

**Main nav:** `overview` · `gateways` · `sites` · **`subnets` (Routed Ranges)** · `access` · `devices` ·
`users` · `flows` (ENT) · `audit` · `cli` · `settings` · `k8s` (ENT) · `ops`
**OTHER SCREENS:** `auth` · `desktop` · `license` · `onboarding`

`subnets` was missing from the ruling's list of 12 and is a real main-nav screen.

## THE THREE BUCKETS — and the answer is better than feared

### ✅ SURVIVES AS ITSELF — write the test now, it carries through (7 of 9)

| census screen | wireframe id | |
|---|---|---|
| `Gateways.tsx` | `gateways` | **covered** |
| `Devices.tsx` | `devices` | **covered** |
| `Access.tsx` | `access` (Access Policies) | pending |
| `Kubernetes.tsx` | `k8s` (ENT) | pending |
| `Users.tsx` | `users` (Users & Roles) | pending |
| `AuditLog.tsx` | `audit` | pending |
| `Dashboard.tsx` | `overview` | pending |

### ⚠️ SURVIVES BUT SHEDS SUB-SURFACES — test the DECISION, name the destination (2 of 9)

| census screen | stays | splits out to |
|---|---|---|
| `Sites.tsx` | `sites` | **`subnets`** — routed ranges live inside `Sites.tsx` today and become their own screen |
| `Settings.tsx` | `settings` | **`cli`** (`MachineCredentials.tsx`, today rendered inside Settings) and **`license`** (Edition — no surface today) |

**Neither is absorbed. Both keep their identity and lose a section.** A test asserting a DECISION — *"a routed
range that fails to load is surfaced, not rendered as none"* — carries to whichever screen renders it. A test
asserting *"the Sites page shows a routed-range list"* would not. **Write the decision.**

### ❌ NO WIREFRAME EQUIVALENT — **none among the 9.** Nothing is dropped.

**No throwaway work exists in the current census.** The only current screens without a 1:1 wireframe entry are
the **EXEMPT** ones: the seven auth pages consolidate into `auth`, and `CreateOrg` into `onboarding`. **They are
exempt precisely because they carry no backend concept to disagree about**, so the consolidation costs the tier
nothing.

**One genuine flag:** `CliAuth.tsx` / `CliDevice.tsx` have **no wireframe equivalent** — the wireframe's `cli`
is *CLI Credentials* (an admin list), **not** the browser consent flow. **Assessment: not a finding against
either side.** Those routes are entered from the CLI, not from the dashboard nav, so a dashboard wireframe has
no reason to draw them. They remain exempt, covered by S5.1's Playwright no-click-no-mint leg.

## WIREFRAME SCREENS WITH NO CURRENT EQUIVALENT — the census's 9 is a SNAPSHOT, NOT A TARGET

| wireframe id | status today | note |
|---|---|---|
| **`subnets`** (Routed Ranges) | lives **inside** `Sites.tsx` | an extraction, not net-new |
| **`cli`** (CLI Credentials) | lives **inside** `Settings.tsx` (`MachineCredentials.tsx`) | an extraction, not net-new |
| **`flows`** (Access Events, ENT) | **no UI has ever existed** | one of the four REGISTERED GAPS the redesign closes (S7.5.1b) |
| **`ops`** (Operations) | **no surface at all** | net-new |
| **`license`** (Edition) | **no surface at all** | net-new; S12.1 territory, and decide-item 6's one-seam ruling binds it |
| **`onboarding`** | no surface | net-new |
| **`desktop`** (Desktop Client) | **not a dashboard screen** | Item A ruled the client CONNECT-ONLY with its own components; it is drawn here for reference only |

**So the tier's ceiling grows from 9 to ~13 accountable screens after the redesign.** The census must be
re-baselined at that point — its totals are a ledger of today, and the redesign is a deliberate, reviewable
edit to them.

## CONSEQUENCE FOR ORDERING — Access is NOT automatically next

**The founder's criterion: a screen that both survives intact AND carries more of the four findings outranks
one that survives intact and carries none.**

- **`Access.tsx`** — survives intact, carries **none of the four walk findings**. Its case is
  consequence-based: *a rule shown active but not compiled is a silent authorization gap.*
- **`Kubernetes.tsx`** — survives intact, and **carries WF-S11-7 itself** — the unrendered health kind
  (`k8s_endpoints_unavailable`), the canonical producer-without-consumer instance this repo cites everywhere.

**By the stated criterion, `Kubernetes` outranks `Access`.** Recommended, not assumed — the founder rules.


---

# ⛔ CORRECTION TO THE RECORD — SLICES 1-5 (2026-08-01)

**Every "green" reported for slices 1-5 before 2026-08-01 was LOCALLY TRUE AND GLOBALLY UNVERIFIED.**

`@testing-library/react` and `jsdom` were **never declared** in `apps/web/package.json` and **never in
`pnpm-lock.yaml`**. They resolved only from one machine's `node_modules`, installed while on the
`story/S13.1-gateway-recovery` branch. **On a clean checkout or a CI runner, none of those tests could have
run at all.**

**Do not read the earlier "217 tests green" reports as CI evidence.** They were `vitest` in a developer shell.

**DECLARED AND LOCKED 2026-08-01**, and verified by running the gate itself. Slices 1-5 are clean — but the
statement that makes them clean is *"`make web-gate` (typecheck + vitest + build — NOT Playwright; e2e runs in CI only) passes"*, not *"the suite passed here"*, and only the
second was ever said before today.

**Two other defects the same verification surfaced**, both invisible to every gate until then:

- `tsconfig.json` included only `src`, so **`tsc --noEmit` had never typechecked a single test file**
- a duplicate `import { ruleRow }` in `test/policyview.test.ts` — a genuine `TS2300`, behaviourally benign

## STANDING RULE, from here

> ### A SLICE IS NOT GREEN UNTIL `make web-gate` (typecheck + vitest + build — NOT Playwright; e2e runs in CI only) PASSES.
>
> Not until the suite passes locally. **Every slice reports the GATE's result, not `vitest`'s** — typecheck,
> test and build, in the Node 20 container that mirrors CI.

**The framing worth keeping:** this tier exists to catch defects a surface's own tests cannot see, and **its
first five slices carried a defect its own gate could not see.** That is why *"the gate is the authority"* must
mean the gate **as CI runs it**, on every slice — not once at the end.
