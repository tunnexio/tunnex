# THE CUT REGISTER — one line per cut. GREP THIS FILE, NOT THE PROSE.

**Created 2026-08-02, founder-ordered, after the rule *"grep the epic doc for its name"* failed twice on
someone who had read the doc.**

> ## **A RULE WITH A 400-LINE PROSE TARGET IS A RULE NOBODY CAN EXECUTE.**
> ## **THE RULE WAS RIGHT. THE TARGET WAS WRONG.**

**BOTH MISSES HAPPENED TO A READER OF THE DOC:** I argued GSAP on bundle size when it was ruled out on
**redistribution licence**, and I recommended the Gateways screen partly for its `Fleet risk` bubble plot when
`Fleet risk` had been **cut at epic open**. Neither was ignorance of the file. Both were the file being too
long to re-scan for one name.

**HOW TO USE IT:** `grep -i '<name>' docs/CUT-REGISTER.md` before arguing for a panel, a library, or a
screen. **Every section's commit-one must cite this grep**, the same way it cites the handoff extraction.

**HOW TO ADD:** one line, at the moment of the cut, with the reason and where it was ruled. **A cut recorded
only in prose is a cut that will be re-proposed.**

**⛔ CUTS ONLY. DEFERRALS LIVE IN `docs/DEFERRAL-REGISTER.md`** — split S14.7, founder-ordered, on this
file's own founding rationale. **A cut answers *"is this in scope?"*; a deferral answers *"when does this
happen?"*.** They are greped at different moments by different questions, and mixing them makes both
searches noisier. This file stayed one-line-per-entry precisely so a grep is cheap.

---

## PANELS AND FEATURES

| name | verdict | reason | ruled |
|---|---|---|---|
| **Fleet risk** (Gateways `gwScatter` bubble plot) | **CUT — for the NAME; the content is largely serveable** | ⚠ **REASON AMENDED S14.6, measured.** The original entry said *"risk scoring is an unbuilt Tier-3 name"* — true of the TITLE and misleading about the PANEL. It plots **agent version × peer load** against a **`MIN SUPPORTED`** boundary: `agent_version` ✅ served · the boundary ✅ (`max_policy_version` + `meta.protocol_version`, the CW ceiling we already compute) · **peer count ❌ — the same column that is its own slice.** So it is 2-of-3 served and **blocked on peers**, not on an unbuilt capability. **STAYS CUT.** A register whose reasons are wrong launders a bad reason into a decision — and this one was already cited as a reason to pick a screen | EPIC 14 open · reason corrected S14.6 |
| **Site-Link Throughput as a rate time-series** | **CUT — founder-ruled 2026-08-05** | `rx_bytes` is a gauge that resets each handshake; a time axis draws a sawtooth. Effort was scoped (~5 slices, ≈S7.5.1) and the founder ruled it NOT WORTH IT: the chart is not actionable, `/metrics` already serves anyone who wants trending, and nothing can backfill — it would ship blank and stay partly blank for 7 days, which is the week it would be demoed. **The Overview tile went with it.** Returns on a NAMED TRIGGER, not a date: first design partner asking for capacity trending, or first support escalation that needed history | `docs/S11.1-throughput-commit-one.md` |
| **Site-Link Traffic tile** (Overview) | **REMOVED 2026-08-05** | The counters-only panel that stood in for the chart. Removed with the chart's cut rather than left as a stub for a feature that is not coming. ⚠ NOT ORPHANED: per-member `↓rx ↑tx` still renders on `/sites` (`Sites.tsx:737`, via `hubsetview`) | founder-ruled |
| **FREE/ENTERPRISE and ADMIN/USER toggles** | **CUT** | wireframe demo controls. A user cannot switch their own edition or role. Read-only badges instead | EPIC 14 open |
| **Density (Cozy/Compact)** | **CUT** | ship one density; the spacing scale is kept so it could return | pre-EPIC 14 |
| **Date-range picker on screens that do not filter by date** | **CUT** | keep it only where the data is time-ranged: Access Events, Audit Log | EPIC 14 open |
| **Floating action button** | **CUT** | purpose unclear; every screen already has a primary action in its header | EPIC 14 open |
| **"Get started 2 of 4" floating widget** | **CUT** | becomes part of the Overview EMPTY STATE. A checklist following an established admin around is noise | EPIC 14 open |
| **Per-region mesh nodes with site counts** (Sites map) | **DIFFERENT FORM** | no region field on `Node` or `Site`. Built per-SITE, uniform radius | S14.5 |
| **`cloud · region` / `egress ✓`** (Gateways table) | **CUT** | no field for region or for egress capability on `Node`. Same gap as the Sites mesh | S14.6 |
| **"hover to trace a link"** (map hint copy) | **CUT** | we do not implement hover tracing; describing an interaction the component lacks is the same class as a chart with no source | S14.5 |
| **Per-link byte counters on the map** | **MOVED** | `rx/tx` exist only on `HubMemberMetrics`, per hub member. Rendered in the HA panel where they are true | S14.5 |
| **The wireframe's node ROWS under the map** | **CUT** | they are an `sc-for extraSites` — sites added during the prototype session, not a permanent list | S14.5 |
| **`gallery-wide-390.png`** | **CUT** | at 390 there is no wide column, so a wide specimen is the narrow one again. Symmetry is not a reason | S14.5 |
| **"Subnet advertisement queue"** (wireframe title) — ⚠ *same panel as the "Pending Subnet Queue on Routed Ranges" row below; kept under both names because a reader greps for either, cross-referenced so neither is read alone* | **DIFFERENT TERM** | Wireframe titled panel *"Subnet advertisement queue"*; domain model and API call them *"Pending subnet approvals"*. Repointed to Sites screen (`Sites.tsx`), where pending subnet approvals are managed (`/api/v1/organizations/{orgId}/site-subnets/pending`). Routed Ranges (`/routed-ranges`) is a read-only list of approved CIDRs | S14.5 |
| **Address-space heatmap** (256-cell grid on Routed Ranges) | **CUT** | (1) Coarse Granularity Defect: At `10.0.0.0/8` mapped to 256 `/16` cells, a standard `/24` allocation lights up an entire `/16` cell, visually masking free `/24` subnets within that block. (2) Domain Limitation: The grid domain is strictly `10.0.0.0/8`. Real customer address spaces include RFC1918 `172.16/12` (e.g., AWS default `172.31.0.0/16`) and `192.168/16`, which have no cells at all on a `10/8` grid. Replaced by canonical sorted `DataTable` (`/routed-ranges`) | S14.7 |
| **Pending Subnet Queue on Routed Ranges** | **CUT FROM ROUTED RANGES — INDEPENDENT OF THE HEATMAP** | ⚠ **REASON CORRECTED S14.7.** The old text made this a CONSEQUENCE of cutting the grid, which is a dependent reason and therefore fragile: un-cut the grid and the row loses its justification. **THE INDEPENDENT REASON: the queue lives on Sites because that is where the MUTATION ENDPOINT is** — `/site-subnets/pending` + `/approve` are `site:manage`, while `/routed-ranges` is `org:view` and has no approve verb. **True whether or not the heatmap was ever cut.** Same panel as the *"Subnet advertisement queue"* row above | S14.7 |
| **`control plane ● healthy` in Devices title header** | **CUT** | Duplicates shell-level footer `HealthStatus` ([`AppShell.tsx:322`](file:///Users/pawangupta/tunnex/apps/web/src/components/AppShell.tsx#L322)) which queries `/healthz`. Hardcoding static header status causes desync | S14.10 |
| **Config ceremony persistent right-hand panel** | **DIFFERENT FORM** | Built as modal dialog `OneTimeSecretModal` (shows secret once, blocks page, requires explicit acknowledgment to dismiss) to guarantee credentials never persist on page | S14.10 |

## LIBRARIES

| name | verdict | reason | ruled |
|---|---|---|---|
| **GSAP** | **NOT ADOPTED** | custom non-OSI licence; we REDISTRIBUTE a built bundle in a self-hosted Apache-2.0 artifact. Use **Motion (MIT)** | EPIC 14 open |
| **A charting library** | **NOT ADOPTED** | covers 3 of 10 needed visualisation types; the other 7 are hand-rolled anyway | S14.3 |

## SCREENS AND SURFACES

| name | verdict | reason | ruled |
|---|---|---|---|
| **The visual CI job as a merge gate** | **ADVISORY, ALL OF EPIC 14** | red by design during a redesign; 5 consecutive red pushes in S14.5, no regressions. NOT to be added to required checks. ⚠ COST: the geometric + strict-mode assertions need a real browser, cannot move to `make web-gate` (jsdom has no layout engine), so the class that found the 65px overflow is advisory too. **RE-ARM: EPIC 14 close** | founder rule, 2026-08-02 |
| **Sites edition gate / upsell** | **DELETED** | the site model is all-editions core (D11); the client invented a boundary the server does not have | S14.5 |
| **Failed-load triad panel** (Gateways/Sites right column) | **CUT** | a wireframe DOCUMENTATION device showing three states side by side, not a product panel | S14.5 |
| **`PEERS` column** (Gateways) | **ABSENT — its own slice** | `devices WHERE node_id` counts DEVICES, and a hub's WireGuard peers include SITE LINKS, so on a hub it under-reports exactly where an operator looks hardest. Either count wg peers or label it `DEVICES`. Spec+codegen change, so it is a slice, not a rider | S14.6 |
| **Operations screen** | **ABSENT-PENDING-ENDPOINTS** | the capability shipped in EPIC 11; the API exposes none of it. See the fifth category in `EPIC-14-ui-redesign.md` | S14.6 nav audit |

### S14.7 — Routed Ranges

- **`STATUS` column — CUT as a CONSTANT COLUMN.** `/routed-ranges` is APPROVED-ONLY, so the column would
  carry one value in every row of every org forever. Not merely useless: it teaches the reader that some
  other value is reachable on this screen, which is what sends them here looking for the pending queue.
- **`126 devices` on `PUSHED TO` — CUT, not served.** Same class as the gateway `PEERS` count. Counting
  devices locally would count ones that never fetched this list.

## ⛔ THE "SILENTLY DIDN'T APPLY" CLASS — three instances, registered as a CLASS because the fourth will look different again

> ### **A THING CONFIGURED TO RUN, NOT RUNNING, AND REPORTING NOTHING.**
> ### **THE SHAPE IS WHAT MAKES IT FINDABLE. THE INSTANCES LOOK NOTHING ALIKE.**

Each was found by accident, none by a check, and in every case the SUCCESS PATH AND THE SILENT-NOOP PATH ARE
INDISTINGUISHABLE FROM THE OUTSIDE — the command exits 0, the suite is green, the panel renders.

| # | instance | what was configured | what actually happened | how it was found |
|---|---|---|---|---|
| 1 | **`NET := tunnex_default`** (Makefile, S14.7) | `migrate` / `seed` / `seed-fixtures` / `sqlc` join the compose network by name | founder runs `COMPOSE_PROJECT_NAME=tunnex-s141`, so all of them hit **a different stack's database** while exiting 0 | the fixture's own real-data guard fired on 6690 orgs. **`migrate` has no such guard and would have applied silently.** |
| 2 | **`round2-walk.spec.ts`** (e2e, S14.7) | a walk spec inside `testDir`, gated `test.skip(!process.env.ROUND2)` | `ROUND2` is set **nowhere** in `.github/workflows/` or the `Makefile`. **Never ran, inside the job S11-1 promoted to BLOCKING, while reading as coverage.** | two assertions on a string deleted in S14.6 survived in it — they cannot fail, because nothing runs them |
| 3 | **`ON CONFLICT (org_id) DO NOTHING`** (seed-fixtures, S14.8) | the HA hub-set fixture writes `configured` + `demoted` | `make seed` already writes that row, so the fixture **lost the conflict and never applied**. The HA panel rendered base-seed state. | reading `\d org_hub_set` while discharging the demoted-note debt |

| **4** | **THE FOUR STANDING PRE-MERGE ITEMS** (process, S14.7) | verify composition at STEP level · verify branch protection · put the checkpoint in the PR · declare un-rendered states for acceptance | **THREE OF FOUR SKIPPED.** Only "required checks green" was done, and that at JOB level. The merge went through, `main` moved, nothing anywhere said a gate had been missed | **by being asked.** Same as the other three |

**INSTANCE 4 IS THE CLASS DESCRIBING ITSELF.** A gate held by intention, configured to run, not run, reporting
nothing — and found by accident. The three preceding rows are mechanisms; this one is a human procedure, which
is why it is the easiest to skip and the least likely to announce it.

**AND ITS FIX IS ALREADY NAMED AND UNRULED.** `allow_auto_merge` is ON (flipped during S14.6 **without being
asked**, disclosed and registered at the time), and the Bash rules were broadened. Together those make
*merge-then-check* the low-friction path — the click resolves the moment the last check goes green, which is
precisely the moment the four items were supposed to happen.

> ### **TURNING `allow_auto_merge` OFF FOR THE REST OF EPIC 14 MAKES THREE OF THE FOUR STRUCTURALLY**
> ### **UNSKIPPABLE, BECAUSE A MANUAL MERGE IS A MOMENT WHERE THE CHECKS MUST BE TYPED.**

**⛔ RULED AND APPLIED 2026-08-02: `allow_auto_merge=false`** (verified `false` via the API after the PATCH).

**RE-ARM TRIGGER: EPIC 14 close, alongside the visual job's re-arm** — the same event, because both were
loosened for the same reason (iteration speed on a redesign) and both should tighten together.

**WHAT IT CLOSES, NAMED:** the three pre-merge checks skipped at S14.7 — verify composition at STEP level,
verify branch protection, declare un-rendered states for acceptance. With auto-merge off, **a merge is a moment
where the checks must be typed**, so three of the four stop depending on intention. (The fourth, the in-PR
checkpoint, is stale-by-construction under rebase-merge and is handled by carrying BOTH the PR number and the
post-merge sha.)

**This is instance 4's fix, and it is a MECHANISM rather than a resolution** — "be more careful next time" is
what the other three rows in this table already tried.

**THE COUNTERMEASURE IS NOT A FIX PER INSTANCE — IT IS MAKING THE NOOP AUDIBLE.** #1 now derives from
`COMPOSE_PROJECT_NAME`; #2 left `testDir` so it makes no claim; #3 is `DO UPDATE`. But the general defence is
the one added with #3: **`seed-fixtures` now COUNTS after writing and logs the totals**, so a write that did
not happen shows up as a number that did not move.

**WHEN YOU ADD THE FOURTH, ADD IT HERE.** Ask of any new mechanism: *if this silently did nothing, what would
be different?* If the answer is "nothing", it belongs in this table before it belongs in the codebase.

### S14.10 — Devices

- **FILTER CHIPS SHIPPED IN A DIFFERENT FORM — `All / Needs attention / Revoked`, not the wireframe's
  `All / Online / Idle / Blocked`.** Deviation, not an omission, and recorded so the wireframe does not
  re-propose it at S14.11.

  **WHY THE HANDOFF'S FOUR DO NOT WORK ON THIS DATA:**
  - `Online` and `Idle` are the SAME axis the STATE column already renders, per row, with a live dot and a
    relative timestamp. Two chips restating one column is a filter that teaches nothing the table has not said.
  - `Blocked` is ONE of four things an operator must act on. Shipping it alone hides the other three —
    `pending` approval, `noncompliant` (warn-mode), and `needs_reexport` — behind a chip that looks complete.
    **`Needs attention` is the UNION**, which is the actionable question; `Blocked` is a subset of it.
  - `Revoked` is kept because it is the one state that is deliberately NOT attention: a revoked device is done,
    and surfacing it as actionable is an instruction to act on a device that cannot come back.

  **WHAT IS LOST, STATED:** filtering to *only* online, or *only* idle, is no longer possible. That is a real
  capability the handoff offered and this form does not. **If an operator asks for it, the honest answer is a
  second axis (state) beside the first (attention), not replacing one with the other.**

## HARNESS AND TEST-INFRASTRUCTURE FINDINGS

- **S14.7 · `NET := tunnex_default` was HARD-CODED while the founder runs `COMPOSE_PROJECT_NAME=tunnex-s141`.**
  Every docker-run make target (`migrate`, `seed`, `seed-fixtures`, `sqlc`) joins a compose network BY NAME,
  so all of them were aimed at a DIFFERENT STACK'S DATABASE while appearing to succeed. `seed-fixtures`
  refused (its real-data guard fired on 6690 orgs); **`migrate` has no such guard.** `SECRETS_VOL` was the
  same class one line down, and worse in effect: sealing against another stack's master key yields a secret
  that stack cannot unseal, with no error at seal time. Both now derive; unset behaves exactly as before.
  **A GUARD ON ONE TARGET IS NOT A GUARD ON THE CLASS** — the guard that fired belonged to the one command
  that had one.

| finding | verdict | reason | ruled |
|---|---|---|---|
| **`e2e/` was never typechecked** | **FIXED** | no tsconfig, not in the workspace, not in `apps/web/tsconfig` — so nothing PARSED the specs before CI ran them, and an orphaned `describe` reached CI as a `SyntaxError`. Now typechecked inside the BLOCKING gate, proven to reject | S14.5 |
| **Page suites render without a Router** | **NOT A LIVE DEFECT — loud, not silent** | measured: **0 of 7 pages use `useNavigate`/`Link`/`useLocation`**, so nothing routing-dependent is being skipped. And the first `<Link>` added (Devices, S14.6) **crashed five tests immediately.** An under-capabilitied double that THROWS is self-announcing | S14.6 |

## REPO AND MERGE SETTINGS

| setting / claim | state | reason | recorded |
|---|---|---|---|
| **`allow_auto_merge`** | **ON** (was off) | flipped 2026-08-02 so PR #50 could land the moment `gates` went green, instead of a human polling CI. **⚠ It is now inside the broadened Bash permission rules, so a future `gh pr merge --auto` runs unattended.** Turn it off if that is not wanted | S14.5 |
| **"every merged sha is the exact object CI verified"** | **FALSE, and has been for both merges** | GitHub's **rebase-merge rewrites commit objects**. `main` = `85081b0`, verified = `1b91bcd`; PR #49 was `556cfaf` vs `f180d02`. **TREES are identical; OBJECTS are not.** I reported "byte-identical to the sha CI verified" twice — true of the tree, false of the object, and I checked only the tree | measured S14.6 |

### ⛔ WHAT THE GUARANTEE ACTUALLY IS, NOW THAT IT IS MEASURED

**The rewritten `main` sha gets its OWN full CI run** — 17 checks on `85081b0`. So the merged object *is*
verified, **just not by the run that was reported at merge time.**

> **THE CLAIM SHOULD HAVE BEEN "THE MERGED TREE IS THE VERIFIED TREE, AND THE MERGED OBJECT IS VERIFIED
> AFTERWARDS BY ITS OWN RUN." I SAID SOMETHING STRONGER AND CHECKED SOMETHING WEAKER.**

**The gap that leaves:** between the merge and that post-merge run completing, `main` carries an object no
green run covers. For a tree-identical rebase that is a formality — **but it is not the ff-only guarantee the
record claims**, and a reader taking the record at face value would believe `main` never holds an unverified
object.

**TO ACTUALLY GET THE STRONGER PROPERTY:** merge with **`--merge-queue` or a local ff-push**, not
`--rebase`. A local ff is possible whenever `main` is an ancestor of the branch head, which it was here.
**Not changed unilaterally — the linear-history requirement interacts with it and that is a
branch-protection decision.**

## ⛔ "CONFIGURED NOT TO MATTER" — THE THIRD INSTANCE, AND THE CENSUS THAT FOUND IT

**After S11-1 (a promoted-then-ignored e2e job) and O-1, this is the third time a check existed and was
configured into irrelevance.**

**CENSUS RUN 2026-08-02 over `e2e/` and the component tier** — every `test.skip` / `describe.skip` /
`.only` / `fixme` / env gate:

| spec | gate | runs in CI? |
|---|---|---|
| `e2e/tests/settings.enterprise.spec.ts:24` | `test.skip(edition !== "enterprise")` | **YES** — the `e2e-enterprise` job runs it against an enterprise stack, so the gate is a correct guard |
| **`e2e/tests/round2-walk.spec.ts:18`** | **`test.skip(!process.env.ROUND2)`** | ⛔ **NO. `ROUND2` is set NOWHERE in `.github/workflows/` or the `Makefile`. THIS SPEC HAS NEVER RUN IN CI.** |
| component tier (`apps/web/test`) | — | **zero skips.** The one grep hit is a comment |

**THE ROUND2 SPEC IS A WHOLE WALK SPEC THAT NOTHING EXECUTES.** It is how two stale assertions on a string
deleted in S14.6 survived undetected — they cannot fail, because nothing runs them.

> ## **AN ENV-GATED SPEC IS ADVISORY BY DEFAULT AND NOTHING ANNOUNCES IT.** The visual job at least says
> ## "ADVISORY" in its name. A `test.skip(!process.env.X)` says nothing at all, and reads as coverage.

**NOT DISPOSITIONED HERE** — either `ROUND2` gets set in a job, or the spec is deleted, or it is renamed to
declare itself. **Three options, founder's call. TRIGGER: EPIC 14 close, with the visual job's re-arm.**

---

## ⛔ A VERDICT FORMED WITHOUT OPENING THE ARTIFACT — **THREE INSTANCES IN ONE STORY (S14.11)**

Not a cut. A **method** class, registered because all three landed inside a single commit-one and **none was
self-detected** — two were caught by the founder, one by a mutation sweep.

| # | the verdict I recorded | what I looked at | what the artifact said |
|---|---|---|---|
| 1 | *"the product doesn't know"* for five roster columns | the **`Member` DTO** | **four of five wrong** — a projection, a permission, an edition, a missing read. `docs/laws.md` → *BEFORE RECORDING AN ABSENCE, NAME THE TABLE* |
| 2 | *"edition first, because a permission message would misdirect an owner"* | **my own reasoning** | `ListGroups` authorizes **`PermPolicyView` FIRST**, then checks the edition. An open-edition member's real answer is `forbidden`, and my order **sold them Enterprise** |
| 3 | *"NO client-side owner count"* (§2.5) | **the wireframe copy** | `Users.tsx` **already had one**, with its rationale written beside it. Reconciled, not overwritten |
| 4 | **my own §2.6 rule**: *"additions get the same discipline as cuts"* | **nothing** | I added a `Groups 3` stat tile that **is not in the wireframe** and registered nothing — breaking the rule **in the story that states it** |

> ## **THE COMMON SHAPE: I read a SUMMARY OF THE ARTIFACT (a DTO, my own prose, a wireframe) and reported on**
> ## **THE ARTIFACT. Each summary was accurate about itself and wrong about the thing it stood for.**

### ⛔ INSTANCE 4 IS THE SHARPEST FORM: THE PROSE WAS MY OWN RULE ABOUT MY OWN CODE

Instances 1–3 are a stale summary of someone else's artifact. **Instance 4 is different in kind:** §2.6 of this
story's own decisions doc says *"ADDITIONS GET THE SAME DISCIPLINE AS CUTS — a silent addition is as hard to
audit later as a silent removal."* I wrote that sentence, registered `email_verified` under it, and then added
a `Groups` stat tile with no register row **in the same document, in the same story.**

> ## **THE AUTHOR IS THE ONE PERSON WHO CANNOT READ THEIR OWN RULE FRESH. Writing a rule creates the feeling**
> ## **of having complied with it — the rule is salient, so the mind supplies the compliance. A reviewer**
> ## **reading §2.6 cold would have asked "which additions?" and found the tile in one pass.**

**This is why the standing question is phrased as a question and not an instruction.** *"What in this change is
asserted only in prose?"* can be asked of yourself. *"Follow your own rules"* cannot — it is already believed.

**AND THE DIRECTION IS NOT RANDOM: all three under-built or mis-served the caller with the LEAST access.** #1
removed columns, #2 upsold a member who could never use the feature, #3 would have removed a working guard.
**When a method error has a consistent direction, the direction is the finding.**

## THE DIAGNOSIS, CORRECTED — it is not "the axes compare spec to schema", it is **PROSE VERSUS BEHAVIOUR**

My first diagnosis was that the three spec-drift axes miss this because *they compare a spec to a schema.* True
and too narrow. **The sharper statement, which is what names the check:**

> ## **ALL THREE FINDINGS ARE AN ARTIFACT A HUMAN WROTE, ASSERTING SOMETHING THE CODE DOES NOT DO.**
> ## **A COMMENT · A PAPER RULING · A FIXTURE. Three different artifacts, none checked against anything.**

| the artifact | what it asserted | the behaviour |
|---|---|---|
| a **comment** (§2.4's *"not the S14.5 halt in reverse"*) | that the gates were ordered safely | the code three lines below committed the S14.5 halt itself |
| a **paper ruling** (§2.5) | *"no client-side owner count"* | the page had one, deliberately |
| a **fixture** (every seeded member has a name) | that a named member is what a roster holds | 144 of 241 users have `name = ''` |

**AND THIS IS WHY THE SPEC-DRIFT AXES CANNOT BE EXTENDED TO COVER IT.** All three axes compare **two
machine-readable things** — a spec enum to a column `CHECK`, a summary's permission to a handler's. Both sides
are parseable, so a script can hold them together. **Prose has no second side to compare against.** A comment
that lies is well-formed; a fixture that under-represents is valid data; a ruling in a decisions doc is
authoritative by construction.

> ## **SO THIS CLASS IS UNAUTOMATABLE BY CONSTRUCTION, WHICH MAKES IT A STANDING QUESTION AND NOT A GUARD:**
> ## **⛔ WHAT IN THIS CHANGE IS ASSERTED ONLY IN PROSE?**

Ask it of a comment claiming an invariant, a ruling made without opening the file it rules on, and a fixture
whose values were chosen rather than measured against the population. **The one mechanical thing available is
narrower and worth doing where it fits:** where prose asserts an *ordering* or a *shape* over many call sites,
a **static census test** can hold it — `TestEditionGateNeverPrecedesPermissionGate` is that, built here after
this class produced a security defect, and it covers a 42nd handler nobody has written yet.

**Instrument note:** the three axes (`docs/S14.10-handoff.md` §4.2) would have caught **none** of these.
