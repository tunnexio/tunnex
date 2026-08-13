# THE VIEWPORT LEG — APPROVED AND BUILT

> ## ⛔ **THE JUSTIFICATION IS A MEASUREMENT, NOT A PREFERENCE.**
>
> **All three visual defects of 2026-08-01 originated in SHARED CODE** — a spacing config re-keyed px-vs-rem
> (128 use sites, 17 screens), a shared scale that rendered a donut at a quarter size, and a shared primitive
> whose `backdrop-filter` broke five modals. **NONE originated in a screen.**
>
> **A SCREEN-SHAPED SUITE PAYS PER-SCREEN MAINTENANCE TO CATCH DEFECTS THAT ARE NOT SCREEN-SHAPED** — and is
> re-baselined every time a screen is redesigned, twelve more times this epic.

**ORIGINALLY PROPOSED, NOW APPROVED.** Registered at S14.2, trigger fired at S14.4, owed before EPIC 14 closes.

**THE STEER, TAKEN LITERALLY:** *"I would rather have a small suite I trust than broad coverage I
rubber-stamp."* **The proposal below is deliberately smaller than the obvious one, and the reasoning for each
cut is given rather than the coverage defended.**

---

# THE DEFECT CLASS IT EXISTS FOR — measured, from the three that actually happened

| # | defect | where it came from |
|---|---|---|
| 1 | spacing scale re-keyed px-vs-rem → **128 use sites** changed magnitude | **a shared config** |
| 2 | donut rendered at **24×24 instead of 96×96** | **a shared scale**, via `h-24` |
| 3 | `backdrop-filter` on `Card` → **5 modals** lost viewport positioning | **a shared primitive** |

> ## **ALL THREE ORIGINATED IN SHARED CODE. NONE ORIGINATED IN A SCREEN.**

**THAT IS THE DESIGN INPUT.** A suite that screenshots *screens* pays per-screen maintenance to catch defects
that are not screen-shaped. **A suite that screenshots the SHARED SURFACE catches all three at a fraction of
the cost — and does not need re-baselining every time a screen is redesigned**, which is the founder's
objection to capturing baselines for the twelve screens still ahead.

---

# 1. WHAT IT CAPTURES — **a primitives gallery, plus ONE real screen. Not full pages.**

## 1a. `/__visual` — a route rendering every primitive at every state

`Button` (4 variants × enabled/disabled/loading) · `Card` · `Panel` · `Badge` (4 tones) · `EmptyState` ·
`Loading` · `List` · `DataTable` (populated / empty / failed) · `Stat` (ok / loading / failed, with and
without sub-line) · `Donut` · `Histogram` (incl. a `gap` bin) · `NodeLink` · `ComposeGate` (both sides) ·
**`Modal` OPEN** · **`OneTimeSecretModal` OPEN** · the toast stack · the nav rail in all three modes.

**⛔ THE OPEN MODALS ARE THE POINT.** Defect 3 was invisible to every check *because no test had a modal open
while a `Card` was on screen*. **A gallery that renders overlays in their open state is the only cheap way to
keep that class covered**, and it costs one route rather than a spec per screen.

**Route is dev/test-only** — excluded from the production bundle, so it cannot become a shipped surface.

## 1b. **Overview only**, of the real screens

**It is the only redesigned screen that exists.** The other twelve get their snapshot **as the last step of
their own section**, when their design is settled — never before. *A baseline captured for a screen about to be
redesigned is a baseline that will be discarded unread.*

## ⛔ NOT FULL-PAGE SCREENSHOTS OF EVERY SCREEN

Full pages are the obvious choice and the one that dies. **A single spacing change repaints all eighteen
images**, producing eighteen diffs for one cause — and eighteen diffs is the volume at which
`--update-snapshots` stops being a decision and becomes a keystroke.

---

# 2. WIDTHS — **TWO, not five**

| width | why it earns a snapshot |
|---|---|
| **1440** | the design's native width. Catches every geometry regression (all three defects would have fired here). |
| **390** | the narrow rearrangement — drawer nav, triage bar, `ComposeGate` absence. **Ours, not the designer's** (the prototype is desktop-only, min-width 1280), so it has no other reviewer. |

**THE OTHER THREE (768 / 1024 / 1920) ARE CUT.** They exercise the same `layoutIntent` boundaries **already
unit-tested exhaustively at both sides of every threshold**. A snapshot at 1024 would re-assert in pixels what
`layoutIntent(1023) === "compose"` asserts in a value — **at 2.5× the image count and with a human in the
loop.** Two widths, ~20 images total.

---

# 3. HOW A DIFF IS JUDGED, AND BY WHOM — **the question that decides whether it survives**

**Judged by the founder, on the PR.** No automation can decide whether a moved pixel was wanted.

## THE FAILURE MODE, NAMED: a blanket `--update-snapshots` produces a green check with no subject — **mechanism ⑦ in image form.** Three structural defences, none of them procedural:

**(a) `--update-snapshots` CANNOT RUN IN CI.** Baselines change only by a committed `.png`. CI compares; it
never writes. A silent re-baseline is therefore impossible — it would have to appear in a diff.

**(b) A BASELINE UPDATE IS ITS OWN COMMIT, TOUCHING ONLY `.png` FILES.** Enforced by a check: if a commit
contains both baseline images and source changes, the job fails. **This is the load-bearing one** — it makes
"N images changed" a reviewable fact instead of something buried inside a 40-file feature commit, and it forces
the author to state *which* images and *why* in a message that exists only for that purpose.

**(c) A BASELINE CENSUS.** A test asserts the expected snapshot count. **Deleting a snapshot is the easiest way
to make a red suite green**, and it leaves no diff to review — the census makes it red instead.

## DETERMINISM — because a flaky suite gets rubber-stamped no matter how it is governed

| hazard | measured | handling |
|---|---|---|
| **relative timestamps** (`relativeAge` → `"3s ago"`) | **4 screens** | **freeze the clock** via `page.clock`; fixtures use fixed ISO dates |
| animation / transition | Motion + CSS | **force `prefers-reduced-motion: reduce`** — the token CSS already zeroes every duration |
| font loading | **self-hosted `@fontsource`** — no CDN | ✅ already deterministic |
| live API data | seeded demo org | **route-mock every endpoint**; the gallery uses no API at all |
| scrollbars / platform AA | — | one browser (`chromium`), one container, `maxDiffPixelRatio: 0` |

**IF THE SUITE FLAKES ONCE, IT IS TREATED AS A DEFECT IN THE SUITE, NOT AS NOISE TO TOLERATE.** A visual suite
survives exactly as long as its red means something.

---

# 4. WHERE IT RUNS — **its own CI job, blocking, with its own line**

**NOT riding `e2e`.** Three reasons:

1. **Today proved a job whose failures are buried gets ignored.** `e2e` was red for four consecutive pushes
   under a green local gate. A visual diff folded into `e2e` inherits that invisibility.
2. **Different artifact needs** — it must upload `expected/actual/diff` images for adjudication.
3. **Different failure meaning.** `e2e` red = broken behaviour. Visual red = *something moved*, which may be
   intended. Mixing them makes the first less alarming.

**BLOCKING, not advisory** — per `security.yml`'s own rule that *advisory* means "its findings don't block", not
"the job needn't run". Here the finding **is** the point, and it is unblocked by committing a baseline.

**AND IT DOES NOT RIDE `make web-gate`.** That target is typecheck + vitest + build; adding a container browser
to it would slow every local run for a check that needs a stable rendering environment. **Its absence from the
local gate is exactly why the CI-line rule now exists.**

---

# 5. ⛔ WHAT IT STILL CANNOT SEE — stated now, not discovered later

**It answers ONE question: *did anything move that nobody asked to move?*** It cannot answer *is this right*.

**Classes with NO gate even after this exists:**

| still ungated | why |
|---|---|
| **is the design correct** | a diff cannot want something. Only the founder's review answers this. |
| **any state not captured** | a modal not opened, an error not triggered, a permission not simulated is not in an image. **Coverage is exactly the enumerated states and nothing else.** |
| **contrast/readability *in situ*** | the token gate computes ratios on token pairs; it does not see text over a gradient or a badge on an unexpected surface. |
| **the 12 unbuilt screens** | until each takes its own snapshot at the end of its section |
| **real browsers other than chromium** | Safari and Firefox render text and `backdrop-filter` differently. **Out of scope, and named so it is not assumed.** |
| **motion itself** | animations are frozen to make the suite deterministic, so nothing about them is tested |

**AND THE HONEST COST:** it fires on **every intentional visual change**, which is most commits in a redesign
epic. That is not a flaw — **it is the mechanism** — but it means the founder sees image diffs regularly, and
the baseline-only-commit rule exists to keep each one small enough to actually look at.

---

# 6. SIZE, AND WHY THIS IS THE SMALL VERSION

**~20 images. One route + one screen. Two widths. One browser.**

Compare with the obvious build: **18 screens × 5 widths = 90 images**, re-baselined every time any screen is
redesigned — **twelve times over the rest of this epic.** That version catches marginally more and would be
rubber-stamped by the third redesign.

**THE TRADE, STATED PLAINLY: this catches shared-surface regressions — which is where all three of today's
defects came from — and does not catch a screen-specific visual regression on a screen with no snapshot yet.**
That gap closes screen by screen as each section lands.

---

# OPEN QUESTIONS

1. **Does the `/__visual` route need to exist in the app, or should the gallery be a Playwright-mounted
   component page?** Proposal: **a real route**, dev-only. Component mounting needs its own harness and would
   drift from how the app actually composes providers — and the provider stack is where `ComposeGate` and the
   theme live.
2. **Should the baseline images live in the repo or in CI cache?** Proposal: **in the repo.** They are the
   subject of review; a cached baseline nobody can see in a diff is the rubber-stamp failure by another route.
   ~20 PNGs at two widths is a few hundred KB.
3. **Snapshot the `violet` theme too, or `mono` only?** Proposal: **`mono` only** — the second theme re-points
   colour and nothing else, and the token census already asserts every theme supplies every name. Doubling the
   image count to re-check a value mapping is the coverage-without-trust trade this proposal exists to avoid.

---

# THE THREE OPEN QUESTIONS — ANSWERED ON MY OWN RECOMMENDATION, PER THE APPROVAL

1. **A REAL ROUTE, `/__visual`, dev-flagged.** Component-mounting needs its own harness and would drift from
   how the app actually composes providers — and the provider stack is precisely where `ComposeGate`, the
   theme and the motion preference live. **A defect in composition is invisible to a harness that composes
   differently.** Behind `VITE_VISUAL_GALLERY`, unset in every production build, with a test asserting the
   flag is not committed anywhere: **an unshipped surface must be PROVEN unshipped.**
2. **BASELINES IN THE REPO.** They are the subject of the review; a cached baseline nobody can see in a diff
   is the rubber-stamp failure by another route. ~4 PNGs.
3. **`mono` ONLY.** The second theme re-points colour and nothing else, and the token census already asserts
   every theme supplies every name. Doubling the image count to re-check a value mapping is exactly the
   coverage-without-trust trade this suite exists to avoid.

# BUILT

| piece | where |
|---|---|
| the gallery | `apps/web/src/pages/VisualGallery.tsx`, route flagged in `App.tsx` |
| the specs | `e2e/visual/visual.spec.ts` (gallery) · `e2e/visual/overview.spec.ts` |
| **the census** | `e2e/visual/baselinecensus.spec.ts` |
| config | `e2e/playwright.visual.config.ts` — `maxDiffPixelRatio: 0`, `retries: 0`, UTC, `en-GB`, dark |
| CI | a **separate blocking job**, `visual`, uploading `expected/actual/diff` as artifacts |
| local | `make visual` · `make visual-update` |
| unshipped proof | `apps/web/test/visualgallery.test.ts` |

## ⛔ THE CENSUS ASSERTS AN **EXACT COUNT**, AND IT IS PROVEN TO REJECT

**A floor is satisfied by deleting all but one — which is the exact move it exists to prevent.** So it is
`toEqual` over the expected set, never `toBeGreaterThan`, the same form as the screen census.

**PROVEN by deleting one baseline:**

```
Error: baseline set drifted.
  expected: gallery-1440.png, gallery-390.png, overview-1440.png, overview-390.png
  found:    gallery-1440.png, gallery-390.png, overview-1440.png
```

**The number moves deliberately, in a reviewable edit to that list, or the suite goes red BY NAME.**

## DETERMINISM, IMPLEMENTED

`page.clock.setFixedTime` (the `relativeAge` "3s ago" problem, live on four screens) · forced
`prefers-reduced-motion: reduce` · `document.fonts.ready` awaited before every shot · self-hosted fonts (no
CDN) · UTC + `en-GB` pinned · one browser, one container image **pinned to CI's**
(`mcr.microsoft.com/playwright:v1.48.2-jammy`).

## ⚠ BASELINE PROVENANCE — bootstrapped FROM CI, deliberately

**The baselines are generated by the CI job itself, not on a developer machine.** Two reasons, and the second
is the one that matters:

1. The local default-project stack could not start — **port 1025 is held by the founder's `tunnex-s141` review
   stack**, which must not be stopped.
2. **More importantly: CI's renderer is the one the baselines must match.** The pinned Playwright image is
   `linux/amd64`; on an arm64 host it runs emulated, and font rasterisation can differ. **A baseline rendered
   on the host and red in CI would leave exactly one escape — widening the threshold — which is how a visual
   suite stops meaning anything.**

**So the first CI run FAILS with "snapshot missing", the actual images are downloaded from the `visual-diff`
artifact, and they land as their OWN COMMIT containing only `.png` files.** That first commit is also the
worked example of the baseline-update rule.
