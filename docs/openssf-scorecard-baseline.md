# OpenSSF Scorecard — BASELINE

**Same discipline as `docs/S11-security-baseline.md`: a measured result, recorded WITH its caveats, so the
number is readable by someone who did not run it.**

| | |
|---|---|
| **AGGREGATE** | **3.7 / 10** |
| tool | Scorecard **v5.1.1-45-g40bbc9c9** (`gcr.io/openssf/scorecard:stable`) |
| target | `github.com/iotunnex/tunnex` |
| measured | **2026-08-01**, locally, `main` at **`a25713e`** |
| **PUBLISHED?** | **NO** |

---

# ⛔ THE REAL FINDING IS NOT THE SCORE, AND NOT THE 71. READ THIS FIRST.

> ## **THE JAVASCRIPT DEPENDENCY SURFACE HAS NO SCANNING AT ALL.**

**Not "unreached" — UNMEASURED.** Searched the entire `.github/` tree on 2026-08-01:

| candidate | present? |
|---|---|
| `npm audit` / `pnpm audit` | **NO** |
| `osv-scanner` | **NO** |
| `.github/dependabot.yml` | **NO** |
| CodeQL `javascript-typescript` | present — scans **OUR SOURCE for security bugs**, *not* dependency advisories |
| Trivy | present — but **`image-ref: tunnex-api:scan`**, the **Go API image only**. Not the web bundle. Not the Electron client. |

**The distinction is the whole point: an UNREACHABLE vulnerability has been examined and dismissed. An
UNMEASURED one has never been looked at.** The 44 npm advisories are the second kind.

## THE BUYER-FACING SENTENCE — verbatim, because it is honest and sayable

> ### *"Our Go dependencies are reachability-gated on every PR; our JavaScript dependencies currently are not."*

**That is the thing to fix.** The score is a symptom; this is the finding.

---

## ⚠ THERE IS NO PUBLIC SCORE, AND THAT IS A DELIBERATE SETTING

`security.yml` runs the job with **`publish_results: false`**, so **`api.securityscorecards.dev` returns
nothing for this repo** — it was queried and returned empty. The job runs on every push to `main`, asserts its
SARIF is non-empty (the O-1 guard), and uploads to code scanning.

**3.7 was obtained by running the scanner locally.** It is **re-earned by any change** to the repo, its
workflows, or its dependencies — like every other measured result here, it is a **dated fact, not a property**.

---

# ⛔ READ THE TRIAGE BEFORE THE NUMBER — 3.7 IS NOT "THREE-POINT-SEVEN PROBLEMS"

**Ten checks score below 10. FOUR are artifacts of being a young solo repo, ONE is a decision already ruled,
ONE is accepted with reason, and THREE are genuinely actionable.**

## FULL MARKS — 6 checks

`CI-Tests` 10 · `Dangerous-Workflow` 10 · `License` 10 · `Packaging` 10 · `SAST` 10 · `Security-Policy` 10.
`Binary-Artifacts` 9.

## GROUP 1 — ARTIFACTS OF A YOUNG SOLO REPO (4). **Nothing to fix; no code change would move them.**

| check | score | why it is an artifact |
|---|---|---|
| `Maintained` | 0 | *"project was created in the last 90 days"* — **a clock, not a practice** |
| `Contributors` | 0 | wants contributors from **2+ organizations** |
| `Code-Review` | 0 | *"0/3 approved changesets"* — **what a solo founder's PRs look like**; there is no second person to approve |
| `CII-Best-Practices` | 0 | no OpenSSF **badge** applied for — an application, not a property of the code |

**These will move on their own, or with the founder-ledger items (design partners, entity formation), not with
engineering effort.**

## GROUP 2 — ALREADY RULED, DEFERRED ON A NAMED TRIGGER (1)

| check | score | disposition |
|---|---|---|
| `Signed-Releases` | 0 | **This is S6.5b.** Deferred on its NAMED trigger — *public beta OR first outside-circle distribution* (Windows EV additionally waits on legal-entity formation). **Scorecard is re-reporting a decision already made**, not finding something new. |

## GROUP 3 — ACCEPTED WITH REASON (1). **Not a gap. Do not re-open it.**

### `Branch-Protection` — 3/10

> *"branch protection is not maximal on development and all release branches"*

**BOTH deductions are deliberate:**

- **`enforce_admins: false` is THE ADMIN ESCAPE HATCH, and it is why a solo founder can merge at all.**
  Recorded at S6.0b when protection was configured and re-confirmed at S7.5.3. With it enabled, a
  single-maintainer repo cannot land its own reviewed-by-nobody PR — the protection would lock the only person
  who can unlock it.
- **Required reviews are STRUCTURALLY UNAVAILABLE to a solo repo** — the same root as `Code-Review` 0/10 above.

**What IS enforced, and was verified immediately before the EPIC-14 merges:** `required_linear_history: true` ·
required checks `gates` + `client (macos-latest)` + `client (windows-latest)` · `strict: true` ·
`allow_force_pushes: false`.

**RECORDED SO A FUTURE SESSION DOES NOT RE-DISCOVER IT AS A FINDING** and spend time on a decision already
made. **Revisit only when the repo has a second maintainer** — at which point `enforce_admins` becomes
affordable and both checks move together.

## GROUP 4 — GENUINELY ACTIONABLE (3). **REGISTERED AS DECIDE-ITEMS. NOT BUILT.**

### 4a. `Pinned-Dependencies` — 0/10 · **DECIDE-ITEM**

> *"dependency not pinned by hash detected — score normalized to 0"*

GitHub Actions are referenced **by tag** (`actions/checkout@v4`, `ossf/scorecard-action@v2.4.0`), not by commit
SHA. A tag is **mutable**: whoever controls the action can repoint it, and a re-run picks up different code.

**⚠ THE INCONSISTENCY IS THE ARGUMENT, and it should be stated plainly: PINNING IS ALREADY A DISCIPLINE IN
THIS REPO.** `apps/helper/internal/wfp/` is a **pinned, diverged fork** of `wireguard/windows` carrying an
explicit **re-diff obligation on every upstream bump** (VENDOR.md). The project already accepts the cost of
pinning where it judged the risk real. **So the CI surface is not unconsidered — it is inconsistent with a
standard the repo already holds itself to.**

**Why it is a decide-item and not a fix:** SHA-pinning changes how CI is allowed to run and **adds a standing
maintenance obligation** (pins must be bumped, or they rot into unpatched actions — the same trade already
paid for `internal/wfp`).

### 4b. `Token-Permissions` — 0/10 · **DECIDE-ITEM**

> *"detected GitHub workflow tokens with excessive permissions"*

Wants **`contents: read` at the top level**, with write granted **per job**. A compromised action currently
inherits more than it needs.

**Why it is a decide-item and not a fix:** it changes what every job is permitted to do. Getting it wrong
breaks CI in a way that looks like a flake, and several jobs legitimately need `security-events: write` and
`id-token: write`.

### 4c. **NO JS DEPENDENCY SCANNING** — the finding behind `Vulnerabilities` 0/10 · **DECIDE-ITEM**

**The check reports *"71 existing vulnerabilities"*. The decide-item is not the 71** — see the analysis below.
It is that **nothing scans the JavaScript dependency surface at all.**

**The cheapest honest step is MANIFEST-LEVEL scanning** (`osv-scanner`, or Dependabot) so the 44 become
*measured*. **PARITY WITH GO IS NOT ACHIEVABLE**: no JS tool does what `govulncheck` does — call-graph
reachability against a curated advisory database. **The achievable goal is VISIBILITY, and the honest framing
should say so rather than implying parity.**

**Why it is a decide-item and not a fix:** a manifest-level scanner on this repo will report **44 findings on
day one**, most of them build-tooling. **Turning it on without first ruling what BLOCKS and what ADVISES
creates a permanently red check** — and `security.yml`'s own header already names that failure (S11-1/O-1: *a
job configured not to matter let a regression merge and then excused it*). **The ruling has to come first.**

---

## ⛔ ALL THREE ARE `security.yml` CHANGES — THEY LAND AS ONE HARDENING SLICE, NOT PIECEMEAL

**4a, 4b and 4c all modify the same file, and two of them change how every job is permitted to run.** Landing
them separately means **three CI-breaking-shaped changes on three different days**, each one hard to attribute
when something goes red.

**They also interact.** SHA-pinning (4a) changes every `uses:` line; token scoping (4b) changes every
`permissions:` block; adding a scanner (4c) adds a job needing both. **Doing them together means the workflow is
reasoned about once, with one CI run to judge the result.**

**TRIGGER (shared): the next `security.yml` change, or an S11-class hardening pass.**

---

# THE 71 — MEASURED, BECAUSE A BARE NUMBER IS FINDABLE BY A PROSPECT AND WE COULD NOT ANSWER IT

**Resolved via `api.osv.dev` per advisory (2026-08-01): 27 Go + 44 npm, across 6 Go packages and 15 npm
packages.** (A few IDs are `GO-… / GHSA-…` pairs, so the two counts overlap the raw 71.)

## DIRECT vs TRANSITIVE

| ecosystem | direct | transitive |
|---|---|---|
| **Go** | **5 packages** — `golang.org/x/crypto` (14 advisories) · `x/net` (9) · `kin-openapi` (2) · `x/oauth2` (1) · `x/sys` (1) | **0 declared-indirect**; plus **`stdlib`** (1), the Go toolchain, in no `go.mod` |
| **npm** | **5** — `electron`, `postcss`, `vite`, `vitest` *(all devDependencies)* · **`react-router-dom`** *(the ONLY runtime direct one)* | **10** — `esbuild`, `tar`, `js-yaml`, `brace-expansion`, `app-builder-lib`, `builder-util-runtime`, `fast-uri`, `launch-editor`, `react-router`, `vite-plus` |

## ⛔ THE REAL FINDING IS NOT 71. IT IS THAT **44 OF THEM HAVE NO REACHABILITY CHECK ANYWHERE — AND NO DEPENDENCY SCAN AT ALL.**

**`govulncheck` IS GO-ONLY BY CONSTRUCTION.** It analyses **Go** call graphs; `security.yml:41` runs it over a
matrix of exactly five Go modules. **It does not look at JavaScript or TypeScript, and never could.**

**Searched the entire `.github/` tree — the JS/TS side has NO dependency scanning of any kind:**

| candidate | present? |
|---|---|
| `npm audit` / `pnpm audit` | **no** |
| `osv-scanner` | **no** |
| `.github/dependabot.yml` | **no** |
| CodeQL `javascript-typescript` | present — but it scans **OUR SOURCE for security bugs**, not dependency advisories |
| Trivy | present — but `image-ref: tunnex-api:scan`, **the Go API image only**; not the web or client bundles |

**So the 44 npm advisories are UNMEASURED, not merely unreached.** The distinction matters: an unreachable
vulnerability has been *examined and dismissed*; an unmeasured one has *never been looked at*.

**THE HONEST SENTENCE FOR A PROSPECT:** *"Our Go dependencies are reachability-gated on every PR. Our
JavaScript dependencies currently are not."*

**MITIGATING, and it should be said in the same breath: 4 of the 5 DIRECT npm packages are devDependencies**
(`electron`, `postcss`, `vite`, `vitest`) — **build-time, not shipped in the SPA bundle**. Only
`react-router-dom` is a runtime dependency.

## ⚠ THE MITIGATION RESTS ON AN UNCHECKED PREMISE — **mechanism ⑦'s shape**

**The reassuring sentence above is *"4 of the 5 direct npm packages are devDependencies, so they are not
shipped."* THAT REASONING RESTS ON PACKAGE ROLE, NOT ON THE BUNDLE GRAPH — and the two are not the same
thing.**

**A TRANSITIVE DEPENDENCY OF A devDependency CAN STILL BE BUNDLED.** Vite and its plugin chain pull packages
that are *build-time by role* and *runtime by inclusion* — a polyfill, a helper, an inlined shim. **`devDependency`
describes where a package is DECLARED, not where its code ENDS UP.**

**So the state is exactly [[⑦ THE SEVENTH VACUITY MECHANISM]]: A CLAIM WITH NO CHECK READS EXACTLY LIKE A CLAIM
THAT IS KEPT.** Nothing in this repo compares "what we assume ships" to "what actually ships", so the
mitigation cannot currently be wrong — it can only be **undiscovered**.

**RECORDED AS AN UNCHECKED PREMISE, NOT AS A MITIGATION.** Several of the transitive packages (`tar`,
`js-yaml`, `brace-expansion`) are *classic* build-tool dependencies — **and *classic* is not *measured*.**

**THE VERIFICATION, REGISTERED AND NOT DONE:** build the SPA and **enumerate what actually ships** — resolve
the production bundle's real module graph and intersect it with the 15 advisory-bearing packages. **Until that
runs, "not shipped" is an assumption wearing a fact's clothing.**

## THE 27 GO ADVISORIES — NO MODULE-LEVEL COVERAGE HOLE

**The repo contains exactly five `go.mod` files, and ALL FIVE are in the govulncheck matrix:** `apps/api`,
`apps/cli`, `apps/helper`, `apps/node`, `apps/operator`. Every advisory-bearing package resolves into one or
more of them — `x/crypto` → api+helper · `x/net` → helper+node+operator · `x/sys` → api+node+operator ·
`x/oauth2` → api+operator · `kin-openapi` → api.

**With `govulncheck` exit=0 on all five, those 27 are DECLARED-BUT-UNREACHABLE** — which is exactly what the
workflow's own comment claims the tool buys: *"a finding here is one we can actually fix, never inherited
noise."* **The claim holds, and it was checked rather than assumed.**

### ⛔ PERMANENT CAVEAT — QUOTE THIS WHENEVER "UNREACHABLE" IS QUOTED

> ## **`govulncheck`'s VERDICT IS A CLAIM ABOUT THE CALL GRAPH IT CAN SEE.**
> ## **REFLECTION, `cgo` AND DYNAMIC DISPATCH ARE WHERE REACHABILITY ANALYSIS IS WEAKEST.**
> ## **"UNREACHABLE" IS STRONG EVIDENCE. IT IS NOT PROOF.**

**THIS IS NOT A FOOTNOTE AND MUST NOT BECOME ONE.** *"Unreachable"* **hardens into a guarantee the moment it is
repeated without the caveat** — and it will be repeated, because it is the reassuring half of the story and the
one a trust page wants.

**SAME CLASS AS TWO FAILURES THIS PROJECT HAS ALREADY PAID FOR:** *"CI green"* without a **sha**, and
*"`make web-gate` passed"* without its **composition**. In all three, a **precise, true, qualified** statement
loses its qualifier in transit and arrives as a **broader claim nobody ever made**. **The qualifier is the
claim; a compressed version of it is a different claim.**

**So: `govulncheck` exit=0 means "no path found by a static analyser that cannot see every path."** It does not
mean the code is not there, and it does not mean it can never be called.

## WHY SCORECARD AND `govulncheck` DISAGREE, AND WHY BOTH ARE RIGHT

**They answer different questions:**

- **Scorecard/OSV** asks *"does the MANIFEST declare a version with a known advisory?"* → **71**
- **`govulncheck`** asks *"is vulnerable code REACHABLE from our call graph?"* → **0**

**Neither is wrong and neither supersedes the other.** This is the repo's own
*[[unit tests prove behaviour, not reachability]]* note **running the other way**: there, a test proved
behaviour without proving the path was reachable; here, a scanner proves a *declaration* without proving the
path is reachable. **The same gap between "it is present" and "it is reached", read from opposite ends.**

---

# TRIGGERS

- **4a `Pinned-Dependencies` · 4b `Token-Permissions` · 4c NO JS DEPENDENCY SCANNING** — **the next
  `security.yml` change, or an S11-class hardening pass.** All three are decide-items, not chores, and
  **ALL THREE LAND TOGETHER AS ONE HARDENING SLICE** — same file, interacting changes, one CI run to judge.
- **`Signed-Releases`** — already carried by **S6.5b**'s trigger.
- **`Branch-Protection`** — **revisit only on a second maintainer.**
- **THE UNCHECKED PREMISE (what actually ships)** — build the SPA, enumerate the production bundle's real
  module graph, intersect with the 15 advisory-bearing packages. **Same trigger.** Until it runs, *"not
  shipped"* is an assumption wearing a fact's clothing.

---

# ⚠ UNRELATED, REGISTERED HERE BECAUSE IT WAS FOUND THE SAME DAY — THE `NET` DEFECT IN THE MAKEFILE

**`Makefile:80` is `NET := tunnex_default`, HARDCODED**, while the same targets invoke `$(COMPOSE)`, which
**does** respect `COMPOSE_PROJECT_NAME`.

**SO ONE TARGET ADDRESSES TWO STACKS.** Running `COMPOSE_PROJECT_NAME=tunnex-s141 make seed`:

```
docker compose up -d --wait postgres     -> tunnex-s141-postgres-1   ✅ right project
docker run --network tunnex_default ...  -> tunnex-postgres-1        ❌ the OTHER project's database
```

**The output shows the RIGHT container going healthy while the work happens on the wrong one.** Same class as
everything else in this session: **the visible signal describes one thing and the operation touches another.**

**FOUND LIVE:** a seed run against a two-stack machine hit the wrong database and was stopped only by the
seeder's own `seed_refused` guard (`real_orgs: 6690`). **The guard held — against the wrong database.**

**WORKAROUND — AND THE FORM MATTERS, WHICH IS ITS OWN TRAP:**

```bash
COMPOSE_PROJECT_NAME=tunnex-s141 make seed NET=tunnex-s141_default   # ✅ works
NET=tunnex-s141_default COMPOSE_PROJECT_NAME=… make seed             # ❌ silently ignored
```

**`NET=x make seed` sets an ENVIRONMENT variable, and a Makefile's `NET := …` OVERRIDES the environment.
`make seed NET=x` is a COMMAND-LINE variable, which overrides the Makefile.** Same characters, opposite
precedence, decided entirely by which side of `make` they sit on — and the wrong form produces **no warning**,
just the default network.

**This cost a second failed seed run against the wrong database.** The workaround was verified with
`make -n seed NET=…` (the correct form) and then written down in the other form: **the verification was right
and the transcription was wrong, which is why it read as checked.**

**FIX:** `NET := $(or $(COMPOSE_PROJECT_NAME),tunnex)_default` — removing the need for either form.

**NOT FIXED — registered. TRIGGER: the next Makefile change, or the next time a second stack is needed.**
