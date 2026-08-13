# UI REDESIGN + DESKTOP-CLIENT SPLIT — REGISTRATION

**REGISTERED 2026-08-01, founder-directed, DURING the EPIC 13 box-walk. PAPER ONLY.**

> ## ⛔ THIS IS A REGISTRATION, NOT A STORY. NOTHING HERE IS BUILT OR STARTED.
>
> Both items are **decide-items awaiting a commit-one**. Neither has been ruled. A future session reading this
> file has a scope inventory and a question list — **it does not have permission to write code against it.**
>
> **Item A REVERSES A LOCKED DECISION** (`PLAN.md`: *"React + Vite + Tailwind SPA; same bundle reused by the
> Electron renderer"*). It is recorded as a decide-item, **not as a ruling** — the founder wants the split
> considered, and reversing a lock is exactly the kind of thing that must be argued on paper first.

**SOURCE ARTIFACT:** the Claude Design wireframe — 12 dashboard screens plus a desktop-client section — **held by
the founder**, not in this repo. Anything below that cannot be traced to the wireframe or to shipped code is
noted as such.
> **ITEM A IS NOW RULED (2026-08-01) — see its section. ITEM B REMAINS A DECIDE-ITEM.**
>
> Item A reversed a locked decision (`PLAN.md`: *"React + Vite + Tailwind SPA; same bundle reused by the
> Electron renderer"*). It was recorded as a decide-item first and argued on paper before being ruled, which is
> the required order for reversing a lock.

**SOURCE ARTIFACT — NOW COMMITTED: `docs/design/TUNNEX-wireframe-v2.html.txt`** (2.9 MB).

**⚠ THE `.txt` SUFFIX IS DELIBERATE — TO VIEW IT, COPY IT OUT AND RENAME THE COPY TO `.html`:**

```
cp docs/design/TUNNEX-wireframe-v2.html.txt /tmp/wireframe.html && open /tmp/wireframe.html
```

**WHY.** CodeQL classifies by EXTENSION, so as `.html` this file was scanned as JavaScript and raised five
alerts (1 high `js/xss-through-dom`, 4 medium `js/cross-window-information-leak`) against an artifact that is
**never built, never served, and imported by no bundle** — turning the code-scanning aggregate red on PR #44
and, by stacking, #46. **A permanently red security check trains people to ignore red security checks.**

**FOUNDER-RULED, and neither of the two options proposed.** Path-excluding `docs/**` is **broader than the
problem and permanent — a guard-shaped hole nobody looks at again**, and this repo has paid for that shape
once already: an unanchored `secrets/` in `.gitignore` silently kept `apps/api/internal/secrets` OUT OF GIT,
fine on the machine that wrote it and broken on every fresh clone. Per-alert dismissal is honest but
**recurs**, and five "won't fix" clicks train the same reflex as a standing red.

**RENAMING REMOVES THE MISCLASSIFICATION AT ITS SOURCE.** Nothing excluded, nothing dismissed, and the scanner
keeps full scope over everything that ships. **FALLBACK IF THE RENAME DOES NOT CLEAR IT: per-alert dismissal,
stated as such — never the path exclusion.**
 **17 declared screens** —
13 main-nav plus a four-item `OTHER SCREENS` group (including the desktop-client reference). **It is the specification for an entire epic and previously existed in exactly one
place outside version control.**

> **IT IS A CLAUDE DESIGN EXPORT.** A **VISUAL SPECIFICATION** — not editable source, and **not a markup
> specification.** It is rendered HTML embedded in JavaScript (`className=` 0, `class=` 109, all styling inline
> and escaped), so it cannot be imported, extended, or refactored into the app. **It can only be read as a
> picture.** Take its LAYOUT, HIERARCHY and COPY. Take none of its DOM — see consequence 1.

Anything below that cannot be traced to the wireframe or to shipped code is noted as such.

**SEQUENCING (founder-ruled):** EPIC 13 merge → **Item A ruling** → UI redesign → EPIC 11 remainder / BETA
BUNDLE → S12.1 → beta.

---

# ITEM A — THE DESKTOP CLIENT AS A SEPARATE UI

## What is locked today, and what would change

`PLAN.md` locks: **one bundle, two hosts.** `apps/web` is a React + Vite + Tailwind SPA, and the Electron
renderer loads the same build. S6.2 added the runtime branch — `window.tunnex` present → `setApiOrigin` +
bearer transport + *"Sign in with your browser"*.

**The proposal: separate them.** Recorded as a decide-item.

## THE CASE FOR (founder)

**A desktop VPN client and a multi-tenant admin console are different products.**

The client needs: connect/disconnect · tunnel status · assigned IP · split-tunnel · posture state · tray.

The client does not need: the audit viewer · the access-rule builder · K8s clusters · org settings · the ops
page.

**Today a user installs a VPN app and gets an admin console with a Connect button in it.**

## THE WIREFRAME ALREADY SPECIFIES THE CLIENT — this is the scope, captured

**State taxonomy, in full:**

| state | note |
|---|---|
| `CONNECTED` | |
| `CONNECTING` | |
| `DISCONNECTED` | |
| `REVOKED` | **loud** |
| `POSTURE_BLOCKED` | |
| `MIGRATE_FAILED` | copy: *"reconnect to retry"* |
| `AWAITING ADMIN APPROVAL` | |
| `HELPER OUTDATED` | |
| `KILL-SWITCH ENGAGED` | |
| `EXPIRED CREDS` | re-login |

**Tray vocabulary:** solid = connected (handshake fresh) · pulsing = connecting / re-key · grey = disconnected ·
**red badge = revoked or kill-switch, plus an OS notification.**

**The rule it renders:** *"Status is derived from handshake liveness — never green while the tunnel is dead."*
That is S6.3's already-shipped rule, drawn.

**Also specified:** byte counters in/out, duration, packets · Connect / Cancel / Disconnect with in-flight copy
(*"linking peers…"*, *"tearing down tunnel…"*) · split-tunnel toggle.

**MFA policy, stated as UI:** *"MFA touches the client only via browser re-auth: expired credentials →
'Sign in with your browser', never an in-app password field."* This is S5.1/S6.2's loopback flow expressed as a
UI rule.

## EVERY STATE MAPS TO SHIPPED BEHAVIOUR — and that must be VERIFIED, not assumed

Claimed backing: S6.3 (helper + kill-switch) · S6.4 (revocation-aware teardown, tray, notifications) · S7.3
(approval gate) · S7.5.3 (posture) · S7.5.5 (MFA-by-browser).

**AT COMMIT-ONE, CHECK EACH ONE AGAINST CODE.** Anything without a backing mechanism is **render-floor** and is
either cut or explicitly marked roadmap. A UI that can draw a state the product cannot produce is the
render-floor violation this repo already has a law for.

## OPEN QUESTIONS — the founder answers these at commit-one

1. **Does the client show ANY admin surface, or is it connect-only?**
2. **If an admin uses the desktop app, do they get the dashboard, or does it open the browser?**
3. **Does the client keep the SPA's component library, or get its own?**

## COST — price it before ruling

`packages/shared` holds **generated types only** today. Any screen both products need either **lives twice** or
**moves into a shared package** — a real refactor, not a file move. Neither branch is free and the estimate
belongs in the commit-one paper, not after.

## ORDERING — why this is ruled FIRST

**Item A must be ruled BEFORE the redesign's screen list is fixed.** If the client splits, the dashboard
redesign does not need to accommodate it — and **screens do not get designed twice.**
## ✅ RULED — 2026-08-01. THE THREE QUESTIONS ARE ANSWERED. THESE ARE DECISIONS, NOT OPTIONS.

### A1 — THE DESKTOP CLIENT IS **CONNECT-ONLY**

A tray app plus a window: **connect / disconnect · tunnel status · assigned IP · split-tunnel · posture state**,
and the ten-state taxonomy above.

**NOT in the client: no audit viewer · no rule builder · no org settings · no K8s · no user management.**

**Two reasons, both recorded:**

1. **Every comparable product ships connect-only with a web console. The audiences barely overlap** — the person
   who connects a laptop and the person who writes access rules are not usually the same person, and when they
   are, they are not doing both at the same moment.
2. **SECURITY, and this is the load-bearing half.** The client holds a `tnx_` bearer in the OS keychain, injected
   by the main process. **Connect-only means an unlocked laptop exposes a VPN client. Admin-capable means an
   unlocked laptop is a live admin console for the whole org.** The blast radius of a stolen unlocked machine is
   decided entirely by this ruling.

### A2 — ADMIN ACTIONS OPEN THE **SYSTEM BROWSER**. No dashboard is rendered in Electron.

**This EXTENDS an existing rule rather than inventing one.** S5.1's `/cli-auth` already completes authentication
in the system browser, and the wireframe already states that **MFA touches the client only via browser re-auth**
— never an in-app password field.

**One rule, no exceptions:** anything beyond connect-and-status leaves Electron and opens the browser.

### A3 — **OWN COMPONENTS, SHARED TOKENS**

The client gets **its own component set**: roughly five screens with a different interaction model, and the
dashboard's tables, filters, modals and pickers would be **dead weight** in it.

**Colours, typography and spacing move to `packages/shared`** so the two products read as one product.

**Divergent components, single visual identity.**

## CONSEQUENCE — the dashboard redesign's screen list SHRINKS

**The redesign DROPS connect / tunnel / tray entirely.** Those screens belong to the client and are designed
once, there.

**The client build is small** — five screens, own components, shared tokens.

**Neither product designs the other's screens. That was the whole reason Item A had to be ruled first**, and it
is now discharged: Item B's screen list can be fixed without reserving space for a connect flow.

## COST — now settled by A3

`packages/shared` holds **generated types only** today. A3 rules that **design tokens** (colour, type, spacing)
move there — a bounded, additive change — while **components deliberately do NOT**. That avoids the expensive
branch (hoisting a shared component library serving two different interaction models) and accepts the cheap one
(two component sets that look identical because they read the same tokens).

---

# ITEM B — DASHBOARD UI/UX REDESIGN (its own epic, arc-sized)

## Scope

**12 screens:** overview · gateways · sites · access · devices · users · flows · audit · cli · settings · k8s ·
ops. **Plus:** a command palette · edition/role toggles · density modes · toasts with undo.
**17 screens, corrected by measurement** (the earlier figure of 12 came from the props script and omitted
`subnets`):

**MAIN NAV (13):** `overview` · `gateways` · `sites` · **`subnets` (Routed Ranges)** · `access` · `devices` ·
`users` · `flows` (ENT) · `audit` · `cli` · `settings` · `k8s` (ENT) · `ops`

**OTHER SCREENS (4):** `auth` · `desktop` · `license` · `onboarding`

**Plus:** a command palette · edition/role toggles · density modes · toasts with undo.

**REDUCED BY ITEM A's RULING (2026-08-01): connect / tunnel / tray are NOT in this list.** They belong to the
desktop client, which is connect-only and has its own components. The redesign reserves no space for them.

## IT IS FAITHFUL TO THE PLAN — it renders shipped laws as UI

This is the reason it is worth building from rather than restarting:

- the **failed-load triad** on every list (the `loadOne` law)
- *"Client-reported, not attestation"* (S7.5.3)
- *"Not a ClusterIP DNAT — enforcement keys the pre-DNAT VIP"* (S10.3's C1)
- the **withheld destructive control** → *"edit the CR"* (S10.2)
- the one-time join token **shown once**
- **append-only** audit
- **verbatim** refusals

## IT CLOSES FOUR REGISTERED GAPS

1. **domain capture** — API since S2.5, never had a UI
2. **the CLI-sessions panel**
3. **the flow-log viewer** (S7.5.1b)
4. **group-member surface** (Deck-D)

## COMMIT-ONE DECIDE-ITEMS — in the order they constrain each other

### 1. RE-SKIN or RE-ARCHITECTURE

New tokens over existing components, or a new component model? **Tenfold cost difference, and it decides
everything below it.** Rule this first.
### ✅ 1. RULED 2026-08-01 — **IT IS A RE-ARCHITECTURE, NOT A RE-SKIN**

**Measured from the committed artifact, not judged by eye — and RE-MEASURED in-repo rather than accepted.**
A decide-item ruled on numbers the repo cannot check is the same class as *"CI green"* with no sha, which this
project has already ruled against.

**METHOD (it matters here):** the file is **2.9 MB in 405 lines**, so `grep -c` — which counts *lines*
containing a match — undercounts by orders of magnitude. All figures below are **occurrence** counts
(`grep -o <pattern> | wc -l`).

| measure | as ruled | **measured** | note |
|---|---|---|---|
| `<div` | 1,015 | **1,018** | |
| inline `style` attributes | 2,129 | **2,134** | `style=`, almost all **escaped** (`style=\"`) — the HTML is embedded inside JS string literals, which is why a naive `style="` search returns **1** |
| `<button` | 1 | **1** | ✅ exact |
| `<table` | 0 | **0** | ✅ exact |
| `<label` | 0 | **0** | ✅ exact |
| `<nav` | 0 | **0** | ✅ exact |
| `<select` | 0 | **0** | ✅ exact |
| **`aria-` anywhere** | 0 | **0** | ✅ exact |
| `backdrop-filter` | 241 | **242** | layered glassmorphism — a RENDERING MODEL, not a colour choice |
| custom typography | 890 | **961** | Instrument Sans **542** + JetBrains Mono **419** |
| screens | 12 | **17** | **CORRECTED BY MEASUREMENT** — 13 main-nav entries + a four-item `OTHER SCREENS` group. The "12" came from the props script and **omitted `subnets` (Routed Ranges) entirely**, which is a real main-nav screen. Still a **CONSOLIDATION** against the current 18 pages — the shape holds, the count did not |

**THE CORRECTIONS DO NOT MOVE THE RULING, AND THE LOAD-BEARING FIGURES ARE EXACT.** Every count that carries
the accessibility argument — the four zeros, the zero `aria-`, and the single `<button>` — matched exactly. The
three that drifted (1,015→1,018 · 241→242 · 890→961) differ by under 8% and change nothing: **the ruling stands
on the shape, not the arithmetic.**

**Two further facts the re-measurement surfaced:** `className=` is **0** and `class=` is **109**, with **5**
`<style>` blocks — so this is **rendered HTML embedded in JavaScript**, not React source. It cannot be imported,
extended, or refactored into the app. **It can only be read as a picture**, which is the strongest possible
argument for the visual-specification-not-markup-specification ruling below.

**And components that do not exist in the product AT ALL:**

- a **command palette** (`cmdk`, with `g-o` / `g-g` / `g-s` keyboard routing)
- **density modes** (cozy / compact) — every list and table gains a size axis
- **theme × palette toggles** (dark / mono / violet)
- **toasts with UNDO** — an action-reversal pattern nothing in the product has

**Each is a new component model, not a variant of an existing one.** That settles decide-item 1 on the
**tenfold** branch.

---

## CONSEQUENCE 1 — A HARD REQUIREMENT: **THE REDESIGNED UI MUST SHIP SEMANTIC, ACCESSIBLE MARKUP**

**Buttons are `<button>`. Tables are `<table>`. Inputs have `<label>`. Navigation is `<nav>`. Interactive
elements carry accessible names.**

**Two reasons, and the second is not optional:**

**(a) THE COMPONENT TEST TIER QUERIES BY ROLE AND ACCESSIBLE NAME.** In a markup model with **one `<button>`
among 1,015 divs** there are no roles to query, and **every test in the tier becomes UNWRITABLE — not broken,
unwritable.** The tier cannot be ported to div soup; it can only be deleted.

**(b) 0 `aria-` attributes and 0 semantic landmarks is a WCAG 2.1 AA failure on its face.** Keyboard
navigation, screen readers and focus order all depend on the elements the wireframe replaced with divs.
**Shipping it as drawn would make the product LESS ACCESSIBLE THAN IT IS TODAY** — a regression delivered as an
improvement.

> ### THE WIREFRAME IS A VISUAL SPECIFICATION, NOT A MARKUP SPECIFICATION.
>
> Its inline-styled div soup is a **Claude Design output artifact**. **Take the LAYOUT, the HIERARCHY and the
> COPY from it. Take NONE of its DOM.**

**ACCESSIBILITY GATE IN THE DEFINITION OF DONE**, using the `design:accessibility-review` skill. **A screen that
cannot be tested by role is not done.**

## CONSEQUENCE 2 — THE TIER'S QUERY STRATEGY, DECIDED NOW (binds `story/web-component-tests` from slice 1)

1. **QUERY BY ROLE + ACCESSIBLE NAME.** Never test-ids, never class names, never DOM structure. **It is the
   most rewrite-resistant selector that exists:** it survives any markup change that preserves semantics, and
   **a redesign that breaks it has broken accessibility too — which is a finding, not test debt.**
2. **MOCK AT THE NETWORK BOUNDARY** (`api.GET` / `api.POST`), never at the component boundary. **That layer
   does not change in a redesign.**
3. **ASSERT DECISIONS, NOT RENDERING** — the D1 ruling, restated here because it is what makes the tier survive
   a re-architecture at all.
4. **NO TEST MAY ASSUME A VIEWPORT** (added with the responsive decide-item). **No assertion may depend on
   layout, column order, or an element being visible only at one width.** The responsive item introduces five
   widths; a test that breaks at a breakpoint **was testing the layout, not the decision** — and it would then
   be rewritten to pass, destroying exactly the signal consequence 3 exists to preserve. Cheap, because a role
   does not move when a column does.
5. **A `waitFor` MUST COVER EVERY ELEMENT THE ASSERTIONS TOUCH** — never the first one that happens to appear.
   **Earned by the gate on the first slice run under it:** Sites' test 1 waited on the PENDING chip and then
   asserted the APPROVED one, which renders later, so it raced ahead and failed — while its SIBLING test, over
   the *same two elements*, passed purely because it happened to wait on the later one. **TWO TESTS OVER THE
   SAME ELEMENTS DISAGREEING IS THE TELL.** It is the **async form of the leaked-render mechanism**
   (`docs/laws.md`): *a correct assertion made against a tree that is not yet — or no longer — the tree it
   describes.*

### THE BOUNDARY, FOUND BY AUDITING SLICE 1 AGAINST THIS RULE

Slice 1 uses **5 role queries — all compliant** (every interactive control). It also uses **11 text queries**,
for badges, status labels and empty states. **None is a test-id, class name or DOM assertion** — they assert
user-visible copy, which is rewrite-resistant for the same reason.

**But they are not role-based, and the reason is exactly consequence 1: those elements carry NO ROLE TODAY.**
A `<span>` holding "revoked" or "certificate expired — re-enroll this gateway" is unreachable by role because
the current markup gives it none.

**RULING: `getByText` is permitted ONLY for content that carries no role, and every such use is a MARKER that
the element should gain one in the redesign** — `role="status"` for badges, `role="alert"` for error text.
**It is a finding-generator, not an exemption.** When the redesign gives those elements roles, the queries
convert and the tier gets stricter for free.

## CONSEQUENCE 3 — **THE REDESIGN IS A REFACTOR UNDER A GREEN SUITE.** This is the tier's PURPOSE.

**The redesign must be performed with the component tests PASSING THROUGHOUT — not rewritten and re-tested
afterwards.**

The tier then proves the redesign **did not change BEHAVIOUR while changing everything else.**

**A test that has to be rewritten to pass is a SIGNAL that the redesign changed a decision** — which is either
a bug, or a deliberate change that needs recording. Either way it is information, and rewriting the test
destroys it.

**This inverts the tier's value:** it is not insurance against the redesign breaking things. It is the
instrument that makes a re-architecture *reviewable at all*.

## CONSEQUENCE 4 — SIZING, STATED HONESTLY

**The redesign is an EPIC, comparable to S8.2's arc — not a story.** Re-architecture is the tenfold branch of
decide-item 1 and the estimate must say so out loud.

**And the component test tier is now LOAD-BEARING rather than prudent.** A re-architecture with no behavioural
guard on **the least-guarded surface in the repo** is how **4-of-15 findings becomes 15-of-15.**

### 2. COMPONENT TEST TIER — lands FIRST or in the same story, NEVER after

**The S11 ledger: zero component coverage on the web app, and 4 of 15 walk findings lived there.**

A redesign is **the largest change that surface will ever take, landing on the least-guarded code in the repo.**
Deferring the test tier to "after the redesign" means the redesign is unguarded exactly when it is most
dangerous.

### 3. RENDER-FLOOR AUDIT, PER SCREEN — every panel names its endpoint or is marked roadmap

**TWO KNOWN VIOLATIONS ALREADY IN THE WIREFRAME:**

- **"Fleet risk" on the gateways screen** — risk scoring is a **Tier-3 name in the competitive ledger,
  explicitly NOT BUILT.**
- **"Site-Link Throughput" with a Jul 13-18 axis** — that is a **rate time-series.** S8.3 ruled metrics **L1 =
  cumulative-since-handshake ONLY**, *"no rate graphs, no sampling implied"*; time-series is **S11.1's** job.
  **That chart is L3 drawn as L1.**

**AUDIT THE REST THE SAME WAY:** System Health · Peer Connection Status · Network map · HA Hub Set · the ops
replica/leader/backup panels.

### 7. RESPONSIVE UI — mobile · tablet · laptop · desktop · large (REGISTERED 2026-08-01, founder-directed)

**The dashboard must work across five widths. NOT BUILT, NOT RULED — a decide-item.**

#### THE PROBLEM, MEASURED — and it is worse than "underspecified"

| measure | count | meaning |
|---|---|---|
| **`@media` in the whole 2.9 MB artifact** | **1** | and it is **`prefers-reduced-motion`** — **NOT A BREAKPOINT.** There are **ZERO width-based media queries** |
| `min-width:1280px` on the ROOT layout | **1** | **a hard desktop floor, asserted positively** |
| `grid-template` declarations | 21 | fixed column definitions, no responsive variants |
| inline `style` attributes | 2,134 | **a `style` attribute CANNOT CARRY A MEDIA QUERY AT ALL** |
| `clamp()` | **0** | no fluid typography or spacing anywhere |
| `min-width:0` | 104 | the flexbox min-content idiom — **not** responsiveness; counted so it is not mistaken for it |

**THE ARTIFACT DOES NOT MERELY OMIT RESPONSIVE BEHAVIOUR — IT DECLARES A 1280px MINIMUM WIDTH ON THE ROOT
ELEMENT.** Below that it does not reflow; it overflows. That is a positive assertion of desktop-only, not a gap.

**CONSEQUENCE: every screen's breakpoint behaviour is NEW DESIGN WORK, not an adaptation of what was drawn.**
There is nothing to adapt. The wireframe cannot express a breakpoint through the mechanism it is built from.

#### THE MULTIPLICATION — stated now so it is not discovered later

**5 widths × 3 themes × 2 densities = 30 visual states per screen.** Across 17 screens that is **510 states**.

**DECIDE-ITEM 5 (theme × palette × density) MUST NOW BE RULED TOGETHER WITH THIS ONE, not separately.** They
multiply; ruling them apart prices neither correctly.

**Founder's recommendation, to weigh at commit-one: CUT DENSITY.** At mobile width *compact* and *cozy* are the
same decision made twice — the viewport has already made it.

#### TWO QUESTIONS FOR THE FOUNDER AT COMMIT-ONE

**1. Is mobile the FULL dashboard, or a SUBSET?** Approving a device queue and reading gateway health work on a
phone. **An access-rule builder with source, destination, port scope and expiry does not — and a bad mobile rule
builder is WORSE THAN NONE, because it is a security surface where a mis-tap grants access.**

**2. Who is the mobile user?** If it is **on-call triage** — check health, approve a device, revoke one — that
is a small, well-defined subset with real value. If it is **"the whole console, smaller,"** that is a much
larger build for a use case **no prospect has asked for.**

#### ⛔ THE BOUNDARY — THREE DIFFERENT THINGS ALL SAY "MOBILE". Name them separately.

| | what it is | status |
|---|---|---|
| **THIS ITEM** | **DASHBOARD-ON-A-PHONE** — the admin console at narrow widths | **registered here, not ruled** |
| **the desktop client** | Item A — **connect-only**, tray + window, own components | **RULED**, and it is not a browser surface |
| **native mobile** | **EPIC M, PARKED.** Mobile *connectivity* ships via the official WireGuard apps | parked; positioning line already agreed |

**Confusing them is how a registered admin-console breakpoint becomes an unplanned native app.**

### 4. BULK MULTI-SELECT ON DESTRUCTIVE VERBS

**Bulk revoke is a different audit and confirmation problem than single revoke.** New security surface; needs
its own ruling, not an inherited one.

### 5. THEME × PALETTE × DENSITY

**Three toggles multiply the visual test surface.** Scope hard or cut to one.

### 6. EDITION GATING BEHIND ONE SEAM

The wireframe reads edition from `/meta`. **S12.1 replaces build-tag gating with a runtime `LicenseManager`.**

**If every gating decision routes through ONE hook, S12.1 rewrites the hook and nothing else.** This is why the
redesign **does NOT need to wait for S12.1** — and why the seam is **binding**, not advisory.

## ONE COPY FIX — RECORD IT NOW SO IT CANNOT SHIP

The wireframe has `editionTag: 'Free plan · cloud-hosted'` for the open edition.

**BOTH EDITIONS ARE SELF-HOSTED. The difference is FEATURES, not HOSTING.** *"cloud-hosted"* contradicts the
entire wedge — fully self-hosted, zero SaaS in the trust path, air-gappable — **and it would end up in a launch
screenshot.**

---

# SEQUENCING AND ITS INTERACTIONS

**EPIC 13 merge → Item A ruling → UI redesign → EPIC 11 remainder / BETA BUNDLE → S12.1 → beta.**

**The redesign does NOT wait for S12.1**, on the strength of decide-item 6.

**CONTENT-FREEZE INTERACTION:** the site's screenshots come from this UI. The BETA BUNDLE's emit-point **(b)** is
*"EPIC 11 close → CONTENT FREEZE."* **Redesigning BEFORE the joint launch is better than after** — otherwise the
launch ships screenshots of a UI that is about to change.

# TOOLING NOTE — for whoever builds this

**Visual iteration belongs in Claude Design; implementation belongs in Claude Code.** Iterating on renders inside
Code burns budget on loops Design does natively. Bring a settled wireframe to the implementation session.
