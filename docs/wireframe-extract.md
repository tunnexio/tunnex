# THE DESIGN SPECIFICATION — sourced from the handoff README

> ## **SOURCE OF TRUTH: `~/Downloads/design_handoff_tunnex_dashboard/README.md`**
> **28 KB, authored by the designer, with an exact token table. It SUPERSEDES the reverse-engineering that
> produced the first version of this file.**

**The handoff contains three things that matter and one that does not:**

| file | what it is | usable? |
|---|---|---|
| `README.md` | **the specification** — tokens, layout, screens, interaction contract | **YES — source of truth** |
| `Tunnex Wireframes.dc.html` | the **unbundled source prototype**, 412 KB, all 18 screens + logic | **reference only** |
| `TUNNEX Wireframe.html` | self-contained bundle — **byte-identical (md5) to `docs/design/TUNNEX-wireframe-v2.html.txt`** | **reference only** |
| `support.js` | 69 KB generated `dc-runtime`, *"do not edit"* | **NO — prototype scaffolding** |

## ⚠ HOW THIS FILE CAME TO EXIST — kept, because the failure it records is the point

**Four slices were built from a SUMMARY of the wireframe rather than the wireframe**, because a
session-scoped founder instruction (*"do not read it for design detail"*) was never lifted after a later ruling
required reading it. **The result passed every automated gate — 388 tests, green CI, mutation proofs — and did
not look like the design.** That produced the SECTION PROTOCOL (`docs/EPIC-14-ui-redesign.md`).

**The first version of this file was reverse-engineered from the bundle.** It got the layout, glass recipe and
type scale right, and got **two things wrong** that the README corrects — both recorded below rather than
quietly overwritten.

---

# ⚠ TWO CORRECTIONS TO THE REVERSE-ENGINEERED VERSION

## 1. `#6E9C7C` IS NOT "THE ACCENT" — it is the `ok` STATUS COLOUR

The status set is **deliberately desaturated**: `#6E9C7C` ok · `#C39A4E` warn · `#C77474` error · `#858582`
neutral/unknown. **Mislabelling it as the accent would have made every "live" indicator the brand colour** —
which is the `ok`-reservation violation (S4.4 decision f) arriving through a palette rather than a use-site.

## 2. **THERE ARE TWO PALETTES. THE VIOLET WAS NEVER A MISTAKE.**

The source prototype's own state:

```js
pal: (['mono','violet'].includes(localStorage.getItem('tnx-pal')) ? … : 'mono')
```

**MONO IS THE DEFAULT**, which is why the rendered bundle contains no violet and the reverse-engineered scan
found none. The README documents the **violet** as the accent: **`#7C5CFC`**, used for nav-active (13% alpha),
row selection (14%), row hover (6%), focus ring `#A78BFA`.

### ⛔ AND THE APP ALREADY SHIPS `#7c5cff` — ONE HEX DIGIT FROM THE DESIGN'S `#7C5CFC`

**FOUNDER'S CORRECTION TO THEIR OWN FRAMING, RECORDED AS RULED:** S14.1 did **not** carry a wrong colour
forward. **It shipped the design's violet, near-exactly, out of the old config by coincidence.**

> **Two things being right for the wrong reason is still worth writing down.** The token set matched the
> specification while nobody had read the specification — so the match was luck, and luck is not a property.
> Had the design's accent been anything else, the same process would have produced the same confident result.

---

# ⚖ RULING 1 — **MONO IS THE DEFAULT THEME. VIOLET IS THE SECOND.**

Both are faithful; **Mono is the prototype's own default and the palette every screenshot has been judged
against.** S14.1 already built the n-theme mechanism with two themes shipping — **this is exactly the seam it
was built for, so it costs nothing structural.**

**The violet theme cites the README: `#7c5cff` → `#7C5CFC`.** One digit — and the token set now cites the
design instead of resembling it.

---

# 1. COLOUR — dark (default), from the README's table

| role | value |
|---|---|
| app background | **`#0A0A0A`** |
| card surface | `rgba(31,31,31,.72)` + `blur(24px) saturate(140%)` |
| card border | `rgba(255,255,255,0.14)` |
| inset / sub-panel | `rgba(18,18,18,.72)`, border `rgba(255,255,255,0.09)` |
| code block | `#101010`, border `#2E2E2E` |
| badge background | `#1A1A1A`, border `#2E2E2E` |
| row divider | `#1A1A1A` · header divider `#1E1E1E` |
| light-mode background | `#EEEEF1` |

**Text ramp (8 named tones):** `#F5F5F5` headings · `#EDEDEB` primary · `#D6D6D2` emphasis · `#A9A9A6` body ·
`#858582` secondary · `#5E5E5B` tertiary · `#4A4A48` faint · `#454542` disabled.

**Status:** `#6E9C7C` ok · `#C39A4E` warn · `#C77474` error · `#858582` neutral. **Never saturated alert
colours.**

**Mono interaction colours** (measured from the source): focus ring `2px solid #C9C9C4` at 2px offset ·
nav-active `rgba(255,255,255,.12)`.

## ⚖ RULING 2 — CONTRAST: TERTIARY AND FAINT COLLAPSE TO `#858582`

**Measured with S14.1's own gate against the composited card surface (`rgba(31,31,31,.72)` over `#0A0A0A`):**

| tone | ratio | verdict |
|---|---|---|
| `#F5F5F5` … `#A9A9A6` | 15.8 … 7.3 | PASS |
| `#858582` secondary | **4.65** | PASS — barely |
| **`#5E5E5B` tertiary** | **2.65** | ⛔ **FAIL → `#858582`** |
| **`#4A4A48` faint** | **1.94** | ⛔ **FAIL → `#858582`** |
| `#454542` **disabled** | 1.85 | **EXEMPT — WCAG does not require contrast for disabled controls** |
| all four status tones | 3.15 – 8.91 | PASS at the 3:1 UI floor |

**Minimum warm grey clearing 4.5:1 on the card is `#838380`** — so **only three text levels survive**, and the
remaining hierarchy is carried by **weight and size**, which the README specifies in full (`700 26px` /
`600 13.5px` / `500 12.5px` / `500 11px` / `9px` / `600 9px` mono).

**DARKENING THE SURFACE TO BUY MORE TONES IS REFUSED — the glass recipe is the identity.**

## ⚠ FIFTH RENDER-FLOOR-CLASS FINDING — **THE DESIGN SETS ITS OWN HONESTY CAPTIONS IN ITS LEAST READABLE TONE**

`#4A4A48`, at **1.94:1**, carries:

> *"'Failed' is never rendered as a reassuring empty state."*
> *"Sync freshness: ok → degraded → escalated."*

**A colour that cannot be read is a value the interface claims to show and does not.** The first four findings
were charts and a noun; this one is a *colour*. **The artifact is a VISUAL specification, not an ACCESSIBILITY
specification** — the README itself asks us to add the semantics the prototype lacks.

---

# 2. TYPOGRAPHY — two families

**Instrument Sans** (400/500/600/700) for UI · **JetBrains Mono** (400/500/600) for **identifiers, addresses,
error codes, metric names, and TABLE HEADERS**.

| use | spec |
|---|---|
| stat number | `700 26px` Sans |
| card title | `600 13.5px` Sans |
| nav item | `500 12.5px` Sans |
| table cell | `500 11px` Sans |
| **table header** | **`600 9px` Mono, `letter-spacing:.1em`** |
| **sidebar section** | **`600 9px` Mono, `letter-spacing:.16em`** |
| badge | `600 8.5px` Mono |
| row sub-line | `9px` |
| explainer body | `400 9.5px/1.55` Sans |
| mono inline value | `10px` Mono |

---

# 3. LAYOUT

```
┌────────────┬──────────────────────────────────────────┐
│  SIDEBAR   │  TOP BAR                         h:56px  │
│   228px    ├──────────────────────────────────────────┤
│ (64px      │  PAGE HEADER (title + subtitle)          │
│  collapsed)│  PAGE BODY  padding 20px 24px 28px       │
│            │  flex column · gap 14px                   │
└────────────┴──────────────────────────────────────────┘
```

**App shell** `display:flex`, **`min-width:1280px`**, full viewport height. **No page-body max width — grids
fill available width.**

**Spacing scale:** 4 · 6 · 7 · 8 · 9 · 10 · 12 · 14 · 16 · 20 · 24. Gaps **12px** (cards) / **14px** (page
sections). Card padding **16px**.

**Radius:** `99px` pills · `14px` cards · `13px` floating bars · `9px` nav/buttons · `8px` inset · `7px`
inputs/code · `6px` chips.

**Elevation:** card `0 10px 30px rgba(0,0,0,.3)` · floating bar `0 20px 50px rgba(0,0,0,.5)` · modal
`0 24px 60px rgba(0,0,0,.45)` · drawer `-24px 0 60px rgba(0,0,0,.5)` · input inset
`inset 0 1px 3px rgba(0,0,0,.22)`.

> ## ⛔ **LIQUID GLASS, NOT GLOSSY. NO INSET WHITE HIGHLIGHT LINES** — explicitly removed by the designer.
> **Do not reintroduce `inset 0 1px 0 rgba(255,255,255,…)`.**

**Z-index:** 110 checklist · 115 bulk bar · 120 drawer · 130 palette · 9999 toast.

## ⚖ RULING 3 — THE RESPONSIVE GAP IS FILLED BY A **FOUNDER DECISION**, NOT BY THE ARTIFACT

The README states plainly:

> *"The prototype is **desktop-only** (min-width 1280px, no responsive breakpoints authored). Responsive
> behavior is a **design gap, not a design decision** — flag it before implementing."*

**FLAGGED AND RULED: S14.2's FIVE BREAKPOINTS AND THE TRIAGE-SUBSET RULING STAND.** They are the **founder's**
decisions, made deliberately, filling a gap the designer explicitly declared and asked to be told about.

> ## **RECORDED SO NO LATER READER ATTRIBUTES THEM TO THE ARTIFACT: WHERE THE DESIGN AUTHORED NOTHING, OUR
> RULES GOVERN. WHERE IT AUTHORED SOMETHING, IT GOVERNS.**

---

# 4. OVERVIEW — the reconciliation, and what is being built

**THE README SAYS "4-up stat row → `8fr 4fr`". THE SCREENSHOT SHOWS SIX CARDS. THE SOURCE SETTLES IT:**

```
display:grid; grid-template-columns:repeat(12,1fr); gap:12px      ← the Overview stat row
```

**Six cards, each spanning 2 of 12.** The README's *"4-up"* describes the **standard page composition** used by
the other screens (`repeat(4,1fr)`); **Overview is the exception and uses the 12-column base**, which is also
how its panels are placed (`span 6` / `span 3`).

**BUILDING: six cards on a 12-column grid.** Source and screenshot agree; the README's generic sentence does
not override the screen's own markup.

**Panels, with their spans:** Site-Link Throughput `6` · Peer Connection Status `3` · Recent Activity `3` ·
Gateway Health `3` · Device Posture `3` · Needs Attention `3` · System Health `3` · Network map `6` ·
HA Hub Set `3` · Alerts `3`.

---

# 5. ASSETS — REPORTED BEFORE USE, per the founder rule

| asset | measured | verdict |
|---|---|---|
| **`lucide-icons.js`** | 7,241 B · **40 icons** · raw 24×24 path data on a `window.LUCIDE_PATHS` global | **the designer's ICON SELECTION is authoritative; the FILE is scaffolding** (a window global). Do not port as-is. |
| **`lucide-react`** | **v1.28.0 · ISC · `sideEffects:false` · ESM** · 31 MB *unpacked in node_modules* | **usable — see the ruling below** |
| `tunnex-logo.svg` | 2,822 B · 577×551 · **no `<script>`, no `href`, no `<image>`** | **clean, usable** |
| `tunnex-wordmark.svg` / `-light.svg` | 2,457 B each · 792×120 · same checks clean | **clean, usable** |
| **`support.js`** | 69 KB · *"GENERATED from dc-runtime — do not edit"* | ⛔ **NOT USED — prototype scaffolding, on the README's explicit do-not-port list** |

## THE LUCIDE QUESTION, CHECKED THE WAY GSAP WAS

**LICENCE: ISC.** Permissive, functionally equivalent to MIT/BSD-2. **Compatible with the Apache-2.0 open core
AND the proprietary enterprise build.** Requires the copyright notice be retained → **NOTICE attribution
needed**, same as any vendored dependency. *(Contrast with GSAP, which was refused: its "standard no-charge
licence" is not an OSS licence and a self-hosted product is redistribution.)*

**BUNDLE COST: paid per icon, not per package.** `sideEffects:false` + ESM means the 31 MB is **install size,
not ship size**; only imported icons are bundled. Each icon is ~300 B of path data, so **~40 icons ≈ 12 KB raw
/ ~4 KB gzip** against a current 352 KB bundle.

**CRITICAL PATH: YES — and that is a constraint, not a disqualifier.** Nav icons are above the fold, so they
**must be in the initial bundle, never lazy-loaded** — a nav that renders without its icons and then reflows is
worse than one that never had them. *(This is the opposite of the Motion ruling, where lazy was the point.)*

**RECOMMENDED: `lucide-react`, per the README's own instruction, pinned, with NOTICE attribution.**

**⚠ ONE THING THE FOUNDER SHOULD WEIGH, because it is this week's finding:** the OpenSSF baseline established
that **this repo has NO JavaScript dependency scanning at all** — no `npm audit`, no `osv-scanner`, no
Dependabot. **Adding a runtime dependency into an unscanned surface is a decision, not a default.** The
alternative is vendoring the designer's 40 paths as a local TSX module: **~7 KB, zero dependency, zero
supply-chain surface** — at the cost of owning them and drifting from upstream Lucide.

## ⚖ RULED — **VENDOR THE 40 PATHS. NOT THE DEPENDENCY.**

- **This week's OpenSSF baseline established the JS dependency surface has NO scanning at all** — no
  `npm`/`pnpm audit`, no `osv-scanner`, no Dependabot; Trivy covers only the Go API image. **Adding a RUNTIME
  dependency into an unscanned surface is a decision in the wrong direction — and it would be the first one
  made after measuring the gap.**
- **7 KB of static SVG paths has no supply-chain surface.** Nothing to scan, nothing to update, nothing to
  reach a CVE feed about.
- **THE ICON SELECTION IS THE DESIGNER'S CONTRIBUTION; THE DELIVERY MECHANISM IS OURS.** Vendoring keeps the
  first and drops the second.
- ⛔ **ISC IS CLEAN — THIS IS NOT A LICENCE REFUSAL.** Recorded explicitly so nobody re-litigates it as one.
  **Lucide is attributed in `NOTICE` anyway**, because the paths are theirs.

**COST ACCEPTED: we own them.** They do not change, and a new icon is a copy-paste.
