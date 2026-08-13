// DESIGN TOKENS — the ONE authored form (S14.1, EPIC 14).
//
// Shared because Item A ruling A3 says the desktop client gets its OWN COMPONENTS but the SAME TOKENS: two
// component sets that look like one product because they read the same values. This file is the source of
// truth for both; nothing else may hold a colour.
//
// TWO EMITTERS, ONE SOURCE. `tailwindColors()` gives Tailwind a palette of `var(--tnx-*)` references so every
// existing utility class keeps working unchanged; `themeCss()` emits the variables themselves, per theme.
// Neither mechanism works alone: a Tailwind config bakes hex at BUILD time (so a theme swap would need a
// rebuild or a `dark:`-variant on every element — the div-soup coupling this epic exists to remove), and CSS
// variables alone would abandon every class in the app. Together, a theme swap is one attribute on <html>.
//
// N-THEME BY CONSTRUCTION, TWO SHIPPED. The founder ruled two for this slice: a third palette is churn inside
// an infrastructure slice and belongs where it can be judged against rendered output.

export type Tone = "ok" | "warn" | "danger";

/**
 * THE SEMANTIC RESERVATION, AS DATA — not as a comment.
 *
 * S4.4 decision f reserved `ok` for LIVENESS ONLY ("alive right now": an online peer, a healthy check) and
 * explicitly NOT for success feedback — "sent / saved / role changed" use the accent, so that green keeps
 * meaning LIVE. That is a shipped decision about what a colour MEANS.
 *
 * It is carried here as data because a token migration is exactly how such a rule dies: `ok` drifts into a
 * generic "success" colour, every screen still renders, nothing looks wrong, and the one place that recorded
 * the rule was a comment in a config file that got rewritten. `tokens.test.ts` asserts it.
 */
export const RESERVATIONS: Record<
  Tone,
  { meaning: string; forbiddenUses: string[] }
> = {
  ok: {
    meaning: "LIVENESS ONLY — alive right now (online peer, healthy check).",
    // If any of these appear as a use-site for `ok`, the reservation has been broken.
    forbiddenUses: [
      "success",
      "saved",
      "sent",
      "created",
      "confirmed",
      "role changed",
    ],
  },
  warn: { meaning: "caution / one-time secret.", forbiddenUses: [] },
  danger: { meaning: "revoked / error.", forbiddenUses: [] },
};

/** Every token name the system defines. A theme MUST supply all of them — see `assertThemeComplete`. */
export const TOKEN_NAMES = [
  // surfaces — README "Color — dark (default)"
  "bg", // app background
  // The two backdrops the glass refracts. NOT colours — CSS background shorthands, which custom properties
  // carry perfectly well. They are tokens because the glass is meaningless without them.
  "bg-glow", // <body> ambient glow, fixed attachment
  "bg-page", // the content area's radial field
  "surface", // card fill (translucent; the glass recipe composes it)
  "surface-inset", // inset / sub-panel
  "code", // code block
  "badge-bg", // badge background
  "border", // card border
  "border-inset", // inset border
  "divider", // row divider
  "divider-head", // header divider
  // text ramp — EIGHT NAMED TONES (README), two of which are contrast-corrected below
  "text-heading",
  "text-primary",
  "text-emphasis",
  "text-body",
  "text-secondary",
  "text-tertiary",
  "text-faint",
  "text-disabled",
  // status — deliberately DESATURATED, never saturated alert colours
  "ok",
  "warn",
  "danger",
  "neutral",
  // interaction
  "accent", // nav-active / selection / hover base
  "focus", // focus-visible ring
] as const;
export type TokenName = (typeof TOKEN_NAMES)[number];

export type Theme = Record<TokenName, string>;

/**
 * `dark` is the CURRENT brand kit, value-for-value. S14.1 must not alter rendering, so these are copied from
 * the pre-existing tailwind config rather than re-picked — a re-pick would make the slice a visual change
 * wearing an infrastructure slice's name.
 */
/**
 * `mono` — THE DEFAULT, and the prototype's own default (`pal: 'mono'`).
 *
 * Every value cites the handoff README's token table (docs/wireframe-extract.md), except the TWO recorded
 * contrast corrections below. This is not a re-pick: the previous `dark` was the OLD APP'S palette, shipped
 * before the specification had been read.
 */
const mono: Theme = {
  bg: "#0A0A0A",
  // The two backdrops the glass needs SOMETHING to refract. Without them a translucent card sits on a flat
  // field and looks identical to an opaque one — the effect is in the CONTRAST BEHIND, not in the blur.
  "bg-glow":
    "radial-gradient(1200px 700px at 80% -10%,rgba(255,255,255,.03),transparent 62%),#0A0A0A",
  "bg-page":
    "radial-gradient(130% 120% at 12% -5%,#1C1C1C 0%,#141414 48%,#0D0D0D 100%)",
  // ⛔ TRANSLUCENT, NOT COMPOSITED. A first pass set these to the composited hex (#1B1B1B) "because the alpha
  // lives in the glass recipe" — which made every card OPAQUE, so `backdrop-filter` had nothing to see through
  // and the liquid glass rendered as flat plastic. The alpha IS the material.
  surface: "rgba(31,31,31,.72)",
  "surface-inset": "rgba(18,18,18,.72)",
  code: "#101010",
  "badge-bg": "#1A1A1A",
  border: "#2E2E2E",
  "border-inset": "#242424",
  divider: "#1A1A1A",
  "divider-head": "#1E1E1E",

  "text-heading": "#F5F5F5",
  "text-primary": "#EDEDEB",
  "text-emphasis": "#D6D6D2",
  "text-body": "#A9A9A6",
  "text-secondary": "#858582",
  // ⛔ TWO CONTRAST CORRECTIONS, FOUNDER-RULED. The README's tertiary #5E5E5B (2.65:1) and faint #4A4A48
  // (1.94:1) FAIL the WCAG AA 4.5:1 floor that S14.1 built and mutation-proved. The minimum warm grey that
  // clears it on this surface is #838380, so both collapse to #858582 and the hierarchy is carried by WEIGHT
  // and SIZE instead — which the README specifies in full.
  //
  // Recorded rather than silently applied: the design sets its own honesty captions ("'Failed' is never
  // rendered as a reassuring empty state") in its least readable tone. A colour that cannot be read is a
  // value the interface claims to show and does not.
  "text-tertiary": "#858582", // README: #5E5E5B — raised
  "text-faint": "#858582", // README: #4A4A48 — raised
  // Disabled is EXEMPT: WCAG does not require contrast for disabled controls, so this stays verbatim.
  "text-disabled": "#454542",

  ok: "#6E9C7C",
  warn: "#C39A4E",
  danger: "#C77474",
  neutral: "#858582",

  // Mono's interaction colours, measured from the source prototype rather than the README's violet row.
  accent: "#C9C9C4",
  focus: "#C9C9C4",
};

/** `mono` — the second theme, present to PROVE the mechanism is n-theme. Hue stripped, contrast preserved. */
/**
 * `violet` — the prototype's SECOND palette. Same surfaces and ramp; the accent becomes the brand violet.
 *
 * The app shipped `#7c5cff` before the specification was read — ONE HEX DIGIT from the README's `#7C5CFC`.
 * It was never a mistake; it was right by coincidence. The value now CITES the design rather than resembling it.
 */
const violet: Theme = {
  ...mono,
  accent: "#7C5CFC",
  focus: "#A78BFA",
};

export const THEMES: Record<string, Theme> = { mono, violet };
export const DEFAULT_THEME = "mono";

/** Typography + spacing travel as tokens now; ADOPTION is S14.2, so this slice cannot alter rendering. */
export const TYPOGRAPHY = {
  sans: [
    '"Inter Variable"',
    "ui-sans-serif",
    "system-ui",
    "Segoe UI",
    "Roboto",
    "sans-serif",
  ],
  mono: [
    '"JetBrains Mono Variable"',
    "ui-monospace",
    "SFMono-Regular",
    "Menlo",
    "monospace",
  ],
} as const;

// ── S14.3 SLICE 0 — THE SCALES S14.1'S PAPER CLAIMED AND ITS ARTIFACT DID NOT CARRY ──────────────────────────
//
// ⚠ THIS IS A DEFECT BEING CORRECTED, NOT A GAP BEING FILLED (founder-ruled).
//
// S14.1's commit-one listed FIVE covered groups — colour, typography, spacing, radius/border/elevation, motion.
// The emitted set was THIRTEEN NAMES AND EVERY ONE WAS A COLOUR. Font FAMILIES shipped (TYPOGRAPHY above, into
// the palette JSON); a size scale, a spacing scale, radius, elevation and motion did not.
//
// A PAPER VOUCHING FOR A PROPERTY THE ARTIFACT LACKS IS THE SAME CLASS AS A COMMENT VOUCHING FOR ABSENT CODE —
// and this repo has just paid for that class once, in S14.2's mutation 1.
//
// WHY S14.1'S OWN GATES MISSED IT, which is the part worth fixing: `tokens.test.ts` asserted theme
// COMPLETENESS (every theme supplies every token NAME) and contrast and the `ok` reservation. NOTHING ASSERTED
// THE EMITTED SET AGAINST THE CLAIMED COVERAGE. Every gate passed because every gate was aimed at the names
// that existed, never at the ones the paper promised. See CLAIMED_COVERAGE below — that assertion now exists.

/** Spacing scale. One scale, so a gap is a decision rather than a number someone typed. */
export const SPACING = {
  // The README's scale, VERBATIM and keyed by its own px values — 4 · 6 · 7 · 8 · 9 · 10 · 12 · 14 · 16 · 20 · 24.
  //
  // Keyed by px rather than by a t-shirt or step index on purpose: the design is specified in px, and every
  // other naming scheme requires a translation table that nobody maintains. `--tnx-space-7` IS 7px.
  // (A first attempt used fractional step keys, which emit `--tnx-space-1.5` — legal CSS, but the coverage
  // census could not match it and went red. The census caught a naming choice, which is what it is for.)
  4: "4px",
  6: "6px",
  7: "7px",
  8: "8px",
  9: "9px",
  10: "10px",
  12: "12px",
  14: "14px",
  16: "16px",
  20: "20px",
  24: "24px",
} as const;

/** Type scale. Sizes only — families are TYPOGRAPHY, and the two are separate so a theme may re-scale without re-picking a face. */
export const TYPE_SCALE = {
  // The README's scale, in px, because the design is specified in px and a rem conversion would drift.
  badge: "8.5px",
  micro: "9px",
  explainer: "9.5px",
  mono: "10px",
  cell: "11px",
  nav: "12.5px",
  title: "13.5px",
  stat: "26px",
} as const;

export const RADIUS = {
  chip: "6px",
  input: "7px",
  inset: "8px",
  nav: "9px",
  bar: "13px",
  card: "14px",
  pill: "99px",
} as const;

/**
 * Elevation. The wireframe's glassmorphism layer model lives HERE rather than as inline `backdrop-filter`
 * declarations across the app — the artifact carries 242 of those, which is 242 places for one of them to drift.
 */
/**
 * ⛔ LIQUID GLASS, NOT GLOSSY. The README is explicit: the inset white highlight lines were REMOVED, and
 * `inset 0 1px 0 rgba(255,255,255,…)` must not be reintroduced.
 */
export const ELEVATION = {
  none: "none",
  card: "0 10px 30px rgba(0,0,0,.3)",
  bar: "0 20px 50px rgba(0,0,0,.5)",
  modal: "0 24px 60px rgba(0,0,0,.45)",
  drawer: "-24px 0 60px rgba(0,0,0,.5)",
  "input-inset": "inset 0 1px 3px rgba(0,0,0,.22)",
} as const;

/**
 * Motion. Durations and easings, so an animation is a token rather than a number chosen per component.
 *
 * ⛔ `prefers-reduced-motion` IS A GATE, NOT A COURTESY (founder-ruled), and the CSS-first half of that gate is
 * emitted alongside these values: a media block that re-points every duration to `0ms`. That means the
 * REDUCTION IS UNCONDITIONAL AND NEEDS NO JAVASCRIPT — a component that forgets to check the preference still
 * animates for zero milliseconds. The JS half (the pure `motionAllowed` decision) is slice B, and it gates the
 * animations CSS cannot reach.
 */
export const MOTION = {
  duration: { instant: "0ms", fast: "120ms", normal: "200ms", slow: "320ms" },
  easing: {
    standard: "cubic-bezier(0.2, 0, 0, 1)",
    decelerate: "cubic-bezier(0, 0, 0, 1)",
    accelerate: "cubic-bezier(0.3, 0, 1, 1)",
  },
} as const;

/**
 * THE CLAIM, AS DATA — hand-authored to mirror what the PAPER promises, and deliberately NOT derived from the
 * scales above.
 *
 * A derived list would compare the token set to itself and pass by construction: the fixture-restates-production
 * shape, which is exactly how S14.1's coverage claim survived unchallenged. This list is the CLAIM; the emitted
 * CSS is the ARTIFACT; the census in `tokens.test.ts` compares one to the other.
 *
 * ⛔ ADDING A CATEGORY HERE WITHOUT EMITTING IT GOES RED. That is the whole point — the failure mode being
 * guarded is a paper (or this list) growing a promise the artifact never grew.
 */
export const CLAIMED_COVERAGE: Array<{
  category: string;
  claim: string;
  prefix: string;
  minCount: number;
}> = [
  {
    category: "colour",
    claim: "ink surfaces, accent, semantic ok/warn/danger, text",
    prefix: "",
    minCount: 13,
  },
  {
    category: "typography",
    claim: "a size scale (families ship in the palette JSON)",
    prefix: "text-",
    minCount: 6,
  },
  {
    category: "spacing",
    claim: "one spacing scale",
    prefix: "space-",
    minCount: 9,
  },
  {
    category: "radius",
    claim: "border radius scale",
    prefix: "radius-",
    minCount: 5,
  },
  {
    category: "elevation",
    claim:
      "the layer/glassmorphism model, as tokens not 242 inline declarations",
    prefix: "elevation-",
    minCount: 4,
  },
  {
    category: "motion",
    claim: "duration + easing, with prefers-reduced-motion honoured",
    prefix: "duration-",
    minCount: 4,
  },
  { category: "motion", claim: "easing curves", prefix: "ease-", minCount: 3 },
];

// ── emitters ────────────────────────────────────────────────────────────────────────────────────────────────

const cssVar = (n: TokenName) => `--tnx-${n}`;

/** The Tailwind palette: every colour is a `var()` reference, so a theme swap needs no rebuild. */
export function tailwindColors() {
  const ref = (n: TokenName) => `var(${cssVar(n)})`;
  return {
    bg: ref("bg"),
    surface: {
      DEFAULT: ref("surface"),
      inset: ref("surface-inset"),
      code: ref("code"),
      badge: ref("badge-bg"),
    },
    line: {
      DEFAULT: ref("border"),
      inset: ref("border-inset"),
      row: ref("divider"),
      head: ref("divider-head"),
    },
    ok: ref("ok"),
    warn: ref("warn"),
    danger: ref("danger"),
    neutral: ref("neutral"),
    accent: {
      DEFAULT: ref("accent"),
      // ⛔ MIGRATION BRIDGE — the OLD token names, kept alive so the sixteen screens that have not had their
      // section pass yet keep rendering. Tailwind DROPS unknown classes SILENTLY: removing these names would
      // not fail the build, it would blank half the product's surfaces and nothing would go red.
      //
      // Each entry disappears when its screen's section lands. See docs/EPIC-14-ui-redesign.md.
      400: ref("accent"),
      500: ref("accent"),
      600: ref("accent"),
    },
    focus: ref("focus"),
    ink: {
      heading: ref("text-heading"),
      primary: ref("text-primary"),
      emphasis: ref("text-emphasis"),
      body: ref("text-body"),
      secondary: ref("text-secondary"),
      tertiary: ref("text-tertiary"),
      faint: ref("text-faint"),
      disabled: ref("text-disabled"),
      // MIGRATION BRIDGE, same reason: ink-950..600 were SURFACES in the old set, not text.
      950: ref("bg"),
      900: ref("bg"),
      800: ref("surface"),
      700: ref("surface-inset"),
      600: ref("border"),
    },
  };
}

/**
 * The non-colour scales, emitted as `:root` variables — plus the reduced-motion media block.
 *
 * Colour is per-theme; these are NOT. A theme changes what the product looks like, never how far apart things
 * sit or how long a transition runs; making spacing themeable would let a theme change layout, which is a
 * different decision wearing a palette's name.
 */
export function scaleCss(): string {
  const decls = [
    ...Object.entries(TYPE_SCALE).map(([k, v]) => `--tnx-text-${k}:${v}`),
    ...Object.entries(SPACING).map(([k, v]) => `--tnx-space-${k}:${v}`),
    ...Object.entries(RADIUS).map(([k, v]) => `--tnx-radius-${k}:${v}`),
    ...Object.entries(ELEVATION).map(([k, v]) => `--tnx-elevation-${k}:${v}`),
    ...Object.entries(MOTION.duration).map(
      ([k, v]) => `--tnx-duration-${k}:${v}`,
    ),
    ...Object.entries(MOTION.easing).map(([k, v]) => `--tnx-ease-${k}:${v}`),
  ];
  // The CSS half of the motion gate. Unconditional: nothing has to remember to check.
  const reduced = Object.keys(MOTION.duration)
    .map((k) => `--tnx-duration-${k}:0ms`)
    .join(";");
  return [
    `:root{${decls.join(";")}}`,
    `@media (prefers-reduced-motion: reduce){:root{${reduced}}}`,
  ].join("\n");
}

/** `:root` carries the default theme; `[data-theme="x"]` re-points the same names. One attribute, no rebuild. */
export function themeCss(): string {
  const block = (sel: string, t: Theme) =>
    `${sel}{${TOKEN_NAMES.map((n) => `${cssVar(n)}:${t[n]}`).join(";")}}`;
  return [
    block(":root", THEMES[DEFAULT_THEME]),
    ...Object.entries(THEMES).map(([name, t]) =>
      block(`[data-theme="${name}"]`, t),
    ),
  ].join("\n");
}

// ── contrast, computed — so the accessibility floor is a TEST, not a review ──────────────────────────────────

function srgbToLinear(c: number): number {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

/** WCAG 2.1 relative luminance. */
/**
 * The solid colour a TRANSLUCENT surface composites to over the page background.
 *
 * ⛔ CONTRAST IS COMPUTED AGAINST THIS, NOT AGAINST THE `rgba()` STRING. A ratio computed from an alpha value
 * is `NaN`, and `NaN >= 4.5` is FALSE — so the gate fails loudly rather than certifying an unreadable pair.
 * That is the safe direction, and it is why the resolver lives here rather than in the test: a consumer that
 * needs "what colour is this really" must not each invent its own answer.
 */
export const COMPOSITED: Record<string, string> = {
  surface: "#1B1B1B", // rgba(31,31,31,.72) over #0A0A0A
  "surface-inset": "#161616", // rgba(18,18,18,.72) over #0A0A0A
};

/** Resolve a token to the solid colour it actually renders as. Hex passes through; translucency composites. */
export function solid(theme: Theme, name: TokenName): string {
  const v = theme[name];
  return v.startsWith("#") ? v : (COMPOSITED[name] ?? v);
}

export function luminance(hex: string): number {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return (
    0.2126 * srgbToLinear(r) +
    0.7152 * srgbToLinear(g) +
    0.0722 * srgbToLinear(b)
  );
}

/** WCAG 2.1 contrast ratio, 1..21. */
export function contrastRatio(a: string, b: string): number {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
}

/**
 * THE PAIRS THE SYSTEM PERMITS, with the floor each must meet. Enumerated deliberately rather than derived:
 * a derived list would compare the token set to itself and pass by construction, which is the
 * fixture-restates-production shape applied to a design system.
 *
 * AA floors: 4.5:1 for body text, 3:1 for large text and for UI/graphical boundaries.
 */
export const CONTRAST_PAIRS: Array<{
  fg: TokenName;
  bg: TokenName;
  floor: number;
  why: string;
}> = [
  {
    fg: "text-heading",
    bg: "bg",
    floor: 4.5,
    why: "headings on the app background",
  },
  { fg: "text-heading", bg: "surface", floor: 4.5, why: "headings on a card" },
  {
    fg: "text-primary",
    bg: "surface",
    floor: 4.5,
    why: "primary text on a card",
  },
  { fg: "text-emphasis", bg: "surface", floor: 4.5, why: "emphasis on a card" },
  { fg: "text-body", bg: "surface", floor: 4.5, why: "body text on a card" },
  { fg: "text-secondary", bg: "surface", floor: 4.5, why: "labels on a card" },
  // The two CORRECTED tones. They are asserted at the SAME floor as body text precisely because the README's
  // originals failed it — if a future edit re-points them at the design's literal values, this goes red.
  {
    fg: "text-tertiary",
    bg: "surface",
    floor: 4.5,
    why: "sub-lines — README's #5E5E5B failed at 2.65:1",
  },
  {
    fg: "text-faint",
    bg: "surface",
    floor: 4.5,
    why: "explainer captions — README's #4A4A48 failed at 1.94:1",
  },
  {
    fg: "text-secondary",
    bg: "surface-inset",
    floor: 4.5,
    why: "labels on an inset panel",
  },
  {
    fg: "ok",
    bg: "surface",
    floor: 3,
    why: "liveness badge — a UI boundary, not body text",
  },
  { fg: "warn", bg: "surface", floor: 3, why: "caution badge" },
  { fg: "danger", bg: "surface", floor: 3, why: "error badge" },
  { fg: "neutral", bg: "surface", floor: 3, why: "unknown/neutral badge" },
  {
    fg: "accent",
    bg: "surface",
    floor: 3,
    why: "focus ring / active affordance",
  },
];
