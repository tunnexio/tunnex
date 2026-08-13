import tokens from "../../packages/shared/generated/tokens.palette.json" with { type: "json" };

/** @type {import('tailwindcss').Config} */
// S14.1: NO HARDCODED HEX LIVES HERE. The palette is `var(--tnx-*)` references GENERATED from the one authored
// form (packages/shared/src/tokens.ts) by `make generate`, and drift is caught by `make generate-check` —
// exactly as api.d.ts and rbac-policy.json already are.
//
// The config reads JSON rather than TypeScript deliberately. Config files load through Node, which cannot read
// a raw .ts entry; importing the .ts by relative path deadlocks TypeScript's project references. Consuming a
// generated artifact removes the whole class of problem.
//
// The semantic reservation (ok = LIVENESS ONLY, never success feedback — S4.4 decision f) travels with the
// tokens as DATA and is asserted in apps/web/test/tokens.test.ts. It used to live in a comment here, which is
// exactly how such a rule dies during a migration.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: tokens.colors,
      fontFamily: tokens.fontFamily,
      // ⛔ `spacing` IS DELIBERATELY NOT EXTENDED. Tailwind's scale is keyed 4 = 1rem = 16px; the design's is
      // keyed in PX. Overriding it with px values does not ADD a scale — it REDEFINES every existing numeric
      // spacing class in the product. `h-24` went from 96px to 24px, `p-4` from 16px to 4px, across 128 use
      // sites in 17 screens, silently, with nothing failing.
      //
      // The symptom was a donut that "was wired" and did not appear: it rendered at 24×24 instead of 96×96.
      // Tailwind's defaults already express the design's scale (12px = `3`, 14px = `3.5`, 16px = `4`,
      // 20px = `5`, 24px = `6`); the two odd values are written as `[7px]` / `[9px]`.
      //
      // The px values remain EMITTED as `--tnx-space-*` for reference and for anything that needs them by
      // name — they are simply not bound to Tailwind's numeric keys.
      borderRadius: tokens.borderRadius,
      boxShadow: tokens.boxShadow,
      fontSize: tokens.fontSize,
      transitionDuration: tokens.transitionDuration,
      transitionTimingFunction: tokens.transitionTimingFunction,
    },
  },
  plugins: [],
};
