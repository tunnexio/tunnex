import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  CLAIMED_COVERAGE,
  CONTRAST_PAIRS,
  DEFAULT_THEME,
  MOTION,
  RESERVATIONS,
  THEMES,
  TOKEN_NAMES,
  contrastRatio,
  solid,
  tailwindColors,
  themeCss,
} from "../../../packages/shared/src/tokens";
import { stripCssComments } from "./support/source";
// Imported by RELATIVE path, matching vite.config.ts and tailwind.config.ts. One specifier for the one
// authored form: the package-name route resolves through @tunnex/shared's raw .ts entry, which Node cannot
// load at config time and which a cached workspace link can serve staleley. Same file, no ambiguity.

// S14.1 — THE DESIGN SYSTEM'S GATES. Both FAIL the build; neither warns.
//
// A linter that emits warnings is a convention. A failing test is a mechanism — and this repo has already
// ruled that a standard recorded only in prose is the convention-not-mechanism failure.

describe("accessibility floor — WCAG 2.1 AA, COMPUTED not reviewed", () => {
  // Contrast is computable from the token values, so the floor is a unit test rather than a design review.
  // Every (foreground, background) pair the system PERMITS is enumerated deliberately in CONTRAST_PAIRS — a
  // derived list would compare the token set to itself and pass by construction.
  for (const themeName of Object.keys(THEMES)) {
    for (const pair of CONTRAST_PAIRS) {
      it(`[${themeName}] ${pair.fg} on ${pair.bg} meets ${pair.floor}:1 — ${pair.why}`, () => {
        const theme = THEMES[themeName]!;
        // `solid()` composites a translucent surface to the colour it actually renders as. The glass is
        // rgba by design, and a ratio computed from an alpha value is NaN — which FAILS, correctly, but for
        // the wrong reason. Resolving first means the assertion measures what the eye sees.
        const ratio = contrastRatio(
          solid(theme, pair.fg),
          solid(theme, pair.bg),
        );
        expect(
          ratio,
          `${pair.fg} (${solid(theme, pair.fg)}) on ${pair.bg} (${solid(theme, pair.bg)}) = ${ratio.toFixed(2)}:1, floor ${pair.floor}:1`,
        ).toBeGreaterThanOrEqual(pair.floor);
      });
    }
  }

  it("the pair list is not empty — a floor over zero pairs cannot fail", () => {
    // The gate's own vacuity guard. An empty CONTRAST_PAIRS would make every assertion above vanish and the
    // suite would go green having checked nothing.
    expect(CONTRAST_PAIRS.length).toBeGreaterThanOrEqual(8);
  });
});

describe("the `ok` reservation — S4.4 decision f, asserted rather than commented", () => {
  // WHY THIS EXISTS. `ok` is reserved for LIVENESS ONLY — an online peer, a healthy check — and explicitly NOT
  // for success feedback, so that green keeps meaning LIVE. That is a decision about what a colour MEANS, and
  // a token migration is exactly how it dies: `ok` drifts into a generic "success" colour, every screen still
  // renders, nothing looks wrong, and the only record of the rule was a comment in a config that got rewritten.
  it("carries its meaning and its forbidden uses as DATA", () => {
    expect(RESERVATIONS.ok.meaning).toMatch(/liveness only/i);
    expect(RESERVATIONS.ok.forbiddenUses).toContain("success");
  });

  it("NO forbidden use appears as an `ok` use-site anywhere in the app", () => {
    // The real assertion. `text-ok` / `bg-ok` next to success wording is the drift this reservation forbids,
    // and it is the form the violation actually takes — nobody renames the token, they reuse it.
    const files = import.meta.glob("../src/**/*.tsx", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
    const offenders: string[] = [];

    for (const [path, src] of Object.entries(files)) {
      for (const line of src.split("\n")) {
        if (!/\b(?:text|bg|border|ring)-ok\b/.test(line)) continue;
        const hit = RESERVATIONS.ok.forbiddenUses.find((w: string) =>
          new RegExp(`\\b${w}\\b`, "i").test(line),
        );
        if (hit)
          offenders.push(
            `${path}: "${hit}" beside an \`ok\` colour — ${RESERVATIONS.ok.meaning}`,
          );
      }
    }

    expect(offenders, offenders.join("\n")).toEqual([]);
  });

  it("scans a non-trivial number of files — the scan must not pass by finding nothing", () => {
    // Same vacuity guard as above: a glob that silently matched zero files would make the check green forever.
    const files = import.meta.glob("../src/**/*.tsx", {
      query: "?raw",
      import: "default",
      eager: true,
    });
    expect(Object.keys(files).length).toBeGreaterThanOrEqual(20);
  });
});

describe("theme completeness — a theme that omits a token renders a broken var()", () => {
  for (const [name, theme] of Object.entries(THEMES) as Array<
    [string, Record<string, string>]
  >) {
    it(`[${name}] supplies every token name`, () => {
      const missing = TOKEN_NAMES.filter((n) => !theme[n]);
      expect(
        missing,
        `missing tokens in "${name}": ${missing.join(", ")}`,
      ).toEqual([]);
    });
  }

  it("the emitted CSS carries :root plus one selector per theme", () => {
    const css = themeCss();
    expect(css).toContain(":root{");
    for (const name of Object.keys(THEMES))
      expect(css).toContain(`[data-theme="${name}"]`);
    expect(Object.keys(THEMES)).toContain(DEFAULT_THEME);
  });

  it("the Tailwind palette references variables ONLY — a literal hex here defeats theming", () => {
    // If any colour resolved to a hex, that class would stop responding to a theme swap — silently, since it
    // would still render a colour.
    const flat = JSON.stringify(tailwindColors());
    expect(flat).not.toMatch(/#[0-9a-f]{3,8}/i);
    expect(flat).toContain("var(--tnx-");
  });
});

describe("COVERAGE CENSUS — the CLAIM compared to the ARTIFACT (S14.3 slice 0)", () => {
  // ⚠ THE ASSERTION THAT DID NOT EXIST, AND THE REASON THE DEFECT SHIPPED.
  //
  // S14.1's paper claimed five covered groups — colour, typography, spacing, radius/elevation, motion. The
  // emitted set was thirteen names and every one was a colour. EVERY GATE PASSED, because every gate was
  // aimed at the names that existed and none at the ones the paper promised: theme completeness compares each
  // theme to TOKEN_NAMES, contrast compares colours to colours, the reservation scan compares source to a
  // rule. Nothing compared the CLAIM to the ARTIFACT.
  //
  // A paper vouching for a property the artifact lacks is the same class as a comment vouching for absent
  // code, which this repo paid for once already in S14.2's mutation 1.
  //
  // The claim is hand-authored (CLAIMED_COVERAGE) and the artifact is generated, so the two are independent.
  // Deriving the claim from the scales would compare the token set to itself and pass by construction.
  // ⚠ READ FROM DISK, NOT VIA `?raw`. The obvious route — `import css from "…/tokens.css?raw"` — returns an
  // EMPTY STRING under vitest: CSS processing is disabled by default, and the raw query is swallowed with it.
  // It failed loudly here only because the assertions below are lower-bounds (0 < 13). Had any of them been an
  // "and nothing unexpected" check, an empty artifact would have satisfied it VACUOUSLY. The guard three tests
  // down exists for that reason and is what identified the empty.
  const css = stripCssComments(
    readFileSync(
      fileURLToPath(
        new URL(
          "../../../packages/shared/generated/tokens.css",
          import.meta.url,
        ),
      ),
      "utf8",
    ),
  );

  for (const c of CLAIMED_COVERAGE) {
    it(`[${c.category}] emits ≥${c.minCount} variables — claim: ${c.claim}`, () => {
      const names = new Set(
        [...css.matchAll(/--tnx-([a-z0-9-]+)\s*:/g)]
          .map((m) => m[1]!)
          .filter((n) => (c.prefix ? n.startsWith(c.prefix) : true)),
      );
      expect(
        names.size,
        `"${c.category}" claims ${c.claim} but the emitted CSS carries ${names.size} matching variable(s) ` +
          `for prefix "${c.prefix}" — a claim with nothing behind it.`,
      ).toBeGreaterThanOrEqual(c.minCount);
    });
  }

  it("the coverage list is non-empty — a census over zero claims cannot fail", () => {
    expect(CLAIMED_COVERAGE.length).toBeGreaterThanOrEqual(5);
  });

  it("the emitted CSS was actually read — an empty artifact would satisfy nothing above", () => {
    // The vacuity guard that matters most here: if the raw import silently resolved to "", every prefix would
    // match zero names and every assertion would fail loudly — which is the safe direction. This asserts the
    // opposite risk, that the file is real, so a passing run means the comparison happened.
    expect(css.length).toBeGreaterThan(200);
    expect(css).toContain("--tnx-");
  });

  it("prefers-reduced-motion is honoured in the ARTIFACT, unconditionally — not left to each component", () => {
    // The CSS half of the motion gate. It needs no JavaScript and nothing has to remember to check: a
    // component that forgets the preference still animates for zero milliseconds.
    expect(css).toMatch(/@media \(prefers-reduced-motion: reduce\)/);
    for (const k of Object.keys(MOTION.duration)) {
      expect(
        css,
        `--tnx-duration-${k} is not zeroed under reduced motion`,
      ).toMatch(new RegExp(`--tnx-duration-${k}\\s*:\\s*0ms`));
    }
  });
});
