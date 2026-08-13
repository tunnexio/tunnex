import { test, expect } from "@playwright/test";
import { readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// `__dirname` is undefined here: the e2e package is ESM, so the module directory comes from import.meta.
const HERE = dirname(fileURLToPath(import.meta.url));

// ⛔ THE BASELINE CENSUS — THE LOAD-BEARING DEFENCE, and the reason this suite can be trusted.
//
// THE FAILURE MODE IT CLOSES: a red visual suite is easiest to silence by DELETING A SNAPSHOT. That leaves
// NO DIFF TO REVIEW — the check goes green and its subject is simply gone. Mechanism ⑦ in image form: a claim
// with nothing behind it, indistinguishable from a claim that is kept.
//
// ⛔ AN EXACT COUNT, NEVER A MINIMUM. A floor (`>= 1`) is satisfied by deleting all but one, which is exactly
// the move it is meant to prevent. The number moves DELIBERATELY, in a reviewable edit to this file, or the
// suite goes red BY NAME.
//
// Same form as the screen census (`toBe`, not `toBeGreaterThan`) and for the same reason.

// ⛔ TWO, NOT FOUR — and the number went DOWN in a reviewed edit, which is the census working, not failing.
//
// The two `overview-*.png` baselines were harvested, read, committed, and then DROPPED (founder-ruled
// 2026-08-02) because the surface is data-determined rather than code-determined. The rationale is at the
// top of `overview.spec.ts`; Overview keeps its two GEOMETRIC assertions, which are what found the defects.
//
// This is the distinction the census exists to enforce: a baseline removed by a ruling, in a diff, with the
// count edited alongside it, is not the same act as a baseline deleted to silence a red check. The census
// cannot tell those apart on its own — it forces the second one to LOOK like the first, in public.
const EXPECTED_SNAPSHOTS = [
  "gallery-1440.png",
  "gallery-390.png",
  // ⛔ NO `gallery-wide-390.png`, AND THIS LINE IS WHY.
  //
  // The wide specimen isolates the class where a component's geometry derives from its CONTAINER — the
  // defect that shipped a 750px-tall diagram because the gallery pinned every specimen to `w-80`. At 390
  // THERE IS NO WIDE COLUMN, so a wide specimen at phone width is just the narrow one again: it would test
  // nothing while costing a baseline and a re-harvest on every change.
  //
  // Symmetry is not a reason. If you are here to add the 390 counterpart, this is the argument against it.
  "gallery-wide-1440.png",
] as const;

test("the baseline set is EXACTLY what is expected — no additions, no silent deletions", () => {
  const dir = join(HERE, "visual.spec.ts-snapshots");
  const dir2 = join(HERE, "overview.spec.ts-snapshots");
  const found = [
    ...(existsSync(dir) ? readdirSync(dir) : []),
    ...(existsSync(dir2) ? readdirSync(dir2) : []),
  ]
    .filter((f) => f.endsWith(".png"))
    // Playwright suffixes baselines with the platform (…-linux.png). The census is about WHICH images exist,
    // not which platform produced them.
    // Playwright suffixes with PROJECT and PLATFORM (…-chromium-linux.png).
    .map((f) =>
      f.replace(
        /-(chromium|firefox|webkit)-(linux|darwin|win32)\.png$/,
        ".png",
      ),
    )
    .sort();

  expect(
    found,
    `baseline set drifted.\n  expected: ${[...EXPECTED_SNAPSHOTS].sort().join(", ")}\n  found:    ${found.join(", ")}`,
  ).toEqual([...EXPECTED_SNAPSHOTS].sort());
});

test("the expectation list is not empty — a census over zero baselines cannot fail", () => {
  // A FLOOR ON THE FLOOR. The count above is allowed to move, so this guards the move: it may be reduced by
  // a ruling, but never to nothing. An empty EXPECTED_SNAPSHOTS makes the census above pass over an empty
  // directory — the subject and its check vanishing together, which is the mechanism this file is named for.
  expect(EXPECTED_SNAPSHOTS.length).toBeGreaterThanOrEqual(3);
});
