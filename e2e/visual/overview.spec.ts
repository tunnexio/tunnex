import { test, expect, type Page } from "@playwright/test";
import { OWNER } from "../tests/helpers";

// ⛔ OVERVIEW HAS NO PIXEL BASELINE, DELIBERATELY. GEOMETRIC ASSERTIONS ONLY.
//
// ════════════════════════════════════════════════════════════════════════════════════════════════════════
// A VISUAL SUITE'S SUBJECT SHOULD BE THE SURFACE WHOSE OUTPUT IS DETERMINED BY CODE, NOT BY DATA.
// ════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// The gallery renders FIXTURES. Overview renders a LIVE CONTROL PLANE: async panels that resolve in
// whatever order the API answers, and audit rows stamped at SEED time. That is where the product is
// interesting and where a pixel diff is LEAST able to say anything.
//
// THE MEASUREMENT THAT SETTLED IT (founder-ruled 2026-08-02, after seven rounds):
//   · gallery baselines           stable across 7 rounds
//   · overview-1440 full-page     621 px different, ACROSS RUNS OF IDENTICAL APP CODE
//   · the same 621 px before and after the fix aimed at it — so the hypothesis was wrong, twice
//   · three diffing text runs, glyph pixels only, no layout shift: the two empty states and the
//     health line. Async arrival, not layout.
//
// AND THE PART THAT ACTUALLY DECIDED IT — WHAT EACH INSTRUMENT PAID:
//   · the 65px header overflow        found by a GEOMETRIC ASSERTION (the two tests below)
//   · the Menu-over-<h1> overlap      found by a HUMAN READING AN IMAGE
//   · the duplicate health indicator  found by a STRICT-MODE LOCATOR VIOLATION
//   · the full-page pixel diff        found NOTHING, in six rounds
//
// ⛔ SCOPE A SUITE TO WHAT HAS PAID, NOT TO WHAT LOOKS COMPREHENSIVE.
//
// Keeping the 390 snapshot because it happened to pass twice was considered and REJECTED: it is the same
// code path that flakes at 1440. Two passes is luck, not a property.

const WIDTHS = [
  { name: "1440", width: 1440, height: 1200 },
  { name: "390", width: 390, height: 1200 },
];

async function stabilise(page: Page) {
  await page.clock.setFixedTime(new Date("2026-08-01T12:00:00Z"));
  await page.emulateMedia({ reducedMotion: "reduce" });
}

// The geometric invariant on the real screen — this is where it actually fired.
for (const w of WIDTHS) {
  test(`overview has no horizontal overflow @ ${w.name}`, async ({ page }) => {
    await page.setViewportSize({ width: w.width, height: w.height });
    await stabilise(page);
    await page.goto("/login");
    await page.getByLabel("Email").fill(OWNER.email);
    await page.getByLabel("Password").fill(OWNER.pass);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    const overflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    );
    expect(
      overflow,
      `Overview is ${overflow}px wider than the ${w.name}px viewport`,
    ).toBeLessThanOrEqual(0);
  });
}
