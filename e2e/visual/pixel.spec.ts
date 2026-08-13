import { test, expect } from "@playwright/test";

// ⛔ THE PIXEL DIFF — SEPARATED SO IT CAN BE DEMOTED WITHOUT DEMOTING THE REST (founder-ruled 2026-08-02).
//
// The visual job was made advisory wholesale, and that surrendered the part that PAYS along with the part
// that does not. The epic's own accounting:
//
//   geometric assertions      1 real defect (a 65px header overflow on every screen)
//   strict-mode locators      1 real defect (a health indicator rendered twice)
//   a human reading an image  1 real defect (the Menu button over the page h1)
//   THE FULL-PAGE PIXEL DIFF  0, in six rounds
//
// What makes the job red on every push is THIS FILE: a committed image, compared against a surface the epic
// is deliberately changing every slice. The geometric assertions and the strict-mode locators are
// DETERMINISTIC — no baseline, no harvest, and no 621-pixel data difference can flake them.
//
// SO THEY LIVE IN DIFFERENT FILES AND RUN AS DIFFERENT CI STEPS. This one is `continue-on-error`; the others
// still block. Re-arm trigger for this file: EPIC 14 close.

const WIDTHS = [
  { name: "1440", width: 1440, height: 1200 },
  { name: "390", width: 390, height: 1200 },
];

async function stabilise(page: import("@playwright/test").Page) {
  await page.clock.setFixedTime(new Date("2026-08-01T12:00:00Z"));
  await page.emulateMedia({ reducedMotion: "reduce" });
}

test.describe("visual — the shared surface (primitives gallery)", () => {
for (const w of WIDTHS) {
    test(`@pixel primitives gallery @ ${w.name}`, async ({ page }) => {
      await page.setViewportSize({ width: w.width, height: w.height });
      await stabilise(page);
      await page.goto("/__visual");
      await expect(page.locator("[data-visual-gallery]")).toBeVisible();
      // Fonts must be loaded before the shot or glyph metrics shift mid-capture.
      await page.evaluate(() => document.fonts.ready);
      await expect(page).toHaveScreenshot(`gallery-${w.name}.png`, {
        fullPage: true,
        maxDiffPixelRatio: 0,
        animations: "disabled",
      });
    });
  }
});

test.describe("width-sensitive specimens at full column width", () => {
  test("@pixel wide specimens @ 1440", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1200 });
    await stabilise(page);
    await page.goto("/__visual");
    // ⛔ CLOSE THE MODAL RATHER THAN MASK IT. The gallery keeps one open on purpose, and it is
    // `fixed inset-0` — so it lies over EVERY element screenshot on this page, not just its own section.
    //
    // The first attempt masked `[role="dialog"]`, which is that full-viewport overlay, and produced a
    // baseline that was ENTIRELY MAGENTA: a solid rectangle that would have compared equal forever with no
    // subject inside it. Caught only by LOOKING at the harvested image before committing it.
    await page.locator('[role="dialog"]').click({ position: { x: 5, y: 5 } });
    await expect(page.locator('[role="dialog"]')).toHaveCount(0);

    const wide = page.locator("[data-wide-specimens]");
    await expect(wide).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    await expect(wide).toHaveScreenshot("gallery-wide-1440.png", {
      maxDiffPixelRatio: 0,
      animations: "disabled",
    });
  });
});

