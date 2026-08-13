import { defineConfig, devices } from "@playwright/test";

// THE VIEWPORT LEG runs as its OWN Playwright project and its OWN CI job — NOT folded into `e2e`.
//
// THREE REASONS, and the first is a lesson from 2026-08-01:
//   1. A job whose failures are buried gets ignored. `e2e` was RED for four consecutive pushes under a green
//      local gate. A visual diff folded into it would inherit that invisibility.
//   2. Different artifacts: this one must upload expected/actual/diff images so a human can adjudicate.
//   3. Different failure MEANING. `e2e` red = broken behaviour. Visual red = SOMETHING MOVED, which may well
//      be intended. Mixing them makes the first less alarming, and the first is the one that must alarm.
//
// ⛔ `--update-snapshots` MUST NEVER RUN IN CI. CI compares; it never writes. A baseline changes only by a
// committed .png, so a silent re-baseline is impossible — it would have to appear in a diff.
export default defineConfig({
  testDir: "./visual",
  timeout: 60_000,
  expect: {
    timeout: 15_000,
    // Zero tolerance. A threshold is a number nobody can justify, and it is the first thing raised when a
    // suite goes red for a reason someone does not want to look at.
    toHaveScreenshot: { maxDiffPixelRatio: 0, animations: "disabled", caret: "hide", scale: "css" },
  },
  // A visual test that passes on a retry is a flaky test, and a flaky visual suite gets rubber-stamped.
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost",
    trace: "off",
    colorScheme: "dark",
    // Pinned so a runner's locale or zone cannot shift a rendered date.
    locale: "en-GB",
    timezoneId: "UTC",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
