import { configDefaults, defineConfig } from "vitest/config";

// TODO: restore dormant sandbox feature suites only through
// docs/S-sandbox-shelved-main-reentry.md. Shelving acceptance and shared UI
// remain in active discovery; retained source stays typechecked.
const shelvedSandboxTests = [
  "test/sandbox-connection.test.ts",
  "test/sandbox-custom-skills.test.tsx",
  "test/sandbox-image-profiles.test.tsx",
  "test/sandbox-module.test.tsx",
  "test/sandbox-runner-enrollment.test.tsx",
  "test/sandbox-runner-qualification-trial.test.tsx",
  "test/sandbox-setup.test.tsx",
  "test/sandbox-terminal-picker.test.tsx",
  "test/sandboxes.test.tsx",
  "test/saved-ssh-key-picker.test.tsx",
];
const activeTestExclusions = [...configDefaults.exclude, ...shelvedSandboxTests];

// TWO TIERS, deliberately.
//
// `test/**/*.test.ts` — view-model unit tests in the `node` environment: the pure functions in src/lib that
// encode the consequential decisions. This has been the whole suite since S7.4a, and it stays the default,
// because a decision that can live in a pure function should.
//
// `test/**/*.test.tsx` — COMPONENT tests in jsdom, added in S13.1 Slice 3 and scoped to that slice's surfaces.
// The reason is a measurement, not a preference: four of EPIC 11's fifteen findings lived in the UI, the surface
// with zero automated coverage — the same class as apps/cli having had no CI job at all. And Slice 3 exposed the
// precise gap the pure tier cannot close: extracting `defaultDeviceNode` into src/lib made the RULE testable,
// but nothing could assert that the PAGE calls it. A pure test of the rule passes just as happily while the
// component still reads `nodes[0]`. That wiring is what these tests are for, and nothing more — this is a
// foothold for the registered ledger item, not a retroactive suite for the whole app.
export default defineConfig({
  test: {
    projects: [
      { test: { name: "unit", environment: "node", include: ["test/**/*.test.ts"], exclude: activeTestExclusions } },
      { test: { name: "components", environment: "jsdom", include: ["test/**/*.test.tsx"], exclude: activeTestExclusions } },
    ],
  },
});
