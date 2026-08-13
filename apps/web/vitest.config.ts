import { defineConfig } from "vitest/config";

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
    environment: "node",
    environmentMatchGlobs: [["test/**/*.test.tsx", "jsdom"]],
    include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
  },
});
