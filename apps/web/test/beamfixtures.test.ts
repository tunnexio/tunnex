import { afterEach, expect, it, vi } from "vitest";

const fixtureOrg = "01900000-0000-7000-8000-000000000001";
afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });
async function fixtures(dev: boolean, flag: string) {
  vi.stubEnv("DEV", dev);
  vi.stubEnv("VITE_BEAM_UI_FIXTURES", flag);
  vi.resetModules();
  return import("../src/lib/beam-ui-fixtures");
}

it.each([[false, "1"], [true, "0"], [true, ""]] as const)("requires development and explicit opt-in (DEV=%s, flag=%s)", async (dev, flag) => {
  const module = await fixtures(dev, flag);
  expect(module.beamUIFixtures(fixtureOrg)).toEqual([]);
  expect(module.filterBeamUIFixtures(fixtureOrg, undefined, {})).toEqual([]);
});
it("restricts read-only sample states to the seeded organization and never invents history", async () => {
  const module = await fixtures(true, "1");
  expect(module.beamUIFixtures("another-organization")).toEqual([]);
  const samples = module.beamUIFixtures(fixtureOrg);
  expect(samples).toHaveLength(4);
  expect(samples.every(sample => sample.org_id === fixtureOrg && sample.can_manage === false && sample.can_open === false)).toBe(true);
  expect(new Set(samples.map(sample => sample.id)).size).toBe(samples.length);
  expect(module.filterBeamUIFixtures(fixtureOrg, undefined, { scope: "history" })).toEqual([]);
  const offline = module.filterBeamUIFixtures(fixtureOrg, "documentation", { connectivity: "offline", scope: "active" });
  expect(offline.map(sample => sample.name)).toEqual(["API documentation"]);
  expect(offline[0].can_open).toBe(false);
});
