import { afterEach, expect, it, vi } from "vitest";
import { setApiOrigin } from "@tunnex/shared";
import { beamUIFixtures, filterBeamUIFixtures } from "../src/lib/beam-ui-fixtures";

// Resolve the browser's same-origin base for Node's absolute-URL Request constructor.
vi.mock("@tunnex/shared", async () => {
  const actual = await vi.importActual<typeof import("@tunnex/shared")>("@tunnex/shared");
  return { ...actual, createTunnexClient: (baseUrl = "/") => actual.createTunnexClient(baseUrl === "/" ? "https://console.example.test" : baseUrl) };
});
vi.mock("../src/lib/beam-ui-fixtures", () => ({
  beamUIFixtures: vi.fn(() => [{ id: "fixture", name: "Local preview", can_open: false, can_manage: false }]),
  filterBeamUIFixtures: vi.fn(() => [{ id: "fixture", name: "Local preview", can_open: false, can_manage: false }]),
}));
afterEach(() => { setApiOrigin(null); vi.unstubAllGlobals(); vi.clearAllMocks(); });

it("passes chosen limits, offsets and filters to the scoped Beam endpoints without merging preview fixtures", async () => {
  const requests: Request[] = [];
  const backendShare = { id: "backend-share", name: "Real share" };
  setApiOrigin("https://console.example.test");
  vi.stubGlobal("fetch", vi.fn(async (request: Request) => {
    requests.push(request);
    return Response.json({ items: [backendShare], limit: 50, offset: 100 });
  }));
  const { beamApi } = await import("../src/lib/beam");
  const { beamRoomsApi } = await import("../src/lib/beam-rooms");
  const orgId = "01900000-0000-7000-8000-000000000001";
  const result = await beamApi.shares(orgId, false, 100, "review", { scope: "active", connectivity: "offline" }, 50);
  expect(result).toEqual({ ok: true, data: { items: [backendShare], limit: 50, offset: 100 } });
  expect(beamUIFixtures).not.toHaveBeenCalled();
  expect(filterBeamUIFixtures).not.toHaveBeenCalled();
  await beamApi.shares(orgId, true, 10, undefined, {}, 10);
  await beamApi.shareEvents(orgId, "share", 20, { outcome: "denied" }, 10);
  await beamApi.events(orgId, 50, { action: "beam.access.allowed" }, 50);
  await beamRoomsApi.projects(orgId, 50, 50);
  await beamRoomsApi.sessions(orgId, "project", 10, "history", 10);
  await beamRoomsApi.feedback(orgId, "share", 50, 50);
  await beamRoomsApi.notifications(orgId, 10, 10);
  expect(requests.map(request => {
    const url = new URL(request.url);
    return [url.pathname.replace(`/api/v1/organizations/${orgId}/beam/`, ""), Object.fromEntries(url.searchParams)];
  })).toEqual([
    ["shares", { limit: "50", offset: "100", q: "review", scope: "active", connectivity: "offline" }],
    ["shared", { limit: "10", offset: "10" }],
    ["shares/share/events", { limit: "10", offset: "20", outcome: "denied" }],
    ["events", { limit: "50", offset: "50", action: "beam.access.allowed" }],
    ["projects", { limit: "50", offset: "50" }],
    ["projects/project/sessions", { limit: "10", offset: "10", scope: "history" }],
    ["shares/share/feedback", { limit: "50", offset: "50" }],
    ["notifications", { limit: "10", offset: "10" }],
  ]);
  expect(requests.every(request => request.cache === "no-store" && request.credentials === "same-origin")).toBe(true);
});
