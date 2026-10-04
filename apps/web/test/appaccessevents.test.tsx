import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AppAccessEvents from "../src/pages/AppAccessEvents";
import { api } from "../src/lib/api";

const app = "11111111-1111-4111-8111-111111111111";
const session = "22222222-2222-4222-8222-222222222222";
const f = vi.hoisted(() => ({ org: { id: "org-1", name: "Office" }, failed: false, available: false, more: false }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: f.org, loading: false, failed: false }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: { GET: vi.fn(async () => f.failed ? { error: { error: { message: "Event history unavailable" } } } : { data: { items: [], ...(f.more ? { next_cursor: { before_time: "2026-10-03T01:00:00Z", before_id: session } } : {}), telemetry: { available: f.available, emitted: 0, dropped: 0, storage_failures: 0 } } }) } }));
function show(path = `/access-events?source=applications&app_id=${app}`) { return render(<MemoryRouter initialEntries={[path]}><AppAccessEvents /></MemoryRouter>); }
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); f.org = { id: "org-1", name: "Office" }; f.failed = false; f.available = false; f.more = false; });

it("reads independent app events with exact application/session filters and paired keyset cursor", async () => {
  f.more = true; show(`/access-events?source=applications&app_id=${app}&session_id=${session}`);
  fireEvent.click(await screen.findByRole("button", { name: "Load earlier application events" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(2));
  expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/events", { params: { path: { orgId: "org-1" }, query: { limit: 50, app_id: app, session_id: session, before_time: "2026-10-03T01:00:00Z", before_id: session } } });
  expect(api.GET).toHaveBeenNthCalledWith(1, "/api/v1/organizations/{orgId}/app-access/events", expect.any(Object));
  expect(screen.getByText(/Current telemetry counters are unavailable/)).toBeTruthy();
  expect(screen.queryByText(/0 dropped/)).toBeNull();
});
it("refuses invalid deep-link filters before any event request", async () => {
  show("/access-events?source=applications&app_id=bad-id");
  expect(screen.getByText(/invalid filter/)).toBeTruthy(); expect(api.GET).not.toHaveBeenCalled();
  fireEvent.change(screen.getByRole("textbox", { name: "Application ID" }), { target: { value: app } });
  fireEvent.click(screen.getByRole("button", { name: "Apply application filters" }));
  await screen.findByText("No application events match this view.");
  expect(api.GET).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ query: { limit: 50, app_id: app } }) }));
});
it("shows event read failure without claiming an empty history", async () => {
  f.failed = true; show(); await screen.findByText("Event history unavailable");
  expect(screen.queryByText("No application events match this view.")).toBeNull();
  f.failed = false; fireEvent.click(screen.getByRole("button", { name: "Retry application events" }));
  await screen.findByText("No application events match this view.");
});
it("discards a previous organization's late event response", async () => {
  let release!: (value: unknown) => void;
  vi.mocked(api.GET).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }) as never);
  const page = show(); await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(1));
  f.org = { id: "org-2", name: "Cloud" };
  page.rerender(<MemoryRouter><AppAccessEvents /></MemoryRouter>);
  await screen.findByText("No application events match this view.");
  await act(async () => release({ data: { items: [{ id: session, app_id: app, installation_generation: app, created_at: "2026-10-03T00:00:00Z", kind: "request_denied", outcome: "denied", reason: "session_invalid" }], telemetry: { available: true, emitted: 99, dropped: 99, storage_failures: 99 } } }));
  expect(screen.queryByText("session invalid")).toBeNull();
  expect(screen.queryByText(/99 recorded/)).toBeNull();
  expect(api.GET).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ path: { orgId: "org-2" } }) }));
});
it("keeps decision evidence distinct from telemetry and links the exact application", async () => {
  vi.mocked(api.GET).mockImplementationOnce(async () => ({ data: { items: [{ id: session, app_id: app, installation_generation: app, created_at: "2026-10-03T00:00:00Z", kind: "request_denied", outcome: "denied", reason: "session_invalid" }], telemetry: { available: false, emitted: 0, dropped: 0, storage_failures: 0 } } }) as never);
  show();
  await screen.findByText("session invalid");
  expect(screen.getByRole("heading", { name: "Filter event history" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Stored decision history" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Telemetry health" })).toBeTruthy();
  expect(screen.getByRole("link", { name: app.slice(0, 8) }).getAttribute("href")).toBe(`/app-access/applications/${app}`);
  expect(screen.getByText("denied")).toBeTruthy();
  expect(screen.queryByText(/0 dropped/)).toBeNull();
});
