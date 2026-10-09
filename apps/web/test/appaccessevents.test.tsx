import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AppAccessEvents from "../src/pages/AppAccessEvents";
import { api } from "../src/lib/api";

const app = "11111111-1111-4111-8111-111111111111";
const session = "22222222-2222-4222-8222-222222222222";
const f = vi.hoisted(() => ({ org: { id: "org-1", name: "Office" }, failed: false, available: false, more: false, actor: "user-a" }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: f.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: f.actor, email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: { GET: vi.fn(async (_path: string, request?: { params?: { query?: { before_id?: string } } }) => f.failed ? { error: { error: { message: "Event history unavailable" } } } : { data: { items: [], ...(f.more && !request?.params?.query?.before_id ? { next_cursor: { before_time: "2026-10-03T01:00:00Z", before_id: session } } : {}), telemetry: { available: f.available, emitted: 0, dropped: 0, storage_failures: 0 } } }) } }));
function show(path = `/access-events?source=applications&app_id=${app}`) { return render(<MemoryRouter initialEntries={[path]}><AppAccessEvents /></MemoryRouter>); }
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); f.org = { id: "org-1", name: "Office" }; f.failed = false; f.available = false; f.more = false; f.actor = "user-a"; });

it("reads independent app events with exact application/session filters and paired keyset cursor", async () => {
  f.more = true; show(`/access-events?source=applications&app_id=${app}&session_id=${session}`);
  fireEvent.click(await screen.findByRole("button", { name: "Next page" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(2));
  expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/events", { params: { path: { orgId: "org-1" }, query: { limit: 20, app_id: app, session_id: session, before_time: "2026-10-03T01:00:00Z", before_id: session } } });
  expect(api.GET).toHaveBeenNthCalledWith(1, "/api/v1/organizations/{orgId}/app-access/events", expect.any(Object));
  await screen.findByText("Page 2");
  expect(screen.getByText("No events on this page")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
  expect(api.GET).toHaveBeenCalledTimes(2);
  expect(screen.getByText("Page 1")).toBeTruthy();
  expect(screen.getByText(/Current telemetry counters are unavailable/)).toBeTruthy();
  expect(screen.queryByText(/0 dropped/)).toBeNull();
});
it("refuses invalid deep-link filters before any event request", async () => {
  show("/access-events?source=applications&app_id=bad-id");
  expect(screen.getByText(/invalid filter/)).toBeTruthy(); expect(api.GET).not.toHaveBeenCalled();
  fireEvent.change(screen.getByRole("textbox", { name: "Application ID" }), { target: { value: app } });
  fireEvent.click(screen.getByRole("button", { name: "Apply application filters" }));
  await screen.findByText("No application events match this view.");
  expect(api.GET).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ query: { limit: 20, app_id: app } }) }));
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
  expect(screen.getByRole("table", { name: "Application access event history" })).toBeTruthy();
  expect(screen.getByText("Telemetry health")).toBeTruthy();
  expect(screen.getByRole("link", { name: `${app.slice(0, 4)}…${app.slice(-8)}` }).getAttribute("href")).toBe(`/app-access/applications/${app}`);
  expect(screen.getByRole("button", { name: "View request denied event" }).textContent).toBe("denied");
  fireEvent.click(screen.getByRole("button", { name: "View request denied event" }));
  expect(screen.getByRole("navigation", { name: "Application event breadcrumb" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Evidence" }));
  expect(screen.getByText("Event ID").nextElementSibling?.textContent).toBe(session);
  expect(screen.queryByText(/0 dropped/)).toBeNull();
});

const event = (n: number) => ({ id: `01900000-0000-7000-8000-${n.toString().padStart(12, "0")}`, app_id: app, installation_generation: app, created_at: new Date(Date.UTC(2026, 9, 3) - n * 1000).toISOString(), kind: "request_denied", outcome: "denied", reason: "session_invalid" });
const telemetry = { available: false, emitted: 0, dropped: 0, storage_failures: 0 };
type EventRequest = { params?: { path?: { orgId?: string }; query?: Record<string, unknown> } };
function queries() { return vi.mocked(api.GET).mock.calls as unknown as Array<[string, EventRequest]>; }

it("replaces short cursor pages without assuming full pages and caches exact previous results", async () => {
  vi.mocked(api.GET).mockImplementation(async (_path, request) => {
    const q = (request as EventRequest).params?.query ?? {};
    if (q.before_id === event(1).id) return { data: { items: [event(2)], next_cursor: { before_id: event(2).id, before_time: event(2).created_at }, telemetry } } as never;
    if (q.before_id === event(2).id) return { data: { items: [], telemetry } } as never;
    return { data: { items: [event(0), event(1)], next_cursor: { before_id: event(1).id, before_time: event(1).created_at }, telemetry } } as never;
  });
  show();
  await screen.findByText("1–2 shown");
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText("3–3 shown");
  expect(queries()[1][1].params?.query).toMatchObject({ limit: 20, app_id: app, before_id: event(1).id, before_time: event(1).created_at });
  expect(screen.getAllByRole("button", { name: "View request denied event" })).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
  expect(screen.getByText("1–2 shown")).toBeTruthy(); expect(api.GET).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  expect(screen.getByText("3–3 shown")).toBeTruthy(); expect(api.GET).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText("Page 3");
  expect(screen.getByText("No events on this page")).toBeTruthy();
  expect((screen.getByRole("button", { name: "Previous page" }) as HTMLButtonElement).disabled).toBe(false);
});

it("retries a failed application keyset unchanged and resets its query on a real page-size change", async () => {
  let nextFailed = true;
  vi.mocked(api.GET).mockImplementation(async (_path, request) => {
    const q = (request as EventRequest).params?.query ?? {};
    if (q.before_id && nextFailed) return { error: { error: { message: "Application page unavailable" } } } as never;
    return { data: { items: q.before_id ? [event(2)] : [event(0), event(1)], ...(!q.before_id ? { next_cursor: { before_id: event(1).id, before_time: event(1).created_at } } : {}), telemetry } } as never;
  });
  show(); await screen.findByText("1–2 shown");
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText("Application page unavailable");
  const failed = queries()[1][1].params?.query;
  expect(screen.queryByText("No application events match this view.")).toBeNull();
  nextFailed = false; fireEvent.click(screen.getByRole("button", { name: "Retry application events" }));
  await screen.findByText("Page 2"); expect(queries()[2][1].params?.query).toEqual(failed);
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
  await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(4));
  expect(queries()[3][1].params?.query).toEqual({ limit: 10, app_id: app });
  await screen.findByText("Page 1");
});

it("does not accept an application cursor that repeats without advancing", async () => {
  vi.mocked(api.GET).mockImplementation(async () => ({ data: { items: [], next_cursor: { before_id: event(1).id, before_time: event(1).created_at }, telemetry } }) as never);
  show(); fireEvent.click(await screen.findByRole("button", { name: "Next page" }));
  await screen.findByText("Event history did not advance. Refresh before continuing.");
  expect(screen.queryByText("Page 2")).toBeNull();
});
it.each([null, { ...event(0), kind: null }, { ...event(0), reason: 42 }, { ...event(0), app_id: {} }])("shows malformed application evidence as a retryable failure: %j", async record => {
  vi.mocked(api.GET).mockImplementationOnce(async () => ({ data: { items: [record], telemetry } }) as never);
  show(); await screen.findByText("The server returned incomplete application-event evidence. Refresh to try again.");
  expect(screen.queryByRole("table", { name: "Application access event history" })).toBeNull();
  expect(screen.queryByText("No application events match this view.")).toBeNull();
  expect(screen.getByRole("button", { name: "Retry application events" })).toBeTruthy();
});
it("refuses a cursor that loops back to an earlier visited application page", async () => {
  const cursorA = { before_id: event(1).id, before_time: event(1).created_at };
  const cursorB = { before_id: event(2).id, before_time: event(2).created_at };
  vi.mocked(api.GET).mockImplementation(async (_path, request) => {
    const q = (request as EventRequest).params?.query ?? {};
    return { data: { items: q.before_id === cursorB.before_id ? [event(3)] : q.before_id === cursorA.before_id ? [event(2)] : [event(0), event(1)], next_cursor: q.before_id === cursorA.before_id ? cursorB : cursorA, telemetry } } as never;
  });
  show(); await screen.findByText("Page 1");
  fireEvent.click(screen.getByRole("button", { name: "Next page" })); await screen.findByText("Page 2");
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText(/Event history did not advance|Event history repeated an earlier cursor/);
  expect(screen.queryByText("Page 3")).toBeNull();
  expect(screen.getByRole("button", { name: "Previous page" })).toBeTruthy();
});
it("rejects an earlier event served again on the next application page", async () => {
  vi.mocked(api.GET).mockImplementation(async (_path, request) => {
    const q = (request as EventRequest).params?.query ?? {};
    return { data: { items: q.before_id ? [event(0)] : [event(0), event(1)], ...(!q.before_id ? { next_cursor: { before_id: event(1).id, before_time: event(1).created_at } } : {}), telemetry } } as never;
  });
  show(); await screen.findByText("Page 1");
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText(/Event history overlapped earlier events/);
  expect(screen.queryByText("Page 2")).toBeNull();
});
