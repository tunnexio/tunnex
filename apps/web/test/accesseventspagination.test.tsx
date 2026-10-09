import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const f = vi.hoisted(() => ({
  org: { id: "org-a", name: "A" },
  actor: "user-a",
  get: vi.fn(),
  failNext: false,
  emptyNext: false,
}));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: f.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: f.actor, email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: { GET: f.get } }));
import AccessEvents from "../src/pages/AccessEvents";

type Request = { params?: { path?: { orgId?: string }; query?: Record<string, unknown> } };
const shareId = "11111111-1111-4111-8111-111111111111";
const row = (n: number, beam = false) => ({
  id: `01900000-0000-7000-8000-${n.toString().padStart(12, "0")}`,
  created_at: new Date(Date.UTC(2026, 8, 1) - n * 1000).toISOString(),
  occurred_at: new Date(Date.UTC(2026, 8, 1) - n * 1000).toISOString(),
  seq: n, src_ip: `10.99.0.${n + 1}`, dst_ip: "10.0.0.8", protocol: "tcp", decision: "allow",
  ...(beam ? { src_user_id: "user-a", beam: { share_id: shareId, action: "beam.access.allowed", reason: "admission" } } : {}),
});
function eventCalls() { return f.get.mock.calls.filter(([path]) => path.endsWith("/access-events")) as Array<[string, Request]>; }
function show(source = "network") { return render(<MemoryRouter initialEntries={[`/access-events?source=${source}`]}><AccessEvents /></MemoryRouter>); }
function table() { return screen.getByRole("table", { name: "Access events" }); }
function pageRows() { return within(table()).getAllByRole("row"); }
afterEach(cleanup);
beforeEach(() => {
  f.org = { id: "org-a", name: "A" }; f.actor = "user-a"; f.failNext = false; f.emptyNext = false;
  f.get.mockReset().mockImplementation(async (path: string, request?: Request) => {
    if (path.endsWith("/members") || path.endsWith("/devices")) return { data: [] };
    if (path.endsWith("/agents")) return { data: { items: [] } };
    if (path.endsWith("/access-log/health")) return { data: { gateway_collectors: [], retention_dropped: 0, retention_failed: false } };
    if (path.endsWith("/access-events")) {
      const q = request?.params?.query ?? {};
      if (q.cursor_id && f.failNext) return { error: { error: { message: "Next page unavailable" } } };
      if (q.cursor_id && f.emptyNext) return { data: [] };
      const first = q.cursor_id ? Number(String(q.cursor_id).slice(-12)) + 1 : 0;
      return { data: Array.from({ length: 53 }, (_, n) => row(n, q.source === "beam")).slice(first, first + Number(q.limit)) };
    }
    return { data: [] };
  });
});

describe("Access event keyset pages", () => {
  it.each(["network", "beam"])("keeps %s pages bounded, probes without skipping, and restores previous pages from cache", async source => {
    show(source);
    await screen.findByRole("table", { name: "Access events" });
    expect(pageRows()).toHaveLength(21);
    expect(eventCalls()[0][1].params?.query).toMatchObject({ limit: 21 });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(eventCalls()).toHaveLength(2));
    expect(eventCalls()[1][1].params?.query).toMatchObject({ cursor_id: row(19).id, cursor_ts: row(19).created_at, limit: 21, ...(source === "beam" ? { source: "beam" } : {}) });
    await waitFor(() => expect(screen.getByText("Page 2")).toBeTruthy());
    expect(pageRows()).toHaveLength(21);
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(eventCalls()).toHaveLength(2);
    expect(screen.getByText("Page 1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(eventCalls()).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(screen.getByText("Page 3")).toBeTruthy());
    expect(eventCalls()[2][1].params?.query).toMatchObject({ cursor_id: row(39).id, cursor_ts: row(39).created_at });
    expect(pageRows()).toHaveLength(14);
    expect((screen.getByRole("button", { name: "Next page" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Previous page" }) as HTMLButtonElement).disabled).toBe(false);
    if (source === "beam") expect(f.get.mock.calls.some(([path]) => /\/(devices|agents|access-log\/health)$/.test(path))).toBe(false);
  });

  it("resets the paired keyset for real page-size and outcome-filter requests", async () => {
    show(); await screen.findByRole("table", { name: "Access events" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("Page 2");
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    await waitFor(() => expect(eventCalls()).toHaveLength(3));
    expect(eventCalls()[2][1].params?.query).toMatchObject({ limit: 11 });
    expect(eventCalls()[2][1].params?.query?.cursor_id).toBeUndefined();
    expect(eventCalls()[2][1].params?.query?.cursor_ts).toBeUndefined();
    await waitFor(() => expect(pageRows()).toHaveLength(11));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("Page 2");
    fireEvent.click(screen.getByRole("button", { name: "Denies only" }));
    await waitFor(() => expect(eventCalls()).toHaveLength(5));
    expect(eventCalls()[4][1].params?.query).toMatchObject({ limit: 11, denies_only: true });
    expect(eventCalls()[4][1].params?.query?.cursor_id).toBeUndefined();
    await screen.findByText("Page 1");
  });

  it("retries a failed next page using the same keyset and retains a previous-page escape from empty later data", async () => {
    show(); await screen.findByRole("table", { name: "Access events" });
    f.failNext = true;
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("Next page unavailable");
    const failedQuery = eventCalls()[1][1].params?.query;
    f.failNext = false; f.emptyNext = true;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText("Page 2");
    expect(eventCalls()[2][1].params?.query).toEqual(failedQuery);
    expect(screen.getByText("0 results")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Previous page" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(screen.getByText("Page 1")).toBeTruthy(); expect(pageRows()).toHaveLength(21);
    expect(eventCalls()).toHaveLength(3);
  });

  it("withdraws actor-scoped records and ignores a superseded actor's late page", async () => {
    let release!: (value: unknown) => void;
    const normal = f.get.getMockImplementation()!;
    f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/access-events") && eventCalls().length === 1 ? new Promise(resolve => { release = resolve; }) : normal(path, request));
    const view = show(); await waitFor(() => expect(eventCalls()).toHaveLength(1));
    f.actor = "user-b";
    view.rerender(<MemoryRouter><AccessEvents /></MemoryRouter>);
    await screen.findByRole("table", { name: "Access events" });
    await act(async () => release({ data: [{ ...row(80), src_ip: "PRIVATE-OLD-ACTOR" }] }));
    expect(screen.queryByText(/PRIVATE-OLD-ACTOR/)).toBeNull();
    expect(pageRows()).toHaveLength(21);
  });
});
it.each(["historical identity", "share"])("reapplies the same %s filter without withdrawing records into a permanent loader", async filter => {
  show(filter === "share" ? "beam" : "network");
  await screen.findByRole("table", { name: "Access events" });
  fireEvent.click(screen.getByText("More filters"));
  if (filter === "share") fireEvent.change(screen.getByRole("textbox", { name: "Share ID" }), { target: { value: shareId } });
  else fireEvent.change(screen.getByRole("textbox", { name: "Historical identity UUID" }), { target: { value: shareId } });
  const apply = () => fireEvent.click(screen.getByRole("button", { name: filter === "share" ? "Filter share" : "Apply UUID" }));
  apply(); await waitFor(() => expect(eventCalls()).toHaveLength(2));
  await screen.findByRole("table", { name: "Access events" });
  const applied = eventCalls()[1][1].params?.query;
  apply(); await waitFor(() => expect(eventCalls()).toHaveLength(3));
  expect(eventCalls()[2][1].params?.query).toEqual(applied);
  await screen.findByRole("table", { name: "Access events" });
  expect(pageRows()).toHaveLength(21);
  expect(screen.queryByText("Loading access events matching the current filters…")).toBeNull();
});
