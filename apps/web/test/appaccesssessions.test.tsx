import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AppAccessSessions from "../src/components/AppAccessSessions";
import { api } from "../src/lib/api";
const f = vi.hoisted(() => ({ failed: false, revokeFailed: false, count: 1 as number | null }));
const session = { id: "22222222-2222-4222-8222-222222222222", app_id: "app-1", user_id: "33333333-3333-4333-8333-333333333333", installation_generation: "gen-1", app_label: "Payroll", created_at: "2026-10-03T00:00:00Z", expires_at: "2026-10-03T01:00:00Z" };
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: {
  GET: vi.fn(async (_path: string, options: any) => {
    if (f.failed) return { error: { error: { message: "Sessions unavailable" } } };
    const { limit, offset } = options.params.query;
    return { data: { items: Array.from({ length: f.count ?? limit }, (_, index) => ({ ...session, id: index === 0 && offset === 0 ? session.id : `${String(offset + index).padStart(8, "0")}${session.id.slice(8)}` })), limit, offset } };
  }),
  DELETE: vi.fn(async () => f.revokeFailed ? { error: { error: { message: "Withdrawal unconfirmed" } } } : { response: { status: 204 } }),
} }));
function show() { return render(<MemoryRouter><AppAccessSessions orgId="org-1" appId="app-1" /></MemoryRouter>); }
afterEach(cleanup);beforeEach(() => { vi.clearAllMocks(); f.failed = false; f.revokeFailed = false; f.count = 1; });
it("confirms one exact application session before withdrawal and links its scoped events", async () => {
  show(); fireEvent.click(await screen.findByRole("button", { name: "Revoke 22222222" }));
  expect(api.DELETE).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Confirm session revocation" }));
  await screen.findByText(/New requests for this session are denied/);
  expect(api.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/sessions/{sessionId}", { params: { path: { orgId: "org-1", appId: "app-1", sessionId: session.id } } });
  expect(screen.getByRole("link", { name: "Session events" }).getAttribute("href")).toBe(`/access-events?source=applications&app_id=app-1&session_id=${session.id}`);
});
it("does not claim withdrawal or automatically retry an uncertain mutation", async () => {
  f.revokeFailed = true; show();fireEvent.click(await screen.findByRole("button", { name: "Revoke 22222222" }));fireEvent.click(screen.getByRole("button", { name: "Confirm session revocation" }));
  await screen.findByText("Withdrawal unconfirmed");
  expect(screen.queryByText(/New requests for this session are denied/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Refresh application sessions" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(2));expect(api.DELETE).toHaveBeenCalledTimes(1);
});
it("keeps failed reads distinct from no current sessions", async () => {
  f.failed = true; show();await screen.findByText("Sessions unavailable");
  expect(screen.queryByText("No current sessions in this view.")).toBeNull();
});

it("shows a short session identity and semantic timing alongside the scoped user", async () => {
  const view = show();
  expect(await screen.findByText("22222222")).toHaveProperty("title", session.id);
  expect(screen.getByText("33333333")).toHaveProperty("title", session.user_id);
  expect([...view.container.querySelectorAll("time")].map(item => item.dateTime)).toEqual([session.created_at, session.expires_at]);
  expect(screen.getByText(/without changing the application's grants/)).toBeTruthy();
});

it("queries the selected session limit and resets the offset when page size changes", async () => {
  f.count = null;
  show();
  await screen.findByRole("table", { name: "Application sessions" });
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
  await screen.findByRole("table", { name: "Application sessions" });
  expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/sessions", { params: { path: { orgId: "org-1", appId: "app-1" }, query: { limit: 10, offset: 0 } } });
  expect(screen.getAllByRole("row")).toHaveLength(11);
  fireEvent.click(screen.getByRole("button", { name: "Next sessions" }));
  await screen.findByRole("table", { name: "Application sessions" });
  expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/sessions", { params: { path: { orgId: "org-1", appId: "app-1" }, query: { limit: 10, offset: 10 } } });
  expect(screen.getByText("11–20 shown")).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
  await screen.findByRole("table", { name: "Application sessions" });
  expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/sessions", { params: { path: { orgId: "org-1", appId: "app-1" }, query: { limit: 50, offset: 0 } } });
  expect(screen.getAllByRole("row")).toHaveLength(51);
  expect(screen.getByRole("button", { name: "Previous sessions" })).toHaveProperty("disabled", true);
  expect(api.DELETE).not.toHaveBeenCalled();
});

it("omits pagination on an empty session list without empty table headers", async () => {
  f.count = 0;
  show();
  await screen.findByRole("heading", { name: "No current sessions" });
  expect(screen.queryByRole("table", { name: "Application sessions" })).toBeNull();
  expect(screen.queryByRole("columnheader")).toBeNull();
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
  expect(screen.queryByText("0 results")).toBeNull();
});
