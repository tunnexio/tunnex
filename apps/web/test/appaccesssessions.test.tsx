import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AppAccessSessions from "../src/components/AppAccessSessions";
import { api } from "../src/lib/api";
const f = vi.hoisted(() => ({ failed: false, revokeFailed: false }));
const session = { id: "22222222-2222-4222-8222-222222222222", app_id: "app-1", user_id: "33333333-3333-4333-8333-333333333333", installation_generation: "gen-1", app_label: "Payroll", created_at: "2026-10-03T00:00:00Z", expires_at: "2026-10-03T01:00:00Z" };
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: {
  GET: vi.fn(async () => f.failed ? { error: { error: { message: "Sessions unavailable" } } } : { data: { items: [session], limit: 20, offset: 0 } }),
  DELETE: vi.fn(async () => f.revokeFailed ? { error: { error: { message: "Withdrawal unconfirmed" } } } : { response: { status: 204 } }),
} }));
function show() { return render(<MemoryRouter><AppAccessSessions orgId="org-1" appId="app-1" /></MemoryRouter>); }
afterEach(cleanup);beforeEach(() => { vi.clearAllMocks(); f.failed = false; f.revokeFailed = false; });
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
