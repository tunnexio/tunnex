vi.mock("../src/components/TerminalReplay", () => ({ TerminalReplay: (props: unknown) => { f.replay(props); return <section aria-label="Recording playback" />; } }));
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const f = vi.hoisted(() => ({ org: { id: "org-a", name: "A" }, actor: "user-a", get: vi.fn(), replay: vi.fn(), rosterFailed: false }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: f.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: f.actor, email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: { GET: f.get } }));
import AuditLog from "../src/pages/AuditLog";
const entry = { id: "01900000-0000-7000-8000-000000000001", action: "device.created", created_at: "2026-08-01T10:00:00Z", actor_id: "user-a", target_type: "device", target_id: "device-a" };
type Request = { params?: { path?: { orgId?: string }; query?: Record<string, unknown> } };
function show() { return render(<MemoryRouter><AuditLog /></MemoryRouter>); }
afterEach(cleanup);
beforeEach(() => {
  f.org = { id: "org-a", name: "A" }; f.actor = "user-a"; f.rosterFailed = false; f.replay.mockClear();
  f.get.mockReset().mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return f.rosterFailed ? { error: { error: { message: "Roster offline" } } } : { data: [{ user_id: f.actor, name: "Ada", email: "ada@example.com", role: "owner" }] };
    return { data: [entry] };
  });
});
it("does not call a recorded human a former member when the roster is unavailable, and retries names independently", async () => {
  f.rosterFailed = true; show();
  const table = await screen.findByRole("table", { name: "Audit events" });
  await screen.findByText(/Actor names are unavailable/);
  expect(table.textContent).not.toMatch(/Former member|system/i);
  expect((screen.getByRole("combobox", { name: "Actor" }) as HTMLSelectElement).disabled).toBe(true);
  const logReads = f.get.mock.calls.filter(([path]) => path.endsWith("/audit-logs")).length;
  f.rosterFailed = false;
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await within(screen.getByRole("table", { name: "Audit events" })).findByText("Ada");
  expect(f.get.mock.calls.filter(([path]) => path.endsWith("/audit-logs"))).toHaveLength(logReads);
  expect(screen.queryByText(/Actor names are unavailable/)).toBeNull();
});
it.each(["organization", "actor"])("discards a late %s response at the scope boundary", async boundary => {
  let release!: (value: unknown) => void;
  const normal = f.get.getMockImplementation()!;
  let delayed = false;
  f.get.mockImplementation((path: string, request?: Request) => {
    if (path.endsWith("/audit-logs") && !delayed) { delayed = true; return new Promise(resolve => { release = resolve; }); }
    if (path.endsWith("/audit-logs")) return Promise.resolve({ data: [{ ...entry, action: "device.revoked" }] });
    return normal(path, request);
  });
  const view = show(); await waitFor(() => expect(delayed).toBe(true));
  if (boundary === "organization") f.org = { id: "org-b", name: "B" }; else f.actor = "user-b";
  view.rerender(<MemoryRouter><AuditLog /></MemoryRouter>);
  await screen.findByRole("button", { name: "Inspect device.revoked audit event" });
  await act(async () => release({ data: [entry] }));
  expect(screen.queryByRole("button", { name: "Inspect device.created audit event" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Inspect device.revoked audit event" }));
  expect(within(screen.getByRole("region", { name: "Audit evidence" })).getByText("device.revoked")).toBeTruthy();
});
it("keeps audit Refresh on the applied snapshot and validates a reversed date range before a new read", async () => {
  show(); await screen.findByRole("table", { name: "Audit events" });
  fireEvent.change(screen.getByRole("combobox", { name: "Action" }), { target: { value: "device.revoked" } });
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() => expect(f.get.mock.calls.filter(([path]) => path.endsWith("/audit-logs"))).toHaveLength(2));
  const calls = f.get.mock.calls as Array<[string, Request]>;
  expect(calls.filter(([path]) => path.endsWith("/audit-logs"))[1][1].params?.query?.action).toBeUndefined();
  await screen.findByRole("table", { name: "Audit events" });
  fireEvent.click(screen.getByText("More filters"));
  fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-08-03" } });
  fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-08-01" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  expect(screen.getByText("Choose an end date on or after the start date.")).toBeTruthy();
  expect(f.get.mock.calls.filter(([path]) => path.endsWith("/audit-logs"))).toHaveLength(2);
  fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-08-03" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(f.get.mock.calls.filter(([path]) => path.endsWith("/audit-logs"))).toHaveLength(3));
  const applied = (f.get.mock.calls as Array<[string, Request]>).filter(([path]) => path.endsWith("/audit-logs"))[2][1].params?.query;
  expect(applied).toMatchObject({ action: "device.revoked", from: new Date("2026-08-03T00:00:00").toISOString(), to: new Date("2026-08-03T23:59:59.999").toISOString() });
});

it("opens recording review only on explicit request for the exact scoped audit session and withdraws it on scope change", async () => {
  const sessionId = "11111111-1111-4111-8111-111111111111";
  const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/audit-logs") ? Promise.resolve({ data: [{ ...entry, action: "server_access.session_started", target_type: "server_access", target_id: sessionId }] }) : normal(path, request));
  const view = show();
  fireEvent.click(await screen.findByRole("button", { name: "Inspect server_access.session_started audit event" }));
  expect(f.replay).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Review session recording" }));
  expect(f.replay).toHaveBeenLastCalledWith(expect.objectContaining({ orgId: "org-a", sessionId }));
  expect(f.replay.mock.calls[0][0].canManage).not.toBe(true);
  f.org = { id: "org-b", name: "B" };
  view.rerender(<MemoryRouter><AuditLog /></MemoryRouter>);
  expect(screen.queryByRole("region", { name: "Recording playback" })).toBeNull();
});
