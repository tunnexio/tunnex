import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const f = vi.hoisted(() => ({ org: { id: "org-a", name: "A" }, actor: "user-a", verified: true, role: "owner", get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), subscriptionsFailed: false }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: f.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: f.actor, email_verified: f.verified } } }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: { GET: f.get, POST: f.post, PUT: f.put, DELETE: f.del } }));
import Alerts from "../src/pages/Alerts";
const policy = { id: "11111111-1111-4111-8111-111111111111", name: "Platform on-call", kind: "webhook", endpoint_host: "hooks.example.com", endpoint_fingerprint: "a1b2c3", severity_floor: "warning", cooldown_seconds: 900, allow_private: false, archived: false, created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" };
const occurrence = (n: number) => ({ id: `01900000-0000-7000-8000-${n.toString().padStart(12, "0")}`, event_key: "gateway.offline", dedup_key: `gateway:${n}:offline`, resource_type: "gateway", resource_id: `gateway-${n}`, resource_name: `Gateway ${n}`, severity: n % 2 ? "warning" : "critical", subject: `Gateway ${n} offline`, fields: {}, state: "firing", first_observed_at: "2026-09-01T00:00:00Z", last_observed_at: "2026-09-01T00:00:00Z", resolved_at: null, occurrence_count: 2 });
type Request = { params?: { path?: { orgId?: string; destinationId?: string }; query?: Record<string, unknown> }; body?: Record<string, unknown> };
function show() { return render(<MemoryRouter><Alerts /></MemoryRouter>); }
async function management() { fireEvent.click(await screen.findByRole("tab", { name: "Management" })); await screen.findByRole("table", { name: "Routing policies" }); }
function routeAction(label: string) { fireEvent.click(screen.getByRole("button", { name: `Routing policy actions for ${policy.name}` })); fireEvent.click(screen.getByRole("menuitem", { name: label })); }
function wizardDestination() {
  fireEvent.click(screen.getByRole("button", { name: "New routing policy" }));
  const dialog = screen.getByRole("dialog", { name: "New routing policy" });
  fireEvent.change(within(dialog).getByRole("textbox", { name: "Policy name" }), { target: { value: "  New response  " } });
  fireEvent.change(within(dialog).getByRole("textbox", { name: "Endpoint" }), { target: { value: "https://hooks.example.com/PRIVATE-SECRET" } });
  return dialog;
}
afterEach(cleanup);
beforeEach(() => {
  f.org = { id: "org-a", name: "A" }; f.actor = "user-a"; f.verified = true; f.role = "owner"; f.subscriptionsFailed = false;
  f.get.mockReset().mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: f.actor, role: f.role }] };
    if (path.endsWith("/alert-occurrences")) return { data: [occurrence(0)] };
    if (path.endsWith("/alerting-settings")) return { data: { enabled: true } };
    if (path.endsWith("/alert-destinations")) return { data: [policy] };
    if (path.endsWith("/subscriptions")) return f.subscriptionsFailed ? { error: { error: { message: "Signals offline" } } } : { data: ["gateway.offline"] };
    if (path.endsWith("/alert-deliveries")) return { data: [] };
    return { data: [] };
  });
  f.post.mockReset().mockResolvedValue({ data: {} }); f.put.mockReset().mockResolvedValue({ data: { enabled: false } }); f.del.mockReset().mockResolvedValue({ data: {} });
});
it("pages actual loaded occurrences and resets search/severity without additional server reads", async () => {
  const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/alert-occurrences") ? Promise.resolve({ data: Array.from({ length: 53 }, (_, n) => occurrence(n)) }) : normal(path, request));
  show(); const table = await screen.findByRole("table", { name: "Active alerts" });
  expect(within(table).getAllByRole("row")).toHaveLength(21);
  fireEvent.click(screen.getByRole("button", { name: "Next alerts page" }));
  fireEvent.click(screen.getByRole("button", { name: "Next alerts page" }));
  expect(within(table).getAllByRole("row")).toHaveLength(14);
  expect((screen.getByRole("button", { name: "Next alerts page" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByRole("searchbox", { name: "Search alerts" }), { target: { value: "Gateway 52 offline" } });
  expect(screen.getByRole("button", { name: "Gateway 52 offline" })).toBeTruthy();
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  fireEvent.change(screen.getByRole("searchbox", { name: "Search alerts" }), { target: { value: "" } });
  fireEvent.click(screen.getByRole("button", { name: "warning" }));
  expect(within(screen.getByRole("table", { name: "Active alerts" })).getAllByRole("row")).toHaveLength(21);
  expect(screen.getByText("Page 1")).toBeTruthy();
  expect(f.get.mock.calls.filter(([path]) => path.endsWith("/alert-occurrences"))).toHaveLength(1);
});
it("keeps all real delivery outcomes reachable across pages instead of truncating to twelve", async () => {
  const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/alert-deliveries") ? Promise.resolve({ data: Array.from({ length: 53 }, (_, n) => ({ id: `delivery-${n}`, destination_id: policy.id, event_key: "gateway.offline", severity: "critical", state: n === 52 ? "failed" : "sent", attempts: n + 1, suppressed_count: 0, created_at: "2026-09-01T00:00:00Z", last_error: n === 52 ? "Receiver refused" : "" })) }) : normal(path, request));
  show(); await management();
  fireEvent.click(screen.getByRole("button", { name: /^Delivery activity/ }));
  const table = screen.getByRole("table", { name: "Delivery activity" });
  expect(within(table).getAllByRole("row")).toHaveLength(21);
  fireEvent.click(screen.getByRole("button", { name: "Next deliveries page" })); fireEvent.click(screen.getByRole("button", { name: "Next deliveries page" }));
  expect(within(table).getAllByRole("row")).toHaveLength(14);
  expect(within(table).getByText("Receiver refused")).toBeTruthy();
  expect(within(table).getByText("failed")).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
  expect(screen.getByText("Page 1")).toBeTruthy(); expect(within(table).getAllByRole("row")).toHaveLength(11);
  fireEvent.change(screen.getByRole("searchbox", { name: "Search delivery activity" }), { target: { value: "Receiver refused" } });
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
});
it("shows unknown subscriptions rather than zero signals and retries that read before enabling edits", async () => {
  f.subscriptionsFailed = true; show(); await management();
  expect(screen.getByText("Signals unavailable")).toBeTruthy(); expect(screen.queryByText("0 signals")).toBeNull();
  routeAction("Edit signals"); const dialog = screen.getByRole("dialog", { name: policy.name });
  expect(within(dialog).getByRole("heading", { name: "Signals unavailable" })).toBeTruthy();
  expect(within(dialog).queryByRole("checkbox")).toBeNull();
  f.subscriptionsFailed = false; fireEvent.click(within(dialog).getByRole("button", { name: "Retry signals" }));
  const check = await within(dialog).findByRole("checkbox", { name: "Gateway offline" }); expect((check as HTMLInputElement).checked).toBe(true);
  expect(f.post).not.toHaveBeenCalled(); expect(f.del).not.toHaveBeenCalled();
});
it("updates one exact signal at a time and keeps a refused edit visible in the policy drawer", async () => {
  show(); await management(); routeAction("Edit signals"); const dialog = screen.getByRole("dialog", { name: policy.name });
  fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway policy degraded" }));
  await waitFor(() => expect(f.post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions", { params: { path: { orgId: "org-a", destinationId: policy.id } }, body: { event_key: "gateway.policy_degraded" } }));
  await waitFor(() => expect((within(dialog).getByRole("checkbox", { name: "Gateway policy degraded" }) as HTMLInputElement).checked).toBe(true));
  fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway offline" }));
  await waitFor(() => expect(f.del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions/{eventKey}", { params: { path: { orgId: "org-a", destinationId: policy.id, eventKey: "gateway.offline" } } }));
  await waitFor(() => expect((within(dialog).getByRole("checkbox", { name: "Gateway offline" }) as HTMLInputElement).checked).toBe(false));
  f.post.mockResolvedValueOnce({ error: { error: { message: "Signal update refused" } } });
  fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway offline" }));
  await within(dialog).findByText("Signal update refused");
  expect((within(dialog).getByRole("checkbox", { name: "Gateway offline" }) as HTMLInputElement).checked).toBe(false);
});
it("tests a routing policy explicitly and does not turn an unknown delivery result into success", async () => {
  show(); await management();
  routeAction("Send test"); await screen.findByText("Could not confirm the test result. Refresh before trying again.");
  expect(f.post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/test", { params: { path: { orgId: "org-a", destinationId: policy.id } } });
  expect(screen.queryByText(/^Test delivered/)).toBeNull();
  f.post.mockResolvedValueOnce({ data: { delivered: false, failure_code: "network" } });
  routeAction("Send test"); await screen.findByText(`Test failed for ${policy.name}: network.`);
});
it("requires archive confirmation and withdraws a staged archive on organization switch", async () => {
  const view = show(); await management(); routeAction("Archive");
  const dialog = screen.getByRole("dialog", { name: "Archive routing policy?" });
  expect(within(dialog).getByText(policy.name)).toBeTruthy(); expect(f.del).not.toHaveBeenCalled();
  f.org = { id: "org-b", name: "B" }; view.rerender(<MemoryRouter><Alerts /></MemoryRouter>);
  expect(screen.queryByRole("dialog", { name: "Archive routing policy?" })).toBeNull(); expect(f.del).not.toHaveBeenCalled();
  await management(); routeAction("Archive");
  fireEvent.click(within(screen.getByRole("dialog", { name: "Archive routing policy?" })).getByRole("button", { name: "Archive" }));
  await waitFor(() => expect(f.del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}", { params: { path: { orgId: "org-b", destinationId: policy.id } } }));
});
it.each(["owner", "admin"])("keeps private-network destination allowance restricted for %s", async role => {
  f.role = role; show(); await management(); const dialog = wizardDestination();
  const choice = within(dialog).queryByRole("checkbox", { name: /^Allow private-network destination/ });
  if (role === "owner") { expect(choice).toBeTruthy(); fireEvent.click(choice!); } else expect(choice).toBeNull();
  fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
  fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway offline" }));
  f.post.mockImplementation(async (path: string) => path.endsWith("/alert-destinations") ? { data: { ...policy, id: "22222222-2222-4222-8222-222222222222" } } : { data: {} });
  fireEvent.click(within(dialog).getByRole("button", { name: "Create policy" }));
  await waitFor(() => expect(f.post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/alert-destinations", { params: { path: { orgId: "org-a" } }, body: { kind: "webhook", name: "New response", endpoint: "https://hooks.example.com/PRIVATE-SECRET", allow_private: role === "owner", severity_floor: "warning", cooldown_seconds: 900 } }));
  await screen.findByText("Routing policy created.");
  expect(screen.queryByDisplayValue(/PRIVATE-SECRET/)).toBeNull();
});
it("preserves a partial-created policy warning after reconciliation and never replays the secret", async () => {
  show(); await management(); const dialog = wizardDestination();
  fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
  expect(f.post).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway offline" }));
  fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway policy degraded" }));
  let sub = 0;
  f.post.mockImplementation(async (path: string) => path.endsWith("/alert-destinations") ? { data: { ...policy, id: "22222222-2222-4222-8222-222222222222" } } : ++sub === 1 ? { data: {} } : { error: { error: { message: "Second signal refused" } } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Create policy" }));
  await screen.findByText(/The route was created, but not every signal could be subscribed \(1 of 2 confirmed\)/);
  expect(screen.queryByRole("dialog", { name: "New routing policy" })).toBeNull();
  expect(f.post.mock.calls.map(([path]) => path)).toEqual(["/api/v1/organizations/{orgId}/alert-destinations", "/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions", "/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions"]);
  expect(screen.queryByText(/PRIVATE-SECRET/)).toBeNull();
});
it("withdraws an unverified editor and withholds every signal/test/archive write", async () => {
  const view = show(); await management(); wizardDestination();
  f.verified = false; view.rerender(<MemoryRouter><Alerts /></MemoryRouter>);
  expect(screen.queryByRole("dialog", { name: "New routing policy" })).toBeNull();
  await management();
  expect((screen.getByRole("button", { name: "New routing policy" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: `Routing policy actions for ${policy.name}` }));
  expect(screen.queryByRole("menuitem", { name: "Send test" })).toBeNull(); expect(screen.queryByRole("menuitem", { name: "Archive" })).toBeNull();
  fireEvent.click(screen.getByRole("menuitem", { name: "View signals" }));
  expect((screen.getByRole("checkbox", { name: "Gateway offline" }) as HTMLInputElement).matches(":disabled")).toBe(true);
  expect(f.post).not.toHaveBeenCalled(); expect(f.put).not.toHaveBeenCalled(); expect(f.del).not.toHaveBeenCalled();
});
it("ignores a superseded actor's late occurrence response without granting management", async () => {
  let release!: (value: unknown) => void; const normal = f.get.getMockImplementation()!; let delayed = false;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/alert-occurrences") && !delayed ? (delayed = true, new Promise(resolve => { release = resolve; })) : normal(path, request));
  const view = show(); await waitFor(() => expect(delayed).toBe(true));
  f.actor = "member-b"; f.role = "member"; view.rerender(<MemoryRouter><Alerts /></MemoryRouter>);
  await screen.findByRole("table", { name: "Active alerts" });
  await act(async () => release({ data: [{ ...occurrence(99), subject: "PRIVATE-OLD-ACTOR" }] }));
  expect(screen.queryByText("PRIVATE-OLD-ACTOR")).toBeNull(); expect(screen.queryByRole("tab", { name: "Management" })).toBeNull();
  expect(f.get.mock.calls.some(([path]) => path.endsWith("/alert-destinations"))).toBe(false);
});
it("does not subscribe a late-created policy after the editor's organization is withdrawn", async () => {
  let release!: (value: unknown) => void;
  const view = show(); await management(); const dialog = wizardDestination();
  fireEvent.click(within(dialog).getByRole("button", { name: "Continue" })); fireEvent.click(within(dialog).getByRole("checkbox", { name: "Gateway offline" }));
  f.post.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  fireEvent.click(within(dialog).getByRole("button", { name: "Create policy" }));
  await waitFor(() => expect(f.post).toHaveBeenCalledTimes(1));
  f.org = { id: "org-b", name: "B" }; view.rerender(<MemoryRouter><Alerts /></MemoryRouter>);
  await screen.findByRole("table", { name: "Active alerts" });
  await act(async () => release({ data: { ...policy, id: "33333333-3333-4333-8333-333333333333" } }));
  expect(f.post).toHaveBeenCalledTimes(1); expect(screen.queryByText("Routing policy created.")).toBeNull();
});
it.each(["alert-destinations", "alert-deliveries", "alerting-settings"])("keeps a failed %s read unavailable rather than empty or paused", async endpoint => {
  const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith(`/${endpoint}`) ? Promise.resolve({ error: { error: { message: "Inventory offline" } } }) : normal(path, request));
  show(); fireEvent.click(await screen.findByRole("tab", { name: "Management" }));
  if (endpoint === "alert-deliveries") fireEvent.click(await screen.findByRole("button", { name: /^Delivery activity/ }));
  await screen.findByText(endpoint === "alert-destinations" ? "Routing policies unavailable" : endpoint === "alert-deliveries" ? "Delivery activity unavailable" : "Delivery setting unavailable");
  expect(screen.queryByText("No routing policies yet.")).toBeNull();
  expect(screen.queryByText("No delivery attempts yet.")).toBeNull();
  expect(screen.queryByText("Paused")).toBeNull();
});

it.each([
  { state: undefined },
  { state: "unknown" },
  { occurrence_count: -1 },
  { occurrence_count: 1.5 },
  { severity: "unknown" },
  { last_observed_at: "invalid-date" },
])("refuses malformed condition evidence %j instead of inventing resolution or counts", async invalid => {
  const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/alert-occurrences") ? Promise.resolve({ data: [{ ...occurrence(0), ...invalid }] }) : normal(path, request));
  show(); await screen.findByRole("heading", { name: "Could not load alerts." });
  expect(screen.getByText("The alert response could not be read.")).toBeTruthy();
  expect(screen.queryByRole("table", { name: "Active alerts" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Gateway 0 offline" })).toBeNull();
  expect(screen.queryByText("No active conditions have been recorded.")).toBeNull();
  expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
});
it.each([
  { roster: [{ user_id: "user-a", role: "member", roles: "owner" }] },
  { roster: [{ user_id: "user-a", role: "member", roles: ["owner"] }] },
  { roster: [{ user_id: "user-a", role: "owner", roles: ["owner", "unknown"] }] },
  { roster: [{ user_id: "user-a", role: "owner" }, { user_id: "user-a", role: "member" }] },
])("withholds alert management when authority data is malformed: %j", async ({ roster }) => {
  const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => path.endsWith("/members") ? Promise.resolve({ data: roster }) : normal(path, request));
  show(); await screen.findByRole("table", { name: "Active alerts" });
  await screen.findByText(/Management permissions could not be checked/);
  expect(screen.queryByRole("tab", { name: "Management" })).toBeNull();
  expect(f.get.mock.calls.some(([path]) => path.endsWith("/alert-destinations"))).toBe(false);
  expect(f.post).not.toHaveBeenCalled(); expect(f.put).not.toHaveBeenCalled(); expect(f.del).not.toHaveBeenCalled();
});
it("does not let a late active-condition read overwrite the selected resolved history", async () => {
  let release!: (value: unknown) => void; const normal = f.get.getMockImplementation()!;
  f.get.mockImplementation((path: string, request?: Request) => {
    if (path.endsWith("/alert-occurrences")) return request?.params?.query?.state === "firing" ? new Promise(resolve => { release = resolve; }) : Promise.resolve({ data: [{ ...occurrence(1), state: "resolved", resolved_at: "2026-09-01T01:00:00Z" }] });
    return normal(path, request);
  });
  show(); await waitFor(() => expect(release).toBeTypeOf("function"));
  fireEvent.click(screen.getByRole("tab", { name: "History" }));
  await screen.findByRole("table", { name: "Resolved alert history" });
  await act(async () => release({ data: [{ ...occurrence(0), subject: "PRIVATE-OLD-ACTIVE" }] }));
  expect(screen.queryByText("PRIVATE-OLD-ACTIVE")).toBeNull();
  expect(screen.getByRole("table", { name: "Resolved alert history" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "History" }).getAttribute("aria-selected")).toBe("true");
});
