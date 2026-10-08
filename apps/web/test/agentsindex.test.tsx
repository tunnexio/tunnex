import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router-dom";
import { Profiler } from "react";
import type { AgentRow } from "../src/lib/agentview";

const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(),
  org: { id: "org-a", name: "Organization A", managed_agent_runtime_enabled: true },
  auth: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } },
  role: "owner",
}));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("../src/components/AddAgentFlow", () => ({ AddAgentFlow: ({ onDismiss }: { onDismiss: () => void }) => <div role="dialog" aria-label="Agent enrollment"><button onClick={onDismiss}>Close enrollment</button></div> }));
import AgentsIndex from "../src/pages/AgentsIndex";

const agentsPath = "/api/v1/organizations/{orgId}/agents";
type Query = { limit: number; cursor?: string; q?: string; lifecycle?: string[]; dir?: string };
type Request = { params: { path: { orgId: string }; query?: Query } };
const agent = (index: number, values: Partial<AgentRow> = {}): AgentRow => ({
  device_id: `agent-${index}`, name: `Agent ${String(index).padStart(2, "0")}`, owner_email: "owner@example.test",
  unattributable: false, address: `10.80.0.${index}`, gateway_name: "Gateway A", status: "active",
  config_issued: true, online: true, gateway_reporting: true, last_handshake_at: "2026-10-08T08:00:00Z", ...values,
});
function seed(load: (query: Query, orgId: string) => unknown = () => ({ items: [agent(1)] })) {
  state.GET.mockImplementation(async (path: string, request?: Request) => {
    if (path.endsWith("/members")) return { data: [{ user_id: state.auth.user.id, role: state.role }] };
    if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
    if (path === agentsPath) return { data: await load(request!.params.query!, request!.params.path.orgId) };
    return { data: [] };
  });
}
function Location() { return <output aria-label="Agent route">{useLocation().search}</output>; }
const view = () => <><AgentsIndex /><Location /></>;
const mount = (url = "/agents") => render(<MemoryRouter initialEntries={[url]}>{view()}</MemoryRouter>);
const reads = () => state.GET.mock.calls.filter(([path]) => path === agentsPath).map(([, request]) => request as Request);
const row = (name: string) => screen.getByRole("link", { name }).closest("tr")!;
beforeEach(() => {
  vi.resetAllMocks();
  state.org = { id: "org-a", name: "Organization A", managed_agent_runtime_enabled: true };
  state.auth = { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } };
  state.role = "owner";
  seed();
});
afterEach(cleanup);

describe("AI Agents inventory paging and authority", () => {
  it("does not show pagination for one measured first-page result", async () => {
    mount();
    await screen.findByRole("link", { name: "Agent 01" });
    expect(reads()[0].params.query).toMatchObject({ limit: 20 });
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
  });

  it("replaces cursor pages, preserves a short last page, and returns through the actual cursor history", async () => {
    const all = Array.from({ length: 43 }, (_, index) => agent(index + 1));
    seed(query => {
      const offset = query.cursor === "second-backend-token" ? 20 : query.cursor === "third-backend-token" ? 40 : 0;
      return { items: all.slice(offset, offset + query.limit), next_cursor: offset === 0 ? "second-backend-token" : offset === 20 ? "third-backend-token" : null };
    });
    mount(); await screen.findByRole("link", { name: "Agent 01" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("link", { name: "Agent 21" });
    expect(screen.queryByRole("link", { name: "Agent 01" })).toBeNull();
    expect(reads().at(-1)!.params.query).toMatchObject({ cursor: "second-backend-token", limit: 20 });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("link", { name: "Agent 43" });
    expect(within(screen.getByRole("table", { name: "AI Agents" })).getAllByRole("row")).toHaveLength(4);
    expect(screen.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    await screen.findByRole("link", { name: "Agent 21" });
    expect(reads().at(-1)!.params.query?.cursor).toBe("second-backend-token");
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    await screen.findByRole("link", { name: "Agent 01" });
    expect(reads().at(-1)!.params.query?.cursor).toBeUndefined();
  });

  it("retains a way back from an empty later cursor page", async () => {
    seed(query => query.cursor ? { items: [], next_cursor: null } : { items: [agent(1)], next_cursor: "empty-backend-token" });
    mount(); await screen.findByRole("link", { name: "Agent 01" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(screen.queryByRole("link", { name: "Agent 01" })).toBeNull());
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    await screen.findByRole("link", { name: "Agent 01" });
    expect(reads().at(-1)!.params.query?.cursor).toBeUndefined();
  });

  it("uses real page-size limits and resets cursor and history when the size changes", async () => {
    const all = Array.from({ length: 55 }, (_, index) => agent(index + 1));
    seed(query => ({ items: all.slice(query.cursor ? 20 : 0, (query.cursor ? 20 : 0) + query.limit), next_cursor: "backend-next" }));
    mount(); await screen.findByRole("link", { name: "Agent 01" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("link", { name: "Agent 21" });
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    await screen.findByRole("link", { name: "Agent 01" });
    expect(reads().at(-1)!.params.query).toMatchObject({ limit: 10 });
    expect(reads().at(-1)!.params.query?.cursor).toBeUndefined();
    expect(screen.getByLabelText("Agent route").textContent).not.toContain("previous_cursor");
    expect(within(screen.getByRole("table", { name: "AI Agents" })).getAllByRole("row")).toHaveLength(11);
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    await screen.findByRole("link", { name: "Agent 50" });
    expect(reads().at(-1)!.params.query).toMatchObject({ limit: 50 });
    expect(reads().at(-1)!.params.query).not.toHaveProperty("offset");
  });

  it.each([
    ["search", "Search AI agents", "q", "filtered"],
    ["lifecycle", "All lifecycle states", "lifecycle", "revoked"],
    ["sort", "Sort AI agents", "dir", "name:desc"],
  ])("resets current and prior cursors when changing %s", async (_kind, label, key, value) => {
    seed(() => ({ items: [agent(1)], next_cursor: "next-token" }));
    mount("/agents?cursor=current-token&previous_cursor=&previous_cursor=older-token");
    await screen.findByRole("link", { name: "Agent 01" });
    if (key === "lifecycle") fireEvent.click(screen.getByRole("button", { name: /^Filters/ }));
    fireEvent.change(screen.getByRole(key === "q" ? "textbox" : "combobox", { name: label }), { target: { value } });
    await waitFor(() => expect(reads().at(-1)!.params.query?.cursor).toBeUndefined());
    const query = reads().at(-1)!.params.query!;
    expect(query[key as keyof Query]).toEqual(key === "lifecycle" ? ["revoked"] : key === "dir" ? "desc" : "filtered");
    expect(screen.getByLabelText("Agent route").textContent).not.toContain("previous_cursor");
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", true);
  });

  it("treats a direct cursor as a later page with a return to the first page", async () => {
    seed(() => ({ items: [agent(2)], next_cursor: null }));
    mount("/agents?cursor=shared-backend-token");
    await screen.findByRole("link", { name: "Agent 02" });
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    await waitFor(() => expect(reads().at(-1)!.params.query?.cursor).toBeUndefined());
  });

  it("preserves reporter-unknown and revoked states without claiming connectivity", async () => {
    seed(() => ({ items: [agent(1, { online: false, gateway_reporting: false }), agent(2, { status: "revoked", online: true })], partial: true }));
    mount(); await screen.findByRole("link", { name: "Agent 01" });
    expect(within(row("Agent 01")).getByText("liveness unknown")).toBeTruthy();
    expect(within(row("Agent 01")).queryByText(/last seen|connected/)).toBeNull();
    expect(within(row("Agent 02")).getByText("revoked")).toBeTruthy();
    expect(within(row("Agent 02")).queryByText("connected")).toBeNull();
    expect(screen.getByText(/Some posture data is unavailable/).getAttribute("role")).toBe("status");
  });

  it("withdraws enrollment requested in the URL for a plain member", async () => {
    state.role = "member"; mount("/agents?add=1");
    await screen.findByRole("link", { name: "Agent 01" });
    expect(screen.queryByRole("button", { name: "Add agent" })).toBeNull();
    expect(screen.queryByRole("dialog", { name: "Agent enrollment" })).toBeNull();
    expect(screen.getByLabelText("Agent route").textContent).not.toContain("add=1");
    expect(state.POST).not.toHaveBeenCalled();
  });

  it("opens and closes enrollment without reloading or losing the current cursor page", async () => {
    seed(query => ({ items: [agent(query.cursor ? 21 : 1)], next_cursor: query.cursor ? null : "second-page" }));
    mount(); await screen.findByRole("link", { name: "Agent 01" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("link", { name: "Agent 21" });
    const readCount = state.GET.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));
    expect(screen.getByRole("dialog", { name: "Agent enrollment" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Agent 21" })).toBeTruthy();
    expect(state.GET).toHaveBeenCalledTimes(readCount);
    expect(screen.getByLabelText("Agent route").textContent).toContain("cursor=second-page");
    fireEvent.click(screen.getByRole("button", { name: "Close enrollment" }));
    expect(screen.queryByRole("dialog", { name: "Agent enrollment" })).toBeNull();
    expect(screen.getByRole("link", { name: "Agent 21" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    expect(state.GET).toHaveBeenCalledTimes(readCount);
  });

  it("does not read inventory or deployment entitlement when membership is forbidden", async () => {
    state.GET.mockResolvedValue({ error: { error: { code: "permission_denied" } } });
    mount(); await screen.findByRole("heading", { name: "Agent access required" });
    expect(reads()).toHaveLength(0);
    expect(state.GET.mock.calls.some(([path]) => path === "/api/v1/license")).toBe(false);
    expect(screen.queryByRole("button", { name: "Add agent" })).toBeNull();
  });

  it("keeps a failed inventory read distinct from an empty result and recovers on retry", async () => {
    let failed = true;
    const original = state.GET.getMockImplementation()!;
    state.GET.mockImplementation((path: string, request: Request) => path === agentsPath && failed ? Promise.resolve({ error: { error: { code: "unavailable", message: "Agent inventory unavailable" } } }) : original(path, request));
    mount(); await screen.findByRole("alert");
    expect(screen.queryByRole("heading", { name: "No agents yet" })).toBeNull();
    expect(screen.queryByRole("table", { name: "AI Agents" })).toBeNull();
    failed = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("link", { name: "Agent 01" });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("offers navigation-only row actions to the exact agent workspace", async () => {
    mount(); await screen.findByRole("link", { name: "Agent 01" });
    fireEvent.click(screen.getByRole("button", { name: "Agent actions for Agent 01" }));
    const menu = within(screen.getByRole("menu", { name: "Agent actions for Agent 01" }));
    expect(menu.getByRole("menuitem", { name: "View runtime" }).getAttribute("href")).toBe("/agents/agent-1?tab=runtime");
    expect(menu.getByRole("menuitem", { name: "Manage access" }).getAttribute("href")).toBe("/agents/agent-1?tab=access");
    expect(menu.getByRole("menuitem", { name: "View activity" }).getAttribute("href")).toBe("/agents/agent-1?tab=activity");
    expect(state.POST).not.toHaveBeenCalled();
  });

  it("ignores an earlier organization's late inventory response", async () => {
    let complete!: (value: unknown) => void;
    seed((_query, orgId) => orgId === "org-a" ? new Promise(resolve => { complete = resolve; }) : { items: [agent(9, { name: "Organization B agent" })] });
    const page = mount(); await waitFor(() => expect(reads()).toHaveLength(1));
    state.org = { ...state.org, id: "org-b", name: "Organization B" };
    page.rerender(<MemoryRouter>{view()}</MemoryRouter>);
    expect(screen.queryByRole("button", { name: "Add agent" })).toBeNull();
    await screen.findByRole("link", { name: "Organization B agent" });
    await act(async () => complete({ items: [agent(1, { name: "Private organization A agent" })], next_cursor: "private-old-cursor" }));
    expect(screen.queryByRole("link", { name: "Private organization A agent" })).toBeNull();
    expect(screen.getByRole("link", { name: "Organization B agent" })).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  });

  it("withdraws old inventory and enrollment at every organization-switch commit", async () => {
    seed((_query, orgId) => ({ items: [agent(1, { name: orgId === "org-a" ? "Private A agent" : "Visible B agent" })] }));
    const leakedCommits: boolean[] = [];
    const workspace = () => <MemoryRouter initialEntries={["/agents?add=1"]}><Profiler id="agent-scope" onRender={() => {
      if (state.org.id === "org-b") leakedCommits.push(Boolean(screen.queryByRole("link", { name: "Private A agent" }) || screen.queryByRole("dialog", { name: "Agent enrollment" })));
    }}>{view()}</Profiler></MemoryRouter>;
    const page = render(workspace());
    await screen.findByRole("link", { name: "Private A agent" });
    expect(screen.getByRole("dialog", { name: "Agent enrollment" })).toBeTruthy();
    state.org = { ...state.org, id: "org-b", name: "Organization B" }; state.role = "member";
    page.rerender(workspace());
    await screen.findByRole("link", { name: "Visible B agent" });
    expect(leakedCommits.length).toBeGreaterThan(0);
    expect(leakedCommits).not.toContain(true);
    expect(state.POST).not.toHaveBeenCalled();
  });
});
