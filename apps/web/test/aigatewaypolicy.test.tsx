import { createElement } from "react";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AIGatewayWorkspace,
  AgentModelAccess,
} from "../src/pages/AgentsAIGateway";
const mocks = vi.hoisted(() => ({
  GET: vi.fn(),
  PUT: vi.fn(),
  POST: vi.fn(),
  org: { id: "org-a", agent_policy_templates_enabled: true },
}));
vi.mock("../src/lib/api", () => ({ api: mocks }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mocks.org }) }));
vi.mock("../src/components/AIUserAccess", () => ({
  AIAccessGate: ({ children }: { children: (id: string, access: { view: boolean; manage: boolean; agents: boolean }) => unknown }) => children(mocks.org.id, { view: true, manage: true, agents: true }),
  AIGroupAccess: () => null, AIUseModel: () => null,
}));
vi.mock("../src/components/AIGatewaySettings", () => ({
  AIGatewaySettings: () => null,
}));
const team = {
  team_id: "group-a",
  models: ["openrouter/allowed"],
  key_ids: ["provider-id"],
  revision: 3,
};
const assignment = {
  device_id: "agent-a",
  team_id: "group-a",
  enabled: true,
  models_override: ["openrouter/allowed"],
  revision: 4,
  applied_revision: 3,
  applied_team_revision: 2,
  status: "error",
};
let member = true;
function get(path: string) {
  if (path.endsWith("/agent-groups"))
    return Promise.resolve({ data: [{ id: "group-a", name: "Team A" }] });
  if (path === "/api/v1/organizations/{orgId}/agents")
    return Promise.resolve({
      data: { items: [{ device_id: "agent-a", name: "Agent A", status: "active" }], next_cursor: null },
    });
  if (path.endsWith("/members"))
    return Promise.resolve({
      data: member ? [{ device_id: "agent-a", status: "active" }] : [],
    });
  if (path.endsWith("/providers")) return Promise.resolve({ data: { management_available: false, items: [], legacy_key_ids: ["provider-id"] } });
  if (path.endsWith("/teams")) return Promise.resolve({ data: [team] });
  if (path.endsWith("/agents")) return Promise.resolve({ data: [assignment] });
  return Promise.resolve({
    data: {
      total_requests: 2,
      total_tokens: 7,
      prompt_tokens: 4,
      completion_tokens: 3,
      total_cost: 0.01,
      uncosted_requests: 1,
      semantics: "observed_estimate",
      dashboard: {successful_requests: 2, failed_requests: 0, cancelled_requests: 0, daily: [], models: [], teams: [], agents: []},
    },
  });
}
function show(orgId = "org-a") {
  return createElement(
    MemoryRouter,
    null,
    createElement(AIGatewayWorkspace, { orgId, key: orgId }),
  );
}
beforeEach(() => {
  vi.resetAllMocks();
  member = true;
  mocks.org = { id: "org-a", agent_policy_templates_enabled: true };
  mocks.GET.mockImplementation(get);
  mocks.PUT.mockResolvedValue({ data: team });
  mocks.POST.mockResolvedValue({ data: assignment });
});
afterEach(cleanup);
describe("AI team and agent policy workspace", () => {
  it("does not fetch policy inventory or enable groups when the prerequisite is off", async () => {
    mocks.org.agent_policy_templates_enabled = false;
    render(<MemoryRouter initialEntries={["/agents/model-access"]}><AgentModelAccess /></MemoryRouter>);
    expect(await screen.findByText("Agent groups are turned off")).toBeTruthy();
    expect(mocks.GET).not.toHaveBeenCalled();
    expect(mocks.PUT).not.toHaveBeenCalled();
    expect(mocks.POST).not.toHaveBeenCalled();
  });

  it("loads organization agents across pages and preserves selection after a failed page", async () => {
    let attempts = 0;
    mocks.GET.mockImplementation((path: string, options: { params: { query?: { cursor?: string; limit?: number } } }) => {
      if (path !== "/api/v1/organizations/{orgId}/agents") return get(path);
      expect(options.params.query?.limit).toBe(100);
      if (!options.params.query?.cursor) return Promise.resolve({ data: { items: [{ device_id: "agent-a", name: "Other owner's agent", status: "active" }], next_cursor: "page-two" } });
      expect(options.params.query.cursor).toBe("page-two");
      if (++attempts === 1) return Promise.reject(new Error("offline"));
      return Promise.resolve({ data: { items: [{ device_id: "agent-b", name: "Second page agent", status: "revoked" }], next_cursor: null } });
    });
    render(show());
    await screen.findByRole("option", { name: "Other owner's agent (active)" });
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "agent-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Load more agents" }));
    await screen.findByText(/Could not load more agents/);
    expect((screen.getByLabelText("Agent") as HTMLSelectElement).value).toBe("agent-a");
    fireEvent.click(screen.getByRole("button", { name: "Load more agents" }));
    await screen.findByRole("option", { name: "Second page agent (revoked)" });
    expect((screen.getByLabelText("Agent") as HTMLSelectElement).value).toBe("agent-a");
    expect(screen.queryByRole("button", { name: "Load more agents" })).toBeNull();
    expect(mocks.GET.mock.calls.some(([path]) => path.endsWith("/devices"))).toBe(false);
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "agent-b" } });
    await screen.findByRole("button", { name: "Save agent access" });
    fireEvent.click(screen.getByRole("button", { name: "Refresh AI policies" }));
    await screen.findByLabelText("Agent");
    expect((screen.getByLabelText("Agent") as HTMLSelectElement).value).toBe("");
    expect(screen.queryByRole("button", { name: "Save agent access" })).toBeNull();
  });
  it.each([
    [1e-12, "0.000000000001"],
    [1e-20, "0.00000000000000000001"],
    [25.5, "25.5"],
  ])("shows threshold %s as decimal without changing its saved value", async (amount, displayed) => {
    mocks.GET.mockImplementation((path: string) => path.endsWith("/teams") ? Promise.resolve({ data: [{ ...team, daily_cost_limit: amount }] }) : get(path));
    render(show());
    await screen.findByLabelText("Policy team");
    fireEvent.change(screen.getByLabelText("Policy team"), { target: { value: "group-a" } });
    const input = screen.getByLabelText("Daily USD soft threshold (optional)") as HTMLInputElement;
    expect(input.value).toBe(displayed);
    expect(input.validity.rangeUnderflow).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Save team policy" }));
    await waitFor(() => expect(mocks.PUT).toHaveBeenCalled());
    expect(mocks.PUT.mock.calls[0][1].body.daily_cost_limit).toBe(amount);
  });
  it("selects owned connections by label while refusing unapplied additions", async () => {
    mocks.GET.mockImplementation((path: string) => path.endsWith("/providers") ? Promise.resolve({ data: {
      management_available: true, legacy_key_ids: ["provider-id"], items: [
        { id: "connection-a", key_id: "tnx-managed-a", name: "Team OpenRouter", enabled: true, status: "applied", revision: 2, applied_revision: 2, models: ["openrouter/allowed"] },
        { id: "connection-b", key_id: "tnx-managed-b", name: "Pending connection", enabled: true, status: "pending", revision: 2, applied_revision: 1, models: ["openrouter/allowed"] },
      ],
    } }) : get(path));
    render(show()); await screen.findByLabelText("Policy team");
    fireEvent.change(screen.getByLabelText("Policy team"), { target: { value: "group-a" } });
    expect((screen.getByRole("checkbox", { name: /Pending connection/ }) as HTMLInputElement).disabled).toBe(true);
    expect(screen.queryByLabelText("Provider key IDs (one per line)")).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: /Team OpenRouter/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /Legacy operator-managed reference/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save team policy" }));
    await waitFor(() => expect(mocks.PUT).toHaveBeenCalledWith(expect.stringContaining("/teams/{teamId}"), expect.objectContaining({ body: expect.objectContaining({ key_ids: ["tnx-managed-a"], expected_revision: 3 }) })));
  });
  it("sends exact team models, key IDs and expected revision with a soft threshold", async () => {
    render(show());
    await screen.findByLabelText("Policy team");
    fireEvent.change(screen.getByLabelText("Policy team"), {
      target: { value: "group-a" },
    });
    fireEvent.change(screen.getByLabelText("Exact models (one per line)"), {
      target: { value: "openrouter/allowed\nopenrouter/second" },
    });
    fireEvent.change(
      screen.getByLabelText("Daily USD soft threshold (optional)"),
      { target: { value: "2.5" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save team policy" }));
    await waitFor(() =>
      expect(mocks.PUT).toHaveBeenCalledWith(
        expect.stringContaining("/teams/{teamId}"),
        {
          params: { path: { orgId: "org-a", teamId: "group-a" } },
          body: {
            models: ["openrouter/allowed", "openrouter/second"],
            key_ids: ["provider-id"],
            daily_cost_limit: 2.5,
            expected_revision: 3,
          },
        },
      ),
    );
  });
  it("requires current membership and narrowing but still offers disable and reconcile", async () => {
    member = false;
    render(show());
    await screen.findByLabelText("Agent");
    expect(screen.queryByRole("option", { name: /Human/ })).toBeNull();
    fireEvent.change(screen.getByLabelText("Agent"), {
      target: { value: "agent-a" },
    });
    await screen.findByText(/must be an active member/);
    expect(
      (
        screen.getByRole("button", {
          name: "Save agent access",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(screen.getByRole("status").textContent).toContain(
      "Synchronization: error",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Disable agent access" }),
    );
    await waitFor(() =>
      expect(mocks.PUT).toHaveBeenCalledWith(
        expect.stringContaining("/agents/{deviceId}"),
        expect.objectContaining({
          body: {
            team_id: "group-a",
            enabled: false,
            models_override: ["openrouter/allowed"],
            expected_revision: 4,
          },
        }),
      ),
    );
    await screen.findByRole("button", { name: "Retry synchronization" });
    fireEvent.click(
      screen.getByRole("button", { name: "Retry synchronization" }),
    );
    await waitFor(() => expect(mocks.POST).toHaveBeenCalled());
  });
  it("saves an empty override as inheritance with the authoritative revision", async () => {
    render(show());
    await screen.findByLabelText("Agent");
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "agent-a" } });
    await screen.findByText(/Current group membership verified/);
    fireEvent.change(screen.getByLabelText("Agent models (must narrow the team policy)"), { target: { value: "  \n" } });
    const save = screen.getByRole("button", { name: "Save agent access" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(mocks.PUT).toHaveBeenCalledWith(
      expect.stringContaining("/agents/{deviceId}"),
      { params: { path: { orgId: "org-a", deviceId: "agent-a" } }, body: {
        team_id: "group-a", enabled: true, models_override: [], expected_revision: 4,
      } },
    ));
  });
  it("refuses agent overrides outside its team", async () => {
    render(show());
    await screen.findByLabelText("Agent");
    fireEvent.change(screen.getByLabelText("Agent"), {
      target: { value: "agent-a" },
    });
    await screen.findByText(/Current group membership verified/);
    fireEvent.change(
      screen.getByLabelText("Agent models (must narrow the team policy)"),
      { target: { value: "openrouter/forbidden" } },
    );
    expect(
      (
        screen.getByRole("button", {
          name: "Save agent access",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(mocks.PUT).not.toHaveBeenCalled();
  });
  it("ignores a stale organization load", async () => {
    let resolve!: (v: unknown) => void;
    const old = new Promise((r) => {
      resolve = r;
    });
    mocks.GET.mockImplementation(
      (
        path: string,
        options: {
          params: {
            path: {
              orgId: string;
            };
          };
        },
      ) => (options.params.path.orgId === "org-a" ? old : get(path)),
    );
    const page = render(show());
    page.rerender(show("org-b"));
    await screen.findByLabelText("Policy team");
    await act(async () => resolve({ data: [] }));
    expect(screen.getByLabelText("Policy team")).toBeTruthy();
    expect(screen.queryByText(/No Agent Groups yet/)).toBeNull();
  });
  it("keeps saved revision after a network mutation failure", async () => {
    mocks.PUT.mockRejectedValue(new Error("offline"));
    render(show());
    await screen.findByLabelText("Policy team");
    fireEvent.change(screen.getByLabelText("Policy team"), {
      target: { value: "group-a" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save team policy" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("alert").textContent).toContain(
      "Saved state has not been changed locally",
    );
    expect(
      (
        screen.getByLabelText(
          "Exact models (one per line)",
        ) as HTMLTextAreaElement
      ).value,
    ).toBe("openrouter/allowed");
  });
});
