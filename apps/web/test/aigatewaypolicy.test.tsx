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
import AgentsAIGateway, {
  AIGatewayWorkspace,
} from "../src/pages/AgentsAIGateway";
const mocks = vi.hoisted(() => ({
  GET: vi.fn(),
  PUT: vi.fn(),
  POST: vi.fn(),
  org: { id: "org-a", agent_policy_templates_enabled: true },
}));
vi.mock("../src/lib/api", () => ({ api: mocks }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mocks.org }) }));
vi.mock("../src/pages/AgentsManagementGate", () => ({
  AgentsManagementGate: ({ children }: { children: (id: string) => unknown }) =>
    children(mocks.org.id),
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
  if (path.endsWith("/devices"))
    return Promise.resolve({
      data: [
        { id: "agent-a", name: "Agent A", kind: "agent", status: "active" },
        { id: "human", name: "Human", kind: "device", status: "active" },
      ],
    });
  if (path.endsWith("/members"))
    return Promise.resolve({
      data: member ? [{ device_id: "agent-a", status: "active" }] : [],
    });
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
      semantics: "observed estimates",
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
    render(createElement(MemoryRouter, null, createElement(AgentsAIGateway)));
    expect(screen.getByText("Agent groups are turned off")).toBeTruthy();
    expect(mocks.GET).not.toHaveBeenCalled();
    expect(mocks.PUT).not.toHaveBeenCalled();
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
  it("displays uncosted requests and clears stale usage when scope changes", async () => {
    render(show());
    await screen.findByRole("button", { name: "Load usage" });
    fireEvent.change(screen.getByLabelText("From (UTC)"), {
      target: { value: "2026-09-07T00:00" },
    });
    fireEvent.change(screen.getByLabelText("To (UTC)"), {
      target: { value: "2026-09-07T01:00" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Load usage" }));
    await screen.findByText(/Requests without cost: 1/);
    fireEvent.change(screen.getByLabelText("Usage team"), {
      target: { value: "group-a" },
    });
    expect(screen.queryByText(/Requests without cost: 1/)).toBeNull();
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
