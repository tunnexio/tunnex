import { MemoryRouter } from "react-router-dom";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIAgentAccess } from "../src/components/AIUserAccess";

// AI Gateway → Access → Agents and agent groups: model access for an agent is granted where it is
// granted for everyone else, over the same endpoints the agents page uses.
const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user", email_verified: true } } }) }));
vi.mock("../src/components/Toasts", () => ({ toast }));

const base = "/api/v1/organizations/{orgId}";
const model = "openai/gpt-4o-mini", second = "anthropic/claude-sonnet-4";
const connection = (id: string, models: string[]) => ({ id, key_id: `key-${id}`, provider: "openai", name: id, models, enabled: true, status: "applied", revision: 1, applied_revision: 1 });
type World = { teams: Record<string, unknown>[]; assignments: Record<string, unknown>[]; groupsOff?: boolean };
let world: World;
function serve() {
  api.GET.mockImplementation(async (path: string) => {
    if (path === `${base}/ai-gateway`) return { data: { enabled: true, available: true, revision: 1, status: { on: true, reason: null } } };
    if (path === `${base}/agent-groups`) return world.groupsOff ? { error: { error: { code: "opt_in_required", message: "off" } } } : { data: [{ id: "group-a", name: "Build agents", member_count: 2 }, { id: "group-b", name: "Research agents", member_count: 0 }] };
    if (path === `${base}/ai-gateway/teams`) return { data: world.teams };
    if (path === `${base}/ai-gateway/agents`) return { data: world.assignments };
    if (path === `${base}/ai-gateway/providers`) return { data: { management_available: true, legacy_key_ids: [], items: [connection("one", [model]), connection("two", [second])] } };
    if (path === `${base}/agents`) return { data: { items: [{ device_id: "agent-1", name: "builder-01", status: "active" }, { device_id: "agent-2", name: "builder-02", status: "active" }] } };
    if (path === `${base}/agent-groups/{groupId}/members`) return { data: [{ device_id: "agent-1", name: "builder-01", status: "active" }, { device_id: "agent-2", name: "builder-02", status: "active" }, { device_id: "agent-3", name: "old-agent", status: "revoked" }] };
    return { error: { error: { code: "not_found" } } };
  });
  api.PUT.mockImplementation(async (path: string, request: { params: { path: { teamId?: string; deviceId?: string } }; body: Record<string, unknown> }) => {
    if (path === `${base}/ai-gateway/teams/{teamId}`) {
      const saved = { team_id: request.params.path.teamId, models: request.body.models, key_ids: request.body.key_ids, daily_cost_limit: request.body.daily_cost_limit, revision: Number(request.body.expected_revision) + 1 };
      world.teams = [...world.teams.filter((team) => team.team_id !== saved.team_id), saved];
      return { data: saved };
    }
    const saved = { device_id: request.params.path.deviceId, team_id: request.body.team_id, enabled: request.body.enabled, models_override: request.body.models_override, revision: Number(request.body.expected_revision) + 1, applied_revision: 0, applied_team_revision: 0, status: request.body.enabled ? "applied" : "disabled" };
    world.assignments = [...world.assignments.filter((a) => a.device_id !== saved.device_id), saved];
    return { data: saved };
  });
}
const show = (canManage = true) => render(<MemoryRouter><AIAgentAccess orgId="org" canManage={canManage} /></MemoryRouter>);
beforeEach(() => { vi.resetAllMocks(); world = { teams: [], assignments: [] }; serve(); });
afterEach(cleanup);

describe("AI Gateway access for agents and agent groups", () => {
  it("grants a model to an agent group and to the agents chosen from it", async () => {
    show();
    expect(await screen.findByText("No agent has model access yet")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Grant access" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Grant model access to agents" }));
    expect((dialog.getByRole("button", { name: "Save agent access" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(dialog.getByLabelText("Agent group"), { target: { value: "group-a" } });
    fireEvent.click(dialog.getByRole("checkbox", { name: "gpt-4o-mini" }));
    fireEvent.click(await dialog.findByRole("checkbox", { name: "builder-01" }));
    // A member that is no longer active cannot be given access.
    expect(dialog.queryByRole("checkbox", { name: "old-agent" })).toBeNull();
    fireEvent.click(dialog.getByRole("button", { name: "Save agent access" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledTimes(2));
    // The policy names the credential that serves the chosen model; the administrator never types a key id.
    expect(api.PUT).toHaveBeenNthCalledWith(1, `${base}/ai-gateway/teams/{teamId}`, { params: { path: { orgId: "org", teamId: "group-a" } }, body: { models: [model], key_ids: ["key-one"], daily_cost_limit: null, expected_revision: 0 } });
    expect(api.PUT).toHaveBeenNthCalledWith(2, `${base}/ai-gateway/agents/{deviceId}`, { params: { path: { orgId: "org", deviceId: "agent-1" } }, body: { team_id: "group-a", enabled: true, models_override: [], expected_revision: 0 } });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const table = within(await screen.findByRole("table", { name: "Agents and agent groups with model access" }));
    expect(table.getByRole("row", { name: /Build agents Agent group gpt-4o-mini 1 agent has access/ })).toBeTruthy();
    expect(table.getByRole("row", { name: /builder-01.*In Build agents Agent gpt-4o-mini Active/ })).toBeTruthy();
    expect(toast.success).toHaveBeenCalledWith("Agent model access saved");
  });

  it("saves a daily budget with the group and refuses an invalid one", async () => {
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Grant access" }));
    const dialog = within(await screen.findByRole("dialog"));
    fireEvent.change(dialog.getByLabelText("Agent group"), { target: { value: "group-a" } });
    fireEvent.click(dialog.getByRole("checkbox", { name: "gpt-4o-mini" }));
    await dialog.findByRole("checkbox", { name: "builder-01" });
    fireEvent.change(dialog.getByLabelText("Daily budget for this group in USD (optional)"), { target: { value: "-1" } });
    expect((dialog.getByRole("button", { name: "Save agent access" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(dialog.getByLabelText("Daily budget for this group in USD (optional)"), { target: { value: "5" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save agent access" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledTimes(1));
    expect(api.PUT.mock.calls[0][1].body.daily_cost_limit).toBe(5);
  });

  it("revokes one agent after confirmation, in the page, and can restore it", async () => {
    world.teams = [{ team_id: "group-a", models: [model], key_ids: ["key-one"], revision: 2 }];
    world.assignments = [{ device_id: "agent-1", team_id: "group-a", enabled: true, models_override: [], revision: 4, applied_revision: 4, applied_team_revision: 2, status: "applied" }];
    const confirm = vi.spyOn(window, "confirm");
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Actions for agent builder-01" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke access" }));
    const dialog = within(screen.getByRole("dialog", { name: "Revoke model access?" }));
    expect(dialog.getByText(/Other agents in Build agents keep their access/)).toBeTruthy();
    expect(api.PUT).not.toHaveBeenCalled();
    fireEvent.click(dialog.getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledExactlyOnceWith(`${base}/ai-gateway/agents/{deviceId}`, { params: { path: { orgId: "org", deviceId: "agent-1" } }, body: { team_id: "group-a", enabled: false, models_override: [], expected_revision: 4 } }));
    expect(await screen.findByRole("row", { name: /builder-01.*In Build agents Agent gpt-4o-mini Revoked/ })).toBeTruthy();
    expect(confirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Actions for agent builder-01" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Restore access" }));
    await waitFor(() => expect(api.PUT).toHaveBeenLastCalledWith(`${base}/ai-gateway/agents/{deviceId}`, { params: { path: { orgId: "org", deviceId: "agent-1" } }, body: { team_id: "group-a", enabled: true, models_override: [], expected_revision: 5 } }));
  });

  it("revokes from the group dialog by clearing an agent, without rewriting an unchanged group", async () => {
    world.teams = [{ team_id: "group-a", models: [model], key_ids: ["key-one"], revision: 2 }];
    world.assignments = [{ device_id: "agent-1", team_id: "group-a", enabled: true, models_override: [], revision: 4, applied_revision: 4, applied_team_revision: 2, status: "applied" }];
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Actions for agent group Build agents" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Change models or agents" }));
    const dialog = within(await screen.findByRole("dialog"));
    const agent = await dialog.findByRole("checkbox", { name: "builder-01" }) as HTMLInputElement;
    await waitFor(() => expect(agent.checked).toBe(true));
    fireEvent.click(agent);
    fireEvent.click(dialog.getByRole("button", { name: "Save agent access" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledExactlyOnceWith(`${base}/ai-gateway/agents/{deviceId}`, expect.objectContaining({ body: { team_id: "group-a", enabled: false, models_override: [], expected_revision: 4 } })));
  });

  it("reports a refused change in plain words and keeps the saved state", async () => {
    world.teams = [{ team_id: "group-a", models: [model], key_ids: ["key-one"], revision: 2 }];
    world.assignments = [{ device_id: "agent-1", team_id: "group-a", enabled: true, models_override: [], revision: 4, applied_revision: 4, applied_team_revision: 2, status: "applied" }];
    api.PUT.mockResolvedValue({ error: { error: { code: "conflict", message: "Another administrator changed this agent's access." } } });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Actions for agent builder-01" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke access" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Another administrator changed this agent's access.");
    expect(await screen.findByRole("row", { name: /builder-01.*In Build agents Agent gpt-4o-mini Active/ })).toBeTruthy();
  });

  it("shows access read-only to someone who cannot manage it", async () => {
    world.teams = [{ team_id: "group-a", models: [model, second], key_ids: ["key-one", "key-two"], revision: 2 }];
    show(false);
    expect(await screen.findByRole("row", { name: /Build agents Agent group 2 models 0 agents have access/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Grant access" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Actions for/ })).toBeNull();
  });

  it("says agent groups are turned off and where to turn them on", async () => {
    world.groupsOff = true;
    show();
    expect(await screen.findByText("Agent groups are turned off")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open agent groups" }).getAttribute("href")).toBe("/agents/groups");
    expect((screen.getByRole("button", { name: "Grant access" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
