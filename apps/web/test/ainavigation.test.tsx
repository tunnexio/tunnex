import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AgentsAIGateway, { AgentModelAccess } from "../src/pages/AgentsAIGateway";
import { LegacyWorkspaceRedirect } from "../src/components/LegacyWorkspaceRedirect";
import { AIGroupAccess } from "../src/components/AIUserAccess";
import { NAV_GROUPS } from "../src/components/AppShell";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), roles: ["admin"], cpAdmin: false, emailVerified: true, mustChangePassword: false }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mocks.get, POST: mocks.post } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org", agent_policy_templates_enabled: true }, orgs: [{ id: "org", name: "Test organization" }], loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "person", email_verified: mocks.emailVerified, must_change_password: mocks.mustChangePassword, cp_admin: mocks.cpAdmin } } }) }));
const connection = { id: "saved-azure", name: "azure", provider: "azure_foundry", models: ["custom-saved-azure/gpt-5"], model_modes: { "custom-saved-azure/gpt-5": "chat" }, status: "applied", enabled: true, revision: 1, applied_revision: 1 };
const inventory = { items: [connection], definitions: [{ id: "azure_foundry", name: "Azure AI Foundry" }], management_available: true, legacy_key_ids: [] };
beforeEach(() => {
  vi.clearAllMocks(); mocks.roles = ["admin"]; mocks.cpAdmin = false; mocks.emailVerified = true; mocks.mustChangePassword = false;
  mocks.get.mockImplementation(async (path: string) => ({ data: path.endsWith("/members") ? [{ user_id: "person", role: "member", roles: mocks.roles }]
    : path.endsWith("/providers") ? inventory : path.endsWith("/user-groups") ? [{ id: "engineering", name: "Engineering", members: 4 }]
    : path.endsWith("/my-models") ? [{ model: connection.models[0], mode: "chat" }] : [] }));
});
afterEach(cleanup);
function Location() { const loc = useLocation(), navigate = useNavigate(); return <><output aria-label="Current route">{loc.pathname + loc.search + loc.hash}</output><button onClick={() => navigate(-1)}>Back</button></>; }
function workspace(path: string) {
  return (<MemoryRouter initialEntries={[path]}><Location /><Routes>
    <Route path="/agents/ai-gateway" element={<LegacyWorkspaceRedirect />} />
    <Route path="/agents/mcp" element={<LegacyWorkspaceRedirect to="/mcp" />} />
    <Route path="/mcp" element={<p>MCP profiles</p>} />
    <Route path="/access/groups" element={<LegacyWorkspaceRedirect groups />} />
    <Route path="/users/groups" element={<p>User groups</p>} />
    <Route path="/agents/groups" element={<p>Agent groups</p>} />
    <Route path="/agents/model-access" element={<AgentModelAccess />} />
    <Route path="/settings" element={<h1>AI Gateway transport controls</h1>} />
    <Route path="/ai-gateway" element={<AgentsAIGateway />} />
    <Route path="/ai-gateway/:section" element={<AgentsAIGateway />} />
    <Route path="/ai-gateway/models/new" element={<AgentsAIGateway />} />
  </Routes></MemoryRouter>);
}
function mount(path: string) { return render(workspace(path)); }
describe("AI and identity navigation", () => {
  it.each([true, false])("uses server-admin identity for the blocked transport link (cp_admin=%s)", async (cpAdmin) => {
    mocks.cpAdmin = cpAdmin;
    mocks.get.mockImplementation(async (path: string) => path.endsWith("/members")
      ? { data: [{ user_id: "person", role: "owner", roles: ["owner"] }] }
      : { error: { error: { code: "ai_https_required" } }, response: new Response(null, { status: 403 }) });
    mount("/ai-gateway/models");
    await screen.findByRole("alert");
    const link = screen.queryByRole("link", { name: "Open transport settings" });
    if (cpAdmin) {
      expect(link?.getAttribute("href")).toBe("/settings?section=ai-transport");
      fireEvent.click(link!);
      await screen.findByRole("heading", { name: "AI Gateway transport controls" });
      expect(screen.getByLabelText("Current route").textContent).toBe("/settings?section=ai-transport");
      expect(screen.queryByRole("button", { name: "Add Model" })).toBeNull();
    } else expect(link).toBeNull();
  });

  it("separates AI destinations from Network and puts identity beside access", () => {
    expect(NAV_GROUPS.find((g) => g.group === "AI")?.items.map((i) => i.to)).toEqual(["/ai-gateway", "/agents", "/mcp"]);
    expect(NAV_GROUPS.find((g) => g.group === "NETWORK")?.items.some((i) => i.to.startsWith("/agents"))).toBe(false);
    expect(NAV_GROUPS.flatMap((g) => g.items).find((i) => i.to === "/users")?.label).toBe("Users & Groups");
  });
  it.each([
    ["/access/groups?group=people%3Aengineering&q=eng", "/users/groups?group=people%3Aengineering&q=eng"],
    ["/access/groups?type=agents&group=agents%3Aworkers", "/agents/groups?type=agents&group=agents%3Aworkers"],
    ["/agents/ai-gateway", "/ai-gateway/models"],
    ["/agents/mcp?group=workers&profile=shared#assignment", "/mcp?group=workers&profile=shared#assignment"],
  ])("keeps old bookmarks working: %s", async (from, to) => {
    mount(from); await waitFor(() => expect(screen.getByLabelText("Current route").textContent).toBe(to));
  });
  it("opens an exact model grant and preserves the models page in browser history", async () => {
    mount("/ai-gateway/models");
    fireEvent.click(await screen.findByRole("button", { name: `Model actions for ${connection.models[0]} · ${connection.name}` }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Grant access" }));
    await screen.findByRole("option", { name: "Engineering (4)" });
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([connection.id, connection.models[0]]));
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("User group"), { target: { value: "engineering" } });
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(false);
    expect(mocks.post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.getByLabelText("Current route").textContent).toBe("/ai-gateway/models");
  });
  it("does not accept a stale model selection from a bookmarked grant", async () => {
    render(<AIGroupAccess orgId="org" canManage initialConnection="deleted" initialModel="private" />);
    fireEvent.change(await screen.findByLabelText("User group"), { target: { value: "engineering" } });
    await screen.findByRole("option", { name: "Engineering (4)" });
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mocks.post).not.toHaveBeenCalled();
  });
  it("opens My models for members without loading provider administration", async () => {
    mocks.roles = ["member"]; mount("/ai-gateway/credentials");
    await screen.findByRole("region", { name: "Use a model" });
    expect(screen.getByLabelText("Current route").textContent).toBe("/ai-gateway/my-models");
    expect(screen.queryByRole("link", { name: "LLM credentials" })).toBeNull();
    expect(mocks.get.mock.calls.some(([path]) => path.endsWith("/providers"))).toBe(false);
  });
  it("keeps AI viewers read-only even on the direct Add Model URL", async () => {
    mocks.roles = ["member", "ai-view"]; mount("/ai-gateway/models/new");
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.queryByRole("button", { name: "Add Model" })).toBeNull();
    expect(screen.queryByLabelText("API key")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: `Model actions for ${connection.models[0]} · ${connection.name}` }));
    expect(screen.queryByRole("menuitem", { name: "Grant access" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Edit credentials" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Check catalog" })).toBeNull();
    expect(mocks.post).not.toHaveBeenCalled();
  });
  it.each(["unverified", "password change required"])("keeps owner provider views read-only when %s", async restriction => {
    mocks.roles = ["owner"];
    mocks.emailVerified = restriction !== "unverified";
    mocks.mustChangePassword = restriction === "password change required";
    mount("/ai-gateway/models/new");
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.queryByRole("dialog", { name: "Add Model" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Add Model" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: `Model actions for ${connection.models[0]} · ${connection.name}` }));
    for (const action of ["Grant access", "Edit credentials", "Check catalog"])
      expect(screen.queryByRole("menuitem", { name: action })).toBeNull();
    fireEvent.click(screen.getByRole("link", { name: "LLM credentials" }));
    await screen.findByRole("table", { name: "Saved LLM credentials" });
    expect(screen.queryByRole("button", { name: "Add Credentials" })).toBeNull();
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it("withdraws a credential secret draft immediately when the same actor loses verification", async () => {
    mocks.roles = ["owner"];
    const rendered = mount("/ai-gateway/models");
    fireEvent.click(await screen.findByRole("button", { name: `Model actions for ${connection.models[0]} · ${connection.name}` }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Edit credentials" }));
    await screen.findByRole("dialog", { name: "Edit credentials" });
    fireEvent.change(screen.getByLabelText("Replacement API key (optional)"), { target: { value: "synthetic-draft-secret" } });
    mocks.emailVerified = false;
    rendered.rerender(workspace("/ai-gateway/models"));
    expect(screen.queryByRole("dialog", { name: "Edit credentials" })).toBeNull();
    expect(screen.queryByDisplayValue("synthetic-draft-secret")).toBeNull();
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.queryByRole("button", { name: "Add Model" })).toBeNull();
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it("withdraws an agent model-policy editor when the same actor loses verification", async () => {
    mocks.roles = ["owner"];
    const original = mocks.get.getMockImplementation()!;
    mocks.get.mockImplementation(async (path: string, ...args: unknown[]) => {
      if (path.endsWith("/agent-groups")) return { data: [{ id: "agent-group", name: "Workers" }] };
      if (path === "/api/v1/organizations/{orgId}/agents") return { data: { items: [], next_cursor: null } };
      if (path.endsWith("/ai-gateway/teams") || path.endsWith("/ai-gateway/agents")) return { data: [] };
      return original(path, ...args);
    });
    const rendered = mount("/agents/model-access");
    fireEvent.click(await screen.findByRole("button", { name: "Add policy" }));
    await screen.findByRole("dialog");
    mocks.emailVerified = false;
    rendered.rerender(workspace("/agents/model-access"));
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByText("You do not have permission to manage agent model access.");
    expect(screen.queryByRole("button", { name: "Add policy" })).toBeNull();
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it("navigates to credentials without a second tab row", async () => {
    mount("/ai-gateway/models"); await screen.findByRole("table", { name: "Configured models" });
    fireEvent.click(screen.getByRole("link", { name: "LLM credentials" }));
    await screen.findByRole("table", { name: "Saved LLM credentials" });
    expect(screen.getByLabelText("Current route").textContent).toBe("/ai-gateway/credentials");
    expect(screen.queryByRole("tablist", { name: "Model management view" })).toBeNull();
    expect(screen.getByRole("link", { name: "LLM credentials" }).getAttribute("aria-current")).toBe("page");
  });
});
