import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AgentsAIGateway from "../src/pages/AgentsAIGateway";
import { LegacyWorkspaceRedirect } from "../src/components/LegacyWorkspaceRedirect";
import { AIGroupAccess } from "../src/components/AIUserAccess";
import { NAV_GROUPS } from "../src/components/AppShell";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), roles: ["admin"] }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mocks.get, POST: mocks.post } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org", agent_policy_templates_enabled: true } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "person", email_verified: true } } }) }));
const connection = { id: "saved-azure", name: "azure", provider: "azure_foundry", models: ["custom-saved-azure/gpt-5"], model_modes: { "custom-saved-azure/gpt-5": "chat" }, status: "applied", enabled: true, revision: 1, applied_revision: 1 };
const inventory = { items: [connection], definitions: [{ id: "azure_foundry", name: "Azure AI Foundry" }], management_available: true, legacy_key_ids: [] };
beforeEach(() => {
  vi.clearAllMocks(); mocks.roles = ["admin"];
  mocks.get.mockImplementation(async (path: string) => ({ data: path.endsWith("/members") ? [{ user_id: "person", role: "member", roles: mocks.roles }]
    : path.endsWith("/providers") ? inventory : path.endsWith("/user-groups") ? [{ id: "engineering", name: "Engineering", members: 4 }]
    : path.endsWith("/my-models") ? [{ model: connection.models[0], mode: "chat" }] : [] }));
});
afterEach(cleanup);
function Location() { const loc = useLocation(), navigate = useNavigate(); return <><output aria-label="Current route">{loc.pathname + loc.search + loc.hash}</output><button onClick={() => navigate(-1)}>Back</button></>; }
function mount(path: string) {
  return render(<MemoryRouter initialEntries={[path]}><Location /><Routes>
    <Route path="/agents/ai-gateway" element={<LegacyWorkspaceRedirect />} />
    <Route path="/agents/mcp" element={<LegacyWorkspaceRedirect to="/mcp" />} />
    <Route path="/mcp" element={<p>MCP profiles</p>} />
    <Route path="/access/groups" element={<LegacyWorkspaceRedirect groups />} />
    <Route path="/users/groups" element={<p>User groups</p>} />
    <Route path="/agents/groups" element={<p>Agent groups</p>} />
    <Route path="/ai-gateway" element={<AgentsAIGateway />} />
    <Route path="/ai-gateway/:section" element={<AgentsAIGateway />} />
    <Route path="/ai-gateway/models/new" element={<AgentsAIGateway />} />
  </Routes></MemoryRouter>);
}
describe("AI and identity navigation", () => {
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
    fireEvent.click(await screen.findByRole("button", { name: `Grant access to ${connection.models[0]} on azure` }));
    await screen.findByRole("option", { name: "Engineering · 4 users" });
    expect((screen.getByLabelText("Model") as HTMLSelectElement).value).toBe(JSON.stringify([connection.id, connection.models[0]]));
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("User group"), { target: { value: "engineering" } });
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(false);
    expect(mocks.post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.getByLabelText("Current route").textContent).toBe("/ai-gateway/models");
  });
  it("does not accept a stale model selection from a bookmarked grant", async () => {
    render(<AIGroupAccess orgId="org" canManage initialConnection="deleted" initialModel="private" />);
    fireEvent.change(await screen.findByLabelText("User group"), { target: { value: "engineering" } });
    await screen.findByRole("option", { name: "Engineering · 4 users" });
    expect((screen.getByRole("button", { name: "Grant model access" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mocks.post).not.toHaveBeenCalled();
  });
  it("opens My models for members without loading provider administration", async () => {
    mocks.roles = ["member"]; mount("/ai-gateway/credentials");
    await screen.findByRole("heading", { name: "My models" });
    expect(screen.getByLabelText("Current route").textContent).toBe("/ai-gateway/my-models");
    expect(screen.queryByRole("link", { name: "LLM credentials" })).toBeNull();
    expect(mocks.get.mock.calls.some(([path]) => path.endsWith("/providers"))).toBe(false);
  });
  it("keeps AI viewers read-only even on the direct Add Model URL", async () => {
    mocks.roles = ["member", "ai-view"]; mount("/ai-gateway/models/new");
    await screen.findByRole("table", { name: "Configured models" });
    expect(screen.queryByRole("button", { name: "Add Model" })).toBeNull();
    expect(screen.queryByLabelText("API key")).toBeNull();
    expect((screen.getByRole("button", { name: `Grant access to ${connection.models[0]} on azure` }) as HTMLButtonElement).disabled).toBe(true);
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
