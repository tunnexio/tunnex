import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// One stable organization object: the page reloads whenever the organization identity changes.
const { get, org } = vi.hoisted(() => ({ get: vi.fn(), org: { id: "org-a", name: "Acme", managed_agent_runtime_enabled: true } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import { MCPEnforcementNotices } from "../src/components/AgentMCPControls";
import { MCPProfileTools } from "../src/components/MCPProfileTools";
import AgentDetail from "../src/pages/AgentDetail";

const NOW = new Date("2026-11-27T10:00:00Z");
const graceDate = "2026-12-27T00:00:00Z";
const graceLabel = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "long", year: "numeric" }).format(new Date(graceDate));
const assigned = (over: Record<string, unknown>) => ({ assigned: true, profile_id: "p", profile_name: "Billing tools", endpoint: "http://10.0.0.5:8080/mcp", group_id: "g", group_name: "Finance agents", direct_path_closable: true, direct_path_grace_until: null, ...over });
const show = (over: Record<string, unknown>, updateHref?: string) => render(<MemoryRouter><MCPEnforcementNotices profile={assigned(over) as never} now={NOW} updateHref={updateHref} /></MemoryRouter>);
const gatewayLine = "Tool rules are applied at the gateway. This agent needs no network rule for the MCP server.";
const cannotClose = "Tunnex cannot fully block direct access to this server";

afterEach(() => { cleanup(); get.mockReset(); });

describe("MCP enforcement notices", () => {
  it("says tool rules are applied at the gateway", () => {
    show({ enforcement: "gateway" });
    expect(screen.getByText(gatewayLine)).toBeTruthy();
    expect(screen.queryByText(/Reinstall|Update this agent/)).toBeNull();
    expect(screen.queryByText(cannotClose)).toBeNull();
  });

  it("gives the date to update the runtime by while the older path is still allowed, and links to the action", () => {
    show({ enforcement: "agent_host", direct_path_grace_until: graceDate }, "/agents/agent-a?tab=runtime");
    const notice = within(screen.getByRole("note", { name: `Update this agent's runtime before ${graceLabel} to keep MCP working` }));
    expect(notice.getByText(/The new version sends MCP calls through the gateway, which applies the tool rules; the older way is switched off after this date\./)).toBeTruthy();
    expect(notice.getByText(/The agent keeps its identity, access and MCP settings\./)).toBeTruthy();
    expect(notice.getByRole("link", { name: "Update runtime" }).getAttribute("href")).toBe("/agents/agent-a?tab=runtime");
    expect(screen.queryByText(gatewayLine)).toBeNull();
    expect(screen.queryByText(/reinstall/i)).toBeNull();
  });

  it("still asks for a runtime update when the older path has no date left", () => {
    show({ enforcement: "agent_host", direct_path_grace_until: "2026-11-01T00:00:00Z" }, "/agents/agent-a?tab=runtime");
    const notice = within(screen.getByRole("note", { name: "Update this agent's runtime to keep MCP working" }));
    expect(notice.getByText(/The new version sends MCP calls through the gateway, which applies the tool rules; the older way can be switched off at any time\./)).toBeTruthy();
    expect(notice.getByRole("link", { name: "Update runtime" }).getAttribute("href")).toBe("/agents/agent-a?tab=runtime");
    cleanup();
    show({ enforcement: "agent_host" });
    expect(screen.getByRole("note", { name: "Update this agent's runtime to keep MCP working" })).toBeTruthy();
    // Without a place to send the reader, the notice names the action instead of linking nowhere.
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByText(/Use Update runtime on the agent's page\./)).toBeTruthy();
  });

  it("says to upgrade the gateway when MCP is withheld", () => {
    show({ enforcement: "unavailable" });
    const notice = within(screen.getByRole("note", { name: "Upgrade this agent's gateway to use MCP" }));
    expect(notice.getByText("MCP is off for this agent because its gateway cannot apply tool rules yet. If the gateway is already up to date, update this agent's runtime.")).toBeTruthy();
    expect(screen.queryByText(gatewayLine)).toBeNull();
  });

  it("says plainly when direct access to the server cannot be fully blocked, and what to do", () => {
    show({ enforcement: "gateway", endpoint: "https://tools.example.com/mcp", direct_path_closable: false });
    const notice = within(screen.getByRole("note", { name: cannotClose }));
    expect(notice.getByText("The agent's machine may still reach tools.example.com without going through the gateway. Use a private IP address for the server, or add an FQDN resource with the same name. For a public server with no sign-in, tool rules cannot be guaranteed.")).toBeTruthy();
    expect(screen.getByText(gatewayLine)).toBeTruthy();
  });

  it("shows nothing when no profile is assigned or the server did not say", () => {
    const empty = render(<MemoryRouter><MCPEnforcementNotices profile={{ assigned: false } as never} now={NOW} /></MemoryRouter>);
    expect(empty.container.textContent).toBe("");
    cleanup();
    const unknown = render(<MemoryRouter><MCPEnforcementNotices profile={{ assigned: true, endpoint: "http://10.0.0.5/mcp" } as never} now={NOW} /></MemoryRouter>);
    expect(unknown.container.textContent).toBe("");
  });

  it("uses no internal terms", () => {
    for (const over of [{ enforcement: "gateway" }, { enforcement: "agent_host", direct_path_grace_until: graceDate }, { enforcement: "unavailable" }, { enforcement: "gateway", direct_path_closable: false }]) {
      const view = show(over);
      expect(view.container.textContent).not.toMatch(/tuple|hash|digest|v16|loopback|proxy|direct path|grace/i);
      cleanup();
    }
  });
});

describe("where the notices appear", () => {
  const profile = { device_id: "agent-a", name: "builder", environment: "prod", runtime: "python", labels: {}, owner_id: "user-a", owner_email: "owner@example.test", managing_group_id: null, managing_group_name: null, status: "active", last_handshake_at: null, permissions: { view_privileged: true, manage: true, assign: true, grant_access: true, revoke: true, rotate_credentials: true } };
  const inventory = { device_id: "agent-a", observed_at: "2026-11-27T10:00:00Z", source: "gateway", snapshot: { servers: [{ endpoint: "https://tools.example.com/mcp", server_name: "billing", status: "healthy", tools: [{ name: "list_invoices", description: "Lists invoices.", input_schema_hash: "s", definition_state: "changed" }] }] } };
  let effective: Record<string, unknown> = {};
  beforeEach(() => {
    effective = assigned({ enforcement: "agent_host", direct_path_grace_until: "2099-01-15T00:00:00Z", endpoint: "https://tools.example.com/mcp", direct_path_closable: false });
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/agents/{deviceId}")) return { data: profile };
      if (path.endsWith("/effective-mcp-profile")) return { data: effective };
      if (path.endsWith("/mcp-inventory")) return { data: inventory };
      if (path.endsWith("/mcp-tool-activity")) return { data: { items: [], next_cursor: null } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role: "owner", status: "active" }] };
      if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
      if (path.endsWith("/mcp-tool-policy")) return { data: { version: 1, inventory_observed_at: "2026-11-27T10:00:00Z", created_at: "2026-11-27T10:00:00Z", rules: [] } };
      return { data: [] };
    });
  });
  const reinstall = `Update this agent's runtime before ${new Intl.DateTimeFormat(undefined, { day: "numeric", month: "long", year: "numeric" }).format(new Date("2099-01-15T00:00:00Z"))} to keep MCP working`;

  it("shows them with the agent's MCP profile on the agent MCP tab", async () => {
    render(<MemoryRouter initialEntries={["/agents/agent-a?tab=mcp"]}><AgentDetail agentIdOverride="agent-a" /></MemoryRouter>);
    const notice = within(await screen.findByRole("note", { name: reinstall }));
    expect(notice.getByRole("link", { name: "Update runtime" }).getAttribute("href")).toBe("/agents/agent-a?tab=runtime");
    expect(screen.getByRole("note", { name: cannotClose })).toBeTruthy();
    expect(await screen.findByText(/by the gateway\. This is the server.s tool list as last read/)).toBeTruthy();
  });

  it("words the tool policy for the gateway once the gateway applies it", async () => {
    effective = assigned({ enforcement: "gateway" });
    render(<MemoryRouter initialEntries={["/agents/agent-a?tab=mcp"]}><AgentDetail agentIdOverride="agent-a" /></MemoryRouter>);
    expect(await screen.findByText(gatewayLine)).toBeTruthy();
    expect(await screen.findByText("Choose what this agent may do with each tool. A tool nobody has decided about is Off. The gateway checks every call this agent makes.")).toBeTruthy();
    expect(screen.queryByText(/local MCP address/)).toBeNull();
  });

  it("shows them for the chosen agent on the MCP page, and flags a changed tool there", async () => {
    render(<MemoryRouter><MCPProfileTools orgId="org-a" endpoint="https://tools.example.com/mcp" members={[{ device_id: "agent-a", name: "builder", status: "active", node_id: "node", added_at: "now" }] as never} /></MemoryRouter>);
    const notice = within(await screen.findByRole("note", { name: reinstall }));
    expect(notice.getByRole("link", { name: "Update runtime" }).getAttribute("href")).toBe("/agents/agent-a?tab=runtime");
    expect(screen.getByRole("note", { name: cannotClose })).toBeTruthy();
    expect(await screen.findByText("Changed, review")).toBeTruthy();
    expect(get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}/effective-mcp-profile", { params: { path: { orgId: "org-a", deviceId: "agent-a" } } });
  });

  it("keeps workflow history on the Activity tab next to the new MCP calls", async () => {
    render(<MemoryRouter initialEntries={["/agents/agent-a?tab=activity"]}><AgentDetail agentIdOverride="agent-a" /></MemoryRouter>);
    expect(await screen.findByRole("heading", { name: "MCP calls" })).toBeTruthy();
    expect(await screen.findByText("No MCP calls yet.")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "No workflow activity recorded" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Audit Log" })).toBeTruthy();
  });
});
