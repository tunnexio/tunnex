import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// What an administrator saw on the agent page during a live walk, one test per defect.
const { get, org } = vi.hoisted(() => ({ get: vi.fn(), org: { id: "org-a", name: "Acme", managed_agent_runtime_enabled: true } }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import AgentDetail from "../src/pages/AgentDetail";

const endpoint = "http://10.0.0.5:8080/mcp";
const agent = { device_id: "agent-a", name: "builder", environment: "prod", runtime: "python", labels: {}, owner_id: "user-a", owner_email: "owner@example.test", managing_group_id: null, managing_group_name: null, status: "active", last_handshake_at: null, permissions: { view_privileged: true, manage: true, assign: true, grant_access: true, revoke: true, rotate_credentials: true } };
const billing = { profile_id: "profile-billing", profile_name: "Billing database", server_name: "billing-db", endpoint, group_id: "group-1", group_name: "Finance agents", default: true, local_url: "http://127.0.0.1:17100/billing-db", policy_source: "group" };
const connected = (over: Record<string, unknown> = {}) => ({ assigned: true, enforcement: "gateway", profile_id: "profile-billing", profile_name: "Billing database", endpoint, group_id: "group-1", group_name: "Finance agents", servers: [billing], ...over });
let role = "owner";
let effective: Record<string, unknown> = { assigned: false };
let approvals: unknown[] = [];
let activity: unknown[] = [];

beforeEach(() => {
  role = "owner"; effective = { assigned: false }; approvals = []; activity = [];
  get.mockImplementation(async (path: string) => {
    if (path.endsWith("/agents/{deviceId}")) return { data: agent };
    if (path.endsWith("/effective-mcp-profile")) return { data: effective };
    if (path.endsWith("/mcp-inventory")) return { data: { device_id: "agent-a", observed_at: "2026-11-27T10:00:00Z", source: "gateway", snapshot: { servers: [{ endpoint, server_name: "acme-backoffice", tools: [{ name: "refund_order", description: "Refunds an order.", input_schema_hash: "s1" }] }] } } };
    if (path.endsWith("/mcp-tool-approval-requests")) return { data: approvals };
    if (path.endsWith("/mcp-tool-activity")) return { data: { items: activity, next_cursor: null } };
    if (path.endsWith("/tool-policy")) return { data: { group_id: "group-1", profile_id: "profile-billing", server_name: "billing-db", endpoint, version: 1, overriding_agent_count: 0, tools: [] } };
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role, status: "active" }] };
    if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
    return { data: [] };
  });
});
afterEach(() => { cleanup(); get.mockReset(); });

const open = (tab: string) => render(<MemoryRouter initialEntries={[`/agents/agent-a?tab=${tab}`]}><AgentDetail agentIdOverride="agent-a" /></MemoryRouter>);

describe("agent MCP tab, agent with no MCP server yet", () => {
  // The server leaves `servers` out when none is assigned, which used to select the older single-server view.
  it.each([["leaves the list out", { assigned: false }], ["sends an empty list", { assigned: false, servers: [] }]])("offers Connect MCP server for this agent when the server %s", async (_label, answer) => {
    effective = answer;
    open("mcp");
    expect(await screen.findByText("No MCP server is connected to this agent yet.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Manage MCP servers" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Connect MCP server" }));
    expect(screen.getByRole("dialog", { name: "Connect MCP server to builder" })).toBeTruthy();
    // The agent is already chosen: the dialog asks only for the address.
    expect(within(screen.getByRole("dialog")).queryByRole("combobox", { name: "Connect to" })).toBeNull();
  });

  it("tells a person who may not connect servers whom to ask", async () => {
    role = "member";
    open("mcp");
    expect(await screen.findByText("Ask an owner or administrator to connect one.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Connect MCP server" })).toBeNull();
  });

  it("keeps the single-server view for a control plane that reports a server without the list", async () => {
    effective = { assigned: true, profile_id: "profile-billing", profile_name: "Billing database", endpoint, group_id: "group-1", group_name: "Finance agents" };
    open("mcp");
    expect((await screen.findByRole("link", { name: "Manage MCP servers" })).getAttribute("href")).toBe("/mcp?group=group-1");
    expect(screen.queryByRole("button", { name: "Connect MCP server" })).toBeNull();
  });
});

describe("one name for a server across the agent page", () => {
  // The administrator named the server "Billing database" (address name billing-db). The server calls itself "acme-backoffice".
  const request = { id: "req-1", device_id: "agent-a", policy_version: 1, endpoint, server_name: "acme-backoffice", tool_name: "refund_order", input_schema_hash: "h", state: "pending", requested_at: "2026-11-27T09:59:00Z", expires_at: "2099-01-01T00:00:00Z", arguments: {}, arguments_truncated: false };

  it("uses the administrator's name in the Approvals panel, and the server's own name only as detail under What the gateway sees", async () => {
    effective = connected();
    approvals = [request, { ...request, id: "req-2", state: "expired", tool_name: "close_order" }];
    open("mcp");
    expect(await screen.findByRole("listitem", { name: "refund_order on Billing database" })).toBeTruthy();
    expect(screen.getByRole("listitem", { name: "close_order on Billing database" })).toBeTruthy();
    const seen = within((await screen.findByRole("heading", { name: "What the gateway sees" })).closest("section") as HTMLElement);
    expect(seen.getByText("Billing database").tagName).toBe("STRONG");
    expect(seen.getByText("The server calls itself acme-backoffice").tagName).toBe("SMALL");
    // Outside that section (and its raw tool list) the self-reported name is not shown at all.
    const stage = document.getElementById("agent-detail-stage") as HTMLElement;
    const elsewhere = stage.cloneNode(true) as HTMLElement;
    [...elsewhere.querySelectorAll("section")].find((section) => section.querySelector("h3")?.textContent === "What the gateway sees")?.remove();
    expect(elsewhere.textContent).not.toContain("acme-backoffice");
  });

  it("uses the administrator's name in the Activity list and its server filter", async () => {
    effective = connected();
    activity = [{ id: "act-1", device_id: "agent-a", endpoint, server_name: "acme-backoffice", method: "tools/call", tool_name: "refund_order", decision: "allow", reason: "", result_status: "ok", approval_request_id: null, occurred_at: "2026-11-27T10:00:00Z" }];
    open("activity");
    const row = within((await screen.findByText("refund_order")).closest("tr") as HTMLElement);
    expect(row.getByText("Billing database")).toBeTruthy();
    expect(within(screen.getByLabelText("Server")).getByRole("option", { name: "Billing database" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("acme-backoffice");
  });
});
