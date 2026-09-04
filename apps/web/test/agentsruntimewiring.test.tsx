import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, post, patch, del, put } = vi.hoisted(() => ({
  get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn(), put: vi.fn(),
}));
let org = { id: "org-a", name: "Acme", max_agent_identities: null as number | null, managed_agent_runtime_enabled: false };

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } } }) }));
vi.mock("../src/lib/rbac", () => ({ can: () => true }));
vi.mock("../src/lib/api", () => ({
  api: { GET: get, POST: post, PATCH: patch, PUT: put, DELETE: del },
  loadOne: async (fn: () => Promise<{ data?: unknown; error?: unknown }>) => {
    const result = await fn();
    return result.error ? { ok: false, error: "Unavailable" } : { ok: true, data: result.data };
  },
  apiErrorMessage: (_: unknown, fallback: string) => fallback,
}));

import AgentDetail from "../src/pages/AgentDetail";

const profile = {
  device_id: "agent-a", name: "builder", environment: "prod", runtime: "python", labels: { team: "security" },
  owner_id: "user-a", owner_email: "owner@example.test", managing_group_id: null, managing_group_name: null,
  status: "active", last_handshake_at: "2026-08-22T10:00:00Z",
  permissions: { view_privileged: true, manage: true, assign: true, grant_access: true, revoke: true, rotate_credentials: true },
};
const runtime = { connectivity: "connected", health: "last_good", stale: false, last_seen_at: "2026-08-22T10:01:00Z", desired_revision: 2, applied_revision: 1 };
const rotation = { device_id: "agent-a", current_revision: 1, state: "current", requested_revision: null, deadline: null, wireguard_current_revision: 1, wireguard_state: "current", wireguard_requested_revision: null };
const inventory = { observed_at: "2026-08-22T10:00:00Z", snapshot: { servers: [{ endpoint: "https://mcp.example.test", server_name: "inventory", tools: [{ name: "read", input_schema_hash: "hash" }] }], oauth_discovery: { servers: [{ endpoint: "https://mcp.example.test", status: "protected", protected_resource: "https://resource.example.test", authorization_servers: ["https://issuer.example.test"], scopes_supported: ["read"] }] } } };

function seed() {
  get.mockImplementation(async (path: string) => {
    if (path.endsWith("/agents/{deviceId}")) return { data: profile };
    if (path.endsWith("/runtime-status")) return { data: runtime };
    if (path.endsWith("/credential-rotation")) return { data: rotation };
    if (path.endsWith("/mcp-inventory")) return { data: inventory };
    if (path.endsWith("/workflow-provenance")) return { data: [] };
    if (path.endsWith("/effective-mcp-profile")) return { data: { assigned: false } };
    if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role: "owner", status: "active" }] };
    if (path.endsWith("/groups")) return { data: [{ id: "group-a", name: "Agents" }] };
    if (path.endsWith("/mcp-tool-policy")) return { data: { version: 1, inventory_observed_at: "2026-08-22T10:00:00Z", rules: [] } };
    if (path.endsWith("/mcp-oauth-connections") || path.endsWith("/mcp-tool-approval-requests")) return { data: [] };
    return { data: [] };
  });
  post.mockResolvedValue({ data: {} }); patch.mockResolvedValue({ data: profile }); put.mockResolvedValue({ data: {} }); del.mockResolvedValue({ data: {} });
}
function renderDetail(tab = "overview") {
  return render(<MemoryRouter initialEntries={[`/agents/agent-a?tab=${tab}`]}><AgentDetail agentIdOverride="agent-a" /></MemoryRouter>);
}
afterEach(() => { cleanup(); get.mockReset(); post.mockReset(); patch.mockReset(); put.mockReset(); del.mockReset(); org = { id: "org-a", name: "Acme", max_agent_identities: null, managed_agent_runtime_enabled: false }; });

describe("active Agent detail mutation ownership", () => {
  it("owns metadata, managing-group assignment, lifecycle and revoke-then-remove on Overview", async () => {
    seed(); renderDetail();
    await screen.findByText("Profile and lifecycle");
    fireEvent.click(screen.getByRole("button", { name: "Edit profile" }));
    fireEvent.change(screen.getByLabelText("Environment"), { target: { value: "staging" } });
    fireEvent.click(screen.getByRole("button", { name: "Save metadata" }));
    await waitFor(() => expect(patch).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}", expect.objectContaining({ params: { path: { orgId: "org-a", deviceId: "agent-a" } } })));
    fireEvent.click(screen.getByRole("button", { name: "Remove agent" }));
    expect(screen.getByText(/This first revokes the agent’s tunnel credential/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Revoke and remove" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices/{deviceId}/revoke", expect.anything()));
    expect(del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices/{deviceId}", expect.anything());
  });

  it("owns credential rotation on Runtime and refetches server truth", async () => {
    seed(); renderDetail("runtime");
    fireEvent.click(await screen.findByRole("button", { name: "Rotate credential" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", expect.anything()));
    expect(get.mock.calls.filter(([path]) => String(path).endsWith("/credential-rotation")).length).toBeGreaterThanOrEqual(2);
  });

  it("owns MCP policy, OAuth and one-use step-up approval controls without retaining the submitted secret", async () => {
    seed();
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/mcp-tool-approval-requests")) return { data: [{ id: "approval-a", server_name: "inventory", tool_name: "read", state: "pending" }] };
      if (path.endsWith("/mcp-oauth-connections")) return { data: [] };
      if (path.endsWith("/agents/{deviceId}")) return { data: profile };
      if (path.endsWith("/runtime-status")) return { data: runtime };
      if (path.endsWith("/credential-rotation")) return { data: rotation };
      if (path.endsWith("/mcp-inventory")) return { data: inventory };
      if (path.endsWith("/effective-mcp-profile")) return { data: { assigned: false } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role: "owner", status: "active" }] };
      if (path.endsWith("/groups")) return { data: [] };
      if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
      if (path.endsWith("/mcp-tool-policy")) return { data: { version: 1, inventory_observed_at: "now", rules: [] } };
      return { data: [] };
    });
    renderDetail("mcp");
    fireEvent.click(await screen.findByRole("button", { name: "Approve once" }));
    expect(screen.getByText(/authorizes one retried invocation/i)).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Approve once" })[1]);
    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/approve", expect.anything()));
  });

  it("keeps MCP protected-read failures distinct from an empty policy or request list", async () => {
    seed();
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/agents/{deviceId}")) return { data: profile };
      if (path.endsWith("/runtime-status")) return { data: runtime };
      if (path.endsWith("/credential-rotation")) return { data: rotation };
      if (path.endsWith("/mcp-inventory")) return { data: inventory };
      if (path.endsWith("/workflow-provenance")) return { data: [] };
      if (path.endsWith("/effective-mcp-profile")) return { data: { assigned: false } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role: "owner", status: "active" }] };
      if (path.endsWith("/groups")) return { data: [] };
      if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
      if (path.endsWith("/mcp-tool-policy") || path.endsWith("/mcp-tool-approval-requests") || path.endsWith("/mcp-oauth-connections")) return { error: { error: { message: "forbidden" } } };
      return { data: [] };
    });
    renderDetail("mcp");
    expect(await screen.findByText(/MCP tool policy could not be loaded: Unavailable/)).toBeTruthy();
    expect(screen.getByText(/Step-up requests could not be loaded: Unavailable/)).toBeTruthy();
    expect(screen.getByText(/MCP OAuth connections could not be loaded: Unavailable/)).toBeTruthy();
    expect(screen.queryByText("No policy yet: the local proxy denies every tool.")).toBeNull();
    expect(screen.queryByText("No step-up requests.")).toBeNull();
  });

  it("keeps a failed step-up approval open with a retryable error", async () => {
    seed();
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/mcp-tool-approval-requests")) return { data: [{ id: "approval-a", server_name: "inventory", tool_name: "read", state: "pending" }] };
      if (path.endsWith("/mcp-oauth-connections")) return { data: [] };
      if (path.endsWith("/agents/{deviceId}")) return { data: profile };
      if (path.endsWith("/runtime-status")) return { data: runtime };
      if (path.endsWith("/credential-rotation")) return { data: rotation };
      if (path.endsWith("/mcp-inventory")) return { data: inventory };
      if (path.endsWith("/workflow-provenance")) return { data: [] };
      if (path.endsWith("/effective-mcp-profile")) return { data: { assigned: false } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", email: "owner@example.test", role: "owner", status: "active" }] };
      if (path.endsWith("/groups")) return { data: [] };
      if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
      if (path.endsWith("/mcp-tool-policy")) return { data: { version: 1, inventory_observed_at: "now", rules: [] } };
      return { data: [] };
    });
    post.mockResolvedValue({ error: { error: { message: "request already expired" } } });
    renderDetail("mcp");
    fireEvent.click(await screen.findByRole("button", { name: "Approve once" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Approve once" })[1]);
    expect(await screen.findByText("Could not approve this step-up request. It may already have expired or been consumed. Refresh and try again.")).toBeTruthy();
    expect(screen.getByRole("dialog", { name: "Approve read once?" })).toBeTruthy();
  });
});
