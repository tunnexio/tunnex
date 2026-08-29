import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let role: "admin" | "member" | "operator" = "admin";
let currentOrg = { id: "org-a", name: "Organization A", agent_policy_templates_enabled: true };
let groups: Array<Record<string, unknown>> = [];
let peopleGroups: Array<Record<string, unknown>> = [];
let templates: Array<Record<string, unknown>> = [];
let groupMembers: Array<Record<string, unknown>> = [];
let versions: Array<Record<string, unknown>> = [];
let assignments: Array<Record<string, unknown>> = [];
let f09Reads: string[] = [];
let groupInventoryFail = false;

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: currentOrg, orgs: [currentOrg], setOrg: vi.fn(), loading: false, failed: false }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } } }),
}));

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string } } }) => {
        const orgId = request?.params?.path?.orgId ?? currentOrg.id;
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path === "/api/v1/organizations/{orgId}/members") return { data: [{ user_id: "user-a", role, email_verified: true }] };
        if (path.endsWith("/agent-groups")) {
          f09Reads.push(`${orgId}:groups`);
          if (groupInventoryFail) return { error: { error: { code: "boom", message: "unavailable" } } };
          return { data: orgId === "org-a" ? groups : [] };
        }
        if (path.endsWith("/groups")) {
          if (groupInventoryFail) return { error: { error: { code: "boom", message: "unavailable" } } };
          return { data: orgId === "org-a" ? peopleGroups : [] };
        }
        if (path.endsWith("/agent-policy-templates")) { f09Reads.push(`${orgId}:templates`); return { data: orgId === "org-a" ? templates : [] }; }
        if (path.endsWith("/agent-policy-template-assignments")) { f09Reads.push(`${orgId}:assignments`); return { data: orgId === "org-a" ? assignments : [] }; }
        if (path.endsWith("/agent-groups/{groupId}/members")) return { data: groupMembers };
        if (path.endsWith("/agent-policy-templates/{templateId}/versions")) return { data: versions };
        if (path.endsWith("/agents")) return { data: [{ device_id: "agent-a", name: "build-agent", gateway_name: "gw-a" }] };
        if (path.endsWith("/resources")) return { data: [{ id: "resource-a", name: "database", cidr: "10.50.0.0/24" }] };
        if (path.endsWith("/zero-trust-mode")) return { data: { mode: "enforcing" } };
        return { data: [] };
      }),
      POST: vi.fn(async (path: string) => {
        if (path.endsWith("/agent-groups")) {
          const row = { id: "group-a", org_id: "org-a", name: "workers", description: "", member_count: 0, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
          groups = [row]; return { data: row };
        }
        if (path.endsWith("/agent-groups/{groupId}/members")) { groupMembers = [{ device_id: "agent-a", name: "build-agent", status: "active", node_id: "node-a", assigned_ip: "10.99.0.2", added_at: new Date().toISOString() }]; return { data: undefined }; }
        if (path.endsWith("/agent-policy-templates")) {
          const row = { id: "template-a", org_id: "org-a", name: "database-access", description: "", created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
          templates = [row]; return { data: row };
        }
        if (path.endsWith("/agent-policy-templates/{templateId}/versions")) {
          const row = { id: "version-a", template_id: "template-a", version: 1, created_at: new Date().toISOString() };
          versions = [row]; return { data: row };
        }
        if (path.endsWith("/agent-policy-template-preview")) return { data: { digest: "a".repeat(64), affected_agents: 1, created_rules: 1, reused_rules: 0, removed_rules: 0, changed_gateways: 1, added: [], removed: [] } };
        if (path.endsWith("/agent-policy-template-assignments")) {
          assignments = [{ id: "assignment-a", group_id: "group-a", group_name: "workers", template_id: "template-a", template_name: "database-access", template_version_id: "version-a", version: 1, rule_count: 1, applied_at: new Date().toISOString() }];
          return { data: { assignment_id: "assignment-a", no_op: false, preview: { digest: "a".repeat(64), affected_agents: 1, created_rules: 1, reused_rules: 0, removed_rules: 0, changed_gateways: 1, added: [], removed: [] } } };
        }
        return { data: {} };
      }),
      PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async (path: string) => {
        if (path.endsWith("/agent-policy-template-assignments/{assignmentId}")) assignments = [];
        if (path.endsWith("/agent-groups/{groupId}/members/{deviceId}")) groupMembers = [];
        return { data: { members: 0, assignments: 1, generated_rules: 1, withdrawn_tuples: 1, changed_gateways: 1 } };
      }),
    },
  };
});

import { api } from "../src/lib/api";
import AccessGroups from "../src/pages/AccessGroups";
import AgentsPolicyTemplates from "../src/pages/AgentsPolicyTemplates";

beforeEach(() => {
  role = "admin";
  currentOrg = { id: "org-a", name: "Organization A", agent_policy_templates_enabled: true };
  groups = [];
  peopleGroups = [];
  templates = [];
  groupMembers = [];
  versions = [];
  assignments = [];
  f09Reads = [];
  groupInventoryFail = false;
  vi.mocked(api.GET).mockClear();
  vi.mocked(api.POST).mockClear();
  vi.mocked(api.DELETE).mockClear();
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("released F09 agent group and template workflow", () => {
  it("replaces a failed group load with one retryable error state", async () => {
    groupInventoryFail = true;
    render(<MemoryRouter><AccessGroups /></MemoryRouter>);

    expect(await screen.findByText("Could not load the group inventory.")).toBeTruthy();
    expect(screen.queryByText("Loading groups…")).toBeNull();

    groupInventoryFail = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("button", { name: "Create group" })).toBeTruthy();
  });

  it("renders exact valid member counts and refuses a stale or malformed count contract", async () => {
    peopleGroups = [
      { id: "people-zero", name: "empty people", member_count: 0 },
      { id: "people-one", name: "one person", member_count: 1 },
      { id: "directory-many", name: "directory team", member_count: 2, origin: "idp_sync" },
    ];
    groups = [{ id: "agent-many", name: "workers", member_count: 3 }];
    const view = render(<MemoryRouter><AccessGroups /></MemoryRouter>);
    expect(await screen.findByText("0 members")).toBeTruthy();
    expect(screen.getByText("1 member")).toBeTruthy();
    expect(screen.getByText("2 members")).toBeTruthy();
    expect(screen.getByText("3 members")).toBeTruthy();
    expect(screen.queryByText(/undefined members|null members|NaN members/)).toBeNull();
    view.unmount();

    for (const invalid of [undefined, null, "many"] as const) {
      peopleGroups = [{ id: `broken-${String(invalid)}`, name: "broken group", member_count: invalid }];
      groups = [];
      const invalidView = render(<MemoryRouter><AccessGroups /></MemoryRouter>);
      expect((await screen.findByRole("alert")).textContent).toContain("Member counts require the matching control-plane API version.");
      expect(screen.queryByText(/undefined members|null members|NaN members/)).toBeNull();
      invalidView.unmount();
    }
  });

  it("keeps group and template mutations reachable from their distinct Agents workspaces", async () => {
    const groupsView = render(<MemoryRouter initialEntries={["/access/groups?type=agents"]}><AccessGroups /></MemoryRouter>);
    await screen.findByRole("button", { name: "Create agent group" });
    fireEvent.click(screen.getByRole("button", { name: "Create agent group" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "workers" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Create group" }).at(-1)!);
    await screen.findByText("workers");
    groupsView.unmount();

    render(<MemoryRouter initialEntries={["/agents/policies"]}><AgentsPolicyTemplates /></MemoryRouter>);
    await screen.findByRole("button", { name: "Create template" });
    fireEvent.click(screen.getAllByRole("button", { name: "Create template" }).at(-1)!);
    fireEvent.change(screen.getByLabelText("Template name"), { target: { value: "database-access" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Create template" }).at(-1)!);
    await screen.findByText("database-access");
    fireEvent.click(screen.getByText("database-access"));
    await screen.findByRole("button", { name: "New version" });
    fireEvent.click(screen.getByRole("button", { name: "New version" }));
    fireEvent.change(screen.getByLabelText("Destination resource"), { target: { value: "resource-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Create version" }));
    await screen.findByRole("option", { name: "v1" });
    fireEvent.change(screen.getByLabelText("Assignment group"), { target: { value: "group-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview impact" }));
    await screen.findByText(/1 agents, 1 new rules/);
    fireEvent.click(screen.getByRole("button", { name: "Apply template" }));
    await screen.findByText(/workers.*v1/);
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await screen.findByText("No active assignments.");
    expect(vi.mocked(api.DELETE)).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agent-policy-template-assignments/{assignmentId}",
      expect.objectContaining({ params: { path: { orgId: "org-a", assignmentId: "assignment-a" } } }),
    );
  });

  it("makes no F09 calls or DOM for an unrelated member", async () => {
    role = "member";
    groups = [{ id: "secret-group", name: "secret-agents", member_count: 0 }];
    templates = [{ id: "secret-template", name: "secret-template" }];
    render(<MemoryRouter><AccessGroups /></MemoryRouter>);
    await screen.findByText("You do not have permission to manage groups.");
    expect(screen.queryByRole("button", { name: "Create group" })).toBeNull();
    expect(screen.queryByText("secret-agents")).toBeNull();
    expect(screen.queryByText("secret-template")).toBeNull();
    expect(f09Reads).toEqual([]);
  });

  it("keeps F09 authoring absent for an operator who can manage ordinary policy", async () => {
    role = "operator";
    render(<MemoryRouter><AgentsPolicyTemplates /></MemoryRouter>);
    await screen.findByText("You do not have permission to manage AI Agent groups or policy templates.");
    expect(screen.queryByRole("button", { name: "Create template" })).toBeNull();
    expect(f09Reads).toEqual([]);
  });

  it("withdraws prior-org F09 facts synchronously on organization switch", async () => {
    groups = [{ id: "group-a", name: "old-agent-group", member_count: 0 }];
    templates = [{ id: "template-a", name: "old-template" }];
    const view = render(<MemoryRouter><AccessGroups /></MemoryRouter>);
    await screen.findAllByText("old-agent-group");
    currentOrg = { id: "org-b", name: "Organization B", agent_policy_templates_enabled: true };
    view.rerender(<MemoryRouter><AccessGroups /></MemoryRouter>);
    expect(screen.queryByText("old-agent-group")).toBeNull();
    expect(screen.queryByText("old-template")).toBeNull();
    await screen.findByRole("heading", { name: "Groups" });
    expect(screen.queryByText("old-agent-group")).toBeNull();
  });
});
