import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, post, put, del } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PUT: put, PATCH: vi.fn(), DELETE: del } };
});

import { AgentGroupMCPServers, AgentMCPServers, mcpClientSnippets } from "../src/components/AgentMCPServers";

const billing = "http://10.0.0.5:8080/mcp", crm = "http://10.0.0.9:8080/mcp";
const server = (over: Record<string, unknown>) => ({ profile_id: "profile-billing", profile_name: "Billing tools", server_name: "billing-tools", endpoint: billing, group_id: "group-1", group_name: "Finance agents", default: true, local_url: "http://127.0.0.1:17100/billing-tools", policy_source: "group", ...over });
const crmServer = server({ profile_id: "profile-crm", profile_name: "CRM", server_name: "crm", endpoint: crm, group_id: "group-2", group_name: "Support agents", default: false, local_url: "http://127.0.0.1:17100/crm" });
const inventory = { device_id: "agent", observed_at: "2026-11-27T10:00:00Z", source: "gateway", snapshot: { servers: [
  { endpoint: billing, server_name: "billing", tools: [{ name: "refund_payment", description: "Refunds a payment.", input_schema_hash: "s1", tool_definition_hash: "a".repeat(64) }] },
  { endpoint: crm, server_name: "crm", tools: [{ name: "find_contact", description: "Finds a contact.", input_schema_hash: "s2", tool_definition_hash: "b".repeat(64) }] },
] } } as never;
const setting = (over: Record<string, unknown>) => ({ tool_name: "refund_payment", description: "Refunds a payment.", mode: "ask", effect: "changes", observed: true, tool_definition_hash: "a".repeat(64), definition_state: "current", ...over });
let groupPolicy: Record<string, unknown> = {};
const agentPolicy = { version: 2, inventory_observed_at: "2026-11-27T10:00:00Z", created_at: "2026-11-27T09:00:00Z", override_endpoints: [billing], rules: [{ endpoint: billing, server_name: "billing", tool_name: "refund_payment", input_schema_hash: "s1", step_up_required: false, definition_state: "current" }] };
const changed = vi.fn();
const groupPolicyPath = "/api/v1/organizations/{orgId}/agent-groups/{groupId}/mcp-servers/{profileId}/tool-policy";
function show(servers: Array<Record<string, unknown>>, props: { canManagePolicy?: boolean; canConnect?: boolean } = {}) {
  return render(<MemoryRouter><AgentMCPServers orgId="org-a" deviceId="agent" agentName="billing-runner" effective={{ assigned: servers.length > 0, enforcement: "gateway", servers } as never} inventory={inventory} canManagePolicy={props.canManagePolicy ?? true} canConnect={props.canConnect ?? true} onChanged={changed} /></MemoryRouter>);
}
const chosen = (scope: HTMLElement, name: string) => within(within(scope).getByRole("radiogroup", { name: `Choice for ${name}` })).getAllByRole("radio").find((item) => item.getAttribute("aria-checked") === "true")?.textContent;

beforeEach(() => {
  groupPolicy = { group_id: "group-1", profile_id: "profile-billing", server_name: "billing-tools", endpoint: billing, version: 3, overriding_agent_count: 0, tools: [setting({}), setting({ tool_name: "list_invoices", description: "Lists invoices.", mode: "off", effect: null })] };
  get.mockImplementation(async (path: string, options: { params: { path: { profileId?: string } } }) => {
    if (path === groupPolicyPath) return options.params.path.profileId === "profile-crm" ? { data: { ...groupPolicy, group_id: "group-2", profile_id: "profile-crm", server_name: "crm", endpoint: crm, tools: [setting({ tool_name: "find_contact", description: "Finds a contact.", mode: "allow", effect: "reads" })] } } : { data: groupPolicy };
    if (path.endsWith("/mcp-tool-policy")) return { data: agentPolicy };
    if (path.endsWith("/agent-mcp-assignments")) return { data: [{ id: "a1", profile_id: "profile-billing", profile_name: "Billing tools", group_id: "group-1", group_name: "Finance agents", state: "active" }, { id: "a2", profile_id: "profile-crm", profile_name: "CRM", group_id: "group-1", group_name: "Finance agents", state: "active" }, { id: "a3", profile_id: "profile-old", profile_name: "Old", group_id: "group-1", group_name: "Finance agents", state: "replaced" }, { id: "a4", profile_id: "profile-x", profile_name: "Elsewhere", group_id: "group-7", group_name: "Other", state: "active" }] };
    if (path.endsWith("/agent-mcp-profiles")) return { data: [{ id: "profile-billing", name: "Billing tools", endpoint: billing, server_name: "billing-tools" }, { id: "profile-crm", name: "CRM", endpoint: crm, server_name: "crm" }] };
    return { data: [] };
  });
  put.mockImplementation(async (_path: string, options: { body: { tools: Array<Record<string, unknown>> } }) => ({ data: { ...groupPolicy, version: 4, tools: (groupPolicy.tools as Array<Record<string, unknown>>).map((tool) => ({ ...tool, ...options.body.tools.find((item) => item.tool_name === tool.tool_name) })) } }));
  del.mockResolvedValue({ data: agentPolicy });
  changed.mockReset();
});
afterEach(() => { cleanup(); get.mockReset(); post.mockReset(); put.mockReset(); del.mockReset(); });

describe("an agent's MCP servers", () => {
  it("says so when no server is connected and offers to connect one", () => {
    show([]);
    expect(screen.getByText("No MCP server is connected to this agent yet.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect MCP server" }));
    expect(screen.getByRole("dialog", { name: "Connect MCP server to billing-runner" })).toBeTruthy();
  });

  it("offers no connect action to a person who may not connect servers", () => {
    show([], { canConnect: false });
    expect(screen.queryByRole("button", { name: "Connect MCP server" })).toBeNull();
    expect(screen.getByText("Ask an owner or administrator to connect one.")).toBeTruthy();
  });

  it("shows a server that follows its group: the group's policy, and that a change reaches the whole group", async () => {
    show([server({})]);
    const card = screen.getByRole("region", { name: "Billing tools" });
    expect(within(card).getByText("Group policy")).toBeTruthy();
    expect(within(card).getByText(/A change here applies to every agent in that group\./)).toBeTruthy();
    expect(within(card).getAllByRole("link", { name: "Finance agents" })[0].getAttribute("href")).toBe("/agents/groups?group=agents%3Agroup-1");
    await within(card).findByRole("list", { name: "Tools" });
    expect(get).toHaveBeenCalledWith(groupPolicyPath, { params: { path: { orgId: "org-a", groupId: "group-1", profileId: "profile-billing" } } });
    expect(chosen(card, "refund_payment")).toBe("Ask first");
    expect(chosen(card, "list_invoices")).toBe("Off");
    expect((within(card).getByRole("combobox", { name: "What refund_payment does" }) as HTMLSelectElement).value).toBe("changes");
    expect(within(card).queryByRole("button", { name: "Use the group's policy" })).toBeNull();
    expect(get.mock.calls.some(([path]) => String(path).endsWith("/mcp-tool-policy"))).toBe(false);
  });

  it("saves the group's policy with the choice and the marker for every tool", async () => {
    show([server({})]);
    const card = screen.getByRole("region", { name: "Billing tools" });
    await within(card).findByRole("list", { name: "Tools" });
    expect((within(card).getByRole("button", { name: "Save tool policy" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(within(card).getByRole("radiogroup", { name: "Choice for list_invoices" })).getByRole("radio", { name: "Allow" }));
    fireEvent.change(within(card).getByRole("combobox", { name: "What list_invoices does" }), { target: { value: "reads" } });
    fireEvent.click(within(card).getByRole("button", { name: "Save tool policy" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(groupPolicyPath, { params: { path: { orgId: "org-a", groupId: "group-1", profileId: "profile-billing" } }, body: { tools: [
      { tool_name: "refund_payment", mode: "ask", effect: "changes", tool_definition_hash: "a".repeat(64) },
      { tool_name: "list_invoices", mode: "allow", effect: "reads", tool_definition_hash: "a".repeat(64) },
    ] } }));
    expect(await within(card).findByText("Tool policy saved.")).toBeTruthy();
  });

  it("shows that an agent's own policy overrides the group, and switches back only after an in-page confirmation", async () => {
    vi.spyOn(window, "confirm").mockImplementation(() => { throw new Error("the page must not use window.confirm"); });
    show([server({ policy_source: "agent" })]);
    const card = screen.getByRole("region", { name: "Billing tools" });
    expect(within(card).getByText("This agent's own policy")).toBeTruthy();
    expect(within(card).getByText(/It overrides the policy of Finance agents: changes to the group's policy do not reach this agent\./)).toBeTruthy();
    // The editor shown is the agent's own policy for this server, not the group's.
    await within(card).findByRole("list", { name: "Tools on billing" });
    expect(chosen(card, "refund_payment")).toBe("Allow");
    expect(get.mock.calls.some(([path]) => path === groupPolicyPath)).toBe(false);
    fireEvent.click(within(card).getByRole("button", { name: "Use the group's policy" }));
    expect(del).not.toHaveBeenCalled();
    expect(within(card).getByText(/This agent's own choices for this server are removed, and it follows Finance agents from now on\./)).toBeTruthy();
    fireEvent.click(within(card).getByRole("button", { name: "Keep this agent's policy" }));
    expect(del).not.toHaveBeenCalled();
    fireEvent.click(within(card).getByRole("button", { name: "Use the group's policy" }));
    fireEvent.click(within(card).getByRole("button", { name: "Use the group's policy" }));
    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy/override", { params: { path: { orgId: "org-a", deviceId: "agent" }, query: { endpoint: billing } } }));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    vi.restoreAllMocks();
  });

  it("treats an override that was already removed as done", async () => {
    del.mockResolvedValue({ error: { error: { code: "mcp_tool_policy_override_not_found" } } });
    show([server({ policy_source: "agent" })]);
    const card = screen.getByRole("region", { name: "Billing tools" });
    fireEvent.click(within(card).getByRole("button", { name: "Use the group's policy" }));
    fireEvent.click(within(card).getByRole("button", { name: "Use the group's policy" }));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(within(card).queryByRole("alert")).toBeNull();
  });

  it("lists two servers by name, each with its own address, and marks the first", async () => {
    show([server({}), crmServer]);
    expect(screen.getByText(/This agent can use 2 MCP servers, each at its own address\./)).toBeTruthy();
    const first = screen.getByRole("region", { name: "Billing tools" }), second = screen.getByRole("region", { name: "CRM" });
    expect(within(first).getByText("http://127.0.0.1:17100/billing-tools")).toBeTruthy();
    expect(within(first).getByText("First server")).toBeTruthy();
    expect(first.textContent).toContain("As the first server it also answers at http://127.0.0.1:17100/mcp");
    expect(within(second).getByText("http://127.0.0.1:17100/crm")).toBeTruthy();
    expect(within(second).queryByText("First server")).toBeNull();
    expect(second.textContent).not.toContain("also answers at");
    await within(second).findByRole("list", { name: "Tools" });
    expect(chosen(second, "find_contact")).toBe("Allow");
    expect(chosen(first, "refund_payment")).toBe("Ask first");
  });

  it("gives ready-to-paste client settings with a copy button", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    show([crmServer]);
    const card = screen.getByRole("region", { name: "CRM" });
    const claude = within(card).getByRole("group", { name: "Claude Code" });
    expect(claude.textContent).toContain("claude mcp add --transport http crm http://127.0.0.1:17100/crm");
    fireEvent.click(within(claude).getByRole("button", { name: "Copy the Claude Code setup" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("claude mcp add --transport http crm http://127.0.0.1:17100/crm"));
    fireEvent.click(within(card).getByRole("button", { name: "Copy address for mcp clients on the agent host" }));
    await waitFor(() => expect(writeText).toHaveBeenLastCalledWith("http://127.0.0.1:17100/crm"));
    expect(JSON.parse(mcpClientSnippets("crm", "http://127.0.0.1:17100/crm")[1].text)).toEqual({ mcpServers: { crm: { url: "http://127.0.0.1:17100/crm" } } });
  });
});

describe("an agent group's MCP servers and tool policy", () => {
  const showGroup = () => render(<MemoryRouter><AgentGroupMCPServers orgId="org-a" groupId="group-1" groupName="Finance agents" canManage /></MemoryRouter>);

  it("lists the group's active servers with the policy every agent in it follows", async () => {
    showGroup();
    const first = await screen.findByRole("region", { name: "Billing tools" });
    expect(screen.getByRole("region", { name: "CRM" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Old" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Elsewhere" })).toBeNull();
    expect(within(first).getByText("http://127.0.0.1:17100/billing-tools")).toBeTruthy();
    expect(await within(first).findByText("Choose what every agent in Finance agents may do with this server. A tool nobody has decided about is Off.")).toBeTruthy();
  });

  it("says how many agents have their own policy and do not follow the group", async () => {
    groupPolicy = { ...groupPolicy, overriding_agent_count: 2 };
    showGroup();
    const first = await screen.findByRole("region", { name: "Billing tools" });
    expect((await within(first).findByRole("note")).textContent).toBe("2 agents in this group have their own policy for this server and do not follow this one.");
  });

  it("does not accept a changed tool by saving something else", async () => {
    groupPolicy = { ...groupPolicy, tools: [setting({ definition_state: "changed", description: "Refunds a payment and emails the customer list." }), setting({ tool_name: "list_invoices", mode: "off", effect: null })] };
    showGroup();
    const first = await screen.findByRole("region", { name: "Billing tools" });
    const row = within(await within(first).findByRole("listitem", { name: "refund_payment" }));
    expect(row.getByText("Changed, review")).toBeTruthy();
    expect(row.getByText("Refunds a payment and emails the customer list.")).toBeTruthy();
    fireEvent.click(within(within(first).getByRole("radiogroup", { name: "Choice for list_invoices" })).getByRole("radio", { name: "Allow" }));
    fireEvent.click(within(first).getByRole("button", { name: "Save tool policy" }));
    expect((await within(first).findByRole("alert")).textContent).toBe("Review refund_payment first: accept its new version, or turn it Off.");
    expect(put).not.toHaveBeenCalled();
    fireEvent.click(row.getByRole("button", { name: "Accept new version" }));
    fireEvent.click(within(first).getByRole("button", { name: "Save tool policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
  });

  it("opens the connect dialog for the group", async () => {
    showGroup();
    await screen.findByRole("region", { name: "Billing tools" });
    fireEvent.click(screen.getByRole("button", { name: "Connect MCP server" }));
    expect(screen.getByRole("dialog", { name: "Connect MCP server to Finance agents" })).toBeTruthy();
  });
});
