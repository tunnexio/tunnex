import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import { ConnectMCPServer, PREVIEW_GIVE_UP_MS, PREVIEW_POLL_MS, type MCPConnectTarget } from "../src/components/ConnectMCPServer";

const endpoint = "http://10.0.0.5:8080/mcp";
const previewPath = "/api/v1/organizations/{orgId}/mcp-connections/preview";
const waiting = { preview_id: "preview-1", state: "waiting", endpoint, tools: [], expires_at: "2026-11-27T10:05:00Z" };
const ready = { ...waiting, state: "ready", server_name: "Billing tools", suggested_server_name: "billing-tools", tools: [
  { name: "list_invoices", description: "Lists invoices for a customer.", tool_definition_hash: "a".repeat(64), input_schema_hash: "s1" },
  { name: "refund_payment", description: "Refunds a payment.", tool_definition_hash: "b".repeat(64), input_schema_hash: "s2" },
  { name: "delete_customer", description: null, tool_definition_hash: "c".repeat(64), input_schema_hash: "s3" },
] };
const connection = { profile: { id: "profile-1", name: "Billing tools", endpoint, server_name: "billing-tools" }, group: { id: "group-1", name: "billing-runner" }, group_created: true, assignment: { id: "assignment-1" }, tool_policy: { group_id: "group-1", profile_id: "profile-1", server_name: "billing-tools", endpoint, version: 1, tools: [] } };

let previewRead: () => unknown = () => ({ data: waiting });
const connected = vi.fn(), dismissed = vi.fn();
const agent: MCPConnectTarget = { kind: "agent", id: "device-1", name: "billing-runner" };
const show = (target: MCPConnectTarget | undefined = agent) => render(<MemoryRouter><ConnectMCPServer orgId="org-a" target={target} onDismiss={dismissed} onConnected={connected} /></MemoryRouter>);
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
async function start() {
  fireEvent.change(screen.getByLabelText("Server address"), { target: { value: endpoint } });
  fireEvent.click(screen.getByRole("button", { name: "Read tool list" }));
  await tick(0);
}
const choice = (name: string, label: string) => within(screen.getByRole("radiogroup", { name: `Choice for ${name}` })).getByRole("radio", { name: label });
const chosen = (name: string) => within(screen.getByRole("radiogroup", { name: `Choice for ${name}` })).getAllByRole("radio").find((item) => item.getAttribute("aria-checked") === "true")?.textContent;

beforeEach(() => {
  vi.useFakeTimers({ now: new Date("2026-11-27T10:00:00Z").getTime() });
  previewRead = () => ({ data: waiting });
  get.mockImplementation(async (path: string) => path.endsWith("/preview/{previewId}") ? previewRead() : path.endsWith("/agent-groups") ? { data: [{ id: "group-9", name: "Support agents" }] } : path.endsWith("/agents") ? { data: { items: [{ device_id: "device-1", name: "billing-runner" }], next_cursor: null } } : { data: [] });
  post.mockImplementation(async (path: string) => path === previewPath ? { data: waiting } : { data: connection });
  connected.mockReset(); dismissed.mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); get.mockReset(); post.mockReset(); });

describe("Connect MCP server", () => {
  it("refuses an address that is not a web address, or that carries a password, before asking the gateway", async () => {
    show();
    fireEvent.change(screen.getByLabelText("Server address"), { target: { value: "billing server" } });
    fireEvent.click(screen.getByRole("button", { name: "Read tool list" }));
    expect(screen.getByText("Enter the full address of the MCP server, for example http://10.0.0.5:8080/mcp.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Server address"), { target: { value: "http://admin:secret@10.0.0.5/mcp" } });
    fireEvent.click(screen.getByRole("button", { name: "Read tool list" }));
    expect(screen.getByText(/Leave any user name or password out of the address/)).toBeTruthy();
    expect(post).not.toHaveBeenCalled();
  });

  it("shows that the gateway is reading the tool list, and keeps reading the preview until it answers", async () => {
    show(); await start();
    expect(post).toHaveBeenCalledWith(previewPath, { params: { path: { orgId: "org-a" } }, body: { endpoint, via_device_id: "device-1" } });
    expect(screen.getByText("Reading the tool list from the gateway…")).toBeTruthy();
    expect(screen.getByText(/This usually takes about 35 seconds\./)).toBeTruthy();
    expect(screen.getByText("Nothing is connected yet, and no tool is allowed until you save.")).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "Reading the tool list" }).getAttribute("aria-valuenow")).toBe("0");
    await tick(PREVIEW_POLL_MS * 3);
    expect(get.mock.calls.filter(([path]) => String(path).endsWith("/preview/{previewId}"))).toHaveLength(3);
    expect(get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/mcp-connections/preview/{previewId}", { params: { path: { orgId: "org-a", previewId: "preview-1" } } });
    expect(Number(screen.getByRole("progressbar").getAttribute("aria-valuenow"))).toBeGreaterThan(10);
    expect(screen.queryByRole("list", { name: "Tools" })).toBeNull();
    previewRead = () => ({ data: ready });
    await tick(PREVIEW_POLL_MS);
    expect(screen.getByRole("list", { name: "Tools" })).toBeTruthy();
  });

  it("lists each tool with the server's own name and description, every one starting Off", async () => {
    post.mockImplementation(async (path: string) => path === previewPath ? { data: ready } : { data: connection });
    show(); await start();
    const tools = within(screen.getByRole("list", { name: "Tools" })).getAllByRole("listitem");
    expect(tools.map((item) => item.getAttribute("aria-label"))).toEqual(["list_invoices", "refund_payment", "delete_customer"]);
    expect(within(tools[0]).getByText("Lists invoices for a customer.")).toBeTruthy();
    expect(within(tools[2]).getByText("The server gives no description for this tool.")).toBeTruthy();
    for (const name of ["list_invoices", "refund_payment", "delete_customer"]) {
      expect(chosen(name)).toBe("Off");
      expect((screen.getByRole("combobox", { name: `What ${name} does` }) as HTMLSelectElement).value).toBe("");
    }
    expect(screen.getByText("0 allowed, 0 ask first, 3 off")).toBeTruthy();
    expect((screen.getByLabelText("Server name") as HTMLInputElement).value).toBe("Billing tools");
    expect(screen.getByText("http://127.0.0.1:17100/billing-tools")).toBeTruthy();
    expect(screen.queryByText(/hash|digest/i)).toBeNull();
  });

  it("saves the choices and the markers in one step and shows the address clients use", async () => {
    post.mockImplementation(async (path: string) => path === previewPath ? { data: ready } : { data: connection });
    show(); await start();
    fireEvent.click(choice("list_invoices", "Allow"));
    fireEvent.change(screen.getByRole("combobox", { name: "What list_invoices does" }), { target: { value: "reads" } });
    fireEvent.click(choice("refund_payment", "Ask first"));
    fireEvent.change(screen.getByRole("combobox", { name: "What refund_payment does" }), { target: { value: "changes" } });
    fireEvent.change(screen.getByRole("combobox", { name: "What delete_customer does" }), { target: { value: "destructive" } });
    expect(screen.getByText("1 allowed, 1 ask first, 1 off")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect server" }));
    await tick(0);
    expect(post).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/mcp-connections", { params: { path: { orgId: "org-a" } }, body: {
      target: { device_id: "device-1" }, name: "Billing tools", endpoint, server_name: "billing-tools", preview_id: "preview-1",
      tools: [
        { tool_name: "list_invoices", mode: "allow", effect: "reads", tool_definition_hash: "a".repeat(64) },
        { tool_name: "refund_payment", mode: "ask", effect: "changes", tool_definition_hash: "b".repeat(64) },
        { tool_name: "delete_customer", mode: "off", effect: "destructive", tool_definition_hash: "c".repeat(64) },
      ],
    } });
    expect(screen.getByRole("heading", { name: "MCP server connected" })).toBeTruthy();
    expect(screen.getByText("http://127.0.0.1:17100/billing-tools")).toBeTruthy();
    expect(screen.getByText(/The agent needs no network rule for this server/)).toBeTruthy();
    expect(screen.getByText(/was created to hold this server's tool choices/)).toBeTruthy();
    expect(connected).toHaveBeenCalledWith(connection);
  });

  it("connects to an agent group when opened from one", async () => {
    post.mockImplementation(async (path: string) => path === previewPath ? { data: ready } : { data: { ...connection, group_created: false } });
    show({ kind: "group", id: "group-9", name: "Support agents" }); await start();
    expect(post).toHaveBeenCalledWith(previewPath, expect.objectContaining({ body: { endpoint, via_group_id: "group-9" } }));
    fireEvent.click(screen.getByRole("button", { name: "Connect server" }));
    await tick(0);
    expect(post.mock.calls.at(-1)?.[1].body.target).toEqual({ group_id: "group-9" });
  });

  it("asks which agent or group when opened from the MCP page", async () => {
    render(<MemoryRouter><ConnectMCPServer orgId="org-a" onDismiss={dismissed} /></MemoryRouter>);
    await tick(0);
    expect((screen.getByRole("button", { name: "Read tool list" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Agent group"), { target: { value: "group-9" } });
    await start();
    expect(post).toHaveBeenCalledWith(previewPath, expect.objectContaining({ body: { endpoint, via_group_id: "group-9" } }));
  });

  it.each([
    ["unreachable", /The gateway could not reach this address\./],
    ["invalid", /not as an MCP server/],
    ["no_gateway", /No gateway that can read this server is connected\./],
    ["timed_out", /The gateway did not answer in time\./],
  ])("says in plain words why reading failed (%s), connects nothing and lets the administrator try again", async (failure_reason, message) => {
    previewRead = () => ({ data: { ...waiting, state: "failed", failure_reason } });
    show(); await start(); await tick(PREVIEW_POLL_MS);
    expect(screen.getByRole("alert").textContent).toBe("The tool list could not be read.");
    expect(screen.getByText(message)).toBeTruthy();
    expect(screen.getByText("Nothing was connected.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Connect with every tool off" })).toBeNull();
    previewRead = () => ({ data: ready });
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await tick(0);
    expect(screen.getByText("Reading the tool list from the gateway…")).toBeTruthy();
    await tick(PREVIEW_POLL_MS);
    expect(screen.getByRole("list", { name: "Tools" })).toBeTruthy();
    expect(post.mock.calls.filter(([path]) => path === previewPath)).toHaveLength(2);
  });

  it("lets a server that needs a sign-in be connected with every tool off", async () => {
    previewRead = () => ({ data: { ...waiting, state: "failed", failure_reason: "unauthorized" } });
    show(); await start(); await tick(PREVIEW_POLL_MS);
    expect(screen.getByText(/asks for a sign-in before it lists its tools/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect with every tool off" }));
    fireEvent.change(screen.getByLabelText("Server name"), { target: { value: "CRM" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect server" }));
    await tick(0);
    expect(post.mock.calls.at(-1)?.[1].body).toEqual({ target: { device_id: "device-1" }, name: "CRM", endpoint, tools: [] });
  });

  it("stops waiting when the gateway never answers", async () => {
    show(); await start();
    await tick(PREVIEW_GIVE_UP_MS);
    expect(screen.getByText("The gateway did not answer in time. Try again.")).toBeTruthy();
  });

  it("keeps the choices when the server changed a tool or the name is taken, and says what to do", async () => {
    post.mockImplementation(async (path: string) => path === previewPath ? { data: ready } : { error: { error: { code: "mcp_tool_definition_stale", message: "stale" } } });
    show(); await start();
    fireEvent.click(choice("list_invoices", "Allow"));
    fireEvent.click(screen.getByRole("button", { name: "Connect server" }));
    await tick(0);
    expect(screen.getByText("The server changed a tool while you were choosing. Read the tool list again and check it before saving.")).toBeTruthy();
    expect(chosen("list_invoices")).toBe("Allow");
    expect(connected).not.toHaveBeenCalled();
    post.mockImplementation(async () => ({ error: { error: { code: "mcp_server_name_taken", message: "taken" } } }));
    fireEvent.click(screen.getByRole("button", { name: "Connect server" }));
    await tick(0);
    expect(screen.getByText("Another MCP server already uses this address name. Choose a different one.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Address name"), { target: { value: "mcp" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect server" }));
    expect(screen.getByText(/The address name "mcp" is kept for clients set up earlier/)).toBeTruthy();
  });
});
