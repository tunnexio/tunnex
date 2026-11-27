import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get } };
});

import { AgentMCPToolActivityPanel, mcpActivityExportHref } from "../src/components/AgentMCPControls";

const path = "/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-activity";
const call = (over: Record<string, unknown>) => ({
  id: "act-1", device_id: "agent", endpoint: "http://10.0.0.5:8080/mcp", server_name: "billing", method: "tools/call", tool_name: "list_invoices",
  decision: "allow", reason: "", result_status: "ok", approval_request_id: null, occurred_at: "2026-11-27T10:00:00Z", ...over,
});
const rows = [
  call({}),
  call({ id: "act-2", tool_name: "refund_payment", approval_request_id: "9f8e7d6c-1111-4222-8333-444455556666" }),
  call({ id: "act-3", tool_name: "export_ledger", result_status: "error" }),
  call({ id: "act-4", tool_name: "sync_bank", result_status: "upstream_unavailable" }),
  call({ id: "act-5", tool_name: "run_sql", decision: "deny", reason: "policy", result_status: "not_forwarded" }),
  call({ id: "act-6", tool_name: "slow_report", result_status: "pending" }),
];
const show = () => render(<AgentMCPToolActivityPanel orgId="org" deviceId="agent" />);
const row = (tool: string) => within(screen.getByText(tool).closest("tr") as HTMLElement);

beforeEach(() => { get.mockResolvedValue({ data: { items: rows, next_cursor: null } }); });
afterEach(() => { cleanup(); get.mockReset(); });

it("lists each call with its time, tool, server, result and approval", async () => {
  show();
  const table = await screen.findByRole("table", { name: "MCP calls" });
  expect(within(table).getAllByRole("columnheader").map(header => header.textContent)).toEqual(["Time", "Tool", "Server", "Result", "Approval"]);
  expect(row("list_invoices").getByText("Ran")).toBeTruthy();
  expect(row("list_invoices").getByText("billing")).toBeTruthy();
  expect(row("list_invoices").getByText("Not needed")).toBeTruthy();
  expect(row("list_invoices").getByTitle(new Date("2026-11-27T10:00:00Z").toLocaleString())).toBeTruthy();
  expect(row("refund_payment").getByText("Approved request 9f8e7d6c")).toBeTruthy();
  expect(row("export_ledger").getByText("Failed")).toBeTruthy();
  expect(row("sync_bank").getByText("Failed: the MCP server did not answer")).toBeTruthy();
  expect(row("run_sql").getByText("Blocked: not allowed by the tool rules")).toBeTruthy();
  expect(row("slow_report").getByText("Still running")).toBeTruthy();
  expect(get).toHaveBeenCalledWith(path, { params: { path: { orgId: "org", deviceId: "agent" }, query: { limit: 50 } } });
});

const lastQuery = () => get.mock.calls.at(-1)?.[1].params.query;
const startOf = (day: string) => new Date(`${day}T00:00:00`).toISOString(), endOf = (day: string) => new Date(`${day}T23:59:59.999`).toISOString();

it("asks the server for denied calls, and for calls that ran on an approval", async () => {
  show();
  await screen.findByText("list_invoices");
  const all = screen.getByRole("button", { name: "All calls" }), denied = screen.getByRole("button", { name: "Denied calls" }), approved = screen.getByRole("button", { name: "Approved calls" });
  expect(all.getAttribute("aria-pressed")).toBe("true");
  get.mockResolvedValue({ data: { items: [rows[4]], next_cursor: null } });
  fireEvent.click(denied);
  await waitFor(() => expect(lastQuery()).toEqual({ limit: 50, decision: "deny" }));
  expect(denied.getAttribute("aria-pressed")).toBe("true");
  expect(await screen.findByText("run_sql")).toBeTruthy();
  expect(screen.queryByText("list_invoices")).toBeNull();
  get.mockResolvedValue({ data: { items: [call({ id: "act-2", tool_name: "refund_payment", approval_request_id: "9f8e7d6c-1111-4222-8333-444455556666", approved_by_email: "dana@example.test", approved_at: "2026-11-27T09:59:30Z" })], next_cursor: null } });
  fireEvent.click(approved);
  await waitFor(() => expect(lastQuery()).toEqual({ limit: 50, approved: true }));
  expect(await screen.findByText(/^Approved by dana@example\.test/)).toBeTruthy();
  fireEvent.click(all);
  await waitFor(() => expect(lastQuery()).toEqual({ limit: 50 }));
});

it("filters by a date range and by server, and clears the filters in one step", async () => {
  render(<AgentMCPToolActivityPanel orgId="org" deviceId="agent" servers={[{ server_name: "billing-tools", profile_name: "Billing tools" }, { server_name: "crm", profile_name: "CRM" }]} />);
  await screen.findByText("list_invoices");
  fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-11-20" } });
  fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-11-27" } });
  fireEvent.change(screen.getByLabelText("Server"), { target: { value: "crm" } });
  await waitFor(() => expect(lastQuery()).toEqual({ limit: 50, from: startOf("2026-11-20"), to: endOf("2026-11-27"), server: "crm" }));
  expect(within(screen.getByLabelText("Server")).getAllByRole("option").map((option) => option.textContent)).toEqual(["All servers", "Billing tools", "CRM"]);
  fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
  await waitFor(() => expect(lastQuery()).toEqual({ limit: 50 }));
  expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
});

it("refuses a range that ends before it starts instead of showing an empty list", async () => {
  show();
  await screen.findByText("list_invoices");
  fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-11-27" } });
  await waitFor(() => expect(lastQuery()).toEqual({ limit: 50, from: startOf("2026-11-27") }));
  const calls = get.mock.calls.length;
  fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-11-20" } });
  expect((await screen.findByRole("alert")).textContent).toBe("The From date is after the To date. Change one of them to see calls.");
  expect(get.mock.calls.length).toBe(calls);
  expect(screen.queryByRole("link", { name: "Download CSV" })).toBeNull();
});

it("offers the CSV as a normal link that carries the same filters", async () => {
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click");
  show();
  await screen.findByText("list_invoices");
  const link = () => screen.getByRole("link", { name: "Download CSV" }) as HTMLAnchorElement;
  expect(link().getAttribute("href")).toBe("/api/v1/organizations/org/agents/agent/mcp-tool-activity/export");
  expect(link().hasAttribute("download")).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Denied calls" }));
  fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-11-20" } });
  await waitFor(() => expect(link().getAttribute("href")).toBe(`/api/v1/organizations/org/agents/agent/mcp-tool-activity/export?decision=deny&from=${encodeURIComponent(startOf("2026-11-20"))}`));
  expect(mcpActivityExportHref("org", "agent", { show: "approved", from: "", to: "", server: "crm" })).toBe("/api/v1/organizations/org/agents/agent/mcp-tool-activity/export?approved=true&server=crm");
  // Nothing starts the download from script.
  expect(click).not.toHaveBeenCalled();
  click.mockRestore();
});

it("says there are no MCP calls yet, and separately that no call matches the filters", async () => {
  get.mockResolvedValue({ data: { items: [], next_cursor: null } });
  show();
  expect(await screen.findByText("No MCP calls yet.")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Approved calls" }));
  expect(await screen.findByText("No calls match these filters.")).toBeTruthy();
  expect(screen.queryByText("No MCP calls yet.")).toBeNull();
});

it("loads older calls on request and keeps the ones already shown", async () => {
  get.mockResolvedValueOnce({ data: { items: [call({})], next_cursor: "older" } });
  get.mockResolvedValueOnce({ data: { items: [call({ id: "act-9", tool_name: "close_books" })], next_cursor: null } });
  show();
  fireEvent.click(await screen.findByRole("button", { name: "Show older calls" }));
  await waitFor(() => expect(get).toHaveBeenLastCalledWith(path, { params: { path: { orgId: "org", deviceId: "agent" }, query: { limit: 50, cursor: "older" } } }));
  expect(await screen.findByText("close_books")).toBeTruthy();
  expect(screen.getByText("list_invoices")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Show older calls" })).toBeNull();
});

it("never shows a failed load as an empty list", async () => {
  get.mockResolvedValueOnce({ error: { error: { code: "permission_denied", message: "You cannot view this agent's activity." } } });
  show();
  expect((await screen.findByRole("alert")).textContent).toBe("MCP calls could not be loaded: You cannot view this agent's activity.");
  expect(screen.queryByText("No MCP calls yet.")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Retry MCP calls" }));
  expect(await screen.findByText("list_invoices")).toBeTruthy();
});
