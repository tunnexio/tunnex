import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get } };
});

import { AgentMCPToolActivityPanel } from "../src/components/AgentMCPControls";

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

it("filters to the calls that ran on an approval", async () => {
  show();
  await screen.findByText("list_invoices");
  const all = screen.getByRole("button", { name: "All calls" }), approved = screen.getByRole("button", { name: "Approved calls" });
  expect(all.getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(approved);
  expect(approved.getAttribute("aria-pressed")).toBe("true");
  expect(screen.getByText("refund_payment")).toBeTruthy();
  expect(screen.queryByText("list_invoices")).toBeNull();
  expect(screen.queryByText("run_sql")).toBeNull();
  fireEvent.click(all);
  expect(screen.getByText("list_invoices")).toBeTruthy();
});

it("says there are no MCP calls yet, and separately that none of them needed approval", async () => {
  get.mockResolvedValue({ data: { items: [], next_cursor: null } });
  show();
  expect(await screen.findByText("No MCP calls yet.")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  cleanup();
  get.mockResolvedValue({ data: { items: [call({})], next_cursor: null } });
  show();
  await screen.findByText("list_invoices");
  fireEvent.click(screen.getByRole("button", { name: "Approved calls" }));
  expect(screen.getByText("None of the calls shown ran on an approval.")).toBeTruthy();
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
