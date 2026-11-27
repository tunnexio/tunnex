import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Acme" } }) }));

import Approvals, { APPROVALS_REFRESH_MS } from "../src/pages/Approvals";
import { MCP_APPROVAL_COUNT_CHANGED, MCP_APPROVAL_COUNT_REFRESH_MS, useMCPApprovalCount } from "../src/lib/useMCPApprovalCount";
import { NAV_PERMISSIONS } from "../src/lib/navaccess";
import { NAV_GROUPS } from "../src/components/AppShell";
import { can } from "../src/lib/rbac";

const NOW = new Date("2026-11-27T10:00:00Z").getTime();
const listPath = "/api/v1/organizations/{orgId}/mcp-tool-approval-requests";
const denyPath = "/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/deny";
const approvePath = "/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/approve";
const item = (over: Record<string, unknown> = {}, request: Record<string, unknown> = {}) => ({
  agent_name: "billing-runner", owner_email: "dana@example.test", mcp_server_name: "billing-tools",
  request: { id: "req-1", device_id: "device-1", policy_version: 3, endpoint: "http://10.0.0.5:8080/mcp", server_name: "billing", tool_name: "refund_payment", input_schema_hash: "h", state: "pending", requested_at: "2026-11-27T09:59:00Z", expires_at: "2026-11-27T10:04:10Z", arguments: { customer: "cus_42", amount: 120 }, arguments_truncated: false, ...request },
  ...over,
});
let items: Array<Record<string, unknown>> = [];
const show = () => render(<MemoryRouter><Approvals /></MemoryRouter>);
const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });

beforeEach(() => {
  vi.useFakeTimers({ now: NOW });
  vi.spyOn(window, "confirm").mockImplementation(() => { throw new Error("the page must not use window.confirm"); });
  vi.spyOn(window, "alert").mockImplementation(() => { throw new Error("the page must not use window.alert"); });
  items = [item()];
  get.mockImplementation(async (path: string) => path === listPath ? { data: { items, next_cursor: null } } : { data: { pending: items.length } });
  post.mockResolvedValue({ data: { id: "req-1", state: "denied" } });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); get.mockReset(); post.mockReset(); });

describe("Approvals inbox", () => {
  it("says nothing is waiting when the inbox is empty, and that it keeps checking", async () => {
    items = [];
    show(); await flush();
    expect(screen.getByRole("heading", { name: "Nothing is waiting for a decision" })).toBeTruthy();
    expect(screen.getByText(/This page checks for new ones every few seconds\./)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve once" })).toBeNull();
    expect(get).toHaveBeenCalledWith(listPath, { params: { path: { orgId: "org-a" }, query: { state: "pending", limit: 50 } } });
  });

  it("does not show a failed read as an empty inbox", async () => {
    get.mockResolvedValue({ error: { error: { code: "agent_ux_not_implemented", message: "Not available yet." } } });
    show(); await flush();
    expect(screen.getByRole("alert").textContent).toBe("Approvals could not be loaded: Not available yet.");
    expect(screen.queryByText("Nothing is waiting for a decision")).toBeNull();
  });

  it("shows a waiting call: agent, tool, server, arguments, the agent's owner and the time left", async () => {
    show(); await flush();
    const row = within(screen.getByRole("listitem", { name: "refund_payment on billing-tools, from billing-runner" }));
    expect(row.getByRole("link", { name: "billing-runner" }).getAttribute("href")).toBe("/agents/device-1?tab=mcp");
    expect(row.getByText("dana@example.test")).toBeTruthy();
    expect(row.getByText("4 min 10 s left")).toBeTruthy();
    const args = within(row.getByRole("group", { name: "Arguments" }));
    expect(args.getByText("customer").nextElementSibling?.textContent).toBe("cus_42");
    expect(args.getByText("amount").nextElementSibling?.textContent).toBe("120");
    expect(row.getByRole("button", { name: "Approve once" })).toBeTruthy();
    expect(row.getByRole("button", { name: "Deny" })).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(row.getByText("4 min 9 s left")).toBeTruthy();
  });

  it("says so when an agent has no owner", async () => {
    items = [item({ owner_email: null })];
    show(); await flush();
    expect(screen.getByText("No owner")).toBeTruthy();
  });

  it("picks up a new request without a page refresh", async () => {
    items = [];
    show(); await flush();
    items = [item()];
    await act(async () => { await vi.advanceTimersByTimeAsync(APPROVALS_REFRESH_MS); });
    expect(screen.getByRole("listitem", { name: /refund_payment on billing-tools/ })).toBeTruthy();
  });

  it("approves once after showing the arguments again, through the agent's own endpoint", async () => {
    post.mockResolvedValue({ data: { id: "req-1", state: "approved" } });
    show(); await flush();
    fireEvent.click(screen.getByRole("button", { name: "Approve once" }));
    const dialog = within(screen.getByRole("dialog", { name: "Approve refund_payment once?" }));
    expect(dialog.getByText("cus_42")).toBeTruthy();
    expect(post).not.toHaveBeenCalled();
    items = [];
    fireEvent.click(dialog.getByRole("button", { name: "Approve once" }));
    await flush();
    expect(post).toHaveBeenCalledWith(approvePath, { params: { path: { orgId: "org-a", deviceId: "device-1", requestId: "req-1" } } });
    expect(screen.getByText("Approved. billing-runner can run refund_payment once.")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("denies only after an in-page confirmation, and never with a browser dialog", async () => {
    show(); await flush();
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(post).not.toHaveBeenCalled();
    expect(screen.getByText("Deny this call? The agent is told no and has to ask again.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Keep waiting" }));
    expect(post).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Approve once" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    items = [];
    fireEvent.click(screen.getByRole("button", { name: "Deny call" }));
    await flush();
    expect(post).toHaveBeenCalledWith(denyPath, { params: { path: { orgId: "org-a", deviceId: "device-1", requestId: "req-1" } } });
    expect(screen.getByText("Denied. billing-runner was told no.")).toBeTruthy();
    expect(window.confirm).not.toHaveBeenCalled();
  });

  it.each([["deny", "Deny call"], ["approve", "Approve once"]])("says a request was already handled when someone else decided first (%s), and refreshes the list", async (kind, action) => {
    post.mockResolvedValue({ error: { error: { code: "mcp_tool_approval_not_pending", message: "not pending" } } });
    show(); await flush();
    fireEvent.click(screen.getByRole("button", { name: kind === "deny" ? "Deny" : "Approve once" }));
    items = [];
    const scope = kind === "deny" ? screen : within(screen.getByRole("dialog"));
    fireEvent.click(scope.getByRole("button", { name: action }));
    await flush();
    expect(screen.getByText("This request was already handled. The list is now up to date.")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { name: "Nothing is waiting for a decision" })).toBeTruthy();
  });

  it("keeps a failed denial open with what went wrong", async () => {
    post.mockResolvedValue({ error: { error: { code: "internal", message: "Something went wrong." } } });
    show(); await flush();
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    fireEvent.click(screen.getByRole("button", { name: "Deny call" }));
    await flush();
    expect(screen.getByRole("alert").textContent).toBe("Something went wrong.");
    expect(screen.getByRole("button", { name: "Deny call" })).toBeTruthy();
  });

  it("can also show recent requests with what happened to them", async () => {
    show(); await flush();
    items = [item(), item({}, { id: "req-0", tool_name: "list_invoices", state: "denied" })];
    fireEvent.click(screen.getByRole("button", { name: "Waiting and recent" }));
    await flush();
    expect(get).toHaveBeenLastCalledWith(listPath, { params: { path: { orgId: "org-a" }, query: { state: "all", limit: 50 } } });
    const recent = within(screen.getByRole("list", { name: "Recent requests" }));
    expect(recent.getByText("list_invoices")).toBeTruthy();
    expect(recent.getByText(/Denied/)).toBeTruthy();
    expect(within(screen.getByRole("list", { name: "Waiting for a decision" })).getAllByRole("listitem")).toHaveLength(1);
  });
});

describe("Approvals in the sidebar", () => {
  function Count({ enabled }: { enabled: boolean }) { const count = useMCPApprovalCount(enabled); return <output>{count.state === "ok" ? count.value : count.state}</output>; }

  it("has an entry in the AI group that only people who can approve are offered", () => {
    expect(NAV_GROUPS.find((group) => group.group === "AI")?.items.find((entry) => entry.to === "/approvals")?.label).toBe("Approvals");
    expect(NAV_PERMISSIONS["/approvals"]).toEqual(["agent_mcp_tool_approval:approve"]);
    expect(can("owner", "agent_mcp_tool_approval:approve")).toBe(true);
    expect(can("member", "agent_mcp_tool_approval:approve")).toBe(false);
    expect(NAV_PERMISSIONS["/mcp"]).toContain("mcp:manage");
  });

  it("reads the pending count, refreshes it, and re-reads at once when a decision is made", async () => {
    items = [item(), item({}, { id: "req-2" })];
    render(<Count enabled />); await flush();
    expect(get).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/mcp-tool-approval-requests/count", { params: { path: { orgId: "org-a" } } });
    expect(screen.getByRole("status").textContent).toBe("2");
    items = [item()];
    await act(async () => { await vi.advanceTimersByTimeAsync(MCP_APPROVAL_COUNT_REFRESH_MS); });
    expect(screen.getByRole("status").textContent).toBe("1");
    items = [];
    await act(async () => { window.dispatchEvent(new Event(MCP_APPROVAL_COUNT_CHANGED)); await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByRole("status").textContent).toBe("0");
  });

  it("never turns a failed count into a number, and asks nothing for a person who cannot approve", async () => {
    get.mockResolvedValue({ error: { error: { code: "unavailable" } } });
    const view = render(<Count enabled />); await flush();
    expect(screen.getByRole("status").textContent).toBe("failed");
    view.unmount(); get.mockClear();
    render(<Count enabled={false} />); await flush();
    expect(get).not.toHaveBeenCalled();
    expect(screen.getByRole("status").textContent).toBe("loading");
  });
});
