import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", () => ({
  api: { GET: get, POST: post },
  loadOne: async (fn: () => Promise<{ data?: unknown; error?: unknown }>) => {
    const result = await fn();
    return result.error ? { ok: false, error: "Unavailable" } : { ok: true, data: result.data };
  },
  apiErrorMessage: (_: unknown, fallback: string) => fallback,
  apiErrorCode: (value: { error?: { code?: string } } | undefined) => value?.error?.code,
}));

import { MemoryRouter } from "react-router-dom";
import { AgentMCPToolApprovalPanel } from "../src/components/AgentMCPControls";

const NOW = new Date("2026-11-27T10:00:00Z").getTime();
const request = (over: Record<string, unknown>) => ({
  id: "req-1", device_id: "agent", policy_version: 3, endpoint: "http://10.0.0.5:8080/mcp", server_name: "billing", tool_name: "refund_payment",
  input_schema_hash: "h", state: "pending", requested_at: "2026-11-27T09:59:00Z", expires_at: "2026-11-27T10:04:10Z",
  arguments: { customer: "cus_42", amount: 120, notify: true, note: { reason: "duplicate" } }, arguments_truncated: false, ...over,
});
const show = () => render(<MemoryRouter><AgentMCPToolApprovalPanel orgId="org" deviceId="agent" canApprove /></MemoryRouter>);
const denyPath = "/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/deny";

let requests: Array<Record<string, unknown>> = [];
beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(NOW);
  vi.spyOn(window, "confirm").mockImplementation(() => { throw new Error("the page must not use window.confirm"); });
  requests = [request({})];
  get.mockImplementation(async () => ({ data: requests }));
  post.mockResolvedValue({ data: request({ state: "denied" }) });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); get.mockReset(); post.mockReset(); });

it("shows what a waiting request will do: tool, server, each argument and the time left", async () => {
  show();
  const item = await screen.findByRole("listitem", { name: "refund_payment on billing" });
  const args = within(within(item).getByRole("group", { name: "Arguments" }));
  expect(args.getByText("customer").nextElementSibling?.textContent).toBe("cus_42");
  expect(args.getByText("amount").nextElementSibling?.textContent).toBe("120");
  expect(args.getByText("notify").nextElementSibling?.textContent).toBe("true");
  expect(args.getByText("note").nextElementSibling?.textContent).toBe('{"reason":"duplicate"}');
  expect(within(item).getByText("4 min 10 s left")).toBeTruthy();
  expect(within(item).getByRole("button", { name: "Approve once" })).toBeTruthy();
  expect(within(item).getByRole("button", { name: "Deny" })).toBeTruthy();
  expect(screen.queryByText(/never shown/i)).toBeNull();
});

it("says when the arguments were shortened, and when none were kept", async () => {
  requests = [request({ arguments: null, arguments_truncated: true }), request({ id: "req-2", tool_name: "list_invoices", arguments: null }), request({ id: "req-3", tool_name: "ping", arguments: {} })];
  show();
  const shortened = await screen.findByRole("listitem", { name: "refund_payment on billing" });
  expect(within(shortened).getByText("Shortened: the arguments were too long to show in full. Deny the call if you are not sure what it will do.")).toBeTruthy();
  expect(within(screen.getByRole("listitem", { name: "list_invoices on billing" })).getByText("The arguments were not kept for this request.")).toBeTruthy();
  expect(within(screen.getByRole("listitem", { name: "ping on billing" })).getByText("This call has no arguments.")).toBeTruthy();
});

it("shows the arguments again in the approval dialog", async () => {
  show();
  fireEvent.click(await screen.findByRole("button", { name: "Approve once" }));
  const dialog = within(screen.getByRole("dialog", { name: "Approve refund_payment once?" }));
  expect(dialog.getByText("cus_42")).toBeTruthy();
  post.mockResolvedValue({ data: request({ state: "approved" }) });
  fireEvent.click(dialog.getByRole("button", { name: "Approve once" }));
  await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/approve", { params: { path: { orgId: "org", deviceId: "agent", requestId: "req-1" } } }));
});

it("denies only after an in-page confirmation and then reloads the list", async () => {
  show();
  fireEvent.click(await screen.findByRole("button", { name: "Deny" }));
  expect(post).not.toHaveBeenCalled();
  expect(screen.getByText("Deny this call? The agent is told no and has to ask again.")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Keep waiting" }));
  expect(screen.queryByRole("button", { name: "Deny call" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Deny" }));
  requests = [request({ state: "denied" })];
  fireEvent.click(screen.getByRole("button", { name: "Deny call" }));
  await waitFor(() => expect(post).toHaveBeenCalledWith(denyPath, { params: { path: { orgId: "org", deviceId: "agent", requestId: "req-1" } } }));
  expect(await screen.findByText("Denied")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Deny" })).toBeNull();
  expect(get).toHaveBeenCalledTimes(2);
});

it("refreshes and says the request was already handled when someone else got there first", async () => {
  show();
  fireEvent.click(await screen.findByRole("button", { name: "Deny" }));
  post.mockResolvedValue({ error: { error: { code: "mcp_tool_approval_not_pending", message: "not pending" } } });
  requests = [request({ state: "approved" })];
  fireEvent.click(screen.getByRole("button", { name: "Deny call" }));
  expect(await screen.findByText("This request was already handled. The list is now up to date.")).toBeTruthy();
  await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
  expect(await screen.findByText("Approved, not used yet")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Deny call" })).toBeNull();
});

it("keeps the request and explains when a denial fails for another reason", async () => {
  show();
  fireEvent.click(await screen.findByRole("button", { name: "Deny" }));
  post.mockResolvedValue({ error: { error: { code: "internal", message: "boom" } } });
  fireEvent.click(screen.getByRole("button", { name: "Deny call" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Could not deny this request. Refresh and try again.");
  expect(screen.getByRole("button", { name: "Deny call" })).toBeTruthy();
});

it("lists earlier requests with their outcome and no actions", async () => {
  requests = [
    request({ id: "a", tool_name: "t_approved", state: "approved" }), request({ id: "b", tool_name: "t_denied", state: "denied" }),
    request({ id: "c", tool_name: "t_expired", state: "expired" }), request({ id: "d", tool_name: "t_used", state: "consumed" }),
  ];
  show();
  const earlier = within(await screen.findByRole("list", { name: "Earlier requests" }));
  const outcome = (name: string) => within(earlier.getByRole("listitem", { name: `${name} on billing` }));
  expect(outcome("t_approved").getByText("Approved, not used yet")).toBeTruthy();
  expect(outcome("t_denied").getByText("Denied")).toBeTruthy();
  expect(outcome("t_expired").getByText("Expired")).toBeTruthy();
  expect(outcome("t_used").getByText("Used")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Approve once" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Deny" })).toBeNull();
  expect(screen.getByText("Nothing is waiting for a decision.")).toBeTruthy();
});
