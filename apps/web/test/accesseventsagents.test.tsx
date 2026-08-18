import { createElement, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

let currentOrg = { id: "org-a", name: "Organization A" };

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: currentOrg }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string }; query?: { src_agent_id?: string } } }) => {
  const orgId = request?.params?.path?.orgId ?? currentOrg.id;
  if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
  if (path.endsWith("/agents")) return { data: orgId === "org-a" ? [{ device_id: "agent-a", name: "build-agent", gateway_name: "gw-a", status: "active" }] : [] };
  if (path.endsWith("/access-log/health")) return { data: { retention_dropped: 0, retention_failed: false } };
  if (path.endsWith("/access-events")) return { data: orgId === "org-a" ? [{
    id: "event-a", created_at: "2026-08-16T00:00:00Z", seq: 1, occurred_at: "2026-08-16T00:00:00Z",
    decision: "deny", decision_reason: "no_matching_grant", src_agent_id: "agent-a", src_ip: "10.99.0.9",
    dst_ip: "10.0.0.8", protocol: "tcp", policy_hash: "abcdef123456", policy_version: 7, src_config_revision: 4,
  }] : [] };
  return { data: [] };
}) }, apiErrorMessage: () => "error" }));
vi.mock("../src/components/ui", () => ({
  // Mocked to an h1 so the route's heading stays assertable — spreading `title` onto a DOM node would
  // drop the text out of the tree entirely.
  PageHeader: ({ title, subtitle }: { title: string; subtitle?: ReactNode }) =>
    createElement("header", null, createElement("h1", null, title), subtitle ?? null),
  Button: ({ children, ...props }: { children?: ReactNode; [key: string]: unknown }) => createElement("button", props, children),
  Card: ({ children, ...props }: { children?: ReactNode; [key: string]: unknown }) => createElement("section", props, children),
  ErrorText: ({ children }: { children?: ReactNode }) => createElement("span", null, children),
  DataTable: ({ rows, columns }: { rows: Array<Record<string, unknown>>; columns: Array<{ key: string; header: string; cell?: (row: Record<string, unknown>) => ReactNode }> }) => createElement("div", null,
    ...columns.map((c) => createElement("span", { key: c.key }, c.header)),
    ...rows.flatMap((row) => columns.map((c) => createElement("div", { key: String(row.id) + c.key }, c.cell?.(row)))),
  ),
}));

import AccessEvents from "../src/pages/AccessEvents";
import { api } from "../src/lib/api";

afterEach(() => { cleanup(); vi.mocked(api.GET).mockClear(); currentOrg = { id: "org-a", name: "Organization A" }; });

describe("released access-event agent attribution", () => {
  it("filters server-side, renders applied facts, and clears them synchronously on org switch", async () => {
    const view = render(<AccessEvents />);
    expect(await screen.findByText("build-agent (current name) · 10.99.0.9")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "agent-a" } });
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[string, { params?: { query?: { src_agent_id?: string } } }]>;
      expect(calls.some(([, req]) => req?.params?.query?.src_agent_id === "agent-a")).toBe(true);
    });
    fireEvent.click(screen.getByRole("button", { name: "View" }));
    expect(screen.getByText("Gateway not recorded · applied policy v7 · abcdef123456")).toBeTruthy();
    expect(screen.getByText("Source agent agent-a · configuration revision 4")).toBeTruthy();

    currentOrg = { id: "org-b", name: "Organization B" };
    view.rerender(<AccessEvents />);
    expect(screen.queryByText("build-agent (current name) · 10.99.0.9")).toBeNull();
    expect(screen.queryByText("Gateway not recorded · applied policy v7 · abcdef123456")).toBeNull();
  });
});
