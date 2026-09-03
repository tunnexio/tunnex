import { createElement, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

type TestOrg = { id: string; name: string };

let currentOrg: TestOrg | null = { id: "org-a", name: "Organization A" };
let orgLoading = false;
let orgFailed = false;
let eventMode: "success" | "error" | "reject" = "success";
let eventRows: Array<Record<string, unknown>> | null = null;
let healthMode: "success" | "error" | "reject" = "success";
let healthResponse: Record<string, unknown> = {
  retention_dropped: 0,
  retention_failed: false,
  gateway_collectors: [],
};

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: currentOrg, loading: orgLoading, failed: orgFailed }),
}));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string }; query?: { src_agent_id?: string } } }) => {
  const orgId = request?.params?.path?.orgId ?? currentOrg?.id ?? "";
  if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
  if (path.endsWith("/agents")) return { data: orgId === "org-a" ? [{ device_id: "agent-a", name: "build-agent", gateway_name: "gw-a", status: "active" }] : [] };
  if (path.endsWith("/access-log/health")) {
    if (healthMode === "reject") throw new Error("offline");
    if (healthMode === "error") return { error: { error: { message: "Health unavailable" } } };
    return { data: healthResponse };
  }
  if (path.endsWith("/access-events")) {
    if (eventMode === "reject") throw new Error("offline");
    if (eventMode === "error") return { error: { error: { message: "Event query failed" } } };
    if (eventRows) return { data: eventRows };
    return { data: orgId === "org-a" ? [{
    id: "event-a", created_at: "2026-08-16T00:00:00Z", seq: 1, occurred_at: "2026-08-16T00:00:00Z",
    decision: "deny", decision_reason: "no_matching_grant", src_agent_id: "agent-a", src_ip: "10.99.0.9",
    dst_ip: "10.0.0.8", protocol: "tcp", policy_hash: "abcdef123456", policy_version: 7, src_config_revision: 4,
    }] : [] };
  }
  return { data: [] };
}) } };
});
vi.mock("../src/components/ui", () => ({
  // Mocked to an h1 so the route's heading stays assertable — spreading `title` onto a DOM node would
  // drop the text out of the tree entirely.
  PageHeader: ({ title, subtitle }: { title: string; subtitle?: ReactNode }) =>
    createElement("header", null, createElement("h1", null, title), subtitle ?? null),
  Button: ({ children, ...props }: { children?: ReactNode; [key: string]: unknown }) => createElement("button", props, children),
  Card: ({ children, ...props }: { children?: ReactNode; [key: string]: unknown }) => createElement("section", props, children),
  EmptyState: ({ children }: { children?: ReactNode }) => createElement("div", null, children),
  ErrorText: ({ children }: { children?: ReactNode }) => createElement("span", null, children),
  Loading: ({ label }: { label?: string }) => createElement("div", { role: "status" }, label ?? "Loading…"),
  Modal: ({ title, children, onDismiss }: { title: string; children?: ReactNode; onDismiss: () => void }) =>
    createElement("div", { role: "dialog", "aria-label": title }, children, createElement("button", { onClick: onDismiss }, "Close")),
  DataTable: ({ rows, columns, empty, failed }: {
    rows: Array<Record<string, unknown>>;
    columns: Array<{
      key: string;
      header: string;
      cell?: (row: Record<string, unknown>) => ReactNode;
    }>;
    empty?: ReactNode;
    failed?: boolean;
  }) => failed ? null : createElement("div", null,
    ...columns.map((c) => createElement("span", { key: c.key }, c.header)),
    ...(rows.length === 0 ? [createElement("div", { key: "empty" }, empty)] : rows.flatMap((row) => columns.map((c) => createElement("div", { key: String(row.id) + c.key }, c.cell?.(row))))),
  ),
}));

import AccessEvents from "../src/pages/AccessEvents";
import { api } from "../src/lib/api";

afterEach(() => {
  cleanup();
  vi.mocked(api.GET).mockClear();
  currentOrg = { id: "org-a", name: "Organization A" };
  orgLoading = false;
  orgFailed = false;
  eventMode = "success";
  eventRows = null;
  healthMode = "success";
  healthResponse = {
    retention_dropped: 0,
    retention_failed: false,
    gateway_collectors: [],
  };
});

describe("released access-event agent attribution", () => {
  it("filters server-side, renders applied facts, and clears them synchronously on org switch", async () => {
    const view = render(<AccessEvents />);
    expect(await screen.findByText("build-agent (current name) · 10.99.0.9")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "agent-a" } });
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[string, { params?: { query?: { src_agent_id?: string } } }]>;
      expect(calls.some(([, req]) => req?.params?.query?.src_agent_id === "agent-a")).toBe(true);
    });
    fireEvent.click(screen.getByRole("button", { name: "View DENY event details" }));
    expect(screen.getByRole("dialog", { name: "Access event" })).toBeTruthy();
    expect(screen.getByText("Gateway not recorded · applied policy v7 · abcdef123456")).toBeTruthy();
    expect(screen.getByText("Source agent agent-a · configuration revision 4")).toBeTruthy();

    currentOrg = { id: "org-b", name: "Organization B" };
    view.rerender(<AccessEvents />);
    expect(screen.queryByText("build-agent (current name) · 10.99.0.9")).toBeNull();
    expect(screen.queryByText("Gateway not recorded · applied policy v7 · abcdef123456")).toBeNull();
  });

  it("keeps organization loading distinct from having no organization", async () => {
    currentOrg = null;
    orgLoading = true;
    const view = render(<AccessEvents />);

    expect(screen.getByRole("status").textContent).toMatch(/loading access events/i);
    expect(screen.queryByText(/not a member of any organization/i)).toBeNull();

    orgLoading = false;
    currentOrg = { id: "org-a", name: "Organization A" };
    view.rerender(<AccessEvents />);
    expect(await screen.findByText("build-agent (current name) · 10.99.0.9")).toBeTruthy();
  });

  it("turns a rejected event request into a retryable failure, never an empty feed", async () => {
    eventMode = "reject";
    render(<AccessEvents />);

    expect(await screen.findByText(/could not reach the api/i)).toBeTruthy();
    expect(screen.queryByText(/no access events/i)).toBeNull();

    eventMode = "success";
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("build-agent (current name) · 10.99.0.9")).toBeTruthy();
  });

  it("surfaces collector truth and never invents a successful retention sweep", async () => {
    eventRows = [];
    healthResponse = {
      retention_dropped: 0,
      retention_failed: false,
      gateway_collectors: [
        {
          node_id: "gateway-off",
          name: "edge-off",
          state: "disabled",
          last_reported_at: "2026-09-03T00:00:00Z",
          last_observed_at: "2026-09-03T00:01:00Z",
          last_delivered_at: "2026-09-03T00:02:00Z",
          last_event_at: "2026-09-03T00:03:00Z",
        },
      ],
    };
    render(<AccessEvents />);

    expect(await screen.findByText("edge-off")).toBeTruthy();
    expect(screen.getByText("Disabled")).toBeTruthy();
    expect(screen.getByText("Observed:")).toBeTruthy();
    expect(screen.getByText("Delivered:")).toBeTruthy();
    expect(screen.getByText("Retained:")).toBeTruthy();
    expect(screen.getByText(/collection is disabled on every gateway/i)).toBeTruthy();
    expect(screen.getByText(/retention pruning has not run yet/i)).toBeTruthy();
    expect(screen.queryByText(/last sweep dropped 0/i)).toBeNull();
  });

  it("labels a genuinely empty feed as uncertain when collector health rejects", async () => {
    eventRows = [];
    healthMode = "reject";
    render(<AccessEvents />);

    expect(await screen.findByText(/gateway collector status is unavailable/i)).toBeTruthy();
    expect(screen.getByText(/could not reach the api/i)).toBeTruthy();
  });
});
