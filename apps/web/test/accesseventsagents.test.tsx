import { createElement, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

type TestOrg = { id: string; name: string };

let currentOrg: TestOrg | null = { id: "org-a", name: "Organization A" };
let orgLoading = false;
let orgFailed = false;
let eventMode: "success" | "error" | "reject" = "success";
let eventRows: Array<Record<string, unknown>> | null = null;
let memberRows: Array<Record<string, unknown>> = [{
  user_id: "user-a",
  email: "alice@example.com",
  name: "Alice",
  role: "member",
  status: "active",
  email_verified: true,
  joined_at: "2026-01-01T00:00:00Z",
}];
let deviceRows: Array<Record<string, unknown>> = [{
  id: "device-a",
  user_id: "user-a",
  node_id: "gateway-a",
  name: "Alice laptop",
  kind: "human",
  public_key: "pubkey",
  full_tunnel: false,
  assigned_ip: "10.99.0.20",
  status: "active",
  created_at: "2026-01-01T00:00:00Z",
}];
let agentRows: Array<Record<string, unknown>> = [{
  device_id: "agent-a",
  name: "build-agent",
  gateway_name: "gw-a",
  status: "active",
}];
let laterAgentRows: Array<Record<string, unknown>> = [];
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
  return { ...actual, api: { GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string }; query?: {
    cursor?: string;
    src_agent_id?: string;
    src_device_id?: string;
    src_user_id?: string;
  } } }) => {
  const orgId = request?.params?.path?.orgId ?? currentOrg?.id ?? "";
  if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
  if (path.endsWith("/members")) return { data: orgId === "org-a" ? memberRows : [] };
  if (path.endsWith("/devices")) return { data: orgId === "org-a" ? deviceRows : [] };
  if (path.endsWith("/agents")) {
    const cursor = request?.params?.query?.cursor;
    return { data: {
      items: orgId !== "org-a" ? [] : cursor === "agents-next" ? laterAgentRows : agentRows,
      next_cursor: orgId === "org-a" && !cursor && laterAgentRows.length > 0
        ? "agents-next"
        : null,
    } };
  }
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
    decision: "deny", decision_reason: "no_matching_grant", src_agent_id: "agent-a", src_device_id: "agent-a",
    src_user_id: "user-a", src_kind: "agent", src_ip: "10.99.0.9",
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
  memberRows = [{
    user_id: "user-a",
    email: "alice@example.com",
    name: "Alice",
    role: "member",
    status: "active",
    email_verified: true,
    joined_at: "2026-01-01T00:00:00Z",
  }];
  deviceRows = [{
    id: "device-a",
    user_id: "user-a",
    node_id: "gateway-a",
    name: "Alice laptop",
    kind: "human",
    public_key: "pubkey",
    full_tunnel: false,
    assigned_ip: "10.99.0.20",
    status: "active",
    created_at: "2026-01-01T00:00:00Z",
  }];
  agentRows = [{
    device_id: "agent-a",
    name: "build-agent",
    gateway_name: "gw-a",
    status: "active",
  }];
  laterAgentRows = [];
  healthMode = "success";
  healthResponse = {
    retention_dropped: 0,
    retention_failed: false,
    gateway_collectors: [],
  };
});

describe("released access-event identity attribution", () => {
  it("filters server-side, renders applied facts, and clears them synchronously on org switch", async () => {
    const view = render(<AccessEvents />);
    const attributedSource = "build-agent (current agent name) · recorded person Alice · alice@example.com (current member label) · 10.99.0.9";
    expect(await screen.findByText(attributedSource)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Source identity"), {
      target: { value: "agent:agent-a" },
    });
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[string, { params?: { query?: { src_agent_id?: string } } }]>;
      expect(calls.some(([, req]) => req?.params?.query?.src_agent_id === "agent-a")).toBe(true);
    });
    fireEvent.click(screen.getByRole("button", { name: "View DENY event details" }));
    expect(screen.getByRole("dialog", { name: "Access event" })).toBeTruthy();
    expect(screen.getByText("Gateway not recorded · applied policy v7 · abcdef123456")).toBeTruthy();
    expect(screen.getByText("Source AI agent agent-a · recorded person user-a · configuration revision 4")).toBeTruthy();
    expect(screen.getByText(/device-owner accountability at ingest/i)).toBeTruthy();

    currentOrg = { id: "org-b", name: "Organization B" };
    view.rerender(<AccessEvents />);
    expect(screen.queryByText(attributedSource)).toBeNull();
    expect(screen.queryByText("Gateway not recorded · applied policy v7 · abcdef123456")).toBeNull();
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
        string,
        { params?: { path?: { orgId?: string }; query?: Record<string, unknown> } },
      ]>;
      const query = calls.find(([path, request]) =>
        path.endsWith("/access-events") && request?.params?.path?.orgId === "org-b"
      )?.[1].params?.query;
      expect(query).toBeTruthy();
      expect(query?.src_user_id).toBeUndefined();
      expect(query?.src_device_id).toBeUndefined();
      expect(query?.src_agent_id).toBeUndefined();
    });
  });

  it("groups current people, human devices, and AI agents and maps each to one server filter", async () => {
    const view = render(<AccessEvents />);

    expect(await screen.findByRole("option", {
      name: "Alice · alice@example.com (current member label) · user-a",
    })).toBeTruthy();
    expect(screen.getByRole("option", {
      name: "Alice laptop (current device name) · device-a",
    })).toBeTruthy();
    expect(screen.getByRole("option", {
      name: "build-agent (current agent name) · agent-a",
    })).toBeTruthy();
    expect(
      [...view.container.querySelectorAll("optgroup")].map((group) => group.label),
    ).toEqual(["People", "Devices", "AI agents"]);

    fireEvent.change(screen.getByLabelText("Source identity"), {
      target: { value: "person:user-a" },
    });
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
        string,
        { params?: { query?: Record<string, unknown> } },
      ]>;
      const query = calls.find(([, request]) =>
        request?.params?.query?.src_user_id === "user-a"
      )?.[1].params?.query;
      expect(query).toBeTruthy();
      expect(query?.src_device_id).toBeUndefined();
      expect(query?.src_agent_id).toBeUndefined();
    });

    fireEvent.change(await screen.findByLabelText("Source identity"), {
      target: { value: "device:device-a" },
    });
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
        string,
        { params?: { query?: Record<string, unknown> } },
      ]>;
      const query = calls.find(([, request]) =>
        request?.params?.query?.src_device_id === "device-a"
      )?.[1].params?.query;
      expect(query).toBeTruthy();
      expect(query?.src_user_id).toBeUndefined();
      expect(query?.src_agent_id).toBeUndefined();
    });

    fireEvent.change(await screen.findByLabelText("Source identity"), {
      target: { value: "agent:agent-a" },
    });
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
        string,
        { params?: { query?: Record<string, unknown> } },
      ]>;
      const query = calls.find(([, request]) =>
        request?.params?.query?.src_agent_id === "agent-a"
      )?.[1].params?.query;
      expect(query).toBeTruthy();
      expect(query?.src_user_id).toBeUndefined();
      expect(query?.src_device_id).toBeUndefined();
    });
  });

  it("loads every current AI-agent page before building the selector", async () => {
    laterAgentRows = [{
      device_id: "agent-b",
      name: "deploy-agent",
      gateway_name: "gw-b",
      status: "active",
    }];

    render(<AccessEvents />);

    expect(await screen.findByRole("option", {
      name: "deploy-agent (current agent name) · agent-b",
    })).toBeTruthy();
    const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
      string,
      { params?: { query?: { cursor?: string } } },
    ]>;
    expect(calls.some(([path, request]) =>
      path.endsWith("/agents") && request?.params?.query?.cursor === "agents-next"
    )).toBe(true);
  });

  it("filters by an explicit historical UUID even when it is absent from rosters and the first page", async () => {
    const historicalID = "019fc421-4a5b-7c6d-8e9f-0123456789ab";
    render(<AccessEvents />);

    await screen.findByLabelText("Historical identity UUID");
    fireEvent.change(screen.getByLabelText("Historical identity type"), {
      target: { value: "device" },
    });
    fireEvent.change(screen.getByLabelText("Historical identity UUID"), {
      target: { value: historicalID.toUpperCase() },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply UUID" }));

    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
        string,
        { params?: { query?: Record<string, unknown> } },
      ]>;
      const query = calls.find(([, request]) =>
        request?.params?.query?.src_device_id === historicalID
      )?.[1].params?.query;
      expect(query).toBeTruthy();
      expect(query?.src_user_id).toBeUndefined();
      expect(query?.src_agent_id).toBeUndefined();
    });
    expect(screen.getByRole("option", {
      name: `device ${historicalID} (current name unavailable)`,
    })).toBeTruthy();
  });

  it("connects an invalid historical UUID to a visible validation message", async () => {
    render(<AccessEvents />);

    const input = await screen.findByLabelText("Historical identity UUID");
    fireEvent.change(input, { target: { value: "not-a-uuid" } });

    const error = screen.getByText(/enter a complete uuid/i);
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(input.getAttribute("aria-describedby")).toBe(error.id);
    expect(error.id).toBe("historical-identity-uuid-error");
    expect((screen.getByRole("button", { name: "Apply UUID" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("describes filtered zero results without claiming the global retained feed is empty", async () => {
    render(<AccessEvents />);
    await screen.findByText(
      "build-agent (current agent name) · recorded person Alice · alice@example.com (current member label) · 10.99.0.9",
    );

    eventRows = [];
    fireEvent.click(screen.getByRole("button", { name: "Denies only" }));

    expect(await screen.findByText(
      "No retained access events match the current filters.",
    )).toBeTruthy();
    expect(screen.queryByText(/no access events are retained/i)).toBeNull();
    expect(screen.getByLabelText("Source identity")).toBeTruthy();
  });

  it("keeps focused filters mounted and clears stale results when a filtered query fails", async () => {
    render(<AccessEvents />);
    const attributedSource = "build-agent (current agent name) · recorded person Alice · alice@example.com (current member label) · 10.99.0.9";
    await screen.findByText(attributedSource);

    const sourceFilter = screen.getByLabelText("Source identity");
    sourceFilter.focus();
    eventMode = "error";
    fireEvent.change(sourceFilter, { target: { value: "person:user-a" } });

    expect(screen.queryByText(attributedSource)).toBeNull();
    expect(await screen.findByText("Event query failed")).toBeTruthy();
    expect(screen.getByLabelText("Source identity")).toBe(sourceFilter);
    expect(document.activeElement).toBe(sourceFilter);
    expect((sourceFilter as HTMLSelectElement).value).toBe("person:user-a");

    eventMode = "success";
    fireEvent.change(sourceFilter, { target: { value: "" } });
    expect(await screen.findByText(attributedSource)).toBeTruthy();
    expect((sourceFilter as HTMLSelectElement).value).toBe("");
    await waitFor(() => {
      const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[
        string,
        { params?: { query?: Record<string, unknown> } },
      ]>;
      const unfilteredCalls = calls.filter(([path, request]) =>
        path.endsWith("/access-events") &&
        request?.params?.query?.src_user_id === undefined &&
        request?.params?.query?.src_device_id === undefined &&
        request?.params?.query?.src_agent_id === undefined
      );
      expect(unfilteredCalls.length).toBeGreaterThanOrEqual(2);
    });
  });

  it("keeps deleted identities filterable from loaded event UUIDs", async () => {
    memberRows = [];
    deviceRows = [];
    agentRows = [];
    eventRows = [{
      id: "event-history",
      created_at: "2026-08-16T00:00:00Z",
      seq: 2,
      occurred_at: "2026-08-16T00:00:00Z",
      decision: "allow",
      src_device_id: "device-deleted-123456",
      src_user_id: "user-deleted-123456",
      src_kind: "human",
      src_ip: "10.99.0.30",
      dst_ip: "10.0.0.8",
      protocol: "tcp",
    }];

    render(<AccessEvents />);

    expect(await screen.findByText(
      "device device-d (current name unavailable) · recorded person user-del (current member unavailable) · 10.99.0.30",
    )).toBeTruthy();
    expect(screen.getByRole("option", {
      name: "person user-deleted-123456 (current member unavailable)",
    })).toBeTruthy();
    expect(screen.getByRole("option", {
      name: "device device-deleted-123456 (current name unavailable)",
    })).toBeTruthy();
  });

  it("does not infer a current device or person from a matching source IP", async () => {
    eventRows = [{
      id: "event-address-only",
      created_at: "2026-08-16T00:00:00Z",
      seq: 3,
      occurred_at: "2026-08-16T00:00:00Z",
      decision: "allow",
      src_ip: "10.99.0.20",
      dst_ip: "10.0.0.8",
      protocol: "tcp",
    }];

    render(<AccessEvents />);

    expect(await screen.findByText("10.99.0.20")).toBeTruthy();
    expect(screen.queryByText(
      "Alice laptop (current device name) · recorded person Alice · alice@example.com (current member label) · 10.99.0.20",
    )).toBeNull();
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
    expect(await screen.findByText(
      "build-agent (current agent name) · recorded person Alice · alice@example.com (current member label) · 10.99.0.9",
    )).toBeTruthy();
  });

  it("turns a rejected event request into a retryable failure, never an empty feed", async () => {
    eventMode = "reject";
    render(<AccessEvents />);

    expect(await screen.findByText(/could not reach the api/i)).toBeTruthy();
    expect(screen.queryByText(/no access events/i)).toBeNull();

    eventMode = "success";
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(
      "build-agent (current agent name) · recorded person Alice · alice@example.com (current member label) · 10.99.0.9",
    )).toBeTruthy();
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
