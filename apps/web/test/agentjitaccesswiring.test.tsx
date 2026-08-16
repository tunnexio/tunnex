import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

let role: "admin" | "member" = "admin";
let currentOrg = {
  id: "org-a",
  name: "Organization A",
  agent_jit_access_enabled: true,
  agent_policy_templates_enabled: false,
};
let profileAllowed = true;
let requests: Array<Record<string, unknown>> = [];
let requestReads: string[] = [];

const now = "2026-08-16T10:00:00Z";
const requestRow = (state: string) => ({
  id: "request-a",
  org_id: "org-a",
  device_id: "agent-a",
  agent_name: "build-agent",
  destination_kind: "resource",
  destination_id: "resource-a",
  destination_name: "database",
  reason: "ship release",
  requested_duration_seconds: 3600,
  state,
  requested_by_user_id: "user-a",
  requested_at: now,
  updated_at: now,
  ...(state === "approved"
    ? { approved_by_user_id: "admin-a", approved_at: now, approved_expires_at: "2026-08-16T11:00:00Z" }
    : {}),
});

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: currentOrg, orgs: [currentOrg], setOrg: vi.fn(), loading: false, failed: false }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({
    state: { status: "authed", user: { id: role === "admin" ? "admin-a" : "user-a", email: "human@example.test", email_verified: true } },
  }),
}));

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, input?: { params?: { path?: { orgId?: string; deviceId?: string; requestId?: string } } }) => {
        const orgId = input?.params?.path?.orgId ?? currentOrg.id;
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path.endsWith("/members")) return { data: [{ user_id: role === "admin" ? "admin-a" : "user-a", role, email_verified: true }] };
        if (path.endsWith("/zero-trust-mode")) return { data: { mode: "enforcing" } };
        if (path.endsWith("/agents")) return { data: [{ device_id: "agent-a", name: "build-agent", gateway_name: "gw-a" }] };
        if (path.endsWith("/agents/{deviceId}")) return profileAllowed ? { data: { device_id: "agent-a", name: "build-agent" } } : { error: { error: { code: "forbidden" } } };
        if (path.endsWith("/agent-access-destinations")) { requestReads.push(`${orgId}:destinations`); return { data: [{ kind: "resource", id: "resource-a", name: "database" }] }; }
        if (path.endsWith("/agent-access-requests/{requestId}")) return { data: { request: requests[0], events: [{ id: "event-a", state: requests[0]?.state ?? "pending", created_at: now }] } };
        if (path.endsWith("/agent-access-requests")) {
          requestReads.push(`${orgId}:requests`);
          if (role === "member" && !profileAllowed && requests.length === 0)
            return { error: { error: { code: "forbidden" } } };
          return { data: { items: orgId === "org-a" ? requests : [] } };
        }
        if (path.endsWith("/policies")) return { data: requests[0]?.state === "approved" ? [{ id: "rule-a", org_id: "org-a", src_kind: "agent", src_device_id: "agent-a", dst_kind: "resource", dst_resource_id: "resource-a", created_at: now, expires_at: "2026-08-16T11:00:00Z", enabled: true, managed_by_operator: false, managed_by_agent_template: false, managed_by_agent_access: true, agent_access_request_id: "request-a", cidr_outside_org_ranges: false, dst_k8s_service_vanished: false }] : [] };
        if (path.endsWith("/resources")) return { data: [{ id: "resource-a", name: "database", cidr: "10.20.0.0/24" }] };
        return { data: [] };
      }),
      POST: vi.fn(async (path: string) => {
        if (path.endsWith("/agent-access-requests")) requests = [requestRow("pending")];
        if (path.endsWith("/approve")) requests = [requestRow("approved")];
        if (path.endsWith("/revoke")) requests = [{ ...requestRow("approved"), state: "revoked", revoked_by_user_id: "admin-a", revoked_at: now }];
        if (path.endsWith("/cancel")) requests = [{ ...requestRow("pending"), state: "cancelled", cancelled_by_user_id: "user-a", cancelled_at: now }];
        return { data: requests[0] ?? {} };
      }),
      PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { api } from "../src/lib/api";
import Access from "../src/pages/Access";
import { grantControls } from "../src/lib/policyview";

beforeEach(() => {
  role = "admin";
  currentOrg = { id: "org-a", name: "Organization A", agent_jit_access_enabled: true, agent_policy_templates_enabled: false };
  profileAllowed = true;
  requests = [];
  requestReads = [];
  vi.mocked(api.GET).mockClear();
  vi.mocked(api.POST).mockClear();
  vi.stubGlobal("crypto", { randomUUID: () => "00000000-0000-4000-8000-000000000001" });
});

afterEach(() => {
  vi.unstubAllGlobals();
  cleanup();
});

describe("released F10 JIT agent access workflow", () => {
  it("creates, approves, shows history, revokes, and refetches server state", async () => {
    render(<Access />);
    await screen.findByRole("heading", { name: "Just-in-time agent access" });
    fireEvent.change(screen.getByPlaceholderText("Why is access needed?"), { target: { value: "ship release" } });
    fireEvent.click(screen.getByRole("button", { name: "Request access" }));
    await screen.findByText(/ship release · pending/);
    expect(vi.mocked(api.POST)).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agent-access-requests",
      expect.objectContaining({ body: expect.objectContaining({ duration_seconds: 3600, destination_id: "resource-a" }) }),
    );

    fireEvent.click(screen.getByRole("button", { name: "History" }));
    await screen.findByText("pending");
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await screen.findByText(/ship release · approved/);
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await screen.findByText(/ship release · revoked/);
  });

  it("lets a scoped member request and cancel but never approve", async () => {
    role = "member";
    render(<Access />);
    await screen.findByRole("heading", { name: "Just-in-time agent access" });
    fireEvent.change(screen.getByPlaceholderText("Why is access needed?"), { target: { value: "debug incident" } });
    fireEvent.click(screen.getByRole("button", { name: "Request access" }));
    await screen.findByRole("button", { name: "Cancel" });
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await screen.findByText(/cancelled/);
  });

  it("makes no F10 calls or DOM for an unrelated member", async () => {
    role = "member";
    profileAllowed = false;
    render(<Access />);
    await screen.findByText("Access policies are managed by owners and admins.");
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Just-in-time agent access" })).toBeNull());
    expect(requestReads).toEqual(["org-a:requests"]);
    expect(screen.queryByText("Just-in-time agent access")).toBeNull();
  });

  it("keeps original-requester history and cancel after current scope is removed", async () => {
    role = "member";
    profileAllowed = false;
    requests = [requestRow("pending")];
    render(<Access />);
    await screen.findByText(/ship release · pending/);
    expect(screen.queryByPlaceholderText("Why is access needed?")).toBeNull();
    expect(requestReads).toEqual(["org-a:requests"]);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await screen.findByText(/ship release · cancelled/);
  });

  it("withdraws prior-organization JIT facts synchronously", async () => {
    requests = [requestRow("pending")];
    const view = render(<Access />);
    await screen.findByText(/ship release · pending/);
    currentOrg = { id: "org-b", name: "Organization B", agent_jit_access_enabled: true, agent_policy_templates_enabled: false };
    view.rerender(<Access />);
    expect(screen.queryByText(/ship release · pending/)).toBeNull();
    expect(screen.getByText("Loading access policies…")).toBeTruthy();
  });

  it("withholds every ordinary mutation for a JIT-owned rule", () => {
    expect(grantControls({ managedByOperator: false, managedByAgentAccess: true })).toEqual({ withheld: true });
  });
});
