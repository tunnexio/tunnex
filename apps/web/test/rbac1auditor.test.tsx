import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

// RBAC-1 (founder, 2026-11-28): the Auditor reads the admin lists read-only, with one sentence on who can
// change them and no control that the server would refuse.
const state = vi.hoisted(() => ({ roles: ["auditor"] as string[] }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" }, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "me", email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path.endsWith("/members")) return { data: [{ user_id: "me", role: state.roles[0], roles: state.roles, email: "me@example.test", status: "active", email_verified: true }] };
        if (path.endsWith("/device-approval")) return { data: { mode: "on" } };
        if (path.endsWith("/devices/pending")) return { data: [{ id: "d1", user_id: "p1", name: "Pending laptop", owner_email: "p@example.test", created_at: "2026-11-27T08:00:00Z", status: "pending" }] };
        if (path.endsWith("/alerting-settings")) return { data: { enabled: true } };
        if (path.endsWith("/alert-destinations")) return { data: [{ id: "a1", kind: "webhook", name: "Ops hook", endpoint_host: "hooks.example.test", endpoint_fingerprint: "f", allow_private: false, severity_floor: "warning", cooldown_seconds: 300, archived: false, created_at: "2026-11-27T08:00:00Z", updated_at: "2026-11-27T08:00:00Z" }] };
        if (path.endsWith("/alert-deliveries")) return { data: [] };
        if (path.endsWith("/sessions")) return { data: { items: [{ id: "session-12345678", user_id: "p1", user_email: "p@example.test", created_at: "2026-11-27T08:00:00Z", expires_at: "2026-11-28T08:00:00Z" }] } };
        return { data: [] };
      }),
      POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn(),
    },
  };
});
import DeviceApprovals from "../src/pages/DeviceApprovals";
import { AlertManagement } from "../src/components/AlertManagement";
import AppAccessSessions from "../src/components/AppAccessSessions";
import { api } from "../src/lib/api";

afterEach(cleanup);

describe("RBAC-1 auditor on admin lists", () => {
  it("reads the device approval queue without approving", async () => {
    state.roles = ["auditor"];
    render(<MemoryRouter><DeviceApprovals /></MemoryRouter>);
    expect(await screen.findByText("Pending laptop")).toBeTruthy();
    expect(screen.getByText("Only owners, admins, network admins and Helpdesk can approve or reject devices.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Pending laptop" }));
    expect(screen.queryByRole("menuitem", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Reject" })).toBeNull();
  });

  it("reads alert routing without changing it", async () => {
    render(<MemoryRouter><AlertManagement orgId="org-a" canEdit={false} canAllowPrivate={false} readOnlyReason="Only owners and admins can change alert routing." /></MemoryRouter>);
    expect(await screen.findByText("Ops hook")).toBeTruthy();
    expect(screen.getByText("Only owners and admins can change alert routing.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "New routing policy" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText(/Verify your email/)).toBeNull();
  });

  it("lists App Access sessions without a revoke control", async () => {
    render(<MemoryRouter><AppAccessSessions orgId="org-a" appId="app-1" canRevoke={false} /></MemoryRouter>);
    expect(await screen.findByText("session-")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /^Revoke / })).toBeNull();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});
