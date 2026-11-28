import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// RBAC-1: the CIDR resources page reads with policy:view and changes with resource:manage, so the auditor and the
// AI Agents admin see the inventory read-only with one sentence on who can change it, and the network admin
// manages it.
let roles: string[] = ["auditor"];
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: roles[0], roles }] };
        if (path.endsWith("/resources")) return { data: [{ id: "r1", name: "Payroll", cidr: "10.0.0.0/24", protocol: "any", port_low: null, port_high: null }] };
        return { data: [] };
      }),
      POST: vi.fn(), PATCH: vi.fn(), PUT: vi.fn(), DELETE: vi.fn(),
    },
  };
});
import AccessResources from "../src/pages/AccessResources";

beforeEach(() => { roles = ["auditor"]; });
afterEach(cleanup);

describe("RBAC-1 resources page per role", () => {
  it.each([["auditor"], ["agents-admin"]])("%s reads resources and is told who can change them", async (role) => {
    roles = [role];
    render(<MemoryRouter><AccessResources /></MemoryRouter>);
    expect(await screen.findByText("Payroll")).toBeTruthy();
    expect(screen.getByText("Only owners, admins and network admins can change resources.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create resource" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Payroll" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Actions for Payroll" })).toBeNull();
  });

  it("network admin manages resources", async () => {
    roles = ["network-admin"];
    render(<MemoryRouter><AccessResources /></MemoryRouter>);
    expect(await screen.findByRole("button", { name: "Payroll" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Create resource" }).length).toBeGreaterThan(0);
    expect(screen.queryByText("Only owners, admins and network admins can change resources.")).toBeNull();
  });

  it("helpdesk does not get the resources page", async () => {
    roles = ["helpdesk"];
    render(<MemoryRouter><AccessResources /></MemoryRouter>);
    expect(await screen.findByText("You do not have permission to manage CIDR resources.")).toBeTruthy();
  });
});
