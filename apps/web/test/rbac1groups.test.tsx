import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Member, Org, UserGroup } from "../src/lib/api";

// RBAC-1: user groups stay policy:manage (owner, admin). A network admin reads them and is told who can change them.
const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn(),
  org: { id: "org-a", name: "Organization A" } as Org,
  auth: { status: "authed", user: { id: "person-1", email: "net@example.test", email_verified: true } },
  people: [] as Member[],
}));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }) }));
import AccessGroups from "../src/pages/AccessGroups";

const group: UserGroup = { id: "group-1", org_id: "org-a", name: "Engineering", description: "", member_count: 0, created_at: "2026-10-08T08:00:00Z", updated_at: "2026-10-08T08:00:00Z", origin: "manual" } as UserGroup;
beforeEach(() => {
  vi.resetAllMocks();
  state.people = [{ user_id: "person-1", name: "Net", email: "net@example.test", role: "network-admin", roles: ["network-admin"], status: "active", email_verified: true, joined_at: "2026-10-08T08:00:00Z" } as Member];
  state.GET.mockImplementation(async (path: string) => {
    if (path.endsWith("/groups/{groupId}/members")) return { data: [] };
    if (path.endsWith("/members")) return { data: state.people };
    if (path.endsWith("/groups")) return { data: [group] };
    return { data: [] };
  });
});
afterEach(cleanup);

describe("RBAC-1 user groups for a network admin", () => {
  it("lists groups read-only with one sentence on who can change them", async () => {
    render(<MemoryRouter><AccessGroups /></MemoryRouter>);
    const table = await screen.findByRole("table", { name: "Groups inventory" });
    expect(within(table).getByRole("button", { name: "Engineering" })).toBeTruthy();
    expect(screen.getByText("Only owners and admins can change groups.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Create group/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Engineering" }));
    expect(screen.getByRole("menuitem", { name: "View members" })).toBeTruthy();
    expect(screen.queryByRole("menuitem", { name: "Rename" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Archive" })).toBeNull();
    expect(state.POST).not.toHaveBeenCalled();
  });
});
