import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Member, Org, UserGroup } from "../src/lib/api";

type GroupMember = { user_id: string; name: string; email: string; added_at: string };
const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn(),
  org: { id: "org-a", name: "Organization A" } as Org,
  auth: { status: "authed", user: { id: "person-1", email: "owner@example.test", email_verified: true } },
  people: [] as Member[], groups: [] as UserGroup[], members: [] as GroupMember[],
}));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }) }));
import AccessGroups from "../src/pages/AccessGroups";
const person = (index: number, values: Partial<Member> = {}): Member => ({ user_id: `person-${index}`, name: `Person ${index}`, email: `person${index}@example.test`, role: index === 1 ? "owner" : "member", status: "active", email_verified: true, joined_at: "2026-10-08T08:00:00Z", ...values });
const group = (index: number, values: Partial<UserGroup> = {}): UserGroup => ({ id: `group-${index}`, org_id: "org-a", name: `Group ${index}`, description: "", member_count: 1, created_at: "2026-10-08T08:00:00Z", updated_at: "2026-10-08T08:00:00Z", origin: "manual", ...values });
const asMember = (value: Member): GroupMember => ({ user_id: value.user_id, name: value.name, email: value.email, added_at: "2026-10-08T08:00:00Z" });
const workspace = () => <MemoryRouter><AccessGroups /></MemoryRouter>;
beforeEach(() => {
  vi.resetAllMocks();
  state.org = { id: "org-a", name: "Organization A" } as Org;
  state.auth = { status: "authed", user: { id: "person-1", email: "owner@example.test", email_verified: true } };
  state.people = [person(1), person(2)]; state.groups = [group(1)]; state.members = [asMember(state.people[0])];
  state.GET.mockImplementation(async (path: string) => {
    if (path.endsWith("/groups/{groupId}/members")) return { data: state.members };
    if (path.endsWith("/members")) return { data: state.people };
    if (path.endsWith("/groups")) return { data: state.groups };
    return { data: [] };
  });
  state.POST.mockImplementation(async (path: string, request: { body: { user_id?: string; name?: string } }) => {
    if (path.endsWith("/groups/{groupId}/members")) {
      state.members = [...state.members, asMember(state.people.find(value => value.user_id === request.body.user_id)!)];
      state.groups = state.groups.map(value => ({ ...value, member_count: state.members.length }));
    }
    return { data: {} };
  });
  state.PATCH.mockResolvedValue({ data: {} });
  state.DELETE.mockImplementation(async (_path: string, request: { params: { path: { userId?: string } } }) => {
    state.members = state.members.filter(value => value.user_id !== request.params.path.userId);
    state.groups = state.groups.map(value => ({ ...value, member_count: state.members.length }));
    return { data: {} };
  });
});
afterEach(cleanup);
const groupNames = () => within(screen.getByRole("table", { name: "Groups inventory" })).getAllByRole("row").slice(1).map(row => within(row).getByRole("button", { name: /^Group \d+$/ }).textContent);

describe("People groups authoritative workflow", () => {
  it("pages the real loaded groups and resets size/search/source without reading agent inventories", async () => {
    state.groups = Array.from({ length: 45 }, (_, index) => group(index + 1, index === 40 ? { origin: "idp_sync" } : {}));
    render(workspace()); await screen.findByRole("table", { name: "Groups inventory" });
    expect(groupNames()).toHaveLength(20);
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(groupNames()).toEqual(["Group 41", "Group 42", "Group 43", "Group 44", "Group 45"]);
    expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(groupNames()).toHaveLength(45);
    expect(screen.queryByRole("button", { name: "Next page" })).toBeNull();
    fireEvent.change(screen.getByRole("textbox", { name: "Search groups" }), { target: { value: "Group 3" } });
    expect(groupNames()).toContain("Group 3");
    expect(groupNames()).not.toContain("Group 41");
    fireEvent.change(screen.getByRole("textbox", { name: "Search groups" }), { target: { value: "" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Group source" }), { target: { value: "directory" } });
    expect(groupNames()).toEqual(["Group 41"]);
    expect(screen.queryByRole("button", { name: "Create group" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Group 41" }));
    expect(screen.getByRole("menuitem", { name: "View members" })).toBeTruthy();
    expect(screen.queryByRole("menuitem", { name: "Rename" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Archive" })).toBeNull();
    expect(state.GET.mock.calls.some(([path]) => /agent-groups|agent-policy/.test(path))).toBe(false);
    expect(state.POST).not.toHaveBeenCalled();
  });

  it("preserves a chosen person across large candidate pages and adds exactly that user ID", async () => {
    state.people = Array.from({ length: 46 }, (_, index) => person(index + 1));
    render(workspace()); fireEvent.click(await screen.findByRole("button", { name: "Group 1" }));
    expect(screen.getByRole("navigation", { name: "Group breadcrumb" })).toBeTruthy();
    await screen.findByRole("table", { name: "Group members" });
    fireEvent.click(screen.getByRole("button", { name: "Add member" }));
    const dialog = screen.getByRole("dialog", { name: "Add person member" });
    await within(dialog).findByRole("radio", { name: "Select Person 2" });
    expect(within(dialog).queryByRole("radio", { name: "Select Person 1" })).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Next available people" }));
    fireEvent.click(within(dialog).getByRole("radio", { name: "Select Person 22" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Previous available people" }));
    expect(within(dialog).getByText("Selected: Person 22")).toBeTruthy();
    expect(state.POST).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Add member" }));
    await waitFor(() => expect(state.POST).toHaveBeenCalledTimes(1));
    expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId: "org-a", groupId: "group-1" } }, body: { user_id: "person-22" } });
    await screen.findByRole("table", { name: "Group members" });
    expect(screen.getByRole("table", { name: "Group members" }).textContent).toContain("Person 22");
  });

  it("confirms membership removal and keeps a refused action open with the exact target", async () => {
    state.DELETE.mockResolvedValueOnce({ error: { error: { message: "Removal refused" } } });
    render(workspace()); fireEvent.click(await screen.findByRole("button", { name: "Group 1" }));
    fireEvent.click(await screen.findByRole("button", { name: "Actions for Person 1" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Remove member" }));
    const dialog = screen.getByRole("dialog", { name: "Remove member?" });
    expect(dialog.textContent).toContain("Person 1");
    expect(dialog.textContent).toContain("Group 1");
    expect(state.DELETE).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(state.DELETE).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Person 1" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Remove member" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove member" }));
    await screen.findByText("Removal refused");
    expect(screen.getByRole("dialog", { name: "Remove member?" })).toBeTruthy();
    expect(state.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/groups/{groupId}/members/{userId}", { params: { path: { orgId: "org-a", groupId: "group-1", userId: "person-1" } } });
    expect(state.members).toHaveLength(1);
  });

  it("keeps an authorized unverified caller's read view while withholding manual group mutations", async () => {
    state.auth = { ...state.auth, user: { ...state.auth.user, email_verified: false } };
    render(workspace()); await screen.findByRole("table", { name: "Groups inventory" });
    expect(screen.queryByRole("button", { name: "Create group" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Group 1" }));
    expect(screen.queryByRole("menuitem", { name: "Rename" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Archive" })).toBeNull();
    fireEvent.click(screen.getByRole("menuitem", { name: "View members" }));
    await screen.findByRole("table", { name: "Group members" });
    expect(screen.queryByRole("button", { name: "Add member" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Actions for Person 1" })).toBeNull();
    expect(state.POST).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });

  it("ignores old group members after an organization switch instead of leaking them into the new scope", async () => {
    let complete!: (value: unknown) => void;
    const defaultRead = state.GET.getMockImplementation()!;
    state.GET.mockImplementation(async (path: string, request: unknown) => path.endsWith("/groups/{groupId}/members") ? new Promise(resolve => { complete = resolve; }) : defaultRead(path, request));
    const view = render(workspace()); fireEvent.click(await screen.findByRole("button", { name: "Group 1" }));
    await waitFor(() => expect(complete).toBeTypeOf("function"));
    state.org = { ...state.org, id: "org-b" }; state.groups = [];
    view.rerender(workspace());
    expect(screen.queryByRole("navigation", { name: "Group breadcrumb" })).toBeNull();
    await screen.findByText("This group is not available in the current organization.");
    await act(async () => complete({ data: [asMember(person(9, { name: "Superseded private member" }))] }));
    expect(screen.queryByText("Superseded private member")).toBeNull();
    expect(screen.queryByRole("table", { name: "Group members" })).toBeNull();
    expect(state.POST).not.toHaveBeenCalled();
  });

  it("keeps a failed member read retryable and does not claim an empty group or offer an add based on missing data", async () => {
    let failed = true;
    const defaultRead = state.GET.getMockImplementation()!;
    state.GET.mockImplementation(async (path: string, request: unknown) => path.endsWith("/groups/{groupId}/members") && failed ? { error: { error: { message: "Membership unavailable" } } } : defaultRead(path, request));
    render(workspace()); fireEvent.click(await screen.findByRole("button", { name: "Group 1" }));
    await screen.findByText("Membership unavailable");
    expect(screen.queryByText("No members.")).toBeNull();
    expect(screen.getByRole("button", { name: "Add member" })).toHaveProperty("disabled", true);
    failed = false; fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("table", { name: "Group members" });
    expect(screen.getByRole("button", { name: "Add member" })).toHaveProperty("disabled", false);
    expect(state.POST).not.toHaveBeenCalled();
  });
});
