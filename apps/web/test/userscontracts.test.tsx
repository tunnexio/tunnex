import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { Profiler } from "react";
import type { Member, Org, Role } from "../src/lib/api";
import type { Invitation } from "../src/lib/invitationview";

const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(),
  org: { id: "org-a", name: "Organization A" } as Org,
  auth: { status: "authed", user: { id: "person-1", email: "owner@example.test", email_verified: true } },
  members: [] as Member[], invites: [] as Invitation[],
}));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }) }));
import Users from "../src/pages/Users";

const member = (index: number, values: Partial<Member> = {}): Member => ({ user_id: `person-${index}`, name: `Person ${index}`, email: `person${index}@example.test`, role: index === 1 ? "owner" : "member", status: "active", email_verified: true, joined_at: "2026-10-08T08:00:00Z", ...values });
const invitation = (index: number, values: Partial<Invitation> = {}): Invitation => ({ id: `invitation-${index}`, email: `invited${index}@example.test`, role: "member", created_at: "2026-10-08T08:00:00Z", expires_at: "2099-10-08T08:00:00Z", accepted_at: null, revoked_at: null, ...values });
type Request = { params?: { path?: { orgId?: string; userId?: string } }; body?: { email?: string; role?: Role; roles?: Role[] } };
const workspace = (view: "users" | "roles" | "invitations" = "users") => <MemoryRouter><Users view={view} /></MemoryRouter>;
beforeEach(() => {
  vi.resetAllMocks();
  state.org = { id: "org-a", name: "Organization A" } as Org;
  state.auth = { status: "authed", user: { id: "person-1", email: "owner@example.test", email_verified: true } };
  state.members = [member(1), member(2)]; state.invites = [];
  state.GET.mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: state.members };
    if (path.endsWith("/invitations")) return { data: state.invites };
    if (path.endsWith("/meta")) return { data: { edition: "enterprise", smtp_configured: false } };
    return { data: [] };
  });
  state.POST.mockImplementation(async (path: string, request: Request) => {
    if (path.endsWith("/invitations")) return { data: { invite_token: "private-once-token", delivered: false, message: "Invitation created." } };
    if (path.endsWith("/deactivate") || path.endsWith("/reactivate")) state.members = state.members.map(value => value.user_id === request.params?.path?.userId ? { ...value, status: path.endsWith("/deactivate") ? "deactivated" : "active" } : value);
    return { data: {} };
  });
  state.PUT.mockImplementation(async (_path: string, request: Request) => {
    state.members = state.members.map(value => value.user_id === request.params?.path?.userId ? { ...value, roles: request.body?.roles } : value);
    return { data: {} };
  });
});
afterEach(cleanup);
async function invite() {
  fireEvent.click(await screen.findByRole("button", { name: "Invite user" }));
  const dialog = screen.getByRole("dialog", { name: "Invite user" });
  fireEvent.change(within(dialog).getByRole("textbox", { name: "Email address" }), { target: { value: "new.person@example.test" } });
  return dialog;
}
async function rowAction(email: string, action: string) {
  fireEvent.click(await screen.findByRole("button", { name: `User actions for ${email}` }));
  fireEvent.click(screen.getByRole("menuitem", { name: action }));
}
async function invitationAction(action: string) {
  fireEvent.click(await screen.findByRole("button", { name: "Invitation actions for invited1@example.test" }));
  fireEvent.click(screen.getByRole("menuitem", { name: action }));
}

describe("Users authoritative role and account changes", () => {
  it("opens the advertised role editor and sends exactly the chosen role set only on Save", async () => {
    render(workspace()); await rowAction("person2@example.test", "Edit roles");
    const detail = screen.getByRole("region", { name: "Person details" });
    expect(within(detail).getByRole("button", { name: "Roles" }).getAttribute("aria-current")).toBe("step");
    fireEvent.click(within(detail).getByRole("checkbox", { name: "ai-admin" }));
    expect(state.PUT).not.toHaveBeenCalled();
    fireEvent.click(within(detail).getByRole("button", { name: "Save roles" }));
    await waitFor(() => expect(state.PUT).toHaveBeenCalledTimes(1));
    expect(state.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/members/{userId}/roles", { params: { path: { orgId: "org-a", userId: "person-2" } }, body: { roles: ["member", "ai-admin"] } });
    await screen.findByText("Roles updated.");
    expect(screen.getByRole("checkbox", { name: "ai-admin" })).toHaveProperty("checked", true);
  });

  it("reconciles a refused role change without claiming it succeeded", async () => {
    state.PUT.mockResolvedValueOnce({ error: { error: { code: "last_owner", message: "Role update refused" } } });
    render(workspace()); await rowAction("person2@example.test", "Edit roles");
    fireEvent.click(screen.getByRole("checkbox", { name: "ai-view" }));
    fireEvent.click(screen.getByRole("button", { name: "Save roles" }));
    await screen.findByText("Role update refused");
    await screen.findByRole("checkbox", { name: "ai-view" });
    expect(screen.queryByText("Roles updated.")).toBeNull();
    expect(state.GET.mock.calls.filter(([path]) => path.endsWith("/members"))).toHaveLength(2);
    expect(state.members[1].roles).toBeUndefined();
  });

  it("keeps deactivation impact and exact named targets in a confirmation, with no write on Cancel", async () => {
    state.members[1] = member(2, { machine_credentials: 3, managed_agent_delegations: 2 });
    render(workspace()); await rowAction("person2@example.test", "Deactivate");
    const dialog = screen.getByRole("dialog", { name: "Deactivate account?" });
    expect(dialog.textContent).toContain("person2@example.test");
    expect(dialog.textContent).toContain("3");
    expect(dialog.textContent).toContain("2");
    expect(dialog.textContent).toContain("machine");
    expect(dialog.textContent).toContain("agent");
    expect(state.POST).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(state.POST).not.toHaveBeenCalled();
    await rowAction("person2@example.test", "Deactivate");
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    await waitFor(() => expect(state.POST).toHaveBeenCalledTimes(1));
    expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/members/{userId}/deactivate", { params: { path: { orgId: "org-a", userId: "person-2" } } });
    await screen.findByText("1 account deactivated.");
  });

  it("confirms single-person 2FA reset and does not duplicate a pending request", async () => {
    let complete!: (value: unknown) => void;
    state.POST.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    render(workspace()); await rowAction("person2@example.test", "Reset 2FA");
    const dialog = screen.getByRole("dialog", { name: "Reset two-factor authentication" });
    expect(dialog.textContent).toContain("person2@example.test");
    const apply = within(dialog).getByRole("button", { name: "Reset 2FA" });
    fireEvent.click(apply); fireEvent.click(apply);
    expect(state.POST).toHaveBeenCalledTimes(1);
    expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/members/{userId}/mfa-reset", { params: { path: { orgId: "org-a", userId: "person-2" } } });
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveProperty("disabled", true);
    await act(async () => complete({ data: {} }));
    await screen.findByText("1 account had 2FA reset.");
  });

  it("reconciles partial bulk changes while retaining each failed account's error", async () => {
    state.members.push(member(3));
    state.POST.mockImplementation(async (_path: string, request: Request) => {
      if (request.params?.path?.userId === "person-3") return { error: { error: { message: "Target refused" } } };
      state.members = state.members.map(value => value.user_id === request.params?.path?.userId ? { ...value, status: "deactivated" } : value);
      return { data: {} };
    });
    render(workspace());
    for (const email of ["person2@example.test", "person3@example.test"]) fireEvent.click(await screen.findByRole("checkbox", { name: `Select ${email}` }));
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Deactivate" }));
    await screen.findByText("1 account deactivated.");
    expect(screen.getByText("person3@example.test: Target refused")).toBeTruthy();
    expect(state.POST).toHaveBeenCalledTimes(2);
    expect(state.GET.mock.calls.filter(([path]) => path.endsWith("/members"))).toHaveLength(2);
    await screen.findByRole("button", { name: "Person 2" });
    expect(within(screen.getByRole("button", { name: "Person 2" }).closest("tr")!).getByText("Deactivated")).toBeTruthy();
    expect(within(screen.getByRole("button", { name: "Person 3" }).closest("tr")!).getByText("Active")).toBeTruthy();
  });
});

describe("Users invitation and authorization scope", () => {
  it("locks duplicate creation and preserves a real one-time link across invitation refresh until explicitly dismissed", async () => {
    let complete!: (value: unknown) => void;
    state.POST.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    render(workspace()); const editor = await invite();
    const submit = within(editor).getByRole("button", { name: "Create invite" });
    fireEvent.click(submit); fireEvent.click(submit);
    fireEvent.submit(within(editor).getByRole("textbox", { name: "Email address" }).closest("form")!);
    expect(state.POST).toHaveBeenCalledTimes(1);
    expect(within(editor).getByRole("textbox", { name: "Email address" }).matches(":disabled")).toBe(true);
    await act(async () => complete({ data: { invite_token: "private-once-token", delivered: false } }));
    const secret = await screen.findByRole("dialog", { name: "Invitation link" });
    expect(secret.textContent).toContain("/accept-invite?token=private-once-token");
    expect(secret.textContent).toContain("Email was not delivered");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    await waitFor(() => expect(state.GET.mock.calls.filter(([path]) => path.endsWith("/invitations"))).toHaveLength(2));
    expect(screen.getByRole("dialog", { name: "Invitation link" })).toBe(secret);
    fireEvent.click(within(secret).getByRole("button", { name: "I’ve saved it" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("table", { name: "Members" });
    expect(screen.queryByText(/private-once-token/)).toBeNull();
    expect(state.POST).toHaveBeenCalledTimes(1);
  });

  it("ignores a late invitation token after an organization switch", async () => {
    let complete!: (value: unknown) => void;
    state.POST.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    const view = render(workspace()); const editor = await invite();
    fireEvent.click(within(editor).getByRole("button", { name: "Create invite" }));
    state.org = { ...state.org, id: "org-b" };
    state.members = [member(1, { name: "Current owner" })];
    view.rerender(workspace());
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByRole("button", { name: "Current owner" });
    await act(async () => complete({ data: { invite_token: "SUPERSEDED-PRIVATE-TOKEN", delivered: true } }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText(/SUPERSEDED-PRIVATE-TOKEN/)).toBeNull();
    expect(state.GET.mock.calls.filter(([path, request]) => path.endsWith("/invitations") && request.params.path.orgId === "org-a")).toHaveLength(1);
  });

  it.each(["actor", "verification"])("withdraws old private roster and role-edit authority at every %s-change commit", async (change) => {
    const leaked: boolean[] = [];
    const scoped = () => <MemoryRouter><Profiler id="users-scope" onRender={() => {
      if (state.auth.user.id === "person-4" || !state.auth.user.email_verified) leaked.push(Boolean(screen.queryByRole("region", { name: "Person details" }) || screen.queryByRole("dialog")));
    }}><Users /></Profiler></MemoryRouter>;
    const view = render(scoped()); await rowAction("person2@example.test", "Edit roles");
    state.auth = { ...state.auth, user: { ...state.auth.user, ...(change === "actor" ? { id: "person-4" } : { email_verified: false }) } };
    if (change === "actor") state.members = [member(4)];
    view.rerender(scoped());
    expect(leaked.length).toBeGreaterThan(0);
    expect(leaked).not.toContain(true);
    await screen.findByRole("table", { name: "Members" });
    expect(screen.queryByRole("button", { name: "Invite user" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^User actions for/ })).toBeNull();
    expect(state.PUT).not.toHaveBeenCalled();
  });

  it.each(["refusal", "transport"])("keeps a %s invitation-renewal outcome visible after authoritative reconciliation", async (failure) => {
    state.invites = [invitation(1)];
    if (failure === "transport") state.POST.mockRejectedValueOnce(new Error("response lost"));
    else state.POST.mockResolvedValueOnce({ error: { error: { code: "forbidden", message: "Renewal denied" } } });
    render(workspace("invitations")); await invitationAction("Resend");
    const confirm = screen.getByRole("dialog", { name: "Renew invitation?" });
    expect(confirm.textContent).toContain("invited1@example.test");
    expect(state.POST).not.toHaveBeenCalled();
    fireEvent.click(within(confirm).getByRole("button", { name: "Resend invitation" }));
    await waitFor(() => expect(state.GET.mock.calls.filter(([path]) => path.endsWith("/invitations"))).toHaveLength(2));
    await screen.findByRole("table", { name: "Invitation history" });
    expect(screen.queryByText("Invitation renewed.")).toBeNull();
    expect(screen.getByRole("alert").textContent).toMatch(failure === "transport" ? /Could not confirm.*Refresh/ : /Could not complete the request\./);
    expect(state.POST).toHaveBeenCalledTimes(1);
    expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/invitations/resend", { params: { path: { orgId: "org-a" } }, body: { email: "invited1@example.test" } });
  });

  it("keeps missing invitation inventory unavailable rather than claiming that nobody has been invited", async () => {
    state.GET.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: state.members } : path.endsWith("/invitations") ? { data: undefined } : { data: [] });
    render(workspace("invitations"));
    await screen.findByText("Could not load invitations.");
    expect(screen.queryByText("No invitations yet")).toBeNull();
    expect(screen.queryByRole("table", { name: "Invitation history" })).toBeNull();
    expect(state.POST).not.toHaveBeenCalled();
  });
});
