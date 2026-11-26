import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Member, Org } from "../src/lib/api";
import { accountActionBlocked, activeOwnerCount } from "../src/lib/usersview";

// RBAC-0 (docs/RBAC-0-people-management-security.md): the Users screen explains why an action is
// unavailable instead of hiding it, mirrors the server's ACTIVE-owner count, and handles step-up inline.

const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(),
  org: { id: "org-a", name: "Organization A" } as Org,
  auth: { status: "authed", user: { id: "admin-1", email: "admin@example.test", email_verified: true, reauthentication: { password: true, mfa: false, available: true } } } as Record<string, unknown>,
  members: [] as Member[],
  verified: vi.fn(),
}));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }), useOptionalAuth: () => ({ state: state.auth }) }));
vi.mock("../src/components/InlineTerminalMfa", () => ({
  InlineTerminalMfa: ({ action, onVerified }: { action: string; onVerified: () => void }) => <section aria-label={`MFA for ${action}`}><button type="button" onClick={() => { state.verified(); onVerified(); }}>Verify code</button></section>,
}));
import Users from "../src/pages/Users";

const member = (id: string, values: Partial<Member> = {}): Member => ({ user_id: id, name: id, email: `${id}@example.test`, role: "member", status: "active", email_verified: true, joined_at: "2026-10-08T08:00:00Z", ...values });

beforeEach(() => {
  vi.resetAllMocks();
  state.auth = { status: "authed", user: { id: "admin-1", email: "admin@example.test", email_verified: true, reauthentication: { password: true, mfa: false, available: true } } };
  state.members = [member("owner-1", { role: "owner" }), member("admin-1", { role: "admin" }), member("person-2")];
  state.GET.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: state.members } : path.endsWith("/meta") ? { data: { smtp_configured: true } } : { data: [] });
  state.POST.mockResolvedValue({ data: {} });
});
afterEach(cleanup);

async function openRowMenu(email: string) {
  fireEvent.click(await screen.findByRole("button", { name: `User actions for ${email}` }));
}

describe("RBAC-0 account action reasons", () => {
  it("shows an admin the owner's actions as unavailable, with the reason", async () => {
    render(<MemoryRouter><Users view="users" /></MemoryRouter>);
    await openRowMenu("owner-1@example.test");
    const deactivate = screen.getByRole("menuitem", { name: "Deactivate" });
    expect(deactivate).toHaveProperty("disabled", true);
    expect(screen.getByText("Only an owner can deactivate an owner.")).toBeTruthy();
    expect(screen.getByRole("menuitem", { name: "Reset 2FA" })).toHaveProperty("disabled", true);
  });

  it("explains why a directory or another organization's deactivation cannot be reversed here", () => {
    const ctx = { actorId: "owner-9", actorRole: "owner" as const, emailVerified: true, activeOwners: 2 };
    expect(accountActionBlocked(member("p", { status: "deactivated", deactivated_by: "directory" }), "reactivate", ctx)).toMatch(/Directory sync/);
    expect(accountActionBlocked(member("p", { status: "deactivated", deactivated_by: "other_organization" }), "reactivate", ctx)).toMatch(/Another organization/);
    expect(accountActionBlocked(member("p", { status: "deactivated", deactivated_by: "organization" }), "reactivate", ctx)).toBeNull();
  });

  it("counts only ACTIVE owners toward the last-owner rule", () => {
    const roster = [member("a", { role: "owner" }), member("b", { role: "owner", status: "deactivated" })];
    expect(activeOwnerCount(roster)).toBe(1);
    expect(accountActionBlocked(roster[0], "deactivate", { actorId: "z", actorRole: "owner", emailVerified: true, activeOwners: activeOwnerCount(roster) })).toMatch(/at least one owner/);
  });
});

describe("RBAC-0 step-up", () => {
  it("asks for the current password up front and sends it with the deactivation", async () => {
    render(<MemoryRouter><Users view="users" /></MemoryRouter>);
    await openRowMenu("person-2@example.test");
    fireEvent.click(screen.getByRole("menuitem", { name: "Deactivate" }));
    const dialog = screen.getByRole("dialog", { name: "Deactivate account?" });
    fireEvent.change(within(dialog).getByLabelText("Your current password"), { target: { value: "hunter2-but-longer" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));
    await waitFor(() => expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/members/{userId}/deactivate", { params: { path: { orgId: "org-a", userId: "person-2" } }, body: { current_password: "hunter2-but-longer" } }));
  });

  it("pauses for an MFA check inline and continues the same action after it", async () => {
    state.POST.mockResolvedValueOnce({ error: { error: { code: "mfa_step_up_required", message: "Verify MFA to deactivate this member." } } }).mockResolvedValue({ data: {} });
    render(<MemoryRouter><Users view="users" /></MemoryRouter>);
    await openRowMenu("person-2@example.test");
    fireEvent.click(screen.getByRole("menuitem", { name: "Deactivate" }));
    const dialog = screen.getByRole("dialog", { name: "Deactivate account?" });
    fireEvent.change(within(dialog).getByLabelText("Your current password"), { target: { value: "hunter2-but-longer" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));
    fireEvent.click(await screen.findByRole("button", { name: "Verify code" }));
    await waitFor(() => expect(state.POST).toHaveBeenCalledTimes(2));
    expect(state.verified).toHaveBeenCalledTimes(1);
    await screen.findByText("1 account deactivated.");
    expect(screen.queryByText(/mfa_step_up_required/)).toBeNull();
  });
});
