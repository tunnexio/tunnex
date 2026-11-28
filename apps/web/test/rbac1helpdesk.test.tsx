import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Device, Member } from "../src/lib/api";

// RBAC-1 Helpdesk in the console: it resets 2FA and approves devices for ordinary people, never sees a control
// it cannot use, and an action out of its reach says who can.
const pending: Device[] = [
  { id: "dev-admin", user_id: "admin-1", name: "Admin laptop", owner_email: "admin@example.test", created_at: "2026-11-27T08:00:00Z", status: "pending" } as Device,
  { id: "dev-plain", user_id: "plain-1", name: "Plain laptop", owner_email: "plain@example.test", created_at: "2026-11-27T08:00:00Z", status: "pending" } as Device,
];
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => path.endsWith("/device-approval") ? { data: { mode: "on" } } : path.endsWith("/devices/pending") ? { data: pending } : { data: [] }),
      POST: vi.fn(async () => ({ data: {} })), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn(),
    },
  };
});
import UsersInventory, { type UsersInventoryProps } from "../src/components/UsersInventory";
import { DeviceApprovalSection } from "../src/components/DeviceApprovalSection";
import { RoleAssignment } from "../src/components/RoleAssignment";
import { HELPDESK_CEILING_REASON, ROLE_DESCRIPTIONS, ROLE_LABELS } from "../src/lib/rbac";

afterEach(cleanup);
const person = (id: string, roles: Member["role"][]): Member => ({ user_id: id, name: id, email: `${id}@example.test`, role: roles[0], roles, status: "active", email_verified: true, joined_at: "2026-10-08T08:00:00Z" } as Member);
function roster(actorRoles: Member["role"][], members: Member[]) {
  const props: UsersInventoryProps = { members, devices: [], actorId: "me", actorRole: actorRoles[0], actorRoles, emailVerified: true, busy: false, view: "users", ownerCount: 1, onInspect: vi.fn(), onRequestAction: vi.fn() };
  render(<MemoryRouter><UsersInventory {...props} /></MemoryRouter>);
  return props;
}
function menu(email: string) {
  fireEvent.click(screen.getByRole("button", { name: `User actions for ${email}` }));
  return within(screen.getByRole("menu", { name: `User actions for ${email}` }));
}

describe("RBAC-1 Helpdesk on the Users roster", () => {
  it("offers Reset 2FA only, and only for people without an administrator role", () => {
    const props = roster(["helpdesk"], [person("me", ["helpdesk"]), person("plain", ["member"]), person("boss", ["network-admin", "member"])]);
    const plain = menu("plain@example.test");
    expect(plain.queryByRole("menuitem", { name: "Edit roles" })).toBeNull();
    expect(plain.queryByRole("menuitem", { name: "Deactivate" })).toBeNull();
    fireEvent.click(plain.getByRole("menuitem", { name: "Reset 2FA" }));
    expect(props.onRequestAction).toHaveBeenCalledWith("reset", [expect.objectContaining({ user_id: "plain" })]);
    const boss = menu("boss@example.test");
    expect(boss.getByRole("menuitem", { name: "Reset 2FA" })).toHaveProperty("disabled", true);
    expect(boss.getByText(HELPDESK_CEILING_REASON)).toBeTruthy();
    expect(screen.queryByRole("checkbox", { name: /Select / })).toBeNull();
  });

  it("the auditor sees the roster with labels and no actions at all", () => {
    roster(["auditor"], [person("me", ["auditor"]), person("plain", ["member", "ai-admin"])]);
    expect(screen.getByText("Member + AI Gateway admin")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /User actions for/ })).toBeNull();
    expect(screen.queryByRole("checkbox", { name: /Select / })).toBeNull();
  });
});

describe("RBAC-1 Helpdesk on device approvals", () => {
  it("approves an ordinary person's device and is told who can approve an administrator's", async () => {
    render(<MemoryRouter><DeviceApprovalSection orgId="org-a" canManage blockedReason={(device) => device.user_id === "admin-1" ? HELPDESK_CEILING_REASON : null} /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Actions for Admin laptop" }));
    expect(screen.getByRole("menuitem", { name: "Approve" })).toHaveProperty("disabled", true);
    expect(screen.getAllByText(HELPDESK_CEILING_REASON).length).toBeGreaterThan(0);
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    cleanup();
    render(<MemoryRouter><DeviceApprovalSection orgId="org-a" canManage blockedReason={(device) => device.user_id === "admin-1" ? HELPDESK_CEILING_REASON : null} /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Actions for Plain laptop" }));
    expect(screen.getByRole("menuitem", { name: "Approve" })).toHaveProperty("disabled", false);
  });
});

describe("RBAC-1 role picker", () => {
  it("shows each role's label and one-sentence description, saving stored values", () => {
    const save = vi.fn().mockResolvedValue(undefined);
    render(<RoleAssignment email="p@example.test" roles={["member"]} options={["auditor", "helpdesk", "ai-admin", "member"]} soleOwner={false} onSave={save} />);
    for (const role of ["auditor", "helpdesk", "ai-admin", "member"] as const) {
      expect(screen.getAllByText(ROLE_LABELS[role]).length).toBeGreaterThan(0);
      expect(screen.getByText(ROLE_DESCRIPTIONS[role])).toBeTruthy();
    }
    expect(screen.getByText("Member", { selector: "summary" })).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/^Auditor/));
    fireEvent.click(screen.getByRole("button", { name: "Save roles", hidden: true }));
    expect(save).toHaveBeenCalledWith(["member", "auditor"]);
  });
});
