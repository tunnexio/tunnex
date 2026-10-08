import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { Profiler } from "react";

const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn(),
  org: { id: "org-a", name: "Organization A" },
  auth: { status: "authed", user: { id: "actor-a", email: "owner@example.test", email_verified: true } },
  role: "owner",
}));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }) }));
import DeviceApprovals from "../src/pages/DeviceApprovals";
import DevicePosture from "../src/pages/DevicePosture";
const views = [
  { name: "approvals", Component: DeviceApprovals, open: "Actions for Pending phone", table: "Pending devices" },
  { name: "posture", Component: DevicePosture, open: "Disk encryption", table: "Posture checks" },
] as const;

beforeEach(() => {
  vi.resetAllMocks();
  state.org = { id: "org-a", name: "Organization A" };
  state.auth = { status: "authed", user: { id: "actor-a", email: "owner@example.test", email_verified: true } };
  state.role = "owner";
  state.GET.mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: state.auth.user.id, email: state.auth.user.email, role: state.role }] };
    if (path.endsWith("/device-approval")) return { data: { mode: "on" } };
    if (path.endsWith("/devices/pending")) return { data: [{ id: "pending-a", name: "Pending phone", user_id: "actor-a", status: "pending", created_at: "2026-10-08T08:00:00Z" }] };
    return { data: [] };
  });
});
afterEach(cleanup);

describe.each(views)("Device $name permission boundary", ({ name, Component, open, table }) => {
  it("keeps an authorized unverified owner's read view without offering policy writes", async () => {
    state.auth = { ...state.auth, user: { ...state.auth.user, email_verified: false } };
    render(<MemoryRouter><Component /></MemoryRouter>);
    await screen.findByRole("table", { name: table });
    expect(screen.getByRole("status").textContent).toContain(`Verify your email to manage device ${name}.`);
    expect(screen.queryByRole("checkbox")).toBeNull();
    if (name === "posture") {
      expect(screen.queryByRole("button", { name: "Disk encryption" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Actions for Disk encryption" })).toBeNull();
    } else {
      fireEvent.click(screen.getByRole("button", { name: "Actions for Pending phone" }));
      expect(screen.queryByRole("menuitem", { name: "Approve" })).toBeNull();
      expect(screen.queryByRole("menuitem", { name: "Reject" })).toBeNull();
    }
    expect(state.POST).not.toHaveBeenCalled();
    expect(state.PUT).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });

  it("withholds policy inventory and mutation controls from a member", async () => {
    state.role = "member";
    render(<MemoryRouter><Component /></MemoryRouter>);
    await screen.findByText(`You do not have permission to manage device ${name}.`);
    expect(screen.queryByRole("table", { name: table })).toBeNull();
    expect(screen.queryByRole("button", { name: open })).toBeNull();
    expect(state.GET.mock.calls.every(([path]) => path.endsWith("/members"))).toBe(true);
    expect(state.POST).not.toHaveBeenCalled();
    expect(state.PUT).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });

  it.each(["actor", "verification"])("withdraws old management inventory and dialogs at every %s-change commit", async (change) => {
    const leaked: boolean[] = [];
    const workspace = () => <MemoryRouter><Profiler id={`device-${name}`} onRender={() => {
      if (state.auth.user.id === "actor-b" || !state.auth.user.email_verified) leaked.push(Boolean(screen.queryByRole("table", { name: table }) || screen.queryByRole("dialog")));
    }}><Component /></Profiler></MemoryRouter>;
    const view = render(workspace());
    fireEvent.click(await screen.findByRole("button", { name: open }));
    if (name === "approvals") fireEvent.click(screen.getByRole("menuitem", { name: "Approve" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
    state.auth = { ...state.auth, user: { ...state.auth.user, ...(change === "actor" ? { id: "actor-b" } : { email_verified: false }) } };
    state.role = "member";
    view.rerender(workspace());
    await screen.findByText(`You do not have permission to manage device ${name}.`);
    expect(leaked.length).toBeGreaterThan(0);
    expect(leaked).not.toContain(true);
    expect(state.POST).not.toHaveBeenCalled();
    expect(state.PUT).not.toHaveBeenCalled();
  });

  it("makes an unavailable permission read retryable without presenting it as a role denial", async () => {
    state.GET.mockResolvedValueOnce({ error: { error: { message: "Membership temporarily unavailable" } } });
    render(<MemoryRouter><Component /></MemoryRouter>);
    await screen.findByRole("alert");
    expect(screen.queryByText(`You do not have permission to manage device ${name}.`)).toBeNull();
    expect(screen.queryByRole("table", { name: table })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByRole("table", { name: table })).toBeTruthy());
  });
});
