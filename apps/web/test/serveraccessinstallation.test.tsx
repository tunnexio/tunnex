import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerAccessInstallationSettings } from "../src/components/ServerAccessInstallationSettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PATCH: vi.fn(), POST: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
const endpoint = "/api/v1/admin/server-access/installation";
const view = (overrides = {}) => ({ enabled: false, effective: false, locked: false, source: "environment", version: 0, reauthentication: { password: true, mfa: false, available: true }, ...overrides });
const show = (canEdit = true) => render(<ServerAccessInstallationSettings canEdit={canEdit} />);
const toggle = () => screen.findByRole("switch", { name: "Server Access for this installation" });

beforeEach(() => { vi.resetAllMocks(); api.GET.mockResolvedValue({ data: view() }); });
afterEach(cleanup);

describe("installation Server Access setting", () => {
  it("shows the environment seed and turns it on with the current password", async () => {
    api.PATCH.mockResolvedValue({ data: view({ enabled: true, effective: true, source: "database", version: 1 }) });
    show();
    fireEvent.click(await toggle());
    expect(screen.getByText(/Source: Server environment/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on Server Access" }));
    await screen.findByText(/Server Access is on for this installation/);
    expect(api.PATCH).toHaveBeenCalledExactlyOnceWith(endpoint, { body: { enabled: true, expected_version: 0, current_password: "secret" } });
    expect((await toggle()).getAttribute("aria-checked")).toBe("true");
    expect(screen.getByText(/Source: Saved settings/)).toBeTruthy();
  });

  it("runs the MFA step-up when the server asks for it, then retries once", async () => {
    api.GET.mockResolvedValue({ data: view({ enabled: true, effective: true, source: "database", version: 3, reauthentication: { password: false, mfa: true, available: true } }) });
    api.PATCH.mockResolvedValueOnce({ error: { error: { code: "mfa_step_up_required", message: "Verify MFA" } } })
      .mockResolvedValueOnce({ data: view({ source: "database", version: 4, ended_sessions: 2, reauthentication: { password: false, mfa: true, available: true } }) });
    api.POST.mockResolvedValue({ data: { verified_at: new Date().toISOString() } });
    show();
    fireEvent.click(await toggle());
    fireEvent.click(screen.getByRole("button", { name: "Turn off Server Access" }));
    fireEvent.change(await screen.findByLabelText("Authenticator or recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));
    await screen.findByText(/2 active sessions were ended/);
    expect(api.PATCH).toHaveBeenCalledTimes(2);
    expect(api.PATCH).toHaveBeenLastCalledWith(endpoint, { body: { enabled: false, expected_version: 3 } });
  });

  it("cannot be turned on while locked by the server environment", async () => {
    api.GET.mockResolvedValue({ data: view({ locked: true }) });
    show();
    expect(await toggle()).toHaveProperty("disabled", true);
    expect(screen.getByText(/TUNNEX_SERVER_ACCESS_LOCKED is set on the server/)).toBeTruthy();
    expect(screen.getByText(/locked by the server environment/)).toBeTruthy();
  });

  it("says no sessions were open instead of '0 active sessions were ended'", async () => {
    api.GET.mockResolvedValue({ data: view({ enabled: true, effective: true, source: "database", version: 2 }) });
    api.PATCH.mockResolvedValue({ data: view({ source: "database", version: 3, ended_sessions: 0 }) });
    show();
    fireEvent.click(await toggle());
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn off Server Access" }));
    expect(await screen.findByText(/New sessions are refused; no sessions were open\./)).toBeTruthy();
  });

  it("shows the enforced Off state, not a saved On, while locked (found in the local walk)", async () => {
    api.GET.mockResolvedValue({ data: view({ locked: true, enabled: true, source: "database", version: 3 }) });
    show();
    const control = await toggle();
    expect(control.getAttribute("aria-checked")).toBe("false");
    expect(control).toHaveProperty("disabled", true);
    expect(screen.getByText(/Saved setting: On\. It applies again when the lock is removed/)).toBeTruthy();
  });

  it("explains when the administrator cannot re-authenticate", async () => {
    api.GET.mockResolvedValue({ data: view({ reauthentication: { password: false, mfa: false, available: false } }) });
    show();
    expect(await toggle()).toHaveProperty("disabled", true);
    expect(screen.getByText(/Set up an authenticator app in/)).toBeTruthy();
    await waitFor(() => expect(api.PATCH).not.toHaveBeenCalled());
  });
});

describe("one action for installation and organization (SA-UX-2 item 6)", () => {
  const orgWorkspace = { enabled: false, can_manage: true, recording_retention_days: 30, mfa_freshness_seconds: 600, recording_max_session_bytes: 1048576, recording_max_org_bytes: 33554432 };
  beforeEach(() => {
    api.GET.mockImplementation(async (path: string) => ({ data: path === endpoint ? view() : orgWorkspace }));
    api.PATCH.mockResolvedValue({ data: view({ enabled: true, effective: true, source: "database", version: 1 }) });
    api.PUT.mockResolvedValue({ data: { status: "updated" } });
  });
  const turnOn = async () => {
    fireEvent.click(await toggle());
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "secret" } });
  };
  it("also turns the current organization on through its own endpoint when checked (default)", async () => {
    render(<ServerAccessInstallationSettings canEdit organization={{ id: "org-a", name: "Acme" }} />);
    await turnOn();
    expect((screen.getByLabelText(/Also turn on Server Access for Acme/) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Turn on Server Access" }));
    await screen.findByText(/on for this installation and for Acme/);
    expect(api.PATCH).toHaveBeenCalledTimes(1);
    expect(api.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/server-access", { params: { path: { orgId: "org-a" } }, body: { enabled: true, recording_retention_days: 30, mfa_freshness_seconds: 600, recording_max_session_bytes: 1048576, recording_max_org_bytes: 33554432 } });
  });
  it("only changes the installation when unchecked", async () => {
    render(<ServerAccessInstallationSettings canEdit organization={{ id: "org-a", name: "Acme" }} />);
    await turnOn();
    fireEvent.click(screen.getByLabelText(/Also turn on Server Access for Acme/));
    fireEvent.click(screen.getByRole("button", { name: "Turn on Server Access" }));
    await screen.findByText(/Each organization still turns it on/);
    expect(api.PUT).not.toHaveBeenCalled();
  });
  it("reports an organization refusal separately", async () => {
    api.PUT.mockResolvedValue({ error: { error: { code: "forbidden", message: "Not allowed here." } } });
    render(<ServerAccessInstallationSettings canEdit organization={{ id: "org-a", name: "Acme" }} />);
    await turnOn();
    fireEvent.click(screen.getByRole("button", { name: "Turn on Server Access" }));
    await screen.findByText(/on for this installation, but turning it on for Acme failed: Not allowed here\. Use Settings → Features/);
  });
  it("offers no organization option when the administrator cannot manage it", async () => {
    show();
    fireEvent.click(await toggle());
    expect(screen.queryByLabelText(/Also turn on Server Access/)).toBeNull();
  });
});
