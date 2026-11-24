import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerAccessInstallationSettings } from "../src/components/ServerAccessInstallationSettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PATCH: vi.fn(), POST: vi.fn() }));
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

  it("explains when the administrator cannot re-authenticate", async () => {
    api.GET.mockResolvedValue({ data: view({ reauthentication: { password: false, mfa: false, available: false } }) });
    show();
    expect(await toggle()).toHaveProperty("disabled", true);
    expect(screen.getByText(/set up MFA in your account settings first/)).toBeTruthy();
    await waitFor(() => expect(api.PATCH).not.toHaveBeenCalled());
  });
});
