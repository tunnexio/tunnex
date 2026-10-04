import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { components } from "@tunnex/shared";
import AppAccessMfaPolicy from "../src/components/AppAccessMfaPolicy";
import AppAccessMfaChallenge from "../src/components/AppAccessMfaChallenge";
import { MfaSettings } from "../src/components/MfaSettings";
import { api } from "../src/lib/api";

const setUser = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ setUser }) }));
vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});
type Application = components["schemas"]["AppAccessApplication"];
const app = { id: "app-1", org_id: "org-1", version: 9, state: "draft", publication_state: "published", require_mfa: false, mfa_freshness_seconds: 900, draft: { name: "Payroll" } } as Application;
afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.GET).mockResolvedValue({ data: { id: "user-1" } } as never);
});
function showPolicy(options: Partial<Parameters<typeof AppAccessMfaPolicy>[0]> = {}) {
  const onChanged = vi.fn(), onReload = vi.fn();
  render(<AppAccessMfaPolicy orgId="org-1" application={app} canManage onChanged={onChanged} onReload={onReload} {...options} />);
  return { onChanged, onReload };
}

describe("application MFA policy", () => {
  it("requires confirmation before changing the current published policy", async () => {
    const { onChanged } = showPolicy();
    fireEvent.click(screen.getByRole("switch", { name: "Require MFA" }));
    expect(api.PATCH).not.toHaveBeenCalled();
    expect(screen.getByText(/already have this application open/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.PATCH).not.toHaveBeenCalled();
    vi.mocked(api.PATCH).mockResolvedValueOnce({ data: { ...app, version: 10, require_mfa: true } } as never);
    fireEvent.click(screen.getByRole("switch", { name: "Require MFA" }));
    fireEvent.click(screen.getByRole("button", { name: "Enable MFA requirement" }));
    await screen.findByText("MFA is now required for this application.");
    expect(api.PATCH).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/mfa-policy", { params: { path: { orgId: "org-1", appId: "app-1" } }, body: { require_mfa: true, expected_version: 9 } });
    expect(onChanged).toHaveBeenCalledWith(expect.objectContaining({ version: 10, require_mfa: true }));
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("keeps organization MFA intact when turning off the application requirement", async () => {
    vi.mocked(api.PATCH).mockResolvedValueOnce({ data: { ...app, version: 10 } } as never);
    showPolicy({ application: { ...app, require_mfa: true } });
    fireEvent.click(screen.getByRole("switch", { name: "Require MFA" }));
    expect(screen.getByText(/Account and organization login requirements remain/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Turn off MFA requirement" }));
    await screen.findByText("The extra MFA requirement is now off for this application.");
    expect(api.PATCH).toHaveBeenCalledWith(expect.stringContaining("/mfa-policy"), expect.objectContaining({ body: { require_mfa: false, expected_version: 9 } }));
  });
  it("does not claim that MFA was changed after a version conflict", async () => {
    vi.mocked(api.PATCH).mockResolvedValueOnce({ error: { error: { code: "version_conflict" } } } as never);
    const { onChanged, onReload } = showPolicy();
    fireEvent.click(screen.getByRole("switch", { name: "Require MFA" }));
    fireEvent.click(screen.getByRole("button", { name: "Enable MFA requirement" }));
    await screen.findByRole("alert");
    expect(onChanged).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("false");
    fireEvent.click(screen.getByRole("button", { name: "Reload application settings" }));
    expect(onReload).toHaveBeenCalledOnce();
  });
  it("does not expose mutation controls to read-only viewers", () => {
    showPolicy({ canManage: false });
    expect(screen.queryByRole("switch")).toBeNull();
    expect(api.PATCH).not.toHaveBeenCalled();
  });
  it("protects unsaved draft edits and archived apps", () => {
    const first = render(<AppAccessMfaPolicy orgId="org-1" application={app} canManage dirty onChanged={vi.fn()} onReload={vi.fn()} />);
    expect(screen.getByRole("switch")).toHaveProperty("disabled", true);
    first.rerender(<AppAccessMfaPolicy orgId="org-1" application={{ ...app, state: "archived" }} canManage onChanged={vi.fn()} onReload={vi.fn()} />);
    expect(screen.getByRole("switch")).toHaveProperty("disabled", true);
  });
});

describe("application MFA verification", () => {
  it("does not treat an unreadable account MFA status as an unenrolled account", async () => {
    vi.mocked(api.GET).mockRejectedValueOnce(new Error("offline"));
    render(<MfaSettings setupLabel="Set up MFA" />);
    expect(await screen.findByRole("button", { name: "Retry MFA status" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Set up MFA" })).toBeNull();
    expect(screen.queryByText("Off")).toBeNull();
    vi.mocked(api.GET).mockResolvedValueOnce({ data: { id: "user-1", recovery_codes_remaining: 0 } } as never);
    fireEvent.click(screen.getByRole("button", { name: "Retry MFA status" }));
    expect(await screen.findByRole("button", { name: "Manage" })).toBeTruthy();
    expect(screen.getByText("On")).toBeTruthy();
  });
  it("does not continue for an invalid code, then reuses the existing factor", async () => {
    const onVerified = vi.fn();
    vi.mocked(api.POST).mockResolvedValueOnce({ error: { error: { message: "Invalid or already used code" } } } as never).mockResolvedValueOnce({ data: { verified_at: "2026-10-04T12:00:00Z" } } as never);
    render(<AppAccessMfaChallenge setupRequired={false} onVerified={onVerified} />);
    fireEvent.change(screen.getByLabelText("Authenticator or recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    await screen.findByText("Invalid or already used code");
    expect(onVerified).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Authenticator or recovery code")).toHaveProperty("value", "");
    fireEvent.change(screen.getByLabelText("Authenticator or recovery code"), { target: { value: "RECOVERY-ONE" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    await waitFor(() => expect(onVerified).toHaveBeenCalledOnce());
    expect(api.POST).toHaveBeenLastCalledWith("/api/v1/auth/mfa/step-up", { body: { code: "RECOVERY-ONE" } });
    expect(api.POST).not.toHaveBeenCalledWith(expect.stringContaining("/enroll"), expect.anything());
  });
  it("keeps application access gated if verification cannot be confirmed", async () => {
    const onVerified = vi.fn();
    vi.mocked(api.POST).mockRejectedValueOnce(new Error("offline"));
    render(<AppAccessMfaChallenge setupRequired={false} onVerified={onVerified} />);
    fireEvent.change(screen.getByLabelText("Authenticator or recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    await screen.findByText(/Could not confirm verification/);
    expect(onVerified).not.toHaveBeenCalled();
  });
  it.each(["unauthenticated", "session_required", "mfa_session_invalid"])("offers a fresh sign-in for %s without replaying the old app launch", async code => {
    const onVerified = vi.fn();
    vi.mocked(api.POST).mockResolvedValueOnce({ error: { error: { code } } } as never);
    render(<AppAccessMfaChallenge setupRequired={false} onVerified={onVerified} />);
    fireEvent.change(screen.getByLabelText("Authenticator or recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify MFA" }));
    const signIn = await screen.findByRole("link", { name: "Sign in again" });
    expect(signIn.getAttribute("href")).toBe("/login?next=%2Fapp-access%2Fmy-applications");
    expect(screen.queryByLabelText("Authenticator or recovery code")).toBeNull();
    expect(onVerified).not.toHaveBeenCalled();
    expect(api.POST).toHaveBeenCalledTimes(1);
  });
  it("offers fresh sign-in when account MFA status rejects an expired parent", async () => {
    vi.mocked(api.GET).mockResolvedValueOnce({ error: { error: { code: "unauthenticated" } } } as never);
    render(<MfaSettings setupLabel="Set up MFA" signInReturnTo="/app-access/my-applications" />);
    expect((await screen.findByRole("link", { name: "Sign in again" })).getAttribute("href")).toBe("/login?next=%2Fapp-access%2Fmy-applications");
    expect(screen.queryByRole("button", { name: "Retry MFA status" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Set up MFA" })).toBeNull();
    expect(screen.queryByText("Off")).toBeNull();
  });
  it("recovers from a parent expiring during enrollment without continuing the app", async () => {
    const onEnrolled = vi.fn();
    vi.mocked(api.POST).mockResolvedValueOnce({ data: { otpauth_uri: "otpauth://totp/Test?secret=TEST", secret: "TEST" } } as never).mockResolvedValueOnce({ error: { error: { code: "mfa_session_invalid" } } } as never);
    render(<MfaSettings setupLabel="Set up MFA" onEnrolled={onEnrolled} signInReturnTo="/app-access/my-applications" />);
    fireEvent.click(await screen.findByRole("button", { name: "Set up MFA" }));
    fireEvent.change(await screen.findByLabelText("6-digit code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & turn on" }));
    expect(await screen.findByRole("link", { name: "Sign in again" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(onEnrolled).not.toHaveBeenCalled();
  });
  it("requires fresh sign-in after turning off the shared account factor", async () => {
    vi.mocked(api.GET).mockResolvedValueOnce({ data: { id: "user-1", recovery_codes_remaining: 2 } } as never);
    vi.mocked(api.DELETE).mockResolvedValueOnce({ response: { status: 204 } } as never);
    render(<MfaSettings />);
    fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
    fireEvent.click(screen.getByRole("button", { name: "Turn off two-factor authentication" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(await screen.findByRole("link", { name: "Sign in again" })).toBeTruthy();
    expect(screen.getByText("Off")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Set up" })).toBeNull();
    expect(api.GET).toHaveBeenCalledTimes(1);
  });
  it("offers the shared account setup for a user without a factor", async () => {
    const onVerified = vi.fn();
    render(<AppAccessMfaChallenge setupRequired onVerified={onVerified} />);
    expect(await screen.findByRole("button", { name: "Set up MFA" })).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Use an existing authenticator" }));
    expect(screen.getByLabelText("Authenticator or recovery code")).toBeTruthy();
    expect(onVerified).not.toHaveBeenCalled();
  });
  it("shows an invalid setup code inside the open dialog and keeps access gated", async () => {
    const onEnrolled = vi.fn();
    vi.mocked(api.POST).mockResolvedValueOnce({ data: { otpauth_uri: "otpauth://totp/Test?secret=TEST", secret: "TEST" } } as never).mockResolvedValueOnce({ error: { error: { code: "mfa_invalid", message: "Invalid authenticator code" } } } as never);
    render(<MfaSettings setupLabel="Set up MFA" onEnrolled={onEnrolled} />);
    fireEvent.click(await screen.findByRole("button", { name: "Set up MFA" }));
    fireEvent.change(await screen.findByLabelText("6-digit code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & turn on" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Invalid authenticator code");
    expect(screen.getByRole("dialog", { name: "Set up two-factor authentication" }).contains(screen.getByRole("alert"))).toBe(true);
    expect(onEnrolled).not.toHaveBeenCalled();
    expect(api.GET).toHaveBeenCalledTimes(1);
  });
  it("does not release app access before recovery codes have been acknowledged", async () => {
    const onEnrolled = vi.fn();
    vi.mocked(api.POST).mockResolvedValueOnce({ data: { otpauth_uri: "otpauth://totp/Test?secret=TEST", secret: "TEST" } } as never).mockResolvedValueOnce({ data: { recovery_codes: ["RECOVERY-ONE"] } } as never);
    render(<MfaSettings setupLabel="Set up MFA" onEnrolled={onEnrolled} />);
    fireEvent.click(await screen.findByRole("button", { name: "Set up MFA" }));
    fireEvent.change(await screen.findByLabelText("6-digit code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & turn on" }));
    await screen.findByRole("dialog", { name: "Save your recovery codes" });
    expect(onEnrolled).not.toHaveBeenCalled();
    expect(api.GET).toHaveBeenCalledTimes(1);
    vi.mocked(api.GET).mockResolvedValueOnce({ data: { id: "user-1", recovery_codes_remaining: 1 } } as never);
    fireEvent.click(screen.getByRole("checkbox", { name: /I have saved my recovery codes/ }));
    fireEvent.click(screen.getByRole("button", { name: "I’ve saved it" }));
    await waitFor(() => expect(onEnrolled).toHaveBeenCalledOnce());
  });
});
