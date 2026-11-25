import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InlineTerminalMfa } from "../src/components/InlineTerminalMfa";

const auth = vi.hoisted(() => ({ value: null as null | { state: { status: string; user?: Record<string, unknown> } } }));
vi.mock("../src/lib/auth", () => ({ useOptionalAuth: () => auth.value }));
vi.mock("../src/components/MfaSettings", () => ({ MfaSettings: () => <div>Setup ceremony</div> }));
afterEach(() => { cleanup(); auth.value = null; });
const show = () => render(<InlineTerminalMfa action="Test action" onVerified={() => {}} onCancel={() => {}} />);

describe("InlineTerminalMfa authenticator setup offer", () => {
  it("is hidden for a user who already has a confirmed factor", () => {
    auth.value = { state: { status: "authed", user: { id: "u", email: "a@b.c", email_verified: true, recovery_codes_remaining: 8 } } };
    show();
    expect(screen.getByLabelText("Authenticator or recovery code")).toBeTruthy();
    expect(screen.queryByText("Set up an authenticator app")).toBeNull();
  });
  it("is hidden even when every recovery code is used (the factor is still confirmed)", () => {
    auth.value = { state: { status: "authed", user: { id: "u", email: "a@b.c", email_verified: true, recovery_codes_remaining: 0 } } };
    show();
    expect(screen.queryByText("Set up an authenticator app")).toBeNull();
  });
  it("is still offered to a user without a confirmed factor", () => {
    auth.value = { state: { status: "authed", user: { id: "u", email: "a@b.c", email_verified: true } } };
    show();
    expect(screen.getByText("Set up an authenticator app")).toBeTruthy();
  });
  it("is still offered when the account state is unknown (no auth provider)", () => {
    show();
    expect(screen.getByText("Set up an authenticator app")).toBeTruthy();
  });
});
describe("SA-UX-2 I1", () => {
  it("leads with setup, already open, when the account has no factor", () => {
    auth.value = { state: { status: "authed", user: { id: "u", email: "a@b.c", email_verified: true } } };
    show();
    expect(screen.getByText(/Your account has no authenticator app yet/)).toBeTruthy();
    expect(screen.getByText("Set up an authenticator app").closest("details")?.open).toBe(true);
    expect(screen.getByText("Setup ceremony")).toBeTruthy();
  });
});
