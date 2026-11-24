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
    expect(screen.queryByText("Authenticator setup")).toBeNull();
  });
  it("is hidden even when every recovery code is used (the factor is still confirmed)", () => {
    auth.value = { state: { status: "authed", user: { id: "u", email: "a@b.c", email_verified: true, recovery_codes_remaining: 0 } } };
    show();
    expect(screen.queryByText("Authenticator setup")).toBeNull();
  });
  it("is still offered to a user without a confirmed factor", () => {
    auth.value = { state: { status: "authed", user: { id: "u", email: "a@b.c", email_verified: true } } };
    show();
    expect(screen.getByText("Authenticator setup")).toBeTruthy();
  });
  it("is still offered when the account state is unknown (no auth provider)", () => {
    show();
    expect(screen.getByText("Authenticator setup")).toBeTruthy();
  });
});
