import { afterEach, describe, it, expect, vi } from "vitest";
import {
  cleanup,
  render,
  screen,
  fireEvent,
  waitFor,
} from "@testing-library/react";
import {
  SsoConnections,
  type SsoConnectionTransport,
} from "../src/components/SsoConnections";
const c = {
  id: "22222222-2222-4222-8222-222222222222",
  org_id: "org",
  name: "Workforce",
  provider: "okta" as const,
  issuer_url: "https://company.okta.com",
  client_id: "client",
  enabled: false,
  revision: 1,
  verified: false,
  updated_at: "2026-09-06T00:00:00Z",
  callback_url: "https://vpn.example.com/api/v1/auth/sso-connections/callback",
  login_url: "https://vpn.example.com/login?connection=connection",
};
function transport(): SsoConnectionTransport {
  return {
    list: vi.fn().mockResolvedValue([c]),
    save: vi.fn(),
    test: vi.fn(),
    activate: vi.fn(),
  };
}
afterEach(cleanup);
describe("custom SSO connections", () => {
  it("does not offer enabling an unverified connection", async () => {
    const t = transport();
    render(<SsoConnections orgId="org" canEdit transport={t} />);
    fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
    expect(
      screen.queryByRole("button", { name: /Enable connection/ }),
    ).toBeNull();
    expect(screen.getByRole("button", { name: /Test sign-in/ })).toBeTruthy();
    expect(t.activate).not.toHaveBeenCalled();
  });
  it("a failed read does not masquerade as an empty configuration", async () => {
    const t = transport();
    t.list = vi.fn().mockRejectedValue(new Error("Cannot read settings"));
    render(<SsoConnections orgId="org" canEdit transport={t} />);
    await screen.findByRole("alert");
    expect(screen.queryByText(/No custom connections yet/)).toBeNull();
    expect(
      (
        screen.getByRole("button", {
          name: /Add connection/,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
  it("read-only users cannot start a test", async () => {
    render(
      <SsoConnections orgId="org" canEdit={false} transport={transport()} />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
    expect(
      (
        screen.getByRole("button", {
          name: /Test sign-in/,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
  it("saving credentials resets verification and does not enable", async () => {
    const t = transport();
    t.list = vi.fn().mockResolvedValue([{ ...c, verified: true }]);
    t.save = vi.fn().mockResolvedValue({ ...c, revision: 2 });
    render(<SsoConnections orgId="org" canEdit transport={t} />);
    fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit configuration" }));
    fireEvent.click(
      screen.getByRole("button", { name: "Save and continue →" }),
    );
    await waitFor(() => expect(t.save).toHaveBeenCalled());
    await screen.findByRole("button", { name: "Test sign-in ↗" });
    expect(t.activate).not.toHaveBeenCalled();
  });
});
it("blocks switching editors while a save is pending", async () => {
  const t = transport();
  t.list = vi.fn().mockResolvedValue([{ ...c, verified: true }]);
  t.save = vi.fn().mockReturnValue(new Promise(() => {}));
  render(<SsoConnections orgId="org" canEdit transport={t} />);
  fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
  fireEvent.click(screen.getByRole("button", { name: "Edit configuration" }));
  fireEvent.click(screen.getByRole("button", { name: "Save and continue →" }));
  await waitFor(() => expect(t.save).toHaveBeenCalled());
  expect(
    screen.getByRole("button", { name: "Manage" }).matches(":disabled"),
  ).toBe(true);
  expect(
    screen.getByRole("button", { name: /Add connection/ }).matches(":disabled"),
  ).toBe(true);
});
