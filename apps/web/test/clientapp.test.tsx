import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { ClientApp } from "../src/client/ClientApp";

// ⛔ THE CLIENT SURFACE HAD NO TEST AT ALL, AND THAT IS HOW THE CONNECT BUTTON GOT INTO A STATE
// WHERE IT COULD ONLY THROW.
//
// `ClientApp` asked `tunnel.status()` and never `auth.status()`. A device with no credential
// therefore rendered "Disconnected" — a healthy idle state — with a Connect button. Pressing it
// threw `not_authenticated` out of the main process into a terminal log; the window did not move.
//
// > **THE BUTTON WAS NOT BROKEN. IT WAS OFFERED IN A STATE WHERE IT CANNOT WORK** — the same defect
// > as a revoked device being shown "Connect", which the state model already refuses by returning a
// > null action. The model was right; nothing was asking it the right question.
//
// The bridge is faked here rather than mocked at the module boundary: `desktop()` reads
// `window.tunnex`, which is exactly what the preload sets, so a fake object IS the contract.

type Bridge = NonNullable<Window["tunnex"]>;

function fakeBridge(over: {
  loggedIn?: boolean;
  expired?: boolean;
  up?: () => Promise<unknown>;
}): Bridge {
  return {
    auth: {
      login: vi.fn().mockResolvedValue({ fingerprint: "fp", expiresAt: "" }),
      logout: vi.fn().mockResolvedValue(undefined),
      removeDevice: vi.fn().mockResolvedValue(true),
      status: vi.fn().mockResolvedValue({
        loggedIn: over.loggedIn ?? true,
        expired: over.expired ?? false,
        fingerprint: "abcdef0123",
        secureStorage: true,
      }),
    },
    diag: {
      logPath: vi.fn().mockResolvedValue("/tmp/main.log"),
      openLogs: vi.fn().mockResolvedValue(undefined),
      readLog: vi.fn().mockResolvedValue("[info] log line"),
      exportLog: vi.fn().mockResolvedValue("/tmp/export.txt"),
      appInfo: vi.fn().mockResolvedValue({
        version: "0.1.0",
        update: {
          kind: "disabled",
          reason: "Automatic updates are off in this build.",
          detail: "not signed yet",
        },
      }),
      checkRelease: vi.fn().mockResolvedValue({ kind: "unavailable" }),
      openReleaseDownload: vi.fn().mockResolvedValue(undefined),
    },
    config: {
      getServerUrl: vi.fn().mockResolvedValue("https://vpn.example.com"),
      setServerUrl: vi.fn(),
    },
    tunnel: {
      up: over.up ?? vi.fn().mockResolvedValue({ state: "up" }),
      down: vi.fn().mockResolvedValue(undefined),
      status: vi.fn().mockResolvedValue({ state: "down" }),
      onStatusChanged: vi.fn().mockReturnValue(() => {}),
      managedOrganizations: vi.fn().mockResolvedValue({ organizations: [], enrollmentLocked: false }),
      selectManagedOrganization: vi.fn().mockResolvedValue({ organizations: [], enrollmentLocked: false }),
      onOrganizationSelectionRequired: vi.fn().mockReturnValue(() => {}),
      importConfig: vi
        .fn()
        .mockResolvedValue({ id: "profile-a", name: "profile-a", address: "10.99.0.7/32", endpoint: "vpn.example.com:51820", fullTunnel: false, active: true }),
      importedInfo: vi.fn().mockResolvedValue(null),
      importedProfiles: vi.fn().mockResolvedValue([]),
      selectImportedProfile: vi.fn().mockResolvedValue([]),
      useManagedProfile: vi.fn().mockResolvedValue([]),
      forgetImported: vi.fn().mockResolvedValue([]),
    },
  } as unknown as Bridge;
}

async function openDrawerPage(name: "Home" | "Profiles" | "Settings" | "Logs" | "Help") {
  fireEvent.click(await screen.findByRole("button", { name: "Open navigation" }));
  fireEvent.click(await screen.findByRole("button", { name }));
}

function mutableTunnelStatus(
  bridge: Bridge,
  initial: "up" | "down",
): { push(state: "up" | "down"): void } {
  let state = initial;
  let listener: Parameters<Bridge["tunnel"]["onStatusChanged"]>[0] = () => {};
  bridge.tunnel.status = vi.fn(async () => ({ state }));
  bridge.tunnel.onStatusChanged = vi.fn((next) => {
    listener = next;
    return () => {};
  });
  return {
    push(next) {
      state = next;
      listener({ state: next });
    },
  };
}

beforeEach(() => {
  // jsdom has no canvas 2D context; the hyperdrive draws through it and must not throw.
  HTMLCanvasElement.prototype.getContext = vi.fn().mockReturnValue(null);
});

afterEach(() => {
  // ⚠ EXPLICIT. Auto-cleanup only runs with vitest globals; without it every render STACKS and the
  // queries find two headings — which reads as a component bug and is a harness bug.
  cleanup();
  delete window.tunnex;
  vi.restoreAllMocks();
});

describe("the client asks the SESSION, not only the tunnel", () => {
  it("⛔ no credential renders Not signed in — never a Connect button that can only throw", async () => {
    window.tunnex = fakeBridge({ loggedIn: false });
    render(<ClientApp />);
    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain(
        "Not signed in",
      ),
    );
    // The verb is browser re-auth. It must NOT be "Connect", and it must NOT collect a password:
    // the wireframe's own rule is that MFA touches the client only via browser re-auth.
    const btn = screen.getByRole("button", {
      name: /sign in with your browser/i,
    });
    expect(btn).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
  });

  it("a valid session shows the tunnel state, so auth does not mask a working client", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain("Disconnected"),
    );
  });

  it("an EXPIRED session is the design's own state, not signed-out", async () => {
    // Main reports an expired credential as not logged in plus the more
    // specific expired flag. Keep this fixture wire-accurate so the renderer
    // cannot pass against an impossible status combination.
    window.tunnex = fakeBridge({ loggedIn: false, expired: true });
    render(<ClientApp />);
    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain(
        "Session expired",
      ),
    );
  });

  it.each([
    { loggedIn: false, expired: false, heading: "Not signed in" },
    { loggedIn: false, expired: true, heading: "Session expired" },
  ])(
    "a failed login refreshes tunnel truth before restoring $heading auth truth",
    async ({ loggedIn, expired, heading }) => {
      const b = fakeBridge({ loggedIn, expired });
      const transport = mutableTunnelStatus(b, "down");
      b.auth.login = vi.fn(async () => {
        // Main may truthfully publish Down before a later PKCE or credential
        // replacement failure. The renderer must still apply auth truth last.
        transport.push("down");
        throw new Error("login_cancelled");
      });
      vi.spyOn(console, "error").mockImplementation(() => {});
      window.tunnex = b;
      render(<ClientApp />);

      expect(await screen.findByRole("heading", { name: heading })).toBeTruthy();
      fireEvent.click(
        screen.getByRole("button", { name: /sign in with your browser/i }),
      );

      expect((await screen.findByRole("alert")).textContent).toContain(
        "That action did not complete. Try again or check Logs.",
      );
      expect(screen.getByRole("heading", { name: heading })).toBeTruthy();
      expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
    },
  );

  it("⛔ a not_authenticated rejection becomes a STATE — the exact error that reached the log", async () => {
    // Reproduces the founder's terminal output:
    //   Error occurred in handler for 'tunnel:up': Error: not_authenticated
    // Before the fix this rejection was unhandled and the surface stayed on "Disconnected".
    const up = vi.fn().mockRejectedValue(new Error("not_authenticated"));
    window.tunnex = fakeBridge({ loggedIn: true, up });
    render(<ClientApp />);
    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain("Disconnected"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain(
        "Not signed in",
      ),
    );
  });

  it("any OTHER failure is shown as safe, actionable copy rather than an IPC detail", async () => {
    const up = vi.fn().mockRejectedValue(new Error("helper_unreachable"));
    window.tunnex = fakeBridge({ loggedIn: true, up });
    render(<ClientApp />);
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Connect" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "That action did not complete. Try again or check Logs.",
    );
  });

  it("⛔ sign-out is REACHABLE — the step-3 flip left it only in the web dashboard", async () => {
    // DesktopSettings (sign out / change server) lives in the SPA the client no longer loads, so
    // the capability existed with no call site. Without a reset there is no way to re-authenticate.
    const b = fakeBridge({ loggedIn: true });
    window.tunnex = b;
    render(<ClientApp />);
    // ⛔ REACHED THROUGH THE NAV, NOT ASSUMED PRESENT. The control moved to its own pane, so the
    // test now proves the PATH to it as well as the control — which is what "reachable" means.
    await openDrawerPage("Settings");
    const out = await screen.findByRole("button", { name: /sign out/i });
    fireEvent.click(out);
    await waitFor(() => expect(b.auth.logout).toHaveBeenCalled());
  });

  it("keeps Connected and signed in when logout teardown is refused", async () => {
    const b = fakeBridge({ loggedIn: true });
    mutableTunnelStatus(b, "up");
    b.auth.logout = vi.fn().mockRejectedValue(new Error("helper_teardown_refused"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy(),
    );
    await openDrawerPage("Settings");
    fireEvent.click(await screen.findByRole("button", { name: /sign out/i }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeTruthy();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy();
  });

  it("shows Disconnected but remains honestly signed in when credential clear fails after down", async () => {
    const b = fakeBridge({ loggedIn: true });
    const transport = mutableTunnelStatus(b, "up");
    b.auth.logout = vi.fn(async () => {
      transport.push("down");
      throw new Error("insecure_storage");
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy(),
    );
    await openDrawerPage("Settings");
    fireEvent.click(await screen.findByRole("button", { name: /sign out/i }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeTruthy();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy();
  });

  it.each([
    "helper_asset_missing",
    "create_device_failed: 500",
    "tunnel_up_failed",
  ])("keeps a failed reconnect Disconnected after %s", async (failure) => {
    const b = fakeBridge({ loggedIn: true });
    const transport = mutableTunnelStatus(b, "up");
    b.tunnel.down = vi.fn(async () => {
      transport.push("down");
    });
    b.tunnel.up = vi.fn(async () => {
      transport.push("down");
      throw new Error(failure);
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Disconnect" })).toBeTruthy(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy();
  });

  it("keeps Connected when plain Disconnect is refused", async () => {
    const b = fakeBridge({ loggedIn: true });
    mutableTunnelStatus(b, "up");
    b.tunnel.down = vi.fn().mockRejectedValue(new Error("helper_teardown_refused"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Disconnect" })).toBeTruthy(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy();
  });
});

describe("managed device lifecycle", () => {
  it("reports a completed explicit removal as success and never signs out", async () => {
    const b = fakeBridge({ loggedIn: true });
    window.tunnex = b;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ClientApp />);
    await openDrawerPage("Settings");
    fireEvent.click(await screen.findByRole("button", { name: "Remove device" }));
    await waitFor(() => expect(b.auth.removeDevice).toHaveBeenCalledTimes(1));
    expect(b.auth.logout).not.toHaveBeenCalled();

    await openDrawerPage("Profiles");
    expect(
      await screen.findByText(
        "Device removed. Choose an organization for the next enrollment.",
      ),
    ).toBeTruthy();
  });

  it("surfaces explicit abandon and re-enroll for an unresolved recovery anchor", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi
      .fn()
      .mockResolvedValueOnce({
        organizations: [
          { id: "org-recovery", name: "Recovery org", slug: "recovery", selected: true },
          { id: "org-other", name: "Other org", slug: "other", selected: false },
        ],
        enrollmentLocked: true,
        enrollmentRecoveryRequired: true,
      })
      .mockResolvedValue({
        organizations: [
          { id: "org-recovery", name: "Recovery org", slug: "recovery", selected: false },
          { id: "org-other", name: "Other org", slug: "other", selected: false },
        ],
        enrollmentLocked: false,
        enrollmentRecoveryRequired: false,
      });
    window.tunnex = b;
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ClientApp />);
    await openDrawerPage("Settings");

    fireEvent.click(await screen.findByRole("button", { name: "Abandon and re-enroll" }));
    await waitFor(() => expect(b.auth.removeDevice).toHaveBeenCalledTimes(1));
    expect(confirm).toHaveBeenCalledWith(
      "Abandon this unfinished enrollment and enroll again? Any same-owner active or pending device will be revoked first.",
    );

    await openDrawerPage("Profiles");
    expect(
      await screen.findByText(
        "Unfinished enrollment cleared. The next connection will create a new device key.",
      ),
    ).toBeTruthy();
    expect(b.auth.logout).not.toHaveBeenCalled();
  });

  it("shows a foreign-enrollment block, prevents managed actions, and lets the original account return", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [
        { id: "current-user-org-a", name: "Current user A", slug: "a", selected: true },
        { id: "current-user-org-b", name: "Current user B", slug: "b", selected: false },
      ],
      enrollmentLocked: false,
      enrollmentRecoveryRequired: false,
      enrollmentBlockedByOtherUser: true,
    });
    window.tunnex = b;
    const confirm = vi.spyOn(window, "confirm");
    render(<ClientApp />);
    expect(await screen.findByText(/An unfinished enrollment belongs to another account/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Connect" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(b.tunnel.up).not.toHaveBeenCalled();

    await openDrawerPage("Profiles");
    const select = screen.getByRole("button", { name: "Use Current user B" }) as HTMLButtonElement;
    expect(select.disabled).toBe(true);
    fireEvent.click(select);
    expect(b.tunnel.selectManagedOrganization).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Abandon and re-enroll" })).toBeNull();
    await openDrawerPage("Settings");
    const remove = screen.getByRole("button", { name: "Remove device" }) as HTMLButtonElement;
    expect(remove.disabled).toBe(true);
    fireEvent.click(remove);
    expect(confirm).not.toHaveBeenCalled();
    expect(b.auth.removeDevice).not.toHaveBeenCalled();

    b.auth.status = vi.fn().mockResolvedValue({ loggedIn: false, secureStorage: true });
    fireEvent.click(screen.getByRole("button", { name: "Sign out to recover enrollment" }));
    await waitFor(() => expect(b.auth.logout).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByText(/An unfinished enrollment belongs to another account/)).toBeNull());
    await openDrawerPage("Home");
    b.auth.status = vi.fn().mockResolvedValue({ loggedIn: true, secureStorage: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [], enrollmentLocked: true, enrollmentRecoveryRequired: true, enrollmentBlockedByOtherUser: false,
    });
    fireEvent.click(screen.getByRole("button", { name: /Sign in with your browser/ }));
    await waitFor(() => expect(b.tunnel.managedOrganizations).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/An unfinished enrollment belongs to another account/)).toBeNull();
  });

  it("reports a late foreign-enrollment removal refusal honestly without absence or retry copy", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.auth.removeDevice = vi.fn().mockRejectedValue(new Error("managed_enrollment_owner_mismatch"));
    window.tunnex = b;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ClientApp />);
    await openDrawerPage("Settings");
    fireEvent.click(screen.getByRole("button", { name: "Remove device" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Sign out, then sign in with the account that started it");
    expect(screen.queryByText(/No enrolled managed device was found|The saved enrollment was kept; try Remove device again|Unfinished enrollment cleared/)).toBeNull();
    expect(b.auth.logout).not.toHaveBeenCalled();
  });

  it("keeps imported connections and disconnection available while another account owns enrollment", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [], enrollmentLocked: false, enrollmentRecoveryRequired: false, enrollmentBlockedByOtherUser: true,
    });
    b.tunnel.importedProfiles = vi.fn().mockResolvedValue([
      { id: "imported", name: "Existing imported profile", fullTunnel: false, active: true },
    ]);
    const transport = mutableTunnelStatus(b, "down");
    window.tunnex = b;
    render(<ClientApp />);
    await screen.findByText(/An unfinished enrollment belongs to another account/);
    const connect = screen.getByRole("button", { name: "Connect" }) as HTMLButtonElement;
    expect(connect.disabled).toBe(false);
    fireEvent.click(connect);
    await waitFor(() => expect(b.tunnel.up).toHaveBeenCalledTimes(1));
    await act(async () => transport.push("up"));
    const disconnect = screen.getByRole("button", { name: "Disconnect" }) as HTMLButtonElement;
    expect(disconnect.disabled).toBe(false);
    fireEvent.click(disconnect);
    await waitFor(() => expect(b.tunnel.down).toHaveBeenCalledTimes(1));
  });

  it("keeps the live state and never claims success when main reports no device", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.auth.removeDevice = vi.fn().mockResolvedValue(false);
    b.tunnel.status = vi.fn().mockResolvedValue({ state: "up" });
    window.tunnex = b;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain("Connected"),
    );
    await openDrawerPage("Settings");
    fireEvent.click(await screen.findByRole("button", { name: "Remove device" }));

    expect(
      await screen.findByText(
        "No enrolled managed device was found. Nothing was removed.",
      ),
    ).toBeTruthy();
    expect(
      screen.queryByText(
        "Device removed. Choose an organization for the next enrollment.",
      ),
    ).toBeNull();

    await openDrawerPage("Home");
    expect(screen.getByRole("heading").textContent).toContain("Connected");
  });

  it("keeps the live state and reports an error when device removal is refused", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.auth.removeDevice = vi.fn().mockRejectedValue(new Error("helper_teardown_refused"));
    b.tunnel.status = vi.fn().mockResolvedValue({ state: "up" });
    window.tunnex = b;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.spyOn(console, "error").mockImplementation(() => {});
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("heading").textContent).toContain("Connected"),
    );
    await openDrawerPage("Settings");
    fireEvent.click(await screen.findByRole("button", { name: "Remove device" }));

    expect(
      await screen.findByText(
        "Device removal did not finish. The saved enrollment was kept; try Remove device again or check Logs.",
      ),
    ).toBeTruthy();
    expect(
      screen.queryByText(
        "Device removed. Choose an organization for the next enrollment.",
      ),
    ).toBeNull();

    await openDrawerPage("Home");
    expect(screen.getByRole("heading").textContent).toContain("Connected");
  });

  it.each([
    ["server revoke", "revoke_device_failed: 503"],
    ["local clear", "insecure_storage"],
  ])("keeps confirmed-down truth and retryable enrollment when %s fails", async (_stage, failure) => {
    const b = fakeBridge({ loggedIn: true });
    const transport = mutableTunnelStatus(b, "up");
    b.auth.removeDevice = vi.fn(async () => {
      transport.push("down");
      throw new Error(failure);
    });
    window.tunnex = b;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.spyOn(console, "error").mockImplementation(() => {});
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy(),
    );
    await openDrawerPage("Settings");
    fireEvent.click(await screen.findByRole("button", { name: "Remove device" }));

    expect(
      await screen.findByText(
        "Device removal did not finish. The saved enrollment was kept; try Remove device again or check Logs.",
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/Disconnect it/i)).toBeNull();
    expect(
      screen.queryByText(
        "Device removed. Choose an organization for the next enrollment.",
      ),
    ).toBeNull();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy();
  });
});

describe("managed organization selection", () => {
  it("shows every organization when a multi-organization account has no selection", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [
        { id: "org-old", name: "Older organization", slug: "older", selected: false },
        { id: "org-clean", name: "Clean test org", slug: "clean-test", selected: false },
      ],
      enrollmentLocked: false,
    });
    window.tunnex = b;
    render(<ClientApp />);

    await openDrawerPage("Profiles");

    expect(await screen.findByText("Older organization")).toBeTruthy();
    expect(screen.getByText("Clean test org")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Use Older organization" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Use Clean test org" })).toBeTruthy();
  });

  it("selects an organization through main and renders the returned selection", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [
        { id: "org-old", name: "Older organization", slug: "older", selected: false },
        { id: "org-clean", name: "Clean test org", slug: "clean-test", selected: false },
      ],
      enrollmentLocked: false,
    });
    b.tunnel.selectManagedOrganization = vi.fn().mockResolvedValue({
      organizations: [
        { id: "org-old", name: "Older organization", slug: "older", selected: false },
        { id: "org-clean", name: "Clean test org", slug: "clean-test", selected: true },
      ],
      enrollmentLocked: false,
    });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");

    fireEvent.click(await screen.findByRole("button", { name: "Use Clean test org" }));

    await waitFor(() =>
      expect(b.tunnel.selectManagedOrganization).toHaveBeenCalledWith("org-clean"),
    );
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Use Clean test org" })).toBeNull(),
    );
  });

  it("keeps an enrolled organization read-only until Remove device reloads the choices", async () => {
    const enrolled = {
      organizations: [
        { id: "org-old", name: "Older organization", slug: "older", selected: true },
        { id: "org-clean", name: "Clean test org", slug: "clean-test", selected: false },
      ],
      enrollmentLocked: true,
    };
    const unlocked = {
      organizations: enrolled.organizations.map((organization) => ({
        ...organization,
        selected: false,
      })),
      enrollmentLocked: false,
    };
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi
      .fn()
      .mockResolvedValueOnce(enrolled)
      .mockResolvedValueOnce(unlocked);
    window.tunnex = b;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ClientApp />);
    await openDrawerPage("Profiles");

    expect(await screen.findByText("Enrolled device")).toBeTruthy();
    expect(screen.getByText("Remove device first")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Use Clean test org" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Remove device" }));

    await waitFor(() => expect(b.auth.removeDevice).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("button", { name: "Use Clean test org" })).toBeTruthy();
    expect(b.tunnel.managedOrganizations).toHaveBeenCalledTimes(2);
  });

  it("keeps selection locked even when the enrolled organization is absent from live memberships", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [
        { id: "org-clean", name: "Clean test org", slug: "clean-test", selected: false },
      ],
      enrollmentLocked: true,
    });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");

    expect(await screen.findByRole("button", { name: "Remove device" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Use Clean test org" })).toBeNull();
    expect(screen.getByText("Remove device first")).toBeTruthy();
    expect(screen.queryByText("Enrolled device")).toBeNull();
    expect(b.tunnel.selectManagedOrganization).not.toHaveBeenCalled();
  });

  it("states that a sole organization is automatic without asking for a decision", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [
        { id: "org-only", name: "Only org", slug: "only", selected: false },
      ],
      enrollmentLocked: false,
    });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");

    expect(await screen.findByText("Only organization")).toBeTruthy();
    expect(screen.getByText(/No selection is needed/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Use Only org" })).toBeNull();
    expect(b.tunnel.selectManagedOrganization).not.toHaveBeenCalled();
  });

  it("opens Profiles with friendly copy when main refuses a missing selection", async () => {
    const listeners: Array<() => void> = [];
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.managedOrganizations = vi.fn().mockResolvedValue({
      organizations: [
        { id: "org-old", name: "Older organization", slug: "older", selected: false },
        { id: "org-clean", name: "Clean test org", slug: "clean-test", selected: false },
      ],
      enrollmentLocked: false,
    });
    b.tunnel.onOrganizationSelectionRequired = vi.fn((listener) => {
      listeners.push(listener);
      return () => {};
    });
    window.tunnex = b;
    render(<ClientApp />);
    await waitFor(() =>
      expect(b.tunnel.onOrganizationSelectionRequired).toHaveBeenCalledTimes(1),
    );

    act(() => listeners[0]?.());

    expect(await screen.findByRole("heading", { name: "Organizations" })).toBeTruthy();
    expect(screen.getByText(/will not guess/i)).toBeTruthy();
  });

  it("distinguishes no organizations from an organization load failure", async () => {
    const empty = fakeBridge({ loggedIn: true });
    window.tunnex = empty;
    const first = render(<ClientApp />);
    await openDrawerPage("Profiles");
    expect(await screen.findByText(/No organizations are available/i)).toBeTruthy();
    first.unmount();

    const failed = fakeBridge({ loggedIn: true });
    failed.tunnel.managedOrganizations = vi
      .fn()
      .mockRejectedValue(new Error("control plane unavailable"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = failed;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    expect(await screen.findByText(/Organizations could not be loaded/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
  });
});

describe("the numbers are measured and the verb is one word", () => {
  it("⛔ real rx/tx render as NUMBERS — the fields were hard-wired to n/a forever", async () => {
    // They were `useState({rx: null, tx: null, ...})` with a comment saying they would arrive "in
    // step 3". Step 3 came and went. Meanwhile the plot beside them drew invented samples.
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.status = vi.fn().mockResolvedValue({
      state: "up",
      rx_bytes: 2048,
      tx_bytes: 1024,
      last_handshake_sec: Math.floor(Date.now() / 1000) - 5,
    });
    window.tunnex = b;
    render(<ClientApp />);
    await waitFor(() => expect(screen.getByText("2.00 KB")).toBeTruthy()); // BYTES IN
    expect(document.querySelector("[data-status-detail]")).toBeNull();
    expect(screen.getByText("1.00 KB")).toBeTruthy(); // BYTES OUT
    // The helper reports a handshake; there is no packet counter anywhere in the chain.
    expect(screen.getByText(/Last handshake/)).toBeTruthy();
    expect(screen.queryByText(/PACKET RECEIVED/)).toBeNull();
    // ⛔ THE TUNNEL IP WAS ALREADY ON THE WIRE AND NOTHING SHOWED IT. TunnelController.withAddress
    // decorates every status with it precisely so the client can answer "what is my IP" — and the
    // preload TYPE omitted the field, so TypeScript denied the existence of data already arriving.
    expect(screen.getByText(/Tunnel IP/)).toBeTruthy();
  });

  it("⛔ the centre control has a concise accessible verb — no verbose disconnect suffix", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.status = vi.fn().mockResolvedValue({ state: "up" });
    window.tunnex = b;
    render(<ClientApp />);
    const btn = await screen.findByRole("button", { name: "Disconnect" });
    expect(btn.getAttribute("aria-label")).toBe("Disconnect");
    expect(btn.textContent).toBe("Disconnect");
    expect(screen.getByText("Disconnect")).toBeTruthy();
  });

  it("keeps the established animation and graph on the disconnected home surface", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    const { container } = render(<ClientApp />);
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy(),
    );
    expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
    expect(container.querySelector("[data-action] .tnx-connect-orb")).not.toBeNull();
    expect(container.querySelector("[data-connection-metrics]")).not.toBeNull();
    expect(container.querySelector("[data-status-detail]")).not.toBeNull();
    expect(container.querySelector("#tnxHyper")).not.toBeNull();
    expect(container.querySelector("#tnxGraph")).not.toBeNull();
    expect(container.querySelector("[data-animation-control] [data-action]")).not.toBeNull();
    expect(container.querySelectorAll("[data-action] .tnx-connect-ripple")).toHaveLength(2);
    expect(container.querySelectorAll("[data-action] .tnx-connect-orbit-segment")).toHaveLength(3);
    expect(screen.getByText("Click here")).toBeTruthy();
    // The connected state adds peak/rate values, but must not move the stats surface.
    // Reserve that row while disconnected instead of conditionally mounting it.
    expect(container.querySelector("[data-connection-rate-summary]")).not.toBeNull();
    expect(screen.queryByText("n/a")).toBeNull();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });
});

describe("routing mode and the server, both reachable and both unambiguous", () => {
  it("⛔ NO checkbox whose label is the OPPOSITE of what it sets", async () => {
    // The control was `<input type="checkbox" checked={fullTunnel}>` labelled "Split tunnel".
    // Unchecked read as "split is off" — i.e. everything is tunnelled — while actually meaning
    // fullTunnel === false, which is SPLIT. The safe-looking state was the leaking one.
    window.tunnex = fakeBridge({ loggedIn: true });
    const { container } = render(<ClientApp />);
    await openDrawerPage("Settings");
    expect(container.querySelector('input[type="checkbox"]')).toBeNull();
    // Two NAMED options; neither requires inferring meaning from a tick.
    const radios = container.querySelectorAll(
      'input[type="radio"][name="routing"]',
    );
    expect(radios).toHaveLength(2);
    expect(screen.getByText(/All traffic/)).toBeTruthy();
    expect(screen.getByText(/Only Tunnex routes/)).toBeTruthy();
  });

  it("each routing option says what it does to traffic, not just its name", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    await openDrawerPage("Settings");
    await waitFor(() =>
      expect(screen.getByText(/Send all traffic through Tunnex/i)).toBeTruthy(),
    );
    expect(screen.getByText(/Only routes published by your admin use Tunnex/i)).toBeTruthy();
  });

  it("⛔ CHANGE SERVER is reachable — setServerUrl had no caller after the step-3 flip", async () => {
    // The verb has been on the preload allowlist since S6.2. Once the client stopped loading the
    // web dashboard, nothing called it: changing control plane meant deleting the app-data
    // directory by hand. A documented capability with no way to reach it.
    const b = fakeBridge({ loggedIn: true });
    b.config.setServerUrl = vi.fn().mockResolvedValue({
      url: "https://b.example.com",
      reloginRequired: true,
    });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Settings");
    fireEvent.click(
      await screen.findByRole("button", { name: /change server/i }),
    );
    const input = await screen.findByLabelText(/control-plane url/i);
    fireEvent.change(input, { target: { value: "https://b.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: /switch server/i }));
    await waitFor(() =>
      expect(b.config.setServerUrl).toHaveBeenCalledWith(
        "https://b.example.com",
      ),
    );
  });

  it("reconciles server, profiles, tunnel, and auth after a failed server change", async () => {
    const b = fakeBridge({ loggedIn: true });
    const oldProfiles = [
      { id: "old", name: "Old gateway", address: "10.99.0.7/32", fullTunnel: false, active: true },
    ];
    const actualProfiles = [
      { id: "actual", name: "Actual gateway", address: "10.99.1.7/32", fullTunnel: false, active: false },
    ];
    b.config.getServerUrl = vi
      .fn()
      .mockResolvedValueOnce("https://old.example.com")
      .mockResolvedValue("https://actual.example.com");
    b.auth.status = vi
      .fn()
      .mockResolvedValueOnce({
        loggedIn: true,
        expired: false,
        fingerprint: "abcdef0123",
        secureStorage: true,
      })
      .mockResolvedValue({
        loggedIn: false,
        expired: false,
        secureStorage: true,
      });
    b.tunnel.importedProfiles = vi
      .fn()
      .mockResolvedValueOnce(oldProfiles)
      .mockResolvedValue(actualProfiles);
    const transport = mutableTunnelStatus(b, "up");
    b.config.setServerUrl = vi.fn(async () => {
      transport.push("down");
      throw new Error("server_persist_failed");
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    expect(await screen.findByRole("heading", { name: "Connected" })).toBeTruthy();
    await waitFor(() => {
      expect(b.config.getServerUrl).toHaveBeenCalledTimes(1);
      expect(b.tunnel.importedProfiles).toHaveBeenCalledTimes(1);
    });
    await openDrawerPage("Settings");
    expect(await screen.findByText("https://old.example.com")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /change server/i }));
    fireEvent.change(screen.getByLabelText(/control-plane url/i), {
      target: { value: "https://requested.example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: /switch server/i }));

    expect((await screen.findByRole("alert")).textContent).toContain(
      "That action did not complete. Try again or check Logs.",
    );
    expect(screen.getByText("https://actual.example.com")).toBeTruthy();
    await waitFor(() => {
      expect(b.config.getServerUrl).toHaveBeenCalledTimes(2);
      expect(b.tunnel.importedProfiles).toHaveBeenCalledTimes(2);
      expect(b.auth.status).toHaveBeenCalledTimes(2);
    });

    await openDrawerPage("Profiles");
    expect(await screen.findByText("Actual gateway")).toBeTruthy();
    expect(screen.queryByText("Old gateway")).toBeNull();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Not signed in" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Connect" })).toBeNull();
  });

  it("⛔ the sign-out cost is stated BEFORE the switch, not discovered after", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    await openDrawerPage("Settings");
    fireEvent.click(
      await screen.findByRole("button", { name: /change server/i }),
    );
    // A credential is only valid for its issuing server; switching revokes it. The user must be
    // told that is the price while they can still cancel.
    expect(
      await screen.findByText(/signs you out and tears down the tunnel/i),
    ).toBeTruthy();
  });
});

describe("troubleshooting is reachable from the client", () => {
  it("⛔ a Logs control exists — the file had 30 lines of updater noise and none of the failures", async () => {
    // ~/Library/Logs/@tunnex/client/main.log existed, rotated, and was writable. electron-log was
    // imported by updater.ts ALONE, so the only code that logged had nothing to say, and the one
    // error anybody hit — not_authenticated on tunnel:up — appears in it zero times.
    //
    // > **A LOG FILE THAT EXISTS IS NOT LOGGING.** "Check the logs" reads as a real instruction,
    // > the file opens, it has content and timestamps, and the incident is simply absent — which
    // > looks like nothing went wrong rather than nothing was recorded.
    const b = fakeBridge({ loggedIn: true });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Logs");
    fireEvent.click(await screen.findByRole("button", { name: /reveal/i }));
    await waitFor(() => expect(b.diag.openLogs).toHaveBeenCalled());
  });
});

describe("the home pane stays one screen", () => {
  it("⛔ settings are NOT on the connection screen — it was growing a section per request", async () => {
    // Routing mode, then a server form, then a row of footer buttons. Each defensible alone;
    // together a column you scroll to find anything in. A surface that only ever gains sections is
    // not a design, it is an accumulation.
    window.tunnex = fakeBridge({ loggedIn: true });
    const { container } = render(<ClientApp />);
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: /connected|disconnected/i }),
      ).toBeTruthy(),
    );
    expect(screen.queryByRole("button", { name: /change server/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /sign out/i })).toBeNull();
    expect(container.querySelectorAll('input[type="radio"]')).toHaveLength(0);
    // What the home pane DOES answer: am I connected, and what do I press.
    expect(
      screen.getByRole("button", { name: /^(Connect|Disconnect|Cancel)$/ }),
    ).toBeTruthy();
  });

  it("every pane is reachable from the drawer", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    for (const name of ["Profiles", "Settings", "Logs", "Help", "Home"] as const) {
      await openDrawerPage(name);
    }
    expect(screen.getByRole("heading", { name: /connected|disconnected/i })).toBeTruthy();
  });
});

describe("the log is visible IN the client, and export tells the truth", () => {
  it("⛔ shows the file's contents — 'reveal in Finder' is not troubleshooting", async () => {
    // A log a user cannot see is a log they will not read, and revealing a file is useless on a
    // machine where the problem is that the app will not start.
    const b = fakeBridge({ loggedIn: true });
    b.diag.readLog = vi
      .fn()
      .mockResolvedValue(
        "[info] tunnex client started\n[error] not_authenticated",
      );
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Logs");
    await waitFor(() =>
      expect(screen.getByText(/not_authenticated/)).toBeTruthy(),
    );
  });

  it("⛔ a CANCELLED export does not claim the file was saved", async () => {
    // exportLog resolves null when the save dialog is dismissed. Reporting success there is the
    // UI claiming an action it did not perform — the rule this repo already holds elsewhere.
    const b = fakeBridge({ loggedIn: true });
    b.diag.exportLog = vi.fn().mockResolvedValue(null);
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Logs");
    fireEvent.click(await screen.findByRole("button", { name: /export/i }));
    await waitFor(() => expect(b.diag.exportLog).toHaveBeenCalled());
    expect(screen.queryByText(/saved to/i)).toBeNull();
  });

  it("a completed export names the path it wrote", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.diag.exportLog = vi
      .fn()
      .mockResolvedValue("/Users/x/tunnex-client-log.txt");
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Logs");
    fireEvent.click(await screen.findByRole("button", { name: /export/i }));
    await waitFor(() =>
      expect(screen.getByText(/tunnex-client-log\.txt/)).toBeTruthy(),
    );
  });

  it("an unreadable log renders the FAILURE, never an empty box", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.diag.readLog = vi
      .fn()
      .mockResolvedValue("Could not read the log at /x: EACCES");
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Logs");
    await waitFor(() => expect(screen.getByText(/EACCES/)).toBeTruthy());
  });
});

describe("version, updates and the tagline", () => {
  it("⛔ the client can state its own version — the first thing support asks for", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    await openDrawerPage("Settings");
    await waitFor(() =>
      expect(screen.getByText(/Tunnex v0\.1\.0/)).toBeTruthy(),
    );
  });

  it("keeps automatic install off while allowing a manual signed-release check", async () => {
    // The Electron auto-updater remains disabled until the desktop binaries are signed. The
    // explicit check only discovers a release and the user still chooses the official download.
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    await openDrawerPage("Settings");
    await waitFor(() =>
      expect(screen.getByText(/Automatic updates are off/i)).toBeTruthy(),
    );
    expect(
      screen.getByRole("button", { name: /check for updates/i }),
    ).toBeTruthy();
  });

  it("the button appears only when a check could actually run", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.diag.appInfo = vi
      .fn()
      .mockResolvedValue({ version: "9.9.9", update: { kind: "ready" } });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Settings");
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /check for updates/i }),
      ).toBeTruthy(),
    );
  });

  it("⛔ the header shows no raw tray-appearance word — that was a debug readout", async () => {
    // It printed "grey" / "solid" beside the dot: internal vocabulary for how the MENU-BAR ICON is
    // drawn, shown three lines above a status word that already says "Connected". The dot stays and
    // carries the state in its label instead.
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.status = vi.fn().mockResolvedValue({ state: "up" });
    window.tunnex = b;
    const { container } = render(<ClientApp />);
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: /connected/i })).toBeTruthy(),
    );
    for (const word of ["grey", "solid", "pulsing", "red"]) {
      expect(screen.queryByText(word)).toBeNull();
    }
    const dot = container.querySelector("[data-tray]");
    expect(dot?.getAttribute("aria-label")).toMatch(/^Status: /);
  });

  it("the tagline is rendered from ONE definition, shared with the web shell", async () => {
    window.tunnex = fakeBridge({ loggedIn: true });
    render(<ClientApp />);
    expect(screen.getByText(/Connect Everything\./)).toBeTruthy();
    expect(screen.getByText(/Trust Nothing\./)).toBeTruthy();
  });

  it("the preview state renders the product label without preview controls", async () => {
    const previous = window.location.href;
    window.history.replaceState({}, "", "?state=posture_warning");
    try {
      window.tunnex = fakeBridge({ loggedIn: true });
      render(<ClientApp />);
      expect(await screen.findByRole("heading", { name: "Device posture warning" })).toBeTruthy();
      expect(screen.queryByRole("link", { name: "posture_warning" })).toBeNull();
    } finally {
      window.history.replaceState({}, "", previous);
    }
  });
});

describe("an imported .conf connects, and says what it gives up", () => {
  it("⛔ import is reachable — a .conf from the control plane had no way in", async () => {
    const b = fakeBridge({ loggedIn: true });
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    fireEvent.click(
      await screen.findByRole("button", { name: /import \.conf/i }),
    );
    await waitFor(() => expect(b.tunnel.importConfig).toHaveBeenCalled());
  });

  it("keeps imported-profile monitoring limits in Profiles, not the compact home", async () => {
    // A generic WireGuard file cannot provide posture facts or a CP identity for proactive
    // monitoring. Gateway-side revocation still removes the peer, and the UI must say both.
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi
      .fn()
      .mockResolvedValue([{ id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: true, active: true }]);
    window.tunnex = b;
    render(<ClientApp />);
    expect(screen.queryByText(/Server-side revocation still applies/i)).toBeNull();
    await openDrawerPage("Profiles");
    await waitFor(() =>
      expect(
        screen.getByText(/do not report posture or monitor revocation in this app/i),
      ).toBeTruthy(),
    );
  });

  it("⛔ a CANCELLED picker imports nothing and says nothing", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importConfig = vi.fn().mockResolvedValue(null);
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    fireEvent.click(
      await screen.findByRole("button", { name: /import \.conf/i }),
    );
    await waitFor(() => expect(b.tunnel.importConfig).toHaveBeenCalled());
    // ⚠ ASSERT WHAT STAYS TRUE, NOT WHAT STAYS ABSENT. The first version of this test only checked
    // that the warning banner was missing — which it is either way, so the mutation "treat cancel
    // as an import" passed it. The state that actually distinguishes the two is the section still
    // offering to import, and no error being claimed for a cancel.
    expect(screen.getByRole("button", { name: /import \.conf/i })).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: /remove imported profile/i }),
    ).toBeNull();
    expect(screen.queryByText(/That action did not complete/i)).toBeNull();
  });

  it("a malformed .conf surfaces the parser's refusal rather than half-importing", async () => {
    // parseWgConf is strict because the result is handed to a ROOT helper.
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importConfig = vi
      .fn()
      .mockRejectedValue(new Error("malformed .conf line: Addres = x"));
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    fireEvent.click(
      await screen.findByRole("button", { name: /import \.conf/i }),
    );
    await waitFor(() =>
      expect(screen.getByText(/That action did not complete. Try again or check Logs./)).toBeTruthy(),
    );
  });

  it("an imported profile can be removed, returning to the account path", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi
      .fn()
      .mockResolvedValue([{ id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: false, active: true }]);
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    fireEvent.click(
      await screen.findByRole("button", { name: /^remove$/i }),
    );
    await waitFor(() => expect(b.tunnel.forgetImported).toHaveBeenCalledWith("profile-a"));
  });

  it("returns to the account path without deleting an active imported profile", async () => {
    const b = fakeBridge({ loggedIn: false });
    b.tunnel.importedProfiles = vi
      .fn()
      .mockResolvedValue([{ id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: false, active: true }]);
    b.tunnel.useManagedProfile = vi.fn().mockResolvedValue([
      { id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: false, active: false },
    ]);
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    fireEvent.click(await screen.findByRole("button", { name: "Use account" }));
    await waitFor(() => expect(b.tunnel.useManagedProfile).toHaveBeenCalledTimes(1));
    expect(b.tunnel.forgetImported).not.toHaveBeenCalled();
    expect(await screen.findByRole("heading", { name: "Not signed in" })).toBeTruthy();
  });

  it("keeps several imported gateways separate and only switches when the user chooses one", async () => {
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi.fn().mockResolvedValue([
      { id: "profile-a", name: "Mumbai gateway", endpoint: "in1.example.com:51820", address: "10.99.0.7/32", fullTunnel: false, active: true },
      { id: "profile-b", name: "London gateway", endpoint: "uk1.example.com:51820", address: "10.99.1.7/32", fullTunnel: true, active: false },
    ]);
    b.tunnel.selectImportedProfile = vi.fn().mockResolvedValue([
      { id: "profile-a", name: "Mumbai gateway", endpoint: "in1.example.com:51820", address: "10.99.0.7/32", fullTunnel: false, active: false },
      { id: "profile-b", name: "London gateway", endpoint: "uk1.example.com:51820", address: "10.99.1.7/32", fullTunnel: true, active: true },
    ]);
    window.tunnex = b;
    render(<ClientApp />);
    await openDrawerPage("Profiles");
    expect(await screen.findByText("Mumbai gateway")).toBeTruthy();
    expect(screen.getByText("London gateway")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /use this profile/i }));
    await waitFor(() => expect(b.tunnel.selectImportedProfile).toHaveBeenCalledWith("profile-b"));
    expect(screen.getAllByRole("button", { name: "Selected" }).length).toBe(1);
  });

  it("refreshes profiles after selection failure and clears the banner on a successful retry", async () => {
    const profiles = [
      { id: "profile-a", name: "Mumbai gateway", endpoint: "in1.example.com:51820", address: "10.99.0.7/32", fullTunnel: false, active: true },
      { id: "profile-b", name: "London gateway", endpoint: "uk1.example.com:51820", address: "10.99.1.7/32", fullTunnel: true, active: false },
    ];
    const selectedProfiles = [
      { ...profiles[0], active: false },
      { ...profiles[1], active: true },
    ];
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi.fn().mockResolvedValue(profiles);
    const transport = mutableTunnelStatus(b, "up");
    let attempts = 0;
    b.tunnel.selectImportedProfile = vi.fn(async () => {
      attempts += 1;
      if (attempts === 1) {
        transport.push("down");
        throw new Error("profile_selection_persist_failed");
      }
      return selectedProfiles;
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await openDrawerPage("Profiles");
    const london = (await screen.findByText("London gateway")).closest("li");
    expect(london).not.toBeNull();
    fireEvent.click(within(london as HTMLElement).getByRole("button", { name: "Use this profile" }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    await waitFor(() => expect(b.tunnel.importedProfiles).toHaveBeenCalledTimes(2));
    const mumbai = screen.getByText("Mumbai gateway").closest("li");
    expect(within(mumbai as HTMLElement).getByRole("button", { name: "Selected" })).toBeTruthy();

    const retryLondon = screen.getByText("London gateway").closest("li");
    fireEvent.click(within(retryLondon as HTMLElement).getByRole("button", { name: "Use this profile" }));
    await waitFor(() => expect(b.tunnel.selectImportedProfile).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("alert")).toBeNull();
    const selectedLondon = screen.getByText("London gateway").closest("li");
    expect(within(selectedLondon as HTMLElement).getByRole("button", { name: "Selected" })).toBeTruthy();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy();
  });

  it("refreshes profiles and stays Disconnected when Use account persistence fails", async () => {
    const profiles = [
      { id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: false, active: true },
    ];
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi.fn().mockResolvedValue(profiles);
    const transport = mutableTunnelStatus(b, "up");
    b.tunnel.useManagedProfile = vi.fn(async () => {
      transport.push("down");
      throw new Error("profile_selection_persist_failed");
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await openDrawerPage("Profiles");
    fireEvent.click(await screen.findByRole("button", { name: "Use account" }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    await waitFor(() => expect(b.tunnel.importedProfiles).toHaveBeenCalledTimes(2));
    const gateway = screen.getByText("Gateway A").closest("li");
    expect(within(gateway as HTMLElement).getByRole("button", { name: "Selected" })).toBeTruthy();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy();
  });

  it("refreshes profiles after active deletion failure and clears the banner on a successful retry", async () => {
    const profiles = [
      { id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: false, active: true },
    ];
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi.fn().mockResolvedValue(profiles);
    const transport = mutableTunnelStatus(b, "up");
    let attempts = 0;
    b.tunnel.forgetImported = vi.fn(async () => {
      attempts += 1;
      if (attempts === 1) {
        transport.push("down");
        throw new Error("profile_delete_persist_failed");
      }
      return [];
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await openDrawerPage("Profiles");
    const gateway = (await screen.findByText("Gateway A")).closest("li");
    fireEvent.click(within(gateway as HTMLElement).getByRole("button", { name: "Remove" }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    await waitFor(() => expect(b.tunnel.importedProfiles).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Gateway A")).toBeTruthy();

    const retryGateway = screen.getByText("Gateway A").closest("li");
    fireEvent.click(within(retryGateway as HTMLElement).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(b.tunnel.forgetImported).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText("Gateway A")).toBeNull();
    expect(screen.getByText("No imported profiles yet.")).toBeTruthy();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Disconnected" })).toBeTruthy();
  });

  it("refreshes an inactive delete failure without changing the live connection", async () => {
    const profiles = [
      { id: "profile-a", name: "Gateway A", address: "10.99.0.7/32", fullTunnel: false, active: true },
      { id: "profile-b", name: "Gateway B", address: "10.99.1.7/32", fullTunnel: false, active: false },
    ];
    const b = fakeBridge({ loggedIn: true });
    b.tunnel.importedProfiles = vi.fn().mockResolvedValue(profiles);
    mutableTunnelStatus(b, "up");
    b.tunnel.forgetImported = vi.fn().mockRejectedValue(new Error("profile_delete_persist_failed"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    window.tunnex = b;
    render(<ClientApp />);

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy(),
    );
    await openDrawerPage("Profiles");
    const inactive = (await screen.findByText("Gateway B")).closest("li");
    fireEvent.click(within(inactive as HTMLElement).getByRole("button", { name: "Remove" }));

    expect(
      await screen.findByText("That action did not complete. Try again or check Logs."),
    ).toBeTruthy();
    await waitFor(() => expect(b.tunnel.importedProfiles).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Gateway A")).toBeTruthy();
    expect(screen.getByText("Gateway B")).toBeTruthy();
    await openDrawerPage("Home");
    expect(screen.getByRole("heading", { name: "Connected" })).toBeTruthy();
  });
});

describe("connected preview data", () => {
  it("renders a compact IPv6 tunnel address when the review URL asks for it", async () => {
    const previous = window.location.href;
    window.history.replaceState({}, "", "/client.html?state=connected&ip=ipv6");
    try {
      render(<ClientApp />);
      expect(await screen.findByText("fd42:99::2/128")).toBeTruthy();
    } finally {
      window.history.replaceState({}, "", previous);
    }
  });
});

describe("the window IS the card — one surface, not a card inside a frame", () => {
  it("⛔ no inner card chrome: no max-width, no radius, no outer margin", async () => {
    // This test asserted the OPPOSITE one revision ago, and both versions were right in turn.
    //
    // The design draws the client as a 440px card with `margin:0 auto` — which is how it MUST be
    // drawn in a wireframe, because a wireframe is a web page and the card needs a page to sit on.
    // Transcribed literally into a fixed-width window it produced a card floating inside a window
    // frame: two chromes, one of them meaningless.
    //
    // > **A DESIGN'S CONTAINER IS NOT ALWAYS PART OF THE DESIGN.** Some of what a wireframe shows is
    // > the wireframe's own medium. The 440px width was real; the page it was centred on was not.
    window.tunnex = fakeBridge({ loggedIn: true });
    const { container } = render(<ClientApp />);
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).not.toMatch(/max-w-/);
    expect(root.className).not.toMatch(/rounded-/);
    expect(root.className).not.toMatch(/\bp-4\b/);
    // It fills the viewport instead — the OS window draws the frame.
    expect(root.className).toContain("h-dvh");
    // And there is exactly ONE root: no wrapper-inside-a-wrapper.
    expect(container.children).toHaveLength(1);
    expect(root.querySelector(".max-w-\\[440px\\]")).toBeNull();
  });
});
