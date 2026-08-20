import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const mocks = vi.hoisted(() => ({
  cpAdmin: true,
  hostState: { available: true, state: "idle" } as Record<string, unknown>,
  get: vi.fn(),
  post: vi.fn(),
}));

const meta = {
  edition: "open",
  upgrade: {
    available: true,
    verified: true,
    current_version: "v0.1.5",
    current_source_sha: "a".repeat(64),
    version: "v0.1.7",
    source_sha: "b".repeat(64),
    sequence: 61,
    state: "available",
    approval_mode: "host_updater",
  },
};

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({
    state: mocks.cpAdmin
      ? { status: "authed", user: { id: "cp-1", email: "cp@example.com", email_verified: true, cp_admin: true } }
      : { status: "authed", user: { id: "owner-1", email: "owner@example.com", email_verified: true, cp_admin: false } },
  }),
}));

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_error: unknown, fallback: string) => fallback,
    api: { GET: mocks.get, POST: mocks.post },
  };
});

import { UpgradeCenter } from "../src/components/UpgradeCenter";

afterEach(cleanup);

beforeEach(() => {
  mocks.cpAdmin = true;
  mocks.hostState = { available: true, state: "idle" };
  meta.upgrade.available = true;
  mocks.get.mockReset();
  mocks.post.mockReset();
  mocks.get.mockImplementation(async (path: string) => {
    if (path === "/api/v1/meta") return { data: meta };
    if (path === "/api/v1/admin/upgrade") return { data: mocks.hostState };
    throw new Error(`unexpected GET ${path}`);
  });
  mocks.post.mockImplementation(async (path: string) => {
    if (path !== "/api/v1/admin/upgrade") throw new Error(`unexpected POST ${path}`);
    mocks.hostState = {
      available: true,
      state: "requested",
      request_id: "123e4567-e89b-42d3-a456-426614174000",
      target_version: "v0.1.7",
      target_source_sha: "b".repeat(64),
    };
    return { data: mocks.hostState };
  });
});

describe("control-plane upgrade authority", () => {
  it("does not expose host upgrade controls to a non-CP-admin", () => {
    mocks.cpAdmin = false;
    render(<UpgradeCenter />);

    expect(screen.queryByRole("region", { name: "Upgrade available" })).toBeNull();
    expect(mocks.get).not.toHaveBeenCalled();
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it("requires confirmation and requests the server-selected verified target", async () => {
    render(<UpgradeCenter />);

    fireEvent.click(await screen.findByRole("button", { name: "Upgrade control plane" }));
    expect(screen.getByText(/Create and verify a database backup/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Confirm upgrade" }));

    await waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
    expect(mocks.post).toHaveBeenCalledWith("/api/v1/admin/upgrade");
    expect(await screen.findByText("Request accepted")).toBeTruthy();
  });

  it("renders durable backup progress without exposing host paths", async () => {
    mocks.hostState = {
      available: true,
      state: "backing_up",
      target_version: "v0.1.7",
      backup_dump: "postgres-20260821.dump",
      backup_manifest: "backup-20260821.json",
    };

    render(<UpgradeCenter />);

    expect(await screen.findByText("Creating and verifying database backup")).toBeTruthy();
    expect(screen.getByText("postgres-20260821.dump")).toBeTruthy();
    expect(screen.getByText("backup-20260821.json")).toBeTruthy();
    expect(screen.queryByText(/\/var\/lib\/tunnex/)).toBeNull();
  });

  it("does not advertise an absent update or let an earlier healthy target hide a newer release", async () => {
    meta.upgrade.available = false;
    render(<UpgradeCenter />);
    await waitFor(() => expect(mocks.get).toHaveBeenCalled());
    expect(screen.queryByRole("region", { name: "Upgrade available" })).toBeNull();
    cleanup();

    meta.upgrade.available = true;
    mocks.hostState = {
      available: true,
      state: "healthy",
      target_source_sha: "c".repeat(40),
      target_version: "v0.1.6",
    };
    render(<UpgradeCenter />);
    expect(await screen.findByRole("button", { name: "Upgrade control plane" })).toBeTruthy();
  });

  it("offers installer repair instead of a missing helper on old installations", async () => {
    mocks.hostState = { available: false, state: "idle" };
    render(<UpgradeCenter />);
    expect(await screen.findByRole("button", { name: "Copy repair installer command" })).toBeTruthy();
    expect(screen.getByText(/predates UI-managed upgrades/)).toBeTruthy();
  });
});
