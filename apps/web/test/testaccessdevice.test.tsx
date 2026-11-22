import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const role = "admin";


const currentOrg = { id: "org-a", name: "Organization A" };

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({
    org: currentOrg,
    orgs: [], setOrg: vi.fn(), loading: false, failed: false,
  }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({
    state: { status: "authed", user: { id: "user-a", email: "a@example.com", email_verified: true } },
  }),
}));

const calls: Array<{ path: string; deviceId?: string }> = [];

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { deviceId?: string } } }) => {
        if (path === "/api/v1/license") return { data: { state: "unlicensed", tier: "community", features: [] } };
        if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role, email_verified: true }] };
        if (path.endsWith("/devices")) return { data: [
          { id: "dev-1", name: "ops-laptop", owner_email: "ops@example.test", kind: "user", status: "active" },
          { id: "dev-2", name: "old-phone", kind: "user", status: "revoked" },
          { id: "dev-3", name: "runner", kind: "agent", status: "active" },
        ] };
        if (path.endsWith("/test-access")) {
          calls.push({ path, deviceId: request?.params?.path?.deviceId });
          return { data: { device_id: "dev-1", destination: "10.0.0.9", protocol: "tcp", port: 443, overall: "denied", first_blocker: "no_matching_grant",
            checks: [{ status: "pass", code: "device_active", message: "Device is active." }, { status: "fail", code: "no_matching_grant", message: "No active compiled grant permits this tuple." }] } };
        }
        if (path.endsWith("/zero-trust-mode")) return { data: { mode: "enforcing" } };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import Access from "../src/pages/Access";

afterEach(() => { calls.length = 0; cleanup(); });

describe("UIX-1 — Test access for a person's device", () => {
  it("lists people's active devices only and asks the device endpoint", async () => {
    render(<MemoryRouter><Access /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Test access" }));
    const picker = screen.getByLabelText("Device") as HTMLSelectElement;
    expect([...picker.options].map(option => option.textContent)).toEqual(["ops-laptop · ops@example.test"]);
    // With no agents there is nothing to choose between, so the subject choice is not shown.
    expect(screen.queryByLabelText("Test for")).toBeNull();
    fireEvent.change(screen.getByPlaceholderText("10.20.0.15"), { target: { value: "10.0.0.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Run test" }));
    await screen.findByText("Blocked by current Tunnex intent");
    await waitFor(() => expect(calls).toEqual([{ path: "/api/v1/organizations/{orgId}/devices/{deviceId}/test-access", deviceId: "dev-1" }]));
    expect(screen.getByText("First blocker: no_matching_grant")).toBeTruthy();
  });
});
