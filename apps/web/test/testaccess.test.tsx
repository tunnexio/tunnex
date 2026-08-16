import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

let role: "admin" | "member" = "admin";
let profileAllowed = true;
let releaseFirst: ((value: unknown) => void) | null = null;
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

const diagnostic = (destination: string, overall: "allowed" | "denied") => ({
  device_id: "agent-a", destination, protocol: "tcp", port: 443, overall,
  first_blocker: overall === "denied" ? "no_matching_grant" : null,
  checks: ["agent_active", "runtime_ready", "gateway_reporting", "destination_ip", "route_configured",
    overall === "allowed" ? "matching_grant" : "no_matching_grant", "applied_policy_current"].map((code) => ({
      status: code === "no_matching_grant" ? "fail" : "pass", code, message: code,
      facts: code === "matching_grant" ? { rule_id: "rule-1" } : undefined,
    })),
});

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { deviceId?: string }; query?: { destination?: string } } }) => {
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role, email_verified: true }] };
        if (path.endsWith("/agents")) return { data: [{ device_id: "agent-a", name: "agent alpha", gateway_name: "gw-a" }] };
        if (path.endsWith("/agents/{deviceId}")) return profileAllowed ? { data: { device_id: "agent-a", name: "agent alpha" } } : { error: { error: { code: "forbidden" } } };
        if (path.endsWith("/test-access")) {
          const destination = request?.params?.query?.destination ?? "";
          if (destination === "10.0.0.1") return await new Promise((resolve) => { releaseFirst = resolve; });
          return { data: diagnostic(destination, destination === "10.0.0.2" ? "denied" : "allowed") };
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

afterEach(() => {
  releaseFirst?.({ data: diagnostic("10.0.0.1", "allowed") });
  releaseFirst = null;
  role = "admin";
  profileAllowed = true;
  cleanup();
});

describe("released F08 Test Access panel", () => {
  it("renders ordered server checks and ignores a superseded tuple response", async () => {
    render(<Access />);
    await screen.findByTestId("test-access-panel");
    const destination = screen.getByPlaceholderText("10.20.0.15");
    const button = screen.getByRole("button", { name: "Test access" });

    fireEvent.change(destination, { target: { value: "10.0.0.1" } });
    fireEvent.click(button);
    await waitFor(() => expect(releaseFirst).not.toBeNull());

    fireEvent.change(destination, { target: { value: "10.0.0.2" } });
    fireEvent.click(screen.getByRole("button", { name: "Test access" }));
    await screen.findByText("Blocked by current Tunnex intent");
    releaseFirst?.({ data: diagnostic("10.0.0.1", "allowed") });
    await Promise.resolve();

    expect(screen.getByText("Blocked by current Tunnex intent")).toBeTruthy();
    expect(screen.queryByText("Allowed by current Tunnex intent")).toBeNull();
    expect(screen.getAllByRole("listitem")).toHaveLength(7);
    expect(screen.queryByRole("button", { name: /apply|fix|probe/i })).toBeNull();

    fireEvent.change(destination, { target: { value: "10.0.0.3" } });
    fireEvent.click(screen.getByRole("button", { name: "Test access" }));
    await screen.findByText("Allowed by current Tunnex intent");
    expect(screen.getByText("rule-1")).toBeTruthy();
  });

  it("omits the diagnostic DOM for an unrelated member", async () => {
    role = "member";
    profileAllowed = false;
    render(<Access />);
    await screen.findByText("Access policies are managed by owners and admins.");
    await waitFor(() => expect(screen.queryByTestId("test-access-panel")).toBeNull());
    expect(screen.queryByText("agent alpha")).toBeNull();
  });
});
