import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";

let currentOrg = { id: "org-a", name: "Organization A" };
let releaseOrgBMembers: (() => void) | null = null;

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({
    org: currentOrg,
    orgs: [currentOrg],
    setOrg: vi.fn(),
    loading: false,
    failed: false,
  }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({
    state: {
      status: "authed",
      user: { id: "admin-a", email: "admin@example.com", email_verified: true },
    },
  }),
}));

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string } } }) => {
        const orgId = request?.params?.path?.orgId ?? currentOrg.id;
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path.endsWith("/members")) {
          if (orgId === "org-b") {
            await new Promise<void>((resolve) => {
              releaseOrgBMembers = resolve;
            });
          }
          return {
            data: [{
              user_id: "admin-a",
              role: orgId === "org-c" ? "member" : "admin",
              email_verified: true,
            }],
          };
        }
        if (path.endsWith("/zero-trust-mode")) return { data: { mode: "enforcing" } };
        if (path.endsWith("/policies")) {
          return orgId === "org-a"
            ? {
                data: [{
                  id: "old-agent-rule",
                  enabled: true,
                  src_kind: "agent",
                  src_device_id: "old-agent-id",
                  dst_kind: "resource",
                  dst_resource_id: "resource-a",
                }],
              }
            : { data: [] };
        }
        if (path.endsWith("/agents")) {
          return orgId === "org-a"
            ? { data: [{ device_id: "old-agent-id", name: "old-org-agent", gateway_name: "gw-a" }] }
            : { data: [] };
        }
        if (path.endsWith("/resources")) {
          return orgId === "org-a"
            ? { data: [{ id: "resource-a", name: "old-org-resource" }] }
            : { data: [] };
        }
        if (path.endsWith("/groups") || path.endsWith("/sites")) return { data: [] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import Access from "../src/pages/Access";

afterEach(() => {
  releaseOrgBMembers?.();
  releaseOrgBMembers = null;
  currentOrg = { id: "org-a", name: "Organization A" };
  cleanup();
});

describe("released Access route organization isolation", () => {
  it("withdraws old facts and ignores an out-of-order admin response after A to B to C", async () => {
    const view = render(<Access />);
    await screen.findAllByText("old-org-agent");
    expect(screen.getAllByText("old-org-resource").length).toBeGreaterThan(0);

    currentOrg = { id: "org-b", name: "Organization B" };
    view.rerender(<Access />);

    expect(screen.queryAllByText("old-org-agent")).toHaveLength(0);
    expect(screen.queryAllByText("old-org-resource")).toHaveLength(0);
    expect(screen.getByText("Loading access policies…")).toBeTruthy();

    await waitFor(() => expect(releaseOrgBMembers).not.toBeNull());
    currentOrg = { id: "org-c", name: "Organization C" };
    view.rerender(<Access />);
    await waitFor(() =>
      expect(screen.getByText("Access policies are managed by owners and admins.")).toBeTruthy(),
    );

    releaseOrgBMembers?.();
    await waitFor(() =>
      expect(screen.getByText("Access policies are managed by owners and admins.")).toBeTruthy(),
    );
    expect(screen.queryByRole("button", { name: "Add rule" })).toBeNull();
    expect(screen.queryAllByText("old-org-agent")).toHaveLength(0);
  });
});
