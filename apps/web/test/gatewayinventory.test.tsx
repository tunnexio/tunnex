import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  orgState: {
    org: { id: "org-1", name: "Org one" },
    loading: false,
    failed: false,
  } as { org: { id: string; name: string } | null; loading: boolean; failed: boolean },
  authState: { status: "authed", user: { id: "user-1" } },
  apiGet: vi.fn(),
}));

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => mocks.orgState }));
vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: mocks.authState }),
}));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { ...actual.api, GET: mocks.apiGet } };
});

import { useGatewayInventory } from "../src/lib/useGatewayInventory";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function Probe() {
  const inventory = useGatewayInventory();
  return (
    <div>
      <span>{inventory.state.kind}</span>
      <span>{inventory.state.nodes.map((node) => node.name).join(",")}</span>
      <span>{inventory.canManage ? "can-manage" : "cannot-manage"}</span>
    </div>
  );
}

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  mocks.orgState = { org: { id: "org-1", name: "Org one" }, loading: false, failed: false };
});

describe("Gateway inventory organization isolation", () => {
  it("withdraws prior organization facts synchronously and loads only the new organization", async () => {
    const orgTwoNodes = deferred<{ data: unknown[] }>();
    mocks.apiGet.mockImplementation(async (path: string, options?: { params?: { path?: { orgId?: string } } }) => {
      const orgId = options?.params?.path?.orgId;
      if (path === "/api/v1/license") return { data: { tier: "community", gateway_ceiling: 1, gateways_in_use: 1 } };
      if (path.endsWith("/nodes")) {
        if (orgId === "org-2") return orgTwoNodes.promise;
        return { data: [{ id: "gw-old", name: "old-org-gateway", status: "active" }] };
      }
      if (path.endsWith("/members")) return { data: [{ user_id: "user-1", role: orgId === "org-1" ? "owner" : "member" }] };
      return { data: [] };
    });

    const view = render(<Probe />);
    expect(await screen.findByText("old-org-gateway")).toBeTruthy();
    expect(screen.getByText("can-manage")).toBeTruthy();

    mocks.orgState = { org: { id: "org-2", name: "Org two" }, loading: false, failed: false };
    view.rerender(<Probe />);
    expect(screen.getByText("loading")).toBeTruthy();
    expect(screen.queryByText("old-org-gateway")).toBeNull();
    expect(screen.getByText("cannot-manage")).toBeTruthy();

    await act(async () => {
      orgTwoNodes.resolve({ data: [{ id: "gw-new", name: "new-org-gateway", status: "active" }] });
      await orgTwoNodes.promise;
    });
    expect(await screen.findByText("new-org-gateway")).toBeTruthy();
    await waitFor(() => expect(screen.getByText("cannot-manage")).toBeTruthy());
    expect(mocks.apiGet).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/nodes",
      { params: { path: { orgId: "org-2" } } },
    );
  });
});
