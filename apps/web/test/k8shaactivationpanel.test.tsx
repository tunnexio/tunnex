import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

vi.mock("../src/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { GET: vi.fn(), PUT: vi.fn() } };
});

import { K8sHAActivationPanel } from "../src/components/K8sHAActivationPanel";
import { api } from "../src/lib/api";

const get = vi.mocked(api.GET);
const put = vi.mocked(api.PUT);

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  get.mockImplementation(async (path: string) => path.endsWith("ha-settings")
    ? { data: { enabled: false, revision: 0, actual_state: "disabled", reason_code: "opt_in_disabled", updated_at: null } }
    : { data: [{ pool_id: "11111111-1111-1111-1111-111111111111", cluster_id: "22222222-2222-2222-2222-222222222222", active_node_id: "33333333-3333-3333-3333-333333333333", requested_mode: "legacy", actual_mode: "legacy", promotion_generation: 1, membership_epoch_known: false, membership_epoch: null, transition_revision: 0, reason_code: "legacy", requested_at: null, achieved_at: null }] } as never);
  put.mockResolvedValue({ data: { enabled: true, revision: 1, actual_state: "enabled", reason_code: "enabled", updated_at: null } } as never);
});

describe("K8sHAActivationPanel", () => {
  it("removes protected HA data and calls from the DOM without the named view permission", () => {
    render(<K8sHAActivationPanel orgId="org-1" role="member" emailVerified />);
    expect(screen.queryByText("Connector HA activation")).toBeNull();
    expect(get).not.toHaveBeenCalled();
  });

  it("renders requested and actual state separately and sends expected revisions", async () => {
    render(<K8sHAActivationPanel orgId="org-1" role="admin" emailVerified />);
    expect(await screen.findByText("Connector HA activation")).toBeTruthy();
    expect(await screen.findByText(/requested legacy/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Enable HA availability" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/ha-settings",
      expect.objectContaining({ body: { enabled: true, expected_revision: 0 } }),
    ));
  });

  it("never turns a failed status read into a successful empty pool list", async () => {
    get.mockResolvedValue({ error: { error: { message: "status projection failed" } } } as never);
    render(<K8sHAActivationPanel orgId="org-1" role="owner" emailVerified />);
    expect((await screen.findByRole("alert")).textContent).toContain("status projection failed");
    expect(screen.queryByText(/No connector pools are configured/)).toBeNull();
  });

  it("confirms organization disable and explains blocked-drain survival before mutating", async () => {
    get.mockImplementation(async (path: string) => path.endsWith("ha-settings")
      ? { data: { enabled: true, revision: 4, actual_state: "enabled", reason_code: "enabled", updated_at: null } }
      : { data: [] } as never);
    render(<K8sHAActivationPanel orgId="org-1" role="owner" emailVerified />);
    fireEvent.click(await screen.findByRole("button", { name: "Begin safe HA drain" }));
    expect(put).not.toHaveBeenCalled();
    expect(screen.getByText(/remains fenced and reports a blocked or drain-pending actual state/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Begin safe drain" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/ha-settings",
      expect.objectContaining({ body: { enabled: false, expected_revision: 4 } }),
    ));
  });
});
