import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

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
    render(<MemoryRouter><K8sHAActivationPanel orgId="org-1" role="member" emailVerified /></MemoryRouter>);
    expect(screen.queryByText("Connector HA activation")).toBeNull();
    expect(get).not.toHaveBeenCalled();
  });

  it("renders requested and actual state separately and sends expected revisions", async () => {
    render(<MemoryRouter><K8sHAActivationPanel orgId="org-1" role="admin" emailVerified /></MemoryRouter>);
    expect(await screen.findByText("Connector HA activation")).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: "Review pools" }));
    const review = screen.getByRole("dialog", { name: "Connector pools" });
    expect(within(review).getByText("Requested legacy")).toBeTruthy();
    expect(within(review).getByText("legacy", { exact: true, selector: "span" })).toBeTruthy();
    expect(put).not.toHaveBeenCalled();
    fireEvent.click(within(review).getByRole("button", { name: "Done" }));
    expect(screen.getByRole("link", { name: "Manage in Features" }).getAttribute("href")).toBe("/settings?section=features&feature=kubernetes-ha");
    expect(screen.queryByRole("button", { name: "Enable HA availability" })).toBeNull();
    cleanup();
    render(<MemoryRouter><K8sHAActivationPanel orgId="org-1" role="admin" emailVerified central /></MemoryRouter>);
    await screen.findByRole("button", { name: "Enable HA availability" });
    fireEvent.click(screen.getByRole("button", { name: "Enable HA availability" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/ha-settings",
      expect.objectContaining({ body: { enabled: true, expected_revision: 0 } }),
    ));
  });

  it("never turns a failed status read into a successful empty pool list", async () => {
    get.mockResolvedValue({ error: { error: { message: "status projection failed" } } } as never);
    render(<MemoryRouter><K8sHAActivationPanel orgId="org-1" role="owner" emailVerified /></MemoryRouter>);
    expect((await screen.findByRole("alert")).textContent).toContain("status projection failed");
    expect(screen.queryByText(/No connector pools are configured/)).toBeNull();
  });

  it("confirms organization disable and explains blocked-drain survival before mutating", async () => {
    get.mockImplementation(async (path: string) => path.endsWith("ha-settings")
      ? { data: { enabled: true, revision: 4, actual_state: "enabled", reason_code: "enabled", updated_at: null } }
      : { data: [] } as never);
    render(<MemoryRouter><K8sHAActivationPanel orgId="org-1" role="owner" emailVerified central /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Begin safe HA drain" }));
    expect(put).not.toHaveBeenCalled();
    expect(screen.getByText(/remains fenced and reports a blocked or drain-pending actual state/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Begin safe drain" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/ha-settings",
      expect.objectContaining({ body: { enabled: false, expected_revision: 4 } }),
    ));
  });

  it("keeps a blocked actual state distinct from fenced intent and sends the exact pool transition revision", async () => {
    get.mockImplementation(async (path: string) => path.endsWith("ha-settings")
      ? { data: { enabled: true, revision: 4, actual_state: "enabled", reason_code: "enabled", updated_at: null } }
      : { data: [{ pool_id: "pool-a", cluster_id: "cluster-a", active_node_id: "node-a", requested_mode: "fenced_ha", actual_mode: "blocked", promotion_generation: 6, membership_epoch_known: true, membership_epoch: 2, transition_revision: 7, reason_code: "drain_unproven", requested_at: null, achieved_at: null }] } as never);
    render(<MemoryRouter><K8sHAActivationPanel orgId="org-1" role="owner" emailVerified /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Review pools" }));
    const review = screen.getByRole("dialog", { name: "Connector pools" });
    expect(within(review).getByText("Requested fenced ha")).toBeTruthy();
    expect(within(review).getByText("blocked", { exact: true })).toBeTruthy();
    expect(within(review).queryByText("fenced ha", { exact: true })).toBeNull();
    fireEvent.click(within(review).getByRole("button", { name: "Request safe legacy drain" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/k8s/connector-pools/{poolId}/ha-mode", {
      params: { path: { orgId: "org-1", poolId: "pool-a" } }, body: { requested_mode: "legacy", expected_transition_revision: 7 },
    }));
    expect(put).toHaveBeenCalledTimes(1);
  });

  it("withdraws old organization HA status and rejects its late response after a scope switch", async () => {
    let finishSettings!: (value: unknown) => void;
    get.mockImplementationOnce(() => new Promise(resolve => { finishSettings = resolve; }) as never);
    const view = render(<MemoryRouter><K8sHAActivationPanel orgId="org-a" role="owner" emailVerified /></MemoryRouter>);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    view.rerender(<MemoryRouter><K8sHAActivationPanel orgId="org-b" role="member" emailVerified /></MemoryRouter>);
    expect(screen.queryByText("Connector HA activation")).toBeNull();
    await act(async () => { finishSettings({ data: { enabled: true, revision: 99, actual_state: "enabled", reason_code: "enabled" } }); });
    expect(screen.queryByRole("button", { name: "Begin safe HA drain" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Review pools" })).toBeNull();
    expect(get).toHaveBeenCalledTimes(2);
    expect(put).not.toHaveBeenCalled();
  });
});
