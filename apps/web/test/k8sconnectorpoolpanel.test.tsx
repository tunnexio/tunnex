import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { GET: vi.fn(), PUT: vi.fn() } };
});

import { K8sConnectorPoolPanel } from "../src/components/K8sConnectorPoolPanel";
import { api, type K8sConnectorPoolConfiguration, type Node } from "../src/lib/api";

const get = vi.mocked(api.GET);
const put = vi.mocked(api.PUT);
const CLUSTER = { id: "cluster-a", siteId: "site-a", connectorNodeId: "node-0" };
const nodes = Array.from({ length: 55 }, (_, index) => ({ id: `node-${index}`, name: `Connector ${String(index).padStart(3, "0")}`, site_id: "site-a", status: "active", endpoint: `connector-${index}.internal:51820` } as Node));
const configuration: K8sConnectorPoolConfiguration = {
  pool_id: "pool-a", cluster_id: "cluster-a", active_node_id: "node-0", preferred_node_id: "node-0", generation: 9,
  membership_epoch: 12, membership_epoch_known: true,
  members: [{ node_id: "node-0", admin_priority: 100 }, { node_id: "node-1", admin_priority: 90 }],
};

const panelProps = () => ({ orgId: "org-a", cluster: CLUSTER, nodes, role: "admin" as const, emailVerified: true, onChanged: vi.fn(async () => {}) });

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  get.mockResolvedValue({ data: configuration } as never);
  put.mockResolvedValue({ data: configuration } as never);
});

describe("Kubernetes connector pool membership", () => {
  it("withdraws protected reads and controls without the named view permission", () => {
    render(<K8sConnectorPoolPanel {...panelProps()} role="member" />);
    expect(screen.queryByRole("heading", { name: "Connector pool" })).toBeNull();
    expect(get).not.toHaveBeenCalled();
    expect(put).not.toHaveBeenCalled();
  });

  it("pages eligible candidates and saves all selected members with the exact known membership epoch", async () => {
    const props = panelProps();
    render(<K8sConnectorPoolPanel {...props} nodes={[
      ...nodes,
      { ...nodes[0], id: "revoked", name: "Revoked connector", status: "revoked" },
      { ...nodes[0], id: "foreign", name: "Other network connector", site_id: "other-site" },
      { ...nodes[0], id: "no-endpoint", name: "No endpoint connector", endpoint: "" },
    ]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Edit connector pool" }));
    const dialog = screen.getByRole("dialog", { name: "Configure connector pool" });
    const candidates = () => within(dialog).getByRole("list", { name: "Connector candidates" });
    expect(within(candidates()).getAllByRole("checkbox")).toHaveLength(20);
    expect(within(dialog).getByRole("checkbox", { name: "Include Connector 000" })).toHaveProperty("checked", true);
    expect(within(dialog).getByRole("checkbox", { name: "Include Connector 000" })).toHaveProperty("disabled", true);
    fireEvent.click(within(dialog).getByRole("button", { name: "Next connector candidates" }));
    expect(within(dialog).getByRole("checkbox", { name: "Include Connector 020" })).toBeTruthy();
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(candidates()).getAllByRole("checkbox")).toHaveLength(50);
    fireEvent.click(within(dialog).getByRole("button", { name: "Next connector candidates" }));
    expect(within(candidates()).getAllByRole("checkbox")).toHaveLength(5);
    expect(within(dialog).getByRole("button", { name: "Previous connector candidates" })).toHaveProperty("disabled", false);
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Include Connector 054" }));
    fireEvent.change(within(dialog).getByRole("spinbutton", { name: "Connector 054 priority" }), { target: { value: "70" } });
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Search Connector candidates" }), { target: { value: "Connector 000" } });
    expect(within(candidates()).getAllByRole("checkbox")).toHaveLength(1);
    expect(within(dialog).queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(put).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save pool" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector-pool", {
      params: { path: { orgId: "org-a", clusterId: "cluster-a" } },
      body: { members: [{ node_id: "node-0", admin_priority: 100 }, { node_id: "node-1", admin_priority: 90 }, { node_id: "node-54", admin_priority: 70 }], expected_membership_epoch: 12 },
    }));
    expect(put).toHaveBeenCalledTimes(1);
    expect(props.onChanged).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog", { name: "Configure connector pool" })).toBeNull();
  });

  it("blocks invalid priorities without changing desired membership or active ownership", async () => {
    render(<K8sConnectorPoolPanel {...panelProps()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Edit connector pool" }));
    const dialog = screen.getByRole("dialog", { name: "Configure connector pool" });
    fireEvent.change(within(dialog).getByRole("spinbutton", { name: "Connector 001 priority" }), { target: { value: "1.5" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save pool" }));
    expect(within(dialog).getByText("Each priority must be a whole number in the supported range.")).toBeTruthy();
    expect(put).not.toHaveBeenCalled();
  });

  it("keeps a failed pool read unavailable until an explicit successful retry", async () => {
    get.mockResolvedValueOnce({ error: { error: { code: "unavailable", message: "Pool read failed." } } } as never);
    render(<K8sConnectorPoolPanel {...panelProps()} />);
    expect(await screen.findByText("Pool read failed.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Configure connector pool" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit connector pool" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("button", { name: "Edit connector pool" })).toBeTruthy();
    expect(screen.queryByText("Pool read failed.")).toBeNull();
    expect(put).not.toHaveBeenCalled();
  });

  it("preserves readable configured membership when candidate inventory is unavailable or email is unverified", async () => {
    const props = panelProps();
    const view = render(<K8sConnectorPoolPanel {...props} nodes={null} />);
    expect(await screen.findByRole("list", { name: "Pool members" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Edit connector pool" })).toBeNull();
    view.rerender(<K8sConnectorPoolPanel {...props} emailVerified={false} />);
    await screen.findByRole("list", { name: "Pool members" });
    expect(screen.queryByRole("button", { name: "Edit connector pool" })).toBeNull();
    expect(put).not.toHaveBeenCalled();
  });

  it("discards a late prior-organization pool read before it can become another cluster's editor defaults", async () => {
    let finishOld!: (value: unknown) => void;
    get.mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve; }) as never);
    get.mockResolvedValue({ data: { ...configuration, pool_id: "pool-b", cluster_id: "cluster-b", active_node_id: "node-2", preferred_node_id: "node-2", members: [{ node_id: "node-2", admin_priority: 200 }] } } as never);
    const props = panelProps();
    const view = render(<K8sConnectorPoolPanel {...props} />);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    view.rerender(<K8sConnectorPoolPanel {...props} orgId="org-b" cluster={{ ...CLUSTER, id: "cluster-b", connectorNodeId: "node-2" }} />);
    const current = await screen.findByRole("list", { name: "Pool members" });
    expect(within(current).getByText("Connector 002")).toBeTruthy();
    await act(async () => { finishOld({ data: configuration }); });
    expect(within(screen.getByRole("list", { name: "Pool members" })).getByText("Connector 002")).toBeTruthy();
    expect(within(screen.getByRole("list", { name: "Pool members" })).queryByText("Connector 000")).toBeNull();
    expect(put).not.toHaveBeenCalled();
  });
});
