import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

vi.mock("../src/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, GET: vi.fn(), POST: vi.fn(), DELETE: vi.fn() } };
});

import { K8sNamespaceRulesPanel } from "../src/components/K8sNamespaceRules";
import { api } from "../src/lib/api";

const get = vi.mocked(api.GET);
const post = vi.mocked(api.POST);
const del = vi.mocked(api.DELETE);

const CLUSTER = { id: "cluster", name: "prod", vipRange: "100.66.0.0/24" };
const PORT = (ref: string, port: number) => ({ port_ref: ref, name: null, protocol: "tcp" as const, service_port: port });
const INVENTORY = {
  observed_at: "2026-11-23T06:00:00Z",
  fresh_until: "2026-11-23T06:01:30Z",
  next_cursor: null,
  items: [
    { inventory_ref: "i1", namespace: "shop", service: "web", ports: [PORT("p1", 80), PORT("p2", 443)] },
    { inventory_ref: "i2", namespace: "shop", service: "api", ports: [PORT("p3", 8080)] },
    { inventory_ref: "i3", namespace: "kube-system", service: "kube-dns", ports: [PORT("p4", 53)] },
    { inventory_ref: "i4", namespace: "billing", service: "ledger", ports: [PORT("p5", 5432)] },
  ],
};
const RULE = {
  id: "rule-1", cluster_id: "cluster", namespace: "billing", status: "applied" as const, status_message: "",
  waiting_services: 0, exposed_services: 1, exposed_ports: 1, last_reconciled_at: "2026-11-23T06:00:00Z", created_at: "2026-11-23T05:00:00Z",
};

function panel(overrides: Partial<Parameters<typeof K8sNamespaceRulesPanel>[0]> = {}) {
  const onChanged = vi.fn(async () => {});
  render(<K8sNamespaceRulesPanel orgId="org" cluster={CLUSTER} canManage exposed={[{ namespace: "shop", name: "web", protocol: "tcp", ports: "80" }]} onChanged={onChanged} fixtureInventory={INVENTORY} {...overrides} />);
  return onChanged;
}

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  get.mockResolvedValue({ data: [] } as never);
});

describe("namespace rules panel (K8N-4)", () => {
  it("states the consequences and needs an explicit confirmation before creating a rule", async () => {
    post.mockResolvedValue({ data: { ...RULE, id: "rule-2", namespace: "shop", exposed_services: 2, exposed_ports: 2 } } as never);
    const onChanged = panel();
    fireEvent.click(await screen.findByRole("button", { name: "Expose every Service in a namespace…" }));
    const dialog = screen.getByRole("dialog");

    // Only eligible namespaces are offered: never kube-system.
    const options = within(dialog).getAllByRole("option").map((option) => option.textContent);
    expect(options).toEqual(["Choose one namespace…", "billing", "shop"]);
    expect(within(dialog).getByRole("button", { name: "Create namespace rule" })).toHaveProperty("disabled", true);

    fireEvent.change(within(dialog).getByRole("combobox", { name: "Namespace" }), { target: { value: "shop" } });
    const impact = within(dialog).getByLabelText("What this rule will do");
    // web:80 is already exposed by hand, so 2 of the 3 reported ports are new and only api needs an address.
    expect(impact.textContent).toMatch(/2 ports of 2 Services in shop are exposed, using 1 new address from 100\.66\.0\.0\/24/);
    expect(impact.textContent).toMatch(/1 port is already exposed and stays exactly as it is/);
    expect(impact.textContent).toMatch(/every Service added to shop is exposed automatically/);
    expect(impact.textContent).toMatch(/Nobody gains access\./);
    expect(impact.textContent).toMatch(/Access rules still decide who can reach it; this creates none/);
    expect(impact.textContent).toMatch(/stays gone for 10 minutes, its exposure is withdrawn/);
    expect(impact.textContent).toMatch(/kept but allow nothing/);
    expect(impact.textContent).toMatch(/address range is full, nothing new is exposed/);

    const confirm = within(dialog).getByRole("button", { name: "Expose 2 Services and keep exposing" });
    expect(confirm).toHaveProperty("disabled", true);
    expect(post).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Expose every Service in shop, including Services added later/ }));
    fireEvent.click(confirm);

    await waitFor(() => expect(post).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/namespace-rules",
      { params: { path: { orgId: "org", clusterId: "cluster" } }, body: { namespace: "shop" } },
    ));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("keeps the dialog open with the reason when the new rule could not be applied", async () => {
    post.mockResolvedValue({ data: { ...RULE, namespace: "shop", status: "vip_range_exhausted", status_message: "the cluster's address range 100.66.0.0/24 is full", waiting_services: 2, exposed_services: 0, exposed_ports: 0 } } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Expose every Service in a namespace…" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Namespace" }), { target: { value: "shop" } });
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(within(dialog).getByRole("button", { name: /keep exposing/ }));
    expect(await within(dialog).findByText(/created but is not applied yet.*address range 100\.66\.0\.0\/24 is full/)).toBeTruthy();
  });

  it("shows a rule that is not applied with its reason, never as healthy", async () => {
    get.mockResolvedValue({ data: [{ ...RULE, status: "inventory_stale", status_message: "the cluster's gateway has not reported its Services recently" }] } as never);
    panel();
    expect(await screen.findByText("Report is stale")).toBeTruthy();
    expect(screen.getByText(/has not reported its Services recently/)).toBeTruthy();
    expect(screen.queryByText("Applied")).toBeNull();
  });

  it("makes the administrator choose keep or withdraw before removing a rule", async () => {
    get.mockResolvedValue({ data: [RULE] } as never);
    del.mockResolvedValue({} as never);
    const onChanged = panel();
    fireEvent.click(await screen.findByRole("button", { name: "Remove rule" }));
    const dialog = screen.getByRole("dialog");
    const remove = within(dialog).getByRole("button", { name: "Remove rule" });
    expect(remove).toHaveProperty("disabled", true);
    expect(dialog.textContent).toMatch(/1 exposed port of 1 Service this rule created/);
    expect(dialog.textContent).toMatch(/kept but allow nothing/);

    fireEvent.click(within(dialog).getByRole("radio", { name: /Withdraw all of them/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove rule and withdraw exposures" }));
    await waitFor(() => expect(del).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/namespace-rules/{ruleId}",
      { params: { path: { orgId: "org", clusterId: "cluster", ruleId: "rule-1" }, query: { exposures: "withdraw" } } },
    ));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("offers no control without the manage permission", async () => {
    get.mockResolvedValue({ data: [RULE] } as never);
    panel({ canManage: false });
    expect(await screen.findByText("billing")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Expose every Service in a namespace…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove rule" })).toBeNull();
  });
});
