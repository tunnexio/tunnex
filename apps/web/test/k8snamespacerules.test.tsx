import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

vi.mock("../src/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import { K8sNamespaceRulesPanel } from "../src/components/K8sNamespaceRules";
import { api } from "../src/lib/api";

const get = vi.mocked(api.GET);
const post = vi.mocked(api.POST);
const del = vi.mocked(api.DELETE);
const patch = vi.mocked(api.PATCH);

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
  id: "rule-1", cluster_id: "cluster", namespace: "billing", excluded_services: [] as string[], selector: {} as Record<string, string>, status: "applied" as const, status_message: "",
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

  it("states what excluding a Service withdraws and needs a tick before saving (slice A)", async () => {
    const shop = { ...RULE, id: "rule-shop", namespace: "shop", excluded_services: ["legacy"], exposed_services: 2, exposed_ports: 3 };
    get.mockResolvedValue({ data: [shop] } as never);
    patch.mockResolvedValue({ data: { ...shop, excluded_services: ["web"], exposed_services: 1, exposed_ports: 1 } } as never);
    const onChanged = panel({
      exposed: [
        { namespace: "shop", name: "web", protocol: "tcp", ports: "80", namespaceRuleId: "rule-shop" },
        { namespace: "shop", name: "web", protocol: "tcp", ports: "443", namespaceRuleId: "rule-shop" },
        { namespace: "shop", name: "api", protocol: "tcp", ports: "8080", namespaceRuleId: "rule-shop" },
        { namespace: "shop", name: "manual", protocol: "tcp", ports: "1", namespaceRuleId: null },
      ],
    });
    expect(await screen.findByText("Excluded, never exposed by this rule: legacy")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Exclusions for shop" }));
    const dialog = screen.getByRole("dialog");
    const save = () => within(dialog).getByRole("button", { name: /^Save/ });
    expect(save()).toHaveProperty("disabled", true);

    // Only Services this rule exposes are offered; a hand-made exposure is not the rule's to withdraw.
    const select = within(dialog).getByRole("combobox", { name: "Exclude a Service this rule exposes" });
    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual(["Choose a Service…", "api", "web"]);
    fireEvent.change(select, { target: { value: "web" } });
    const impact = within(dialog).getByLabelText("What this change will do");
    expect(impact.textContent).toContain("2 ports of 1 Service this rule exposed are withdrawn at once, with no waiting period");
    expect(impact.textContent).toContain("Access rules that point at them are kept but allow nothing");
    expect(save().textContent).toBe("Save and withdraw 2 exposed ports");
    expect(save()).toHaveProperty("disabled", true);

    // Taking a name off the list is stated too. A pattern is refused while typing.
    fireEvent.click(within(dialog).getByRole("button", { name: "Stop excluding legacy" }));
    expect(impact.textContent).toContain("legacy: exposed again by the rule as a new exposure");
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Or name a Service" }), { target: { value: "web-*" } });
    expect(within(dialog).getByText(/Patterns are not supported/)).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "Add to the list" })).toHaveProperty("disabled", true);

    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Withdraw 2 exposed ports now" }));
    fireEvent.click(save());
    await waitFor(() => expect(patch).toHaveBeenCalledTimes(1));
    expect(patch.mock.calls[0]?.[1]).toMatchObject({ params: { path: { orgId: "org", clusterId: "cluster", ruleId: "rule-shop" } }, body: { excluded_services: ["web"] } });
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("keeps the exclusions dialog open with the reason when the change could not be applied (slice A)", async () => {
    const shop = { ...RULE, id: "rule-shop", namespace: "shop" };
    get.mockResolvedValue({ data: [shop] } as never);
    patch.mockResolvedValue({ data: { ...shop, excluded_services: ["later"], status: "inventory_stale", status_message: "the cluster's gateway has not reported its Services recently" } } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Exclusions for shop" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Or name a Service" }), { target: { value: "later" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Add to the list" }));
    // Nothing of "later" is exposed by the rule, so nothing is withdrawn and no tick is asked for.
    expect(within(dialog).getByLabelText("What this change will do").textContent).toContain("nothing is withdrawn");
    fireEvent.click(within(dialog).getByRole("button", { name: "Save exclusions" }));
    expect(await within(dialog).findByText(/The exclusions were saved but are not applied yet\. the cluster's gateway has not reported/)).toBeTruthy();
  });

  it("creates a rule with a label selector and says there is no count (slice B)", async () => {
    post.mockResolvedValue({ data: { ...RULE, id: "rule-2", namespace: "shop", selector: { app: "web", tier: "frontend" } } } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Expose every Service in a namespace…" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Namespace" }), { target: { value: "shop" } });
    const selector = within(dialog).getByRole("textbox", { name: "Only Services with these labels (optional)" });

    // A wildcard or an operator is refused with the reason, and the consequences are not offered.
    fireEvent.change(selector, { target: { value: "app=*" } });
    expect(within(dialog).getByText(/Wildcards and lists are not supported/)).toBeTruthy();
    expect(within(dialog).queryByLabelText("What this rule will do")).toBeNull();
    fireEvent.change(selector, { target: { value: "app!=web" } });
    expect(within(dialog).getByText(/Operators such as !=, in and ! are not supported/)).toBeTruthy();

    fireEvent.change(selector, { target: { value: "tier=frontend, app=web" } });
    const impact = within(dialog).getByLabelText("What this rule will do");
    expect(impact.textContent).toContain("labelled app=web, tier=frontend is exposed");
    expect(impact.textContent).toContain("The number is not shown here: the dashboard does not read Service labels");
    expect(impact.textContent).toContain("When a Service's labels stop matching for 10 minutes, its exposure is withdrawn");
    expect(impact.textContent).toContain("Nobody gains access.");
    const create = within(dialog).getByRole("button", { name: "Create namespace rule" });
    expect(create).toHaveProperty("disabled", true);
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Expose every Service in shop labelled app=web, tier=frontend, including Services added or labelled later" }));
    fireEvent.click(create);
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(post.mock.calls[0]?.[1]).toMatchObject({ body: { namespace: "shop", selector: { app: "web", tier: "frontend" } } });
  });

  it("shows a selector rule on an old gateway as not applied, never as healthy (slice B)", async () => {
    get.mockResolvedValue({ data: [{ ...RULE, selector: { app: "web" }, status: "gateway_too_old", status_message: "the cluster's gateway reports Services without labels: it is older than label selectors. Upgrade the gateway.", exposed_services: 0, exposed_ports: 0 }] } as never);
    panel();
    expect(await screen.findByText("Gateway too old for label selectors")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Upgrade the gateway");
    expect(screen.getByText("app=web")).toBeTruthy();
    expect(screen.queryByText("Applied")).toBeNull();
  });

  it("states that a changed selector withdraws after the wait and needs a tick (slice B)", async () => {
    const shop = { ...RULE, id: "rule-shop", namespace: "shop", selector: { app: "web" } };
    get.mockResolvedValue({ data: [shop] } as never);
    patch.mockResolvedValue({ data: { ...shop, selector: {} } } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Selector for shop" }));
    const dialog = screen.getByRole("dialog");
    const input = within(dialog).getByRole("textbox", { name: "Only Services with these labels" });
    expect(input).toHaveProperty("value", "app=web");
    const save = within(dialog).getByRole("button", { name: "Save selector" });
    expect(save).toHaveProperty("disabled", true);

    fireEvent.change(input, { target: { value: "" } });
    const impact = within(dialog).getByLabelText("What this change will do");
    expect(impact.textContent).toContain("every Service in shop that is not exposed yet is exposed");
    expect(impact.textContent).toContain("In 10 minutes: exposures this rule made for Services that no longer match are withdrawn");
    expect(save).toHaveProperty("disabled", true);
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Cover every Service in shop" }));
    fireEvent.click(save);
    await waitFor(() => expect(patch).toHaveBeenCalledTimes(1));
    expect(patch.mock.calls[0]?.[1]).toMatchObject({ params: { path: { ruleId: "rule-shop" } }, body: { selector: {} } });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("offers no control without the manage permission", async () => {
    get.mockResolvedValue({ data: [RULE] } as never);
    panel({ canManage: false });
    expect(await screen.findByText("billing")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Expose every Service in a namespace…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Exclusions for billing" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Selector for billing" })).toBeNull();
  });
});
