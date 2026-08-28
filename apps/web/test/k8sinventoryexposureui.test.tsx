import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

vi.mock("../src/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, POST: vi.fn(async () => ({ data: { service_child_ids: ["child"], pending_review_count: 0 } })) } };
});

import { ExposeServiceModal } from "../src/pages/Kubernetes";
import { api } from "../src/lib/api";

afterEach(cleanup);

const INVENTORY = {
  observed_at: "2026-08-28T06:00:00Z",
  fresh_until: "2026-08-28T06:05:00Z",
  next_cursor: null,
  items: [
    {
      inventory_ref: "55555555-5555-4555-8555-555555555551",
      namespace: "payments",
      service: "checkout-api",
      ports: [
        { port_ref: "66666666-6666-4666-8666-666666666661", name: "https", protocol: "tcp" as const, service_port: 443 },
        { port_ref: "66666666-6666-4666-8666-666666666662", name: "metrics", protocol: "tcp" as const, service_port: 9090 },
      ],
    },
  ],
};

describe("verified Kubernetes inventory exposure", () => {
  it("cascades namespace to Service to an atomic multi-port selection", async () => {
    const expose = vi.fn(async () => {});
    render(<ExposeServiceModal orgId="org" clusterId="cluster" fixtureInventory={INVENTORY} onFixtureExpose={expose} onClose={() => {}} onDone={() => {}} />);

    fireEvent.change(screen.getByRole("combobox", { name: "Namespace" }), { target: { value: "payments" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Service" }), { target: { value: INVENTORY.items[0].inventory_ref } });
    fireEvent.click(screen.getByRole("checkbox", { name: /https.*TCP 443/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /metrics.*TCP 9090/ }));
    fireEvent.click(screen.getByRole("button", { name: "Expose selected ports (2)" }));

    await waitFor(() => expect(expose).toHaveBeenCalledWith(INVENTORY.items[0].inventory_ref, [
      INVENTORY.items[0].ports[0].port_ref,
      INVENTORY.items[0].ports[1].port_ref,
    ]));
  });

  it("keeps unverified manual entry behind a separate advanced path", () => {
    render(<ExposeServiceModal orgId="org" clusterId="cluster" fixtureInventory={INVENTORY} onFixtureExpose={async () => {}} onClose={() => {}} onDone={() => {}} />);
    expect((screen.getByRole("button", { name: "Expose manual value" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByText("Advanced manual entry"));
    expect(screen.getByText(/Manual values are not verified/)).toBeTruthy();
  });

  it("uses the atomic inventory-reference endpoint in production mode", async () => {
    render(<ExposeServiceModal orgId="org" clusterId="cluster" fixtureInventory={INVENTORY} onClose={() => {}} onDone={() => {}} />);
    fireEvent.change(screen.getByRole("combobox", { name: "Namespace" }), { target: { value: "payments" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Service" }), { target: { value: INVENTORY.items[0].inventory_ref } });
    fireEvent.click(screen.getByRole("checkbox", { name: /https.*TCP 443/ }));
    fireEvent.click(screen.getByRole("button", { name: "Expose selected ports (1)" }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/inventory/{inventoryRef}/expose",
      { params: { path: { orgId: "org", clusterId: "cluster", inventoryRef: INVENTORY.items[0].inventory_ref } }, body: { port_refs: [INVENTORY.items[0].ports[0].port_ref] } },
    ));
  });
});
