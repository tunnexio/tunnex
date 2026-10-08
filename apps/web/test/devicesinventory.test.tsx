import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Device, Node } from "../src/lib/api";
import DevicesInventory from "../src/components/DevicesInventory";

const device = (index: number, values: Partial<Device> = {}): Device => ({
  id: `device-${index}`, user_id: `owner-${index}`, node_id: "gateway-a", name: `Device ${index}`,
  public_key: "wg-key", full_tunnel: false, status: "active", assigned_ip: `10.99.0.${index}`,
  created_at: "2026-10-08T08:00:00Z", platform: "macos", ...values,
});
const nodes: Node[] = [{ id: "gateway-a", name: "Office gateway", status: "active", agent_version: "1.0.0", enrolled_at: "2026-10-08T08:00:00Z" }];
function mount(devices: Device[], values: { busy?: boolean; canMutate?: boolean; url?: string; ownerEmail?: Map<string, string> } = {}) {
  const onInspect = vi.fn();
  const onRequestAction = vi.fn();
  const onRefresh = vi.fn();
  const lastSeenLabel = vi.fn((value: Device) => `Reported handshake for ${value.id}`);
  const props = { devices, nodes, ownerEmail: values.ownerEmail ?? new Map<string, string>(), busy: values.busy ?? false, canMutate: values.canMutate ?? true, lastSeenLabel, onInspect, onRequestAction, onRefresh };
  const ui = (next = props) => <MemoryRouter initialEntries={[values.url ?? "/devices"]}><DevicesInventory {...next} /></MemoryRouter>;
  const view = render(ui());
  return { ...view, ...props, ui };
}
const row = (name: string) => screen.getByRole("button", { name }).closest("tr")!;
const names = () => within(screen.getByRole("table", { name: "Devices" })).getAllByRole("row").slice(1).map(value => within(value).getByRole("button", { name: /^Device \d+$/ }).textContent);
function menu(name: string) {
  fireEvent.click(screen.getByRole("button", { name: `Device actions for ${name}` }));
  return within(screen.getByRole("menu", { name: `Device actions for ${name}` }));
}
afterEach(cleanup);

describe("DevicesInventory loaded inventory", () => {
  it("omits pagination for ten devices and never presents a bulk mutation without a selection", () => {
    mount(Array.from({ length: 10 }, (_, index) => device(index + 1)));
    expect(names()).toHaveLength(10);
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(screen.queryByRole("group", { name: "Selected device actions" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("pages all 55 devices, preserves the short last page and applies real page-size changes", () => {
    mount(Array.from({ length: 55 }, (_, index) => device(index + 1)));
    expect(names()).toEqual(Array.from({ length: 20 }, (_, index) => `Device ${index + 1}`));
    fireEvent.click(screen.getByRole("button", { name: "Next devices page" }));
    expect(names()[0]).toBe("Device 21");
    fireEvent.click(screen.getByRole("button", { name: "Next devices page" }));
    expect(names()).toEqual(Array.from({ length: 15 }, (_, index) => `Device ${index + 41}`));
    expect(screen.getByRole("button", { name: "Next devices page" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "Previous devices page" }));
    expect(names()[0]).toBe("Device 21");
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(names()).toHaveLength(50);
    expect(names()[0]).toBe("Device 1");
    fireEvent.click(screen.getByRole("button", { name: "Next devices page" }));
    expect(names()).toEqual(["Device 51", "Device 52", "Device 53", "Device 54", "Device 55"]);
    expect(screen.getByRole("button", { name: "Previous devices page" })).toHaveProperty("disabled", false);
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    expect(names()).toHaveLength(10);
    expect(names()[0]).toBe("Device 1");
  });

  it("retains selections across pages and owner searches, but sends only eligible current devices", () => {
    const devices = Array.from({ length: 55 }, (_, index) => device(index + 1, index === 40 ? { status: "revoked" } : {}));
    const view = mount(devices, { ownerEmail: new Map([["owner-41", "former.owner@example.test"]]) });
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Device 1" }));
    fireEvent.click(screen.getByRole("button", { name: "Next devices page" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Device 21" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search devices" }), { target: { value: "former.owner@example.test revoked" } });
    expect(names()).toEqual(["Device 41"]);
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Device 41" }));
    const selected = within(screen.getByRole("group", { name: "Selected device actions" }));
    expect(selected.getByText("3 selected")).toBeTruthy();
    expect(selected.getByText("2 outside this page")).toBeTruthy();
    expect(selected.getByText("2 of 3")).toBeTruthy();
    expect(selected.getByText("1 of 3")).toBeTruthy();
    fireEvent.click(selected.getByRole("button", { name: "Revoke" }));
    expect(view.onRequestAction).toHaveBeenLastCalledWith("revoke", [devices[0], devices[20]]);
    fireEvent.click(selected.getByRole("button", { name: "Remove" }));
    expect(view.onRequestAction).toHaveBeenLastCalledWith("remove", [devices[40]]);
    fireEvent.change(screen.getByRole("textbox", { name: "Search devices" }), { target: { value: "" } });
    expect(names()[0]).toBe("Device 1");
    expect(screen.getByRole("checkbox", { name: "Select Device 1" })).toHaveProperty("checked", true);
    view.rerender(view.ui({ ...view, devices: devices.filter(value => value.id !== "device-21") }));
    expect(screen.getByText("2 selected")).toBeTruthy();
  });

  it("selects only the current page until all matching devices are explicitly requested", () => {
    const devices = Array.from({ length: 55 }, (_, index) => device(index + 1));
    const view = mount(devices);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 20 on this page" }));
    expect(screen.getByText("20 selected")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(view.onRequestAction).toHaveBeenLastCalledWith("revoke", devices.slice(0, 20));
    fireEvent.click(screen.getByRole("button", { name: "Select all 55 matching" }));
    expect(screen.getByText("55 selected")).toBeTruthy();
    expect(screen.getByText("35 outside this page")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(view.onRequestAction).toHaveBeenLastCalledWith("revoke", devices);
  });

  it("keeps lifecycle mutations state-specific and routes pending approval without granting authority", () => {
    const devices = [device(1), device(2, { status: "revoked" }), device(3, { status: "pending" }), device(4, { status: "suspended" })];
    const view = mount(devices);
    let actions = menu("Device 1");
    expect(actions.getByRole("menuitem", { name: "Remove" })).toHaveProperty("disabled", true);
    fireEvent.click(actions.getByRole("menuitem", { name: "Revoke" }));
    expect(view.onRequestAction).toHaveBeenLastCalledWith("revoke", [devices[0]]);
    actions = menu("Device 2");
    expect(actions.getByRole("menuitem", { name: "Revoke" })).toHaveProperty("disabled", true);
    fireEvent.click(actions.getByRole("menuitem", { name: "Remove" }));
    expect(view.onRequestAction).toHaveBeenLastCalledWith("remove", [devices[1]]);
    actions = menu("Device 3");
    expect(actions.getByRole("menuitem", { name: "Review approval" }).getAttribute("href")).toBe("/devices/approvals");
    expect(actions.getByRole("menuitem", { name: "Revoke" })).toHaveProperty("disabled", true);
    expect(actions.getByRole("menuitem", { name: "Remove" })).toHaveProperty("disabled", true);
    expect(actions.queryByRole("menuitem", { name: "Approve" })).toBeNull();
    expect(actions.queryByRole("menuitem", { name: "Reject" })).toBeNull();
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Device 4" }));
    expect(screen.getByRole("button", { name: "Revoke" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Remove" })).toHaveProperty("disabled", true);
    expect(view.onRequestAction).toHaveBeenCalledTimes(2);
  });

  it("keeps OpenVPN liveness unknown and never presents an inactive device as connected or posture-compliant", () => {
    const devices = [
      device(1, { health_state: "compliant", last_handshake_at: "2026-10-08T08:00:00Z" }),
      device(2, { public_key: "", last_handshake_at: "2026-10-08T08:00:00Z", online: true }),
      device(3, { status: "revoked", health_state: "compliant", needs_reexport: true }),
      device(4, { status: "pending", health_state: "compliant" }),
      device(5, { status: "suspended", health_state: "noncompliant", health_blocked: true, needs_reexport: true }),
      device(6, { health_state: "unknown" }),
      device(7, { health_state: "unknown", health_reported_at: "2026-07-16T00:00:00Z" }),
      device(8, { platform: "linux", health_state: "compliant" }),
    ];
    const view = mount(devices);
    expect(within(row("Device 1")).getByText("posture ok")).toBeTruthy();
    expect(within(row("Device 2")).getByText("liveness not reported")).toBeTruthy();
    expect(within(row("Device 2")).queryByText(/Reported handshake/)).toBeNull();
    for (const name of ["Device 3", "Device 4", "Device 5"]) {
      expect(within(row(name)).queryByText("posture ok")).toBeNull();
      expect(within(row(name)).queryByText(/Reported handshake/)).toBeNull();
    }
    expect(within(row("Device 3")).queryByText("re-export needed")).toBeNull();
    expect(within(row("Device 5")).getByText("posture blocked")).toBeTruthy();
    expect(within(row("Device 5")).getByText("re-export needed")).toBeTruthy();
    expect(within(row("Device 6")).getByText("posture not reported")).toBeTruthy();
    expect(within(row("Device 7")).getByText("posture stale")).toBeTruthy();
    expect(within(row("Device 8")).getByText("Not supported")).toBeTruthy();
    expect(new Set(view.lastSeenLabel.mock.calls.map(([value]) => value.id))).toEqual(new Set(["device-1", "device-6", "device-7", "device-8"]));
  });

  it("scopes gateway counts and targets to the supplied gateway while preserving an escape to the full inventory", () => {
    const devices = [device(1), device(2, { node_id: "gateway-b", status: "revoked" })];
    const view = mount(devices, { url: "/devices?gateway=gateway-a&keep=1" });
    expect(names()).toEqual(["Device 1"]);
    expect(screen.getByRole("button", { name: "All (1)" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Show all gateways" }).getAttribute("href")).toBe("/devices?keep=1");
    fireEvent.click(screen.getByRole("button", { name: "Device 1" }));
    expect(view.onInspect).toHaveBeenCalledWith("device-1");
    fireEvent.click(screen.getByRole("button", { name: "Refresh devices" }));
    expect(view.onRefresh).toHaveBeenCalledTimes(1);
  });

  it("withdraws selected lifecycle authority when verification is lost while retaining read-only inspection", () => {
    const view = mount([device(1)]);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Device 1" }));
    expect(screen.getByRole("group", { name: "Selected device actions" })).toBeTruthy();
    view.rerender(view.ui({ ...view, canMutate: false }));
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("group", { name: "Selected device actions" })).toBeNull();
    const actions = menu("Device 1");
    expect(actions.queryByRole("menuitem", { name: "Revoke" })).toBeNull();
    expect(actions.queryByRole("menuitem", { name: "Remove" })).toBeNull();
    fireEvent.click(actions.getByRole("menuitem", { name: "View details" }));
    expect(view.onInspect).toHaveBeenCalledWith("device-1");
    expect(view.onRequestAction).not.toHaveBeenCalled();
    view.rerender(view.ui());
    expect(screen.queryByRole("group", { name: "Selected device actions" })).toBeNull();
    expect(screen.getByRole("checkbox", { name: "Select Device 1" })).toHaveProperty("checked", false);
  });
});
