import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EntityPicker } from "../src/components/EntityPicker";
import { K8S_API_OFF_REASON, K8S_API_UNREAD_REASON, type K8sApiTarget } from "../src/lib/k8sapiaccess";
import { destinationOptions } from "../src/lib/policyview";

// K8N-3 — the access-rule editor's destination list, rendered. Every registered cluster's Kubernetes API
// is LISTED, because the picker never hides a row it can explain. It can be CHOSEN only while API access
// is on for that cluster: a cluster whose API access is off (or could not be read) is a disabled row that
// says why, and neither a click nor Enter selects it. The server refuses the rule as well
// (400 k8s_api_not_enabled); this is the explanation in front of that refusal.

const ON: K8sApiTarget = { clusterId: "c-prod", clusterName: "prod", access: { enabled: true, fqdn: "kubernetes.default.svc.prod.k8s.acme.com", vip: "100.66.0.9" } };
// Never turned on: the server still serves the name the API would have, and no address.
const OFF: K8sApiTarget = { clusterId: "c-demo", clusterName: "demo", access: { enabled: false, fqdn: "kubernetes.default.svc.demo.k8s.acme.com", vip: null } };
const UNREAD: K8sApiTarget = { clusterId: "c-edge", clusterName: "edge", access: null };

afterEach(cleanup);

function picker(srcKind: string) {
  const select = vi.fn();
  render(<EntityPicker label="Destination" value="" onSelect={select}
    options={destinationOptions({ groups: [], resources: [], sites: [], services: [], k8sApis: [OFF, UNREAD, ON], srcKind, srcSite: "" })} />);
  const input = screen.getByRole("combobox");
  fireEvent.focus(input);
  const row = (name: string) => within(screen.getByRole("listbox")).getByText(name).closest("button") as HTMLButtonElement;
  return { select, input, row };
}

describe("rule editor destination list — a cluster whose API access is off", () => {
  it("lists the cluster's API as a disabled row that says API access is off", () => {
    const { row } = picker("group");
    const off = row("Kubernetes API of demo");
    expect(off.disabled).toBe(true);
    expect(off.textContent).toContain(K8S_API_OFF_REASON);
    expect(off.title).toBe(K8S_API_OFF_REASON);
    const unread = row("Kubernetes API of edge");
    expect(unread.disabled).toBe(true);
    expect(unread.textContent).toContain(K8S_API_UNREAD_REASON);
    // The cluster whose API access is on is an ordinary, selectable row with no warning.
    const on = row("Kubernetes API of prod");
    expect(on.disabled).toBe(false);
    expect(on.textContent).not.toContain("API access is off");
  });

  it("cannot be chosen by click or by keyboard; the cluster with API access on can", () => {
    const { select, input, row } = picker("user");
    fireEvent.click(row("Kubernetes API of demo"));
    fireEvent.click(row("Kubernetes API of edge"));
    // The first row is the cluster whose API access is off: Enter on it selects nothing.
    expect(document.getElementById(input.getAttribute("aria-activedescendant")!)?.textContent).toContain("Kubernetes API of demo");
    fireEvent.keyDown(input, { key: "Enter" });
    // Searching for it by name and pressing Enter selects nothing either.
    fireEvent.change(input, { target: { value: "demo" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(select).not.toHaveBeenCalled();
    expect(screen.getByRole("listbox")).toBeTruthy();

    fireEvent.change(input, { target: { value: "" } });
    fireEvent.click(row("Kubernetes API of prod"));
    expect(select).toHaveBeenCalledTimes(1);
    expect(select.mock.calls[0]![0]).toMatchObject({ kind: "k8s_api", value: "c-prod" });
  });
});
