import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OrgProvider, useOrg } from "../src/lib/useOrg";
import type { Org } from "../src/lib/api";

const get = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: get } }));
const organizations: Org[] = ["a", "b"].map(id => ({ id: `org-${id}`, name: `Organization ${id}`, slug: id, pool_cidr: "100.64.0.0/16", max_agent_identities: null, managed_agent_runtime_enabled: false, agent_policy_templates_enabled: false, agent_jit_access_enabled: false, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" }));
function Consumer() {
  const { org, orgs, setOrg, updateOrg } = useOrg();
  return <>
    <p role="status">{org ? `${org.name}: runtime ${org.managed_agent_runtime_enabled ? "on" : "off"}` : "Loading organizations"}</p>
    <p>{orgs.map(value => value.name).join(", ")}</p>
    <button onClick={() => updateOrg({ ...organizations[0], managed_agent_runtime_enabled: true })}>Apply confirmed current organization</button>
    <button onClick={() => updateOrg({ ...organizations[1], name: "Renamed organization b", managed_agent_runtime_enabled: true })}>Apply confirmed other organization</button>
    <button onClick={() => updateOrg({ ...organizations[0], id: "unknown-org", name: "Injected organization" })}>Apply unknown organization</button>
    <button onClick={() => setOrg("org-b")}>Select organization b</button>
  </>;
}
beforeEach(() => {
  vi.resetAllMocks();
  window.localStorage.removeItem("tunnex.currentOrg");
  get.mockResolvedValue({ data: organizations });
});
afterEach(cleanup);

it("propagates confirmed organization fields to consumers without fetching or changing selection", async () => {
  render(<OrgProvider><Consumer /></OrgProvider>);
  await screen.findByText("Organization a: runtime off");
  fireEvent.click(screen.getByRole("button", { name: "Apply confirmed current organization" }));
  expect(screen.getByRole("status").textContent).toBe("Organization a: runtime on");
  fireEvent.click(screen.getByRole("button", { name: "Apply confirmed other organization" }));
  expect(screen.getByRole("status").textContent).toBe("Organization a: runtime on");
  fireEvent.click(screen.getByRole("button", { name: "Select organization b" }));
  expect(screen.getByRole("status").textContent).toBe("Renamed organization b: runtime on");
  expect(get).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations");
});

it("cannot create membership or select an unknown organization through a confirmed-row update", async () => {
  render(<OrgProvider><Consumer /></OrgProvider>);
  await screen.findByText("Organization a: runtime off");
  fireEvent.click(screen.getByRole("button", { name: "Apply unknown organization" }));
  expect(screen.queryByText(/Injected organization/)).toBeNull();
  expect(screen.getByRole("status").textContent).toBe("Organization a: runtime off");
  expect(get).toHaveBeenCalledTimes(1);
});
