import { Profiler } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NetworkFeatureControl } from "../src/components/NetworkFeatureControl";

const calls = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: calls }));

type Feature = "ipsec" | "kubernetes-scopes";
const scopes = (enabled = false, unlocked = true, revision = 3) => ({ enabled, revision, entitlement_unlocked: unlocked, effective: enabled && unlocked });
function page(feature: Feature = "ipsec", orgId = "org-a", canEdit = true, roles: Array<"admin" | "member"> = ["admin"]) {
  return <MemoryRouter><NetworkFeatureControl feature={feature} orgId={orgId} roles={roles} canEdit={canEdit} /></MemoryRouter>;
}
beforeEach(() => {
  vi.resetAllMocks();
  calls.GET.mockImplementation(async (path: string) => ({ data: path.endsWith("cluster-scope-settings") ? scopes() : { enabled: false, revision: 4 } }));
  calls.PUT.mockImplementation(async (path: string, request: { body: { enabled: boolean; expected_revision: number } }) => ({ data: path.endsWith("cluster-scope-settings") ? scopes(request.body.enabled, true, request.body.expected_revision + 1) : { enabled: request.body.enabled, revision: request.body.expected_revision + 1 } }));
});
afterEach(cleanup);

describe("central network feature activation", () => {
  it("reviews IPsec activation and sends the exact saved revision without changing connection intent", async () => {
    render(page());
    fireEvent.click(await screen.findByRole("button", { name: "Enable IPsec" }));
    expect(calls.PUT).not.toHaveBeenCalled();
    const review = screen.getByRole("dialog", { name: "Enable IPsec for this organization?" });
    expect(within(review).getByText(/Each connection still requires a capable gateway/)).toBeTruthy();
    fireEvent.click(within(review).getByRole("button", { name: "Confirm enable IPsec" }));
    await screen.findByRole("button", { name: "Disable IPsec" });
    expect(calls.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId: "org-a" } }, body: { enabled: true, expected_revision: 4 } });
  });

  it("allows cluster-scope withdrawal after entitlement loss while refusing activation", async () => {
    calls.GET.mockResolvedValue({ data: scopes(true, false, 9) });
    calls.PUT.mockResolvedValue({ data: scopes(false, false, 10) });
    render(page("kubernetes-scopes"));
    fireEvent.click(await screen.findByRole("button", { name: "Disable for organization" }));
    expect(calls.PUT).not.toHaveBeenCalled();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Disable and withdraw" }));
    await screen.findByText("Cluster scopes are disabled. Derived access was withdrawn; decisions were preserved.");
    expect(calls.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/k8s/cluster-scope-settings", { params: { path: { orgId: "org-a" } }, body: { enabled: false, expected_revision: 9 } });
    expect(screen.queryByRole("button", { name: "Enable for organization" })).toBeNull();
  });

  it.each([{}, { enabled: false, revision: -1 }, { enabled: "false", revision: 2 }])("does not turn malformed settings into an off-looking activation control (%j)", async (data) => {
    calls.GET.mockResolvedValue({ data });
    render(page());
    await screen.findByText("The server returned incomplete feature settings.");
    expect(screen.queryByRole("button", { name: "Enable IPsec" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry IPsec settings" }));
    expect(calls.PUT).not.toHaveBeenCalled();
  });

  it("withholds a second change when the server did not confirm a write", async () => {
    calls.PUT.mockResolvedValue({ data: { status: "updated" } });
    render(page());
    fireEvent.click(await screen.findByRole("button", { name: "Enable IPsec" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm enable IPsec" }));
    await screen.findByText("The server did not confirm the setting. Reload before another change.");
    expect(screen.queryByRole("button", { name: "Enable IPsec" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Disable IPsec" })).toBeNull();
    expect(calls.PUT).toHaveBeenCalledTimes(1);
  });

  it("withdraws confirmation and ignores a prior organization's pending activation", async () => {
    let finish!: (value: unknown) => void;
    calls.PUT.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const view = render(page());
    fireEvent.click(await screen.findByRole("button", { name: "Enable IPsec" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm enable IPsec" }));
    view.rerender(page("ipsec", "org-b", false));
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(calls.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId: "org-b" } } }));
    await act(async () => finish({ data: { enabled: true, revision: 5 } }));
    expect(screen.queryByText("IPsec is enabled for this organization. Connections are configured separately.")).toBeNull();
    expect(screen.queryByRole("button", { name: /Enable IPsec|Disable IPsec/ })).toBeNull();
    expect(calls.PUT).toHaveBeenCalledTimes(1);
  });

  it("never carries another feature's saved state into a selection commit", async () => {
    let selected: Feature = "ipsec";
    const leaked: boolean[] = [];
    const tree = () => <Profiler id="feature-selection" onRender={() => {
      if (selected === "kubernetes-scopes") leaked.push(Boolean(screen.queryByRole("button", { name: "Disable for organization" })));
    }}>{page(selected)}</Profiler>;
    calls.GET.mockImplementation(async (path: string) => ({ data: path.endsWith("cluster-scope-settings") ? scopes(false, true, 1) : { enabled: true, revision: 99 } }));
    const view = render(tree());
    await screen.findByRole("button", { name: "Disable IPsec" });
    selected = "kubernetes-scopes";
    view.rerender(tree());
    await screen.findByRole("button", { name: "Enable for organization" });
    expect(leaked.length).toBeGreaterThan(0);
    expect(leaked).not.toContain(true);
    expect(calls.PUT).not.toHaveBeenCalled();
  });
});
