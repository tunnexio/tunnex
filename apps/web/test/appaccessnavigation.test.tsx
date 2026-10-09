import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AppAccessMemberTabs from "../src/components/AppAccessMemberTabs";
const get = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/api", () => ({ api: { GET: get } }));
const summary = { id: "app", name: "Payroll", description: "", icon: "app", icon_data_url: "", pending_count: 2 };
function managed(items = [] as typeof summary[], view = false, grant = false) {
  return { data: { items, can_view_applications: view, can_manage_grants: grant, limit: 1, offset: 0 } };
}
const requests = { data: { items: [], pending_count: 2, limit: 1, offset: 0 } };
const link = () => screen.queryByRole("link", { name: /^Manage access/ });
function mount(orgId = "org", path = "/app-access/my-applications") { return render(<MemoryRouter initialEntries={[path]}><AppAccessMemberTabs orgId={orgId} /></MemoryRouter>); }
beforeEach(() => { get.mockReset(); });
afterEach(cleanup);
describe("Applications workspace navigation authority", () => {
  it("hides Manage access and configuration from an unassigned ordinary member", async () => {
    get.mockResolvedValue(managed());
    mount();
    await act(async () => {});
    expect(link()).toBeNull();
    expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Access" })).toBeNull();
    expect(screen.getAllByRole("link").map(item => item.textContent)).toEqual(["My Applications", "Company apps", "My requests"]);
    expect(get).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/app-access/managed-apps", { params: { path: { orgId: "org" }, query: { limit: 1, offset: 0 } } });
  });
  it("shows only scoped Manage access for an assigned member, with the authoritative pending count", async () => {
    get.mockImplementation(async path => path.endsWith("/managed-apps") ? managed([summary]) : requests);
    mount();
    expect(await screen.findByRole("link", { name: "Manage access · 2 pending" })).toHaveProperty("pathname", "/app-access/managed-applications");
    expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Access" })).toBeNull();
    expect(screen.getAllByRole("link").map(item => item.textContent)).toEqual(["My Applications", "Company apps", "My requests", "Manage access · 2 pending"]);
    expect(get.mock.calls.every(([path]) => path.endsWith("/managed-apps") || path.endsWith("/access-requests"))).toBe(true);
  });
  it("keeps Applications and grant administration discoverable from actual global capabilities even with no apps", async () => {
    get.mockImplementation(async path => path.endsWith("/managed-apps") ? managed([], true, true) : requests);
    mount();
    expect(await screen.findByRole("link", { name: "Applications" })).toHaveProperty("pathname", "/app-access/applications");
    expect(screen.getByRole("link", { name: "Access" })).toHaveProperty("pathname", "/app-access/access");
    expect(screen.getByRole("link", { name: "Requests" })).toHaveProperty("pathname", "/app-access/requests");
    expect(screen.getByRole("link", { name: "My Applications" })).toBeTruthy();
    expect(link()).toBeNull();
  });
  it("distinguishes view-only application permission from grant authority", async () => {
    get.mockResolvedValue(managed([], true, false));
    mount();
    expect(await screen.findByRole("link", { name: "Applications" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Access" })).toBeNull();
    expect(link()).toBeNull();
  });
  it("removes management navigation after assignment revocation on refresh", async () => {
    let assigned = true;
    get.mockImplementation(async path => path.endsWith("/managed-apps") ? managed(assigned ? [summary] : []) : requests);
    mount(); await screen.findByRole("link", { name: "Manage access · 2 pending" });
    assigned = false; fireEvent(window, new Event("focus"));
    await waitFor(() => expect(link()).toBeNull());
    await act(async () => {});
    expect(link()).toBeNull();
  });
  it("fails closed after a failed refresh instead of retaining prior management controls", async () => {
    let failing = false;
    get.mockImplementation(async path => path.endsWith("/managed-apps") ? failing ? { error: { error: { message: "Permission read failed" } } } : managed([summary], true, true) : requests);
    mount(); await screen.findByRole("link", { name: "Applications" });
    failing = true; fireEvent(window, new Event("app-access-requests-changed"));
    await act(async () => {});
    expect(link()).toBeNull(); expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
    expect(screen.getByRole("link", { name: "My Applications" }).getAttribute("aria-current")).toBe("page");
  });
  it("fails closed for a network error and makes no directory or full-application fallback request", async () => {
    get.mockRejectedValue(new Error("network"));
    mount(); await act(async () => {});
    expect(link()).toBeNull(); expect(get).toHaveBeenCalledTimes(1);
  });
  it("ignores old-organization capabilities after switching organizations", async () => {
    let resolveOld!: (value: unknown) => void;
    get.mockImplementation((path, options) => path.endsWith("/managed-apps") && options.params.path.orgId === "old" ? new Promise(resolve => { resolveOld = resolve; }) : Promise.resolve(managed()));
    const page = mount("old");
    page.rerender(<MemoryRouter><AppAccessMemberTabs orgId="new" /></MemoryRouter>);
    await act(async () => { resolveOld(managed([summary], true, true)); });
    expect(link()).toBeNull(); expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
    expect(get.mock.calls.some(([path]) => path.endsWith("/access-requests"))).toBe(false);
  });
  it("does not resurrect revoked navigation when an older pending-count read finishes last", async () => {
    let resolvePending!: (value: unknown) => void; let assigned = true;
    get.mockImplementation((path) => path.endsWith("/managed-apps") ? Promise.resolve(managed(assigned ? [summary] : [])) : new Promise(resolve => { resolvePending = resolve; }));
    mount();
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    assigned = false; fireEvent(window, new Event("focus"));
    await act(async () => { resolvePending(requests); });
    expect(link()).toBeNull();
  });
  it("hides privileged navigation if the managed request projection fails", async () => {
    get.mockImplementation(async path => path.endsWith("/managed-apps") ? managed([summary], true, true) : { error: { error: { message: "Scope changed" } } });
    mount(); await act(async () => {});
    expect(link()).toBeNull(); expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
  });
});

it("keeps My Applications selected and visible while current permissions are refreshed", async () => {
  let resolveRefresh!: (value: unknown) => void;
  let refreshing = false;
  get.mockImplementation(path => path.endsWith("/managed-apps") ? refreshing ? new Promise(resolve => { resolveRefresh = resolve; }) : Promise.resolve(managed([], true, true)) : Promise.resolve(requests));
  mount();
  await screen.findByRole("link", { name: "Applications" });
  refreshing = true;
  fireEvent(window, new Event("focus"));
  expect(screen.getByRole("link", { name: "My Applications" }).getAttribute("aria-current")).toBe("page");
  expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
  expect(screen.queryByRole("link", { name: "Company apps" })).toBeNull();
  await act(async () => { resolveRefresh(managed([], true, true)); });
  expect(screen.getByRole("link", { name: "My Applications" }).getAttribute("aria-current")).toBe("page");
  expect(screen.getAllByRole("link").map(item => item.textContent)).toEqual(["Applications", "Access", "Requests", "My Applications"]);
});

it("keeps Requests present and selected on the safe managed-request route", async () => {
  get.mockImplementation(async path => path.endsWith("/managed-apps") ? managed([], true, true) : requests);
  mount("org", "/app-access/requests");
  const selected = await screen.findByRole("link", { name: "Requests" });
  expect(selected.getAttribute("aria-current")).toBe("page");
  expect(screen.getAllByRole("link").map(item => item.textContent)).toEqual(["Applications", "Access", "Requests", "My Applications"]);
  expect(get.mock.calls.every(([path]) => path.endsWith("/managed-apps") || path.endsWith("/access-requests"))).toBe(true);
});

it("does not briefly present the member tab set while global capabilities are unresolved", async () => {
  let resolveCapabilities!: (value: unknown) => void;
  get.mockImplementation(path => path.endsWith("/managed-apps") ? new Promise(resolve => { resolveCapabilities = resolve; }) : Promise.resolve(requests));
  mount("org", "/app-access/requests");
  expect(screen.getByText("Loading application navigation…")).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Company apps" })).toBeNull();
  expect(screen.getByRole("link", { name: "My Applications" })).toBeTruthy();
  await act(async () => { resolveCapabilities(managed([], true, true)); });
  expect(screen.getByRole("link", { name: "Requests" }).getAttribute("aria-current")).toBe("page");
});
