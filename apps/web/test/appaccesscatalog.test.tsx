import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import AppAccessCompanyApplications from "../src/pages/AppAccessCompanyApplications";
import AppAccessRequests from "../src/pages/AppAccessRequests";
import AppAccessManagedApplications from "../src/pages/AppAccessManagedApplications";
import AppAccessCatalogSettings from "../src/components/AppAccessCatalogSettings";

const calls = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PATCH: vi.fn() }));
vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, ...calls } };
});
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "member" } }, logout: vi.fn() }) }));
const owner = { id: "owner", name: "Owner One", email: "owner@example.test", available: true };
const request = { id: "request", app_id: "app", app_name: "Payroll", requester: { id: "member", name: "Member", email: "member@example.test", available: true }, app_admin: owner, status: "pending", reason: "Quarter close", decision_reason: "", version: 2, created_at: "2026-10-04T10:00:00Z", decided_at: null, decided_by: null, grant_id: null };
const app = { id: "app", name: "Payroll", description: "Private payroll", icon: "app", icon_data_url: "", app_admin: owner, access_granted: false, require_mfa: true, mfa_required: true, mfa_setup_required: true, mfa_freshness_seconds: 900, latest_request: null };
const response = (items: unknown[], extra = {}) => ({ data: { items, limit: 20, offset: 0, ...extra } });
function mount(node: React.ReactNode) { return render(<MemoryRouter>{node}</MemoryRouter>); }
beforeEach(() => {
  calls.GET.mockReset(); calls.POST.mockReset(); calls.PATCH.mockReset();
  calls.GET.mockImplementation(async (path: string) => path.endsWith("/access-requests") ? response([], { pending_count: 0 }) : path.endsWith("/grant-subjects") ? response([{ id: owner.id, name: owner.name, email: owner.email, kind: "user" }]) : { error: { error: { message: "Unexpected read" } } });
});
afterEach(cleanup);

describe("Company app discovery and requests", () => {
  it("renders only server-returned display metadata and requests access without loading config or directory", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/company-apps") ? response([app], { availability: "available" }) : response([], { pending_count: 0 }));
    calls.POST.mockResolvedValue({ data: request });
    mount(<AppAccessCompanyApplications orgId="org" />);
    await screen.findByText("Payroll");
    expect(screen.queryByRole("link", { name: "Open Payroll" })).not.toBeTruthy();
    expect(screen.getByText(/App admin: Owner One/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Request access" }));
    fireEvent.change(screen.getByLabelText("Reason (optional)"), { target: { value: "Quarter close" } });
    fireEvent.click(screen.getByRole("button", { name: "Send request" }));
    await waitFor(() => expect(calls.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/access-requests", { params: { path: { orgId: "org", appId: "app" } }, body: { reason: "Quarter close" } }));
    expect(calls.GET.mock.calls.every(([path]) => path.endsWith("/company-apps") || path.endsWith("/access-requests") || path.endsWith("/managed-apps"))).toBe(true);
  });
  it("keeps Open for an entitled user even when MFA setup is required", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/company-apps") ? response([{ ...app, access_granted: true, launch_url: "https://payroll.apps.example.test/__tunnex_app/start" }], { availability: "available" }) : response([], { pending_count: 0 }));
    mount(<AppAccessCompanyApplications orgId="org" />);
    expect(await screen.findByRole("link", { name: "Open Payroll" })).toBeTruthy();
    expect(screen.getByText("MFA required")).toBeTruthy();
    expect(screen.getByText("Set up MFA when you open this app")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Request access/ })).not.toBeTruthy();
  });
  it("does not treat an approved request as a current grant", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/company-apps") ? response([{ ...app, latest_request: { ...request, status: "approved" } }], { availability: "available" }) : response([], { pending_count: 0 }));
    mount(<AppAccessCompanyApplications orgId="org" />);
    expect(await screen.findByRole("button", { name: "Request access again" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Open Payroll" })).not.toBeTruthy();
  });
  it("shows unavailable owner fallback and keeps pending request visible", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/company-apps") ? response([{ ...app, app_admin: { ...owner, available: false }, latest_request: request }], { availability: "available" }) : response([], { pending_count: 0 }));
    mount(<AppAccessCompanyApplications orgId="org" />);
    expect(await screen.findByText("Waiting for review")).toBeTruthy();
    expect(screen.getByText(/App admin unavailable/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Request access" })).not.toBeTruthy();
  });
  it("surfaces catalog failure instead of an empty catalog", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/company-apps") ? { error: { error: { message: "Catalog unavailable" } } } : response([], { pending_count: 0 }));
    mount(<AppAccessCompanyApplications orgId="org" />);
    expect(await screen.findByRole("button", { name: "Retry company apps" })).toBeTruthy();
    expect(screen.queryByText("No company applications are available in this view.")).not.toBeTruthy();
  });
});

describe("Access request history and review", () => {
  it("retains own pending request history without needing catalog visibility", async () => {
    calls.GET.mockImplementation(async (_path: string, options: any) => response(options.params.query.scope === "mine" ? [request] : [], { pending_count: 0 }));
    mount(<AppAccessRequests orgId="org" />);
    expect(await screen.findByText("Payroll")).toBeTruthy();
    expect(screen.getByText(/App admin: Owner One/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeTruthy();
    expect(calls.GET.mock.calls.every(([path]) => (path.endsWith("/access-requests") || path.endsWith("/managed-apps")))).toBe(true);
  });
  it("approves atomically with the observed request version and no separate grant call", async () => {
    calls.GET.mockResolvedValue(response([request], { pending_count: 1 }));
    calls.POST.mockResolvedValue({ data: { ...request, status: "approved" } });
    mount(<AppAccessRequests orgId="org" appId="app" managed embedded />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm approval" }));
    await waitFor(() => expect(calls.POST).toHaveBeenCalledTimes(1));
    expect(calls.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/access-requests/{requestId}/decision", { params: { path: { orgId: "org", requestId: "request" } }, body: { expected_version: 2, decision: "approved", reason: "", expires_at: null } });
  });
  it("preserves review input when another reviewer wins the version race", async () => {
    calls.GET.mockResolvedValue(response([request], { pending_count: 1 }));
    calls.POST.mockResolvedValue({ error: { error: { code: "version_conflict", message: "This request changed" } } });
    mount(<AppAccessRequests orgId="org" managed embedded />);
    fireEvent.click(await screen.findByRole("button", { name: "Reject" }));
    fireEvent.change(screen.getByLabelText("Rejection reason"), { target: { value: "Needs manager approval" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm rejection" }));
    await waitFor(() => expect(calls.POST).toHaveBeenCalledTimes(1));
    expect((screen.getByLabelText("Rejection reason") as HTMLTextAreaElement).value).toBe("Needs manager approval");
    expect(screen.getByRole("dialog")).toBeTruthy();
  });
  it("shows a request read failure separately from no requests", async () => {
    calls.GET.mockResolvedValue({ error: { error: { message: "Requests unavailable" } } });
    mount(<AppAccessRequests orgId="org" managed embedded />);
    await waitFor(() => expect(screen.queryByText("No access requests in this view.")).not.toBeTruthy());
    expect(await screen.findByText("Requests unavailable")).toBeTruthy();
  });
});

describe("Scoped App admin and visibility", () => {
  it("loads scoped grants without global settings, origin or directory reads", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/managed-apps") ? response([{ id: "app", name: "Payroll", description: "", icon: "app", icon_data_url: "", pending_count: 0 }]) : response([], { pending_count: 0 }));
    mount(<AppAccessManagedApplications orgId="org" appId="app" />);
    expect(await screen.findByRole("button", { name: "Add grant" })).toBeTruthy();
    expect(calls.GET.mock.calls.some(([path]) => path.endsWith("/applications/{appId}/managed-grants"))).toBe(true);
    expect(calls.GET.mock.calls.every(([path]) => /managed-apps|managed-grants|access-requests/.test(path))).toBe(true);
    expect(screen.queryByText("Origin connection")).not.toBeTruthy();
    expect(screen.queryByRole("link", { name: /Open/ })).not.toBeTruthy();
  });
  it("filters and pages Current and History only through the assigned app grant endpoint", async () => {
    const grants = Array.from({ length: 20 }, (_, index) => ({ id: `grant-${index}`, app_id: "app", subject_label: `Member ${index}`, subject_kind: "user", subject_id: `member-${index}`, status: "active", enabled: true, starts_at: null, expires_at: null, revoked_at: null, version: 1 }));
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/managed-apps") ? response([{ id: "app", name: "Payroll", description: "", icon: "app", icon_data_url: "", pending_count: 0 }]) : path.endsWith("/managed-grants") ? response(grants) : response([], { pending_count: 0 }));
    mount(<AppAccessManagedApplications orgId="org" appId="app" />);
    await screen.findByRole("table", { name: "Application grants" });
    const expectedQuery = (query: object) => expect(calls.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/managed-grants", { params: { path: { orgId: "org", appId: "app" }, query: { limit: 20, offset: 0, ...query } } });
    expectedQuery({ view: "current", status: undefined });
    expect(screen.getByRole("button", { name: "Current" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("option", { name: "Active and disabled" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "Expired" })).toBeNull();
    fireEvent.change(screen.getByRole("combobox", { name: "Grant status" }), { target: { value: "subject_unavailable" } });
    await screen.findByRole("table", { name: "Application grants" });
    expectedQuery({ view: "current", status: "subject_unavailable" });
    fireEvent.click(screen.getByRole("button", { name: "Next grants" }));
    await screen.findByRole("table", { name: "Application grants" });
    expectedQuery({ view: "current", status: "subject_unavailable", offset: 20 });
    fireEvent.click(screen.getByRole("button", { name: "History" }));
    await screen.findByRole("table", { name: "Application grants" });
    expectedQuery({ view: "history", status: undefined });
    expect(screen.getByRole("option", { name: "Revoked and expired" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "Scheduled" })).toBeNull();
    fireEvent.change(screen.getByRole("combobox", { name: "Grant status" }), { target: { value: "expired" } });
    await screen.findByRole("table", { name: "Application grants" });
    expectedQuery({ view: "history", status: "expired" });
    fireEvent.click(screen.getByRole("button", { name: "Current" }));
    await screen.findByRole("table", { name: "Application grants" });
    expectedQuery({ view: "current", status: undefined });
    expect(calls.GET.mock.calls.every(([path]) => /managed-apps|managed-grants|access-requests/.test(path))).toBe(true);
    expect(calls.POST).not.toHaveBeenCalled();
    expect(calls.PATCH).not.toHaveBeenCalled();
  });
  it("ignores a delayed previous grant view and surfaces scoped filter errors without a global fallback", async () => {
    let resolveCurrent!: (value: unknown) => void;
    calls.GET.mockImplementation((path: string, options: any) => {
      if (path.endsWith("/managed-apps")) return Promise.resolve(response([{ id: "app", name: "Payroll", description: "", icon: "app", icon_data_url: "", pending_count: 0 }]));
      if (!path.endsWith("/managed-grants")) return Promise.resolve(response([], { pending_count: 0 }));
      return options.params.query.view === "current" ? new Promise(resolve => { resolveCurrent = resolve; }) : Promise.resolve({ error: { error: { message: "Scoped grant history unavailable" } } });
    });
    mount(<AppAccessManagedApplications orgId="org" appId="app" />);
    fireEvent.click(await screen.findByRole("button", { name: "History" }));
    expect(await screen.findByText("Scoped grant history unavailable")).toBeTruthy();
    resolveCurrent(response([{ id: "old", app_id: "app", subject_label: "Stale current subject", subject_kind: "user", status: "active" }]));
    await waitFor(() => expect(screen.queryByText("Stale current subject")).toBeNull());
    expect(screen.getByText("Scoped grant history unavailable")).toBeTruthy();
    expect(calls.GET.mock.calls.every(([path]) => /managed-apps|managed-grants|access-requests/.test(path))).toBe(true);
  });
  it("fails closed when safe managed-app lookup loses ownership", async () => {
    calls.GET.mockResolvedValue(response([], { pending_count: 0 }));
    mount(<AppAccessManagedApplications orgId="org" appId="app" />);
    expect(await screen.findByText("This app is unavailable or you no longer manage its access.")).toBeTruthy();
    expect(calls.GET.mock.calls.some(([path]) => path.endsWith("/managed-grants"))).toBe(false);
  });
  it("displays managed-app read failure without falsely claiming no assigned apps", async () => {
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/managed-apps") ? { error: { error: { message: "Owner lookup unavailable" } } } : response([], { pending_count: 0 }));
    mount(<AppAccessManagedApplications orgId="org" />);
    expect(await screen.findByRole("button", { name: "Retry managed apps" })).toBeTruthy();
    expect(screen.queryByText("No applications are assigned to you for access management.")).not.toBeTruthy();
  });
  it("does not read or offer assignment without the administrator capability", () => {
    mount(<AppAccessCatalogSettings orgId="org" appId="app" permitted={false} dirty={false} onChanged={vi.fn()} />);
    expect(calls.GET).not.toHaveBeenCalled();
    expect(screen.queryByText("Show in Company apps")).not.toBeTruthy();
  });
  it("keeps visibility off until explicitly saved and assignment never creates an access grant", async () => {
    const settings = { app_id: "app", version: 5, catalog_visible: false, app_admin_user_id: owner.id, app_admin: owner };
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/access-management") ? { data: settings } : response([{ ...owner, kind: "user" }]));
    calls.PATCH.mockResolvedValue({ data: { ...settings, version: 6, catalog_visible: true } });
    mount(<AppAccessCatalogSettings orgId="org" appId="app" permitted dirty={false} onChanged={vi.fn()} />);
    const toggle = await screen.findByLabelText("Show in Company apps");
    expect((toggle as HTMLInputElement).checked).toBe(false);
    fireEvent.click(toggle);
    fireEvent.click(screen.getByRole("button", { name: "Save access management" }));
    await waitFor(() => expect(calls.PATCH).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/access-management", { params: { path: { orgId: "org", appId: "app" } }, body: { expected_version: 5, catalog_visible: true, app_admin_user_id: "owner" } }));
    expect(calls.POST).not.toHaveBeenCalled();
  });
});

describe("Catalog scope and lifecycle regressions", () => {
  it("preserves visibility and pending review fallback when an App admin is unassigned", async () => {
    const settings = { app_id: "app", version: 8, catalog_visible: true, app_admin_user_id: owner.id, app_admin: owner };
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/access-management") ? { data: settings } : response([{ ...owner, kind: "user" }]));
    calls.PATCH.mockResolvedValue({ data: { ...settings, version: 9, app_admin_user_id: null, app_admin: null } });
    mount(<AppAccessCatalogSettings orgId="org" appId="app" permitted dirty={false} onChanged={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove App admin assignment" }));
    expect((screen.getByLabelText("Show in Company apps") as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Save access management" }));
    await waitFor(() => expect(calls.PATCH).toHaveBeenCalledWith(expect.stringContaining("/access-management"), expect.objectContaining({ body: { expected_version: 8, catalog_visible: true, app_admin_user_id: null } })));
  });
  it("does not offer a default-off editable form when settings could not be read", async () => {
    calls.GET.mockResolvedValue({ error: { error: { message: "Settings unavailable" } } });
    mount(<AppAccessCatalogSettings orgId="org" appId="app" permitted dirty={false} onChanged={vi.fn()} />);
    expect(await screen.findByText("Settings unavailable")).toBeTruthy();
    expect(screen.queryByLabelText("Show in Company apps")).toBeNull();
    expect(screen.queryByRole("button", { name: "Save access management" })).toBeNull();
  });
  it("ignores a previous organization's delayed company catalog", async () => {
    let resolveOld!: (value: unknown) => void;
    calls.GET.mockImplementation((path: string, options: any) => {
      if (!path.endsWith("/company-apps")) return Promise.resolve(response([], { pending_count: 0 }));
      if (options.params.path.orgId === "old") return new Promise(resolve => { resolveOld = resolve; });
      return Promise.resolve(response([{ ...app, name: "New company app" }], { availability: "available" }));
    });
    const rendered = mount(<AppAccessCompanyApplications orgId="old" />);
    rendered.rerender(<MemoryRouter><AppAccessCompanyApplications orgId="new" /></MemoryRouter>);
    await screen.findByText("New company app");
    resolveOld(response([{ ...app, name: "Old private company app" }], { availability: "available" }));
    await waitFor(() => expect(screen.queryByText("Old private company app")).toBeNull());
  });
  it("does not duplicate a pending approval when clicked twice", async () => {
    calls.GET.mockResolvedValue(response([request], { pending_count: 1 }));
    calls.POST.mockImplementation(() => new Promise(() => {}));
    mount(<AppAccessRequests orgId="org" managed embedded />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    const button = screen.getByRole("button", { name: "Confirm approval" });
    fireEvent.click(button); fireEvent.click(button);
    expect(calls.POST).toHaveBeenCalledTimes(1);
  });
  it("confirms scoped grant disable with the observed version and no global API writes", async () => {
    const grant = { id: "grant", app_id: "app", subject_label: "Member", subject_kind: "user", subject_id: "member", status: "active", enabled: true, starts_at: null, expires_at: null, revoked_at: null, version: 3 };
    calls.GET.mockImplementation(async (path: string) => path.endsWith("/managed-apps") ? response([{ id: "app", name: "Payroll", description: "", icon: "app", icon_data_url: "", pending_count: 0 }]) : path.endsWith("/managed-grants") ? response([grant]) : response([], { pending_count: 0 }));
    calls.PATCH.mockResolvedValue({ data: { ...grant, enabled: false, version: 4 } });
    mount(<AppAccessManagedApplications orgId="org" appId="app" />);
    fireEvent.click(await screen.findByRole("button", { name: "Disable" }));
    expect(calls.PATCH).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm grant disable" }));
    await waitFor(() => expect(calls.PATCH).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}/managed-grants/{grantId}", { params: { path: { orgId: "org", appId: "app", grantId: "grant" } }, body: { expected_version: 3, enabled: false, starts_at: null, expires_at: null } }));
  });
});
