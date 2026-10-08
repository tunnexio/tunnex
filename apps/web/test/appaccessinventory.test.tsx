import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { components } from "@tunnex/shared";
import AppAccessInventoryTable from "../src/components/AppAccessInventoryTable";
import { api } from "../src/lib/api";
type Application = components["schemas"]["AppAccessApplication"];
const state = vi.hoisted(() => ({ publications: {} as Record<string, unknown>, readFail: false, conflict: "", grantFail: "", entitled: true, enabled: true, domainReady: true }));
function app(id: string, name: string, publication_state: Application["publication_state"] = "published"): Application {
  return { require_mfa: false, mfa_freshness_seconds: 900, id, org_id: "org-1", version: 7, draft_revision: 7, state: "draft", publication_state, active_revision: publication_state === "published" ? 3 : undefined, draft: { allowed_destination_cidrs: [], origin_ca_digest: "", name, description: "", icon: "app", origin_url: "https://private.test", public_hostname: `${id}.apps.test`, gateway_id: "gateway-1", idle_timeout_seconds: 1800, absolute_timeout_seconds: 28800, revision: 7, digest: "a".repeat(64), created_at: "2026-10-04T00:00:00Z" }, connector_status: "supported", created_at: "2026-10-04T00:00:00Z", updated_at: "2026-10-04T00:00:00Z" };
}
function publication(disabled = false, withdrawn = false) {
  return { application_version: 7, rollback_revisions: [], browser_capability: "supported", active: { state: disabled ? "disabled" : "active", withdrawal_confirmed: withdrawn, authority_version: 11, hostname: "payroll.apps.test" } };
}
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: {
  GET: vi.fn(async (path: string, options: { params: { path: { appId?: string } } }) => {
    if (path.endsWith("/publication")) return state.readFail ? { error: { error: { message: "Publication unavailable" } } } : { data: state.publications[options.params.path.appId!] ?? publication() };
    if (path.endsWith("/settings")) return { data: { enabled: state.enabled, entitlement_available: state.entitled, domain_ready: state.domainReady, version: 1 } };
    if (path.endsWith("/members")) return { data: [{ user_id: "u1", name: "Alice", email: "alice@test", status: "active" }, { user_id: "u2", name: "Inactive", email: "inactive@test", status: "deactivated" }] };
    if (path.endsWith("/groups")) return { data: [{ id: "g1", name: "Engineering", member_count: 3 }] };
    throw Error(path);
  }),
  POST: vi.fn(async (path: string, options: { params: { path: { appId?: string } }; body: { app_id?: string } }) => {
    if (path.endsWith("/grants")) return options.body.app_id === state.grantFail ? { error: { error: { message: "Grant rejected" } } } : { data: { id: "grant-1" } };
    if (options.params.path.appId === state.conflict) return { error: { error: { code: "version_conflict" } }, response: { status: 409 } };
    return { data: publication(true, false) };
  }),
  DELETE: vi.fn(async (_path: string, options: { params: { path: { appId: string } } }) => options.params.path.appId === state.conflict ? { error: { error: { code: "version_conflict" } }, response: { status: 409 } } : { response: { status: 204 } }),
} }));
const changed = vi.fn();
beforeEach(() => { Object.assign(state, { publications: {}, readFail: false, conflict: "", grantFail: "", entitled: true, enabled: true, domainReady: true }); vi.clearAllMocks(); });
afterEach(cleanup);
function show(applications = [app("a1", "Payroll"), app("a2", "Billing")], permissions = { manage: true, grant: true, canGrant: true }) {
  return render(<MemoryRouter><AppAccessInventoryTable orgId="org-1" applications={applications} {...permissions} empty="No applications" onChanged={changed} /></MemoryRouter>);
}
function rowAction(name: string, action: string) {
  const trigger = screen.getByRole("button", { name: `Actions for ${name}` });
  if (trigger.getAttribute("aria-expanded") !== "true") fireEvent.click(trigger);
  const menu = screen.getByRole("menu", { name: `Actions for ${name}` });
  return within(menu).getByRole("menuitem", { name: action === "Disable" || action === "Delete" ? `${action} application` : action });
}
function bulkAction(action: string) { return within(document.querySelector(".tnx-table-selection") as HTMLElement).getByRole("button", { name: action }); }

describe("Applications inventory actions", () => {
  it("reveals bulk controls only for an explicit selection and hides them when cleared", () => {
    show();
    expect(document.querySelector(".tnx-table-selection")).toBeNull();
    expect(screen.queryByRole("button", { name: "Disable" })).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Payroll" }));
    expect(bulkAction("Disable")).toBeTruthy();
    expect(screen.getByRole("checkbox", { name: "Select Billing" })).toHaveProperty("checked", false);
    fireEvent.click(bulkAction("Clear"));
    expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", false);
    expect(document.querySelector(".tnx-table-selection")).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("opens row actions from the keyboard and returns focus after Escape", () => {
    show();
    const trigger = screen.getByRole("button", { name: "Actions for Payroll" });
    trigger.focus();
    fireEvent.keyDown(trigger, { key: "ArrowDown" });
    const menu = screen.getByRole("menu", { name: "Actions for Payroll" });
    const grant = within(menu).getByRole("menuitem", { name: "Grant access" });
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(document.activeElement).toBe(grant);
    fireEvent.keyDown(grant, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(trigger);
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("uses the shared table, selects the current page, and names the full disable confirmation", async () => {
    show();
    const table = screen.getByRole("table", { name: "Applications" });
    expect(table.querySelector("thead")).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 2 on this page" }));
    expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", true);
    expect(screen.getByRole("checkbox", { name: "Select Billing" })).toHaveProperty("checked", true);
    fireEvent.click(bulkAction("Disable"));
    const dialog = await screen.findByRole("dialog", { name: "Disable applications" });
    expect(within(dialog).getByText("2 applications selected")).toBeTruthy();
    expect(within(dialog).getByText("Payroll")).toBeTruthy();
    expect(within(dialog).getByText("Billing")).toBeTruthy();
    expect(within(dialog).getByText(/Are you sure/)).toBeTruthy();
    expect(within(dialog).getByText(/members with existing grants/)).toBeTruthy();
    expect(within(dialog).getByText(/Live connections may take a few seconds to close/)).toBeTruthy();
    await waitFor(() => expect(screen.getByRole("button", { name: "Confirm disable" })).toHaveProperty("disabled", false));
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("allows disabling after entitlement loss and never requires a grant lookup or removal", async () => {
    state.entitled = false;
    show([app("a1", "Payroll")], { manage: true, grant: true, canGrant: false });
    expect(rowAction("Payroll", "Grant access")).toHaveProperty("disabled", true);
    fireEvent.click(rowAction("Payroll", "Disable"));
    await waitFor(() => expect(screen.getByRole("button", { name: "Confirm disable" })).toHaveProperty("disabled", false));
    fireEvent.click(screen.getByRole("button", { name: "Confirm disable" }));
    await screen.findByText(/Disabled. Waiting for server withdrawal/);
    expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/publication\/disable$/), { params: { path: { orgId: "org-1", appId: "a1" } }, body: { expected_application_version: 7, expected_authority_version: 11 } });
    expect(api.GET).not.toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.anything());
  });

  it("blocks deletion until disabled, withdrawn and free of a pending publication", async () => {
    state.publications = { a2: publication(true, false), a3: { ...publication(true, true), pending_operation: { status: "checking" } }, a4: publication(true, true) };
    show([app("a1", "Payroll"), app("a2", "Billing", "disabled"), app("a3", "Pending", "disabled"), app("a4", "Ready", "disabled")]);
    await screen.findByText(/Withdrawal confirmed · Ready to delete/);
    expect(rowAction("Payroll", "Delete")).toHaveProperty("disabled", true);
    expect(rowAction("Billing", "Delete")).toHaveProperty("disabled", true);
    expect(rowAction("Pending", "Delete")).toHaveProperty("disabled", true);
    expect(rowAction("Ready", "Delete")).toHaveProperty("disabled", false);
    expect(api.DELETE).not.toHaveBeenCalled();
    fireEvent.click(rowAction("Ready", "Delete"));
    await waitFor(() => expect(screen.getByRole("button", { name: "Confirm delete" })).toHaveProperty("disabled", false));
    expect(screen.getByText(/history and hostname reservations are retained/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
    await screen.findByText("Removed from inventory. History and hostname reservation retained.");
    expect(api.DELETE).toHaveBeenCalledWith(expect.any(String), { params: { path: { orgId: "org-1", appId: "a4" }, query: { expected_version: 7 } } });
  });

  it("rechecks deletion when the dialog opens and blocks stale versions", async () => {
    state.publications.a1 = publication(true, true);
    show([app("a1", "Payroll", "disabled")]);
    await screen.findByText(/Withdrawal confirmed · Ready to delete/);
    state.publications.a1 = { ...publication(true, true), application_version: 8 };
    fireEvent.click(rowAction("Payroll", "Delete"));
    await screen.findByText(/Payroll: Application changed/);
    expect(screen.getByRole("button", { name: "Confirm delete" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "Close and refresh" }));
    expect(changed).toHaveBeenCalledTimes(1);
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("blocks destructive controls when publication readback fails", async () => {
    state.readFail = true; show([app("a1", "Payroll", "disabled")]);
    await screen.findByText(/Could not read withdrawal status\. Refresh applications\./);
    expect(rowAction("Payroll", "Delete")).toHaveProperty("disabled", true);
    fireEvent.click(rowAction("Payroll", "Disable"));
    await screen.findByText("Payroll: Publication unavailable");
    expect(screen.getByRole("button", { name: "Confirm disable" })).toHaveProperty("disabled", true);
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("reports mixed bulk outcomes per application without replaying a successful disable", async () => {
    state.conflict = "a2"; show();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 2 on this page" }));
    fireEvent.click(bulkAction("Disable"));
    await waitFor(() => expect(screen.getByRole("button", { name: "Confirm disable" })).toHaveProperty("disabled", false));
    fireEvent.click(screen.getByRole("button", { name: "Confirm disable" }));
    await screen.findByText("1 succeeded · 1 not confirmed");
    expect(screen.getByText(/Refresh applications and review its current state/)).toBeTruthy();
    expect(api.POST).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("button", { name: "Confirm disable" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Close and refresh" }));
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it("separates grant and manage permissions before reading privileged subjects", () => {
    const view = show(undefined, { manage: false, grant: false, canGrant: true });
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Grant access" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Disable application" })).toBeNull();
    expect(api.GET).not.toHaveBeenCalled();
    view.unmount();
    show(undefined, { manage: false, grant: true, canGrant: true });
    expect(rowAction("Payroll", "Grant access")).toBeTruthy();
    expect(screen.queryByRole("menuitem", { name: "Disable application" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Delete application" })).toBeNull();
  });

  it("grants an explicit group to each selected application and preserves partial outcomes", async () => {
    state.grantFail = "a2"; show();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 2 on this page" }));
    fireEvent.click(bulkAction("Grant access"));
    fireEvent.focus(await screen.findByRole("combobox", { name: "Grant subject" }));
    expect(screen.queryByRole("button", { name: /Inactive/ })).toBeNull();
    fireEvent.click(await screen.findByRole("button", { name: /Engineering.*GROUP/ }));
    fireEvent.click(screen.getByRole("button", { name: "Grant access to selected applications" }));
    await screen.findByText("1 succeeded · 1 not confirmed");
    expect(screen.getByText("Access granted to Engineering.")).toBeTruthy();
    expect(screen.getByText("Grant rejected")).toBeTruthy();
    expect(api.POST).toHaveBeenCalledTimes(2);
    expect(api.POST).toHaveBeenNthCalledWith(1, expect.stringMatching(/\/grants$/), { params: { path: { orgId: "org-1" } }, body: { app_id: "a1", subject_kind: "group", subject_id: "g1", enabled: true, starts_at: null, expires_at: null } });
    expect(screen.queryByRole("button", { name: "Grant access to selected applications" })).toBeNull();
  });

  it("refreshes grant eligibility on opening and refuses entitlement loss", async () => {
    state.entitled = false; show([app("a1", "Payroll")]);
    fireEvent.click(rowAction("Payroll", "Grant access"));
    await screen.findByText(/Close and refresh applications/);
    expect(screen.getByRole("button", { name: "Grant access to selected applications" })).toHaveProperty("disabled", true);
    expect(screen.queryByRole("combobox", { name: "Grant subject" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });
});
