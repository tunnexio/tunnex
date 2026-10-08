import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AppAccessAccess from "../src/pages/AppAccessAccess";
import { api } from "../src/lib/api";
const state = vi.hoisted(() => ({ entitled: true, accessAllowed: false, domainReady: true, fail: false, stale: false, impactFail: false, grantCount: 1, revoked: false, filterError: false, calls: [] as string[] }));
const grant = { id: "44444444-4444-4444-8444-444444444444", org_id: "o1", app_id: "a1", app_label: "Payroll", subject_kind: "user", subject_id: "u1", subject_label: "Alice", enabled: true, starts_at: "2026-10-03T00:00:12Z", expires_at: null, version: 4, revoked_at: null, status: "active", created_at: "2026-10-03T00:00:00Z", updated_at: "2026-10-03T00:00:00Z" };
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: {
 GET: vi.fn(async (path: string, options?: { params?: { query?: { limit?: number } } }) => { state.calls.push(path); if (path.endsWith("/settings")) return { data: { enabled: state.entitled, entitlement_available: state.entitled, version: 1, base_domain: "apps.test", domain_ready: state.domainReady } }; if (path.endsWith("/grants")) return state.fail ? { error: { error: { message: "Grant service unavailable" } } } : state.filterError ? { error: { error: { message: "Invalid grant view and status combination." } } } : { data: { items: Array.from({ length: state.grantCount }, (_, index) => ({ ...grant, id: index ? grant.id + "-" + index : grant.id, ...(state.revoked ? { revoked_at: "2026-10-04T00:00:00Z", status: "revoked" } : {}) })), limit: options?.params?.query?.limit ?? 20, offset: 0 } }; if (path.endsWith("/applications")) return { data: { items: [{ id: "a1", draft: { name: "Payroll" } }, { id: "a2", draft: { name: "Billing" } }], limit: 100, offset: 0 } }; if (path.endsWith("/members")) return { data: [{ user_id: "u1", name: "Alice", email: "alice@test", status: "active" }, { user_id: "u2", name: "Inactive", email: "inactive@test", status: "deactivated" }] }; if (path.endsWith("/groups")) return { data: [{ id: "everyone", name: "Everyone", member_count: 2 }] }; if (path.endsWith("/revoke-impact")) return state.impactFail ? { error: { error: { message: "Impact unavailable" } } } : { data: { matching_user_count: 2, users_losing_grant_match_count: 1, grant_version: 4, evaluated_at: "2026-10-03T00:00:00Z", session_impact_available: false } }; throw Error(path); }),
 PATCH: vi.fn(async () => state.stale ? { error: { error: { code: "version_conflict" } }, response: { status: 409 } } : { data: grant }),
 POST: vi.fn(async (path: string) => path.endsWith("/effective-access") ? { data: { grant_match: true, access_allowed: state.accessAllowed, deny_reason: state.accessAllowed ? "" : "app_unpublished", matching_grant_ids: [grant.id], evaluated_at: "2026-10-03T00:00:00Z", next_expiry_at: null } } : { data: grant }),
} }));
beforeEach(() => { Object.assign(state, { entitled: true, accessAllowed: false, domainReady: true, fail: false, stale: false, impactFail: false, grantCount: 1, revoked: false, filterError: false, calls: [] }); vi.clearAllMocks(); });
afterEach(cleanup);
function show(local = true, permitted = true, path = "/app-access/access?app_id=a1") { return render(<MemoryRouter initialEntries={[path]}><AppAccessAccess orgId="o1" appId={local ? "a1" : undefined} permitted={permitted} canViewEvents canViewAudit /></MemoryRouter>); }
async function ready() { await screen.findByRole("table", { name: "Access grants" }); }
function grantAction(name: string) {
  const trigger = screen.getByRole("button", { name: "Grant actions for Alice" });
  if (trigger.getAttribute("aria-expanded") !== "true") fireEvent.click(trigger);
  return screen.getByRole("menuitem", { name });
}
function openGrantOptions() {
  const summary = screen.getByText("Schedule and options");
  expect(summary.closest("details")).toHaveProperty("open", false);
  fireEvent.click(summary);
  expect(summary.closest("details")).toHaveProperty("open", true);
}
function openEffectiveAccessPreview() {
  const summary = screen.getByText("Preview effective access");
  expect(summary.closest("details")).toHaveProperty("open", false);
  fireEvent.click(summary);
  expect(summary.closest("details")).toHaveProperty("open", true);
}
describe("Applications explicit grants", () => {
 it("links exact grant audit history after lapse and hides it without grant permission", async () => {
  state.entitled = false; const view = show(); await ready();
  const link = grantAction("Grant change audits");
  expect(link.getAttribute("href")).toBe(`/audit?target_type=app_access&target_id=${grant.id}`);
  expect(link.getAttribute("href")).not.toContain("target_id=a1");
  view.unmount(); state.calls = []; show(true, false);
  expect(screen.queryByRole("menuitem", { name: "Grant change audits" })).toBeNull();
  expect(state.calls).toEqual([]);
 });
 it("refuses privileged readers before permission", () => { show(true, false); expect(screen.getByRole("alert").textContent).toContain("permission"); expect(state.calls).toEqual([]); });
 it("failed listing never fabricates no grants and can retry", async () => { state.fail = true; show(); expect(await screen.findByText("Grant service unavailable")).toBeTruthy(); expect(screen.queryByText("No matching grants")).toBeNull(); state.fail = false; fireEvent.click(screen.getByRole("button", { name: "Retry grants" })); await ready(); });
 it("requires an explicit subject and allows a real named Everyone group", async () => { show(); await ready(); fireEvent.click(screen.getByRole("button", { name: "Add grant" })); expect(screen.getByRole("button", { name: "Save grant" })).toHaveProperty("disabled", true); const picker = screen.getByRole("combobox", { name: "Grant subject" }); fireEvent.focus(picker); fireEvent.change(picker, { target: { value: "Everyone" } }); fireEvent.click(await screen.findByRole("button", { name: /Everyone/ })); fireEvent.click(screen.getByRole("button", { name: "Save grant" })); await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ body: { app_id: "a1", subject_kind: "group", subject_id: "everyone", enabled: true, starts_at: null, expires_at: null } }))); });
 it("refuses an inverted validity window before sending a mutation", async () => { show(); await ready(); fireEvent.click(grantAction("Edit grant")); openGrantOptions(); fireEvent.change(screen.getByLabelText("Starts at"), { target: { value: "2026-10-04T12:00" } }); fireEvent.change(screen.getByLabelText("Expires at"), { target: { value: "2026-10-03T12:00" } }); fireEvent.click(screen.getByRole("button", { name: "Save grant" })); expect(await screen.findByText("Expiry must be after the start time.")).toBeTruthy(); expect(api.PATCH).not.toHaveBeenCalled(); });
 it("uses the same app-filtered grant query globally and locally", async () => { const local = show(); await ready(); const query = { params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: undefined, limit: 20, offset: 0 } } }; expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), query); local.unmount(); vi.clearAllMocks(); show(false); await ready(); expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), query); expect(screen.getByRole("link", { name: "Payroll" })).toBeTruthy(); });
 it("revokes only the reviewed grant version after explicit confirmation", async () => { show(); await ready(); fireEvent.click(grantAction("Revoke grant")); await screen.findByText("Users currently matching this grant: 2"); expect(api.POST).not.toHaveBeenCalled(); expect(screen.getByText(/does not confirm termination/)).toBeTruthy(); expect(screen.getByText("Browser session impact is unavailable in this grant preview.")).toBeTruthy(); expect(screen.queryByText(/Applications are unpublished drafts/)).toBeNull(); fireEvent.click(screen.getByRole("button", { name: "Confirm grant revocation" })); await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/revoke$/), expect.objectContaining({ params: { path: { orgId: "o1", grantId: grant.id } }, body: { expected_version: 4 } }))); });
 it("preserves stale input, immutable identity and precise original timestamps", async () => { state.stale = true; show(); await ready(); fireEvent.click(grantAction("Edit grant")); expect(screen.queryByRole("combobox", { name: "Grant subject" })).toBeNull(); expect(screen.getByText(/application and subject cannot be changed/)).toBeTruthy(); openGrantOptions(); fireEvent.click(screen.getByLabelText("Grant enabled")); fireEvent.click(screen.getByRole("button", { name: "Save grant" })); expect(await screen.findByText(/Your edits are preserved/)).toBeTruthy(); expect(screen.getByLabelText("Grant enabled")).toHaveProperty("checked", false); expect(api.PATCH).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { enabled: false, starts_at: grant.starts_at, expires_at: null, expected_version: 4 } })); });
 it("closes an editor before rebinding the global application filter", async () => { show(false); await ready(); fireEvent.click(screen.getByRole("button", { name: "Add grant" })); fireEvent.change(screen.getByLabelText("Filter by application"), { target: { value: "a2" } }); await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull()); expect(api.POST).not.toHaveBeenCalled(); });
 it("keeps revoke and disable usable after entitlement loss with authoritative union impact", async () => { state.entitled = false; show(); await ready(); expect(screen.getByRole("button", { name: "Add grant" })).toHaveProperty("disabled", true); expect(grantAction("Edit grant")).toHaveProperty("disabled", true); fireEvent.click(grantAction("Disable grant")); expect(await screen.findByText("Users losing their last current grant match: 1")).toBeTruthy(); expect(screen.getByText(/Other valid user or group grants/)).toBeTruthy(); fireEvent.click(screen.getByRole("button", { name: "Confirm grant disable" })); await waitFor(() => expect(api.PATCH).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body: { expected_version: 4, enabled: false, starts_at: grant.starts_at, expires_at: null } }))); });
 it("blocks add and edit when the configured domain is unavailable", async () => { state.domainReady = false; show(); await ready(); expect(screen.getByRole("button", { name: "Add grant" })).toHaveProperty("disabled", true); expect(grantAction("Edit grant")).toHaveProperty("disabled", true); expect(grantAction("Revoke grant")).toHaveProperty("disabled", false); });
 it("blocks removal when impact failed rather than guessing counts", async () => { state.impactFail = true; show(); await ready(); fireEvent.click(grantAction("Revoke grant")); expect(await screen.findByText("Impact unavailable")).toBeTruthy(); expect(screen.getByRole("button", { name: "Confirm grant revocation" })).toHaveProperty("disabled", true); expect(screen.queryByText(/Users currently matching/)).toBeNull(); });
 it("previews eligible users while separating grant match from application delivery", async () => { show(); await ready(); openEffectiveAccessPreview(); const picker = screen.getByRole("combobox", { name: "Preview user" }); fireEvent.focus(picker); expect(screen.queryByRole("button", { name: /Inactive/ })).toBeNull(); fireEvent.click(await screen.findByRole("button", { name: /Alice.*USER/ })); fireEvent.click(screen.getByRole("button", { name: "Check effective access" })); expect(await screen.findByText("A current explicit grant matches this user.")).toBeTruthy(); expect(screen.getByText(/Current application access is denied/)).toBeTruthy(); expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/effective-access$/), expect.objectContaining({ params: { path: { orgId: "o1", appId: "a1" } }, body: { user_id: "u1" } })); });
});

it("uses configured eligibility readback for a published app without authorizing browser content", async () => {
  state.accessAllowed = true; show(); await ready();
  openEffectiveAccessPreview();
  fireEvent.focus(screen.getByRole("combobox", { name: "Preview user" })); fireEvent.click(await screen.findByRole("button", { name: /Alice.*USER/ }));
  fireEvent.click(screen.getByRole("button", { name: "Check effective access" }));
  expect(await screen.findByText(/Current configuration permits this user/)).toBeTruthy();
  expect(screen.getByText(/does not create a session or open/)).toBeTruthy();
  expect(screen.queryByText(/Current application access is denied/)).toBeNull();
  expect(api.POST).toHaveBeenCalledTimes(1);
});

it("shows grant inventory as a table and preserves revoked records with their audit trail", async () => {
  state.revoked = true; show(false, true, "/app-access/access?app_id=a1&grant_view=history"); await ready();
  const table = screen.getByRole("table", { name: "Access grants" });
  for (const name of ["Subject", "Application", "Status", "Validity", "Actions"]) expect(within(table).getByRole("columnheader", { name })).toBeTruthy();
  expect(within(table).getByText("revoked")).toBeTruthy();
  expect(within(table).getByText("No expiry")).toBeTruthy();
  expect(grantAction("Grant change audits").getAttribute("href")).toContain("target_id=" + grant.id);
  expect(screen.queryByRole("menuitem", { name: /Edit|Disable|Revoke/ })).toBeNull();
});

it("applies search and status to the server result set, resetting pagination and preserving app scope", async () => {
  state.grantCount = 20; show(false, true, "/app-access/access?app_id=a1&grant_page=3"); await ready();
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: undefined, limit: 20, offset: 40 } } }));
  fireEvent.change(screen.getByRole("textbox", { name: "Search grants" }), { target: { value: "  alice@example.test  " } });
  fireEvent.click(screen.getByRole("button", { name: "Search grants" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: "alice@example.test", status: undefined, limit: 20, offset: 0 } } })));
  await ready();
  // Display the server-authoritative results, even when their display label differs from a matched email.
  expect(screen.getAllByText("Alice")).toHaveLength(20);
  fireEvent.click(screen.getByRole("button", { name: "Next grants" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: "alice@example.test", status: undefined, limit: 20, offset: 20 } } })));
  await ready();
  fireEvent.change(screen.getByRole("combobox", { name: "Grant status" }), { target: { value: "scheduled" } });
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: "alice@example.test", status: "scheduled", limit: 20, offset: 0 } } })));
  await ready();
  fireEvent.click(screen.getByRole("button", { name: "Clear search and status" }));
  await waitFor(() => expect(screen.getByRole("textbox", { name: "Search grants" })).toHaveProperty("value", ""));
  expect(screen.getByRole("combobox", { name: "Filter by application" })).toHaveProperty("value", "a1");
  expect(screen.getByRole("combobox", { name: "Grant status" })).toHaveProperty("value", "");
  expect(api.POST).not.toHaveBeenCalled(); expect(api.PATCH).not.toHaveBeenCalled();
});

it("requires an explicit application inside the unfiltered grant drawer and retains the all-app inventory", async () => {
  show(false, true, "/app-access/access"); await ready();
  expect(screen.queryByText("Select an application to add a grant.")).toBeNull();
  expect(screen.getByRole("link", { name: "Payroll" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Add grant" }));
  const dialog = screen.getByRole("dialog", { name: "Add application grant" });
  expect(dialog.closest("[data-placement]")?.getAttribute("data-placement")).toBe("right");
  expect(within(dialog).getByText("Starts immediately · No expiry")).toBeTruthy();
  expect(within(dialog).getByText("Schedule and options").closest("details")).toHaveProperty("open", false);
  expect(screen.getByRole("button", { name: "Save grant" })).toHaveProperty("disabled", true);
  fireEvent.focus(screen.getByRole("combobox", { name: "Grant subject" }));
  fireEvent.click(await screen.findByRole("button", { name: /Alice.*USER/ }));
  expect(screen.getByRole("button", { name: "Save grant" })).toHaveProperty("disabled", true);
  expect(api.POST).not.toHaveBeenCalled();
  fireEvent.change(screen.getByRole("combobox", { name: "Application" }), { target: { value: "a2" } });
  fireEvent.click(screen.getByRole("button", { name: "Save grant" }));
  await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ body: { app_id: "a2", subject_kind: "user", subject_id: "u1", enabled: true, starts_at: null, expires_at: null } })));
});

it("distinguishes an empty filtered inventory from a failed grant read", async () => {
  state.grantCount = 0; show(false, true, "/app-access/access?app_id=a1&grant_search=unknown&grant_status=expired"); await screen.findByText("No matching grants");
  expect(screen.getByText("No matching grants")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Clear filters" })).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
  expect(screen.queryByRole("alert")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
  await screen.findByText("No access history");
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "history", search: undefined, status: undefined, limit: 20, offset: 0 } } }));
});

it("keeps external activity feeds out of this workspace while retaining exact row audits", async () => {
  show(false); await ready();
  expect(screen.queryByRole("link", { name: "Access events" })).toBeNull();
  expect(screen.queryByRole("link", { name: "Audit log" })).toBeNull();
  expect(grantAction("Grant change audits").getAttribute("href")).toBe(`/audit?target_type=app_access&target_id=${grant.id}`);
  expect(state.calls.some(path => path.includes("audit") || path.endsWith("/events"))).toBe(false);
});

it("does not infer event or audit permission from grant management permission", async () => {
  render(<MemoryRouter><AppAccessAccess orgId="o1" permitted /></MemoryRouter>); await ready();
  expect(screen.queryByRole("link", { name: "Access events" })).toBeNull();
  expect(screen.queryByRole("link", { name: "Audit log" })).toBeNull();
  expect(grantAction("Revoke grant")).toBeTruthy();
  expect(screen.queryByRole("menuitem", { name: "Grant change audits" })).toBeNull();
});

it("defaults to current active and disabled grants and keeps scheduled or unavailable subjects selectable", async () => {
  show(); await ready();
  expect(screen.getByRole("button", { name: "Current access" }).getAttribute("aria-pressed")).toBe("true");
  expect(screen.getByRole("combobox", { name: "Grant status" }).textContent).toBe("All currentActiveDisabledScheduledSubject unavailable");
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: undefined, limit: 20, offset: 0 } } }));
  fireEvent.change(screen.getByRole("combobox", { name: "Grant status" }), { target: { value: "subject_unavailable" } });
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: "subject_unavailable", limit: 20, offset: 0 } } })));
  expect(screen.queryByRole("option", { name: "Revoked" })).toBeNull();
  expect(screen.queryByRole("option", { name: "Expired" })).toBeNull();
});

it("switches History on the server, resets incompatible status and page, and preserves application/search scope", async () => {
  state.grantCount = 20;
  show(false, true, "/app-access/access?app_id=a1&grant_search=Alice&grant_status=disabled&grant_page=3"); await ready();
  fireEvent.click(screen.getByRole("button", { name: "History" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "history", search: "Alice", status: undefined, limit: 20, offset: 0 } } })));
  await ready();
  expect(screen.getByRole("combobox", { name: "Grant status" }).textContent).toBe("All historyRevokedExpired");
  expect(screen.getByRole("button", { name: "History" }).getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(screen.getByRole("button", { name: "Next grants" }));
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "history", search: "Alice", status: undefined, limit: 20, offset: 20 } } })));
  await ready();
  fireEvent.click(screen.getByRole("button", { name: "Current access" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Current access" }).getAttribute("aria-pressed")).toBe("true"));
  expect(screen.getByRole("combobox", { name: "Grant status" })).toHaveProperty("value", "");
  expect(api.POST).not.toHaveBeenCalled(); expect(api.PATCH).not.toHaveBeenCalled();
});

it.each(["revoked", "expired"])("opens legacy %s status links in History and keeps that view when filters clear", async status => {
  show(false, true, "/app-access/access?app_id=a1&grant_status=" + status); await ready();
  expect(screen.getByRole("button", { name: "History" }).getAttribute("aria-pressed")).toBe("true");
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "history", search: undefined, status, limit: 20, offset: 0 } } }));
  fireEvent.click(screen.getByRole("button", { name: "Clear search and status" })); await ready();
  expect(screen.getByRole("button", { name: "History" }).getAttribute("aria-pressed")).toBe("true");
  expect(screen.getByRole("combobox", { name: "Grant status" })).toHaveProperty("value", "");
});

it("surfaces a rejected incompatible view/status without silently retrying the unfiltered inventory", async () => {
  state.filterError = true;
  show(false, true, "/app-access/access?app_id=a1&grant_view=current&grant_status=revoked");
  expect(await screen.findByText("Invalid grant view and status combination.")).toBeTruthy();
  expect(screen.queryByRole("table", { name: "Access grants" })).toBeNull();
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: "revoked", limit: 20, offset: 0 } } }));
  expect(state.calls.filter(path => path.endsWith("/grants"))).toHaveLength(1);
});


it("keeps one row control and a keyboard-accessible menu without mutating on open", async () => {
  show(); await ready();
  const table = screen.getByRole("table", { name: "Access grants" });
  expect(within(table).getAllByRole("button")).toHaveLength(1);
  const trigger = within(table).getByRole("button", { name: "Grant actions for Alice" });
  trigger.focus(); fireEvent.keyDown(trigger, { key: "ArrowDown" });
  expect(screen.getByRole("menuitem", { name: "Edit grant" })).toBe(document.activeElement);
  fireEvent.keyDown(document.activeElement!, { key: "End" });
  expect(screen.getByRole("menuitem", { name: "Grant change audits" })).toBe(document.activeElement);
  fireEvent.keyDown(document.activeElement!, { key: "Escape" });
  expect(screen.queryByRole("menu")).toBeNull();
  expect(trigger).toBe(document.activeElement);
  expect(api.POST).not.toHaveBeenCalled(); expect(api.PATCH).not.toHaveBeenCalled();
});

it("offers a useful action for empty current access and preserves application scope", async () => {
  state.grantCount = 0; show();
  await screen.findByText("No access granted");
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Grant access" }));
  expect(screen.getByRole("dialog", { name: "Add application grant" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Save grant" })).toHaveProperty("disabled", true);
  expect(api.POST).not.toHaveBeenCalled();
});

it("keeps unavailable current grants inspectable and hides unauthorized empty-state mutation", async () => {
  state.grantCount = 0; state.entitled = false; show();
  await screen.findByText("No access granted");
  expect(screen.queryByRole("button", { name: "Grant access" })).toBeNull();
  expect(screen.getByRole("button", { name: "Add grant" })).toHaveProperty("disabled", true);
  expect(screen.getByText(/An eligible license is required/)).toBeTruthy();
  expect(api.POST).not.toHaveBeenCalled(); expect(api.PATCH).not.toHaveBeenCalled();
});

it("explains empty history and returns to current access without changing app scope", async () => {
  state.grantCount = 0; show(false, true, "/app-access/access?app_id=a1&grant_view=history");
  await screen.findByText("No access history");
  expect(screen.getByText("Revoked and expired grants will appear here.")).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "View current access" }));
  await screen.findByText("No access granted");
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: undefined, limit: 20, offset: 0 } } }));
});


it("uses adjustable page size in the server query and resets page without losing filters", async () => {
  state.grantCount = 20;
  show(false, true, "/app-access/access?app_id=a1&grant_view=history&grant_search=Alice&grant_status=revoked&grant_page=3"); await ready();
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "history", search: "Alice", status: "revoked", limit: 50, offset: 0 } } })));
  await ready();
  expect(screen.getByRole("combobox", { name: "Rows per page" })).toHaveProperty("value", "50");
  expect(screen.getByText("1–20 shown")).toBeTruthy();
  expect(screen.queryByText("Page 1")).toBeNull();
  expect(screen.queryByRole("button", { name: "Previous grants" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Next grants" })).toBeNull();
  expect(api.POST).not.toHaveBeenCalled(); expect(api.PATCH).not.toHaveBeenCalled();
});

it("clamps page to the API offset bound for the selected size and keeps the pager visible", async () => {
  state.grantCount = 50;
  show(false, true, "/app-access/access?app_id=a1&grant_limit=50&grant_page=999"); await ready();
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: "a1", view: "current", search: undefined, status: undefined, limit: 50, offset: 10000 } } }));
  expect(screen.getByText("Page 201")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Next grants" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Previous grants" })).toHaveProperty("disabled", false);
});

it("falls back to twenty rows for an unsupported page size", async () => {
  show(false, true, "/app-access/access?grant_limit=999&grant_page=2"); await ready();
  expect(api.GET).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ params: { path: { orgId: "o1" }, query: { app_id: undefined, view: "current", search: undefined, status: undefined, limit: 20, offset: 20 } } }));
  expect(screen.getByRole("combobox", { name: "Rows per page" })).toHaveProperty("value", "20");
});

it("retains local schedule values and stores explicit valid window changes as UTC", async () => {
  show(); await ready();
  fireEvent.click(screen.getByRole("button", { name: "Add grant" }));
  fireEvent.focus(screen.getByRole("combobox", { name: "Grant subject" }));
  fireEvent.click(await screen.findByRole("button", { name: /Alice.*USER/ }));
  openGrantOptions();
  fireEvent.change(screen.getByLabelText("Starts at"), { target: { value: "2026-10-08T10:30" } });
  fireEvent.change(screen.getByLabelText("Expires at"), { target: { value: "2026-10-09T10:30" } });
  fireEvent.click(screen.getByRole("button", { name: "Save grant" }));
  await waitFor(() => expect(api.POST).toHaveBeenCalledWith(expect.stringMatching(/\/grants$/), expect.objectContaining({ body: { app_id: "a1", subject_kind: "user", subject_id: "u1", enabled: true, starts_at: new Date("2026-10-08T10:30").toISOString(), expires_at: new Date("2026-10-09T10:30").toISOString() } })));
});
