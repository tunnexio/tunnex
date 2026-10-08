import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "../src/lib/auth";
import { OrgProvider } from "../src/lib/useOrg";
import AppAccess from "../src/pages/AppAccess";
import { AppAccessFeatureSettings } from "../src/components/AppAccessFeatureSettings";
import { api } from "../src/lib/api";

const data = vi.hoisted(() => ({ roles: ["admin"] as string[], serverAdmin: false, verified: true, appAdmin: false, baseDomain: "apps.example", iconData: "", savedHostname: "payroll.apps.example", listFail: false, listState: "unpublished", listEmpty: false, membershipFail: false, entitled: true, enabled: true, stale: false, conflict: "", revoked: false, existingPolicy: false, archived: false, requests: [] as string[], patches: [] as unknown[] }));
const draft = { name: "Payroll", description: "Team payroll", icon: "app", origin_url: "https://private.example", gateway_id: "gateway-1", public_hostname: "payroll.apps.example", idle_timeout_seconds: 1800, absolute_timeout_seconds: 28800 };
const application = { require_mfa: false, mfa_freshness_seconds: 900, id: "app-1", org_id: "org-1", version: 7, draft_revision: 7, state: "draft", publication_state: "unpublished", draft: { ...draft, revision: 7, digest: "approved", created_at: "2026-10-03T00:00:00Z" }, connector_status: "unknown", created_at: "2026-10-03T00:00:00Z", updated_at: "2026-10-03T00:00:00Z" };
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: {
    GET: vi.fn(async (path: string) => {
      data.requests.push(path);
      if (path.endsWith("/auth/me")) return { data: { id: "u1", email_verified: data.verified, cp_admin: data.serverAdmin } };
      if (path === "/api/v1/admin/app-access/domains") return { data: { portal_url: "https://console.example.com", app_base_domain: "apps.example", version: 2, source: "database", configuration_ready: true } };
      if (path === "/api/v1/organizations") return { data: [{ id: "org-1", name: "Acme" }] };
      if (path.endsWith("/members")) return data.membershipFail ? { error: { error: { message: "Permission lookup failed" } } } : { data: [{ user_id: "u1", status: "active", role: data.roles[0], roles: data.roles }] };
      if (path.endsWith("/managed-apps")) return { data: { items: data.appAdmin ? [{ id: "app-1", name: "Payroll", description: "", icon: "app", icon_data_url: "", pending_count: 0 }] : [], can_view_applications: data.roles.includes("admin") || data.roles.includes("owner"), can_manage_grants: data.roles.includes("admin") || data.roles.includes("owner"), limit: 1, offset: 0 } };
      if (path.endsWith("/access-management")) return { data: { app_id: "app-1", version: 7, catalog_visible: false, app_admin_user_id: null, app_admin: null } };
      if (path.endsWith("/grant-subjects")) return { data: { items: [], limit: 20, offset: 0 } };
      if (path.endsWith("/access-requests")) return { data: { items: [], pending_count: 0, limit: 20, offset: 0 } };
      if (path.endsWith("/grants")) return { data: { items: [], limit: 20, offset: 0 } };
      if (path.endsWith("/groups")) return { data: [] };
      if (path.endsWith("/settings")) return { data: { enabled: data.enabled, version: 2, entitlement_available: data.entitled, base_domain: data.baseDomain, domain_ready: !!data.baseDomain } };
      if (path.endsWith("/status")) return { data: { org_id: "org-1", gateway_id: "gateway-1", capability_version: 0, reported_at: null, status: "unknown" } };
      if (path.endsWith("/my-apps")) return { data: { items: [], limit: 20, offset: 0, availability: "available" } };
      if (path.endsWith("/my-sessions")) return { data: { items: [], limit: 20, offset: 0 } };
      if (path.endsWith("/applications")) return data.listFail ? { error: { error: { message: "Inventory unavailable" } } } : { data: { items: data.listEmpty ? [] : [{ ...application, draft: { ...application.draft, icon_data_url: data.iconData }, publication_state: data.listState, ...(data.listState === "published" ? { active_revision: 3 } : {}) }], limit: 20, offset: 0 } };
      if (path.endsWith("/{appId}")) return { data: { ...application, state: data.archived ? "archived" : "draft", draft: { ...application.draft, public_hostname: data.savedHostname, icon_data_url: data.iconData, ...(data.existingPolicy ? { allowed_destination_cidrs: ["10.20.0.0/16"], origin_ca_digest: "a".repeat(64) } : {}) } } };
      if (path.endsWith("/nodes")) return { data: [{ id: "gateway-1", name: "Office gateway", status: data.revoked ? "revoked" : "active", enrolled_kind: "gateway" }, { id: "gateway-2", name: "Active replacement", status: "active", enrolled_kind: "gateway" }, { id: "old-gateway", name: "Other revoked gateway", status: "revoked", enrolled_kind: "gateway" }, { id: "agent-1", name: "AI agent", enrolled_kind: "agent" }] };
      throw new Error(`Unexpected request ${path}`);
    }),
    POST: vi.fn(async (_path: string, options: unknown) => { data.patches.push(options); if (data.conflict) return { error: { error: { code: data.conflict, message: data.conflict === "hostname_taken" ? "Hostname is already registered" : "Configure the application domain first" } }, response: { status: 409 } }; return { data: application, response: { status: 201 } }; }),
    PATCH: vi.fn(async (_path: string, options: unknown) => { data.patches.push(options); if (data.conflict) return { error: { error: { code: data.conflict, message: data.conflict === "hostname_taken" ? "Hostname is already registered" : "Configure the application domain first" } }, response: { status: 409 } }; if (_path.endsWith("/settings") && !data.stale) return { data: { enabled: !data.enabled, version: 3, entitlement_available: data.entitled, base_domain: data.baseDomain, domain_ready: !!data.baseDomain }, response: { status: 200 } }; return data.stale ? { error: { error: { code: "version_conflict" } }, response: { status: 409 } } : { data: application, response: { status: 200 } }; }),
  } };
});
afterEach(cleanup);
beforeEach(() => { Object.assign(data, { roles: ["admin"], serverAdmin: false, verified: true, appAdmin: false, baseDomain: "apps.example", iconData: "", savedHostname: "payroll.apps.example", listFail: false, listState: "unpublished", listEmpty: false, membershipFail: false, entitled: true, enabled: true, stale: false, conflict: "", revoked: false, existingPolicy: false, archived: false, requests: [], patches: [] }); vi.clearAllMocks(); window.localStorage.clear(); window.sessionStorage.clear(); });
function show(path: string) { return render(<MemoryRouter initialEntries={[path]}><AuthProvider><OrgProvider><Routes><Route path="/app-access" element={<AppAccess />} /><Route path="/app-access/applications" element={<AppAccess />} /><Route path="/app-access/applications/new" element={<AppAccess />} /><Route path="/app-access/applications/:appId" element={<AppAccess />} /><Route path="/app-access/access" element={<AppAccess />} /><Route path="/app-access/my-applications" element={<AppAccess />} /><Route path="/app-access/requests" element={<AppAccess />} /><Route path="/app-access/my-requests" element={<AppAccess />} /></Routes></OrgProvider></AuthProvider></MemoryRouter>); }
async function openConnection() {
  fireEvent.click(await screen.findByRole("button", { name: "2. Connection" }));
  return screen.findByLabelText("Origin URL");
}
function openAdvancedConnectionSettings() {
  const summary = screen.getByText("Advanced connection settings");
  fireEvent.click(summary);
  expect(summary.closest("details")).toHaveProperty("open", true);
}
describe("Applications draft workspace", () => {
  it("lands an admin on actual drafts without publishing or opening controls", async () => {
    show("/app-access");
    expect(await screen.findByRole("link", { name: "Payroll" })).toBeTruthy();
    const status = within(screen.getByRole("table", { name: "Applications" })).getByText("Draft");
    expect(status.getAttribute("title")).toBe("Draft · Browser traffic is not published");
    expect(within(status).getByText(/Browser traffic is not published/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /publish|open application/i })).toBeNull();
    expect(screen.queryByText(/enabled for this organization/)).toBeNull();
  });
  it("uses permission unions rather than the legacy first role", async () => { data.roles = ["member", "admin"]; show("/app-access"); expect(await screen.findByRole("link", { name: "Payroll" })).toBeTruthy(); });
  it("loads a member's own catalog without reading administrative configuration", async () => { data.roles = ["member"]; show("/app-access"); expect(await screen.findByText(/No published applications are granted/)).toBeTruthy(); expect(data.requests.some(path => path.endsWith("/my-apps"))).toBe(true); expect(data.requests.some(path => path.endsWith("/applications") || path.endsWith("/settings"))).toBe(false); });
  it("denies a member deep link before reading app topology", async () => { data.roles = ["member"]; show("/app-access/applications/app-1"); expect(await screen.findByText(/do not have permission/)).toBeTruthy(); expect(data.requests.some(path => path.includes("app-access"))).toBe(false); expect(screen.queryByText("private.example")).toBeNull(); });
  it("denies member grant routes before fetching privileged configuration", async () => { data.roles = ["member"]; show("/app-access/access"); expect(await screen.findByText(/do not have permission/)).toBeTruthy(); expect(data.requests.some(path => path.includes("app-access"))).toBe(false); });
  it("distinguishes failed inventory from no drafts and retries", async () => { data.listFail = true; show("/app-access/applications"); expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Inventory unavailable"); expect(screen.queryByText("No application drafts yet.")).toBeNull(); data.listFail = false; fireEvent.click(screen.getByRole("button", { name: "Retry applications" })); expect(await screen.findByRole("link", { name: "Payroll" })).toBeTruthy(); });
  it("failed role lookup cannot render admin controls", async () => { data.membershipFail = true; show("/app-access/applications"); expect(await screen.findByRole("button", { name: "Retry permissions" })).toBeTruthy(); expect(screen.queryByRole("link", { name: "Add application" })).toBeNull(); expect(data.requests.some(path => path.includes("app-access"))).toBe(false); });
  it("does not grant AI-only roles a catalog while retaining own session withdrawal", async () => {
    data.roles = ["ai-admin"]; show("/app-access/my-applications");
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "You do not have permission to launch applications. You can still revoke your own sessions.");
    expect(data.requests.some(path => path.endsWith("my-sessions"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "My sessions" }));
    await screen.findByText("No active application sessions.");
    expect(data.requests.some(path => path.endsWith("my-apps") || path.endsWith("/applications") || path.endsWith("/settings"))).toBe(false);
    expect(data.requests.some(path => path.endsWith("my-sessions"))).toBe(true);
  });
  it("bounds URL supplied search and page offsets", async () => { show(`/app-access/applications?q=${"a".repeat(150)}&page=999999`); await screen.findByRole("link", { name: "Payroll" }); expect(api.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId: "org-1" }, query: { search: "a".repeat(100), limit: 20, offset: 10000 } } }); });
  it("off organizations cannot save through a direct new-draft link", async () => { data.enabled = false; show("/app-access/applications/new"); await screen.findByLabelText("Application name"); expect(screen.queryByRole("button", { name: "Save draft" })).toBeNull(); });
  it("keeps ineligible configuration inspectable without edit controls", async () => {
    data.entitled = false; data.existingPolicy = true;
    show("/app-access/applications/app-1");
    const saved = await screen.findByLabelText("Saved application details");
    expect(within(saved).getByText("Payroll")).toBeTruthy();
    expect(within(saved).getByText("Team payroll")).toBeTruthy();
    expect(within(saved).getByText("payroll.apps.example")).toBeTruthy();
    expect(screen.queryByLabelText("Application name")).toBeNull();
    expect(screen.queryByRole("button", { name: /Save draft|Save and continue/ })).toBeNull();
    expect(screen.getByText(/Applications requires an eligible license/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Continue to connection" }));
    const connection = await screen.findByLabelText("Saved connection details");
    expect(within(connection).getByText("https://private.example")).toBeTruthy();
    expect(within(connection).getByText("Office gateway")).toBeTruthy();
    expect(screen.queryByLabelText("Origin URL")).toBeNull();
    expect(screen.queryByLabelText("Gateway connector")).toBeNull();
    openAdvancedConnectionSettings();
    const advanced = screen.getByLabelText("Saved advanced connection settings");
    expect(within(advanced).getByText("10.20.0.0/16")).toBeTruthy();
    expect(within(advanced).getByText("Custom CA certificates")).toBeTruthy();
    expect(within(advanced).getByText("a".repeat(64))).toBeTruthy();
    expect(screen.queryByLabelText("Allowed private destination ranges")).toBeNull();
    expect(screen.queryByRole("button", { name: /Save draft|Save and continue/ })).toBeNull();
    expect(api.PATCH).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
  });
  it("sends only generated draft input and expected version, preserving stale-save edits", async () => { data.stale = true; show("/app-access/applications/app-1"); const name = await screen.findByLabelText("Application name"); fireEvent.change(name, { target: { value: "Payroll revised" } }); fireEvent.click(screen.getByRole("button", { name: "Save draft" })); expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("changed since you opened")); expect(name).toHaveProperty("value", "Payroll revised"); expect(data.patches[0]).toMatchObject({ body: { ...draft, name: "Payroll revised", expected_version: 7 } }); const options = data.patches[0] as { body: Record<string, unknown> }; expect(options.body.revision).toBeUndefined(); expect(options.body.digest).toBeUndefined(); expect(window.sessionStorage.getItem("tunnex.appAccessDraft:u1:org-1:app-1")).toContain("Payroll revised"); });
  it("preserves hostname collision errors instead of calling them stale saves", async () => { data.conflict = "hostname_taken"; show("/app-access/applications/app-1"); fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Edited payroll" } }); fireEvent.click(screen.getByRole("button", { name: "Save draft" })); expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Hostname is already registered"); expect(screen.getByLabelText("Application name")).toHaveProperty("value", "Edited payroll"); });
  it("retains a revoked assignment honestly while offering only active replacements", async () => {
    data.revoked = true; show("/app-access/applications/app-1");
    fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Reassigned payroll" } });
    await openConnection();
    const picker = screen.getByLabelText("Gateway connector");
    expect(picker).toHaveProperty("value", "gateway-1");
    expect(screen.getByRole("option", { name: /Office gateway.*Revoked/ })).toHaveProperty("disabled", true);
    expect(screen.queryByRole("option", { name: /Other revoked gateway/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", true);
    fireEvent.change(picker, { target: { value: "gateway-2" } });
    expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", false);
  });
  it("restores scoped unsaved draft only after an explicit action", async () => { window.sessionStorage.setItem("tunnex.appAccessDraft:u1:org-1:app-1", JSON.stringify({ ...draft, name: "Recovered edits" })); show("/app-access/applications/app-1"); expect(await screen.findByLabelText("Application name")).toHaveProperty("value", "Payroll"); fireEvent.click(screen.getByRole("button", { name: "Restore unsaved changes" })); expect(screen.getByLabelText("Application name")).toHaveProperty("value", "Recovered edits"); expect(api.PATCH).not.toHaveBeenCalled(); });
  it("requires application details before connection and saves before access", async () => {
    show("/app-access/applications/new");
    expect(await screen.findByRole("button", { name: "Continue to connection" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "3. Access" })).toHaveProperty("disabled", true);
    expect(screen.queryByLabelText("Origin URL")).toBeNull();
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "Payroll" } });
    fireEvent.change(screen.getByLabelText("Application subdomain"), { target: { value: "payroll" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue to connection" }));
    expect(screen.getByLabelText("Origin URL")).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "4. Review & publish" })).toHaveProperty("disabled", true);
  });
  it("creates a draft with a server-issued identity without publishing it", async () => {
    show("/app-access/applications/new");
    fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Payroll" } });
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "Team payroll" } });
    fireEvent.change(screen.getByLabelText("Application subdomain"), { target: { value: "payroll" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue to connection" }));
    fireEvent.change(screen.getByLabelText("Origin URL"), { target: { value: "https://private.example" } });
    fireEvent.change(screen.getByLabelText("Gateway connector"), { target: { value: "gateway-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "2. Connection" }).getAttribute("aria-current")).toBe("step"));
    expect(await screen.findByRole("button", { name: "Continue to access" })).toBeTruthy();
    expect(data.patches[0]).toMatchObject({ body: draft });
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: /^Publish application$/ })).toBeNull();
  });
  it("preserves the saved private network and custom CA while changing ordinary metadata", async () => {
    data.existingPolicy = true; show("/app-access/applications/app-1");
    fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Updated payroll" } });
    await openConnection();
    openAdvancedConnectionSettings();
    expect(screen.getByLabelText("Allowed private destination ranges")).toHaveProperty("value", "10.20.0.0/16");
    expect(screen.getByLabelText("Origin certificate trust")).toHaveProperty("value", "preserve");
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
    await waitFor(() => expect(data.patches).toHaveLength(1));
    expect(data.patches[0]).toMatchObject({ body: { allowed_destination_cidrs: ["10.20.0.0/16"], expected_version: 7 } });
    expect((data.patches[0] as { body: Record<string, unknown> }).body.origin_ca_pem).toBeUndefined();
  });
  it("clears private ranges and custom trust only through explicit edits", async () => {
    data.existingPolicy = true; show("/app-access/applications/app-1");
    await openConnection();
    openAdvancedConnectionSettings();
    fireEvent.change(screen.getByLabelText("Allowed private destination ranges"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Origin certificate trust"), { target: { value: "system" } });
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
    await waitFor(() => expect(data.patches).toHaveLength(1));
    expect(data.patches[0]).toMatchObject({ body: { allowed_destination_cidrs: [], origin_ca_pem: "" } });
  });
  it("refuses a pasted private key and keeps it out of browser draft recovery", async () => {
    show("/app-access/applications/app-1");
    await openConnection();
    openAdvancedConnectionSettings();
    fireEvent.change(screen.getByLabelText("Origin certificate trust"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("Public CA certificate PEM"), { target: { value: "-----BEGIN PRIVATE KEY-----\nfixture" } });
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("Private keys are not accepted"));
    expect(api.PATCH).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem("tunnex.appAccessDraft:u1:org-1:app-1")).not.toContain("PRIVATE KEY");
  });
  it("gateway enrollment never claims connector readiness and excludes agent nodes", async () => { show("/app-access/applications/new"); fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Payroll" } }); fireEvent.change(screen.getByLabelText("Application subdomain"), { target: { value: "payroll" } }); fireEvent.click(screen.getByRole("button", { name: "Continue to connection" })); expect(await screen.findByRole("option", { name: /Office gateway.*Active gateway/ })).toBeTruthy(); expect(screen.queryByRole("option", { name: /AI agent/ })).toBeNull(); expect(screen.getByText(/Save the draft to inspect the connector/)).toBeTruthy(); await waitFor(() => expect(screen.getByLabelText("Origin URL")).toBeTruthy()); });
});

it("filters publication on the server before pagination and labels active revision independently", async () => {
  data.listState = "published"; show("/app-access/applications?publication=published&page=2");
  await screen.findByRole("link", { name: "Payroll" });
  const status = within(screen.getByRole("table", { name: "Applications" })).getByText("Published");
  expect(status.getAttribute("title")).toBe("Published · Active revision 3");
  expect(within(status).getByText(/Active revision 3/)).toBeTruthy();
  expect(api.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId: "org-1" }, query: { search: "", limit: 20, offset: 20, publication_state: "published" } } });
  fireEvent.change(screen.getByLabelText("Search applications"), { target: { value: "Payroll" } });
  await waitFor(() => expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId: "org-1" }, query: { search: "Payroll", limit: 20, offset: 0, publication_state: "published" } } }));
});
it("distinguishes a filtered empty inventory from no drafts", async () => {
  data.listEmpty = true; show("/app-access/applications?publication=disabled");
  expect(await screen.findByText("No applications match this publication filter.")).toBeTruthy();
  expect(screen.queryByText("No application drafts yet.")).toBeNull();
});

it("retains archived configuration as read-only history on a direct link", async () => {
  data.archived = true; show("/app-access/applications/app-1?step=application");
  expect(await screen.findByRole("heading", { name: "Payroll" })).toBeTruthy();
  expect(screen.getByText("This application is archived. Its configuration and publication history are retained.")).toBeTruthy();
  expect(within(screen.getByLabelText("Saved application details")).getByText("Payroll")).toBeTruthy();
  expect(screen.queryByLabelText("Application name")).toBeNull();
  expect(screen.queryByRole("button", { name: /Save draft|Save and continue/ })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Continue to connection" }));
  expect(within(await screen.findByLabelText("Saved connection details")).getByText("https://private.example")).toBeTruthy();
  expect(screen.queryByLabelText("Origin URL")).toBeNull();
  expect(screen.queryByRole("button", { name: /Save draft|Save and continue/ })).toBeNull();
  expect(api.PATCH).not.toHaveBeenCalled();
});


it("keeps one workspace title, named inventory columns and active section navigation", async () => {
  show("/app-access/applications");
  await screen.findByRole("link", { name: "Payroll" });
  expect(screen.getAllByRole("heading", { level: 1 }).map(node => node.textContent)).toEqual(["App Access"]);
  const sections = screen.getByRole("navigation", { name: "Applications" });
  expect(within(sections).getByRole("link", { name: "Applications" }).getAttribute("aria-current")).toBe("page");
  const table = screen.getByRole("table", { name: "Applications" });
  expect(within(table).getByRole("columnheader", { name: "Application" })).toBeTruthy();
  expect(within(table).getByRole("columnheader", { name: "Status" })).toBeTruthy();
  expect(api.POST).not.toHaveBeenCalled();
});

it("uses breadcrumbs and presents only the current application setup step", async () => {
  show("/app-access/applications/app-1");
  await screen.findByLabelText("Application name");
  expect(screen.getByRole("heading", { name: "Application details" })).toBeTruthy();
  expect(screen.queryByLabelText("Origin URL")).toBeNull();
  expect(screen.getByRole("button", { name: "1. Application" }).getAttribute("aria-current")).toBe("step");
  const breadcrumb = screen.getByRole("navigation", { name: "Breadcrumb" });
  expect(within(breadcrumb).getByRole("link", { name: "App Access" }).getAttribute("href")).toBe("/app-access");
  expect(within(breadcrumb).getByRole("link", { name: "Applications" }).getAttribute("href")).toBe("/app-access/applications");
  expect(within(breadcrumb).getByRole("link", { name: "Payroll" }).getAttribute("href")).toBe("/app-access/applications/app-1?step=application");
  expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", true);
  fireEvent.click(screen.getByRole("button", { name: "Continue to connection" }));
  expect(await screen.findByLabelText("Origin URL")).toBeTruthy();
  expect(screen.queryByLabelText("Application name")).toBeNull();
  expect(screen.getByRole("button", { name: "2. Connection" }).getAttribute("aria-current")).toBe("step");
  expect(api.PATCH).not.toHaveBeenCalled();
  fireEvent.click(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "Applications" }));
  expect(await screen.findByRole("table", { name: "Applications" })).toBeTruthy();
});

it("saves identity before continuing and refuses access while connection edits are unsaved", async () => {
  show("/app-access/applications/app-1");
  fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Payroll revised" } });
  fireEvent.click(screen.getByRole("button", { name: "Save and continue" }));
  await screen.findByLabelText("Origin URL");
  expect(data.patches[0]).toMatchObject({ body: { ...draft, name: "Payroll revised", expected_version: 7 } });
  expect(api.PATCH).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("button", { name: "2. Connection" }).getAttribute("aria-current")).toBe("step");
  fireEvent.change(screen.getByLabelText("Origin URL"), { target: { value: "https://new-private.example" } });
  expect(screen.getByRole("button", { name: "Continue to access" })).toHaveProperty("disabled", true);
  fireEvent.click(screen.getByRole("button", { name: "Continue to access" }));
  expect(screen.getByRole("button", { name: "2. Connection" }).getAttribute("aria-current")).toBe("step");
  fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Continue to access" })).toHaveProperty("disabled", false));
  expect(data.patches[1]).toMatchObject({ body: { origin_url: "https://new-private.example", expected_version: 7 } });
  fireEvent.click(screen.getByRole("button", { name: "Continue to access" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "3. Access" }).getAttribute("aria-current")).toBe("step"));
  expect(screen.queryByLabelText("Origin URL")).toBeNull();
  expect(api.PATCH).toHaveBeenCalledTimes(2);
  expect(api.POST).not.toHaveBeenCalled();
});

it("uses only the configured Applications suffix and sends a full hostname to the API", async () => {
  data.baseDomain = "private.customer.test";
  show("/app-access/applications/new");
  fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Payroll" } });
  fireEvent.change(screen.getByLabelText("Application subdomain"), { target: { value: "payroll" } });
  expect(screen.getByText(".private.customer.test")).toBeTruthy();
  expect(screen.getByText("Application address: https://payroll.private.customer.test")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Continue to connection" }));
  fireEvent.change(screen.getByLabelText("Origin URL"), { target: { value: "https://private.example" } });
  fireEvent.change(screen.getByLabelText("Gateway connector"), { target: { value: "gateway-1" } });
  fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(data.patches).toHaveLength(1));
  expect(data.patches[0]).toMatchObject({ body: { public_hostname: "payroll.private.customer.test" } });
});

it("extracts saved hostnames, avoids a duplicate pasted suffix, and prevents invalid new prefixes", async () => {
  show("/app-access/applications/app-1");
  const input = await screen.findByLabelText("Application subdomain");
  expect(input).toHaveProperty("value", "payroll");
  fireEvent.change(input, { target: { value: "finance.apps.example" } });
  expect(input).toHaveProperty("value", "finance");
  expect(screen.getByText("Application address: https://finance.apps.example")).toBeTruthy();
  fireEvent.change(input, { target: { value: "-bad" } });
  expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", true);
  expect(api.PATCH).not.toHaveBeenCalled();
});

it("makes a missing domain explicit and preserves existing multi-label hostnames during metadata edits", async () => {
  data.baseDomain = "";
  const empty = show("/app-access/applications/new");
  expect(await screen.findByLabelText("Application subdomain")).toHaveProperty("disabled", true);
  expect(screen.getByText(/An operator must configure the Applications domain/)).toBeTruthy();
  empty.unmount(); data.baseDomain = "apps.example"; data.savedHostname = "old.payroll.apps.example";
  show("/app-access/applications/app-1");
  fireEvent.change(await screen.findByLabelText("Application name"), { target: { value: "Renamed payroll" } });
  const identityFields = screen.getByLabelText("Application name").closest("fieldset")!;
  expect(within(identityFields).getByText("old.payroll.apps.example")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(data.patches).toHaveLength(1));
  expect(data.patches[0]).toMatchObject({ body: { public_hostname: "old.payroll.apps.example" } });
});

it("renders a saved image and explicitly removes it in the next draft update", async () => {
  data.iconData = "data:image/png;base64,iVBORw0KGgo=";
  show("/app-access/applications/app-1");
  await screen.findByLabelText("Application name");
  const iconSummary = screen.getByText("Application icon");
  expect(iconSummary.closest("details")).toHaveProperty("open", false);
  expect(iconSummary.closest("summary")?.querySelector('img[src^="data:image/png;base64,"]')).toBeTruthy();
  fireEvent.click(iconSummary);
  expect(iconSummary.closest("details")).toHaveProperty("open", true);
  fireEvent.click(screen.getByRole("button", { name: "Remove uploaded icon" }));
  expect(iconSummary.closest("summary")?.querySelector('img[src^="data:image/png;base64,"]')).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(data.patches).toHaveLength(1));
  expect(data.patches[0]).toMatchObject({ body: { icon_data_url: "", icon: "app" } });
});


it("opens domain configuration in context only for a server administrator", async () => {
  const owner = show("/app-access/applications");
  await screen.findByRole("link", { name: "Payroll" });
  expect(screen.queryByRole("button", { name: "Configure domains" })).toBeNull();
  owner.unmount(); data.serverAdmin = true;
  show("/app-access/applications");
  const configure = await screen.findByRole("button", { name: "Configure domains" });
  expect(data.requests).not.toContain("/api/v1/admin/app-access/domains");
  fireEvent.click(configure);
  const dialog = await screen.findByRole("dialog", { name: "Application domains" });
  expect(await within(dialog).findByLabelText("Portal URL")).toHaveProperty("value", "https://console.example.com");
  expect(screen.getByRole("link", { name: "Payroll", hidden: true })).toBeTruthy();
  expect(data.requests.filter(path => path === "/api/v1/admin/app-access/domains")).toHaveLength(1);
  expect(data.patches).toHaveLength(0);
});

it("changes server page size without retaining selection and omits an unnecessary first-page footer", async () => {
  show("/app-access/applications?page=2");
  await screen.findByRole("link", { name: "Payroll" });
  fireEvent.click(screen.getByLabelText("Select Payroll"));
  expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", true);
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
  await waitFor(() => expect(api.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId: "org-1" }, query: { search: "", limit: 10, offset: 0 } } }));
  await screen.findByRole("link", { name: "Payroll" });
  expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", false);
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
});

it("keeps inline domain settings read only for an unverified server administrator", async () => {
  data.serverAdmin = true; data.verified = false;
  show("/app-access/applications");
  fireEvent.click(await screen.findByRole("button", { name: "Configure domains" }));
  const dialog = await screen.findByRole("dialog", { name: "Application domains" });
  expect(await within(dialog).findByLabelText("Portal URL")).toHaveProperty("disabled", true);
  expect(within(dialog).getByRole("button", { name: "Save changes" })).toHaveProperty("disabled", true);
  expect(data.patches).toHaveLength(0);
});

it("clears inventory selection when search, publication filter or server page changes", async () => {
  show("/app-access/applications?page=2");
  fireEvent.click(await screen.findByRole("checkbox", { name: "Select Payroll" }));
  expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", true);
  fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", false));
  fireEvent.click(screen.getByRole("checkbox", { name: "Select Payroll" }));
  fireEvent.change(screen.getByLabelText("Search applications"), { target: { value: "Pay" } });
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", false));
  fireEvent.click(screen.getByRole("checkbox", { name: "Select Payroll" }));
  fireEvent.change(screen.getByLabelText("Publication"), { target: { value: "published" } });
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Select Payroll" })).toHaveProperty("checked", false));
  expect(api.POST).not.toHaveBeenCalled();
});

describe("Applications navigation entry regression", () => {
  it("returns a control-panel application administrator from My access to Applications and Add application", async () => {
    data.serverAdmin = true;
    show("/app-access/my-applications");
    fireEvent.click(await screen.findByRole("link", { name: "Applications" }));
    expect(await screen.findByRole("link", { name: "Add application" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Payroll" })).toBeTruthy();
  });
  it("keeps configuration navigation for an org administrator without the installation cp_admin flag", async () => {
    data.serverAdmin = false;
    show("/app-access/my-applications");
    expect(await screen.findByRole("link", { name: "Applications" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Access" })).toBeTruthy();
  });
  it("gives an assigned ordinary member scoped Manage access without configuration or create links", async () => {
    data.roles = ["member"]; data.appAdmin = true;
    show("/app-access");
    expect(await screen.findByRole("link", { name: "Manage access" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Add application" })).toBeNull();
    expect(data.requests.some(path => path.endsWith("/applications") || path.endsWith("/settings"))).toBe(false);
  });
  it("lands an unassigned ordinary member on My access without a Manage access entry", async () => {
    data.roles = ["member"];
    show("/app-access");
    await screen.findByText(/No published applications are granted/);
    await waitFor(() => expect(data.requests.some(path => path.endsWith("/managed-apps"))).toBe(true));
    expect(screen.queryByRole("link", { name: /^Manage access/ })).toBeNull();
    expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
  });
});

describe("Applications feature setting", () => {
  function feature(orgId = "org-1", permitted = true, canEdit = true) {
    return <AppAccessFeatureSettings orgId={orgId} permitted={permitted} canEdit={canEdit} />;
  }

  it("keeps draft opt-in gating in inventory and links authorized administrators to Features only while disabled", async () => {
    data.enabled = false; data.serverAdmin = true;
    show("/app-access/applications");
    await screen.findByRole("link", { name: "Payroll" });
    expect(screen.queryByRole("link", { name: "Add application" })).toBeNull();
    expect(screen.getByRole("link", { name: "Manage in Features" }).getAttribute("href")).toBe("/settings?section=features&feature=app-access");
    expect(screen.queryByRole("button", { name: /Enable Applications|Turn off Applications/ })).toBeNull();
    expect(screen.queryByRole("switch", { name: "App Access" })).toBeNull();
    expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("requires explicit opt-in and preserves stale settings until authoritative reload", async () => {
    data.enabled = false; data.stale = true;
    render(feature());
    const toggle = await screen.findByRole("switch", { name: "App Access" });
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    expect(api.PATCH).not.toHaveBeenCalled();
    fireEvent.click(toggle);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("settings changed"));
    expect(data.patches[0]).toMatchObject({ params: { path: { orgId: "org-1" } }, body: { enabled: true, expected_version: 2 } });
    expect(screen.queryByRole("switch", { name: "App Access" })).toBeNull();
    expect(screen.getByText("Unavailable")).toBeTruthy();
    fireEvent.click(toggle);
    expect(api.PATCH).toHaveBeenCalledTimes(1);
    data.stale = false; data.enabled = true;
    fireEvent.click(screen.getByRole("button", { name: "Reload App Access setting" }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "App Access" }).getAttribute("aria-checked")).toBe("true"));
    expect(screen.getByRole("switch", { name: "App Access" })).toHaveProperty("disabled", false);
  });

  it("permits turning off persisted access after entitlement and domain loss", async () => {
    data.entitled = false; data.baseDomain = "";
    render(feature());
    const toggle = await screen.findByRole("switch", { name: "App Access" });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    expect(toggle).toHaveProperty("disabled", false);
    fireEvent.click(toggle);
    await waitFor(() => expect(data.patches[0]).toMatchObject({ body: { enabled: false, expected_version: 2 } }));
    await waitFor(() => expect(toggle.getAttribute("aria-checked")).toBe("false"));
    expect(toggle).toHaveProperty("disabled", true);
  });

  it("preserves app-domain setting conflicts instead of claiming another edit", async () => {
    data.enabled = false; data.conflict = "app_domain_unavailable";
    render(feature());
    fireEvent.click(await screen.findByRole("switch", { name: "App Access" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Configure the application domain first");
    expect(screen.queryByRole("switch", { name: "App Access" })).toBeNull();
    expect(screen.getByRole("button", { name: "Reload App Access setting" })).toBeTruthy();
  });

  it("does not read the feature without view permission and cannot write read-only settings", async () => {
    const view = render(feature("org-1", false, false));
    expect(api.GET).not.toHaveBeenCalled();
    expect(api.PATCH).not.toHaveBeenCalled();
    view.rerender(feature("org-1", true, false));
    const toggle = await screen.findByRole("switch", { name: "App Access" });
    expect(toggle).toHaveProperty("disabled", true);
    fireEvent.click(toggle);
    expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("treats a failed read as unavailable and recovers only by reloading the setting", async () => {
    vi.mocked(api.GET).mockResolvedValueOnce({ error: { error: { message: "Settings unavailable" } } } as never);
    render(feature());
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Settings unavailable");
    expect(screen.queryByRole("switch", { name: "App Access" })).toBeNull();
    expect(api.PATCH).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Reload App Access setting" }));
    expect((await screen.findByRole("switch", { name: "App Access" })).getAttribute("aria-checked")).toBe("true");
  });

  it("ignores a previous organization's late update and saves only the new setting version", async () => {
    let finishOld!: () => void;
    const pending = new Promise<void>(resolve => { finishOld = resolve; });
    vi.mocked(api.PATCH).mockImplementationOnce(async () => {
      await pending;
      return { data: { enabled: false, version: 3, entitlement_available: true, base_domain: "apps.example", domain_ready: true } } as never;
    });
    const view = render(feature());
    fireEvent.click(await screen.findByRole("switch", { name: "App Access" }));
    vi.mocked(api.GET).mockResolvedValueOnce({ data: { enabled: false, version: 9, entitlement_available: true, base_domain: "apps.example", domain_ready: true } } as never);
    view.rerender(feature("org-2"));
    await waitFor(() => expect(screen.getByRole("switch", { name: "App Access" }).getAttribute("aria-checked")).toBe("false"));
    finishOld();
    await pending;
    fireEvent.click(screen.getByRole("switch", { name: "App Access" }));
    await waitFor(() => expect(api.PATCH).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/app-access/settings", {
      params: { path: { orgId: "org-2" } }, body: { enabled: true, expected_version: 9 },
    }));
  });
});

describe("stable administration navigation across Applications routes", () => {
  it.each([true, false])("keeps the same administration tabs and selected route with cp_admin=%s", async serverAdmin => {
    data.serverAdmin = serverAdmin; data.roles = ["member", "admin"];
    show("/app-access/applications");
    const labels = ["Applications", "Access", "Requests", "My Applications"];
    for (const selected of ["Applications", "Requests", "Access", "My Applications", "Applications"]) {
      const destination = await screen.findByRole("link", { name: selected });
      fireEvent.click(destination);
      await waitFor(() => {
        const navigation = screen.getByRole("navigation", { name: "Applications" });
        expect(within(navigation).getAllByRole("link").map(link => link.textContent)).toEqual(labels);
        expect(within(navigation).getByRole("link", { name: selected }).getAttribute("aria-current")).toBe("page");
      });
    }
    expect(await screen.findByRole("link", { name: "Add application" })).toBeTruthy();
  });
  it("keeps scoped member request review out of the global configuration shell", async () => {
    data.roles = ["member"]; data.appAdmin = true;
    show("/app-access/requests");
    expect(await screen.findByRole("link", { name: "Manage access" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "App Access" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Applications" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Access" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Requests" })).toBeNull();
    expect(data.requests.some(path => path.endsWith("/members") || path.endsWith("/applications") || path.endsWith("/settings"))).toBe(false);
  });
});

describe("concise Applications inventory availability", () => {
  it("removes the whole enabled banner and feature link without changing enabled actions", async () => {
    data.serverAdmin = true; show("/app-access/applications");
    expect(await screen.findByRole("link", { name: "Add application" })).toBeTruthy();
    expect(screen.queryByText(/enabled for this organization|Connection and routing changes|Saved icons update immediately/)).toBeNull();
    expect(screen.queryByRole("link", { name: "Manage in Features" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Manage feature" })).toBeNull();
    expect(api.PATCH).not.toHaveBeenCalled();
  });
  it("shows the disabled state and organization feature shortcut without requiring CP authority", async () => {
    data.enabled = false; data.serverAdmin = false; show("/app-access/applications");
    expect(await screen.findByText("App Access is off for this organization.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Manage in Features" }).getAttribute("href")).toBe("/settings?section=features&feature=app-access");
    expect(screen.queryByRole("link", { name: "Add application" })).toBeNull();
    expect(screen.queryByText(/Connection and routing changes|Saved icons update immediately/)).toBeNull();
  });
  it("does not give a CP admin inventory or feature authority without organization permissions", async () => {
    data.enabled = false; data.serverAdmin = true; data.roles = ["member"]; show("/app-access/applications");
    expect(await screen.findByText("You do not have permission to view application configuration.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Manage in Features" })).toBeNull();
    expect(data.requests.some(path => path.endsWith("/app-access/settings"))).toBe(false);
    expect(api.PATCH).not.toHaveBeenCalled();
  });
  it("keeps the disabled shortcut hidden until the administrator has verified edit authority", async () => {
    data.enabled = false; data.serverAdmin = true; data.verified = false; show("/app-access/applications");
    expect(await screen.findByText("App Access is off for this organization.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Manage in Features" })).toBeNull();
    expect(api.PATCH).not.toHaveBeenCalled();
  });
});
