import { Profiler } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { BrowserRouter, Link, MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Settings from "../src/pages/Settings";

const fixture = vi.hoisted(() => ({
  actor: { id: "actor-a", email: "actor@example.test", email_verified: true, must_change_password: false, cp_admin: false },
  org: { id: "org-a", name: "Organization A", slug: "org-a", pool_cidr: "100.64.0.0/16", managed_agent_runtime_enabled: false, agent_policy_templates_enabled: false, agent_jit_access_enabled: false, ovpn_enabled: false, cross_gateway_clients_enabled: false, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" },
  role: "owner", roles: ["owner"] as unknown, status: "active", aiEnabled: false,
  GET: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), POST: vi.fn(), DELETE: vi.fn(), updateOrg: vi.fn(),
}));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: fixture.actor } }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: fixture.org, orgs: [fixture.org], loading: false, failed: false, updateOrg: fixture.updateOrg, setOrg: vi.fn() }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: fixture.GET, PUT: fixture.PUT, PATCH: fixture.PATCH, POST: fixture.POST, DELETE: fixture.DELETE } }));
vi.mock("../src/lib/beam", async () => ({ ...await vi.importActual("../src/lib/beam"), beamApi: { policy: vi.fn(async () => ({ ok: true, data: { version: 1, enabled: false, domain_ready: false, can_manage_policy: true, require_mfa: false, max_duration_seconds: 3600, max_shares: 3, open_for_all_users: false, publisher_group_ids: [], reviewer_user_ids: [], reviewer_group_ids: [] } })) } }));

function page() { return <MemoryRouter><Settings /></MemoryRouter>; }
function ai() { return within(screen.getByRole("region", { name: "AI Gateway" })).getByRole("switch", { name: "AI Gateway" }); }
beforeEach(() => {
  vi.clearAllMocks();
  fixture.actor = { id: "actor-a", email: "actor@example.test", email_verified: true, must_change_password: false, cp_admin: false };
  fixture.org = { ...fixture.org, id: "org-a", name: "Organization A", managed_agent_runtime_enabled: false, agent_policy_templates_enabled: false, agent_jit_access_enabled: false, ovpn_enabled: false, cross_gateway_clients_enabled: false };
  fixture.role = "owner"; fixture.roles = ["owner"]; fixture.status = "active"; fixture.aiEnabled = false;
  fixture.GET.mockImplementation(async (path: string) => {
    if (path === "/api/v1/meta") return { data: { edition: "enterprise", sandbox_module_state: "disabled" } };
    if (path.endsWith("/members")) return { data: [{ user_id: fixture.actor.id, email: fixture.actor.email, role: fixture.role, roles: fixture.roles, status: fixture.status }] };
    if (path === "/api/v1/organizations/{orgId}") return { data: fixture.org };
    if (path.endsWith("/ai-gateway")) return { data: { enabled: fixture.aiEnabled, available: true, revision: 2 } };
    if (path.endsWith("/app-access/settings")) return { data: { enabled: false, version: 2, entitlement_available: true, domain_ready: true, base_domain: "apps.example.test" } };
    if (path.endsWith("/server-access")) return { data: { enabled: false, can_manage: true, recording_retention_days: 7, mfa_freshness_seconds: 900, recording_max_session_bytes: 4194304, recording_max_org_bytes: 67108864 } };
    if (path.endsWith("/zero-trust-mode")) return { data: { mode: "off" } };
    if (path.endsWith("/cluster-scope-settings")) return { data: { enabled: false, revision: 2, entitlement_unlocked: true, effective: false } };
    if (path.endsWith("/ipsec/settings")) return { data: { enabled: false, revision: 2 } };
    if (path.endsWith("/ha-settings")) return { data: { enabled: false, revision: 2, actual_state: "disabled", reason_code: "opt_in_disabled" } };
    if (path.endsWith("/agent-jit-access-settings")) return { data: { enabled: false, pending_requests: 0, approved_requests: 0 } };
    if (path.endsWith("/alerting-settings") || path.endsWith("/fqdn-resources/setting")) return { data: { enabled: false } };
    if (path === "/api/v1/license") return { data: { features: ["agent_jit_access"], limits: {} } };
    return { data: [] };
  });
  fixture.PUT.mockImplementation(async (path: string, request: { body: { enabled: boolean } }) => {
    if (path.endsWith("/ai-gateway")) { fixture.aiEnabled = request.body.enabled; return { data: { enabled: fixture.aiEnabled, available: true, revision: 3 } }; }
    return { data: { enabled: request.body.enabled } };
  });
  window.history.replaceState({}, "", "/settings?section=features");
});
afterEach(cleanup);

describe("central organization Features authority", () => {
  it("follows a same-page feature link from another Settings section without browser reload", async () => {
    fixture.role = "ai-admin"; fixture.roles = ["ai-admin"];
    window.history.replaceState({}, "", "/settings?section=authentication");
    render(<BrowserRouter><Link to="/settings?section=features&feature=ai-gateway">Manage AI feature</Link><Settings /></BrowserRouter>);
    await waitFor(() => expect(screen.getByRole("tab", { name: "Authentication" }).getAttribute("aria-selected")).toBe("true"));
    expect(screen.queryByRole("switch", { name: "AI Gateway" })).toBeNull();
    fireEvent.click(screen.getByRole("link", { name: "Manage AI feature" }));
    await screen.findByRole("switch", { name: "AI Gateway" });
    expect(screen.getByRole("tab", { name: "Features" }).getAttribute("aria-selected")).toBe("true");
    expect(window.location.search).toBe("?section=features&feature=ai-gateway");
    expect(fixture.PUT).not.toHaveBeenCalled();
  });

  it("lets an AI administrator manage only the AI feature without organization-update authority", async () => {
    fixture.role = "ai-admin"; fixture.roles = ["ai-admin"];
    render(page());
    const toggle = await screen.findByRole("switch", { name: "AI Gateway" });
    expect(screen.getByRole("tab", { name: "Features" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("1 feature")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "OpenVPN" })).toBeNull();
    expect(screen.queryByRole("region", { name: "App Access" })).toBeNull();
    expect(fixture.GET.mock.calls.some(([path]) => path.endsWith("/app-access/settings") || path.endsWith("/server-access"))).toBe(false);
    fireEvent.click(toggle);
    await waitFor(() => expect(toggle.getAttribute("aria-checked")).toBe("true"));
    expect(fixture.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId: "org-a" } }, body: { enabled: true } });
    expect(fixture.PATCH).not.toHaveBeenCalled();
  });

  it("uses active union roles and exposes the complete catalog without performing activation writes", async () => {
    fixture.role = "member"; fixture.roles = ["member", "admin"];
    render(page());
    await screen.findByRole("switch", { name: "OpenVPN" });
    expect(screen.getByText("16 features")).toBeTruthy();
    expect(screen.getByRole("region", { name: "Server Access" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Kubernetes cluster scopes" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Zero Trust enforcement" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Sandbox creation" }).textContent).toContain("Unavailable");
    expect(fixture.GET.mock.calls.some(([path]) => path.includes("sandbox"))).toBe(false);
    for (const mutation of [fixture.PUT, fixture.PATCH, fixture.POST, fixture.DELETE]) expect(mutation).not.toHaveBeenCalled();
  });

  it.each([
    { role: "admin", roles: ["admin"], status: "deactivated" },
    { role: "member", roles: ["member"], status: "active" },
    { role: "member", roles: "admin", status: "active" },
    { role: "unknown", roles: ["admin"], status: "active" },
  ])("does not derive feature authority from an inactive or malformed membership (%j)", async ({ role, roles, status }) => {
    fixture.role = role; fixture.roles = roles; fixture.status = status; fixture.actor.cp_admin = true;
    render(page());
    await screen.findByRole("tab", { name: "Authentication" });
    await waitFor(() => expect(fixture.GET.mock.calls.some(([path]) => path.endsWith("/members"))).toBe(true));
    expect(screen.queryByRole("tab", { name: "Features" })).toBeNull();
    expect(screen.queryByRole("switch", { name: "AI Gateway" })).toBeNull();
    expect(fixture.GET.mock.calls.some(([path]) => path.endsWith("/ai-gateway") || path.endsWith("/app-access/settings"))).toBe(false);
    expect(fixture.PUT).not.toHaveBeenCalled();
  });

  it.each([
    { field: "ovpn_enabled", region: "OpenVPN", toggle: "OpenVPN", reload: "Reload OpenVPN setting", value: undefined },
    { field: "ovpn_enabled", region: "OpenVPN", toggle: "OpenVPN", reload: "Reload OpenVPN setting", value: "false" },
    { field: "cross_gateway_clients_enabled", region: "Cross-gateway clients", toggle: "Cross-gateway client connectivity", reload: "Reload connectivity setting", value: undefined },
    { field: "cross_gateway_clients_enabled", region: "Cross-gateway clients", toggle: "Cross-gateway client connectivity", reload: "Reload connectivity setting", value: "false" },
  ])("does not invent disabled truth for a missing or malformed saved flag ($field: $value)", async ({ field, region, toggle, reload, value }) => {
    (fixture.org as unknown as Record<string, unknown>)[field] = value;
    render(page()); const entry = await screen.findByRole("region", { name: region });
    expect(within(entry).queryByRole("switch", { name: toggle })).toBeNull();
    expect(within(entry).getByText("Unavailable")).toBeTruthy();
    fireEvent.click(within(entry).getByRole("button", { name: reload }));
    await waitFor(() => expect(fixture.GET.mock.calls.some(([path]) => path === "/api/v1/organizations/{orgId}")).toBe(true));
    await within(entry).findByRole("alert");
    expect(within(entry).queryByRole("switch", { name: toggle })).toBeNull();
    expect(fixture.PUT).not.toHaveBeenCalled();
  });

  it("resolves a feature deep link and filters by its actual capability keywords", async () => {
    window.history.replaceState({}, "", "/settings?section=features&feature=agent-runtime");
    render(page());
    const runtime = await screen.findByRole("region", { name: "Agent runtime synchronization" });
    expect(document.activeElement).toBe(runtime);
    expect(screen.queryByRole("region", { name: "OpenVPN" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "All features" }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search features" }), { target: { value: "ovpn_enabled" } });
    expect(screen.getByRole("region", { name: "OpenVPN" })).toBeTruthy();
    expect(screen.getByText("1 feature")).toBeTruthy();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search features" }), { target: { value: "missing capability" } });
    expect(screen.getByText("No matching features")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByText("16 features")).toBeTruthy();
    expect(fixture.PUT).not.toHaveBeenCalled();
  });

  it("withdraws prior actor authority at every commit and ignores its delayed feature write", async () => {
    fixture.role = "ai-admin"; fixture.roles = ["ai-admin"];
    let finish!: (value: unknown) => void;
    fixture.PUT.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const leaked: boolean[] = [];
    const tree = () => <Profiler id="feature-actor-scope" onRender={() => {
      if (fixture.actor.id !== "actor-a") leaked.push(Boolean(screen.queryByRole("switch", { name: "AI Gateway" })));
    }}>{page()}</Profiler>;
    const view = render(tree());
    fireEvent.click(await screen.findByRole("switch", { name: "AI Gateway" }));
    fixture.actor = { ...fixture.actor, id: "actor-b" }; fixture.role = "member"; fixture.roles = ["member"];
    view.rerender(tree());
    await waitFor(() => expect(fixture.GET.mock.calls.filter(([path]) => path.endsWith("/members"))).toHaveLength(2));
    await act(async () => finish({ data: { enabled: true, available: true, revision: 3 } }));
    expect(leaked.length).toBeGreaterThan(0); expect(leaked).not.toContain(true);
    expect(screen.queryByRole("tab", { name: "Features" })).toBeNull();
    expect(fixture.PUT).toHaveBeenCalledTimes(1);
    expect(fixture.updateOrg).not.toHaveBeenCalled();
  });

  it("replaces a pending verification scope with read-only saved truth and never commits its late result", async () => {
    fixture.role = "ai-admin"; fixture.roles = ["ai-admin"];
    let finish!: (value: unknown) => void;
    fixture.PUT.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const view = render(page());
    fireEvent.click(await screen.findByRole("switch", { name: "AI Gateway" }));
    fixture.actor = { ...fixture.actor, email_verified: false };
    view.rerender(page());
    await screen.findByRole("switch", { name: "AI Gateway" });
    expect(ai()).toHaveProperty("disabled", true);
    await act(async () => finish({ data: { enabled: true, available: true, revision: 3 } }));
    expect(ai().getAttribute("aria-checked")).toBe("false");
    fireEvent.click(ai());
    expect(fixture.PUT).toHaveBeenCalledTimes(1);
  });
});
