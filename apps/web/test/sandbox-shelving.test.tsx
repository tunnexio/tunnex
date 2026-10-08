import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import App from "../src/App";
import { DeploymentMetaProvider, useDeploymentMeta, useSandboxModuleState } from "../src/lib/deploymentMeta";
import type { Meta } from "../src/lib/api";

// This route-only test never opens a terminal; avoid xterm probing jsdom canvas on import.
vi.mock("@xterm/xterm", () => ({ Terminal: class {} }));

const requests = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: requests }));

const metadata = (state: Meta["sandbox_module_state"]): Meta => ({
  edition: "enterprise", protocol_version: 1, sso_providers: [], sandbox_module_state: state,
});
const user = {
  id: "fixture-user", email: "fixture@example.test", email_verified: true,
  cp_admin: true, must_change_password: false, mfa_enrollment_required: false,
};
const org = {
  id: "fixture-org", name: "Fixture organization", ovpn_enabled: false,
  cross_gateway_clients_enabled: false, agent_policy_templates_enabled: false,
};

beforeEach(() => {
  vi.resetAllMocks();
  window.history.replaceState({}, "", "/");
  requests.GET.mockImplementation(async (path: string) => {
    if (path === "/api/v1/auth/me") return { data: user };
    if (path === "/api/v1/meta") return { data: metadata("enabled") };
    if (path === "/api/v1/organizations") return { data: [org] };
    if (path === "/api/v1/organizations/{orgId}") return { data: org };
    if (path.endsWith("/members")) return { data: [{
      user_id: user.id, email: user.email, role: "owner", roles: ["owner"], status: "active", email_verified: true,
    }] };
    if (path === "/api/v1/license") return { data: { features: [], limits: {} } };
    if (path.endsWith("/app-access/settings")) return { data: {
      enabled: false, version: 1, entitlement_available: true, domain_ready: true, base_domain: "apps.example.test",
    } };
    if (path.endsWith("/server-access")) return { data: {
      enabled: true, can_manage: false, can_grant: false, can_manage_sessions: false,
      grants: [], sessions: [], limitations: [], mfa_freshness_seconds: 900,
      servers: [{
        id: "fixture-server", name: "Build host", gateway_id: "fixture-gateway", ssh_port: 22,
        accounts: ["fixture"], ready_accounts: ["fixture"], revision: 1, enabled: true,
        recording_enabled: false, developer_access_enabled: false,
        idle_timeout_seconds: 300, max_session_seconds: 900,
      }],
    } };
    return { data: [] };
  });
});
afterEach(cleanup);

function Location() { return <p>Route: {useLocation().pathname}</p>; }
function mount(path: string) {
  window.history.replaceState({}, "", path);
  return render(<MemoryRouter initialEntries={[path]}><App /><Location /></MemoryRouter>);
}
function expectNoSandboxReads() {
  expect(requests.GET.mock.calls.some(([path]) => path.includes("sandbox") || path.includes("saved-ssh-keys"))).toBe(false);
}

it.each([
  "/sandboxes", "/sandboxes/new", "/sandboxes/setup", "/sandboxes/skills",
  "/sandboxes/skills/fixture-skill", "/sandboxes/fixture-sandbox", "/sandboxes/unknown/nested/path",
])("returns Not found before product providers or requests for %s", async path => {
  mount(path);
  expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
  expect(screen.getByText(`Route: ${path}`)).toBeTruthy();
  // No auth, organization or metadata bootstrap should happen for a shelved URL.
  for (const method of Object.values(requests)) expect(method).not.toHaveBeenCalled();
});

function ModuleState() {
  const { meta } = useDeploymentMeta();
  const effective = useSandboxModuleState();
  return <><p>Server module: {meta?.sandbox_module_state}</p><p>Effective module: {effective}</p></>;
}
it.each(["enabled", "draining", "disabled"] as const)("keeps shelving in force with %s server metadata", state => {
  render(<DeploymentMetaProvider value={metadata(state)}><ModuleState /></DeploymentMetaProvider>);
  expect(screen.getByText(`Server module: ${state}`)).toBeTruthy();
  expect(screen.getByText("Effective module: disabled")).toBeTruthy();
  expect(requests.GET).not.toHaveBeenCalled();
});

it("preserves ordinary organization Features in Settings with enabled sandbox metadata", async () => {
  mount("/settings?section=features");
  expect(await screen.findByRole("heading", { name: "Settings" })).toBeTruthy();
  expect(await screen.findByRole("switch", { name: "OpenVPN" })).toBeTruthy();
  expect(await screen.findByRole("switch", { name: "App Access" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Features" }).getAttribute("aria-selected")).toBe("true");
  expect(screen.queryByRole("link", { name: "Sandboxes", hidden: true })).toBeNull();
  expect(screen.queryByRole("switch", { name: "Enable Sandboxes", hidden: true })).toBeNull();
  expect(screen.getByText("Route: /settings")).toBeTruthy();
  expectNoSandboxReads();
});

it("preserves the ordinary browser terminal catalog with enabled sandbox metadata", async () => {
  mount("/browser-access/terminal");
  expect(await screen.findByRole("heading", { name: "Server Access" })).toBeTruthy();
  fireEvent.click(await screen.findByRole("button", { name: "Build host" }));
  expect(await screen.findByRole("button", { name: "Connect as fixture" })).toBeTruthy();
  expect(screen.getByText("Route: /browser-access/terminal")).toBeTruthy();
  expect(requests.GET.mock.calls.some(([path]) => path.endsWith("/server-access"))).toBe(true);
  expect(screen.queryByRole("link", { name: "Sandboxes", hidden: true })).toBeNull();
  expectNoSandboxReads();
  expect(requests.POST).not.toHaveBeenCalled();
});
