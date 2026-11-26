import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

// LS-UX-2: role-aware console navigation. UX only: every API still enforces its own permission.
const roster = vi.hoisted(() => ({ role: "member" as string, fail: false }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/auth/me") return { data: { id: "u1", email: "rae@example.com", email_verified: true } };
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path === "/api/v1/organizations") return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members")) return roster.fail ? { error: { error: { message: "unavailable" } } } : { data: [{ user_id: "u1", role: roster.role, email: "rae@example.com", name: "Rae", status: "active" }, { user_id: "u2", role: "owner", email: "olu@example.com", name: "Olu Owner", status: "active" }] };
        if (path.endsWith("/devices")) return { data: [] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

vi.mock("../src/components/UpgradeCenter", () => ({ UpgradeCenter: () => <p>Upgrade center mounted</p> }));
import { OrgProvider } from "../src/lib/useOrg";
import { CommandPalette } from "../src/components/CommandPalette";
import { AuthProvider } from "../src/lib/auth";
import { AppShell, NAV_DESTINATIONS } from "../src/components/AppShell";
import { LayoutCapabilityProvider } from "../src/components/ComposeGate";
import { capabilityFor, type LayoutIntent } from "../src/lib/layout";
import { DeploymentMetaProvider } from "../src/lib/deploymentMeta";
import { AdminOnlyRoute } from "../src/components/AdminOnly";
import Dashboard from "../src/pages/Dashboard";
import { NAV_PERMISSIONS, navAllows } from "../src/lib/navaccess";
import type { Meta } from "../src/lib/api";

afterEach(() => { cleanup(); roster.role = "member"; roster.fail = false; });
const meta: Meta = { edition: "open", protocol_version: 1, sso_providers: [], sandbox_module_state: "disabled" };
function providers(children: React.ReactNode, path = "/dashboard", intent: LayoutIntent = "wide") {
  return render(<MemoryRouter initialEntries={[path]}><LayoutCapabilityProvider value={capabilityFor(intent)}><AuthProvider><OrgProvider><DeploymentMetaProvider value={meta}>{children}</DeploymentMetaProvider></OrgProvider></AuthProvider></LayoutCapabilityProvider></MemoryRouter>);
}
async function navLinks(): Promise<{ href: string; label: string }[]> {
  const menu = screen.queryByRole("button", { name: /menu/i });
  if (menu) act(() => fireEvent.click(menu));
  const nav = await screen.findByRole("navigation", { name: "Main" });
  return within(nav).getAllByRole("link").map(a => ({ href: a.getAttribute("href")!, label: a.getAttribute("aria-label") ?? a.textContent ?? "" }));
}
const MEMBER = ["/dashboard", "/ai-gateway", "/devices", "/app-access", "/browser-access/terminal", "/beam", "/vault", "/audit", "/settings"].sort();
const ADMIN_AREAS = ["/gateways", "/sites", "/kubernetes", "/agents", "/mcp", "/access", "/users", "/alerts", "/access-events"];

describe("LS-UX-2 member navigation (M1-M19)", () => {
  it("a member's sidebar keeps what they can use and drops admin areas, at every width", async () => {
    for (const intent of ["triage", "compose", "wide"] as LayoutIntent[]) {
      providers(<AppShell />, "/dashboard", intent);
      await waitFor(async () => expect((await navLinks()).map(l => l.href).sort()).toEqual(MEMBER));
      cleanup();
    }
  });
  it("labels the audit log for what a member sees", async () => {
    providers(<AppShell />);
    await waitFor(async () => expect((await navLinks()).find(l => l.href === "/audit")?.label).toContain("My activity"));
  });
  it("an owner keeps every destination", async () => {
    roster.role = "owner";
    providers(<AppShell />);
    await waitFor(async () => expect((await navLinks()).map(l => l.href).sort()).toEqual(NAV_DESTINATIONS.map(d => d.to).filter(to => to !== "/sandboxes").sort()));
  });
  it("a failed role read never removes a destination", async () => {
    roster.fail = true;
    providers(<AppShell />);
    await waitFor(async () => expect((await navLinks()).map(l => l.href)).toEqual(expect.arrayContaining(ADMIN_AREAS)));
  });
  it("the rules: loading withholds gated areas, failure withholds nothing, admins keep their areas", () => {
    for (const to of ADMIN_AREAS) {
      expect(navAllows(to, { state: "ready", roles: ["member"] })).toBe(false);
      expect(navAllows(to, { state: "loading" })).toBe(false);
      expect(navAllows(to, { state: "failed" })).toBe(true);
    }
    for (const to of ["/kubernetes", "/agents", "/mcp", "/access", "/access-events", "/alerts"]) expect(navAllows(to, { state: "ready", roles: ["admin"] })).toBe(true);
    expect(navAllows("/ai-gateway", { state: "ready", roles: ["ai-view"] })).toBe(true);
    expect(navAllows("/dashboard", { state: "loading" })).toBe(true);
    expect(Object.keys(NAV_PERMISSIONS)).toEqual(expect.arrayContaining(ADMIN_AREAS));
  });
  it("an admin page reached by URL is a calm notice that names who to ask (M20)", async () => {
    providers(<Routes><Route path="/alerts" element={<AdminOnlyRoute to="/alerts" page="Alerts"><p>alert inventory</p></AdminOnlyRoute>} /></Routes>, "/alerts");
    await screen.findByRole("heading", { name: "Alerts is managed by organization admins" });
    await screen.findByText(/ask Olu Owner \(olu@example.com\)/);
    expect(screen.queryByText("alert inventory")).toBeNull();
    expect(screen.queryByText(/permission to perform/)).toBeNull();
    expect(screen.getByRole("link", { name: "Go to your overview" }).getAttribute("href")).toBe("/dashboard");
  });
  it("the same route renders the page for an admin", async () => {
    roster.role = "admin";
    providers(<Routes><Route path="/alerts" element={<AdminOnlyRoute to="/alerts" page="Alerts"><p>alert inventory</p></AdminOnlyRoute>} /></Routes>, "/alerts");
    await screen.findByText("alert inventory");
  });
  it("a member's overview is their workspace, not the admin fleet view (M1)", async () => {
    providers(<Dashboard />);
    await screen.findByText("Your workspace");
    await screen.findByText(/No devices yet\./);
    const cards = screen.getByRole("list");
    for (const name of ["App Access", "Server Access", "Local Sharing", "Vault", "AI Gateway"]) expect(within(cards).getByText(name)).toBeTruthy();
    expect(screen.queryByText("Sandboxes")).toBeNull();
    expect(screen.queryByText("Get started")).toBeNull();
    expect(screen.queryByText("Gateway Health")).toBeNull();
    await screen.findByText(/ask Olu Owner \(olu@example.com\)/);
    // A server admin is not an organization role: one-click upgrades stay on the member overview.
    expect(screen.getByText("Upgrade center mounted")).toBeTruthy();
  });
  it("the command palette offers the member's destinations with the same labels as the sidebar (M19)", async () => {
    providers(<CommandPalette />);
    act(() => { fireEvent.keyDown(window, { key: "k", metaKey: true }); });
    const list = await screen.findByRole("listbox");
    await waitFor(() => expect(within(list).queryByText("Gateways")).toBeNull());
    expect(within(list).getByText("My activity")).toBeTruthy();
    expect(within(list).queryByText("Audit Log")).toBeNull();
    expect(within(list).getByText("Local Sharing")).toBeTruthy();
  });
});
