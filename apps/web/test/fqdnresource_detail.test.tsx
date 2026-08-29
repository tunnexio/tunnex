import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";

let orgId = "org-a";
let role = "admin";
let members: Promise<unknown> | unknown;
let inventories: Record<string, Promise<unknown> | unknown> = {};
let impacts: Record<string, Promise<unknown> | unknown> = {};
const row = (id: string, name = id) => ({ id, name, fqdn: `${id}.internal.example.com`, protocol: "tcp", port_low: 443, port_high: null, state: "stale", answer_count: 7, resolver_context: null, generation: null, effective_ttl_seconds: null, refreshed_at: null, last_good_at: null });
const allowed = () => ({ data: [{ user_id: "user-a", role }] });

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: orgId, name: orgId } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string, options?: { params?: { path?: { orgId?: string; resourceId?: string } } }) => {
    if (path.endsWith("/members")) return await members;
    if (path.endsWith("/impact")) return await impacts[`${options?.params?.path?.orgId}:${options?.params?.path?.resourceId}`];
    if (path.endsWith("/fqdn-resources")) return await inventories[options?.params?.path?.orgId ?? ""];
    return { data: [] };
  }) } };
});

import { api } from "../src/lib/api";
import AccessResources, { FQDNResourceDetail } from "../src/pages/AccessResources";

function page(path = "/access/resources/fqdn/fqdn-1?q=orders&status=stale&sort=name&dir=asc", state?: unknown) {
  const [pathname, query = ""] = path.split("?");
  return render(<MemoryRouter initialEntries={[{ pathname, search: query ? `?${query}` : "", state }]}><Routes><Route path="/access/resources/fqdn/:resourceId" element={<FQDNResourceDetail />} /></Routes></MemoryRouter>);
}
function Navigator() { const navigate = useNavigate(); return <><button onClick={() => navigate("/access/resources/fqdn/b")}>B</button><FQDNResourceDetail /></>; }

beforeEach(() => {
  orgId = "org-a"; role = "admin"; members = allowed();
  inventories = { "org-a": { data: [row("fqdn-1", "Orders")] } };
  impacts = { "org-a:fqdn-1": { data: { referencing_rule_count: 2, referencing_rule_ids: ["rule-7", "rule-9"], generation_withdrawal_required: false } } };
  vi.mocked(api.GET).mockClear();
});
afterEach(cleanup);

describe("FQDN resource detail route", () => {
  it("opens the stable detail workspace from a narrow-summary View action with its full back query", async () => {
    render(<MemoryRouter initialEntries={["/access/resources?type=fqdn&q=orders&status=stale&sort=name&dir=asc"]}><Routes><Route path="/access/resources" element={<AccessResources />} /><Route path="/access/resources/fqdn/:resourceId" element={<FQDNResourceDetail />} /></Routes></MemoryRouter>);
    const view = await screen.findByRole("link", { name: "View Orders" });
    expect(view.getAttribute("href")).toBe("/access/resources/fqdn/fqdn-1?type=fqdn&q=orders&status=stale&sort=name&dir=asc");
    fireEvent.click(view);
    expect(await screen.findByRole("heading", { name: "Orders" })).toBeTruthy();
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "Resources" }).getAttribute("href")).toBe("/access/resources?type=fqdn&q=orders&status=stale&sort=name&dir=asc");
  });

  it("allows viewers, preserves the exact back query, and keeps Audit a plain link", async () => {
    page(undefined, { from: "/access/resources?type=fqdn&q=orders&status=stale&sort=name&dir=asc" });
    expect(await screen.findByRole("heading", { name: "Orders" })).toBeTruthy();
    expect(screen.getByText("Unavailable — no active generation")).toBeTruthy();
    expect(screen.getByText(/2 access rules reference this resource/i)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Audit log" }).getAttribute("href")).toBe("/audit");
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "Resources" }).getAttribute("href")).toBe("/access/resources?type=fqdn&q=orders&status=stale&sort=name&dir=asc");
  });

  it("denies a member without loading inventory", async () => {
    role = "member"; members = allowed(); page();
    expect(await screen.findByText(/do not have permission/i)).toBeTruthy();
    expect((vi.mocked(api.GET).mock.calls as unknown[][]).some((call) => String(call[0]).endsWith("/fqdn-resources"))).toBe(false);
  });

  it("retries membership and inventory failures", async () => {
    members = { error: { error: { message: "members down" } } }; page();
    expect(await screen.findByText(/Could not check FQDN resource permissions: members down/)).toBeTruthy();
    members = allowed(); fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Orders" })).toBeTruthy();
    cleanup(); inventories["org-a"] = { error: { error: { message: "inventory down" } } }; page();
    expect(await screen.findByText(/Could not load this FQDN resource: inventory down/)).toBeTruthy();
    inventories["org-a"] = { data: [row("fqdn-1", "Orders")] }; fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Orders" })).toBeTruthy();
  });

  it("keeps impact errors explicit and retryable without fabricating zero", async () => {
    impacts["org-a:fqdn-1"] = { error: { error: { message: "impact down" } } }; page();
    expect(await screen.findByText(/Could not load this FQDN resource: impact down/)).toBeTruthy();
    expect(screen.queryByText(/No access rules currently reference this resource/i)).toBeNull();
    impacts["org-a:fqdn-1"] = { data: { referencing_rule_count: 1, referencing_rule_ids: ["rule-1"], generation_withdrawal_required: false } };
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(/1 access rule references this resource/i)).toBeTruthy();
  });

  it("reports not-found and direct-load falls back to the complete current query", async () => {
    inventories["org-a"] = { data: [] }; page();
    expect(await screen.findByText(/unavailable or no longer exists/i)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Back to Resources" }).getAttribute("href")).toBe("/access/resources?q=orders&status=stale&sort=name&dir=asc");
  });

  it("ignores a delayed A list after the route changes to B", async () => {
    let resolveA!: (value: unknown) => void;
    inventories["org-a"] = new Promise((resolve) => { resolveA = resolve; });
    render(<MemoryRouter initialEntries={["/access/resources/fqdn/a"]}><Routes><Route path="/access/resources/fqdn/:resourceId" element={<Navigator />} /></Routes></MemoryRouter>);
    inventories["org-a"] = { data: [row("b", "Beta")] };
    impacts["org-a:b"] = { data: { referencing_rule_count: 3, referencing_rule_ids: ["b-rule"], generation_withdrawal_required: false } };
    fireEvent.click(await screen.findByRole("button", { name: "B" }));
    expect(await screen.findByRole("heading", { name: "Beta" })).toBeTruthy();
    resolveA({ data: [row("a", "Alpha")] }); await Promise.resolve();
    expect(screen.getByRole("heading", { name: "Beta" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Alpha" })).toBeNull();
  });

  it("ignores delayed organization-A results after switching to B", async () => {
    let resolveA!: (value: unknown) => void;
    inventories["org-a"] = new Promise((resolve) => { resolveA = resolve; });
    const rendered = page("/access/resources/fqdn/fqdn-1");
    orgId = "org-b"; inventories["org-b"] = { data: [row("fqdn-1", "Org B resource")] }; impacts["org-b:fqdn-1"] = { data: { referencing_rule_count: 4, referencing_rule_ids: ["b-rule"], generation_withdrawal_required: false } };
    rendered.rerender(<MemoryRouter initialEntries={["/access/resources/fqdn/fqdn-1"]}><Routes><Route path="/access/resources/fqdn/:resourceId" element={<FQDNResourceDetail />} /></Routes></MemoryRouter>);
    expect(await screen.findByRole("heading", { name: "Org B resource" })).toBeTruthy();
    resolveA({ data: [row("fqdn-1", "Org A resource")] }); await Promise.resolve();
    expect(screen.getByRole("heading", { name: "Org B resource" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Org A resource" })).toBeNull();
  });
});
