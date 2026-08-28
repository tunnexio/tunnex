import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let fqdnResources: Array<Record<string, unknown>> = [];
let role = "admin";
let impact: Record<string, unknown> = { resource_id: "fqdn-1", referencing_rule_count: 2, referencing_rule_ids: ["rule-a", "rule-b"], generation_withdrawal_required: true };
let resourceLoadError = "";
let settingLoadError = "";
let orgId = "org-a";

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: orgId, name: orgId === "org-a" ? "Org A" : "Org B" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string, options?: { params?: { path?: { orgId?: string } } }) => {
    const requestOrg = options?.params?.path?.orgId;
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role }] };
    if (path.endsWith("/fqdn-resources/setting")) return settingLoadError ? { error: { error: { message: settingLoadError } } } : { data: { enabled: false } };
    if (path.endsWith("/impact")) return { data: impact };
    if (path.endsWith("/fqdn-resources")) return resourceLoadError ? { error: { error: { message: resourceLoadError } } } : { data: fqdnResources };
    if (path.endsWith("/sites")) return { data: requestOrg === "org-b" ? [{ id: "site-b", name: "Branch" }] : [{ id: "site-a", name: "HQ" }] };
    if (path.endsWith("/nodes")) return { data: requestOrg === "org-b" ? [{ id: "gateway-b", name: "Branch gateway", status: "active", enrolled_kind: "gateway", site_id: "site-b" }] : [{ id: "gateway-a", name: "HQ gateway", status: "active", enrolled_kind: "gateway", site_id: "site-a" }] };
    if (path.endsWith("/resources")) return { data: [] };
    return { data: [] };
  }), POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })), PUT: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })) } };
});

import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

function page() { return render(<MemoryRouter><AccessResources /></MemoryRouter>); }
beforeEach(() => { role = "admin"; impact = { resource_id: "fqdn-1", referencing_rule_count: 2, referencing_rule_ids: ["rule-a", "rule-b"], generation_withdrawal_required: true }; resourceLoadError = ""; settingLoadError = ""; orgId = "org-a"; fqdnResources = []; vi.mocked(api.GET).mockClear(); vi.mocked(api.POST).mockClear(); vi.mocked(api.PATCH).mockClear(); vi.mocked(api.PUT).mockClear(); vi.mocked(api.DELETE).mockClear(); });
afterEach(cleanup);

describe("FQDN access resources", () => {
  it("renders server state metadata and never turns a stale answer count into zero", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "stale", answer_count: 7, resolver_context: { site_id: "site-a", site_name: "HQ", gateway_id: "gateway-a", gateway_name: "HQ gateway" }, generation: null, effective_ttl_seconds: null, refreshed_at: null, last_good_at: "2026-08-27T10:00:00Z" }];
    page();
    await screen.findByText("Orders");
    expect(screen.getByText("Not available")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Orders" }));
    expect(await screen.findByText("Last good")).toBeTruthy();
    expect(screen.getByText("2026-08-27T10:00:00Z")).toBeTruthy();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("uses only an explicit selected Site/Gateway context and sends port scope", async () => {
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Create FQDN resource" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Orders" } });
    fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "orders.internal.example.com" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "single" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443" } });
    await screen.findByRole("option", { name: "HQ" });
    fireEvent.change(screen.getByLabelText("Resolver site (optional)"), { target: { value: "site-a" } });
    await screen.findByRole("option", { name: "HQ gateway" });
    fireEvent.change(screen.getByLabelText("Gateway"), { target: { value: "gateway-a" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toMatchObject({ body: { fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: 443, resolver_context: { site_id: "site-a", gateway_id: "gateway-a" } } });
  });

  it("withdraws prior-org resolver selection and dialog state before loading the new organization", async () => {
    const rendered = page();
    fireEvent.click(await screen.findByRole("button", { name: "Create FQDN resource" }));
    await screen.findByRole("option", { name: "HQ" });
    fireEvent.change(screen.getByLabelText("Resolver site (optional)"), { target: { value: "site-a" } });
    fireEvent.change(screen.getByLabelText("Gateway"), { target: { value: "gateway-a" } });
    orgId = "org-b";
    rendered.rerender(<MemoryRouter><AccessResources /></MemoryRouter>);

    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(await screen.findByRole("button", { name: "Create FQDN resource" }));
    expect((screen.getByLabelText("Resolver site (optional)") as HTMLSelectElement).value).toBe("");
    await screen.findByRole("option", { name: "Branch" });
    expect(screen.queryByRole("option", { name: "HQ" })).toBeNull();
    expect(vi.mocked(api.POST)).not.toHaveBeenCalled();
    const getCalls = vi.mocked(api.GET).mock.calls as unknown as unknown[][];
    expect(getCalls.some((call) => JSON.stringify(call).includes('"org-b"'))).toBe(true);
  });

  it("keeps inventory and narrow-form controls accessible on responsive layouts", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 }];
    page();
    expect(await screen.findByRole("table", { name: "FQDN resources inventory" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Orders" }).className).toContain("focus-visible:outline");
    fireEvent.click(screen.getByRole("button", { name: "Create FQDN resource" }));
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "range" } });
    expect(screen.getByLabelText("Port").closest(".grid")?.className).toContain("sm:grid-cols-2");
  });

  it("requires the server impact before allowing deletion", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "any", state: "healthy", answer_count: 2, resolver_context: null, generation: 3 }];
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    expect(await screen.findByText(/Server impact: 2 referencing rules/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Delete FQDN resource" }) as HTMLButtonElement).disabled).toBe(true);
    expect(vi.mocked(api.DELETE)).not.toHaveBeenCalled();
  });

  it("shows server-projected rule identities and recovery links in detail and delete", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "any", state: "healthy", answer_count: 2, resolver_context: null, generation: null }];
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Orders" }));
    expect(await screen.findByText(/Referencing rule identities: rule-a, rule-b/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /Review and edit referenced rules/i }).getAttribute("href")).toBe("/access");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText(/Referencing rule identities: rule-a, rule-b/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /Review referenced rules/i }).getAttribute("href")).toBe("/access");
  });

  it("renders exact single, range, and all port scopes in the inventory and detail", async () => {
    fqdnResources = [
      { id: "single", name: "Single", fqdn: "single.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 },
      { id: "range", name: "Range", fqdn: "range.example.com", protocol: "udp", port_low: 53, port_high: 55, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 },
      { id: "all", name: "All", fqdn: "all.example.com", protocol: "tcp", port_low: null, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 },
    ];
    page();
    expect(await screen.findByText("TCP port 443")).toBeTruthy();
    expect(screen.getByText("UDP ports 53–55")).toBeTruthy();
    expect(screen.getByText("TCP, all ports")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Range" }));
    expect((await screen.findAllByText("range.example.com")).length).toBeGreaterThan(1);
    expect(screen.getAllByText(/UDP ports 53–55/).length).toBeGreaterThan(1);
  });

  it("makes opt-in actionable and preserves an announced recovery path when a mutation fails", async () => {
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Enable enforcement" }));
    await waitFor(() => expect(vi.mocked(api.PUT)).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/fqdn-resources/setting", expect.objectContaining({ body: { enabled: true } })));

    fireEvent.click(screen.getByRole("button", { name: "Create FQDN resource" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Orders" } });
    fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "orders.internal.example.com" } });
    vi.mocked(api.POST).mockRejectedValueOnce(new Error("offline"));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    expect((await screen.findAllByRole("alert")).some((alert) => /changes were not confirmed; try again/i.test(alert.textContent ?? ""))).toBe(true);
    expect((within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("keeps edit and delete recovery available after PATCH and DELETE failures", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: null }];
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    vi.mocked(api.PATCH).mockRejectedValueOnce(new Error("offline"));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Save FQDN resource" }));
    await waitFor(() => expect(vi.mocked(api.PATCH)).toHaveBeenCalled());
    expect((screen.getByRole("button", { name: "Save FQDN resource" }) as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    impact = { resource_id: "fqdn-1", referencing_rule_count: 0, referencing_rule_ids: [], generation_withdrawal_required: false };
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await screen.findByText(/Server impact: 0 referencing rules/);
    vi.mocked(api.DELETE).mockRejectedValueOnce(new Error("offline"));
    fireEvent.click(screen.getByRole("button", { name: "Delete FQDN resource" }));
    await waitFor(() => expect(vi.mocked(api.DELETE)).toHaveBeenCalled());
    expect((screen.getByRole("button", { name: "Delete FQDN resource" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("states unavailable permissions and retries a failed inventory instead of claiming it is empty", async () => {
    role = "operator";
    page();
    expect((await screen.findAllByRole("alert")).some((alert) => alert.textContent?.includes("fqdn_resource:view"))).toBe(true);
    expect(screen.queryByRole("button", { name: "Create FQDN resource" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Enable enforcement" })).toBeNull();

    cleanup();
    role = "admin";
    resourceLoadError = "inventory down";
    page();
    expect((await screen.findAllByRole("alert")).some((alert) => /could not load FQDN resources/i.test(alert.textContent ?? ""))).toBe(true);
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
    expect(screen.queryByText(/No FQDN resources yet/)).toBeNull();
  });

  it("keeps resources readable but never presents an unavailable enforcement setting as disabled", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: null }];
    settingLoadError = "fqdn_resources feature is unavailable";

    page();
    expect(await screen.findByText("Orders")).toBeTruthy();
    expect(screen.getByText(/FQDN enforcement setting is unavailable/i)).toBeTruthy();
    expect(screen.queryByText(/Enforcement opt-in:.*not enabled/i)).toBeNull();
    expect(screen.queryByRole("button", { name: "Enable enforcement" })).toBeNull();
  });
});
