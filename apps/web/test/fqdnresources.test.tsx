import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let role = "admin";
let rows: Array<Record<string, unknown>> = [];
let cidrRows: Array<Record<string, unknown>> = [];
let resolverContext: Record<string, unknown> = {};
let connections: Array<Record<string, unknown>> = [];
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email_verified: true } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string) => {
    if (path.endsWith("/ipsec/connections")) return { data: { items: connections, next_cursor: null } };
    if (path.endsWith("/configuration")) return { data: { configuration_revision: 4 } };
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role }] };
    if (path.endsWith("/fqdn-resources/setting")) return { data: { enabled: false } };
    if (path.endsWith("/fqdn-resources")) return { data: rows };
    if (path.endsWith("/sites")) return { data: [{ id: "site-a", name: "Site A" }] };
    if (path.endsWith("/nodes")) return { data: [{ id: "gw-a", name: "Gateway A", site_id: "site-a", status: "active" }] };
    if (path.includes("/fqdn-resolver-contexts/")) return { data: resolverContext };
    if (path.endsWith("/resources")) return { data: cidrRows };
    return { data: [] };
  }), POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })), PUT: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })) } };
});
import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

function page(entry = "/access/resources") { return render(<MemoryRouter initialEntries={[entry]}><AccessResources /></MemoryRouter>); }
beforeEach(() => {
  role = "admin"; rows = []; cidrRows = []; connections = [];
  resolverContext = { id: "resolver-a", org_id: "org-a", site_id: "site-a", gateway_id: "gw-a", version: 1, state: "active", created_at: "2026-08-28T00:00:00Z", provider_hint: "aws", endpoints: [{ address: "10.0.0.53", port: 53, transport: "udp" }], profiles: [{ id: "profile-a", name: "Legacy resolver", provider_hint: "aws", zone_suffixes: [], endpoints: [{ address: "10.0.0.53", port: 53, transport: "udp" }], legacy_default: true }] };
  vi.mocked(api.POST).mockClear(); vi.mocked(api.PUT).mockClear();
});
afterEach(cleanup);

describe("FQDN resource operator index", () => {
  it("uses CIDR and FQDN tabs instead of a resource-type select", async () => {
    page();
    const cidrTab = await screen.findByRole("button", { name: "CIDR" });
    expect(cidrTab.getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("combobox", { name: "Resource type" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "FQDN" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "FQDN" }).getAttribute("aria-current")).toBe("page"));
    expect(await screen.findByRole("heading", { name: "Private DNS resolvers" })).toBeTruthy();
  });

  it("makes the one-time resolver setup discoverable from Resources and the FQDN empty state", async () => {
    page("/access/resources?type=fqdn");
    expect((await screen.findByRole("link", { name: "Private DNS resolvers" })).getAttribute("href")).toBe("/access/resources?type=fqdn#private-dns-heading");
    expect((await screen.findByRole("link", { name: "Configure private DNS resolver" })).getAttribute("href")).toBe("#private-dns-heading");
  });

  it("shows provider marks with text labels", async () => {
    page("/access/resources?type=fqdn");
    expect(await screen.findByText("Legacy resolver")).toBeTruthy();
    expect(screen.getByText("AWS").closest("article")?.querySelector("svg")).toBeTruthy();
    expect(screen.getByText("Configured")).toBeTruthy();
    expect(screen.queryByText("Active")).toBeNull();
  });

  it("uses Cloud DNS inbound server-policy guidance with the shared zone profile form", async () => {
    page("/access/resources?type=fqdn");
    fireEvent.click(await screen.findByRole("button", {name:"Edit profiles"}));
    const dialog=screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Profile 1 provider"),{target:{value:"google_cloud"}});
    expect(within(dialog).getByText(/Cloud DNS inbound server-policy IPs in the VPN region/)).toBeTruthy();
    expect(within(dialog).getByLabelText("Profile 1 DNS zone suffixes")).toBeTruthy();
    expect(within(dialog).queryByText(/Route 53 Resolver inbound endpoint/)).toBeNull();
    expect(screen.getByText(/DNS resolution does not grant application access/)).toBeTruthy();
  });

  it("activates named provider profiles and removes prototype-only behavior", async () => {
    page("/access/resources?type=fqdn");
    expect(await screen.findByRole("button", { name: "Edit profiles" })).toBeTruthy();
    expect(screen.queryByText("Review prototype — not active")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Edit profiles" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog.className).toContain("max-w-2xl");
    fireEvent.click(within(dialog).getByRole("button", { name: "Add endpoint" }));
    expect(within(dialog).getByRole("button", { name: "Remove profile 1 endpoint 1" })).toBeTruthy();
    expect(within(dialog).getByLabelText("Profile 1 endpoint 1 IP").parentElement?.className).toContain("minmax(0,1fr)");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove profile 1 endpoint 2" }));
    fireEvent.change(within(dialog).getByLabelText("Profile 1 DNS zone suffixes"), { target: { value: "internal.example.com" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Add provider profile" }));
    const names = within(dialog).getAllByLabelText("Profile name");
    fireEvent.change(names[1], { target: { value: "Azure private DNS" } });
    fireEvent.change(within(dialog).getByLabelText("Profile 2 provider"), { target: { value: "azure" } });
    fireEvent.change(within(dialog).getByLabelText("Profile 2 DNS zone suffixes"), { target: { value: "azure.internal.example.com" } });
    fireEvent.change(within(dialog).getByLabelText("Profile 2 endpoint 1 IP"), { target: { value: "10.63.0.53" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Activate profiles" }));
    await waitFor(() => expect(vi.mocked(api.PUT)).toHaveBeenCalled());
    const call = vi.mocked(api.PUT).mock.calls[0] as unknown as [string, { body: { profiles: Array<{ provider_hint: string; zone_suffixes: string[] }> } }];
    const body = call[1].body;
    expect(body.profiles).toHaveLength(2);
    expect(body.profiles[1]).toMatchObject({ provider_hint: "azure", zone_suffixes: ["azure.internal.example.com"] });
  });

  it("binds the current owned IPsec revision and documents separate office and WG proxy scope", async () => {
    connections = [
      { id: "ipsec-a", name: "AWS enabled", site_id: "site-a", gateway_node_id: "gw-a", desired_intent: "enabled", cleanup_state: "complete" },
      { id: "ipsec-disabled", name: "AWS disabled", site_id: "site-a", gateway_node_id: "gw-a", desired_intent: "disabled" },
      { id: "ipsec-other", name: "Other site", site_id: "site-b", gateway_node_id: "gw-b", desired_intent: "enabled" },
    ];
    page("/access/resources?type=fqdn");
    expect(await screen.findByText(/Existing office DNS:/)).toBeTruthy();
    expect(screen.getByText(/this does not expose a DNS listener to the office LAN/)).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: "Edit profiles" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Profile 1 DNS zone suffixes"), { target: { value: "private.example.test" } });
    fireEvent.change(within(dialog).getByLabelText("Profile 1 DNS transport path"), { target: { value: "ipsec" } });
    const picker = within(dialog).getByLabelText("Profile 1 IPsec connection");
    await within(picker).findByRole("option", { name: "AWS enabled" });
    expect(within(picker).queryByRole("option", { name: "AWS disabled" })).toBeNull();
    expect(within(picker).queryByRole("option", { name: "Other site" })).toBeNull();
    fireEvent.change(picker, { target: { value: "ipsec-a" } });
    fireEvent.change(within(dialog).getByLabelText("Profile 1 gateway DNS source IPv4"), { target: { value: "10.0.0.254" } });
    const activate = within(dialog).getByRole("button", { name: "Activate profiles" });
    await waitFor(() => expect((activate as HTMLButtonElement).disabled).toBe(false));
    expect((within(dialog).getByLabelText("Profile 1 endpoint 1 port") as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(activate);
    await waitFor(() => expect(vi.mocked(api.PUT)).toHaveBeenCalled());
    const call = vi.mocked(api.PUT).mock.calls[0] as unknown as [string, { body: { profiles: Array<{ ipsec_path: unknown }> } }];
    expect(call[1].body.profiles[0].ipsec_path).toEqual({ connection_id: "ipsec-a", configuration_revision: 4, source_address: "10.0.0.254" });
  });

  it("ignores a connection revision response from a cancelled DNS draft", async () => {
    connections = [{ id: "ipsec-a", name: "GCP enabled", site_id: "site-a", gateway_node_id: "gw-a", desired_intent: "enabled", cleanup_state: "complete" }];
    const original = vi.mocked(api.GET).getMockImplementation()!;
    let finishOld: (value: unknown) => void = () => {};
    let reads = 0;
    vi.mocked(api.GET).mockImplementation((async (path: string, options: unknown) => {
      if (path.endsWith("/configuration")) {
        if (++reads === 1) return await new Promise<unknown>(resolve => { finishOld = resolve; });
        return { data: { configuration_revision: 5 } };
      }
      return (original as unknown as (path: string, options: unknown) => Promise<unknown>)(path, options);
    }) as typeof api.GET);
    try {
      page("/access/resources?type=fqdn");
      async function configure() {
        fireEvent.click(await screen.findByRole("button", { name: "Edit profiles" }));
        const dialog = screen.getByRole("dialog");
        fireEvent.change(within(dialog).getByLabelText("Profile 1 DNS zone suffixes"), { target: { value: "private.example.test" } });
        fireEvent.change(within(dialog).getByLabelText("Profile 1 DNS transport path"), { target: { value: "ipsec" } });
        const picker = within(dialog).getByLabelText("Profile 1 IPsec connection");
        await within(picker).findByRole("option", { name: "GCP enabled" });
        fireEvent.change(picker, { target: { value: "ipsec-a" } });
        fireEvent.change(within(dialog).getByLabelText("Profile 1 gateway DNS source IPv4"), { target: { value: "10.0.0.254" } });
        return dialog;
      }
      const cancelled = await configure();
      fireEvent.click(within(cancelled).getByRole("button", { name: "Cancel" }));
      const current = await configure();
      const activate = within(current).getByRole("button", { name: "Activate profiles" });
      await waitFor(() => expect((activate as HTMLButtonElement).disabled).toBe(false));
      await act(async () => { finishOld({ data: { configuration_revision: 4 } }); });
      fireEvent.click(activate);
      await waitFor(() => expect(api.PUT).toHaveBeenCalled());
      const call = vi.mocked(api.PUT).mock.calls[0] as unknown as [string, { body: { profiles: Array<{ ipsec_path: { configuration_revision: number } }> } }];
      expect(call[1].body.profiles[0].ipsec_path.configuration_revision).toBe(5);
    } finally { vi.mocked(api.GET).mockImplementation(original); }
  });

  it("refuses a stored IPsec profile with a non-DNS port and keeps its port fixed", async () => {
    connections = [{ id: "ipsec-a", name: "AWS enabled", site_id: "site-a", gateway_node_id: "gw-a", desired_intent: "enabled", cleanup_state: "complete" }];
    resolverContext.profiles = [{ id: "profile-a", name: "AWS private DNS", provider_hint: "aws", zone_suffixes: ["private.example.test"], endpoints: [{ address: "10.0.0.53", port: 5353, transport: "udp" }], legacy_default: false, ipsec_path: { connection_id: "ipsec-a", configuration_revision: 4, source_address: "10.0.0.254" } }];
    page("/access/resources?type=fqdn");
    fireEvent.click(await screen.findByRole("button", { name: "Edit profiles" }));
    const dialog = screen.getByRole("dialog");
    await within(dialog).findByRole("option", { name: "AWS enabled" });
    expect((within(dialog).getByLabelText("Profile 1 endpoint 1 port") as HTMLInputElement).disabled).toBe(true);
    expect((within(dialog).getByRole("button", { name: "Activate profiles" }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(dialog).getByText(/UDP and TCP port 53/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Activate profiles" }));
    expect(vi.mocked(api.PUT)).not.toHaveBeenCalled();
  });

  it("retains custom resolver ports for a direct gateway path", async () => {
    page("/access/resources?type=fqdn");
    fireEvent.click(await screen.findByRole("button", { name: "Edit profiles" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Profile 1 DNS zone suffixes"), { target: { value: "private.example.test" } });
    const port = within(dialog).getByLabelText("Profile 1 endpoint 1 port") as HTMLInputElement;
    expect(port.disabled).toBe(false);
    fireEvent.change(port, { target: { value: "5353" } });
    expect((within(dialog).getByRole("button", { name: "Activate profiles" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(within(dialog).getByRole("button", { name: "Activate profiles" }));
    await waitFor(() => expect(vi.mocked(api.PUT)).toHaveBeenCalled());
    const call = vi.mocked(api.PUT).mock.calls[0] as unknown as [string, { body: { profiles: Array<{ endpoints: Array<{ port: number }>; ipsec_path?: unknown }> } }];
    expect(call[1].body.profiles[0].endpoints[0].port).toBe(5353);
    expect(call[1].body.profiles[0].ipsec_path).toBeUndefined();
  });

  it("previews parent and child profile precedence and disables unmatched creation", async () => {
    resolverContext = {
      id: "resolver-a", org_id: "org-a", site_id: "site-a", gateway_id: "gw-a", version: 3, state: "active", created_at: "2026-08-28T00:00:00Z", provider_hint: "aws",
      endpoints: [{ address: "10.53.0.53", port: 53, transport: "udp" }],
      profiles: [
        { id: "profile-aws", name: "AWS private DNS", provider_hint: "aws", zone_suffixes: ["internal.example.com"], endpoints: [{ address: "10.53.0.53", port: 53, transport: "udp" }], legacy_default: false },
        { id: "profile-azure", name: "Azure child zone", provider_hint: "azure", zone_suffixes: ["azure.internal.example.com"], endpoints: [{ address: "10.63.0.53", port: 53, transport: "udp" }], legacy_default: false },
      ],
    };
    page("/access/resources?type=fqdn");
    fireEvent.click(await screen.findByRole("button", { name: "Create resource" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^Create FQDN resource/ }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "Orders" } });
    const hostname = within(dialog).getByLabelText("Exact hostname");

    fireEvent.change(hostname, { target: { value: "orders.internal.example.com" } });
    expect(await within(dialog).findByText("AWS resolver selected automatically")).toBeTruthy();
    expect(within(dialog).getByText(/Profile AWS private DNS · matches internal\.example\.com/)).toBeTruthy();

    fireEvent.change(hostname, { target: { value: "orders.azure.internal.example.com" } });
    expect(await within(dialog).findByText("Microsoft Azure resolver selected automatically")).toBeTruthy();
    expect(within(dialog).getByText(/Profile Azure child zone · matches azure\.internal\.example\.com/)).toBeTruthy();

    fireEvent.change(hostname, { target: { value: "orders.unmatched.example.net" } });
    expect(await within(dialog).findByText("No resolver profile matches this hostname.")).toBeTruthy();
    expect(within(dialog).getByText(/Fail closed: no DNS request will be sent/)).toBeTruthy();
    expect((within(dialog).getByRole("button", { name: "Create resource" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("switches inventories and creates a resolver-bound single-port resource", async () => {
    cidrRows = [{ id: "cidr-1", name: "Private", cidr: "10.0.0.0/24", protocol: "any", port_low: null, port_high: null }];
    rows = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: 443, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 }];
    page("/access/resources?type=cidr");
    expect((await screen.findAllByText("Private")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("table", { name: "FQDN resources inventory" })).toBeNull();
    expect(screen.getAllByRole("button", { name: "Create resource" })).toHaveLength(1);

    cleanup(); page("/access/resources?type=fqdn");
    expect((await screen.findAllByText("Orders")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("table", { name: "Resources inventory" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Orders" }));
    expect(screen.getByRole("menuitem", { name: "Edit Orders" })).toBeTruthy();
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    expect(screen.queryByRole("button", { name: /Bind now|Enable/ })).toBeNull();
    expect(screen.getAllByRole("button", { name: "Create resource" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Create resource" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^Create FQDN resource/ }));
    expect(await screen.findByRole("group", { name: "Identity" })).toBeTruthy();
    expect(screen.getByRole("group", { name: "Access scope" })).toBeTruthy();
    expect(screen.getByRole("group", { name: "Private DNS path" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Orders" } });
    fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "orders.internal.example.com" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "single" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443" } });
    expect(await screen.findByText(/AWS resolver selected automatically/)).toBeTruthy();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create resource" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toEqual({ params: { path: { orgId: "org-a" } }, body: { name: "Orders", fqdn: "orders.internal.example.com", label: null, protocol: "tcp", port_low: 443, port_high: 443, resolver_context: { site_id: "site-a", gateway_id: "gw-a" }, expected_impact_token: null } });
  });
  it("names row actions and leaves member capability unavailable", async () => {
    rows = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 }];
    page("/access/resources?type=fqdn");
    fireEvent.click(await screen.findByRole("button", { name: "Actions for Orders" }));
    expect(screen.getByRole("menuitem", { name: "Delete Orders" })).toBeTruthy();
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    expect(screen.getByLabelText("FQDN status")).toBeTruthy();
    cleanup(); role = "member"; page("/access/resources?type=fqdn");
    expect(await screen.findByText(/fqdn_resource:view/)).toBeTruthy();
  });
});
