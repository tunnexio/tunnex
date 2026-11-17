import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { FQDNResolverContextConfig, Node, PolicyRule, Site } from "../src/lib/api";
import { hostnameDNSPlan, type HostnameRecord, type HostnameResource } from "../src/lib/hostnameAccess";

const mocks = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: { GET: mocks.get, PUT: mocks.put, POST: mocks.post } }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "admin", email_verified: true } } }) }));
import { HostnameAccessDialog } from "../src/components/HostnameAccessDialog";
import { PrivateDNSResolvers } from "../src/components/PrivateDNSResolvers";

const site = { id: "site-a", name: "Office" } as Site;
const gateway = { id: "gw-a", name: "Office gateway", site_id: "site-a", status: "active" } as Node;
const record: HostnameRecord = { name: "app.office.example", type: "CNAME", value: "lb.example.net", ttl: 300 };
const connection = { id: "connection-a", name: "AWS production", site_id: "site-a", gateway_node_id: "gw-a", desired_intent: "enabled", cleanup_state: "not_required", deleted_at: null, finalized_at: null };
const provider = { profile_id: "aws-bgp-ipv4-v1", configuration_revision: 1, configuration: { mode: "ipv4-bgp", remote_prefixes: ["10.20.0.0/16"] } };
let dns: FQDNResolverContextConfig | null;
let resources: HostnameResource[], policies: PolicyRule[], supported: boolean, staticSupported: boolean | undefined;
let currentProvider: typeof provider;
const onClose = vi.fn(), onSaved = vi.fn();
const profile = (id: string, zone: string, records: HostnameRecord[]) => ({ id, name: id, provider_hint: "on_premises" as const, zone_suffixes: [zone], endpoints: [{ address: "9.9.9.9", port: 53, transport: "udp" as const }], static_records: records, legacy_default: false });
function resolverConfig() {
  return { id: "dns-a", version: 1, site_id: "site-a", gateway_id: "gw-a", profiles: [profile("profile-a", "office.example", [record])] } as FQDNResolverContextConfig;
}
function mounted(savedRecord?: HostnameRecord) {
  return render(<MemoryRouter><HostnameAccessDialog orgId="org-a" role="admin" site={site} gateway={gateway} connectionId="connection-a" record={savedRecord} onClose={onClose} onSaved={onSaved} /></MemoryRouter>);
}
async function person(name = "Rajan") {
  const picker = screen.getByRole("combobox", { name: "Users and groups" });
  fireEvent.click(picker);
  fireEvent.click(within(screen.getByRole("listbox", { name: "Users and groups" })).getByRole("button", { name: new RegExp(name) }));
}
async function fill() {
  await screen.findByText(/Gateway supports desktop hostname access/);
  await screen.findByText(/Approved application ranges/);
  fireEvent.change(screen.getByLabelText("Private hostname"), { target: { value: record.name } });
  fireEvent.change(screen.getByLabelText("Target hostname"), { target: { value: record.value } });
  await person();
}
beforeEach(() => {
  vi.clearAllMocks(); dns = null; resources = []; policies = []; supported = true; staticSupported = undefined; currentProvider = provider;
  mocks.get.mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "rajan", name: "Rajan", email: "rajan@example.com", status: "active" }, { user_id: "removed", name: "Removed user", email: "removed@example.com", status: "deactivated" }] };
    if (path.endsWith("/groups")) return { data: [{ id: "engineering", name: "Engineering" }] };
    if (path.endsWith("/sites")) return { data: [site] };
    if (path.endsWith("/nodes")) return { data: [gateway] };
    if (path.endsWith("/eligibility")) return { data: { eligible: true, reason: "eligible", desktop_fqdn_supported: supported, desktop_static_fqdn_supported: staticSupported } };
    if (path.endsWith("/setting")) return { data: { enabled: true } };
    if (path.endsWith("/zero-trust-mode")) return { data: { mode: "enforcing" } };
    if (path.endsWith("/ipsec/connections")) return { data: { items: [connection], next_cursor: null } };
    if (path.endsWith("/ipsec/connections/{connectionId}")) return { data: connection };
    if (path.endsWith("/configuration")) return { data: currentProvider };
    if (path.includes("/fqdn-resolver-contexts/")) return dns ? { data: dns } : { error: { error: { code: "fqdn_resolver_config_not_found" } } };
    if (path.endsWith("/fqdn-resources")) return { data: resources };
    if (path.endsWith("/policies")) return { data: policies };
    return { data: [] };
  });
  mocks.put.mockImplementation(async (_path, request) => {
    dns = { id: "dns-a", version: 2, site_id: "site-a", gateway_id: "gw-a", profiles: request.body.profiles.map((item: object, index: number) => ({ ...item, id: `profile-${index}` })) } as FQDNResolverContextConfig;
    return { data: dns };
  });
  mocks.post.mockImplementation(async (path: string, request) => {
    if (path.endsWith("/fqdn-resources")) {
      const value = { id: "resource-a", ...request.body, state: "resolving", answer_count: 0 } as HostnameResource;
      resources.push(value); return { data: value };
    }
    if (path.endsWith("/policies")) { const value = { id: `rule-${policies.length}`, ...request.body, enabled: true } as PolicyRule; policies.push(value); return { data: value }; }
    return { error: { error: { message: "Unexpected write" } } };
  });
});
afterEach(cleanup);

it("saves a scoped CNAME, TCP 443 resource and explicit user/group rules in one drawer", async () => {
  mounted(); await fill(); await person("Engineering");
  expect((screen.getByLabelText("Connection") as HTMLSelectElement).disabled).toBe(true);
  expect((screen.getByLabelText("Service port") as HTMLInputElement).value).toBe("443");
  expect(screen.getByText(/Other hostnames sharing the same load balancer IP/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText("DNS, hostname resource and access rules saved.");
  expect(mocks.put).toHaveBeenCalledTimes(1);
  expect(dns?.profiles?.[0]).toMatchObject({ zone_suffixes: [record.name], static_records: [record], endpoints: [{ address: "1.1.1.1", port: 53, transport: "udp" }, { address: "8.8.8.8", port: 53, transport: "udp" }] });
  expect(dns?.profiles?.[0]).not.toHaveProperty("ipsec_path");
  expect(resources[0]).toMatchObject({ protocol: "tcp", port_low: 443, port_high: 443, resolver_context: { site_id: "site-a", gateway_id: "gw-a" }, application_ipsec_path: { connection_id: "connection-a", configuration_revision: 1 } });
  expect(policies).toEqual([expect.objectContaining({ src_kind: "user", src_user_id: "rajan", dst_kind: "fqdn_resource", dst_fqdn_resource_id: "resource-a" }), expect.objectContaining({ src_kind: "group", src_group_id: "engineering", dst_kind: "fqdn_resource", dst_fqdn_resource_id: "resource-a" })]);
  expect(screen.getByText(/Saved rules still require fresh DNS answers/)).toBeTruthy();
  expect(screen.getByText("resolving")).toBeTruthy();
});

it("saves AWS static hostname access only with static support and explains both cloud return paths", async () => {
  currentProvider = { ...provider, profile_id: "aws-static-ipv4-v1", configuration: { ...provider.configuration, mode: "ipv4-static" } };
  supported = false; staticSupported = true;
  mounted(); await fill();
  expect(screen.getByText(/assigned VPN IPv4 address as a \/32/)).toBeTruthy();
  expect(screen.getByText(/VGW: add the \/32/)).toBeTruthy();
  expect(screen.getByText(/TGW: route the \/32/)).toBeTruthy();
  expect(screen.getByRole("link", { name: "Devices" }).getAttribute("href")).toBe("/devices");
  fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText("DNS, hostname resource and access rules saved.");
  expect(resources[0]).toMatchObject({ application_ipsec_path: { connection_id: "connection-a", configuration_revision: 1 }, protocol: "tcp", port_low: 443, port_high: 443 });
  expect(policies).toEqual([expect.objectContaining({ src_kind: "user", src_user_id: "rajan", dst_kind: "fqdn_resource" })]);
});

it.each([false, undefined])("blocks AWS static hostname access when its capability is %s even with BGP support", async value => {
  currentProvider = { ...provider, profile_id: "aws-static-ipv4-v1", configuration: { ...provider.configuration, mode: "ipv4-static" } };
  staticSupported = value;
  mounted();
  await screen.findByText(/has not reported current hostname-access support for AWS static routing/);
  expect((screen.getByRole("button", { name: "Save hostname access" }) as HTMLButtonElement).disabled).toBe(true);
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it.each(["gcp-classic-static-ipv4-v1", "azure-active-active-static-ipv4-v1", "azure-active-active-bgp-ipv4-v1"])("keeps %s outside desktop hostname access", async profileId => {
  staticSupported = true;
  currentProvider = { ...provider, profile_id: profileId, configuration: { ...provider.configuration, mode: profileId.includes("-static-") ? "ipv4-static" : "ipv4-bgp" } };
  mounted(); await screen.findByText(/requires an AWS BGP or AWS static connection/);
  expect((screen.getByRole("button", { name: "Save hostname access" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.queryByText(/assigned VPN IPv4 address as a \/32/)).toBeNull();
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("rechecks static hostname capability before changing DNS", async () => {
  currentProvider = { ...provider, profile_id: "aws-static-ipv4-v1", configuration: { ...provider.configuration, mode: "ipv4-static" } };
  staticSupported = true; mounted(); await fill(); staticSupported = false;
  fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText(/has not reported current hostname-access support for AWS static routing/);
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("refuses a different AWS routing profile at save instead of reusing its initial capability", async () => {
  currentProvider = { ...provider, profile_id: "aws-static-ipv4-v1", configuration: { ...provider.configuration, mode: "ipv4-static" } };
  supported = false; staticSupported = true; mounted(); await fill(); currentProvider = provider;
  fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText(/The connection configuration changed/);
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("refuses mismatched AWS static profile and BGP mode", async () => {
  currentProvider = { ...provider, profile_id: "aws-static-ipv4-v1" }; staticSupported = true;
  mounted(); await screen.findByText(/requires an AWS BGP or AWS static connection/);
  expect((screen.getByRole("button", { name: "Save hostname access" }) as HTMLButtonElement).disabled).toBe(true);
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("exposes Grant access beside saved records and prefills its connection context", async () => {
  dns = resolverConfig();
  render(<MemoryRouter><PrivateDNSResolvers orgId="org-a" role="admin" scope={{ siteId: "site-a", gatewayId: "gw-a", connectionId: "connection-a" }} /></MemoryRouter>);
  fireEvent.click(await screen.findByRole("button", { name: `Grant access to ${record.name}` }));
  await screen.findByText(/Approved application ranges/);
  expect((screen.getByLabelText("Private hostname") as HTMLInputElement).value).toBe(record.name);
  expect((screen.getByLabelText("Target hostname") as HTMLInputElement).value).toBe(record.value);
  await person(); fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText("DNS, hostname resource and access rules saved.");
  expect(mocks.put).not.toHaveBeenCalled();
});

it("continues a confirmed partial save without duplicating DNS, resource or completed grants", async () => {
  const post = mocks.post.getMockImplementation()!; let failed = false;
  mocks.post.mockImplementation(async (path, request) => {
    if (path.endsWith("/policies") && request.body.src_kind === "group" && !failed) { failed = true; return { error: { error: { message: "Temporary group grant error" } } }; }
    return post(path, request);
  });
  mounted(); await fill(); await person("Engineering"); fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText("Temporary group grant error");
  expect(resources).toHaveLength(1); expect(policies).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Continue saving" }));
  await screen.findByText("DNS, hostname resource and access rules saved.");
  expect(mocks.put).toHaveBeenCalledTimes(1); expect(resources).toHaveLength(1); expect(policies).toHaveLength(2);
  expect(mocks.post.mock.calls.filter(([path]) => path.endsWith("/fqdn-resources"))).toHaveLength(1);
});

it("reuses an exact bound resource and current rule, without changing its scope", async () => {
  dns = resolverConfig();
  resources = [{ id: "existing-resource", fqdn: record.name, protocol: "tcp", port_low: 443, port_high: 443, resolver_context: { site_id: "site-a", gateway_id: "gw-a" }, application_ipsec_path: { connection_id: "connection-a", configuration_revision: 1 }, state: "healthy", answer_count: 2 } as HostnameResource];
  policies = [{ id: "existing-rule", src_kind: "user", src_user_id: "rajan", dst_kind: "fqdn_resource", dst_fqdn_resource_id: "existing-resource", enabled: true } as PolicyRule];
  mounted(record); await fill(); fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText("DNS, hostname resource and access rules saved.");
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("shows disabled enforcement as pending and never enables organization settings on save", async () => {
  const get = mocks.get.getMockImplementation()!;
  mocks.get.mockImplementation((path, request) => path.endsWith("/setting") ? Promise.resolve({ data: { enabled: false } }) : path.endsWith("/zero-trust-mode") ? Promise.resolve({ data: { mode: "off" } }) : get(path, request));
  mounted(); await fill(); fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText(/Access is pending: enable both/);
  expect(mocks.put.mock.calls.every(([path]) => path.includes("/fqdn-resolver-contexts/"))).toBe(true);
});

it("stops an ambiguous resource POST instead of offering a duplicate retry", async () => {
  mocks.post.mockResolvedValue({}); mounted(); await fill(); fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText(/The resource save was not confirmed/);
  expect((screen.getByRole("button", { name: "Continue saving" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("link", { name: "Review saved resources before retrying" })).toBeTruthy();
  expect(mocks.post).toHaveBeenCalledTimes(1);
});

it("blocks unsupported gateways and refuses stale connection revisions before DNS writes", async () => {
  supported = false; const first = mounted(); await screen.findByText(/This gateway has not reported current hostname-access support/);
  expect((screen.getByRole("button", { name: "Save hostname access" }) as HTMLButtonElement).disabled).toBe(true); first.unmount();
  supported = true; mounted(); await fill();
  const get = mocks.get.getMockImplementation()!;
  mocks.get.mockImplementation((path, request) => path.endsWith("/configuration") ? Promise.resolve({ data: { ...provider, configuration_revision: 2 } }) : get(path, request));
  fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText(/The connection configuration changed/);
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("does not continue into resource or policy writes after the scoped editor unmounts", async () => {
  let finish!: (value: unknown) => void;
  mocks.put.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const view = mounted(); await fill(); fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1)); view.unmount();
  finish({ data: { id: "dns-a" } }); await new Promise(resolve => setTimeout(resolve, 0));
  expect(mocks.post).not.toHaveBeenCalled();
});

it("rechecks connection intent at save and leaves DNS unchanged after disablement", async () => {
  mounted(); await fill(); const get = mocks.get.getMockImplementation()!;
  mocks.get.mockImplementation((path, request) => path.endsWith("/ipsec/connections/{connectionId}") ? Promise.resolve({ data: { ...connection, desired_intent: "disabled" } }) : get(path, request));
  fireEvent.click(screen.getByRole("button", { name: "Save hostname access" }));
  await screen.findByText(/This connection is no longer enabled/);
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("keeps A records in the DNS editor without offering unsupported application binding", async () => {
  dns = resolverConfig(); dns.profiles![0].static_records = [{ ...record, type: "A", value: "10.20.1.5" }];
  render(<MemoryRouter><PrivateDNSResolvers orgId="org-a" role="admin" scope={{ siteId: "site-a", gatewayId: "gw-a", connectionId: "connection-a" }} /></MemoryRouter>);
  await screen.findByText(/app.office.example A 10.20.1.5/);
  expect(screen.queryByRole("button", { name: `Grant access to ${record.name}` })).toBeNull();
  expect(screen.getByRole("button", { name: "Edit profiles" })).toBeTruthy();
});

it("shows an existing profile's real upstreams and keeps alias-only prerequisites actionable", async () => {
  dns = resolverConfig(); const first = mounted(record); await fill();
  expect(screen.getByText(/Target DNS servers: 9.9.9.9/)).toBeTruthy();
  expect(screen.queryByText(/Normal DNS upstreams: 1.1.1.1/)).toBeNull(); first.unmount();
  dns.profiles![0].endpoints = [];
  render(<MemoryRouter><PrivateDNSResolvers orgId="org-a" role="admin" scope={{ siteId: "site-a", gatewayId: "gw-a", connectionId: "connection-a" }} /></MemoryRouter>);
  fireEvent.click(await screen.findByRole("button", { name: `Grant access to ${record.name}` }));
  await screen.findByText(/This flow needs managed CNAME records with target lookup enabled/);
  expect((screen.getByRole("button", { name: "Save hostname access" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Edit DNS profile" }));
  expect(await screen.findByRole("dialog", { name: "Activate new DNS profile version" })).toBeTruthy();
  expect(mocks.put).not.toHaveBeenCalled(); expect(mocks.post).not.toHaveBeenCalled();
});

it("preserves unrelated records, profiles, upstreams and LAN listener when editing a saved record", () => {
  const config = resolverConfig(); const another = { name: "db.office.example", type: "A" as const, value: "10.20.1.5", ttl: 60 };
  config.profiles![0].static_records!.push(another);
  config.profiles![0].lan_listener = { address: "10.1.0.1", interface: "eth0", allowed_sources: ["10.1.0.0/24"] };
  config.profiles!.push(profile("other-profile", "branch.example", [{ ...another, name: "db.branch.example" }]));
  const original = structuredClone(config);
  const plan = hostnameDNSPlan(config, { ...record, value: "new-lb.example.net" }, [], record)!;
  expect(config).toEqual(original); expect(plan[0].static_records).toEqual([{ ...record, value: "new-lb.example.net" }, another]);
  expect(plan[0].endpoints).toEqual(original.profiles![0].endpoints); expect(plan[0].lan_listener).toEqual(original.profiles![0].lan_listener);
  expect(plan[1]).toEqual(expect.objectContaining({ name: "other-profile", static_records: original.profiles![1].static_records }));
  expect(plan[0]).not.toHaveProperty("id"); expect(plan[0]).not.toHaveProperty("ipsec_path");
  expect(() => hostnameDNSPlan(config, { ...record, value: "new-lb.example.net" }, [], { ...record, value: "stale-lb.example.net" })).toThrow(/record changed/);
  expect(() => hostnameDNSPlan(config, { ...record, value: "new-lb.example.net" }, [])).toThrow(/already has DNS records/);
});

it("refuses to replace a forwarding profile with a static record", () => {
  const config = resolverConfig(); delete config.profiles![0].static_records;
  config.profiles![0].ipsec_path = { connection_id: "dns-connection", configuration_revision: 1, source_address: "10.1.0.1" };
  expect(() => hostnameDNSPlan(config, record, [])).toThrow(/forwarded DNS zone/);
});
