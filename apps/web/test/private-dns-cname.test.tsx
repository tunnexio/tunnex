import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { FQDNResolverContextConfig, FQDNResolverProfile } from "../src/lib/api";

const mocks = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "admin", email_verified: true } } }) }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: { GET: mocks.get, PUT: mocks.put } }));
import { PrivateDNSResolvers } from "../src/components/PrivateDNSResolvers";
import { defaultCNAMEUpstreams, validCNAMEUpstreams } from "../src/components/PrivateDNSCNAMEUpstreams";

let saved: FQDNResolverContextConfig | null;
const profile = (overrides: Partial<FQDNResolverProfile> = {}): FQDNResolverProfile => ({
  id: "profile-a", name: "Office DNS", provider_hint: "on_premises", zone_suffixes: ["office.example"], endpoints: [], legacy_default: false,
  static_records: [{ name: "app.office.example", type: "CNAME", value: "lb.example.net", ttl: 300 }], ...overrides,
});
function setSaved(value: FQDNResolverProfile) {
  saved = { id: "dns-a", org_id: "org-a", site_id: "site-a", gateway_id: "gw-a", version: 1, state: "active", created_at: "2026-10-15T00:00:00Z", profiles: [value] } as FQDNResolverContextConfig;
}
function view(scope = { siteId: "site-a", gatewayId: "gw-a" }) { return <PrivateDNSResolvers orgId="org-a" role="admin" scope={scope} />; }
async function editor() {
  fireEvent.click(await screen.findByRole("button", { name: saved ? "Edit profiles" : "Configure profiles" }));
  return within(screen.getByRole("dialog"));
}
beforeEach(() => {
  saved = null; vi.clearAllMocks();
  mocks.get.mockImplementation(async (path: string) => {
    if (path.endsWith("/sites")) return { data: [{ id: "other", name: "Other network" }, { id: "site-a", name: "Office" }, { id: "site-b", name: "Branch" }] };
    if (path.endsWith("/nodes")) return { data: [{ id: "other-gw", name: "Other gateway", site_id: "other", status: "active" }, { id: "gw-a", name: "Office gateway", site_id: "site-a", status: "active" }, { id: "gw-b", name: "Branch gateway", site_id: "site-b", status: "active" }] };
    if (path.endsWith("/ipsec/connections")) return { data: { items: [], next_cursor: null } };
    if (path.includes("/fqdn-resolver-contexts/")) return saved ? { data: saved } : { error: { error: { code: "fqdn_resolver_config_not_found" } } };
    return { data: [] };
  });
  mocks.put.mockImplementation(async (_path, request) => {
    saved = { id: "dns-a", org_id: "org-a", site_id: "site-a", gateway_id: "gw-a", version: 2, state: "active", created_at: "2026-10-15T00:00:00Z", profiles: request.body.profiles.map((item: object, index: number) => ({ ...item, id: `profile-${index}`, legacy_default: false })) } as FQDNResolverContextConfig;
    return { data: saved };
  });
});
afterEach(cleanup);

it("accepts ordinary defaults and rejects malformed or duplicate target upstreams", () => {
  expect(validCNAMEUpstreams(defaultCNAMEUpstreams())).toBe(true);
  for (const address of ["01.1.1.1", "256.1.1.1", "1.1.1", "", "dns.example"]) expect(validCNAMEUpstreams([{ address, port: 53, transport: "udp" }])).toBe(false);
  expect(validCNAMEUpstreams([...defaultCNAMEUpstreams(), defaultCNAMEUpstreams()[0]])).toBe(false);
  expect(validCNAMEUpstreams([defaultCNAMEUpstreams()[0], { ...defaultCNAMEUpstreams()[0], transport: "tcp" }])).toBe(false);
  expect(validCNAMEUpstreams([{ address: "1.1.1.1", port: 5353, transport: "udp" }])).toBe(false);
});

it("creates records first with exact hostname scope and visible editable CNAME defaults, then reads back persisted values", async () => {
  render(view()); const dialog = await editor();
  expect((dialog.getByLabelText("Profile name") as HTMLInputElement).value).toBe("Office DNS");
  expect((dialog.getByLabelText("Profile 1 DNS setup") as HTMLSelectElement).value).toBe("static");
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 name"), { target: { value: "app.office.example" } });
  fireEvent.blur(dialog.getByLabelText("Profile 1 record 1 name"));
  expect((dialog.getByLabelText("Profile 1 DNS zone suffixes") as HTMLInputElement).value).toBe("app.office.example");
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 type"), { target: { value: "CNAME" } });
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 value"), { target: { value: "lb.example.net" } });
  expect(dialog.getByText(/Normal DNS upstreams: 1.1.1.1, 8.8.8.8/)).toBeTruthy();
  fireEvent.click(dialog.getByText("Advanced target DNS settings"));
  fireEvent.change(dialog.getByLabelText("Profile 1 CNAME upstream 1 IP"), { target: { value: "9.9.9.9" } });
  fireEvent.change(dialog.getByLabelText("Profile 1 CNAME upstream 1 transport"), { target: { value: "tcp" } });
  fireEvent.click(dialog.getByRole("button", { name: "Activate profiles" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  const request = mocks.put.mock.calls[0][1];
  expect(request.params.path).toEqual({ orgId: "org-a", siteId: "site-a", gatewayId: "gw-a" });
  expect(request.body.profiles[0]).toMatchObject({ name: "Office DNS", zone_suffixes: ["app.office.example"], endpoints: [{ address: "9.9.9.9", port: 53, transport: "tcp" }, { address: "8.8.8.8", port: 53, transport: "udp" }] });
  expect(request.body.profiles[0]).not.toHaveProperty("ipsec_path");
  expect(request.body.profiles[0]).not.toHaveProperty("cnameDefaultsEligible");
  expect(request.body.profiles[0]).not.toHaveProperty("suggestZone");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.getByText(/External CNAME lookup uses the normal DNS upstreams/)).toBeTruthy();
  const edit = await editor();
  fireEvent.click(edit.getByText("Advanced target DNS settings"));
  expect((edit.getByLabelText("Profile 1 CNAME upstream 1 IP") as HTMLInputElement).value).toBe("9.9.9.9");
});

it("A-only records need no upstream and an explicitly edited scope is never replaced", async () => {
  render(view()); const dialog = await editor();
  fireEvent.change(dialog.getByLabelText("Profile 1 DNS zone suffixes"), { target: { value: "office.example" } });
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 name"), { target: { value: "app.office.example" } });
  fireEvent.blur(dialog.getByLabelText("Profile 1 record 1 name"));
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 value"), { target: { value: "10.20.1.10" } });
  expect(dialog.queryByText("CNAME target lookup")).toBeNull();
  fireEvent.click(dialog.getByRole("button", { name: "Activate profiles" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  expect(mocks.put.mock.calls[0][1].body.profiles[0]).toMatchObject({ zone_suffixes: ["office.example"], endpoints: [], static_records: [{ type: "A", value: "10.20.1.10", ttl: 300 }] });
});

it("opening and editing a saved legacy alias does not opt it into external lookups", async () => {
  setSaved(profile()); render(view()); const dialog = await editor();
  expect(dialog.getByText(/Alias only:/)).toBeTruthy();
  fireEvent.change(dialog.getByLabelText("Profile name"), { target: { value: "Renamed DNS" } });
  fireEvent.blur(dialog.getByLabelText("Profile 1 record 1 name"));
  fireEvent.click(dialog.getByRole("button", { name: "Activate profiles" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  expect(mocks.put.mock.calls[0][1].body.profiles[0]).toMatchObject({ endpoints: [], zone_suffixes: ["office.example"] });
});

it("legacy aliases can explicitly enable, edit and disable target lookup without reappearing on another edit", async () => {
  setSaved(profile()); render(view()); const dialog = await editor();
  fireEvent.click(dialog.getByText("Advanced target DNS settings"));
  fireEvent.click(dialog.getByLabelText("Profile 1 resolve external CNAME targets"));
  expect((dialog.getByLabelText("Profile 1 CNAME upstream 1 IP") as HTMLInputElement).value).toBe("1.1.1.1");
  fireEvent.change(dialog.getByLabelText("Profile 1 CNAME upstream 1 IP"), { target: { value: "" } });
  expect((dialog.getByRole("button", { name: "Activate profiles" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(dialog.getByLabelText("Profile 1 resolve external CNAME targets"));
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 value"), { target: { value: "other-lb.example.net" } });
  fireEvent.click(dialog.getByRole("button", { name: "Activate profiles" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  expect(mocks.put.mock.calls[0][1].body.profiles[0].endpoints).toEqual([]);
});

it("switching to forwarding clears target upstreams and switching back clears resolver binding", async () => {
  setSaved(profile({ endpoints: defaultCNAMEUpstreams() })); render(view()); const dialog = await editor();
  fireEvent.change(dialog.getByLabelText("Profile 1 DNS setup"), { target: { value: "ipsec" } });
  expect((dialog.getByLabelText("Profile 1 endpoint 1 IP") as HTMLInputElement).value).toBe("");
  expect(dialog.getByLabelText("Profile 1 IPsec connection")).toBeTruthy();
  fireEvent.change(dialog.getByLabelText("Profile 1 DNS setup"), { target: { value: "direct" } });
  expect(dialog.queryByLabelText("Profile 1 IPsec connection")).toBeNull();
  fireEvent.change(dialog.getByLabelText("Profile 1 endpoint 1 IP"), { target: { value: "10.0.0.53" } });
  fireEvent.change(dialog.getByLabelText("Profile 1 DNS setup"), { target: { value: "static" } });
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 name"), { target: { value: "app.office.example" } });
  fireEvent.change(dialog.getByLabelText("Profile 1 record 1 value"), { target: { value: "10.20.1.10" } });
  fireEvent.click(dialog.getByRole("button", { name: "Activate profiles" }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  expect(mocks.put.mock.calls[0][1].body.profiles[0]).toMatchObject({ endpoints: [] });
  expect(mocks.put.mock.calls[0][1].body.profiles[0].ipsec_path).toBeUndefined();
});

it("changing contextual network discards its draft and never selects another network when its gateway is missing", async () => {
  const mounted = render(view()); await editor();
  mounted.rerender(view({ siteId: "site-b", gatewayId: "gw-b" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await screen.findByRole("button", { name: "Configure profiles" });
  expect((screen.getByLabelText("Site") as HTMLSelectElement).value).toBe("site-b");
  expect((screen.getByLabelText("Gateway") as HTMLSelectElement).value).toBe("gw-b");
  expect((screen.getByLabelText("Gateway") as HTMLSelectElement).disabled).toBe(true);
  mounted.rerender(view({ siteId: "site-b", gatewayId: "missing" }));
  await screen.findByText(/DNS requires a current gateway assigned to this network/);
  expect(screen.queryByRole("button", { name: "Configure profiles" })).toBeNull();
  expect(mocks.put).not.toHaveBeenCalled();
});
