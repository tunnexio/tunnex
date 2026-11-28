import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIInternalEndpointSettings } from "../src/components/AIInternalEndpointSettings";

const mock = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), DELETE: vi.fn(), success: vi.fn() }));
vi.mock("../src/lib/api", async (importOriginal) => ({ ...await importOriginal<typeof import("../src/lib/api")>(), api: { GET: mock.GET, PUT: mock.PUT, DELETE: mock.DELETE } }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: mock.success, error: vi.fn() } }));

const settingsPath = "/api/v1/organizations/{orgId}/ai-gateway/static-key-settings";
const endpointPath = "/api/v1/organizations/{orgId}/ai-gateway/internal-endpoints/{nodeId}";
const ready = { node_id: "node-1", node_name: "gw-east", tunnel_address: "100.64.0.1", has_site: true, supported: true, ready: true, url: "https://100.64.0.1:9443", certificate_not_after: "2026-12-20T00:00:00Z",
  endpoint: { id: "ep", enabled: true, listen_addresses: ["100.64.0.1"], port: 9443, source_cidrs: ["10.20.0.0/16"], tls_mode: "tunnex_ca", revision: 2, updated_at: "2026-11-01T00:00:00Z" } };
const fresh = { node_id: "node-2", node_name: "gw-west", tunnel_address: "100.64.0.2", has_site: false, supported: true, ready: false };
const old = { node_id: "node-3", node_name: "gw-old", tunnel_address: "100.64.0.3", has_site: false, supported: false, ready: false };
let publicAllowed = false;
beforeEach(() => {
  vi.clearAllMocks(); publicAllowed = false;
  mock.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("internal-endpoints") ? { items: [ready, fresh, old] } : path === settingsPath ? { public_static_keys_allowed: publicAllowed } : {} }));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

async function show(canEdit = true) {
  render(<AIInternalEndpointSettings orgId="org" canEdit={canEdit} />);
  return within(await screen.findByRole("table", { name: "Internal AI endpoint by gateway" }));
}

describe("Internal AI endpoint settings", () => {
  it("shows one row per gateway with status, and the upgrade message for an old gateway", async () => {
    const table = await show();
    const [, east, west, gwOld] = table.getAllByRole("row");
    expect(within(east).getByText("Ready")).toBeTruthy();
    expect(within(east).getByText("https://100.64.0.1:9443")).toBeTruthy();
    expect(within(east).getByText("Tunnex private CA")).toBeTruthy();
    expect(within(west).getByText("Not set up")).toBeTruthy();
    expect(within(gwOld).getByText("Upgrade this gateway to use the internal AI endpoint")).toBeTruthy();
    expect(within(gwOld).queryByRole("button", { name: /Actions for internal AI endpoint/ })).toBeNull();
  });

  it("sets up an endpoint with the tunnel address, warns about the firewall, and sends revision 0", async () => {
    mock.PUT.mockResolvedValue({ data: { ...fresh }, response: new Response(null, { status: 200 }) });
    await show();
    fireEvent.click(screen.getByRole("button", { name: "Actions for internal AI endpoint on gw-west" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Set up endpoint" }));
    const modal = within(await screen.findByRole("dialog", { name: "Internal AI endpoint on gw-west" }));
    expect((modal.getByRole("checkbox", { name: /Tunnel address/ }) as HTMLInputElement).checked).toBe(true);
    expect(modal.getByText(/not part of a site/)).toBeTruthy();
    expect(modal.getByText(/every caller behind it looks the same/)).toBeTruthy();
    expect(modal.getByText("Open TCP 9443 from these ranges in your firewall. Traffic to this port is not covered by access rules.")).toBeTruthy();
    expect(modal.getByText(/\/var\/lib\/tunnex-node\/ai-internal\//)).toBeTruthy();
    const save = modal.getByRole("button", { name: "Save endpoint" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(modal.getByLabelText("Source ranges"), { target: { value: "10.20.0.0/16" } });
    fireEvent.change(modal.getByLabelText("Port"), { target: { value: "8443" } });
    expect(modal.getByText(/Open TCP 8443 from these ranges/)).toBeTruthy();
    fireEvent.click(save);
    await waitFor(() => expect(mock.PUT).toHaveBeenCalledWith(endpointPath, { params: { path: { orgId: "org", nodeId: "node-2" } }, body: { enabled: true, listen_addresses: ["100.64.0.2"], port: 8443, dns_name: null, source_cidrs: ["10.20.0.0/16"], tls_mode: "tunnex_ca", expected_revision: 0 } }));
    await waitFor(() => expect(mock.success).toHaveBeenCalledWith("Internal AI endpoint saved"));
  });

  it("explains an unsupported gateway refusal", async () => {
    mock.PUT.mockResolvedValue({ error: { error: { code: "ai_internal_endpoint_unsupported", message: "x" } }, response: new Response(null, { status: 409 }) });
    await show();
    fireEvent.click(screen.getByRole("button", { name: "Actions for internal AI endpoint on gw-east" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Edit endpoint" }));
    const modal = within(await screen.findByRole("dialog", { name: "Internal AI endpoint on gw-east" }));
    fireEvent.click(modal.getByRole("button", { name: "Save endpoint" }));
    expect((await modal.findByRole("alert")).textContent).toBe("Upgrade this gateway to use the internal AI endpoint.");
    expect(mock.PUT.mock.calls[0][1].body.expected_revision).toBe(2);
  });

  it("turns public static keys on through the switch", async () => {
    mock.PUT.mockResolvedValue({ data: { public_static_keys_allowed: true } });
    await show();
    const toggle = screen.getByRole("switch", { name: "Allow public static keys" });
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(toggle);
    await waitFor(() => expect(mock.PUT).toHaveBeenCalledWith(settingsPath, { params: { path: { orgId: "org" } }, body: { public_static_keys_allowed: true } }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "Allow public static keys" }).getAttribute("aria-checked")).toBe("true"));
  });

  it("downloads the CA certificate as ca.pem", async () => {
    const create = vi.fn(() => "blob:ca"), revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    mock.GET.mockImplementation((path: string) => Promise.resolve({ data: path.endsWith("internal-endpoint-ca") ? { certificate_pem: "-----BEGIN CERTIFICATE-----", not_after: "2036-01-01T00:00:00Z", sha256: "ab" } : path.endsWith("internal-endpoints") ? { items: [ready] } : { public_static_keys_allowed: false } }));
    await show();
    fireEvent.click(screen.getByRole("button", { name: "Download CA certificate" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect((click.mock.instances[0] as unknown as HTMLAnchorElement).download).toBe("ca.pem");
    expect(create).toHaveBeenCalled();
  });

  it("is read-only without ai_gateway:manage", async () => {
    publicAllowed = true;
    await show(false);
    expect(screen.getByText(/Read-only/)).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "Allow public static keys" })).toBeNull();
    expect(screen.getByRole("status").textContent).toBe("On");
    expect(screen.queryByRole("button", { name: /Actions for internal AI endpoint/ })).toBeNull();
    expect(mock.PUT).not.toHaveBeenCalled(); expect(mock.DELETE).not.toHaveBeenCalled();
  });
});
