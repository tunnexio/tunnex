import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { Profiler } from "react";
import type { Device, Node, Org } from "../src/lib/api";

const state = vi.hoisted(() => ({
  GET: vi.fn(), POST: vi.fn(), DELETE: vi.fn(),
  org: { id: "org-a", name: "Organization A", ovpn_enabled: false } as Org | null,
  loading: false, failed: false,
  auth: { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } },
  devices: [] as Device[], nodes: [] as Node[],
}));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: state.org, loading: state.loading, failed: state.failed }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: state.auth }) }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
vi.mock("qrcode.react", () => ({ QRCodeSVG: ({ value }: { value: string }) => <svg aria-label="WireGuard configuration QR" data-secret={value} /> }));
import Devices from "../src/pages/Devices";
import { PRODUCT_NAME } from "../src/brand";

const device = (index: number, values: Partial<Device> = {}): Device => ({
  id: `device-${index}`, user_id: "user-a", node_id: "gateway-a", name: `Device ${index}`,
  public_key: "wireguard-key", full_tunnel: false, status: "active", assigned_ip: `10.99.0.${index}`,
  created_at: "2026-10-08T08:00:00Z", ...values,
});
const gateway = (id: string, values: Partial<Node> = {}): Node => ({ id, name: id, status: "active", agent_version: "1.0.0", enrolled_at: "2026-10-08T08:00:00Z", endpoint: `${id}.example.test:51820`, ...values });
function seed() {
  state.GET.mockImplementation(async (path: string) => {
    if (path.endsWith("/devices")) return { data: state.devices };
    if (path.endsWith("/nodes")) return { data: state.nodes };
    if (path.endsWith("/members")) return { data: [{ user_id: state.auth.user.id, email: state.auth.user.email, role: "owner", email_verified: true }] };
    return { data: [] };
  });
  state.POST.mockImplementation(async (path: string) => ({ data: { device: device(99), ...(path.endsWith("/ovpn-profiles") ? { profile: "PRIVATE OPENVPN PROFILE" } : { config: "PRIVATE WIREGUARD CONFIG" }) } }));
  state.DELETE.mockResolvedValue({ data: {} });
}
const workspace = () => <MemoryRouter><Devices /></MemoryRouter>;
const mount = () => render(workspace());
async function enroll() {
  const add = await screen.findByRole("button", { name: "Add device" });
  await waitFor(() => expect(add).toHaveProperty("disabled", false));
  fireEvent.click(add);
  fireEvent.change(screen.getByPlaceholderText("my-laptop"), { target: { value: "New laptop" } });
  return screen.getByRole("dialog", { name: "Add device" });
}
beforeEach(() => {
  vi.resetAllMocks();
  state.org = { id: "org-a", name: "Organization A", ovpn_enabled: false } as Org;
  state.auth = { status: "authed", user: { id: "user-a", email: "owner@example.test", email_verified: true } };
  state.loading = false; state.failed = false; state.devices = [device(1)]; state.nodes = [gateway("gateway-a")];
  seed();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("Devices enrollment authority and one-time export", () => {
  it("requires an explicit choice when two active gateways are available and excludes revoked gateways", async () => {
    state.nodes = [gateway("old", { status: "revoked" }), gateway("gateway-a"), gateway("gateway-b")];
    mount();
    const dialog = await enroll();
    const create = within(dialog).getByRole("button", { name: "Create device" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(within(dialog).queryByRole("option", { name: /old/ })).toBeNull();
    fireEvent.change(within(dialog).getByLabelText("Gateway"), { target: { value: "gateway-b" } });
    fireEvent.click(create);
    await waitFor(() => expect(state.POST).toHaveBeenCalledTimes(1));
    expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices", {
      params: { path: { orgId: "org-a" } },
      body: { name: "New laptop", node_id: "gateway-b", full_tunnel: false, provisioning: "static" },
    });
  });

  it("locks duplicate enrollment submissions while the server result is pending", async () => {
    let complete!: (value: unknown) => void;
    state.POST.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    mount(); const dialog = await enroll();
    const create = within(dialog).getByRole("button", { name: "Create device" });
    fireEvent.click(create); fireEvent.click(create);
    fireEvent.submit(within(dialog).getByPlaceholderText("my-laptop").closest("form")!);
    expect(state.POST).toHaveBeenCalledTimes(1);
    expect(within(dialog).getByPlaceholderText("my-laptop").matches(":disabled")).toBe(true);
    await act(async () => complete({ data: { device: device(99), config: "PRIVATE WIREGUARD CONFIG" } }));
    await screen.findByRole("dialog", { name: "Your configuration, shown once" });
    expect(screen.queryByRole("dialog", { name: "Add device" })).toBeNull();
    expect(state.POST).toHaveBeenCalledTimes(1);
  });

  it("ignores a late enrollment secret after the actor is replaced", async () => {
    let complete!: (value: unknown) => void;
    state.POST.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    const view = mount(); const dialog = await enroll();
    fireEvent.click(within(dialog).getByRole("button", { name: "Create device" }));
    await waitFor(() => expect(state.POST).toHaveBeenCalledTimes(1));
    state.auth = { ...state.auth, user: { ...state.auth.user, id: "user-b" } };
    state.devices = [device(2, { name: "New actor device", user_id: "user-b" })];
    view.rerender(workspace());
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByRole("button", { name: "New actor device" });
    await act(async () => complete({ data: { device: device(99), config: "SUPERSEDED PRIVATE CONFIG" } }));
    expect(screen.queryByText("SUPERSEDED PRIVATE CONFIG")).toBeNull();
    expect(screen.queryByLabelText("WireGuard configuration QR")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it.each(["wireguard", "openvpn"] as const)("exports a pending %s profile once, with an honest approval warning and protocol-specific download", async (kind) => {
    state.org = { ...state.org!, ovpn_enabled: true };
    const exported = kind === "wireguard" ? "[Interface]\nPrivateKey = pending-wg-key\n" : "<key>pending-openvpn-private-key</key>\n";
    state.POST.mockResolvedValueOnce({ data: { device: device(99, { status: "pending" }), ...(kind === "wireguard" ? { config: exported } : { profile: exported }) } });
    const createURL = vi.fn((_blob: Blob) => "blob:one-time-device");
    const revokeURL = vi.fn();
    const OriginalURL = URL;
    vi.stubGlobal("URL", Object.assign(class extends OriginalURL {}, { createObjectURL: createURL, revokeObjectURL: revokeURL }));
    const downloads: Array<{ name: string; href: string }> = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { downloads.push({ name: this.download, href: this.href }); });
    mount(); const editor = await enroll();
    fireEvent.change(within(editor).getByLabelText("Protocol"), { target: { value: kind } });
    fireEvent.click(within(editor).getByRole("checkbox", { name: /Route all traffic/ }));
    fireEvent.click(within(editor).getByRole("button", { name: kind === "wireguard" ? "Create device" : "Export OpenVPN profile" }));
    const issued = await screen.findByRole("dialog", { name: kind === "wireguard" ? "Your configuration, shown once" : "Your OpenVPN profile, shown once" });
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(issued.textContent).toContain("pending approval");
    expect(issued.textContent).toContain("won’t connect until an admin approves");
    expect(issued.textContent).toContain("exactly once");
    expect(issued.textContent).toContain("current site routes");
    if (kind === "wireguard") expect(within(issued).getByLabelText("WireGuard configuration QR").getAttribute("data-secret")).toBe(exported);
    else expect(within(issued).queryByLabelText("WireGuard configuration QR")).toBeNull();
    const expectedPath = kind === "wireguard" ? "/api/v1/organizations/{orgId}/devices" : "/api/v1/organizations/{orgId}/ovpn-profiles";
    expect(state.POST).toHaveBeenCalledWith(expectedPath, { params: { path: { orgId: "org-a" } }, body: { name: "New laptop", node_id: "gateway-a", full_tunnel: true, ...(kind === "wireguard" ? { provisioning: "static" } : {}) } });
    fireEvent.click(within(issued).getByRole("button", { name: `Download ${PRODUCT_NAME}.${kind === "wireguard" ? "conf" : "ovpn"}` }));
    expect(downloads).toEqual([{ name: `${PRODUCT_NAME}.${kind === "wireguard" ? "conf" : "ovpn"}`, href: "blob:one-time-device" }]);
    const blob = createURL.mock.calls[0]?.[0] as Blob | undefined;
    expect(blob).toBeTruthy();
    const contents = await new Promise(resolve => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.readAsText(blob!); });
    expect(contents).toBe(exported);
    fireEvent.keyDown(issued, { key: "Escape" });
    expect(screen.getByRole("dialog")).toBe(issued);
    fireEvent.click(within(issued).getByRole("button", { name: "I’ve saved it" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByLabelText("WireGuard configuration QR")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Refresh devices" }));
    await screen.findByRole("button", { name: "Device 1" });
    expect(state.POST).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(exported)).toBeNull();
    expect(screen.queryByRole("button", { name: /Download .*\.(conf|ovpn)/ })).toBeNull();
  });

  it.each(["transport", "missing-export"] as const)("does not claim or repeat an unconfirmed enrollment after %s", async (failure) => {
    if (failure === "transport") state.POST.mockRejectedValueOnce(new Error("response lost"));
    else state.POST.mockResolvedValueOnce({ data: { device: device(99) } });
    mount(); const dialog = await enroll();
    fireEvent.click(within(dialog).getByRole("button", { name: "Create device" }));
    await within(dialog).findByText(/Refresh the device list before trying again/);
    expect(within(dialog).getByPlaceholderText("my-laptop")).toHaveProperty("value", "New laptop");
    expect(screen.queryByRole("dialog", { name: "Your configuration, shown once" })).toBeNull();
    expect(screen.queryByLabelText("WireGuard configuration QR")).toBeNull();
    expect(state.POST).toHaveBeenCalledTimes(1);
  });

  it("cannot issue a profile when every gateway is revoked", async () => {
    state.nodes = [gateway("old", { status: "revoked" })];
    mount(); const dialog = await enroll();
    expect(within(dialog).getByRole("button", { name: "Create device" })).toHaveProperty("disabled", true);
    expect(within(dialog).getByText(/No active gateway is available/)).toBeTruthy();
    fireEvent.submit(within(dialog).getByPlaceholderText("my-laptop").closest("form")!);
    expect(state.POST).not.toHaveBeenCalled();
  });
});

describe("Devices data scope", () => {
  it("keeps inventory readable but withholds enrollment and lifecycle mutations for an unverified actor", async () => {
    state.auth = { ...state.auth, user: { ...state.auth.user, email_verified: false } };
    mount();
    await screen.findByRole("button", { name: "Device 1" });
    expect(screen.queryByRole("button", { name: "Add device" })).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Device actions for Device 1" }));
    expect(screen.queryByRole("menuitem", { name: "Revoke" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Remove" })).toBeNull();
    expect(screen.getByRole("menuitem", { name: "View details" })).toBeTruthy();
    expect(state.POST).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });

  it("withdraws old private device facts at every organization-switch commit", async () => {
    state.devices = [device(1, { name: "Private organization A laptop" })];
    const leaked: boolean[] = [];
    const scoped = () => <MemoryRouter><Profiler id="device-scope" onRender={() => {
      if (state.org?.id === "org-b") leaked.push(Boolean(screen.queryByRole("button", { name: "Private organization A laptop" }) || screen.queryByRole("dialog")));
    }}><Devices /></Profiler></MemoryRouter>;
    const view = render(scoped());
    await screen.findByRole("button", { name: "Private organization A laptop" });
    fireEvent.click(screen.getByRole("button", { name: "Add device" }));
    state.org = { ...state.org!, id: "org-b", name: "Organization B" };
    state.devices = [device(2, { name: "Organization B laptop" })];
    view.rerender(scoped());
    await screen.findByRole("button", { name: "Organization B laptop" });
    expect(leaked.length).toBeGreaterThan(0);
    expect(leaked).not.toContain(true);
    expect(state.POST).not.toHaveBeenCalled();
  });

  it("ignores an old organization's late fleet response instead of replacing the current inventory", async () => {
    let complete!: (value: unknown) => void;
    state.GET.mockImplementation(async (path: string, request: { params: { path: { orgId: string } } }) => {
      if (path.endsWith("/devices") && request.params.path.orgId === "org-a") return new Promise(resolve => { complete = resolve; });
      if (path.endsWith("/devices")) return { data: [device(2, { name: "Current organization device" })] };
      if (path.endsWith("/nodes")) return { data: state.nodes };
      return { data: [] };
    });
    const view = mount();
    await waitFor(() => expect(complete).toBeTypeOf("function"));
    state.org = { ...state.org!, id: "org-b" };
    view.rerender(workspace());
    await screen.findByRole("button", { name: "Current organization device" });
    await act(async () => complete({ data: [device(1, { name: "Superseded private device" })] }));
    expect(screen.queryByRole("button", { name: "Superseded private device" })).toBeNull();
    expect(screen.getByRole("button", { name: "Current organization device" })).toBeTruthy();
    expect(state.GET.mock.calls.filter(([path, request]) => path.endsWith("/members") && request.params.path.orgId === "org-a")).toHaveLength(0);
  });

  it("keeps failed inventory distinct from empty and recovers through the explicit retry", async () => {
    state.GET.mockImplementationOnce(async () => ({ error: { error: { message: "Device inventory unavailable" } } }));
    mount();
    await screen.findByText("Device inventory unavailable");
    expect(screen.queryByText("No devices yet.")).toBeNull();
    expect(screen.queryByRole("table", { name: "Devices" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("button", { name: "Device 1" });
    expect(screen.queryByText("Device inventory unavailable")).toBeNull();
  });

  it("preserves a real device inventory when the courtesy owner roster or gateway read fails", async () => {
    state.devices = [device(1, { owner_email: "recorded.owner@example.test" })];
    state.GET.mockImplementation(async (path: string) => path.endsWith("/devices") ? { data: state.devices } : { error: { error: { message: "Auxiliary inventory unavailable" } } });
    mount();
    await screen.findByRole("button", { name: "Device 1" });
    expect(screen.getByRole("table", { name: "Devices" }).textContent).toContain("recorded.owner@example.test");
    expect(screen.getByRole("button", { name: "Add device" })).toHaveProperty("disabled", true);
    expect(screen.queryByText("No devices yet.")).toBeNull();
  });

  it("uses focused read-only detail navigation and retains honest OpenVPN and inactive evaluations", async () => {
    state.devices = [device(1, { public_key: "", last_handshake_at: "2026-10-08T08:00:00Z" }), device(2, { status: "revoked", health_state: "compliant" })];
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Device 1" }));
    const detail = screen.getByRole("region", { name: "Device 1" });
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Devices" })).toBeNull();
    fireEvent.click(within(detail).getByRole("button", { name: "Connection" }));
    expect(within(detail).getByText("liveness not reported")).toBeTruthy();
    expect(within(detail).queryByText(/last seen/)).toBeNull();
    fireEvent.click(within(detail).getByRole("button", { name: "Back to devices" }));
    fireEvent.click(screen.getByRole("button", { name: "Device 2" }));
    fireEvent.click(screen.getByRole("button", { name: "Posture" }));
    expect(screen.getByText("Not evaluated for revoked devices")).toBeTruthy();
    expect(screen.queryByText("posture ok")).toBeNull();
    expect(state.POST).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });
});

describe("Devices lifecycle confirmation", () => {
  it("requires confirmation for active revocation and revoked removal, and cancellation is read-only", async () => {
    state.devices = [device(1), device(2, { status: "revoked" }), device(3, { status: "pending" })];
    mount(); await screen.findByRole("button", { name: "Device 1" });
    fireEvent.click(screen.getByRole("button", { name: "Device actions for Device 1" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke" }));
    const revoke = screen.getByRole("dialog", { name: "Revoke device?" });
    expect(revoke.textContent).toContain("Device 1");
    expect(state.POST).not.toHaveBeenCalled();
    fireEvent.click(within(revoke).getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Device actions for Device 2" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Remove" }));
    const remove = screen.getByRole("dialog", { name: "Remove device?" });
    fireEvent.click(within(remove).getByRole("button", { name: "Remove device" }));
    await waitFor(() => expect(state.DELETE).toHaveBeenCalledTimes(1));
    expect(state.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices/{deviceId}", { params: { path: { orgId: "org-a", deviceId: "device-2" } } });
    await screen.findByRole("button", { name: "Device 1" });
    fireEvent.click(screen.getByRole("button", { name: "Device actions for Device 1" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Revoke" }));
    fireEvent.click(screen.getByRole("button", { name: "Revoke device" }));
    await waitFor(() => expect(state.POST).toHaveBeenCalledTimes(1));
    expect(state.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices/{deviceId}/revoke", { params: { path: { orgId: "org-a", deviceId: "device-1" } } });
  });

  it("reports each unconfirmed bulk target, reloads once, and refuses duplicate confirmation", async () => {
    state.devices = [device(1), device(2), device(3, { status: "pending" })];
    let fail!: (value: unknown) => void;
    state.POST.mockImplementation(async (_path: string, request: { params: { path: { deviceId: string } } }) => {
      if (request.params.path.deviceId === "device-2") return new Promise(resolve => { fail = resolve; });
      state.devices = state.devices.map(value => value.id === request.params.path.deviceId ? { ...value, status: "revoked" } : value);
      return { data: {} };
    });
    mount(); await screen.findByRole("button", { name: "Device 1" });
    for (const name of ["Device 1", "Device 2", "Device 3"]) fireEvent.click(screen.getByRole("checkbox", { name: `Select ${name}` }));
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    const confirm = screen.getByRole("dialog", { name: "Revoke devices?" });
    expect(confirm.textContent).toContain("Device 1");
    expect(confirm.textContent).toContain("Device 2");
    expect(confirm.textContent).not.toContain("Device 3");
    const reads = state.GET.mock.calls.filter(([path]) => path.endsWith("/devices")).length;
    const apply = within(confirm).getByRole("button", { name: "Revoke device" });
    fireEvent.click(apply); fireEvent.click(apply);
    expect(state.POST).toHaveBeenCalledTimes(2);
    await act(async () => fail({ error: { error: { message: "Gateway refusal" } } }));
    const error = await screen.findByText(/1 of 2 devices revoked/);
    expect(error.textContent).toContain("Device 2: Gateway refusal");
    expect(error.textContent).not.toContain("Device 3");
    await screen.findByRole("button", { name: "Device 1" });
    expect(state.GET.mock.calls.filter(([path]) => path.endsWith("/devices"))).toHaveLength(reads + 1);
    const revokedRow = screen.getByRole("button", { name: "Device 1" }).closest("tr")!;
    expect(within(revokedRow).getByText("revoked")).toBeTruthy();
    const failedRow = screen.getByRole("button", { name: "Device 2" }).closest("tr")!;
    expect(within(failedRow).getByText("active")).toBeTruthy();
  });
});
