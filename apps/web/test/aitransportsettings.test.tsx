import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AITransportSettings } from "../src/components/AITransportSettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
const endpoint = "/api/v1/admin/ai-transport-settings";
const vpnName = "Allow HTTP inside the VPN";
const publicName = "Allow HTTP on the public internet";
// A new installation: HTTP inside the VPN on, public HTTP off.
const settings = (allow_http = false, revision = 1, allow_vpn_http = true) => ({ data: { allow_http, allow_vpn_http, revision } });
const show = (canEdit = true) => render(<AITransportSettings canEdit={canEdit} />);
const vpnToggle = () => screen.getByRole("switch", { name: vpnName }) as HTMLButtonElement;
const publicToggle = () => screen.getByRole("switch", { name: publicName }) as HTMLButtonElement;
const save = () => screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement;
const load = () => screen.findByRole("switch", { name: publicName });
const savedPolicy = (vpn: boolean, pub: boolean) => `Saved policy: Inside the VPN ${vpn ? "on" : "off"} · Public internet ${pub ? "on" : "off"}`;

beforeEach(() => { vi.resetAllMocks(); api.GET.mockResolvedValue(settings()); });
afterEach(cleanup);

describe("server AI transport settings", () => {
  it("shows two separate switches with the safe defaults and does not mutate them", async () => {
    show(); await load();
    expect(screen.getAllByRole("switch")).toHaveLength(2);
    expect(vpnToggle().getAttribute("aria-checked")).toBe("true");
    expect(publicToggle().getAttribute("aria-checked")).toBe("false");
    expect(save().disabled).toBe(true);
    expect(screen.getByText(savedPolicy(true, false))).toBeTruthy();
    expect(api.GET).toHaveBeenCalledWith(endpoint);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("explains each switch in plain language and warns only about the public one", async () => {
    show(); await load();
    const vpn = screen.getByRole("group", { name: "Inside the VPN" });
    expect(within(vpn).getByText("Recommended")).toBeTruthy();
    expect(within(vpn).getByText(/connected to the VPN/)).toBeTruthy();
    expect(within(vpn).getByText(/does not open anything on the public internet/)).toBeTruthy();
    expect(within(vpn).queryByText(/unencrypted/)).toBeNull();
    const pub = screen.getByRole("group", { name: "Public internet" });
    expect(within(pub).getByText(/Keep this off/)).toBeTruthy();
    expect(within(pub).getByText(/provider keys and access tokens travel unencrypted/)).toBeTruthy();
    expect(within(pub).queryByText("Recommended")).toBeNull();
    expect(screen.getByText(/HTTPS always works/)).toBeTruthy();
  });

  it("saves only the public switch when only it changes, waiting for server truth", async () => {
    let complete!: (value: ReturnType<typeof settings>) => void;
    api.PUT.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    show(); await load();
    fireEvent.click(publicToggle());
    expect(screen.getByText(savedPolicy(true, false))).toBeTruthy();
    expect(api.PUT).not.toHaveBeenCalled();
    const form = save().closest("form")!;
    fireEvent.submit(form); fireEvent.submit(form);
    expect(api.PUT).toHaveBeenCalledTimes(1);
    expect(api.PUT).toHaveBeenCalledWith(endpoint, { body: { allow_http: true, allow_vpn_http: true, revision: 1 } });
    expect(screen.getByText(savedPolicy(true, false))).toBeTruthy();
    expect(publicToggle().disabled).toBe(true); expect(vpnToggle().disabled).toBe(true);
    await act(async () => complete(settings(true, 2)));
    expect(await screen.findByText(savedPolicy(true, true))).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Public internet: HTTP is allowed");
    expect(screen.getByRole("status").textContent).toContain("HTTPS always works");
    expect(save().disabled).toBe(true);
  });

  it("turns off HTTP inside the VPN without touching the public switch", async () => {
    api.PUT.mockResolvedValue(settings(false, 2, false));
    show(); await load(); fireEvent.click(vpnToggle()); fireEvent.click(save());
    await screen.findByText(savedPolicy(false, false));
    expect(api.PUT).toHaveBeenCalledWith(endpoint, { body: { allow_http: false, allow_vpn_http: false, revision: 1 } });
    expect(vpnToggle().getAttribute("aria-checked")).toBe("false");
    expect(publicToggle().getAttribute("aria-checked")).toBe("false");
    expect(screen.getByRole("status").textContent).toContain("Inside the VPN: HTTP is blocked");
  });

  it("can disable the saved public exception using its current revision", async () => {
    api.GET.mockResolvedValue(settings(true, 9)); api.PUT.mockResolvedValue(settings(false, 10));
    show(); await load(); fireEvent.click(publicToggle()); fireEvent.click(save());
    await screen.findByText(savedPolicy(true, false));
    expect(api.PUT).toHaveBeenCalledWith(endpoint, { body: { allow_http: false, allow_vpn_http: true, revision: 9 } });
    expect(publicToggle().getAttribute("aria-checked")).toBe("false");
    expect(screen.getByRole("status").textContent).toContain("Public internet: HTTP is blocked");
  });

  it("enables saving when either switch differs from the saved policy", async () => {
    show(); await load();
    fireEvent.click(vpnToggle()); expect(save().disabled).toBe(false);
    fireEvent.click(vpnToggle()); expect(save().disabled).toBe(true);
    fireEvent.click(publicToggle()); expect(save().disabled).toBe(false);
    fireEvent.click(publicToggle()); expect(save().disabled).toBe(true);
    fireEvent.submit(save().closest("form")!);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("does not invent an editable default after a failed load and supports retry", async () => {
    api.GET.mockResolvedValueOnce({ error: { error: { message: "Settings unavailable" } } });
    show(); await screen.findByText("Settings unavailable");
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByText(/Saved policy/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry transport settings" }));
    await load(); expect(publicToggle().getAttribute("aria-checked")).toBe("false");
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("preserves the confirmed policy when the server rejects saving", async () => {
    api.PUT.mockResolvedValue({ error: { error: { message: "Server administrator required" } }, response: { status: 403 } });
    show(); await load(); fireEvent.click(publicToggle()); fireEvent.click(save());
    await screen.findByText("Server administrator required");
    expect(screen.getByText(savedPolicy(true, false))).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("requires reload after a stale revision rather than overwriting another admin", async () => {
    api.GET.mockResolvedValueOnce(settings()).mockResolvedValueOnce(settings(true, 4, false));
    api.PUT.mockResolvedValue({ error: { error: { code: "ai_transport_settings_changed" } }, response: { status: 409 } });
    show(); await load(); fireEvent.click(publicToggle()); fireEvent.click(save());
    await screen.findByText(/These settings changed on the server/);
    expect(save().disabled).toBe(true); expect(publicToggle().disabled).toBe(true); expect(vpnToggle().disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Reload saved settings" }));
    await screen.findByText(savedPolicy(false, true));
    expect(vpnToggle().getAttribute("aria-checked")).toBe("false");
    expect(publicToggle().getAttribute("aria-checked")).toBe("true");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });

  it("reloads uncertain network results before permitting another save", async () => {
    api.GET.mockResolvedValueOnce(settings()).mockResolvedValueOnce(settings(true, 2));
    api.PUT.mockRejectedValue(new Error("network interrupted"));
    show(); await load(); fireEvent.click(publicToggle()); fireEvent.click(save());
    await screen.findByText(/response was interrupted/);
    expect(save().disabled).toBe(true);
    expect(screen.getByText(savedPolicy(true, false))).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reload saved settings" }));
    await screen.findByText(savedPolicy(true, true));
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });

  it("requires verified administrator editing even for programmatic form submission", async () => {
    show(false); await load();
    expect(publicToggle().disabled).toBe(true); expect(vpnToggle().disabled).toBe(true); expect(save().disabled).toBe(true);
    expect(screen.getByText(/Verify your email and change your initial password/)).toBeTruthy();
    fireEvent.click(publicToggle()); fireEvent.click(vpnToggle()); fireEvent.submit(save().closest("form")!);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("reflects persisted policy on a new mount", async () => {
    api.GET.mockResolvedValue(settings(true, 6, false));
    const page = show(); await load(); page.unmount();
    show(); await load();
    expect(publicToggle().getAttribute("aria-checked")).toBe("true");
    expect(vpnToggle().getAttribute("aria-checked")).toBe("false");
    expect(screen.getByText(savedPolicy(false, true))).toBeTruthy();
    expect(api.GET).toHaveBeenCalledTimes(2); expect(api.PUT).not.toHaveBeenCalled();
  });
});
