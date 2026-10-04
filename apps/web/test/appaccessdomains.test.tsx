import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppAccessDomainsSettings } from "../src/components/AppAccessDomainsSettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PATCH: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
const endpoint = "/api/v1/admin/app-access/domains";
const settings = (overrides = {}) => ({ data: { portal_url: "https://console.example.net", app_base_domain: "apps.example.org", version: 0, source: "environment", configuration_ready: true, ...overrides } });
const show = (canEdit = true) => render(<AppAccessDomainsSettings canEdit={canEdit} />);
const portal = () => screen.getByLabelText("Portal URL") as HTMLInputElement;
const base = () => screen.getByLabelText("Application base domain") as HTMLInputElement;
const save = () => screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement;
const reload = () => screen.getByRole("button", { name: "Reload saved settings" });
const load = () => screen.findByLabelText("Portal URL");
const edit = () => {
  fireEvent.change(portal(), { target: { value: "https://internal.tunnex.app" } });
  fireEvent.change(base(), { target: { value: "internal.tunnex.app" } });
};

beforeEach(() => { vi.resetAllMocks(); api.GET.mockResolvedValue(settings()); });
afterEach(cleanup);

describe("server App Access domain settings", () => {
  it("loads environment values without claiming DNS or TLS readiness", async () => {
    show(); await load();
    expect(portal().value).toBe("https://console.example.net"); expect(base().value).toBe("apps.example.org");
    expect(screen.getByText("Source: Server environment")).toBeTruthy();
    expect(screen.getByText(/DNS, certificates and reachability have not been checked/)).toBeTruthy();
    expect(screen.getByText(/Saving here does not create DNS records or issue certificates/)).toBeTruthy();
    expect(screen.getByText(/Your organization manages DNS and TLS/)).toBeTruthy();
    expect(screen.getByText(/update the registered redirect URLs in your SSO identity providers/)).toBeTruthy();
    expect(save().disabled).toBe(true); expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("saves same-parent domains once with initial version zero, then displays server truth", async () => {
    let complete!: (result: ReturnType<typeof settings>) => void;
    api.PATCH.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    show(); await load(); edit();
    expect(screen.getByText("https://test.internal.tunnex.app")).toBeTruthy();
    const form = save().closest("form")!;
    fireEvent.submit(form); fireEvent.submit(form);
    expect(api.PATCH).toHaveBeenCalledTimes(1);
    expect(api.PATCH).toHaveBeenCalledWith(endpoint, { body: { portal_url: "https://internal.tunnex.app", app_base_domain: "internal.tunnex.app", expected_version: 0 } });
    expect(screen.getByText("Source: Server environment")).toBeTruthy();
    expect(portal().disabled).toBe(true);
    await act(async () => complete(settings({ portal_url: "https://internal.tunnex.app", app_base_domain: "internal.tunnex.app", version: 1, source: "database" })));
    expect(screen.getByText("Source: Saved settings")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Existing application hostnames are preserved");
    expect(save().disabled).toBe(true);
  });

  it("retains independent-domain and HTTPS IP portal configurations", async () => {
    api.GET.mockResolvedValue(settings({ portal_url: "https://192.0.2.20:9443", version: 3, source: "database" }));
    api.PATCH.mockResolvedValue(settings({ portal_url: "https://192.0.2.20:9443", app_base_domain: "private.example.org", version: 4, source: "database" }));
    show(); await load();
    fireEvent.change(base(), { target: { value: "private.example.org" } }); fireEvent.click(save());
    await screen.findByRole("status");
    expect(api.PATCH).toHaveBeenCalledWith(endpoint, { body: { portal_url: "https://192.0.2.20:9443", app_base_domain: "private.example.org", expected_version: 3 } });
    expect(screen.getByText(/IP address cannot be the application domain/)).toBeTruthy();
  });

  it("does not offer a made-up default after load failure and can retry", async () => {
    api.GET.mockResolvedValueOnce({ error: { error: { message: "Domain settings unavailable" } } });
    show(); await screen.findByText("Domain settings unavailable");
    expect(screen.queryByLabelText("Portal URL")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry domain settings" }));
    await load(); expect(base().value).toBe("apps.example.org"); expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("retains edits after stale-version rejection until an explicit successful reload", async () => {
    api.GET.mockResolvedValueOnce(settings()).mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce(settings({ portal_url: "https://new.example.net", version: 6, source: "database" }));
    api.PATCH.mockResolvedValue({ error: { error: { code: "app_domains_changed" } }, response: { status: 409 } });
    show(); await load(); edit(); fireEvent.click(save());
    await screen.findByText(/These settings changed on the server/);
    expect(portal().value).toBe("https://internal.tunnex.app"); expect(base().value).toBe("internal.tunnex.app");
    expect(save().disabled).toBe(true); expect(api.GET).toHaveBeenCalledTimes(1);
    fireEvent.click(reload()); await screen.findByText(/Could not reach the server/);
    expect(portal().value).toBe("https://internal.tunnex.app"); expect(save().disabled).toBe(true);
    fireEvent.click(reload()); await screen.findByText("Source: Saved settings");
    expect(portal().value).toBe("https://new.example.net"); expect(base().value).toBe("apps.example.org");
    expect(screen.queryByRole("alert")).toBeNull(); expect(api.PATCH).toHaveBeenCalledTimes(1);
  });

  it("does not confuse a reserved portal hostname with another administrator's edit", async () => {
    api.PATCH.mockResolvedValue({ error: { error: { code: "portal_hostname_reserved", message: "Portal hostname is already an application hostname" } }, response: { status: 409 } });
    show(); await load(); edit(); fireEvent.click(save());
    await screen.findByText("Portal hostname is already an application hostname");
    expect(portal().value).toBe("https://internal.tunnex.app"); expect(save().disabled).toBe(false);
    expect(screen.queryByText(/These settings changed on the server/)).toBeNull();
  });

  it("keeps input and blocks repeat writes after an uncertain network outcome", async () => {
    api.PATCH.mockRejectedValue(new Error("connection lost"));
    show(); await load(); edit(); fireEvent.click(save());
    await screen.findByText(/response was interrupted/);
    expect(base().value).toBe("internal.tunnex.app"); expect(save().disabled).toBe(true);
    fireEvent.submit(save().closest("form")!); expect(api.PATCH).toHaveBeenCalledTimes(1);
  });

  it("requires verified administrator editing even for programmatic submit", async () => {
    show(false); await load();
    expect(portal().disabled).toBe(true); expect(base().disabled).toBe(true);
    edit(); fireEvent.submit(save().closest("form")!);
    expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("keeps incomplete configuration honest and does not invent an IP app address", async () => {
    api.GET.mockResolvedValue(settings({ portal_url: "", app_base_domain: "", configuration_ready: false }));
    show(); await load();
    expect(screen.getByText(/Saved configuration: configuration incomplete/)).toBeTruthy();
    expect(save().disabled).toBe(true);
    fireEvent.change(base(), { target: { value: "192.0.2.20" } });
    expect(screen.queryByText("https://test.192.0.2.20")).toBeNull();
  });

  it("does not leak a late save result into a remounted administrator panel", async () => {
    let complete!: (result: ReturnType<typeof settings>) => void;
    api.PATCH.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    const page = show(); await load(); edit(); fireEvent.click(save()); page.unmount();
    show(); await load();
    await act(async () => complete(settings({ app_base_domain: "old-admin.example.org", version: 4, source: "database" })));
    expect(base().value).toBe("apps.example.org"); expect(screen.queryByRole("status")).toBeNull();
  });
});
