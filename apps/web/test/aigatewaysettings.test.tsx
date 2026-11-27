import { MemoryRouter } from "react-router-dom";
import { WorkspaceFeatureControl } from "../src/components/WorkspaceFeatureControl";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIGatewaySettings } from "../src/components/AIGatewaySettings";

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "actor-a", email_verified: true } } }) }));
type Result = { data: { enabled: boolean; available: boolean; revision: number } };
function result(enabled: boolean, available = true): Result {
  return { data: { enabled, available, revision: 1 } };
}
function deferred() {
  let resolve!: (value: Result) => void;
  const promise = new Promise<Result>((done) => { resolve = done; });
  return { promise, resolve };
}
function view(orgId = "org-a", canEdit = true, central = true) {
  return <MemoryRouter>{central ? <WorkspaceFeatureControl feature="ai-gateway" orgId={orgId} canEdit={canEdit} roles={["admin"]} serverAdmin={false} /> : <AIGatewaySettings orgId={orgId} canEdit={canEdit} />}</MemoryRouter>;
}
async function state(enabled: boolean, central = true) {
  await waitFor(() => central ? expect(screen.getByRole("switch", { name: "AI Gateway" }).getAttribute("aria-checked")).toBe(String(enabled)) : expect(screen.getByRole("status").textContent).toContain(enabled ? "Enabled" : "Disabled"));
}
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

describe("AI gateway organization settings", () => {
  it("retries an initial settings load failure without a browser refresh", async () => {
    api.GET.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce(result(false));
    render(view());
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Reload AI Gateway setting" }));
    await state(false);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(api.GET).toHaveBeenCalledTimes(2);
    expect(api.PUT).not.toHaveBeenCalled();
  });
  it("prevents enable when the installation is unavailable", async () => {
    api.GET.mockResolvedValue(result(false, false));
    render(view());
    await state(false);
    const button = screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(api.PUT).not.toHaveBeenCalled();
  });
  it("permits disable even when the installation is unavailable", async () => {
    api.GET.mockResolvedValue(result(true, false));
    api.PUT.mockResolvedValue(result(false, false));
    render(view());
    await state(true);
    const button = screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    await state(false);
    expect(api.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ai-gateway", {
      params: { path: { orgId: "org-a" } }, body: { enabled: false },
    });
  });
  it("waits for server truth rather than optimistic enable", async () => {
    const saving = deferred();
    api.GET.mockResolvedValue(result(false));
    api.PUT.mockReturnValue(saving.promise);
    render(view());
    await state(false);
    fireEvent.click(screen.getByRole("switch", { name: "AI Gateway" }));
    expect(screen.getByRole("switch", { name: "AI Gateway" }).getAttribute("aria-checked")).toBe("false");
    expect((screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { saving.resolve(result(false)); });
    await state(false);
    expect(screen.getByRole("switch", { name: "AI Gateway" })).toBeTruthy();
  });
  it("preserves the setting when saving fails over the network", async () => {
    api.GET.mockResolvedValue(result(true));
    api.PUT.mockRejectedValue(new Error("network unavailable"));
    render(view());
    await state(true);
    fireEvent.click(screen.getByRole("switch", { name: "AI Gateway" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("alert").textContent).toContain("Could not confirm the change");
    expect(screen.queryByRole("switch", { name: "AI Gateway" })).toBeNull();
    expect(screen.getByText("Last reported: Enabled.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reload AI Gateway setting" }));
    await state(true);
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });
  it("ignores stale organization loads", async () => {
    const oldLoad = deferred();
    api.GET.mockReturnValueOnce(oldLoad.promise).mockResolvedValueOnce(result(false, false));
    const page = render(view());
    page.rerender(view("org-b"));
    await state(false);
    await act(async () => { oldLoad.resolve(result(true)); });
    expect(screen.getByRole("switch", { name: "AI Gateway" }).getAttribute("aria-checked")).toBe("false");
    expect((screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement).disabled).toBe(true);
    expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId: "org-b" } } });
  });
  it("ignores stale organization saves", async () => {
    const oldSave = deferred();
    api.GET.mockResolvedValue(result(false));
    api.PUT.mockReturnValue(oldSave.promise);
    const page = render(view());
    await state(false);
    fireEvent.click(screen.getByRole("switch", { name: "AI Gateway" }));
    page.rerender(view("org-b"));
    await state(false);
    await act(async () => { oldSave.resolve(result(true)); });
    await state(false);
    expect(screen.getByRole("switch", { name: "AI Gateway" })).toBeTruthy();
    expect(api.PUT).toHaveBeenCalledTimes(1);
    expect(api.PUT.mock.calls[0][1].params.path.orgId).toBe("org-a");
  });
  it("says who can choose the transport and leaves no silent grey switch", async () => {
    api.GET.mockResolvedValue({ data: { ...result(false, false).data, engine_installed: true, unavailable_reason: "https_required", http_allowed: false } });
    render(view("org-a", true, false)); await state(false);
    const banner = screen.getByRole("status", { name: "AI Gateway is not ready" });
    expect(banner.textContent).toContain("Ask a server administrator to open Settings, then AI Gateway transport");
    expect((screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Transport not chosen")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
  it("reports the saved HTTP exception without claiming private-only access", async () => {
    api.GET.mockResolvedValue({ data: { ...result(true).data, http_allowed: true, private_http_allowed: false } });
    render(view("org-a", true, false)); await state(true);
    expect(screen.getByText("Ready · HTTP allowed")).toBeTruthy();
    expect(screen.getByText(/HTTP does not encrypt credentials or requests/)).toBeTruthy();
  });
  it("hides mutation controls when editing is forbidden", async () => {
    api.GET.mockResolvedValue(result(true));
    render(view("org-a", false, false));
    await state(true, false);
    expect(screen.queryByRole("button", { name: /Enable AI gateway|Disable AI gateway/ })).toBeNull();
    expect(screen.queryByRole("link", { name: "Manage feature" })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("puts the switch on the AI Gateway settings page instead of a link to Features", async () => {
    let enabled = false;
    api.GET.mockImplementation(async () => result(enabled));
    api.PUT.mockImplementation(async () => { enabled = true; return result(true); });
    render(view("org-a", true, false)); await state(false);
    expect(screen.queryByRole("link", { name: "Manage feature" })).toBeNull();
    expect(screen.getByRole("status", { name: "AI Gateway is not ready" }).textContent).toContain("AI Gateway is turned off");
    fireEvent.click(screen.getByRole("switch", { name: "AI Gateway" }));
    await state(true);
    expect(api.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId: "org-a" } }, body: { enabled: true } });
    await waitFor(() => expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull());
  });
  it("turns the gateway on from the banner and the switch follows", async () => {
    let enabled = false;
    api.GET.mockImplementation(async () => result(enabled));
    api.PUT.mockImplementation(async () => { enabled = true; return result(true); });
    render(view("org-a", true, false)); await state(false);
    fireEvent.click(screen.getByRole("button", { name: "Turn on AI Gateway" }));
    await state(true);
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });
});

describe("AI Gateway switch when the transport is not chosen (AI-UX-1)", () => {
  const settingsPath = "/api/v1/organizations/{orgId}/ai-gateway";
  const transportRequired = { data: { enabled: false, available: false, revision: 1, unavailable_reason: "https_required", status: { on: false, reason: "transport_required", fix: { kind: "choose_transport", requires_server_admin: true } } } };
  const central = (serverAdmin: boolean) => <MemoryRouter><WorkspaceFeatureControl feature="ai-gateway" orgId="org-a" canEdit roles={["admin"]} serverAdmin={serverAdmin} /></MemoryRouter>;

  it("opens the transport choice for a server administrator, then finishes turning the gateway on", async () => {
    let chosen = false, enabled = false;
    api.GET.mockImplementation(async (path: string) => path === settingsPath
      ? chosen ? { data: { enabled, available: true, revision: 2 } } : transportRequired
      : { data: { allow_http: false, allow_vpn_http: false, revision: 1 } });
    api.PUT.mockImplementation(async (path: string) => {
      if (path === settingsPath) { enabled = true; return { data: { enabled: true, available: true, revision: 3 } }; }
      chosen = true; return { data: { allow_http: false, allow_vpn_http: true, revision: 2 } };
    });
    render(central(true)); await state(false);
    const toggle = screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement;
    expect(toggle.disabled).toBe(false);
    expect(screen.getByText(/turning AI Gateway on first asks you to choose the transport/)).toBeTruthy();
    fireEvent.click(toggle);
    const dialog = await screen.findByRole("dialog", { name: "Choose how AI Gateway is reached" });
    expect(api.PUT).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole("switch", { name: "Allow HTTP inside the VPN" }));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText(/^Saved\./);
    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));
    await state(true);
    expect(api.PUT).toHaveBeenLastCalledWith(settingsPath, { params: { path: { orgId: "org-a" } }, body: { enabled: true } });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("does not turn the gateway on when the transport choice is closed without one", async () => {
    api.GET.mockImplementation(async (path: string) => path === settingsPath ? transportRequired : { data: { allow_http: false, allow_vpn_http: false, revision: 1 } });
    render(central(true)); await state(false);
    fireEvent.click(screen.getByRole("switch", { name: "AI Gateway" }));
    const dialog = await screen.findByRole("dialog", { name: "Choose how AI Gateway is reached" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await state(false);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("says who can choose the transport for anyone who is not a server administrator", async () => {
    api.GET.mockResolvedValue(transportRequired);
    render(central(false)); await state(false);
    expect((screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/Ask a server administrator to open Settings, then AI Gateway transport/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("says who installs the AI engine when that is what is missing", async () => {
    api.GET.mockResolvedValue({ data: { enabled: false, available: false, revision: 1, unavailable_reason: "engine_not_configured" } });
    render(central(false)); await state(false);
    expect((screen.getByRole("switch", { name: "AI Gateway" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/Only a server administrator can fix this: ask them to upgrade Tunnex Server/)).toBeTruthy();
  });
});
