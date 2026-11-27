import { MemoryRouter } from "react-router-dom";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIGatewayOffBanner, useAIGatewayStatus } from "../src/components/AIGatewayOffBanner";
import { aiGatewayOffCopy, aiGatewayStatus } from "../src/lib/aiGatewayPrerequisite";

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));

type Reason = "not_enabled" | "transport_required" | "no_provider" | "engine_not_installed";
const settingsPath = "/api/v1/organizations/{orgId}/ai-gateway";
const off = (reason: Reason, fix?: object) => ({ data: { enabled: reason !== "not_enabled", available: reason !== "transport_required" && reason !== "engine_not_installed", revision: 1, status: { on: false, reason, fix } } });
const on = { data: { enabled: true, available: true, revision: 2, status: { on: true, reason: null } } };

function Page({ canManage, serverAdmin, onChanged, onAddProvider }: { canManage: boolean; serverAdmin: boolean; onChanged?: () => void; onAddProvider?: () => void }) {
  const gateway = useAIGatewayStatus("org-a");
  return <MemoryRouter><AIGatewayOffBanner orgId="org-a" gateway={gateway} canManage={canManage} serverAdmin={serverAdmin} onChanged={onChanged} onAddProvider={onAddProvider} /><p>Page content</p></MemoryRouter>;
}
const banner = () => screen.findByRole("status", { name: "AI Gateway is not ready" });
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

describe("AI Gateway off banner", () => {
  it("shows nothing while the gateway is on, or while its state is not known", async () => {
    api.GET.mockResolvedValue(on);
    const page = render(<Page canManage serverAdmin />);
    await waitFor(() => expect(api.GET).toHaveBeenCalledWith(settingsPath, { params: { path: { orgId: "org-a" } } }));
    expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull();
    page.unmount();
    api.GET.mockResolvedValue({ error: { error: { code: "forbidden" } } });
    render(<Page canManage={false} serverAdmin={false} />);
    await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull();
  });

  it("not turned on: an administrator turns it on in place", async () => {
    let enabled = false;
    api.GET.mockImplementation(async () => enabled ? on : off("not_enabled", { kind: "enable" }));
    api.PUT.mockImplementation(async () => { enabled = true; return on; });
    const changed = vi.fn();
    render(<Page canManage serverAdmin={false} onChanged={changed} />);
    expect((await banner()).textContent).toContain("AI Gateway is turned off");
    fireEvent.click(screen.getByRole("button", { name: "Turn on AI Gateway" }));
    await waitFor(() => expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull());
    expect(api.PUT).toHaveBeenCalledExactlyOnceWith(settingsPath, { params: { path: { orgId: "org-a" } }, body: { enabled: true } });
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it("not turned on: a refused change is explained and the banner stays", async () => {
    api.GET.mockResolvedValue(off("not_enabled"));
    api.PUT.mockResolvedValue({ error: { error: { code: "forbidden", message: "Verify your email first." } } });
    render(<Page canManage serverAdmin={false} />);
    fireEvent.click(within(await banner()).getByRole("button", { name: "Turn on AI Gateway" }));
    expect((await screen.findByRole("alert")).textContent).toBe("AI Gateway could not be turned on: Verify your email first.");
    expect(screen.getByRole("status", { name: "AI Gateway is not ready" })).toBeTruthy();
  });

  it("not turned on: someone who cannot manage it is told who can, with no button", async () => {
    api.GET.mockResolvedValue(off("not_enabled"));
    render(<Page canManage={false} serverAdmin={false} />);
    expect((await banner()).textContent).toContain("Ask an organization owner or administrator to turn it on.");
    expect(screen.queryByRole("button", { name: "Turn on AI Gateway" })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("transport not chosen: a server administrator chooses it in place", async () => {
    let chosen = false;
    api.GET.mockImplementation(async (path: string) => path === settingsPath
      ? chosen ? off("not_enabled") : off("transport_required", { kind: "choose_transport", href: "/settings?section=ai-transport", requires_server_admin: true })
      : { data: { allow_http: false, allow_vpn_http: false, revision: 1 } });
    render(<Page canManage serverAdmin />);
    expect((await banner()).textContent).toContain("AI Gateway needs a transport choice first");
    fireEvent.click(screen.getByRole("button", { name: "Choose transport" }));
    const dialog = await screen.findByRole("dialog", { name: "Choose how AI Gateway is reached" });
    expect(await within(dialog).findByRole("switch", { name: "Allow HTTP inside the VPN" })).toBeTruthy();
    chosen = true;
    fireEvent.click(within(dialog).getByRole("button", { name: "Done" }));
    // The next missing thing is shown as soon as this one is fixed.
    await waitFor(async () => expect((await banner()).textContent).toContain("AI Gateway is turned off"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("transport not chosen: an organization administrator is told exactly who and where", async () => {
    api.GET.mockResolvedValue(off("transport_required"));
    render(<Page canManage serverAdmin={false} />);
    expect((await banner()).textContent).toContain("Ask a server administrator to open Settings, then AI Gateway transport, and choose how AI Gateway is reached.");
    expect(within(await banner()).queryByRole("button")).toBeNull();
  });

  it("no provider credential: links to where one is added, or opens the form on a page that has it", async () => {
    api.GET.mockResolvedValue(off("no_provider", { kind: "add_provider", href: "/ai-gateway/credentials" }));
    const page = render(<Page canManage serverAdmin={false} />);
    expect((await banner()).textContent).toContain("No provider credential yet");
    expect(screen.getByRole("link", { name: "Add a provider credential" }).getAttribute("href")).toBe("/ai-gateway/credentials");
    page.unmount();
    const add = vi.fn();
    render(<Page canManage serverAdmin={false} onAddProvider={add} />);
    fireEvent.click(await screen.findByRole("button", { name: "Add a provider credential" }));
    expect(add).toHaveBeenCalledTimes(1);
  });

  it("no provider credential: never follows a link that leaves the console", async () => {
    api.GET.mockResolvedValue(off("no_provider", { kind: "add_provider", href: "//evil.example/steal" }));
    render(<Page canManage serverAdmin={false} />);
    expect((await screen.findByRole("link", { name: "Add a provider credential" })).getAttribute("href")).toBe("/ai-gateway/credentials");
  });

  it("no provider credential: someone who cannot manage it is told who can", async () => {
    api.GET.mockResolvedValue(off("no_provider"));
    render(<Page canManage={false} serverAdmin={false} />);
    expect((await banner()).textContent).toContain("Ask an organization owner or administrator to add one under AI Gateway, LLM credentials.");
    expect(screen.queryByRole("link", { name: "Add a provider credential" })).toBeNull();
  });

  it.each([[true, "upgrade Tunnex Server on the server itself"], [false, "Only a server administrator can fix this"]] as const)("engine not installed: says who and what (server administrator=%s)", async (serverAdmin, text) => {
    api.GET.mockResolvedValue(off("engine_not_installed", { kind: "install_engine", requires_server_admin: true }));
    render(<Page canManage serverAdmin={serverAdmin} />);
    const shown = await banner();
    expect(shown.textContent).toContain("The AI engine is not installed on this server");
    expect(shown.textContent).toContain(text);
    expect(within(shown).queryByRole("button")).toBeNull();
    expect(within(shown).queryByRole("link")).toBeNull();
  });

  it("names the reason from a server that does not send a status yet", () => {
    expect(aiGatewayStatus({ enabled: false, available: false, revision: 1, unavailable_reason: "https_required" }).reason).toBe("transport_required");
    expect(aiGatewayStatus({ enabled: false, available: false, revision: 1, unavailable_reason: "engine_not_configured" }).reason).toBe("engine_not_installed");
    expect(aiGatewayStatus({ enabled: false, available: true, revision: 1 }).reason).toBe("not_enabled");
    expect(aiGatewayStatus({ enabled: true, available: true, revision: 1 }).on).toBe(true);
  });

  it("uses plain words: no internal terms and no em dash", () => {
    for (const reason of ["not_enabled", "transport_required", "no_provider", "engine_not_installed"] as const) for (const canManage of [true, false]) for (const serverAdmin of [true, false]) {
      const copy = aiGatewayOffCopy(reason, { canManage, serverAdmin });
      expect(`${copy.title} ${copy.body}`).not.toMatch(/—|backend|bifrost|installation administrator|opt-in/i);
      // One sentence says what is missing; anything after it says who fixes it.
      expect(copy.body.length).toBeGreaterThan(20);
    }
  });
});
