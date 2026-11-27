import { MemoryRouter } from "react-router-dom";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIAgentAccess, AIGroupAccess, AIUseModel } from "../src/components/AIUserAccess";
import { AIProviderWorkspace } from "../src/components/AIProviderWorkspace";
import { AIUsagePage } from "../src/components/AIUsageWorkspace";
import { AIGatewayWorkspace } from "../src/pages/AgentsAIGateway";

// What an administrator saw on a deployment where the gateway was not usable: "Could not load group
// access", "Usage is unavailable", "No models available", "Ask your installation administrator".
// Every page now shows the one banner instead, and nothing that contradicts or repeats it.
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user", email_verified: true } } }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org" }, orgs: [{ id: "org", name: "Demo" }], loading: false, failed: false }) }));
vi.mock("../src/components/Toasts", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

type Reason = "not_enabled" | "transport_required" | "no_provider" | "engine_not_installed";
const response = (status = 200) => new Response(null, { status });
const unavailable = { error: { error: { code: "ai_gateway_unavailable", message: "AI gateway is unavailable" } }, response: response(503) };
const settings = (reason: Reason | null) => ({ data: { enabled: reason !== "not_enabled", available: reason !== "engine_not_installed" && reason !== "transport_required", revision: 1, status: reason ? { on: false, reason } : { on: true, reason: null } }, response: response() });
/** Every AI Gateway read is refused, as on a server without the engine; only the settings answer. */
function gatewayDown(reason: Reason) {
  api.GET.mockImplementation(async (path: string) => path.endsWith("/ai-gateway") ? settings(reason) : unavailable);
}
const banner = () => screen.findByRole("status", { name: "AI Gateway is not ready" });
const noRawError = () => waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
const inRouter = (node: React.ReactNode) => render(<MemoryRouter>{node}</MemoryRouter>);
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

describe("no raw error or misleading empty state beside the banner", () => {
  it("Access: the banner replaces 'Could not load group access'", async () => {
    gatewayDown("engine_not_installed");
    inRouter(<AIGroupAccess orgId="org" canManage />);
    expect((await banner()).textContent).toContain("The AI engine is not installed on this server");
    await noRawError();
    expect(screen.queryByText(/Could not load group access/)).toBeNull();
    expect(screen.queryByText("No model access granted.")).toBeNull();
  });

  it("Access: a real load failure is still reported when the gateway is on", async () => {
    api.GET.mockImplementation(async (path: string) => path.endsWith("/ai-gateway") ? settings(null) : { error: { error: { code: "internal" } }, response: response(500) });
    inRouter(<AIGroupAccess orgId="org" canManage />);
    expect((await screen.findByRole("alert")).textContent).toContain("Could not load group access.");
    expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull();
  });

  it("Access, agents and agent groups: the banner replaces the load error", async () => {
    gatewayDown("transport_required");
    inRouter(<AIAgentAccess orgId="org" canManage />);
    expect((await banner()).textContent).toContain("AI Gateway needs a transport choice first");
    await noRawError();
  });

  it("Usage: the banner replaces 'Usage is unavailable'", async () => {
    gatewayDown("not_enabled");
    inRouter(<AIUsagePage orgId="org" canManage />);
    expect((await banner()).textContent).toContain("AI Gateway is turned off");
    await noRawError();
    expect(screen.queryByText("Usage is unavailable")).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry usage" })).toBeNull();
  });

  it("Usage: a real failure is still reported when the gateway is on", async () => {
    api.GET.mockImplementation(async (path: string) => path.endsWith("/ai-gateway") ? settings(null) : unavailable);
    inRouter(<AIUsagePage orgId="org" canManage />);
    expect(await screen.findByText("Usage is unavailable")).toBeTruthy();
  });

  it.each(["models", "connections"] as const)("Models and LLM credentials (%s): the banner replaces 'Ask your installation administrator'", async (view) => {
    gatewayDown("engine_not_installed");
    inRouter(<AIProviderWorkspace orgId="org" view={view} canManage />);
    expect((await banner()).textContent).toContain("Only a server administrator can fix this");
    await noRawError();
    expect(screen.queryByText(/installation administrator/)).toBeNull();
    expect(screen.queryByText(/Could not load provider connections/)).toBeNull();
  });

  it("LLM credentials: with no credential yet, the banner opens the form in place", async () => {
    api.GET.mockImplementation(async (path: string) => path.endsWith("/ai-gateway") ? settings("no_provider")
      : { data: { management_available: true, definitions: [{ id: "openai", name: "OpenAI", credential_label: "OpenAI API key", model_placeholder: "openai/gpt-4o-mini" }], items: [], legacy_key_ids: [] }, response: response() });
    inRouter(<AIProviderWorkspace orgId="org" view="connections" canManage />);
    await banner();
    fireEvent.click((await screen.findAllByRole("button", { name: "Add a provider credential" }))[0]);
    expect(await screen.findByRole("dialog")).toBeTruthy();
  });

  it("Agent model access page: the banner replaces 'Could not load AI policies'", async () => {
    gatewayDown("engine_not_installed");
    inRouter(<AIGatewayWorkspace orgId="org" canManage />);
    await banner();
    await noRawError();
    expect(screen.queryByRole("button", { name: "Retry AI policies" })).toBeNull();
  });
});

describe("'No models available' only when the gateway is on and truly has none", () => {
  const models = (list: unknown[], providers: unknown[] = []) => async (path: string) => path.endsWith("/ai-gateway") ? settings(null)
    : path.endsWith("/my-models") ? { data: list, response: response() }
    : { data: { management_available: true, items: providers, legacy_key_ids: [] }, response: response() };

  it.each(["not_enabled", "transport_required", "no_provider", "engine_not_installed"] as const)("is not shown while the gateway is off (%s)", async (reason) => {
    api.GET.mockImplementation(async (path: string) => path.endsWith("/ai-gateway") ? settings(reason) : path.endsWith("/my-models") ? { data: [], response: response() } : unavailable);
    inRouter(<AIUseModel orgId="org" canManage />);
    await banner();
    await noRawError();
    expect(screen.queryByText("No models available")).toBeNull();
    expect(screen.queryByText("No model is granted to you yet")).toBeNull();
  });

  it("is not shown when reading the models failed because the gateway is off", async () => {
    gatewayDown("engine_not_installed");
    inRouter(<AIUseModel orgId="org" />);
    await banner();
    await noRawError();
    expect(screen.queryByText(/Could not load your models/)).toBeNull();
  });

  it("is shown with the next step when the gateway is on and no model exists", async () => {
    api.GET.mockImplementation(models([]));
    inRouter(<AIUseModel orgId="org" canManage />);
    expect(await screen.findByText("No models available")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Add a model" }).getAttribute("href")).toBe("/ai-gateway/models/new");
    expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull();
  });

  it("says a model is not granted, not that none exists, when the organization has models", async () => {
    api.GET.mockImplementation(models([], [{ id: "c", models: ["openai/gpt-4o-mini"] }]));
    inRouter(<AIUseModel orgId="org" canManage />);
    expect(await screen.findByText("No model is granted to you yet")).toBeTruthy();
    expect(screen.queryByText("No models available")).toBeNull();
    expect(screen.getByRole("link", { name: "Grant model access" }).getAttribute("href")).toBe("/ai-gateway/access");
  });

  // A member may list their own models but may not read the AI Gateway settings (403). The reason comes
  // from the status the member is allowed to read, which carries only that reason.
  const forbidden = { error: { error: { code: "forbidden" } }, response: response(403) };
  const asMember = (status: unknown) => api.GET.mockImplementation(async (path: string) => path.endsWith("/my-models") ? { data: [], response: response() } : path.endsWith("/ai-gateway/status") ? status : forbidden);

  it.each([
    ["not_enabled", "AI Gateway is turned off", "Ask an organization owner or administrator to turn it on."],
    ["transport_required", "AI Gateway needs a transport choice first", "Ask a server administrator to open Settings, then AI Gateway transport, and choose how AI Gateway is reached."],
    ["no_provider", "No provider credential yet", "Ask an organization owner or administrator to add one under AI Gateway, LLM credentials."],
    ["engine_not_installed", "The AI engine is not installed on this server", "Only a server administrator can fix this"],
  ] as const)("tells a member why no model can answer (%s), in plain words and with no control", async (reason, title, ask) => {
    asMember({ data: { on: false, reason }, response: response() });
    inRouter(<AIUseModel orgId="org" />);
    const shown = await banner();
    expect(shown.textContent).toContain(title);
    expect(shown.textContent).toContain(ask);
    expect(shown.querySelector("button, a")).toBeNull();
    expect(screen.queryByText("No model is granted to you yet")).toBeNull();
    expect(api.GET).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ai-gateway/status", { params: { path: { orgId: "org" } } });
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("ignores a fix or a link in the member's status: only the reason is used", async () => {
    asMember({ data: { on: false, reason: "no_provider", fix: { kind: "add_provider", href: "/ai-gateway/credentials" } }, response: response() });
    inRouter(<AIUseModel orgId="org" />);
    expect((await banner()).querySelector("button, a")).toBeNull();
  });

  it("shows a member no banner when the gateway is on, and does not ask for the status when the settings can be read", async () => {
    asMember({ data: { on: true, reason: null }, response: response() });
    inRouter(<AIUseModel orgId="org" />);
    expect(await screen.findByText("No model is granted to you yet")).toBeTruthy();
    expect(screen.queryByRole("status", { name: "AI Gateway is not ready" })).toBeNull();
    cleanup(); api.GET.mockClear();
    api.GET.mockImplementation(models([]));
    inRouter(<AIUseModel orgId="org" canManage />);
    await screen.findByText("No models available");
    expect(api.GET.mock.calls.some(([path]) => String(path).endsWith("/ai-gateway/status"))).toBe(false);
  });

  it("tells a member who to ask, without claiming the organization has no models", async () => {
    api.GET.mockImplementation(async (path: string) => path.endsWith("/my-models") ? { data: [], response: response() } : { error: { error: { code: "forbidden" } }, response: response(403) });
    inRouter(<AIUseModel orgId="org" />);
    expect(await screen.findByText("No model is granted to you yet")).toBeTruthy();
    expect(screen.getByText("Ask an organization owner or administrator to grant a model to one of your user groups.")).toBeTruthy();
    expect(screen.queryByText("No models available")).toBeNull();
  });
});
