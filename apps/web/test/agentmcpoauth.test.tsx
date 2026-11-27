import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AgentMCPOAuthPanel } from "../src/components/AgentMCPControls";

const state = vi.hoisted(() => ({ connections: [] as Array<Record<string, unknown>>, del: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", () => ({
  api: { GET: vi.fn(), POST: (...args: unknown[]) => state.post(...args), DELETE: (...args: unknown[]) => state.del(...args) },
  apiErrorCode: () => "", apiErrorMessage: () => "",
  loadOne: async () => ({ ok: true, data: state.connections }),
}));

const inventory = { snapshot: { oauth_discovery: { servers: [{ endpoint: "https://mcp.example/rpc", status: "protected", protected_resource: "https://mcp.example/resource", authorization_servers: ["https://issuer.example"], scopes_supported: ["tools:read", "tools:call"] }] } } } as never;
const connection = (over: Record<string, unknown>) => ({ id: "c1", endpoint: "https://mcp.example/rpc", protected_resource: "https://mcp.example/resource", issuer: "https://issuer.example", scopes: ["tools:read"], client_id: "client", state: "connected", failure_code: null, token_expires_at: null, created_at: "", updated_at: "", ...over });
const show = (outcome?: string) => render(<AgentMCPOAuthPanel orgId="org" deviceId="agent" inventory={inventory} canManage outcome={outcome} />);

beforeEach(() => { state.connections = []; state.del.mockReset().mockResolvedValue({ response: { ok: true } }); state.post.mockReset(); });
afterEach(cleanup);

it("shows the redirect address to register and offers the server's scopes", async () => {
  show();
  expect(await screen.findByText(`${window.location.origin}/api/v1/mcp/oauth/callback`)).toBeTruthy();
  expect((screen.getByLabelText("Requested scopes") as HTMLInputElement).value).toBe("tools:read tools:call");
});

it("says a rejected sign-in needs connecting again instead of reading as connected", async () => {
  state.connections = [connection({ state: "expired", failure_code: "refresh_rejected" })];
  show();
  expect(await screen.findByText(/sign-in is no longer accepted/i)).toBeTruthy();
  expect(screen.queryByText(/^Connected/)).toBeNull();
  expect(screen.getByRole("button", { name: "Connect again" })).toBeTruthy();
});

it("disconnects a connected server only after confirming", async () => {
  state.connections = [connection({})];
  show();
  fireEvent.click(await screen.findByRole("button", { name: "Disconnect" }));
  expect(state.del).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Disconnect now" }));
  await waitFor(() => expect(state.del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-oauth-connections/{connectionId}", { params: { path: { orgId: "org", deviceId: "agent", connectionId: "c1" } } }));
});

it("explains the result of returning from the sign-in page", async () => {
  show("expired");
  expect(await screen.findByText(/sign-in was not completed in the browser that started it/i)).toBeTruthy();
  cleanup();
  show("connected");
  expect(await screen.findByText(/sign-in completed/i)).toBeTruthy();
});

describe("where the sign-in token is kept", () => {
  const panel = (enforcement?: string) => render(<AgentMCPOAuthPanel orgId="org" deviceId="agent" inventory={inventory} canManage enforcement={enforcement as never} />);
  const gateway = "This MCP server asks for a sign-in. Tunnex keeps the sign-in here on the server. The sign-in token stays with the gateway, which uses it for one call at a time; it is never stored on or sent to the agent's host. Nothing is shown on this page.";
  const olderRuntime = "This MCP server asks for a sign-in. Tunnex keeps the sign-in here on the server. This agent's runtime is an older version, so a short-lived token is handed to the runtime, which holds it in memory only. Once the runtime is updated, the token stays with the gateway and no longer reaches the agent's host. Nothing is shown on this page.";

  it("says the token stays with the gateway when the gateway applies the tool rules", async () => {
    panel("gateway");
    expect(await screen.findByText(gateway)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/hands the agent|token in memory|handed to/);
  });

  it("says the token is handed to the runtime in memory while the agent is on the older runtime", async () => {
    panel("agent_host");
    expect(await screen.findByText(olderRuntime)).toBeTruthy();
  });

  it.each([["the server did not say", undefined], ["MCP is withheld", "unavailable"]])("claims neither when %s", async (_label, enforcement) => {
    panel(enforcement);
    expect(await screen.findByText("This MCP server asks for a sign-in. Tunnex keeps the sign-in here on the server. Nothing is shown on this page or written to disk on the agent's host.")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/stays with the gateway|in memory/);
  });

  it("does not say the agent holds or sends the credential when the sign-in fails or is disconnected", async () => {
    state.connections = [connection({ state: "expired", failure_code: "token_expired" })];
    panel("gateway");
    expect(await screen.findByText("The MCP server's sign-in has expired and cannot be renewed. No credential is used for this agent's calls until you connect again.")).toBeTruthy();
    cleanup();
    state.connections = [connection({})];
    panel("gateway");
    fireEvent.click(await screen.findByRole("button", { name: "Disconnect" }));
    expect(screen.getByText("This agent's calls to this MCP server stop carrying a credential straight away. You can connect again later.")).toBeTruthy();
  });
});
