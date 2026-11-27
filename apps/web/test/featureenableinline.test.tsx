import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, put } = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, PUT: put, POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});
let role = "owner";
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Acme" }, updateOrg: vi.fn() }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email_verified: true, must_change_password: false } } }) }));

import { FeatureEnableInline } from "../src/components/FeatureEnableInline";
import { useAgentFeatures, type AgentFeature, type AgentFeatureKey } from "../src/lib/agentFeatures";
import { resetMyOrgRolesCache } from "../src/lib/navaccess";

let items: AgentFeature[] = [];
let featureRead: () => unknown = () => ({ data: { items } });
function Harness({ feature, variant }: { feature: AgentFeatureKey; variant?: "inline" | "row" }) {
  const features = useAgentFeatures("org-a");
  return <FeatureEnableInline orgId="org-a" feature={feature} features={features} variant={variant} />;
}
const show = (feature: AgentFeatureKey, variant?: "inline" | "row") => render(<MemoryRouter><Harness feature={feature} variant={variant} /></MemoryRouter>);

beforeEach(() => {
  role = "owner"; resetMyOrgRolesCache();
  items = [{ key: "runtime_sync", enabled: false, available: true }, { key: "agent_groups", enabled: true, available: true }, { key: "mcp", enabled: false, available: true }];
  featureRead = () => ({ data: { items } });
  get.mockImplementation(async (path: string) => path.endsWith("/agent-features") ? featureRead() : path.endsWith("/members") ? { data: [{ user_id: "user-a", role, roles: [role] }] } : { data: {} });
  put.mockImplementation(async (_path: string, options: { body: { enabled: boolean } }) => ({ data: { enabled: options.body.enabled } }));
});
afterEach(() => { cleanup(); get.mockReset(); put.mockReset(); });

describe("FeatureEnableInline", () => {
  it("shows a feature that is off with one sentence and turns it on in place", async () => {
    show("runtime_sync");
    const toggle = await screen.findByRole("switch", { name: "Runtime synchronization" });
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    expect(screen.getByRole("heading", { name: "Turn on Runtime synchronization" })).toBeTruthy();
    expect(screen.getByText("Lets Tunnex install agents on your hosts and keep their settings up to date. It gives an agent no access by itself.")).toBeTruthy();
    await waitFor(() => expect((toggle as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(toggle);
    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/agent-runtime-settings", { params: { path: { orgId: "org-a" } }, body: { enabled: true } }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "Runtime synchronization" }).getAttribute("aria-checked")).toBe("true"));
    expect(screen.getByRole("heading", { name: "Runtime synchronization is on" })).toBeTruthy();
  });

  it("shows a feature that is on", async () => {
    show("agent_groups");
    expect((await screen.findByRole("switch", { name: "Agent groups & policy templates" })).getAttribute("aria-checked")).toBe("true");
    expect(screen.queryByText(/plan/i)).toBeNull();
  });

  it("gives MCP its own switch and its own endpoint", async () => {
    show("mcp");
    const toggle = await screen.findByRole("switch", { name: "MCP" });
    await waitFor(() => expect((toggle as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(toggle);
    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/mcp-settings", { params: { path: { orgId: "org-a" } }, body: { enabled: true } }));
    expect(put).toHaveBeenCalledTimes(1);
  });

  it("disables the switch and names the plan when this edition does not include the feature", async () => {
    items = [{ key: "runtime_sync", enabled: true, available: false, required_plan: "starter" }];
    show("runtime_sync");
    const toggle = await screen.findByRole("switch", { name: "Runtime synchronization" });
    expect((toggle as HTMLButtonElement).disabled).toBe(true);
    // A saved "on" that the plan cannot use is shown as off: the switch never claims a feature that does not run.
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    expect(screen.getByText(/Included in the Starter plan\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "See your plan" }).getAttribute("href")).toBe("/settings?section=licence");
    fireEvent.click(toggle);
    expect(put).not.toHaveBeenCalled();
  });

  it("explains a refusal to turn MCP off while servers are still assigned, and stays on", async () => {
    items = [{ key: "mcp", enabled: true, available: true }];
    put.mockResolvedValue({ error: { error: { code: "mcp_in_use", message: "in use" } } });
    show("mcp");
    const toggle = await screen.findByRole("switch", { name: "MCP" });
    await waitFor(() => expect((toggle as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(toggle);
    expect((await screen.findByRole("alert")).textContent).toBe("MCP is still in use. Remove the MCP servers from your agents and agent groups, then turn this off.");
    expect(screen.getByRole("switch", { name: "MCP" }).getAttribute("aria-checked")).toBe("true");
  });

  it("keeps the switch read-only for a person who may not change it", async () => {
    role = "member";
    show("mcp");
    const toggle = await screen.findByRole("switch", { name: "MCP" });
    expect(await screen.findByText("Ask an owner or administrator to change this.")).toBeTruthy();
    expect((toggle as HTMLButtonElement).disabled).toBe(true);
  });

  it("does not show a failed read as off, and reads again on request", async () => {
    featureRead = () => ({ error: { error: { code: "unavailable", message: "Service unavailable." } } });
    show("mcp");
    expect((await screen.findByRole("alert")).textContent).toBe("Could not check whether MCP is on: Service unavailable.");
    expect(screen.queryByRole("switch")).toBeNull();
    featureRead = () => ({ data: { items } });
    fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    expect(await screen.findByRole("switch", { name: "MCP" })).toBeTruthy();
  });

  it("renders the same switch as a Settings row", async () => {
    show("mcp", "row");
    expect(await screen.findByRole("switch", { name: "MCP" })).toBeTruthy();
    expect(screen.getByText("Lets agents use MCP servers through the gateway. Every tool stays off until you allow it.")).toBeTruthy();
  });
});
