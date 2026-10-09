import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { CrossGatewaySettings } from "../src/components/CrossGatewaySettings";
import type { Org } from "../src/lib/api";

const api = vi.hoisted(() => ({ PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
const org: Org = { id: "org-a", name: "Org", slug: "org", pool_cidr: "10.99.0.0/24", max_agent_identities: null, managed_agent_runtime_enabled: false, agent_policy_templates_enabled: false, agent_jit_access_enabled: false, created_at: "", updated_at: "" };
const saved = vi.fn();
const show = (canEdit = true, enabled = false) => render(<CrossGatewaySettings org={{ ...org, cross_gateway_clients_enabled: enabled }} canEdit={canEdit} onSaved={saved} />);
const toggle = () => screen.getByRole("switch", { name: "Cross-gateway client connectivity" }) as HTMLButtonElement;
beforeEach(() => { vi.resetAllMocks(); });
afterEach(cleanup);

it("defaults off and explains connectivity prerequisites and retained policy", () => {
  show(); expect(toggle().getAttribute("aria-checked")).toBe("false");
  expect(screen.getByText(/Connect clients across gateways/).textContent).toContain("Zero Trust rules still apply");
  expect(screen.getByText(/a reachable WireGuard endpoint is required/)).toBeTruthy();
  expect(api.PUT).not.toHaveBeenCalled();
});
it("requires permission to change the setting", () => {
  show(false); expect(toggle().disabled).toBe(true); fireEvent.click(toggle()); expect(api.PUT).not.toHaveBeenCalled();
});
it("uses server acknowledgement and disables duplicate saves while pending", async () => {
  let complete!: (result: unknown) => void;
  api.PUT.mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
  show(); fireEvent.click(toggle());
  expect(toggle().disabled).toBe(true); expect(saved).not.toHaveBeenCalled();
  expect(api.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/cross-gateway-settings", { params: { path: { orgId: org.id } }, body: { enabled: true } });
  await act(async () => complete({ data: { enabled: true } }));
  expect(saved).toHaveBeenCalledWith({ ...org, cross_gateway_clients_enabled: true });
});
it("withholds the switch after an unconfirmed disable and offers authoritative reload", async () => {
  api.PUT.mockResolvedValue({ error: { error: { message: "Save failed" } } });
  show(true, true); fireEvent.click(toggle()); await screen.findByText("Save failed");
  expect(api.PUT.mock.calls[0][1].body.enabled).toBe(false);
  expect(screen.queryByRole("switch", { name: "Cross-gateway client connectivity" })).toBeNull();
  expect(screen.getByText("Unavailable")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Reload connectivity setting" })).toBeTruthy();
  expect(saved).not.toHaveBeenCalled();
});
