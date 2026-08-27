import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let fqdnResources: Array<Record<string, unknown>> = [];
let role = "admin";
let impact: Record<string, unknown> = { resource_id: "fqdn-1", referencing_rule_count: 2, generation_withdrawal_required: true };

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role }] };
    if (path.endsWith("/fqdn-resources/setting")) return { data: { enabled: false } };
    if (path.endsWith("/impact")) return { data: impact };
    if (path.endsWith("/fqdn-resources")) return { data: fqdnResources };
    if (path.endsWith("/sites")) return { data: [{ id: "site-a", name: "HQ" }] };
    if (path.endsWith("/nodes")) return { data: [{ id: "gateway-a", name: "HQ gateway", status: "active", enrolled_kind: "gateway", site_id: "site-a" }] };
    if (path.endsWith("/resources")) return { data: [] };
    return { data: [] };
  }), POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })) } };
});

import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

function page() { return render(<MemoryRouter><AccessResources /></MemoryRouter>); }
beforeEach(() => { role = "admin"; impact = { resource_id: "fqdn-1", referencing_rule_count: 2, generation_withdrawal_required: true }; fqdnResources = []; vi.mocked(api.POST).mockClear(); vi.mocked(api.DELETE).mockClear(); });
afterEach(cleanup);

describe("FQDN access resources", () => {
  it("renders server state metadata and never turns a stale answer count into zero", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "stale", answer_count: 7, resolver_context: { site_id: "site-a", site_name: "HQ", gateway_id: "gateway-a", gateway_name: "HQ gateway" }, generation: null, effective_ttl_seconds: null, refreshed_at: null, last_good_at: "2026-08-27T10:00:00Z" }];
    page();
    await screen.findByText("Orders");
    expect(screen.getByText("Not available")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Orders" }));
    expect(await screen.findByText("Last good")).toBeTruthy();
    expect(screen.getByText("2026-08-27T10:00:00Z")).toBeTruthy();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("uses only an explicit selected Site/Gateway context and sends port scope", async () => {
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Create FQDN resource" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Orders" } });
    fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "orders.internal.example.com" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "single" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443" } });
    fireEvent.change(screen.getByLabelText("Resolver site (optional)"), { target: { value: "site-a" } });
    await screen.findByRole("option", { name: "HQ gateway" });
    fireEvent.change(screen.getByLabelText("Gateway"), { target: { value: "gateway-a" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toMatchObject({ body: { fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, resolver_context: { site_id: "site-a", gateway_id: "gateway-a" } } });
  });

  it("requires the server impact before allowing deletion", async () => {
    fqdnResources = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "any", state: "healthy", answer_count: 2, resolver_context: null, generation: 3 }];
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    expect(await screen.findByText(/Server impact: 2 referencing rules/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Delete FQDN resource" }) as HTMLButtonElement).disabled).toBe(true);
    expect(vi.mocked(api.DELETE)).not.toHaveBeenCalled();
  });
});
