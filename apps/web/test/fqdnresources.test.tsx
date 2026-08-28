import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let role = "admin";
let rows: Array<Record<string, unknown>> = [];
let cidrRows: Array<Record<string, unknown>> = [];
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role }] };
    if (path.endsWith("/fqdn-resources")) return { data: rows };
    if (path.endsWith("/resources")) return { data: cidrRows };
    return { data: [] };
  }), POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })), PUT: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })) } };
});
import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

function page(entry = "/access/resources") { return render(<MemoryRouter initialEntries={[entry]}><AccessResources /></MemoryRouter>); }
beforeEach(() => { role = "admin"; rows = []; cidrRows = []; vi.mocked(api.POST).mockClear(); });
afterEach(cleanup);

describe("FQDN resource operator index", () => {
  it("switches inventories and creates only unbound single-port drafts", async () => {
    cidrRows = [{ id: "cidr-1", name: "Private", cidr: "10.0.0.0/24", protocol: "any", port_low: null, port_high: null }];
    rows = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: 443, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 }];
    page("/access/resources?type=cidr");
    expect(await screen.findByText("Private")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "FQDN resources inventory" })).toBeNull();
    expect(screen.getAllByRole("button", { name: "Create resource" })).toHaveLength(1);

    cleanup(); page("/access/resources?type=fqdn");
    expect(await screen.findByText("Orders")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Resources inventory" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit Orders" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Bind now|Enable/ })).toBeNull();
    expect(screen.getAllByRole("button", { name: "Create resource" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Create resource" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    expect(await screen.findByRole("group", { name: "Identity" })).toBeTruthy();
    expect(screen.getByRole("group", { name: "Access scope" })).toBeTruthy();
    expect(screen.queryByRole("group", { name: "Resolver binding" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Orders" } });
    fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "orders.internal.example.com" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "single" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Save as draft" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toEqual({ params: { path: { orgId: "org-a" } }, body: { name: "Orders", fqdn: "orders.internal.example.com", label: null, protocol: "tcp", port_low: 443, port_high: 443, resolver_context: null } });
  });
  it("names row actions and leaves member capability unavailable", async () => {
    rows = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 }];
    page("/access/resources?type=fqdn"); expect(await screen.findByRole("button", { name: "Delete Orders" })).toBeTruthy();
    expect(screen.getByLabelText("FQDN status")).toBeTruthy();
    cleanup(); role = "member"; page("/access/resources?type=fqdn");
    expect(await screen.findByText(/fqdn_resource:view/)).toBeTruthy();
  });
});
