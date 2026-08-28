import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let role = "admin";
let rows: Array<Record<string, unknown>> = [];
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role }] };
    if (path.endsWith("/fqdn-resources/setting")) return { data: { enabled: false } };
    if (path.endsWith("/fqdn-resources")) return { data: rows };
    if (path.endsWith("/sites")) return { data: [{ id: "site-a", name: "HQ" }] };
    if (path.endsWith("/nodes")) return { data: [{ id: "gateway-a", name: "HQ gateway", status: "active", enrolled_kind: "gateway", site_id: "site-a" }] };
    return { data: [] };
  }), POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })), PUT: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })) } };
});
import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

function page() { return render(<MemoryRouter><AccessResources /></MemoryRouter>); }
beforeEach(() => { role = "admin"; rows = []; vi.mocked(api.POST).mockClear(); });
afterEach(cleanup);

describe("FQDN resource operator index", () => {
  it("uses one create choice and saves a resolver-free draft", async () => {
    page(); fireEvent.click(await screen.findByRole("button", { name: "Create resource" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    expect(await screen.findByRole("group", { name: "Identity" })).toBeTruthy();
    expect(screen.getByRole("group", { name: "Access scope" })).toBeTruthy();
    expect(screen.getByRole("group", { name: "Resolver binding" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Orders" } });
    fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "orders.internal.example.com" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Save as draft" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toMatchObject({ body: { resolver_context: null } });
  });
  it("names row actions and leaves member capability unavailable", async () => {
    rows = [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 }];
    page(); expect(await screen.findByRole("button", { name: "Edit Orders" })).toBeTruthy();
    expect(screen.getByLabelText("FQDN status")).toBeTruthy();
    cleanup(); role = "member"; page();
    expect(await screen.findByText(/fqdn_resource:view/)).toBeTruthy();
  });
});
