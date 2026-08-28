import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let orgId = "org-a";
let role = "admin";
let membershipError = "";
let inventoryError = "";
let rows: Array<Record<string, unknown>> = [];
let impacts: Record<string, Promise<unknown> | unknown> = {};

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: orgId, name: orgId } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: {
    GET: vi.fn(async (path: string, options?: { params?: { path?: { orgId?: string; resourceId?: string } } }) => {
      if (path.endsWith("/members")) return membershipError ? { error: { error: { message: membershipError } } } : { data: [{ user_id: "user-a", role }] };
      if (path.endsWith("/impact")) return await impacts[options?.params?.path?.resourceId ?? ""];
      if (path.endsWith("/fqdn-resources")) return inventoryError ? { error: { error: { message: inventoryError } } } : { data: rows.filter((row) => row.org_id === undefined || row.org_id === options?.params?.path?.orgId) };
      if (path.endsWith("/resources")) return { data: [] };
      return { data: [] };
    }),
    POST: vi.fn(async () => ({ data: {} })), PATCH: vi.fn(async () => ({ data: {} })), PUT: vi.fn(async () => ({ data: {} })), DELETE: vi.fn(async () => ({ data: {} })),
  } };
});

import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

const row = (id: string, name = id) => ({ id, name, fqdn: `${id}.example.com`, protocol: "tcp", port_low: 443, port_high: null, state: "healthy", answer_count: 1, resolver_context: null, generation: 1 });
const clearImpact = (id: string) => ({ data: { referencing_rule_count: 0, referencing_rule_ids: [], generation_withdrawal_required: false, resource_id: id } });
function page() { return render(<MemoryRouter initialEntries={["/access/resources?type=fqdn"]}><AccessResources /></MemoryRouter>); }

beforeEach(() => { orgId = "org-a"; role = "admin"; membershipError = ""; inventoryError = ""; rows = []; impacts = {}; Object.values(api).forEach((method) => vi.mocked(method).mockClear()); });
afterEach(cleanup);

describe("FQDN resource regressions", () => {
  it("keeps membership lookup failure retryable and distinct from permission denial", async () => {
    membershipError = "members unavailable";
    page();
    expect(await screen.findByText(/Could not check resource permissions: members unavailable/)).toBeTruthy();
    expect(screen.queryByText(/do not have permission|lacks fqdn_resource:view/i)).toBeNull();
    membershipError = "";
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "FQDN resources" })).toBeTruthy();
  });

  it("keeps a failed inventory out of the empty state and has one FQDN search control", async () => {
    inventoryError = "inventory down";
    page();
    expect(await screen.findByText(/Could not load FQDN resources: inventory down/)).toBeTruthy();
    expect(screen.queryByText(/No FQDN resources yet/)).toBeNull();
    inventoryError = "";
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findAllByText(/No FQDN resources yet/);
    expect(screen.getAllByRole("textbox", { name: "Search FQDN resources" })).toHaveLength(1);
    expect(screen.queryByRole("textbox", { name: "Search resources" })).toBeNull();
  });

  it("binds deletion impact to its resource during out-of-order A-to-B responses", async () => {
    rows = [row("a", "Alpha"), row("b", "Beta")];
    let resolveA!: (value: unknown) => void;
    impacts.a = new Promise((resolve) => { resolveA = resolve; });
    impacts.b = clearImpact("b");
    page();
    fireEvent.click((await screen.findAllByRole("button", { name: "Delete Alpha" }))[0]);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Delete Beta" })[0]);
    await screen.findByText(/Server impact: 0 referencing rules/);
    resolveA(clearImpact("a"));
    await Promise.resolve();
    expect(screen.getByText(/Server impact: 0 referencing rules/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Delete FQDN resource" }));
    await waitFor(() => expect(vi.mocked(api.DELETE)).toHaveBeenCalled());
    expect(vi.mocked(api.DELETE).mock.calls[0][1]).toMatchObject({ params: { path: { resourceId: "b" } } });
  });

  it("keeps deletion impact errors retryable and recovers POST/DELETE failures", async () => {
    rows = [row("a", "Alpha")]; impacts.a = { error: { error: { message: "impact down" } } };
    page();
    fireEvent.click((await screen.findAllByRole("button", { name: "Delete Alpha" }))[0]);
    expect(await screen.findByText(/Server deletion impact could not be loaded: impact down/)).toBeTruthy();
    impacts.a = clearImpact("a"); fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText(/Server impact: 0 referencing rules/);
    vi.mocked(api.DELETE).mockResolvedValueOnce({ error: { error: { message: "delete down" } } } as never);
    fireEvent.click(screen.getByRole("button", { name: "Delete FQDN resource" }));
    expect((await screen.findAllByText("delete down")).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Delete FQDN resource" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Create resource" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New" } }); fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "new.example.com" } });
    vi.mocked(api.POST).mockResolvedValueOnce({ error: { error: { message: "post down" } } } as never);
    fireEvent.click(screen.getByRole("button", { name: "Save as draft" }));
    expect((await screen.findAllByText("post down")).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Save as draft" })).toBeTruthy();
  });

  it("isolates organization rows and preserves stale/no-zero and all/single/range truth", async () => {
    rows = [
      { ...row("stale", "Stale"), state: "stale", answer_count: 7, org_id: "org-a" },
      { ...row("all", "All"), port_low: null, port_high: null, org_id: "org-a" },
      { ...row("range", "Range"), protocol: "udp", port_low: 53, port_high: 55, org_id: "org-a" },
      { ...row("other", "Other"), org_id: "org-b" },
    ];
    const rendered = page();
    expect(await screen.findByText("Not available")).toBeTruthy(); expect(screen.queryByText("0")).toBeNull();
    expect(screen.getAllByText("TCP, all ports").length).toBeGreaterThan(0); expect(screen.getAllByText("TCP port 443").length).toBeGreaterThan(0); expect(screen.getAllByText("UDP ports 53–55").length).toBeGreaterThan(0);
    orgId = "org-b"; rendered.rerender(<MemoryRouter initialEntries={["/access/resources?type=fqdn"]}><AccessResources /></MemoryRouter>);
    expect((await screen.findAllByText("Other")).length).toBeGreaterThan(0); expect(screen.queryByText("Stale")).toBeNull();
  });

  it("uses bounded draft POSTs and never calls FQDN PATCH, PUT, or setting endpoints", async () => {
    page(); fireEvent.click(await screen.findByRole("button", { name: "Create resource" })); fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create FQDN resource" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Range" } }); fireEvent.change(screen.getByLabelText("Exact hostname"), { target: { value: "range.example.com" } }); fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "udp" } }); fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "range" } }); fireEvent.change(screen.getByLabelText("Port"), { target: { value: "1" } }); fireEvent.change(screen.getByLabelText("Through"), { target: { value: "65535" } });
    fireEvent.click(screen.getByRole("button", { name: "Save as draft" })); await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toMatchObject({ body: { port_low: 1, port_high: 65535, resolver_context: null } });
    expect(vi.mocked(api.PATCH)).not.toHaveBeenCalled(); expect(vi.mocked(api.PUT)).not.toHaveBeenCalled();
    expect((vi.mocked(api.GET).mock.calls as unknown[][]).some((call) => String(call[0]).includes("/setting"))).toBe(false);
  });
});
