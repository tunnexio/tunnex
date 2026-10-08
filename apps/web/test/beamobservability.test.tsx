vi.mock("../src/components/TerminalReplay", () => ({ TerminalReplay: () => null }));
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import AccessEvents from "../src/pages/AccessEvents";
import AuditLog from "../src/pages/AuditLog";
import { beamAuditDetails } from "../src/lib/beam";

const fixture = vi.hoisted(() => ({ organization: { id: "11111111-1111-4111-8111-111111111111", name: "Beam fixture" }, auth: { status: "authed", user: { id: "22222222-2222-4222-8222-222222222222", email: "reviewer@example.com" } }, org: "11111111-1111-4111-8111-111111111111", user: "22222222-2222-4222-8222-222222222222", share: "33333333-3333-4333-8333-333333333333", beamDenied: false, paths: [] as string[], queries: [] as Record<string, unknown>[] }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: fixture.organization, loading: false, failed: false }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: fixture.auth }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async (path: string, options?: { params?: { query?: Record<string, unknown> } }) => {
    fixture.paths.push(path);
    const query = options?.params?.query ?? {};
    if (path.endsWith("/members")) return { data: [{ user_id: fixture.user, name: "Reviewer", email: "reviewer@example.com", role: "owner" }] };
    if (path.endsWith("/agents")) return { data: { items: [] } };
    if (path.endsWith("/access-log/health")) return { data: { retention_dropped: 0, retention_failed: false, gateway_collectors: [] } };
    if (path.endsWith("/access-events")) {
      fixture.queries.push(query);
      if (query.source !== "beam") return { error: { error: { message: "Network edition required" } } };
      if (fixture.beamDenied) return { error: { error: { message: "Beam audit permission denied" } } };
      return { data: [{ id: "44444444-4444-4444-8444-444444444444", created_at: "2026-10-06T10:00:00Z", occurred_at: "2026-10-06T10:00:00Z", seq: 0, src_ip: "", dst_ip: "", protocol: "", decision: "allow", src_user_id: fixture.user, beam: { share_id: fixture.share, action: "beam.access.allowed", reason: "admission" }, connector_token: "PRIVATE-TOKEN", target: "PRIVATE-TARGET" }] };
    }
    if (path.endsWith("/audit-logs")) { fixture.queries.push(query); return { data: [{ id: "audit-id", action: "beam.access.allowed", actor_id: fixture.user, created_at: "2026-10-06T10:00:00Z", target_type: "beam_share", target_id: fixture.share, details: { outcome: "allowed", reason: "admission", connector_token: "PRIVATE-TOKEN", target: { address: "PRIVATE-TARGET" } } }] }; }
    return { data: [] };
  }) } };
});
beforeEach(() => { fixture.queries = []; fixture.paths = []; fixture.beamDenied = false; vi.clearAllMocks(); }); afterEach(cleanup);
function show(source = "network") { return render(<MemoryRouter initialEntries={[`/access-events?source=${source}`]}><AccessEvents /></MemoryRouter>); }

describe("Unified Beam access evidence", () => {
  it("keeps Beam selectable after the default network edition rejects and requests a separate scoped source", async () => {
    show(); await screen.findByText("Network edition required");
    fireEvent.click(screen.getByRole("link", { name: "Local Sharing access" }));
    await screen.findByText(/browser reviewer Reviewer/);
    expect(fixture.queries.at(-1)).toEqual(expect.objectContaining({ source: "beam", limit: 21 }));
    expect(screen.queryByText("Network edition required")).toBeNull();
    expect(screen.queryByLabelText("Gateway collector status")).toBeNull();
  });
  it("withholds gateway flow claims and secret fields from Beam details while preserving durable evidence", async () => {
    show("beam"); fireEvent.click(await screen.findByRole("button", { name: "View ALLOW event details" }));
    const dialog = screen.getByRole("navigation", { name: "Access event breadcrumb" }).parentElement!;
    expect(within(dialog).getByText(/Gateway addresses, flow sequence/)).toBeTruthy();
    expect(within(dialog).getByText(fixture.share)).toBeTruthy();
    expect(within(dialog).getByRole("link", { name: "Share history and health" }).getAttribute("href")).toBe(`/beam/shares/${fixture.share}`);
    expect(dialog.textContent).not.toMatch(/PRIVATE|sequence 0|Policy hash|Source config/);
    expect(fixture.paths.some(path => path.endsWith("/devices") || path.endsWith("/agents") || path.endsWith("/access-log/health"))).toBe(false);
  });
  it("does not treat denied Beam event access as an empty history", async () => {
    fixture.beamDenied = true; show("beam"); await screen.findByText("Beam audit permission denied");
    expect(screen.queryByText("No retained Local Sharing access events match the current filters.")).toBeNull();
    expect(screen.queryByRole("button", { name: "View ALLOW event details" })).toBeNull();
  });
  it("applies share and reviewer filters on the server without changing network defaults", async () => {
    show("beam"); await screen.findByText(/browser reviewer Reviewer/);
    fireEvent.click(screen.getByText("More filters"));
    fireEvent.change(screen.getByRole("textbox", { name: "Share ID" }), { target: { value: fixture.share } });
    fireEvent.click(screen.getByRole("button", { name: "Filter share" }));
    await waitFor(() => expect(fixture.queries.at(-1)).toEqual(expect.objectContaining({ source: "beam", share_id: fixture.share })));
    fireEvent.change(screen.getByRole("combobox", { name: "Source identity" }), { target: { value: `person:${fixture.user}` } });
    await waitFor(() => expect(fixture.queries.at(-1)).toEqual(expect.objectContaining({ source: "beam", src_user_id: fixture.user, share_id: fixture.share })));
  });
});

describe("Beam Audit Log integration", () => {
  it("applies a typed Beam target filter and shows only redacted metadata in details", async () => {
    render(<MemoryRouter><AuditLog /></MemoryRouter>);
    await screen.findByRole("table", { name: "Audit events" });
    fireEvent.click(screen.getByText("More filters"));
    const activity = await screen.findByRole("button", { name: "Local Sharing activity" }); fireEvent.click(activity);
    await waitFor(() => expect(fixture.queries.at(-1)).toEqual(expect.objectContaining({ target_type: "beam_share" })));
    fireEvent.click(await screen.findByRole("button", { name: "Inspect beam.access.allowed audit event" }));
    const dialog = await screen.findByRole("region", { name: "Audit evidence" });
    expect(dialog.textContent).toContain("admission"); expect(dialog.textContent).not.toMatch(/PRIVATE|connector_token/);
    expect(within(dialog).getByRole("link", { name: "Share history and health" })).toBeTruthy();
  });
  it("refuses unknown or nested detail fields in the Beam audit projection", () => {
    expect(beamAuditDetails({ reason: "admission", authority_version: 3, generation: "generation", ca_pem: "PRIVATE", outcome: { token: "PRIVATE" } })).toEqual([["reason", "admission"], ["authority_version", 3], ["generation", "generation"]]);
  });
});
