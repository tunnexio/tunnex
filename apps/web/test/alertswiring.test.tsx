import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, org } = vi.hoisted(() => ({ get: vi.fn(), org: { id: "org-a", name: "Acme" } }));

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org, loading: false, failed: false }),
}));
vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email_verified: true } } }),
}));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { ...actual.api, GET: get }, apiErrorMessage: (_: unknown, fallback: string) => fallback };
});

import Alerts from "../src/pages/Alerts";

const active = {
  id: "01900000-0000-7000-8000-000000000001",
  event_key: "gateway.offline",
  dedup_key: "gateway:g-1:offline",
  resource_type: "gateway",
  resource_id: "g-1",
  resource_name: "edge-west",
  severity: "critical",
  subject: "Gateway edge-west is offline",
  fields: {},
  state: "firing",
  first_observed_at: "2026-08-29T08:00:00Z",
  last_observed_at: "2026-08-29T08:01:00Z",
  resolved_at: null,
  occurrence_count: 2,
};

afterEach(() => { cleanup(); get.mockReset(); });

describe("cross-product alerts workspace", () => {
  it("shows persistent active conditions and resource navigation", async () => {
    get.mockResolvedValue({ data: [active] });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    expect(await screen.findByRole("table", { name: "Active alerts" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "edge-west" }).getAttribute("href")).toBe("/gateways/g-1");
    expect(within(screen.getByRole("table", { name: "Active alerts" })).getByText("critical")).toBeTruthy();
  });

  it("filters severity and opens an occurrence without changing it", async () => {
    get.mockResolvedValue({ data: [active] });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    await screen.findByRole("table", { name: "Active alerts" });
    fireEvent.click(screen.getByRole("button", { name: "warning" }));
    expect(screen.getByText("No alerts match this severity.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "All severities" }));
    fireEvent.click(screen.getByRole("button", { name: /Gateway edge-west is offline/ }));
    const dialog = screen.getByRole("dialog", { name: active.subject });
    expect(within(dialog).getByText("gateway.offline")).toBeTruthy();
    expect(within(dialog).getByRole("link", { name: "Open gateway →" }).getAttribute("href")).toBe("/gateways/g-1");
    fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("keeps resolved history separate and queries the server state", async () => {
    get.mockResolvedValue({ data: [] });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    await screen.findByText(/No active conditions/);
    fireEvent.click(screen.getByRole("tab", { name: "history" }));
    await waitFor(() => expect(get).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/alert-occurrences",
      { params: { path: { orgId: "org-a" }, query: { state: "resolved" } } },
    ));
    expect(await screen.findByText(/No resolved alerts/)).toBeTruthy();
  });


  it("gives administrators a dedicated management workspace backed by existing routes and signals", async () => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }] };
      if (path.endsWith("/alerting-settings")) return { data: { enabled: true } };
      if (path.endsWith("/alert-destinations")) return { data: [] };
      if (path.endsWith("/alert-deliveries")) return { data: [] };
      return { data: [] };
    });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    const tab = await screen.findByRole("tab", { name: "management" });
    fireEvent.click(tab);
    expect(await screen.findByTestId("alert-management")).toBeTruthy();
    expect(screen.getByRole("button", { name: "New routing policy" })).toBeTruthy();
    expect(screen.getByText(/No routing policies yet/)).toBeTruthy();
  });

  it("renders existing routing policies and composes policies from the reusable signal catalog", async () => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }] };
      if (path.endsWith("/alerting-settings")) return { data: { enabled: true } };
      if (path.endsWith("/alert-destinations")) return { data: [{
        id: "destination-1",
        name: "Platform on-call",
        kind: "slack",
        endpoint_host: "hooks.slack.com",
        endpoint_fingerprint: "a1b2c3d4e5f6",
        severity_floor: "warning",
        cooldown_seconds: 900,
        archived: false,
      }] };
      if (path.endsWith("/subscriptions")) return { data: ["gateway.offline", "device.offline"] };
      if (path.endsWith("/alert-deliveries")) return { data: [] };
      return { data: [] };
    });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("tab", { name: "management" }));
    expect(await screen.findByText("Platform on-call")).toBeTruthy();
    expect(screen.getByText("2 signals")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "New routing policy" }));
    const dialog = screen.getByRole("dialog", { name: "New routing policy" });
    expect(dialog).toBeTruthy();
    expect(within(dialog).getByText("Gateways & Sites")).toBeTruthy();
    expect(within(dialog).getByText("Devices")).toBeTruthy();
    expect(within(dialog).getByText("Kubernetes")).toBeTruthy();
    expect(within(dialog).getByText("AI agents")).toBeTruthy();
    expect(within(dialog).getByLabelText("Gateway offline")).toBeTruthy();
    expect(within(dialog).getByLabelText("Device posture blocked")).toBeTruthy();
  });

  it("does not render a failed read as an all-clear", async () => {
    get.mockResolvedValue({ error: { error: { message: "forbidden" } } });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    expect(await screen.findByText("Could not load alerts.")).toBeTruthy();
    expect(screen.queryByText(/No active conditions/)).toBeNull();
  });
});
