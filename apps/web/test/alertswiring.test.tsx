import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, org } = vi.hoisted(() => ({ get: vi.fn(), org: { id: "org-a", name: "Acme" } }));

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org, loading: false, failed: false }),
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
    expect(screen.getByText("critical")).toBeTruthy();
  });

  it("keeps resolved history separate and queries the server state", async () => {
    get.mockResolvedValue({ data: [] });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    await screen.findByText(/No active conditions/);
    fireEvent.click(screen.getByRole("tab", { name: "history" }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith(
      "/api/v1/organizations/{orgId}/alert-occurrences",
      { params: { path: { orgId: "org-a" }, query: { state: "resolved" } } },
    ));
    expect(await screen.findByText(/No resolved alerts/)).toBeTruthy();
  });

  it("does not render a failed read as an all-clear", async () => {
    get.mockResolvedValue({ error: { error: { message: "forbidden" } } });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    expect(await screen.findByText("Could not load alerts.")).toBeTruthy();
    expect(screen.queryByText(/No active conditions/)).toBeNull();
  });
});
