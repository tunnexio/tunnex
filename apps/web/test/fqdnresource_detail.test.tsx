import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a", name: "Org A" } }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a" } } }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: vi.fn(async () => ({ data: [{ id: "fqdn-1", name: "Orders", fqdn: "orders.internal.example.com", protocol: "tcp", port_low: 443, port_high: null, state: "stale", answer_count: 7, resolver_context: { site_id: "site-a", site_name: "HQ", gateway_id: "gateway-a", gateway_name: "HQ gateway" }, generation: null, effective_ttl_seconds: null, refreshed_at: null, last_good_at: "2026-08-27T10:00:00Z" }] })) } };
});

import { FQDNResourceDetail } from "../src/pages/AccessResources";

describe("FQDN resource detail route", () => {
  it("keeps index controls in the back URL and names unavailable server projections", async () => {
    render(<MemoryRouter initialEntries={[{ pathname: "/access/resources/fqdn/fqdn-1", search: "?q=orders&status=stale&sort=name&dir=asc", state: { from: "/access/resources?q=orders&status=stale&sort=name&dir=asc" } }]}><Routes><Route path="/access/resources/fqdn/:resourceId" element={<FQDNResourceDetail />} /></Routes></MemoryRouter>);
    expect(await screen.findByRole("heading", { name: "Orders" })).toBeTruthy();
    expect(screen.getByLabelText("Stale — last result is not current")).toBeTruthy();
    expect(screen.getByText("Unavailable — no active generation")).toBeTruthy();
    expect(screen.getByText(/Rule impact and audit evidence are unavailable/i)).toBeTruthy();
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "Resources" }).getAttribute("href")).toBe("/access/resources?q=orders&status=stale&sort=name&dir=asc");
  });
});
