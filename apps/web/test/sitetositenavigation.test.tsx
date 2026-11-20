import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { NAV_DESTINATIONS, isNavDestinationActive } from "../src/components/AppShell";
import { SiteToSiteNavigation } from "../src/components/SiteToSiteNavigation";
afterEach(cleanup);
it("groups network inventory and connectivity under one sidebar destination", () => {
  expect(NAV_DESTINATIONS.filter(item => item.to === "/sites" || item.to === "/site-to-site")).toEqual([
    expect.objectContaining({ to: "/sites", label: "Site-to-site" }),
  ]);
  expect(isNavDestinationActive("/sites", "/sites")).toBe(true);
  expect(isNavDestinationActive("/sites", "/site-to-site")).toBe(true);
  expect(isNavDestinationActive("/sites", "/site-to-site/")).toBe(true);
  expect(isNavDestinationActive("/sites", "/settings")).toBe(false);
});
// SSI-13 D1: ONE row of tabs for the whole area, on both pages.
it.each([["overview", "Networks"], ["cloud-vpn", "Cloud VPN"], ["ranges", "Ranges"]] as const)("one row of tabs, %s current", (active, label) => {
  render(<MemoryRouter><SiteToSiteNavigation active={active} /></MemoryRouter>);
  expect(screen.getAllByRole("link").map((link) => link.textContent)).toEqual(["Networks", "Map", "Ranges", "Failover", "DNS forwarding", "Cloud VPN"]);
  expect(screen.getByRole("link", { name: "Networks" }).getAttribute("href")).toBe("/sites");
  expect(screen.getByRole("link", { name: "Ranges" }).getAttribute("href")).toBe("/sites?section=ranges");
  expect(screen.getByRole("link", { name: "Cloud VPN" }).getAttribute("href")).toBe("/site-to-site");
  expect(screen.queryByRole("link", { name: "Connections" })).toBeNull();
  expect(screen.getByRole("link", { name: label }).getAttribute("aria-current")).toBe("page");
  expect(screen.getAllByRole("link").filter((link) => link.getAttribute("aria-current") === "page")).toHaveLength(1);
});
it("SSI-13 D4: Routed ranges has no sidebar entry and still lights Site-to-site", () => {
  expect(NAV_DESTINATIONS.some((item) => item.to === "/routed-ranges")).toBe(false);
  expect(isNavDestinationActive("/sites", "/routed-ranges")).toBe(true);
});
