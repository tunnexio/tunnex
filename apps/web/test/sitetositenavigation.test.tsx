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
it.each(["networks", "connectivity"] as const)("names both workspaces and marks %s current", active => {
  render(<MemoryRouter><SiteToSiteNavigation active={active} /></MemoryRouter>);
  expect(screen.getByRole("link", { name: "Networks" }).getAttribute("href")).toBe("/sites");
  expect(screen.getByRole("link", { name: "Connections" }).getAttribute("href")).toBe("/site-to-site");
  expect(screen.getByRole("link", { name: active === "networks" ? "Networks" : "Connections" }).getAttribute("aria-current")).toBe("page");
});
