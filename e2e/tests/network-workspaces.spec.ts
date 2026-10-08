import { test, expect, type Page } from "@playwright/test";
import { login, OWNER, ORG } from "./helpers";

// Real sign-in and app routing; only network inventory responses are synthetic.
// This keeps the shared seed unchanged while covering populated UI in both editions.
const sites = [
  { id: "01900000-0000-7000-8000-000000009101", name: "Office" },
  { id: "01900000-0000-7000-8000-000000009102", name: "Cloud" },
];
const ranges = Array.from({ length: 13 }, (_, index) => ({
  id: `range-${index}`, site_id: sites[0].id, cidr: `10.${index}.0.0/16`, status: "approved",
}));
const pending = { id: "pending-range", site_id: sites[1].id, cidr: "10.40.0.0/16", status: "pending" };
const connections = Array.from({ length: 26 }, (_, index) => ({
  id: `01900000-0000-7000-8000-${String(9300 + index).padStart(12, "0")}`,
  org_id: ORG, name: `Cloud connection ${index + 1}`, site_id: sites[0].id,
  gateway_node_id: null, historical_site_id: sites[0].id,
  historical_gateway_node_id: "01900000-0000-7000-8000-000000009201",
  desired_intent: index === 0 ? "enabled" : "disabled", desired_revision: 1,
  application_state: index === 0 ? "applied" : "not_applied", cleanup_state: "not_required",
  deleted_at: null, finalized_at: null,
  created_at: new Date(Date.UTC(2026, 9, 7, 12) - index * 60_000).toISOString(),
  updated_at: new Date(Date.UTC(2026, 9, 7, 12) - index * 60_000).toISOString(),
}));
const connectionCursor = (id: string) => `after:${id}`;
type ConnectionRead = { limit: number; after: string | null };

async function inventory(page: Page) {
  const connectionReads: ConnectionRead[] = [];
  await page.route(`**/api/v1/organizations/${ORG}/**`, async route => {
    if (route.request().method() !== "GET") return route.fallback();
    const url = new URL(route.request().url());
    const path = url.pathname;
    let body: unknown;
    if (path.endsWith("/sites")) body = sites;
    else if (path.endsWith("/nodes")) body = [];
    else if (path.endsWith("/hub-set")) body = { generation: 1, members: [] };
    else if (path.endsWith("/dns-forwards")) body = [];
    else if (path.endsWith("/subnets")) body = path.includes(sites[0].id) ? ranges : [pending];
    else if (path.endsWith("/routed-ranges")) body = { ranges: ranges.map(item => item.cidr), forwards: [] };
    else if (path.endsWith("/k8s/clusters")) body = [];
    else if (path.endsWith("/ipsec/settings")) body = { enabled: true, revision: 1 };
    else if (path.endsWith("/ipsec/connections")) {
      // The backend accepts a bounded limit and an opaque keyset cursor. Search
      // and status are explicitly local to the displayed page, not server filters.
      const limit = Number(url.searchParams.get("limit"));
      const after = url.searchParams.get("after");
      connectionReads.push({ limit, after });
      expect([...url.searchParams.keys()].sort()).toEqual(after ? ["after", "limit"] : ["limit"]);
      expect([10, 20, 50]).toContain(limit);
      const cursorIndex = after ? connections.findIndex(item => connectionCursor(item.id) === after) : -1;
      expect(!after || cursorIndex >= 0).toBe(true);
      const start = cursorIndex + 1;
      const items = connections.slice(start, start + limit);
      body = { items, next_cursor: start + items.length < connections.length ? connectionCursor(items.at(-1)!.id) : null };
    }
    else if (path.endsWith("/eligibility")) body = { eligible: false, reason: "unsupported" };
    else return route.fallback();
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  return connectionReads;
}

async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
}

for (const width of [1440, 390]) {
  test.describe(`network workspaces at ${width}px`, () => {
    let connectionReads: ConnectionRead[];
    test.beforeEach(async ({ page }) => {
      await login(page, OWNER);
      connectionReads = await inventory(page);
      await page.setViewportSize({ width, height: 1000 });
      await page.emulateMedia({ reducedMotion: "reduce" });
    });

    test("network sections survive reload and keep detail lists bounded", async ({ page }) => {
      await page.goto("/sites");
      const nav = page.getByRole("navigation", { name: "Network management" });
      await expect(nav.getByRole("link")).toHaveCount(5);
      await nav.getByRole("link", { name: "Topology", exact: true }).click();
      await expect(page).toHaveURL(/section=topology/);
      await page.reload();
      await expect(nav.getByRole("link", { name: "Topology", exact: true })).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("figure", { name: "Site topology" })).toBeVisible();
      await nav.getByRole("link", { name: "Inventory", exact: true }).click();
      await page.getByRole("textbox", { name: "Search networks" }).fill("Office");
      await page.getByRole("table", { name: "Sites", exact: true }).getByRole("button", { name: "Office", exact: true }).click();
      const detail = page.getByRole("region", { name: "Selected Site: Office", exact: true });
      await detail.getByRole("navigation", { name: "Network detail sections" }).getByRole("button", { name: "Ranges", exact: true }).click();
      await expect(page).toHaveURL(/detail=ranges/);
      await page.reload();
      await expect(detail.getByRole("navigation", { name: "Network detail sections" }).getByRole("button", { name: "Ranges", exact: true })).toHaveAttribute("aria-current", "page");
      const rows = detail.getByRole("list", { name: "Routed ranges", exact: true }).getByRole("listitem");
      await expect(rows).toHaveCount(13);
      const pager = detail.getByRole("navigation", { name: "Table pagination", exact: true });
      await pager.getByRole("combobox", { name: "Rows per page" }).selectOption("10");
      await expect(rows).toHaveCount(10);
      const firstRanges = await rows.evaluateAll(items => items.map(item => item.getAttribute("aria-label")));
      await pager.getByRole("button", { name: "Next routed ranges", exact: true }).click();
      await expect(rows).toHaveCount(3);
      const lastRanges = await rows.evaluateAll(items => items.map(item => item.getAttribute("aria-label")));
      expect([...firstRanges, ...lastRanges]).toEqual(ranges.map(item => `${item.cidr}: Approved, routed`));
      await expect(pager.getByRole("button", { name: "Next routed ranges", exact: true })).toBeDisabled();
      await pager.getByRole("button", { name: "Previous routed ranges", exact: true }).click();
      await expect(rows).toHaveCount(10);
      expect(await rows.evaluateAll(items => items.map(item => item.getAttribute("aria-label")))).toEqual(firstRanges);
      // A local search starts at page one and the single-result pager disappears.
      await detail.getByRole("textbox", { name: "Search Routed ranges", exact: true }).fill("10.12.");
      await expect(rows).toHaveCount(1);
      await expect(detail.getByRole("listitem", { name: "10.12.0.0/16: Approved, routed" })).toBeVisible();
      await expect(pager).toHaveCount(0);
      await noOverflow(page);
      await detail.getByRole("navigation", { name: "Network breadcrumb" }).getByRole("link", { name: "Networks", exact: true }).click();
      await expect(page.getByRole("textbox", { name: "Search networks" })).toHaveValue("Office");
      await expect(page.getByRole("table", { name: "Sites", exact: true }).getByRole("button", { name: "Office", exact: true })).toBeVisible();
    });

    test("connection choices preserve URLs and IPsec cursor pages have no gaps", async ({ page }) => {
      await page.goto("/site-to-site?method=wireguard");
      await expect(page.getByRole("radio", { name: /^Between your networks/ })).toBeChecked();
      await page.getByRole("combobox", { name: "First network", exact: true }).selectOption(sites[0].id);
      await page.getByRole("combobox", { name: "Second network", exact: true }).selectOption(sites[1].id);
      await expect(page.getByRole("region", { name: "Office configuration" })).toBeVisible();
      await page.getByRole("link", { name: "View network topology", exact: true }).click();
      await expect(page).toHaveURL(/section=topology/);
      await page.goto("/site-to-site?method=ipsec");
      await expect(page.getByRole("radio", { name: /^To a cloud VPN/ })).toBeChecked();
      const rows = page.getByRole("table", { name: "IPsec connections", exact: true }).getByRole("button", { name: /^Cloud connection \d+$/ });
      const pager = page.getByRole("navigation", { name: "IPsec connection pagination", exact: true });
      await expect(rows).toHaveCount(20);
      expect(connectionReads.at(-1)).toEqual({ limit: 20, after: null });
      const firstConnections = await rows.allTextContents();
      await expect(page.getByRole("button", { name: "Cloud connection 26", exact: true })).toHaveCount(0);
      await pager.getByRole("button", { name: "Next connections", exact: true }).click();
      await expect(rows).toHaveCount(6);
      expect(connectionReads.at(-1)).toEqual({ limit: 20, after: connectionCursor(connections[19].id) });
      const lastConnections = await rows.allTextContents();
      expect([...firstConnections, ...lastConnections]).toEqual(connections.map(item => item.name));
      await expect(pager.getByRole("button", { name: "Next connections", exact: true })).toBeDisabled();
      await pager.getByRole("button", { name: "Previous connections", exact: true }).click();
      await expect(rows).toHaveCount(20);
      expect(await rows.allTextContents()).toEqual(firstConnections);
      expect(connectionReads.at(-1)).toEqual({ limit: 20, after: null });

      // Page-local filters must not hide the backend's next cursor. An empty
      // filtered tail still offers Previous and can reveal its six real records.
      await page.getByRole("combobox", { name: "Connection status" }).selectOption("enabled");
      await expect(rows).toHaveText(["Cloud connection 1"]);
      await pager.getByRole("button", { name: "Next connections", exact: true }).click();
      await expect(page.getByRole("heading", { name: "No connections match your filters.", exact: true })).toBeVisible();
      await expect(pager.getByRole("button", { name: "Previous connections", exact: true })).toBeEnabled();
      await page.getByRole("button", { name: "Clear filters", exact: true }).click();
      await expect(rows).toHaveText(lastConnections);
      await pager.getByRole("button", { name: "Previous connections", exact: true }).click();
      await expect(rows).toHaveText(firstConnections);

      // Changing the server limit starts a new cursor history; every record is
      // also reachable at ten rows, and fifty rows needs no navigation buttons.
      await pager.getByRole("combobox", { name: "Rows per page" }).selectOption("10");
      await expect(rows).toHaveCount(10);
      expect(connectionReads.at(-1)).toEqual({ limit: 10, after: null });
      const tenRowNames = await rows.allTextContents();
      await pager.getByRole("button", { name: "Next connections", exact: true }).click();
      await expect(rows).toHaveText(connections.slice(10, 20).map(item => item.name));
      expect(connectionReads.at(-1)).toEqual({ limit: 10, after: connectionCursor(connections[9].id) });
      tenRowNames.push(...await rows.allTextContents());
      await pager.getByRole("button", { name: "Next connections", exact: true }).click();
      await expect(rows).toHaveCount(6);
      expect(connectionReads.at(-1)).toEqual({ limit: 10, after: connectionCursor(connections[19].id) });
      tenRowNames.push(...await rows.allTextContents());
      expect(tenRowNames).toEqual(connections.map(item => item.name));
      await page.getByRole("button", { name: "Refresh", exact: true }).click();
      await expect(rows).toHaveText(connections.slice(0, 10).map(item => item.name));
      expect(connectionReads.at(-1)).toEqual({ limit: 10, after: null });
      await expect(pager.getByRole("button", { name: "Previous connections", exact: true })).toBeDisabled();
      await pager.getByRole("combobox", { name: "Rows per page" }).selectOption("50");
      await expect(rows).toHaveCount(26);
      expect(connectionReads.at(-1)).toEqual({ limit: 50, after: null });
      await expect(pager.getByRole("button", { name: "Previous connections", exact: true })).toHaveCount(0);
      await expect(pager.getByRole("button", { name: "Next connections", exact: true })).toHaveCount(0);
      await page.reload();
      await expect(page.getByRole("radio", { name: /^To a cloud VPN/ })).toBeChecked();
      await expect(rows).toHaveText(firstConnections);
      expect(connectionReads.at(-1)).toEqual({ limit: 20, after: null });
      await noOverflow(page);
    });

    test("address map leads the inventory and selected ranges have one diagram", async ({ page }) => {
      await page.goto("/routed-ranges");
      const map = page.getByRole("region", { name: "Address space", exact: true });
      const list = page.getByRole("region", { name: "Network destinations", exact: true });
      await expect(map).toBeVisible();
      await expect(list).toBeVisible();
      expect((await map.boundingBox())!.y).toBeLessThan((await list.boundingBox())!.y);
      await map.getByRole("button", { name: "10.40.0.0/16, 1 allocations", exact: true }).click();
      await expect(map.getByRole("region", { name: "Allocations in 10.40.0.0/16" })).toContainText("Pending approval");
      await list.getByRole("button", { name: "Next", exact: true }).click();
      await expect(list.getByRole("button", { name: "10.12.0.0/16 Published", exact: true })).toBeVisible();
      await list.getByRole("textbox", { name: "Search routing graph" }).fill("10.0.0.0");
      await list.getByRole("button", { name: "10.0.0.0/16 Published", exact: true }).click();
      await expect(page.getByRole("figure", { name: "Illustrated route, not live traffic" })).toHaveCount(1);
      await expect(page.getByRole("button", { name: "Office 10.0.0.0/16", exact: true })).toBeVisible();
      await list.getByRole("button", { name: "1 range needs approval Review", exact: true }).click();
      await expect(list.getByRole("textbox", { name: "Search routing graph" })).toHaveValue("");
      await list.getByRole("button", { name: "10.40.0.0/16 Pending approval", exact: true }).click();
      await expect(page.getByRole("button", { name: "Approval needed", exact: true })).toBeVisible();
      await expect(list.getByRole("link", { name: "Review approvals", exact: false })).toHaveAttribute("href", /section=approvals/);
      await noOverflow(page);
    });
  });
}
