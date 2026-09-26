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

async function inventory(page: Page) {
  await page.route(`**/api/v1/organizations/${ORG}/**`, async route => {
    if (route.request().method() !== "GET") return route.fallback();
    const path = new URL(route.request().url()).pathname;
    let body: unknown;
    if (path.endsWith("/sites")) body = sites;
    else if (path.endsWith("/nodes")) body = [];
    else if (path.endsWith("/hub-set")) body = { generation: 1, members: [] };
    else if (path.endsWith("/dns-forwards")) body = [];
    else if (path.endsWith("/subnets")) body = path.includes(sites[0].id) ? ranges : [pending];
    else if (path.endsWith("/routed-ranges")) body = { ranges: ranges.map(item => item.cidr), forwards: [] };
    else if (path.endsWith("/k8s/clusters")) body = [];
    else if (path.endsWith("/ipsec/settings")) body = { enabled: true, revision: 1 };
    else if (path.endsWith("/ipsec/connections")) body = { items: Array.from({ length: 26 }, (_, i) => ({
      id: `connection-${i}`, name: `Cloud connection ${i + 1}`, site_id: sites[0].id,
      desired_intent: i === 0 ? "enabled" : "disabled", desired_revision: 1,
      application_state: i === 0 ? "applied" : "pending", cleanup_state: "none",
    })) };
    else if (path.endsWith("/eligibility")) body = { eligible: false, reason: "unsupported" };
    else return route.fallback();
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
}

for (const width of [1440, 390]) {
  test.describe(`network workspaces at ${width}px`, () => {
    test.beforeEach(async ({ page }) => {
      await login(page, OWNER);
      await inventory(page);
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
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByRole("list", { name: "Routed ranges", exact: true }).getByRole("listitem")).toHaveCount(5);
      await dialog.getByRole("textbox", { name: "Search Routed ranges", exact: true }).fill("10.12.");
      await expect(dialog.getByRole("listitem", { name: "10.12.0.0/16: Approved, routed" })).toBeVisible();
      await noOverflow(page);
    });

    test("connection choices preserve URLs and show every loaded IPsec record", async ({ page }) => {
      await page.goto("/site-to-site?method=wireguard");
      await expect(page.getByRole("radio", { name: /^Between your networks/ })).toBeChecked();
      await page.getByRole("combobox", { name: "First network", exact: true }).selectOption(sites[0].id);
      await page.getByRole("combobox", { name: "Second network", exact: true }).selectOption(sites[1].id);
      await expect(page.getByRole("region", { name: "Office configuration" })).toBeVisible();
      await page.getByRole("link", { name: "View network topology", exact: true }).click();
      await expect(page).toHaveURL(/section=topology/);
      await page.goto("/site-to-site?method=ipsec");
      await expect(page.getByRole("radio", { name: /^To a cloud VPN/ })).toBeChecked();
      await expect(page.getByRole("button", { name: "Cloud connection 26", exact: true })).toBeVisible();
      await page.getByRole("combobox", { name: "Connection status" }).selectOption("enabled");
      await expect(page.getByRole("button", { name: "Cloud connection 1", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Cloud connection 26", exact: true })).toHaveCount(0);
      await page.reload();
      await expect(page.getByRole("radio", { name: /^To a cloud VPN/ })).toBeChecked();
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
