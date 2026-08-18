import { expect, type Page } from "@playwright/test";

// Shared e2e fixtures + login flow, imported by settings.spec.ts (open) and
// settings.enterprise.spec.ts (enterprise) so the login path is defined ONCE —
// a change to the post-login heading, the Settings nav link, or the seed
// credentials updates both suites together instead of drifting.
export const OWNER = { email: "owner@demo.tunnex.local", pass: "tunnex-demo-password" };
export const MEMBER = { email: "member@demo.tunnex.local", pass: "tunnex-demo-password" };
export const ORG = "01900000-0000-7000-8000-000000000001"; // seeddata.DemoOrgID

// login signs in and lands on Settings (both suites start there).
export async function login(page: Page, who: { email: string; pass: string }) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password", { exact: true }).fill(who.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
}

/**
 * Opens a settings SECTION. The page shows ONE section at a time (F-settings rail), so any assertion about
 * a section's contents has to select it first — the same click a person makes.
 *
 * Defined here rather than per-spec so a change to the rail updates both suites together, which is the same
 * reason `login` lives here.
 */
export async function openSection(page: Page, name: string) {
  await page.getByRole("tab", { name, exact: true }).click();
  await expect(page.getByRole("tabpanel")).toHaveCount(1);
}

/**
 * Opens a setting's edit dialog by the row's action button and waits for the dialog to be present.
 *
 * ⚠ THE DIALOG IS A PORTAL. `Modal` renders into document.body, so it is NOT inside the section panel —
 * a locator scoped to the panel will never find it.
 */
export async function openRowDialog(page: Page, action: string) {
  await page.getByRole("button", { name: action, exact: true }).click();
}

