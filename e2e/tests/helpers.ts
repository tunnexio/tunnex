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
  await page.getByLabel("Password").fill(who.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
}
