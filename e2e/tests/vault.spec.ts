import { test, expect, type Page } from "@playwright/test";
import { MEMBER, OWNER } from "./helpers";

// VAULT-UX-1 V20: the whole shared-credential path on a real stack. An administrator quick-generates a
// password, adds its details and assigns it to a member; the member opens it through the step-up (the
// seeded accounts have a local password and no authenticator, so the step-up is the password prompt) and
// cannot assign, edit details or delete it; the administrator deletes it. Serial: one credential, one story.
test.describe.configure({ mode: "serial" });
// The stack is served over plain HTTP inside the compose network; production is HTTPS. Treat the origin as
// secure so the clipboard behaves as it does for a real operator.
test.use({ launchOptions: { args: [`--unsafely-treat-insecure-origin-as-secure=${process.env.E2E_BASE_URL ?? "http://localhost"}`] } });

const TITLE = `E2E shared login ${Date.now()}`;

async function signIn(page: Page, who: { email: string; pass: string }) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password", { exact: true }).fill(who.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Vault", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Vault", level: 1 })).toBeVisible();
}

test("an administrator quick-generates, adds details and assigns to a member", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await signIn(page, OWNER);
  await page.getByRole("button", { name: "Quick generate" }).click();
  const quick = page.getByRole("dialog", { name: "Quick generate" });
  await expect(quick.getByText(/Saving keeps this password in your Vault/)).toBeVisible();
  await quick.getByRole("button", { name: "Save & copy" }).click();
  // Headless Chromium may refuse the clipboard write even with permission; the save is what this story
  // proves. A saved-but-not-copied password closes without the discard prompt.
  const savedOnly = quick.getByText("Saved to Vault, but the password could not be copied. Try Save & copy again.");
  await expect(quick.or(savedOnly).first()).toBeVisible();
  if (await savedOnly.isVisible().catch(() => false)) await quick.getByRole("button", { name: "Close" }).click();
  await expect(quick).toHaveCount(0);
  await page.getByRole("button", { name: "Add details for Generated password" }).first().click();
  const details = page.getByRole("dialog", { name: "Add details" });
  await details.getByLabel("Title", { exact: true }).fill(TITLE);
  await details.getByLabel("Visibility").selectOption("assigned");
  const service = details.getByLabel("Service", { exact: true });
  if (await service.locator("option", { hasText: "E2E service" }).count() === 0) {
    await details.getByRole("button", { name: "Add a service to the catalog" }).click();
    await details.getByLabel("New service name").fill("E2E service");
    await details.getByRole("button", { name: "Add service" }).click();
  } else {
    await service.selectOption({ label: "E2E service" });
  }
  await details.getByLabel("User", { exact: true }).selectOption({ label: `Demo Member (${MEMBER.email})` });
  await details.getByRole("button", { name: "Save details" }).click();
  await expect(details).toHaveCount(0);
  await expect(page.getByRole("button", { name: TITLE, exact: true })).toBeVisible();
});

test("the member reveals it through the step-up and cannot administer it", async ({ page }) => {
  await signIn(page, MEMBER);
  await page.getByRole("button", { name: "Shared with me" }).click();
  await page.getByRole("button", { name: TITLE, exact: true }).click();
  const drawer = page.getByRole("dialog", { name: TITLE });
  await expect(drawer.getByRole("button", { name: "Delete credential" })).toHaveCount(0);
  await expect(drawer.getByRole("button", { name: "Edit details" })).toHaveCount(0);
  await drawer.getByRole("button", { name: "Reveal current secret" }).click();
  await expect(drawer.getByText(/Enter your current password/)).toBeVisible();
  await drawer.getByLabel("Current password").fill(MEMBER.pass);
  await drawer.getByRole("button", { name: "Reveal current secret" }).click();
  await expect(drawer.getByLabel("Revealed secret")).not.toHaveText("••••••••••••••••");
  await expect(drawer.getByLabel("Revealed secret")).toHaveText(/.{24}/);
  await drawer.getByRole("button", { name: "Close" }).first().click();
  await page.getByRole("button", { name: "Add credential" }).click();
  await expect(page.getByRole("dialog", { name: "Add credential" }).getByLabel("Visibility").locator("option", { hasText: "Assigned" })).toHaveCount(0);
});

test("the administrator deletes it", async ({ page }) => {
  await signIn(page, OWNER);
  await page.getByRole("button", { name: TITLE, exact: true }).click();
  await page.getByRole("dialog", { name: TITLE }).getByRole("button", { name: "Delete credential" }).click();
  await page.getByRole("dialog", { name: "Delete credential" }).getByRole("button", { name: "Confirm deletion" }).click();
  await expect(page.getByRole("button", { name: TITLE, exact: true })).toHaveCount(0);
});
