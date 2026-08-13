import { test, expect } from "@playwright/test";

// ⭐ REWRITTEN AGAINST THE PRODUCT AS IT IS (S12.11), not deleted. Public signup is closed (founder-ruled):
// a self-hosted control plane is owned by ONE COMPANY, install mints the deployment administrator, and
// everyone else arrives by INVITATION. `POST /api/v1/auth/signup` now answers `403 signup_closed`.
//
// ⛔ THE PROPERTY THE OLD SPEC PROTECTED SURVIVES THE RULING, WHICH IS WHY IT WAS REWRITTEN RATHER THAN
// DROPPED. "This screen must not tell you whether an account exists" does not stop mattering when signup
// closes — a refusal that varies by email leaks the same directory, and a newly-closed door is a NEW place
// for that tell to appear. What changed is which answer both emails must produce, not whether they must
// match.

// S4.2 auth screens. The demo owner (owner@demo.tunnex.local) is seeded, so it
// is a KNOWN-existing email for the enumeration-resistance check.
const EXISTING_EMAIL = "owner@demo.tunnex.local";

test("signup is closed, and refuses a new and an existing email identically (no enumeration tell)", async ({
  page,
}) => {
  const refusal = async (email: string) => {
    await page.goto("/signup");
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password").fill("a-strong-passphrase-123");
    await page.getByRole("button", { name: "Create account" }).click();
    // The server's own words, surfaced by the page — never "that account already exists".
    await expect(page.getByText(/invitation/i)).toBeVisible();
    return page.locator("main").textContent();
  };

  const fresh = await refusal(`nobody-${Date.now()}@example.com`);
  const existing = await refusal(EXISTING_EMAIL);

  // ⛔ IDENTICAL, NOT MERELY BOTH-REFUSED. A different verb, an extra sentence, a distinguishable delay —
  // any of them turns this form into a probe that answers "is this person one of yours" for anybody who
  // can reach the login page.
  expect(existing).toBe(fresh);
  // And neither created an account: the confirmation the old open flow ended on must not appear.
  await expect(
    page.getByRole("heading", { name: "Check your email" }),
  ).toHaveCount(0);
});

test("login shows a generic invalid-credentials message (no account enumeration)", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(EXISTING_EMAIL);
  await page.getByLabel("Password").fill("definitely-the-wrong-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  // Server keeps this generic ("invalid email or password") — never "wrong password".
  await expect(page.getByText(/invalid email or password/i)).toBeVisible();
});

test("open edition hides SSO on the login page", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  // The open build advertises no SSO providers, so no SSO section renders.
  await expect(page.getByText("Or sign in with SSO")).toHaveCount(0);
});

// ⛔ THE INVERSE OF THE SPEC IT REPLACES, AND THE INVERSION IS THE RULING. This used to assert the login
// page OFFERS a way to create an account. There is no public signup, ever — so the affordance is gone, and
// its absence is the thing worth pinning: a link back to a form that answers 403 to everyone is a funnel
// into a refusal.
//
// ⚠ BOTH HALVES IN ONE SPEC, deliberately. Password reset must still be there; a spec that only asserted
// the absence would pass just as well on a login page that had lost both.
test("login offers password reset and NO way to create an account", async ({
  page,
}) => {
  await page.goto("/login");
  await expect(
    page.getByRole("link", { name: "Forgot password?" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: /create an account/i }),
  ).toHaveCount(0);
  await expect(page.getByRole("link", { name: /sign up/i })).toHaveCount(0);
});

test("forgot-password renders identically for new vs existing email (no enumeration)", async ({
  page,
}) => {
  const confirm = page.getByRole("heading", { name: "Check your email" });
  await page.goto("/forgot-password");
  await page.getByLabel("Email").fill(`nobody-${Date.now()}@example.com`);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(confirm).toBeVisible();
  const newBody = await page.locator("main p").first().textContent();

  await page.goto("/forgot-password");
  await page.getByLabel("Email").fill(EXISTING_EMAIL);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(confirm).toBeVisible();
  expect(await page.locator("main p").first().textContent()).toBe(newBody);
});

test("verify-email with a bad token lands on a human-readable failure (not a raw error)", async ({
  page,
}) => {
  await page.goto("/verify-email?token=not-a-real-token");
  await expect(
    page.getByRole("heading", { name: "Verification failed" }),
  ).toBeVisible();
  // The token is scrubbed from the URL after capture (not left in history).
  await expect(page).toHaveURL(/\/verify-email$/);
});

test("SSO callback failures land on a human-readable login message (watch-item d)", async ({
  page,
}) => {
  await page.goto("/login?sso_error=unverified_local_exists");
  await expect(
    page.getByText(/account with this email already exists/i),
  ).toBeVisible();
});
