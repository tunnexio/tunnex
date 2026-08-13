import { test, expect } from "@playwright/test";
import { login, OWNER, ORG } from "./helpers";

// ⛔ THE SECOND DESTINATION. `onboarding.spec.ts` pins the FIRST one — a membershipless user lands on the
// "Invitation required" card — and it has been green throughout. A suite that asserts only that half passes
// on a product where invitations never work, because "you are not in an org" is exactly what a BROKEN
// invitation also produces. Both states, both destinations, or the green half hides the broken half.
//
// ⭐ THIS SPEC DRIVES A REAL INVITATION and mocks nothing: create it, take the token from the RESPONSE,
// accept it, sign in, and assert the inviting org renders. Every leg of this chain changed in one day
// (delivery now reports `delivered:false` instead of claiming a send, SMTP has no default, accept marks
// the email verified) and no instrument crossed all of them.
//
// ⚠ THE TOKEN COMES FROM THE 202 BODY, NEVER FROM MAIL. That is the SMTP-less delivery path the product
// ships deliberately — so this spec is independent of whether a mail server exists, which is what lets it
// run in CI at all.

const INVITEE_PASSWORD = "tunnex-invited-password";

test("an invited user accepts and lands INSIDE the inviting org (real backend, no mocks)", async ({
  browser,
}) => {
  // A unique address per run: the accept path provisions a user, and a re-run must not collide with the
  // account the previous run created.
  const email = `invitee-${Date.now()}@demo.tunnex.local`;

  // ── The administrator issues the invitation ────────────────────────────────
  const ownerContext = await browser.newContext();
  const ownerPage = await ownerContext.newPage();
  await login(ownerPage, OWNER);
  const created = await ownerPage.request.post(
    `/api/v1/organizations/${ORG}/invitations`,
    {
      headers: { "X-Tunnex-CSRF": "1" },
      data: { email, role: "member" },
    },
  );
  expect(created.status(), await created.text()).toBe(202);
  const body = await created.json();
  // ⛔ THE TOKEN IS THE DELIVERY PATH WHEN SMTP IS UNSET. If this is ever absent, an operator on a box with
  // no mail server has no way to admit anyone — the invitation exists and reaches nobody.
  expect(body.invite_token, "the 202 must carry the raw accept token").toBeTruthy();
  // ⚠ `delivered` is a FACT, not a failure: it is false on a deployment with no SMTP, and the invitation is
  // still valid. Asserted as present-and-boolean so the field cannot quietly vanish from the contract.
  expect(typeof body.delivered).toBe("boolean");
  await ownerContext.close();

  // ── The invited person, in a browser that has never seen this deployment ───
  const inviteeContext = await browser.newContext();
  const page = await inviteeContext.newPage();
  await page.goto(
    `/accept-invite?token=${encodeURIComponent(body.invite_token)}`,
  );
  await page.getByLabel("Your name").fill("Invited Person");
  await page.getByLabel("Password").fill(INVITEE_PASSWORD);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByRole("heading", { name: "You're in" })).toBeVisible();

  // Accepting deliberately does NOT mint a session (the link is admin-visible), so the invitee signs in
  // explicitly — the same step a real invited user takes.
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(INVITEE_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();

  // ⛔ THE ASSERTION THE WHOLE SPEC EXISTS FOR: they are INSIDE the org, not in the funnel.
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);

  // ⚠ AND EXPLICITLY NOT THE FIRST DESTINATION. Without this, a product that dropped the membership would
  // still satisfy "the user is signed in" — and the invitee would be reading "ask an administrator for an
  // invitation" about the invitation they just accepted.
  await expect(
    page.getByRole("heading", { name: "Invitation required" }),
  ).toHaveCount(0);
  await expect(page).not.toHaveURL(/\/create-org$/);
  await inviteeContext.close();
});
