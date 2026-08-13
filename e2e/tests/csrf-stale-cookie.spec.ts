import { test, expect } from "@playwright/test";

// S4.8 / Round-2 bug B1 regression: the server's csrfGuard requires X-Tunnex-CSRF
// whenever a request CARRIES the session cookie — even a stale, revoked one. The
// SPA's pre-auth login POST used to omit the header, so a browser holding a
// revoked cookie (e.g. after a password reset revoked all sessions) was locked
// out of login with "missing X-Tunnex-CSRF header" until the 30-day cookie
// expired. The fix attaches the header to every unsafe-method request inside
// createTunnexClient. This test manufactures the exact failure state — a
// PRESENT-but-INVALID session cookie — and proves login now succeeds.
const OWNER = {
  email: "owner@demo.tunnex.local",
  pass: "tunnex-demo-password",
};

test("login succeeds with a stale session cookie present, and replaces it", async ({
  page,
  context,
  baseURL,
}) => {
  // The bug's trigger state: a session cookie the server does not recognize
  // (same shape as one whose Redis session was revoked by a password reset).
  const STALE = "stale-revoked-session-id-round2-b1";
  await context.addCookies([
    {
      name: "tunnex_session",
      value: STALE,
      url: baseURL!,
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);

  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.pass);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Pre-fix this surfaced "missing X-Tunnex-CSRF header on a state-changing
  // request" and never left /login. Post-fix: a normal successful login.
  await expect(page.getByText(/X-Tunnex-CSRF/)).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // And the login's Set-Cookie REPLACED the stale value (a real session now).
  const session = (await context.cookies()).find(
    (c) => c.name === "tunnex_session",
  );
  expect(session).toBeTruthy();
  expect(session!.value).not.toBe(STALE);
});
