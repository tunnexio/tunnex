import { test, expect, type Page } from "@playwright/test";

// S5.1 CLI consent page (flag-1 acceptance). The browser leg of `tunnex login`
// is the HUMAN CHECKPOINT for the cookie-only credential-minting exception:
//   - it NEVER auto-approves — landing on the page mints NOTHING;
//   - it DISPLAYS the loopback redirect INCLUDING the port;
//   - only the explicit click calls cliAuthorize and redirects to the loopback.
const OWNER = {
  email: "owner@demo.tunnex.local",
  pass: "tunnex-demo-password",
};

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

const REDIRECT = "http://127.0.0.1:54321/callback";
const CONSENT = `/cli-auth?redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${"a".repeat(43)}&state=walk-state`;

test("the consent page shows the loopback target with its port and does NOT auto-mint", async ({
  page,
}) => {
  // Fail the test if ANYTHING calls the mint endpoint before the click.
  let minted = 0;
  await page.route("**/api/v1/auth/cli/authorize", (route) => {
    minted++;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        code: "one-time-code",
        state: "walk-state",
        expires_in: 60,
      }),
    });
  });

  await login(page);
  await page.goto(CONSENT);
  await expect(
    page.getByRole("heading", { name: "Authorize the Tunnex CLI" }),
  ).toBeVisible();
  // The loopback target is displayed WITH the port.
  await expect(page.getByText("127.0.0.1:54321/callback")).toBeVisible();
  // The port is called out on its own (accent span) — proves it's surfaced, not buried.
  await expect(page.getByText("54321", { exact: true })).toBeVisible();

  // NO-CLICK-NO-MINT: the authorize control is present but nothing was minted —
  // re-checked AFTER the control settles, so a deferred/debounced auto-mint
  // (effect, idle callback, focus handler) would still be caught.
  await expect(
    page.getByRole("button", { name: "Authorize this CLI" }),
  ).toBeVisible();
  await page.waitForTimeout(600);
  expect(minted).toBe(0);
});

test("the explicit click mints the code and redirects to the loopback with code + state", async ({
  page,
}) => {
  await page.route("**/api/v1/auth/cli/authorize", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        code: "one-time-code",
        state: "walk-state",
        expires_in: 60,
      }),
    }),
  );
  // Intercept the loopback navigation (there is no server on :54321 in CI) and
  // assert the exact code + state the CLI's listener would receive.
  let landed = "";
  await page.route(`${REDIRECT}**`, (route) => {
    landed = route.request().url();
    return route.fulfill({ status: 200, contentType: "text/html", body: "ok" });
  });

  await login(page);
  await page.goto(CONSENT);
  await page.getByRole("button", { name: "Authorize this CLI" }).click();
  await expect.poll(() => landed).toContain("code=one-time-code");
  expect(landed).toContain("state=walk-state");
});

test("a non-loopback redirect_uri is refused (no authorize control shown)", async ({
  page,
}) => {
  let minted = 0;
  await page.route("**/api/v1/auth/cli/authorize", (route) => {
    minted++;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: "{}",
    });
  });
  await login(page);
  await page.goto(
    `/cli-auth?redirect_uri=${encodeURIComponent("http://evil.example:80/callback")}&code_challenge=${"a".repeat(43)}&state=s`,
  );
  await expect(page.getByText(/can.t be trusted/i)).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Authorize this CLI" }),
  ).toHaveCount(0);
  expect(minted).toBe(0);
});

test("a logged-out `tunnex login` returns to the consent page after sign-in (S5.1/F4)", async ({
  page,
}) => {
  // Fresh-machine case: hit /cli-auth with no session → bounced to login → after
  // sign-in, land BACK on the consent page with its query params intact.
  await page.context().clearCookies();
  await page.goto(CONSENT);
  await expect(page).toHaveURL(/\/login\?next=/);
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(
    page.getByRole("heading", { name: "Authorize the Tunnex CLI" }),
  ).toBeVisible();
  await expect(page.getByText("127.0.0.1:54321/callback")).toBeVisible();
});

test("the device page warns against phishing and approves the printed user_code", async ({
  page,
}) => {
  let approvedCode = "";
  await page.route("**/api/v1/auth/cli/device/approve", (route) => {
    approvedCode = JSON.parse(route.request().postData() || "{}").user_code;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ message: "ok" }),
    });
  });
  await login(page);
  await page.goto("/cli-device?user_code=WXYZ-2345");
  // The anti-phishing warning is present, and the code is displayed (prefilled).
  await expect(
    page.getByText(/Only enter a code you started yourself/i),
  ).toBeVisible();
  await expect(page.getByLabel("Device code")).toHaveValue("WXYZ-2345");
  await page.getByRole("button", { name: "Approve this device" }).click();
  await expect(
    page.getByRole("heading", { name: "CLI approved" }),
  ).toBeVisible();
  expect(approvedCode).toBe("WXYZ-2345");
});
