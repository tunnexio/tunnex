import { test, expect, type Page } from "@playwright/test";

// S4.2 config-download ceremony (re-verified for the S4.3 sign-off): the most
// security-sensitive moment in the app. The server-generated .conf carries the
// device private key and is shown EXACTLY ONCE. This test drives the real
// ceremony component by mocking the gateway list (so the create button enables)
// and the create response (so it returns a config) — no enrolled node needed.
const OWNER_EMAIL = "owner@demo.tunnex.local";
const OWNER_PASS = "tunnex-demo-password";
const FAKE_CONFIG =
  "[Interface]\nPrivateKey = TEST_PRIVATE_KEY_SHOWN_ONCE\nAddress = 10.100.0.2/32\n\n[Peer]\nPublicKey = SERVERKEY\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.100.0.0/24";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER_EMAIL);
  await page.getByLabel("Password").fill(OWNER_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("the config-download ceremony renders once with the amber one-time callout and no route back", async ({
  page,
}) => {
  await login(page);

  // Mock the gateway list so the create form enables, and the create call so it
  // returns a server-generated config (the browser keypair flow).
  await page.route("**/api/v1/organizations/*/nodes", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: "01900000-0000-7000-8000-0000000000aa",
          name: "gw-1",
          status: "active",
          agent_version: "test",
          enrolled_at: new Date(0).toISOString(),
        },
      ]),
    }),
  );
  await page.route("**/api/v1/organizations/*/devices", (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          device: {
            id: "01900000-0000-7000-8000-0000000000bb",
            name: "my-laptop",
            status: "active",
          },
          config: FAKE_CONFIG,
        }),
      });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: "[]",
    });
  });

  await page.getByRole("link", { name: "Devices" }).click();
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();

  // ⚠ ONE CLICK ADDED, NOTHING ELSE CHANGED. The create form moved into a modal; the ceremony it opens is
  // the same ceremony, so every assertion below is untouched.
  await page.getByRole("button", { name: "Add device" }).click();
  await page.getByLabel("New device name").fill("my-laptop");
  await page.getByRole("button", { name: "Create device" }).click();

  // The ceremony modal: amber "shown once" callout, the config in a mono block,
  // the save/copy controls.
  await expect(page.getByText("Your configuration — shown once")).toBeVisible();
  await expect(page.getByText(/exactly once/i)).toBeVisible();
  await expect(page.getByText("TEST_PRIVATE_KEY_SHOWN_ONCE")).toBeVisible();
  await expect(page.getByRole("button", { name: /Download/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy" })).toBeVisible();

  // Explicit acknowledgement gate: "I've saved it" dismisses it.
  await page.getByRole("button", { name: /I.?ve saved it/ }).click();
  await expect(page.getByText("Your configuration — shown once")).toBeHidden();

  // No route back: the config exists only in page state and is never re-fetched.
  // Reloading the devices page must NOT resurrect it.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();
  await expect(page.getByText("Your configuration — shown once")).toBeHidden();
});
