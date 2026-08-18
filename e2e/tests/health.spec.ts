import { test, expect } from "@playwright/test";

test("SPA loads and reports the API operational", async ({ page }) => {
  await page.goto("/");
  // ⛔ THE BRAND IS AN IMAGE NOW, NOT TEXT. S14.17 replaced the placeholder wordmark with the real
  // SVG, so `getByText("tunnex")` finds nothing — the name lives in `alt`. Asserting the ROLE is
  // both correct and stronger: it fails if the mark loses its accessible name, which a text query
  // could never have checked.
  await expect(
    page.getByRole("img", { name: /tunnex/i }).first(),
  ).toBeVisible();
  // ⚠ THE HEALTHY LABEL IS NOW THE VERSION, NOT THE WORD "operational" — the pill renders `v0.1.0` in its
  // up state. Re-pointed rather than deleted, and deliberately NOT re-pointed at the literal "v0.1.0":
  // pinning a version string here would turn every release into a failing e2e. The version only renders in
  // the `up` state, so matching its SHAPE asserts exactly what this test is named for — the SPA reached the
  // API and got a healthy answer. `checking…` and `unreachable` both fail this.
  await expect(page.getByText(/^v\d+\.\d+\.\d+/)).toBeVisible();
});

test("correlation chain: SPA -> API -> X-Request-Id is well-formed and matches body", async ({
  page,
}) => {
  // Capture the /healthz response the SPA triggers on load.
  const healthResponse = page.waitForResponse(
    (r) => r.url().endsWith("/healthz") && r.request().method() === "GET",
  );
  await page.goto("/");
  const resp = await healthResponse;

  expect(resp.ok()).toBeTruthy();

  const requestId = resp.headers()["x-request-id"];
  expect(requestId, "X-Request-Id header must be present").toBeTruthy();
  // nginx stamps a 32-char hex correlation id and the API echoes it.
  expect(requestId).toMatch(/^[a-f0-9]{32}$/);

  const body = (await resp.json()) as { status: string; request_id?: string };
  expect(body.status).toBe("ok");
  expect(body.request_id).toBe(requestId);
});
