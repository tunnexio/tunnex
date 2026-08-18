import { test, expect } from "@playwright/test";
import { login, openRowDialog, openSection, OWNER, ORG } from "./helpers";

// S4.5 + S4.5b — the REAL assertions, run ONLY against the enterprise edition
// (seed-enterprise laid down on top of seed: a sealed SSO config + a device
// holding a pool IP a shrink strands).
//
// These SATISFY what the open-edition substitutes in settings.spec.ts can only
// stand in for:
//   - S4.5: there the SSO section is the "Enterprise feature" 403 gate; HERE the
//     endpoint is served, so we assert the real payload carries the fingerprint
//     and NO client secret (belt-and-braces with the blocking Go httptest
//     TestGetSsoConfigPayloadCarriesNoSecret, which gates in `make test-editions`).
//   - S4.5b: there the 409 orphan list is a page.route MOCK; HERE a live shrink
//     strands the seeded device and the REAL 409 body renders.
//
// ⛔ THESE TESTS HAVE BEEN SKIPPING ON CI, AND THE JOB REPORTED GREEN. The `e2e-enterprise` job's stack has
// no licence installed, so /meta answers edition=open, both tests skip, and the run prints "2 skipped" under
// a passing check. The gate below was introduced to remove a false-green from a typo'd env var and replaced
// it with a quieter one: the STACK is not enterprise, and nothing says so.
//
// ⚠ THE FIRST REAL EXECUTION (locally, against a licensed stack) FAILED IMMEDIATELY — it was asserting
// Google's client id against Microsoft's empty input, for two years of green. Registered: make the
// e2e-enterprise stack actually enterprise (install a licence in the job), or assert the skip is not
// silent. Until then this file's coverage is nominal, not real.
//
// EDITION GATE — self-detected from /meta, NOT an env var. On the OPEN stack /meta
// reports edition=open and both tests skip; on the ENTERPRISE stack they run. This
// removes the false-green where a dropped/typo'd E2E_EDITION would silently skip
// the real assertions and still exit 0.
test.beforeEach(async ({ request }) => {
  const meta = await request.get("/api/v1/meta");
  const edition = meta.ok() ? (await meta.json()).edition : "unknown";
  test.skip(
    edition !== "enterprise",
    `requires the enterprise edition (/meta.edition=${edition})`,
  );
});

// seed-enterprise fixtures (must match apps/api/internal/seeddata/seeddata.go).
const SEEDED_CLIENT_ID = "demo-enterprise-client.apps.googleusercontent.com";
const SEEDED_SECRET = "demo-enterprise-client-secret-do-not-ship";
const STRANDABLE_DEVICE = "demo-strandable-laptop";
const SHRINK_CIDR = "10.99.0.0/25"; // strands the seeded device at 10.99.0.200
const BASE_CIDR = "10.99.0.0/24";

test("S4.5 — the SSO config payload surfaces the fingerprint and NO client secret", async ({
  page,
}) => {
  await login(page, OWNER);

  // SSO lives in the Authentication section, and its config is behind the row's action — one section at a
  // time, form behind an explicit open.
  await openSection(page, "Authentication");
  // The enterprise edition serves the real SSO config form (not the gate note).
  await expect(page.getByText(/Tunnex Enterprise feature/i)).toHaveCount(0);
  // ⛔ SCOPED TO GOOGLE'S ROW, NOT TO THE FIRST MATCHING CONTROL. This spec used to reach the config by
  // "the first Client ID field", which relied on PROVIDERS order and quietly becomes the WRONG provider as
  // soon as both are configured and both offer the same action label — a spec that would have kept passing
  // while asserting Microsoft's payload under Google's name.
  await page
    .getByTestId("sso-row-google")
    .getByRole("button", { name: /Replace config|Configure/ })
    .click();
  // The seeded google config renders its client id and the proof-of-storage
  // fingerprint — and NOTHING that is or contains the secret.
  // ⛔ NO CLIENT-ID ASSERTION HERE, AND ITS REMOVAL IS THE POINT. This read
  // `getByLabel("Client ID").first()`, and Google's row renders NO client-id field at all — the field is
  // gated to `provider === "microsoft"` (unchanged on main). getByLabel is a case-insensitive SUBSTRING, so
  // `.first()` was silently resolving to MICROSOFT's "Microsoft client ID" input and asserting Google's
  // seeded value against it. It never ran on CI to notice: see the vacuity note at the top of this file.
  //
  // What Google's row actually proves is what this test is named for — the fingerprint is shown and the
  // secret is not.
  await expect(page.getByText(/stored secret fingerprint:/i)).toBeVisible();
  await expect(page.getByText(SEEDED_SECRET)).toHaveCount(0);

  // Assert the wire payload directly (authenticated via the logged-in context).
  const res = await page.request.get(`/api/v1/organizations/${ORG}/sso/google`);
  expect(res.status()).toBe(200);
  const body = await res.json();
  const rawText = await res.text();
  expect(body.secret_fingerprint, "fingerprint present").toBeTruthy();
  expect(body.client_id).toBe(SEEDED_CLIENT_ID);
  expect(body).not.toHaveProperty("client_secret");
  expect(rawText, "no secret material anywhere in the payload").not.toContain(
    SEEDED_SECRET,
  );
});

test("S4.5b — a live shrink strands the seeded device and renders the REAL 409 orphan list", async ({
  page,
}) => {
  await login(page, OWNER);

  await openSection(page, "Network");
  await expect(page.getByText("Address pool", { exact: true })).toBeVisible();
  await openRowDialog(page, "Resize");
  await expect(page.getByLabel("Pool CIDR")).toHaveValue(BASE_CIDR);

  // Precondition: the strandable device fixture MUST exist, else the shrink below
  // would find no orphan, return 200, and COMMIT — corrupting the shared demo pool.
  // Assert the device is present before issuing a mutating request.
  const dev = await page.request.get(`/api/v1/organizations/${ORG}/devices`);
  expect(dev.ok(), "devices list").toBeTruthy();
  expect(
    (await dev.text()).includes(STRANDABLE_DEVICE),
    `seed-enterprise fixture ${STRANDABLE_DEVICE} must be present before a live shrink`,
  ).toBeTruthy();

  try {
    // No page.route mock — this hits the real endpoint. The seeded device at
    // 10.99.0.200 is outside 10.99.0.0/25, so the server returns a real 409.
    await page.getByLabel("Pool CIDR").fill(SHRINK_CIDR);
    await page.getByRole("button", { name: "Resize pool" }).click();

    await expect(
      page.getByText(/must be removed or renumbered/i),
    ).toBeVisible();
    await expect(page.getByText(STRANDABLE_DEVICE)).toBeVisible();
    await expect(page.getByText(/outside the new range/i)).toBeVisible();
  } finally {
    // Belt-and-braces: if the shrink ever DID commit (fixture regressed, endpoint
    // changed), restore the base pool so a stray /25 can't corrupt the shared
    // stack for later runs. A grow back to /24 is always legal.
    await page.request.put(`/api/v1/organizations/${ORG}/pool-cidr`, {
      headers: { "X-Tunnex-CSRF": "1" },
      data: { pool_cidr: BASE_CIDR },
    });
  }

  // The 409 is non-mutating, so the pool is unchanged.
  const res = await page.request.get(`/api/v1/organizations/${ORG}`);
  expect((await res.json()).pool_cidr).toBe(BASE_CIDR);
});
