import { test, expect } from "@playwright/test";
import { login, OWNER, MEMBER, ORG } from "./helpers";

// ⛔ SKIPPED, NOT DELETED — AND THE REASON IS THAT THE PRODUCT CHANGED UNDER THEM, NOT THAT THEY ARE WRONG.
//
// Public signup is closed (founder-ruled): a self-hosted control plane is owned by ONE COMPANY, install
// creates the CP admin, and everyone else arrives by INVITATION. These specs assert a self-serve signup
// flow that no longer exists — so they are red because the product moved, which is exactly the state a
// spec should end up in when a ruling lands.
//
// ⚠ THEY ARE NOT REWRITTEN HERE BECAUSE HALF THEIR REPLACEMENT IS NOT BUILT. The invitation flow — invite
// → email → the invited person SETS THEIR OWN PASSWORD from the link → signs in — is the next piece of the
// onboarding rebuild. Rewriting them against a model that is half-finished produces a suite that passes
// while testing nothing, which is worse than one that is honestly red.
//
// ⛔ TRIGGER, NAMED: the invitation flow. These are rewritten as invitation-shaped specs in that story, or
// deleted there with a reason. `docs/laws.md` — a deferred proof is deferred, never dropped.

// S4.5 Org settings + SSO config UI. The e2e stack is the OPEN edition, so the
// SSO section renders as an "Enterprise feature" note (watch-item b: SSO config
// is hidden in open builds), and the org-name edit exercises the settings save.
//
// NOTE (S7.4c): the SSO test below is the OPEN-edition SUBSTITUTE — it proves the
// endpoint is edition-GATED (403), not that its served payload is secret-free.
// The REAL S4.5 secret-payload assertion lives in settings.enterprise.spec.ts
// (enterprise edition, self-detected via /meta) + the blocking Go httptest
// TestGetSsoConfigPayloadCarriesNoSecret (make test-editions).

test("owner sees org settings; SSO config is gated to the enterprise edition", async ({
  page,
}) => {
  await login(page, OWNER);
  // ⛔ THE HEADING, NOT THE TEXT. Also swept into the signup skip batch without touching signup: the S12.5
  // org switcher carries an `sr-only` "Organization" label in the header, so a bare text match now resolves
  // to two elements and trips strict mode. The section heading is what this spec means.
  await expect(
    page.getByRole("heading", { name: "Organization", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("slug: demo")).toBeVisible();
  // Open edition: no SSO config form, just the edition-gated notes. S7.5.5 added a SECOND enterprise
  // note (org-wide MFA enforcement) beside SSO, so assert EACH specifically — a bare /Tunnex Enterprise
  // feature/ now matches both and trips Playwright strict mode.
  await expect(
    page.getByText(/SSO .*is a Tunnex Enterprise feature/i),
  ).toBeVisible();
  await expect(
    page.getByText(/Org-wide MFA enforcement is a Tunnex Enterprise feature/i),
  ).toBeVisible();
  await expect(page.getByLabel("Client ID")).toHaveCount(0);
});

test("a plain member cannot manage settings", async ({ page }) => {
  await login(page, MEMBER);
  await expect(page.getByText(/managed by owners and admins/i)).toBeVisible();
  await expect(page.getByLabel("Name")).toHaveCount(0);
});

test("editing the org name saves (and is reverted to keep the shared seed clean)", async ({
  page,
}) => {
  await login(page, OWNER);
  // exact: true — getByLabel is case-insensitive SUBSTRING by default, so a bare "Name" also matches the
  // machine-credential panel's "Credential name" (S11-1). The accessible names are now distinct (the product
  // fix); this makes the locator express its real intent — the ORG name field — and is STRICTER, not looser.
  const name = page.getByLabel("Name", { exact: true });
  await expect(name).toHaveValue("Demo Organization");
  // Save is disabled until the name actually changes.
  await expect(page.getByRole("button", { name: "Save" })).toBeDisabled();
  try {
    await name.fill("Demo Organization (edited)");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Saved.")).toBeVisible();
  } finally {
    // ALWAYS restore the name via the API so a mid-test failure can't leave the
    // shared demo org renamed for other specs.
    await page.request.patch(`/api/v1/organizations/${ORG}`, {
      headers: { "X-Tunnex-CSRF": "1" },
      data: { name: "Demo Organization" },
    });
  }
});

// S4.5b — the address-pool resize control. The seeded org has the default pool
// (10.99.0.0/24). Real render is checked directly; the success (accept-and-
// surface) and the shrink-conflict (orphan list) renders are mocked here in the
// OPEN suite because it has no seeded device to strand.
//
// NOTE (S7.4c): the 409-orphan MOCK below is the OPEN-edition SUBSTITUTE. The
// REAL S4.5b assertion — a LIVE shrink stranding a seeded device, un-mocked —
// lives in settings.enterprise.spec.ts (E2E_EDITION=enterprise), where
// seed-enterprise provides the device holding a pool IP. (The orphan check is a
// pure DB read — no enrolled agent needed; S7.4c D-c4.)
test("the address-pool section shows the current CIDR and gates Resize on a change", async ({
  page,
}) => {
  await login(page, OWNER);
  await expect(page.getByText("Address pool")).toBeVisible();
  await expect(page.getByLabel("Pool CIDR")).toHaveValue("10.99.0.0/24");
  await expect(
    page.getByRole("button", { name: "Resize pool" }),
  ).toBeDisabled(); // unchanged
});

test("a successful resize surfaces the re-issue-configs consequence (accept-and-surface)", async ({
  page,
}) => {
  await page.route("**/api/v1/organizations/*/pool-cidr", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: ORG,
        name: "Demo Organization",
        slug: "demo",
        pool_cidr: "10.99.0.0/23",
        created_at: new Date(0).toISOString(),
        updated_at: new Date(0).toISOString(),
      }),
    }),
  );
  await login(page, OWNER);
  await page.getByLabel("Pool CIDR").fill("10.99.0.0/23");
  await page.getByRole("button", { name: "Resize pool" }).click();
  await expect(page.getByText(/re-issue their configs/i)).toBeVisible();
  await expect(page.getByText(/revoke \+ recreate/i)).toBeVisible();
});

test("a shrink that would strand devices renders the orphan list with names and reasons", async ({
  page,
}) => {
  await page.route("**/api/v1/organizations/*/pool-cidr", (route) =>
    route.fulfill({
      status: 409,
      contentType: "application/json",
      body: JSON.stringify({
        orphan_count: 3,
        orphans: [
          {
            device_id: "01900000-0000-7000-8000-0000000000a1",
            name: "laptop-a",
            assigned_ip: "10.99.0.127",
            reason: "reserved_collision",
          },
          {
            device_id: "01900000-0000-7000-8000-0000000000a2",
            name: "laptop-b",
            assigned_ip: "10.99.0.200",
            reason: "out_of_range",
          },
        ],
      }),
    }),
  );
  await login(page, OWNER);
  await page.getByLabel("Pool CIDR").fill("10.99.0.0/25");
  await page.getByRole("button", { name: "Resize pool" }).click();
  // Actionable refusal: count, names, both reason phrasings, and the "N more" note.
  await expect(
    page.getByText(/3 devices must be removed or renumbered first/i),
  ).toBeVisible();
  await expect(page.getByText("laptop-a")).toBeVisible();
  await expect(page.getByText("laptop-b")).toBeVisible();
  // ⛔ THE SUBTLE REASON, ON THE WIRE. `reserved_collision` is numerically INSIDE the new
  // range (ipalloc.go:78) — 10.99.0.127 is the broadcast address of 10.99.0.0/25 and looks
  // fine next to the CIDR. The old copy ("collides with a reserved address") let an operator
  // conclude the server was wrong; naming the three reserved addresses is what stops that.
  await expect(
    page.getByText(
      /inside the new range, but on its network, gateway or broadcast address/i,
    ),
  ).toBeVisible();
  await expect(page.getByText(/outside the new range/i)).toBeVisible();
  await expect(page.getByText(/and 1 more/i)).toBeVisible();
  // The refusal is atomic — ShrinkOrphansError returns inside withTx (devices/service.go:539)
  // BEFORE UpdateOrgPoolCidr (:541). Asserted here because this is the only instrument that
  // sees it rendered: without the sentence an operator cannot tell a clean refusal from a
  // partial resize.
  await expect(page.getByText(/nothing was changed/i)).toBeVisible();
});
