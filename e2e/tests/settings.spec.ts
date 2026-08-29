import { test, expect } from "@playwright/test";
import {
  login,
  openRowDialog,
  openSection,
  OWNER,
  MEMBER,
  ORG,
} from "./helpers";

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
  // Organization is the default section, so its group heading is present without selecting anything.
  await expect(
    page.getByRole("heading", { name: "Organization", exact: true }),
  ).toBeVisible();

  // ⛔ THE SLUG MOVED INTO THE RENAME DIALOG, and that is the product decision, not a test workaround:
  // the row states the NAME because that is what most visits come to read, and the immutable slug is
  // detail you only need while renaming. So the spec opens the dialog, which is what a person does.
  await openRowDialog(page, "Edit");
  await expect(page.getByText("slug: demo")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  // The enterprise notes live in Authentication now — one section at a time (the settings rail).
  await openSection(page, "Authentication");
  await expect(
    page.getByText("Google and Microsoft sign-in require an Enterprise plan."),
  ).toBeVisible();
  await expect(
    page.getByText("Organization-wide enforcement requires an Enterprise plan."),
  ).toBeVisible();
  await expect(page.getByLabel("Client ID")).toHaveCount(0);
});

test("a plain member cannot manage settings", async ({ page }) => {
  await login(page, MEMBER);
  await expect(
    page.getByText("Manage your account security and view your plan."),
  ).toBeVisible();
  await expect(page.getByLabel("Name")).toHaveCount(0);
});

test("editing the org name saves (and is reverted to keep the shared seed clean)", async ({
  page,
}) => {
  await login(page, OWNER);

  // The row states the current value; editing happens in a dialog.
  await expect(page.getByText("Demo Organization").first()).toBeVisible();
  await openRowDialog(page, "Edit");

  // exact: true — getByLabel is case-insensitive SUBSTRING by default, so a bare "Name" also matches the
  // machine-credential panel's "Credential name" (S11-1). This expresses the real intent: the ORG name.
  const name = page.getByLabel("Name", { exact: true });
  await expect(name).toHaveValue("Demo Organization");
  // Save is disabled until the name actually changes.
  await expect(page.getByRole("button", { name: "Save" })).toBeDisabled();
  try {
    await name.fill("Demo Organization (edited)");
    await page.getByRole("button", { name: "Save" }).click();

    // ⛔ THE CONFIRMATION IS THE DIALOG CLOSING AND THE ROW UPDATING — there is no "Saved." text any more,
    // and its removal was deliberate: a transient success message beside a field that still showed the old
    // value was the weaker signal. This asserts the STATE, which a stale message could never prove.
    await expect(page.getByRole("button", { name: "Save" })).toHaveCount(0);
    await expect(
      page.getByText("Demo Organization (edited)").first(),
    ).toBeVisible();
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
  await openSection(page, "Network");
  // The row states the pool without opening anything — the common read.
  // exact: true — getByText is case-insensitive SUBSTRING, and the rail's own hint for this section reads
  // "…address pools.", so a loose match resolves to the tab AND the row. The row label is what this means.
  await expect(page.getByText("Address pool", { exact: true })).toBeVisible();
  await expect(page.getByText("10.99.0.0/24").first()).toBeVisible();

  await openRowDialog(page, "Resize");
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
  await openSection(page, "Network");
  await openRowDialog(page, "Resize");
  await page.getByLabel("Pool CIDR").fill("10.99.0.0/23");
  await page.getByRole("button", { name: "Resize pool" }).click();
  // ⚠ THIS DIALOG STAYS OPEN ON SUCCESS, unlike the rename one, and that asymmetry is deliberate: a resize
  // returns a consequence the operator must read (existing devices keep their old addresses and their
  // configs are one-time), so closing would dismiss the only place it is ever said.
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
  await openSection(page, "Network");
  await openRowDialog(page, "Resize");
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
