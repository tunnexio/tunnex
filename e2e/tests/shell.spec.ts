import { test, expect } from "@playwright/test";

// S4.1: the auth-gated app shell. Requires the demo org/owner to be seeded
// (make seed) — owner@demo.tunnex.local / tunnex-demo-password.
const OWNER_EMAIL = "owner@demo.tunnex.local";
const OWNER_PASS = "tunnex-demo-password";

test("unauthenticated visitors are gated to the login screen", async ({
  page,
}) => {
  await page.goto("/devices"); // deep link into a gated route
  // S14.17: the login heading is the design's "Welcome back"; "Sign in" is the BUTTON.
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
});

test("signing in reaches the app shell and the dashboard, then navigates to devices", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER_EMAIL);
  await page.getByLabel("Password").fill(OWNER_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Landed in the authenticated shell on the dashboard (the default authed route).
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
  // The owner's email shows in the header.
  await expect(page.getByText(OWNER_EMAIL)).toBeVisible();

  // The sidebar links to Devices, where a device can be created.
  // ⚠ THE FORM IS NO LONGER ON THE PAGE — it moved into an "Add device" modal. The CAPABILITY is unchanged
  // (Devices.tsx still renders the name field and the Create device submit inside the dialog), so this
  // asserts the affordance that reaches it rather than a form that is now one click away.
  await page.getByRole("link", { name: "Devices" }).click();
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add device" })).toBeVisible();

  // An authenticated user visiting /login is bounced back into the app (AnonOnly).
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // Logging out returns to the login screen.
  await page.getByRole("button", { name: "Log out" }).click();
  // S14.17: the login heading is the design's "Welcome back"; "Sign in" is the BUTTON.
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
});

// ⛔ THE QUESTION ASKED FIVE TIMES: IS THERE A WAY TO CREATE AN ORGANIZATION FROM INSIDE THE APP?
//
// There is, since S12.5, and it is the ONLY one: the org switcher in the header carries a create control
// beside the org name. It is labelled "+ New" — not "+ New organization" — because the header is width-
// constrained and the control sits directly beside the thing it creates another of.
//
// ⚠ THE SWITCHER ITSELF IS CONDITIONAL, WHICH IS WHY THIS SPEC ASSERTS THE PATH AND NOT JUST THE BUTTON.
// It renders when there are 2+ organizations OR the account holds `cp_admin`; a holder with a single org
// sees it precisely so the create route is not invisible to the one person who may use it.
test("the org switcher carries the create path for a capability holder", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER_EMAIL);
  await page.getByLabel("Password").fill(OWNER_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  const create = page.getByRole("button", { name: "+ New" });
  await expect(create).toBeVisible();
  // ⛔ AND IT GOES SOMEWHERE. An affordance that renders and leads nowhere is the defect this route was
  // re-opened to fix — RequireNoOrg used to bounce a holder who already had an organization, which is
  // every holder who has ever used it.
  await create.click();
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/create-org$/);
});

// ⚠ AND NOT FOR ANYONE ELSE. The demo member belongs to one organization and holds no capability, so the
// switcher has nothing to switch between and no creation to offer — it renders at all only for someone it
// can serve. Without this half, "the holder sees a create path" would be indistinguishable from "everyone
// does", which is not the shape a real deployment has.
test("a member with one organization gets no switcher and no create path", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("member@demo.tunnex.local");
  await page.getByLabel("Password").fill(OWNER_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await expect(page.getByRole("button", { name: "+ New" })).toHaveCount(0);
  await expect(
    page.getByRole("combobox", { name: "Organization" }),
  ).toHaveCount(0);
});
