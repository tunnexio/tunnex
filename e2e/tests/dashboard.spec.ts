import { test, expect, type Page } from "@playwright/test";

// S4.3 dashboard home. The seeded demo org has one member (the owner) and no
// gateways, devices, or activity yet — so it exercises BOTH the real-count path
// (Members renders a live number) and the empty-state onboarding funnel.
const OWNER_EMAIL = "owner@demo.tunnex.local";
const OWNER_PASS = "tunnex-demo-password";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER_EMAIL);
  await page.getByLabel("Password").fill(OWNER_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("dashboard renders real counts for the seeded org", async ({ page }) => {
  await login(page);
  // (Org name is asserted in settings.spec, not here — the settings edit test
  // renames+reverts the shared demo org, so an exact-name check would race it.)
  // RE-POINTED IN S14.4. This read the value as "the div BEFORE the label" — true of the old card, false the
  // moment the design put the icon+label row first. A stat card is now a NAMED GROUP, so the query survives
  // any internal rearrangement instead of encoding one.
  const members = page.getByRole("group", { name: "Members" });
  await expect(members).toBeVisible();
  await expect(members.locator("span.font-bold")).toHaveText(/^\d+$/);
  // ⛔ THE "Seen in last 3 min" ASSERTION WAS REMOVED HERE, AND THE CARD IS WHY.
  //
  // f5f84a8a (PR #91) deleted that stat card at the founder's direction and gave its slot to the AI-agent
  // count. The honest-liveness label it asserted is not hidden or renamed — it is GONE from this screen, so
  // there is nothing for this spec to point at. Re-aiming it at the AI-agent card would look like a repair
  // and assert a different property.
  //
  // ⚠ WHAT THAT REMOVAL ALSO TOOK, recorded because nothing else records it: Overview no longer surfaces
  // LIVENESS AT ALL. See the reserved-green test below — its subject went with the same card.
  await expect(members).toHaveCount(1);
});

test("a fresh org shows the empty-state onboarding funnel", async ({
  page,
}) => {
  await login(page);
  // No gateway is enrolled in the seed, so the onboarding call-to-enroll shows.
  // This is the durable empty-state: nothing in the test suite ever enrolls a
  // real node. (We deliberately do NOT assert "No activity yet" here — audit
  // activity legitimately accumulates as other tests invite/change roles, and
  // audit_logs is append-only. The empty activity RENDER is covered
  // deterministically below with a mocked overview.)
  await expect(page.getByText("No gateway enrolled yet.")).toBeVisible();
});

// ⛔ THE ACTIVITY-FEED EMPTY-STATE TEST IS GONE BECAUSE THE FEED IS GONE.
//
// The founder removed Recent Activity, Needs Attention and System Health from Overview. This test proved
// the feed rendered an explicit "No activity yet." rather than an ambiguous blank — a real property, of a
// panel that no longer exists. There is no narrower version of it to keep: you cannot assert the empty
// state of an absent panel.
//
// ⚠ THE CAPABILITY DID NOT MOVE, IT ENDED. The audit log is still reachable at Audit Log and audit.spec.ts
// covers its rendering, but that is a different screen with a different empty state — it is not where this
// assertion went.
//
// ⚠ AND `recent_activity` IS STILL IN THE `/overview` RESPONSE with no consumer. Producer without consumer,
// registered rather than fixed here: deleting a wire field is an API change, not an e2e repair.

// ⛔ REWRITTEN, NOT DELETED. The invariant is "green is a STATUS colour, never brand" — that survives. What
// died is its only positive witness: the one tile that legitimately went green was "Seen in last 3 min",
// and f5f84a8a removed it.
//
// ⚠ SO THIS IS NOW A ONE-SIDED GUARD, AND SAYING SO IS THE POINT. It can prove no stat card is green; it
// can no longer prove green still WORKS where it belongs, because nowhere belongs any more. A one-sided
// guard that presents itself as the original is worse than the gap it hides.
//
// ⚠ AND THE `tone="ok"` PATH IS NOW DORMANT MACHINERY — StatCard still renders `text-ok` for it and no
// caller passes it (docs/laws.md: dormant machinery is removed or given a named trigger, not left to look
// live). Registered for disposition, not ripped out inside an e2e fix.
test("green stays reserved: no stat card renders it", async ({ page }) => {
  // The populated mock is kept: online > 0 is exactly the input that USED to turn a tile green, so this
  // asserts the reservation under the condition most likely to break it.
  await page.route("**/api/v1/organizations/*/overview", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        members: 4,
        devices: 3,
        nodes: 1,
        online: 2,
        recent_activity: [],
      }),
    }),
  );
  await login(page);

  // Every stat card on the screen, not a named sample — a sample would keep passing after a new card
  // arrives wearing brand-green.
  // ⛔ WAIT FOR A CARD BEFORE COUNTING CARDS. `locator.count()` is an INSTANTANEOUS query — unlike
  // `expect(...).toBeVisible()` it does not retry — and `login()` returns as soon as the Overview HEADING
  // is up, which is before the counts have loaded. Counting there races the render.
  //
  // ⚠ AND THE RACE HID INSIDE THE VACUITY FLOOR, WHICH IS THE INSTRUCTIVE PART. The floor exists to catch
  // "zero cards would pass this test forever"; it fired for a completely different reason — zero cards YET
  // — and reported a true statement about a page that was merely not finished. A floor that cannot tell
  // "absent" from "not yet" is a flake with a good explanation attached.
  await expect(page.getByRole("group", { name: "Members" })).toBeVisible();
  const values = page.locator('[role="group"] span.font-bold');
  const n = await values.count();
  expect(n).toBeGreaterThan(0); // vacuity floor: zero cards would pass this test forever
  for (let i = 0; i < n; i++) {
    await expect(values.nth(i)).not.toHaveClass(/text-ok/);
  }
});
