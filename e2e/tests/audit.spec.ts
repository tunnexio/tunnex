import { test, expect, type Page } from "@playwright/test";

// S4.6 Audit log viewer. The seeded org has no audit events and sso.config_updated
// needs an enterprise SSO write, so the feed render + keyset paging are asserted
// against a MOCKED endpoint (like the other UI-render tests); the real page is
// checked for the org-scoped actor filter.
const OWNER = {
  email: "owner@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
// ⛔ THE CROSS-TENANT CAST (S12.11). A deployment administrator who is a member of NOTHING, a second
// organization they are not in, and an account with no memberships to be granted one. The demo owner
// cannot play the administrator: they hold `cp_admin` AND belong to the demo org, so every grant they make
// is an ordinary in-tenant act and proves nothing about the boundary.
const CP_ADMIN = {
  email: "cpadmin@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
const SANDBOX_OWNER = {
  email: "sandbox-owner@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
const SANDBOX_ORG = "01900000-0000-7000-8000-000000000021"; // seeddata.DemoSandboxOrgID
const GRANTEE = "01900000-0000-7000-8000-000000000023"; // seeddata.DemoGranteeUserID

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Audit Log" }).click();
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
}

test("the actor filter is org-scoped (offers only this org's members)", async ({
  page,
}) => {
  await login(page);
  // ⛔ NAMED, NOT `.first()`. This spec was swept into the "assumes public signup" skip batch and it never
  // touched signup: S12.5 put an ORG SWITCHER in the header, so the first combobox on the page became the
  // org list — a control with no "Anyone" option — and the assertion started reading the wrong element.
  // A positional locator names whatever happens to be first, which is a claim about page layout, not about
  // the control under test.
  const actor = page.getByRole("combobox", { name: "Actor" });
  // Only "Anyone" + the seeded org members — no foreign actor probe.
  await expect(actor.getByRole("option", { name: "Anyone" })).toBeAttached();
  await expect(
    actor.getByRole("option", { name: "Demo Member" }),
  ).toBeAttached();
  await expect(
    actor.getByRole("option", { name: "Demo Owner" }),
  ).toBeAttached();
});

test("the feed renders actions + resolved actors + secret-free details, with keyset Load more", async ({
  page,
}) => {
  const OWNER_ID = "01900000-0000-7000-8000-000000000002"; // seeddata.DemoOwnerUserID
  // A real backing store the mock pages over by keyset — 53 events, newest first
  // (i=0 is newest). The mock honors the cursor exactly like the server, so the
  // test proves the CLIENT sends the right cursor and stitches pages with no
  // overlap/gap — not merely "a second request happened".
  const all = Array.from({ length: 53 }, (_, i) => ({
    id: `00000000-0000-7000-8000-0000000${(100 + i).toString().padStart(5, "0")}`,
    created_at: new Date(1_700_000_000_000 - i * 60_000).toISOString(),
    actor_id: OWNER_ID,
    action: "device.created",
    target_type: "device",
    details: {} as Record<string, unknown>,
  }));
  // A secret-adjacent event (newest): details carries the KEYED fingerprint only.
  all[0] = {
    ...all[0],
    action: "sso.config_updated",
    target_type: "sso_config",
    details: {
      provider: "google",
      client_id: "gid-123",
      enabled: true,
      secret_fingerprint: "a1b2c3d4e5f6",
    } as Record<string, unknown>,
  } as (typeof all)[number];

  let sawCursorReq = false;
  await page.route("**/api/v1/organizations/*/audit-logs**", (route) => {
    const q = new URL(route.request().url()).searchParams;
    const limit = Number(q.get("limit"));
    const cts = q.get("cursor_ts");
    const cid = q.get("cursor_id");
    let rows = all;
    if (cts && cid) {
      sawCursorReq = true;
      // The cursor MUST be the last row the client is currently showing (row 49,
      // the 50th displayed — row 50 was the undisplayed has-more probe).
      expect(cts).toBe(all[49].created_at);
      expect(cid).toBe(all[49].id);
      // Row-value keyset: rows strictly older than the cursor.
      rows = all.filter(
        (r) => r.created_at < cts || (r.created_at === cts && r.id < cid),
      );
    }
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(rows.slice(0, limit)),
    });
  });

  await login(page);
  // Secret-free render: the fingerprint shows; no client_secret / sealed material.
  await expect(page.getByText("sso.config_updated")).toBeVisible();
  await expect(page.getByText(/a1b2c3d4e5f6/)).toBeVisible();
  await expect(page.getByText(/client_secret/i)).toHaveCount(0);
  // RE-POINTED IN S14.3 SLICE A. The actor used to be rendered as the inline string "actor <name>"; the log
  // is now a table with an "Actor" COLUMN, so the label lives in the header and the cell carries the name
  // alone. Asserting the bare name is the stronger claim anyway — it survives the label being reworded.
  await expect(
    page.getByRole("cell", { name: "Demo Owner" }).first(),
  ).toBeVisible();
  // Page 1 shows 50 rows (of the 51 fetched); the probe row means "more".
  //
  // `main ul > li` was a DOM-STRUCTURE selector and it broke the moment the list became a table — which is
  // the point: until slice A there was no `<table>` in the app, so neither this spec nor the unit tier had a
  // role to ask for, and both were coupled to markup. +1 for the header row, which `role="row"` includes.
  const rows = page
    .getByRole("table", { name: "Audit events" })
    .getByRole("row");
  await expect(rows).toHaveCount(51);
  const loadMore = page.getByRole("button", { name: "Load more" });
  await expect(loadMore).toBeVisible();
  await loadMore.click();

  // After paging: exactly 53 EVENTS — all stitched in with NO overlap and NO gap (53 distinct events → 53
  // data rows; a re-served/skipped row would change this). The undisplayed page-1 probe (row 50) is correctly
  // re-served on page 2, and the last displayed page-1 row (49) is the cursor, not re-appended.
  //
  // 54 = 53 events + the header row. `role="row"` counts the header, so the +1 is carried here too; leaving
  // it at 53 would have made this assertion silently off by one in the SAFE-LOOKING direction — it would have
  // failed, but for a reason that reads like a paging bug rather than a counting convention.
  await expect(rows).toHaveCount(54);
  expect(sawCursorReq).toBe(true);
  await expect(page.getByRole("button", { name: "Load more" })).toHaveCount(0); // short last page → end
});

// ⛔ THE INVARIANT WITH THE WEAKEST COVERAGE, DRIVEN END TO END (S12.11).
//
// A deployment administrator can change a role in ANY organization. The rule is that the TARGET org's
// owners see it in THEIR feed — the only feed they read — because a privilege change made inside your
// tenant by somebody outside it is the event you are most owed sight of.
//
// ⚠ TWO HALVES, AND THE SECOND IS THE ONE A DATABASE TEST CANNOT SEE. The row landing in the right org is
// the easy half (`audit_logs.org_id` carries no membership constraint). The half that nearly shipped wrong
// is the RENDER: the screen resolves `actor_id` against the org ROSTER, and a deployment administrator is
// on no roster — so the row would have read "former member 019fc421", a confident false claim about
// somebody who was never a member at all, attached to exactly this event.
test("a cross-tenant grant appears in the TARGET org's audit log, naming the deployment admin", async ({
  page,
}) => {
  // 1. The administrator signs in. They belong to no organization, so they never reach the app shell —
  //    the funnel holds them at /create-org — and that is precisely the account this surface is for.
  await page.goto("/login");
  await page.getByLabel("Email").fill(CP_ADMIN.email);
  await page.getByLabel("Password").fill(CP_ADMIN.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/create-org$/);

  // 2. Two grants, so the spec proves a CHANGE on every run rather than only the first. A re-grant of the
  //    role already held writes nothing (no audit row for an act that did not happen), so a single
  //    idempotent call would stop producing evidence the second time this suite runs against a live DB.
  //    ⚠ No web surface calls these routes yet — registered — so the spec drives the API with the session
  //    the browser just minted, exactly as the unverified-admin server-refusal spec does.
  for (const role of ["member", "admin"]) {
    const resp = await page.request.put(
      `/api/v1/admin/organizations/${SANDBOX_ORG}/members/${GRANTEE}/role`,
      { headers: { "X-Tunnex-CSRF": "1" }, data: { role } },
    );
    expect(resp.status()).toBe(204);
  }

  // 3. The TARGET org's owner reads their own feed.
  await page.context().clearCookies();
  await page.goto("/login");
  await page.getByLabel("Email").fill(SANDBOX_OWNER.email);
  await page.getByLabel("Password").fill(SANDBOX_OWNER.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Audit Log" }).click();
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();

  const row = page
    .getByRole("row")
    .filter({ hasText: "member.role_granted_by_cp_admin" })
    .first();
  await expect(row).toBeVisible();

  // ⛔ NAMED, AND NAMED AS WHAT THEY ARE. The kind is asserted from the DOM attribute, not inferred from
  // the words, so a label that happens to contain the right email by coincidence cannot pass.
  const actor = row.getByTestId("audit-actor");
  await expect(actor).toHaveAttribute("data-actor-kind", "cp_admin");
  await expect(actor).toContainText(CP_ADMIN.email);
  await expect(actor).toContainText("deployment admin");
  await expect(actor).not.toContainText("former member");
  await expect(actor).not.toContainText("not recorded");

  // 4. ⛔ AND IT IS NOT IN ANYONE ELSE'S FEED. "Which org" is half the ruling: a deployment-wide event
  //    filed under an arbitrary tenant would put one org's history in another's. The demo owner — a
  //    different tenant entirely — must see nothing of this.
  await page.context().clearCookies();
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Audit Log" }).click();
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(
    page.getByRole("row").filter({ hasText: "member.role_granted_by_cp_admin" }),
  ).toHaveCount(0);
});
