import { test, expect, type Page } from "@playwright/test";

// ⭐ REWRITTEN AGAINST THE PRODUCT AS IT IS (S12.11). The funnel these specs were written for asked ONE
// question — "do you have an organization?" — and offered a create form to everyone who did not. Two
// rulings changed that, and the specs were skipped in a batch rather than re-pointed:
//
//   1. THERE IS NO PUBLIC SIGNUP. A verified account with no membership is not a founder-in-waiting; they
//      are somebody awaiting an invitation, and `create-org` shows them the invitation card FIRST rather
//      than a form that would refuse them after they filled it in.
//   2. `cp_admin` IS THE CAPABILITY. A holder reaches this route deliberately, from the switcher's "+ New",
//      WITH organizations already in hand — so "already has an org → bounce" became wrong for exactly the
//      people the route now exists for.
//
// ⚠ ONE OF THE SEVEN IS DELETED RATHER THAN REWRITTEN, with its reason recorded where it stood.

// S4.7 Fresh-user onboarding funnel. The e2e stack is the OPEN edition. The seeded
// users all already belong to the demo org, so the zero-org branches (create-org,
// verify-pending, invitation-only) are driven by MOCKING GET /organizations to
// return [] for the logged-in user — the same UI-render convention the audit /
// settings specs use. The has-org happy path and the enroll ceremony run against
// the REAL backend.
const OWNER = {
  email: "owner@demo.tunnex.local",
  pass: "tunnex-demo-password",
}; // verified, has demo org
// A VERIFIED user with NO membership (seeddata.DemoNoOrgUser) — the real fresh-
// signup state. Because the open-edition single-org slot is already taken by the
// demo org, this user's create attempt is refused by the REAL backend, so the
// routing and the invitation-only cap are proven end-to-end, not mocked.
const FRESH = {
  email: "fresh-user@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
const UNVERIFIED = {
  email: "unverified-admin@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
// Has the demo org, holds NO capability — the "already inside, may not create" state.
const MEMBER = {
  email: "member@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
const ORG = "01900000-0000-7000-8000-000000000001"; // seeddata.DemoOrgID

// Matches …/api/v1/organizations exactly (optional query) — NOT the sub-resource
// paths like …/organizations/{id}/overview, so those still hit the real backend.
const ORGS_URL = /\/api\/v1\/organizations(\?.*)?$/;

// Raw sign-in that does NOT assert it lands on Overview — a zero-org user is
// bounced into the funnel instead of the dashboard.
async function signIn(page: Page, who: { email: string; pass: string }) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password").fill(who.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("a verified user with no organization and no capability lands on the invitation card (real backend)", async ({
  page,
}) => {
  // No mock — the real fresh user has zero memberships and does NOT hold cp_admin, which is the state
  // every invited-but-not-yet-admitted account is in.
  await signIn(page, FRESH);
  await expect(page).toHaveURL(/\/create-org$/);
  // ⛔ THE CARD IS THE FIRST THING THEY SEE, NOT THE LAST. It used to be one FAILED SUBMIT away: the
  // funnel routed them to a form, the server refused `invitation_required`, and only then were they told
  // how to actually get in. A form offered to someone who cannot use it costs them an attempt to learn
  // what the screen could have said first.
  await expect(
    page.getByRole("heading", { name: "Invitation required" }),
  ).toBeVisible();
  // ⚠ NO USABLE CREATE AFFORDANCE SURVIVES — form, fields and button all absent. Asserting only the
  // heading would pass on a page that rendered the card ABOVE a working form.
  await expect(
    page.getByRole("button", { name: "Create organization" }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Organization name")).toHaveCount(0);
  await expect(page.getByLabel("Slug")).toHaveCount(0);
});

test("an unverified user with no organization is routed to verify-pending, not create-org", async ({
  page,
}) => {
  await page.route(ORGS_URL, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  );
  await signIn(page, UNVERIFIED);
  // Create-org is verified-gated server-side, so the funnel sends them to verify
  // FIRST (structural refusal, not a surprise 403 after filling the form).
  await expect(
    page.getByRole("heading", { name: "Verify your email" }),
  ).toBeVisible();
  await expect(page.getByText(UNVERIFIED.email)).toBeVisible();
  await expect(page).toHaveURL(/\/verify-pending$/);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toHaveCount(0);
});

test("a user who already has an organization skips the funnel and lands on the dashboard", async ({
  page,
}) => {
  // No mock — the real demo org membership must send the owner straight to the shell.
  await signIn(page, OWNER);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toHaveCount(0);
});

// ⛔ DELETED, WITH ITS REASON KEPT WHERE IT STOOD: "the open-build second-signup path ends on the
// invitation card with no usable create affordance (real backend)".
//
// It proved that a fresh user who FILLS IN the create form is refused and lands on the invitation card
// with every create control gone. Its trigger no longer exists — that user never reaches a form, because
// the card is now what `create-org` renders for anyone without `cp_admin`. Every assertion it made about
// the destination is made by the spec above, at the earlier moment.
//
// ⚠ Kept as a comment rather than dropped silently: the next person to read this file will otherwise ask
// where the open-edition second-org proof went.

test("a successful create routes the fresh user into the dashboard", async ({
  page,
}) => {
  const ORG_OBJ = {
    id: ORG,
    name: "Funnel Org",
    slug: "funnel-org",
    pool_cidr: "10.99.0.0/24",
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
  };
  // Stateful: the list is empty until the org is created, then contains it — so
  // RequireOrg funnels first, then (after the POST) admits the user to the shell.
  let created = false;
  await page.route(ORGS_URL, (route) => {
    if (route.request().method() === "POST") {
      created = true;
      return route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify(ORG_OBJ),
      });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(created ? [ORG_OBJ] : []),
    });
  });
  await page.route(/\/api\/v1\/organizations\/[^/]+\/overview$/, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        members: 1,
        devices: 0,
        nodes: 0,
        online: 0,
        recent_activity: [],
      }),
    }),
  );
  // ⚠ THE OWNER, BECAUSE THIS SPEC NEEDS A CAPABILITY HOLDER. The form is only rendered to `cp_admin`
  // now, and the seeded owner is the deployment's holder; the mock supplies the zero-org half.
  await signIn(page, OWNER);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toBeVisible();

  // A manually-typed hyphenated slug must survive left-to-right typing — the sanitizer must not strip a
  // trailing hyphen mid-word (else "acme-corp" would collapse to "acmecorp"). pressSequentially fires one
  // onChange per key. ⚠ MOVED HERE from the fresh-user spec, which no longer renders a form at all.
  const typed = page.getByLabel("Slug");
  await typed.click();
  await typed.pressSequentially("acme-corp");
  await expect(typed).toHaveValue("acme-corp");

  await page.getByLabel("Organization name").fill("Funnel Org");
  await page.getByLabel("Slug").fill(""); // unlatch back to name-derived
  await expect(page.getByLabel("Slug")).toHaveValue("funnel-org"); // auto-derived
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  // ⛔ THE SWITCHER, NOT A BARE TEXT MATCH. S12.5 renders the org name in the header too, so
  // getByText("Funnel Org") now resolves to two elements and trips strict mode — and the switcher is the
  // stronger assertion anyway: the newly created org is the one SELECTED, not merely mentioned.
  await expect(page.getByRole("combobox", { name: "Organization" })).toHaveValue(
    ORG,
  );
  await expect(page).toHaveURL(/\/dashboard$/);
});

// ⭐ RE-POINTED AT THE BRANCH THAT IS NOW REACHABLE. This spec used to prove the OTHER arm of
// `org_limit_reached`: a zero-org user whose membership appeared between the funnel and the refusal is
// re-checked and sent to the dashboard instead of the dead-end card.
//
// ⛔ THAT ARM CAN NO LONGER BE REACHED THROUGH THE UI, and a spec that drives it would have to fake the
// product to do so. A user without `cp_admin` never sees the form — `create-org` renders the invitation
// card to them — so nobody without the capability can submit and be refused. REGISTERED as a finding
// rather than fixed here: the re-check branch in CreateOrg.tsx is now dead code, and dead defensive code
// is exactly what stops being true without anybody noticing.
//
// What IS reachable, and what a paying customer actually hits, is the holder's arm: the person who CAN
// install a licence must be offered the route rather than the invitation card written for a stranger.
test("a capability holder who hits the organization ceiling is offered the upgrade route, not a dead end", async ({
  page,
}) => {
  const ORG_OBJ = {
    id: ORG,
    name: "Joined Org",
    slug: "joined-org",
    pool_cidr: "10.99.0.0/24",
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
  };
  let posted = false; // the membership "appears" only after the create is refused
  await page.route(ORGS_URL, (route) => {
    if (route.request().method() === "POST") {
      posted = true;
      return route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "org_limit_reached",
            message: "single organization only",
          },
        }),
      });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(posted ? [ORG_OBJ] : []),
    });
  });
  await page.route(/\/api\/v1\/organizations\/[^/]+\/overview$/, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        members: 1,
        devices: 0,
        nodes: 0,
        online: 0,
        recent_activity: [],
      }),
    }),
  );
  await signIn(page, OWNER);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toBeVisible();
  await page.getByLabel("Organization name").fill("Whatever Org");
  await page.getByRole("button", { name: "Create organization" }).click();
  // The server's own refusal text — it names the band, the ceiling and what is unaffected — plus a route
  // out of it. ⛔ The invitation card must NOT appear: it tells a holder to ask an administrator for an
  // invitation, and they ARE the administrator.
  await expect(
    page.getByRole("heading", { name: "Organization limit reached" }),
  ).toBeVisible();
  await expect(page.getByText("single organization only")).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Install a licence key" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Invitation required" }),
  ).toHaveCount(0);
});

// ⛔ BOTH DIRECTIONS, BECAUSE THE RULE ITSELF SPLIT IN TWO. S4.8/F4 bounced anyone with an organization
// away from /create-org, so the form could not render pointlessly. S12.5 made this route the ONLY place
// org creation lives, reached from the switcher's "+ New" — so bouncing a capability holder would make
// that affordance a dead link, while bouncing everyone else is still exactly right.
test("/create-org bounces a member who already has an org, and admits a capability holder (S4.8/F4)", async ({
  page,
}) => {
  // Real backend. The demo member belongs to the demo org and holds no capability.
  await signIn(page, MEMBER);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.goto("/create-org");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toHaveCount(0);

  // The holder reaches the same URL deliberately and must NOT be bounced.
  await page.goto("/logout").catch(() => {});
  await page.context().clearCookies();
  await signIn(page, OWNER);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.goto("/create-org");
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/create-org$/);
});

test("enrolling a gateway shows the join token exactly once (one-time-secret ceremony)", async ({
  page,
}) => {
  const TOKEN = "jt-onboarding-secret-xyz";
  let issued = 0;
  await page.route("**/api/v1/organizations/*/nodes/join-token", (route) => {
    issued++;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ join_token: TOKEN }),
    });
  });
  // Owner has the real demo org → straight to the shell, then to Devices where the
  // Gateways enroll ceremony lives.
  await signIn(page, OWNER);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Gateways" }).click();
  // The page also contains an enrolment-card h2 named "Gateways" after data loads. Target the page-title
  // h1 semantically; the broad locator raced that async render and failed strict mode on 3 main runs.
  await expect(
    page.getByRole("heading", { name: "Gateways", level: 1 }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Enroll gateway" }).click();
  // Name the gateway: the token is PINNED to this name server-side, so the
  // ceremony must emit the COMPLETE env line incl. TUNNEX_NODE_NAME (Round-2
  // friction F1 — without it the agent loops node_name_mismatch).
  await page.getByLabel(/Gateway name/).fill("walk-gw");
  await page.getByRole("button", { name: "Generate join token" }).click();

  // The one-time ceremony: amber modal, command shown, must be acknowledged.
  await expect(
    // ⛔ THE EXACT STRING, not /Enroll your gateway/i. The regex was introduced when an em-dash sweep
    // changed this title, and it matches even if "run this once" is deleted — it removed coverage rather
    // than tracking the change. An assertion loosened to make a red go away is a check that has stopped
    // asserting the thing it names.
    page.getByText("Enroll your gateway: run this once"),
  ).toBeVisible();
  // The COMPLETE runnable command (S6.6 / zero-touch ruling): a SINGLE `docker run` (NEVER compose — the
  // paste-mismatch is structurally impossible), carrying the token env AND the shell-quoted pinned name (an
  // unquoted space would truncate the value on paste). Assert the SHAPE the unit test (enrollcommand.test.ts,
  // the authority for the zero-touch ruling) encodes — robust to the CP's image/URL config, not a brittle
  // full-string match.
  const pre = page.locator("pre");
  await expect(pre).toContainText("docker run ");
  await expect(pre).toContainText(`-e TUNNEX_JOIN_TOKEN=${TOKEN}`);
  await expect(pre).toContainText(`-e TUNNEX_NODE_NAME="walk-gw"`);
  await expect(pre).not.toContainText("docker compose");
  await expect(page.getByText(/Pinned to the name/)).toBeVisible();
  await page.getByRole("button", { name: /I.?ve saved it/ }).click();
  // Dismissed → the token is gone from the page (never re-served).
  await expect(page.getByText(new RegExp(TOKEN))).toHaveCount(0);
  expect(issued).toBe(1);

  // UNNAMED branch: a second mint without a name must render the PLAIN single-`docker run` line —
  // the token but NO TUNNEX_NODE_NAME, no pinning note, and no stale pinned name leaking from the
  // previous (named) ceremony.
  await page.getByRole("button", { name: "Enroll gateway" }).click();
  await page.getByRole("button", { name: "Generate join token" }).click();
  await expect(pre).toContainText("docker run ");
  await expect(pre).toContainText(`-e TUNNEX_JOIN_TOKEN=${TOKEN}`);
  await expect(pre).not.toContainText("TUNNEX_NODE_NAME");
  await expect(pre).not.toContainText("docker compose");
  await expect(page.getByText(/Pinned to the name/)).toHaveCount(0);
  await page.getByRole("button", { name: /I.?ve saved it/ }).click();
  expect(issued).toBe(2);
});
