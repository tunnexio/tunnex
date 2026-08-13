import {
  test,
  expect,
  type Page,
  type APIRequestContext,
} from "@playwright/test";
import * as fs from "fs";

// Round-2 manual walk, Part A — SCRIPTED subset, run against a REAL UNSEEDED open
// stack (no mocks except one deliberate network-abort to exercise a failure path).
// Gated on ROUND2=1: this spec assumes an empty database (the walk's fresh-org
// premise) and MUST NOT run in `make e2e` (which seeds the demo org).
//
// Personas: w1 = the fresh first user (creates the org, takes the single open-
// edition slot); w2 = the second signup that must hit the invitation-only cap.
// Steps A1–A4, A6–A8. A5 (real agent enrollment) runs outside this spec — the
// minted join token is written to /e2e/.walk-token for the compose agent.
// ⛔ MOVED OUT OF `tests/` AND RENAMED `.walk.ts` — S14.7, founder-dispositioned.
//
// This is a BOX-WALK RIG, not a CI test. It needs Mailpit, a real signup flow and round-2 conditions, so it
// legitimately does not belong in the automated suite.
//
// ⚠ BUT IT USED TO LIVE IN `testDir: "./tests"`, so the BLOCKING `e2e` job COLLECTED it and skipped it at
// runtime on `!process.env.ROUND2` — which is set NOWHERE in `.github/workflows/` or the `Makefile`.
//
//   IT HAS NEVER RUN, IN THE JOB S11-1 PROMOTED TO BLOCKING, WHILE READING AS COVERAGE.
//
// That is how two assertions on a string DELETED IN S14.6 survived here: they cannot fail, because nothing
// runs them. A `test.skip(!process.env.X)` inside the suite is indistinguishable from a test that passes.
//
// THE FIX IS PLACEMENT, NOT A FLAG. Out of `testDir` it is no longer collected, no longer counted, and no
// longer claims to be part of the suite. Run it deliberately:
//
//     npx playwright test -c playwright.config.ts walk/round2-walk.walk.ts
//
// (Kept as a `test.skip` guard as well, so an accidental direct run still refuses without ROUND2 set.)
test.skip(
  !process.env.ROUND2,
  "Round-2 walk: run explicitly with ROUND2=1 against an UNSEEDED stack",
);

const MAILPIT = process.env.MAILPIT_URL ?? "http://mailpit:8025";
const W1 = {
  email: "w1@walk.local",
  pass: "walk-password-round2",
  name: "Walk One",
};
const W2 = {
  email: "w2@walk.local",
  pass: "walk-password-round2",
  name: "Walk Two",
};

// ---- Mailpit helpers (real mail, not mocked) --------------------------------

async function latestBodyTo(
  rq: APIRequestContext,
  email: string,
  mustContain: string,
): Promise<string> {
  let body = "";
  await expect
    .poll(
      async () => {
        const res = await rq.get(
          `${MAILPIT}/api/v1/search?query=${encodeURIComponent("to:" + email)}`,
        );
        const { messages } = (await res.json()) as {
          messages: { ID: string }[];
        };
        if (!messages?.length) return "";
        const msg = await rq.get(`${MAILPIT}/api/v1/message/${messages[0].ID}`);
        const detail = (await msg.json()) as { Text?: string; HTML?: string };
        body = `${detail.Text ?? ""}\n${detail.HTML ?? ""}`;
        return body.includes(mustContain) ? body : "";
      },
      {
        timeout: 15_000,
        message: `mail to ${email} containing ${mustContain}`,
      },
    )
    .not.toBe("");
  return body;
}

function extractToken(body: string, path: string): string {
  const m = body.match(new RegExp(`${path}\\?token=([A-Za-z0-9_-]+)`));
  expect(m, `${path} token present in email`).toBeTruthy();
  return m![1];
}

// ---- shared flows -----------------------------------------------------------

async function signup(page: Page, who: typeof W1) {
  await page.goto("/signup");
  await page.getByLabel("Name").fill(who.name);
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password").fill(who.pass);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(
    page.getByRole("heading", { name: "Check your email" }),
  ).toBeVisible();
}

async function login(page: Page, who: typeof W1) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password").fill(who.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

// ---- A1: signup → verify-pending, resend success + failure ------------------

test("A1: fresh signup routes to verify-pending; resend claims Sent only on real success", async ({
  page,
}) => {
  await signup(page, W1);
  // Signup does NOT auto-login (observed; enumeration-resistant 202 + mail).
  await login(page, W1);
  await expect(page).toHaveURL(/\/verify-pending$/); // 0 membership + unverified
  await expect(
    page.getByRole("heading", { name: "Verify your email" }),
  ).toBeVisible();
  await expect(page.getByText(W1.email)).toBeVisible();

  // Failure path FIRST (deliberate network abort — the walk's "kill the network"):
  await page.route("**/api/v1/auth/verify-email/resend", (r) => r.abort());
  await page.getByRole("button", { name: "Resend link" }).click();
  await expect(page.getByText(/Couldn.t send/)).toBeVisible(); // no false "Sent"
  await expect(page.getByRole("button", { name: "Resend link" })).toBeVisible(); // retry stays

  // Then the real resend:
  await page.unroute("**/api/v1/auth/verify-email/resend");
  await page.getByRole("button", { name: "Resend link" }).click();
  await expect(page.getByText(/Sent — check your inbox/)).toBeVisible();

  // Real mail arrived (signup + resend → at least the verify link is in Mailpit).
  await latestBodyTo(page.request, W1.email, "/verify-email?token=");
});

// ---- A2: verify link → create-org; session observation -----------------------

test("A2: the verify link works; RECORD: it does NOT establish a session (re-login required)", async ({
  page,
  browser,
}) => {
  const body = await latestBodyTo(
    page.request,
    W1.email,
    "/verify-email?token=",
  );
  const token = extractToken(body, "/verify-email");

  // Fresh anonymous context — the out-of-band email click, as the walk frames it.
  const anon = await browser.newContext();
  const apage = await anon.newPage();
  await apage.goto(`/verify-email?token=${token}`);
  await expect(apage.getByText(/verified/i).first()).toBeVisible();
  // KEY A2 OBSERVATION (feeds S5.1-D3): the verify click does NOT log you in —
  // /dashboard from this context bounces to /login.
  await apage.goto("/dashboard");
  await expect(apage).toHaveURL(/\/login$/);
  await anon.close();

  // After re-login the funnel routes the now-verified 0-org user to create-org.
  await login(page, W1);
  await expect(page).toHaveURL(/\/create-org$/);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toBeVisible();
});

// ---- A3: slug derivation edge cases, then the real create --------------------

test("A3: slug edge cases behave; create succeeds → first dashboard", async ({
  page,
}) => {
  await login(page, W1);
  await expect(page).toHaveURL(/\/create-org$/);
  const name = page.getByLabel("Organization name");
  const slug = page.getByLabel("Slug");
  const submit = page.getByRole("button", { name: "Create organization" });

  await name.fill("Acme Corp-");
  await expect(slug).toHaveValue("acme-corp"); // no trailing hyphen
  await expect(submit).toBeEnabled();

  await name.fill("Ächme  Spaces");
  await expect(slug).toHaveValue("chme-spaces"); // umlaut dropped, not transliterated (RECORD: friction)
  await expect(submit).toBeEnabled();

  await name.fill("🎉");
  await expect(slug).toHaveValue(""); // nothing sluggable
  await expect(submit).toBeDisabled(); // disabled until a slug exists — user may type one manually
  await slug.fill("party");
  await expect(submit).toBeEnabled(); // manual slug un-sticks it (not stuck-disabled)

  await name.fill("A");
  await expect(slug).toHaveValue("party"); // manual slug latched; name edit no longer overwrites

  // The real create — takes the deployment's single open-edition org slot.
  await name.fill("Walk Org");
  await slug.fill("walk-org");
  await submit.click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("Walk Org")).toBeVisible();
});

// ---- A4: gateway empty state → one-time join-token ceremony → audit ---------

test("A4: enroll empty state → ceremony (no route back); audit row is raw-token-free", async ({
  page,
}) => {
  await login(page, W1);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  // Fresh-org empty state offers the affordance.
  await expect(page.getByText("No gateway enrolled yet.")).toBeVisible();
  await page.getByRole("link", { name: /Enroll a gateway/ }).click();
  await expect(
    page.getByRole("heading", { name: "Gateways", level: 1 }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Enroll gateway" }).click();
  await page.getByLabel(/Gateway name/).fill("walk-gw");
  await page.getByRole("button", { name: "Generate join token" }).click();

  // The S4.5-style ceremony: amber, shown-once, explicit ack.
  await expect(
    page.getByText("Enroll your gateway: run this once"),
  ).toBeVisible();
  // Extract ONLY the token value — since S4.8 the pre line also carries
  // TUNNEX_NODE_NAME for a name-pinned token; a prefix-strip would smuggle the
  // suffix into .walk-token (breaking A5 enrollment) AND make the no-resurrect /
  // audit-leak assertions below search for a never-occurring string (vacuous).
  const pre = await page.locator("pre").textContent();
  const token = pre!.match(/TUNNEX_JOIN_TOKEN=(\S+)/)![1];
  expect(token.length).toBeGreaterThan(10);
  // Hand the token to the out-of-band A5 enrollment step (the compose agent).
  fs.writeFileSync("/e2e/.walk-token", token);

  await page.getByRole("button", { name: /I.?ve saved it/ }).click();
  await expect(
    page.getByText("Enroll your gateway: run this once"),
  ).toHaveCount(0);
  // No route back: a reload must not resurrect the token.
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Gateways", level: 1 }),
  ).toBeVisible();
  await expect(page.getByText(token)).toHaveCount(0);

  // Audit: the issuance row exists and is secret-free (raw token nowhere on page).
  await page.getByRole("link", { name: "Audit Log" }).click();
  await expect(page.getByText("node.token_issued")).toBeVisible();
  await expect(page.getByText(token)).toHaveCount(0);
  // RECORD (walk expects a fingerprint in the row): capture what details actually show.
  const row = page
    .getByRole("row")
    .filter({ hasText: "node.token_issued" })
    .first();
  console.log("A4 AUDIT ROW DETAILS →", (await row.textContent())?.trim());
});

// ---- A6: second signup hits the real open-edition cap ------------------------

test("A6: second fresh signup ends on the invitation card with no usable create control (real 403)", async ({
  page,
}) => {
  await signup(page, W2);
  const body = await latestBodyTo(
    page.request,
    W2.email,
    "/verify-email?token=",
  );
  await page.goto(`/verify-email?token=${extractToken(body, "/verify-email")}`);
  await expect(page.getByText(/verified/i).first()).toBeVisible();

  await login(page, W2);
  await expect(page).toHaveURL(/\/create-org$/); // verified + 0 org → create step
  await page.getByLabel("Organization name").fill("Second Walk Org");
  await page.getByRole("button", { name: "Create organization" }).click();
  // REAL org_limit_reached (Walk Org holds the slot) → dead-end, form gone.
  await expect(
    page.getByRole("heading", { name: "Invitation required" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Create organization" }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Organization name")).toHaveCount(0);
  await expect(page.getByLabel("Slug")).toHaveCount(0);
});

// ---- A7: manual /create-org visit while holding an org -----------------------

test("A7: a with-org user visiting /create-org is re-routed to the dashboard at visit time", async ({
  page,
}) => {
  // The original walk run OBSERVED the form rendering here (friction F4 in
  // ROUND2-REPORT.md); S4.8 added the RequireNoOrg visit-time guard. This now
  // asserts the walk's ORIGINAL expectation.
  await login(page, W1);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.goto("/create-org");
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(
    page.getByRole("heading", { name: "Create your organization" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Invitation required" }),
  ).toHaveCount(0);
});

// ---- A8: logout, reset-revokes-all-sessions, cookie TTL ----------------------

test("A8: logout works; password reset revokes the OTHER session; session cookie TTL recorded", async ({
  browser,
}) => {
  // Two independent browsers, both logged in as w1.
  const ctx1 = await browser.newContext();
  const ctx2 = await browser.newContext();
  const p1 = await ctx1.newPage();
  const p2 = await ctx2.newPage();
  await login(p1, W1);
  await login(p2, W1);
  await expect(p1.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(p2.getByRole("heading", { name: "Overview" })).toBeVisible();

  // Cookie TTL observation (feeds S5.1-D3).
  for (const c of await ctx1.cookies()) {
    console.log(
      `A8 COOKIE → ${c.name}: httpOnly=${c.httpOnly} secure=${c.secure} sameSite=${c.sameSite} expires=${c.expires === -1 ? "session" : new Date(c.expires * 1000).toISOString()}`,
    );
  }

  // Reset from a THIRD, anonymous context (/forgot-password is AnonOnly — a
  // logged-in browser is bounced to the app; RECORDED as an observation below).
  const ctx3 = await browser.newContext();
  const p3 = await ctx3.newPage();
  await p3.goto("/forgot-password");
  await p3.getByLabel("Email").fill(W1.email);
  await p3.getByRole("button", { name: /Send|Reset/ }).click();
  const body = await latestBodyTo(
    p3.request,
    W1.email,
    "/reset-password?token=",
  );
  const newPass = "walk-password-round2-NEW";
  await p3.goto(
    `/reset-password?token=${extractToken(body, "/reset-password")}`,
  );
  await p3.getByLabel("New password").fill(newPass);
  await p3.getByRole("button", { name: "Update password" }).click();
  await expect(
    p3.getByRole("heading", { name: "Password updated" }),
  ).toBeVisible();
  await ctx3.close();

  // Browser 2's session must be REVOKED (S2.2 rule), not merely browser 1's.
  await p2.goto("/dashboard");
  await expect(p2).toHaveURL(/\/login$/);

  // Old password refused, new one works; then logout bounces to /login.
  await login(p1, W1);
  await expect(p1.getByText(/invalid email or password/i)).toBeVisible();
  await login(p1, { ...W1, pass: newPass });
  await expect(p1.getByRole("heading", { name: "Overview" })).toBeVisible();
  await p1.getByRole("button", { name: "Log out" }).click();
  await expect(p1).toHaveURL(/\/login$/);
  await p1.goto("/dashboard");
  await expect(p1).toHaveURL(/\/login$/);

  await ctx1.close();
  await ctx2.close();
});
