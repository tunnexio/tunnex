import { test, expect, type Page } from "@playwright/test";

// S4.4 Users & roles UI. Runs SERIALLY and leaves the seed state as it found it
// (the role-change test reverts) so it can't interfere with itself or other
// specs. The seed provides an owner and a plain member in the demo org.
test.describe.configure({ mode: "serial" });

const OWNER = {
  email: "owner@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
const MEMBER = {
  email: "member@demo.tunnex.local",
  pass: "tunnex-demo-password",
};
const UNVERIFIED_ADMIN = {
  email: "unverified-admin@demo.tunnex.local",
  pass: "tunnex-demo-password",
};

async function loginAs(page: Page, who: { email: string; pass: string }) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password", { exact: true }).fill(who.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Users & Groups" }).click();
  await expect(page).toHaveURL(/\/users$/);
  await expect(page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Users", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("table", { name: "Members", exact: true })).toBeVisible();
}

async function openRoles(page: Page, email: string) {
  const row = page.getByRole("table", { name: "Members", exact: true }).getByRole("row").filter({ hasText: email });
  await row.getByRole("button", { name: `User actions for ${email}`, exact: true }).click();
  await page.getByRole("menuitem", { name: "Edit roles", exact: true }).click();
  const detail = page.getByRole("region", { name: "Person details" });
  await expect(detail.getByRole("navigation", { name: "Person detail sections" }).getByRole("button", { name: "Roles", exact: true })).toHaveAttribute("aria-current", "step");
  const roles = detail.getByRole("group", { name: `Roles for ${email}`, exact: true });
  await expect(roles).toBeVisible();
  return roles;
}

// (a) DENY view: a plain member may see the roster but is offered NO management
// controls — the UI mirrors the RBAC matrix (member lacks member:invite/manage).
test("a member sees the roster but no management controls", async ({
  page,
}) => {
  await loginAs(page, MEMBER);
  // Scope to roster rows — the logged-in user's email also shows in the
  // header, so a bare getByText would match twice.
  await expect(
    page.getByRole("row").filter({ hasText: OWNER.email }),
  ).toBeVisible();
  await expect(
    page.getByRole("row").filter({ hasText: MEMBER.email }),
  ).toBeVisible();
  // No invitation or role editor, including hidden role controls.
  await expect(page.getByRole("button", { name: "Invite user", exact: true, includeHidden: true })).toHaveCount(0);
  await expect(page.getByLabel("Email address")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^User actions for /, includeHidden: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Save roles", exact: true, includeHidden: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Deactivate", exact: true, includeHidden: true })).toHaveCount(0);
  await expect(page.getByRole("table", { name: "Members" }).getByRole("checkbox", { includeHidden: true })).toHaveCount(0);
  // Inspection remains available, while the focused Roles view has no authoring controls.
  await page.getByRole("table", { name: "Members" }).getByRole("row").filter({ hasText: MEMBER.email }).getByRole("button", { name: "Demo Member", exact: true }).click();
  const detail = page.getByRole("region", { name: "Person details" });
  await detail.getByRole("navigation", { name: "Person detail sections" }).getByRole("button", { name: "Roles", exact: true }).click();
  await expect(detail.getByRole("group", { name: `Roles for ${MEMBER.email}`, exact: true })).toContainText("member");
  await expect(detail.getByRole("checkbox", { includeHidden: true })).toHaveCount(0);
  await expect(detail.getByRole("button", { name: "Save roles", exact: true, includeHidden: true })).toHaveCount(0);
});

// (a) ALLOW view: an owner gets the invite form and per-member controls.
test("an owner sees the invite form and per-member controls", async ({
  page,
}) => {
  await loginAs(page, OWNER);
  await page.getByRole("button", { name: "Invite user" }).click();
  await expect(page.getByLabel("Email address")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  // Role editing now uses the member's row menu and focused detail panel.
  const memberRow = page
    .getByRole("table", { name: "Members" })
    .getByRole("row")
    .filter({ hasText: MEMBER.email });
  await memberRow.getByRole("button", { name: `User actions for ${MEMBER.email}`, exact: true }).click();
  await expect(page.getByRole("menuitem", { name: "Deactivate", exact: true })).toBeEnabled();
  await expect(page.getByRole("menuitem", { name: "Reset 2FA", exact: true })).toBeEnabled();
  await page.getByRole("menuitem", { name: "Edit roles", exact: true }).click();
  const detail = page.getByRole("region", { name: "Person details" });
  const roles = detail.getByRole("group", { name: `Roles for ${MEMBER.email}`, exact: true });
  await expect(roles.getByRole("checkbox", { name: "member", exact: true })).toBeChecked();
  await expect(roles.getByRole("checkbox", { name: "admin", exact: true })).toBeEnabled();
  await detail.getByRole("button", { name: "Back to users", exact: true }).click();
  // Bulk account management remains separate from role authoring.
  await memberRow.getByRole("checkbox", { name: `Select ${MEMBER.email}`, exact: true }).check();
  await expect(page.getByRole("group", { name: "Selected member actions" }).getByRole("button", { name: "Deactivate", exact: true })).toBeEnabled();
});

// (a) Verified-gate: an admin has the ROLE to invite/manage, but with an
// unverified email the server 403s every such mutation — so the UI must offer
// none of those controls (role grant is necessary, not sufficient).
test("an unverified admin is offered no mutating controls despite the role", async ({
  page,
}) => {
  await loginAs(page, UNVERIFIED_ADMIN);
  await expect(
    page.getByRole("row").filter({ hasText: MEMBER.email }),
  ).toBeVisible(); // can still read the roster
  await expect(page.getByRole("button", { name: "Invite user", exact: true, includeHidden: true })).toHaveCount(0);
  await expect(page.getByLabel("Email address")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^User actions for /, includeHidden: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Save roles", exact: true, includeHidden: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Deactivate", exact: true, includeHidden: true })).toHaveCount(0);
  await expect(page.getByRole("table", { name: "Members" }).getByRole("checkbox", { includeHidden: true })).toHaveCount(0);
  await page.getByRole("table", { name: "Members" }).getByRole("row").filter({ hasText: MEMBER.email }).getByRole("button", { name: "Demo Member", exact: true }).click();
  const detail = page.getByRole("region", { name: "Person details" });
  await detail.getByRole("navigation", { name: "Person detail sections" }).getByRole("button", { name: "Roles", exact: true }).click();
  await expect(detail.getByRole("group", { name: `Roles for ${MEMBER.email}`, exact: true })).toContainText("member");
  await expect(detail.getByRole("checkbox", { includeHidden: true })).toHaveCount(0);
  await expect(detail.getByRole("button", { name: "Save roles", exact: true, includeHidden: true })).toHaveCount(0);
});

// (a) The verified-gate is a SERVER control, not just a UI one: a direct API
// call (bypassing the hidden UI) from the unverified admin is refused 403
// email_not_verified. This proves the UI gate is honest mirroring, not a
// UI-only security control an attacker could curl around.
test("the server (not just the UI) refuses a mutation from an unverified admin", async ({
  page,
}) => {
  const ORG = "01900000-0000-7000-8000-000000000001"; // seeddata.DemoOrgID
  const MEMBER_ID = "01900000-0000-7000-8000-000000000003"; // seeddata.DemoMemberUserID
  await loginAs(page, UNVERIFIED_ADMIN);
  for (const [suffix, data] of [
    ["role", { role: "member" }],
    ["roles", { roles: ["member", "ai-view"] }],
  ] as const) {
    const resp = await page.request.put(
      `/api/v1/organizations/${ORG}/members/${MEMBER_ID}/${suffix}`,
      { headers: { "X-Tunnex-CSRF": "1" }, data },
    );
    expect(resp.status()).toBe(403);
    expect(JSON.parse(await resp.text()).error.code).toBe("email_not_verified");
  }
});

// (b) Last-owner: the sole owner's own role control is disabled-with-explanation
// (client mirror of the server's last-owner refusal).
test("the sole owner's own role control is disabled with an explanation", async ({
  page,
}) => {
  await loginAs(page, OWNER);
  const roles = await openRoles(page, OWNER.email);
  const ownerRole = roles.getByRole("checkbox", { name: "owner", exact: true });
  await expect(ownerRole).toBeChecked();
  await expect(ownerRole).toBeDisabled();
  await expect(ownerRole).toHaveAttribute("title", /at least one owner/i);
});

// (c) Invite enumeration resistance: inviting an address that already has an
// account renders IDENTICALLY to inviting a brand-new one — no account-existence
// tell.
test("invite renders identically for an existing account vs a new email", async ({
  page,
}) => {
  await loginAs(page, OWNER);
  const ORG = "01900000-0000-7000-8000-000000000001"; // seeddata.DemoOrgID

  // The real proof is that BOTH invites reach the success confirmation with NO
  // error shown. Success now surfaces the one-time invite-link modal (constant
  // chrome — title "Invitation link"); the meaningful signal is that neither path
  // errors — a server enumeration tell would 409/error the existing-account invite,
  // so the modal would never appear and an error would be masked. The modal is
  // dismissed between invites (it's a fixed overlay covering the form).
  async function inviteSucceedsCleanly(email: string) {
    await page.getByRole("button", { name: "Invite user" }).click();
    await page.getByLabel("Email address").fill(email);
    await page.getByRole("button", { name: "Create invite" }).click();
    await expect(page.getByText("Invitation link")).toBeVisible();
    await expect(
      page.getByText(/could not create the invitation/i),
    ).toHaveCount(0);
    await page.getByRole("button", { name: /I.?ve saved it/i }).click();
    await expect(page.getByText("Invitation link")).toHaveCount(0);
  }

  const fresh = `nobody-${Date.now()}@example.com`;
  await inviteSucceedsCleanly(MEMBER.email); // an address that already has an account
  await inviteSucceedsCleanly(fresh); // a brand-new address — indistinguishable from the above

  // Clean up the pending invites we created so the test is re-runnable (the
  // invite table would otherwise 409 "invite_pending" on the next run). Uses the
  // owner's authenticated session shared with the page context.
  for (const email of [MEMBER.email, fresh]) {
    await page.request.post(`/api/v1/organizations/${ORG}/invitations/revoke`, {
      headers: { "X-Tunnex-CSRF": "1" },
      data: { email },
    });
  }
});

// (e) Audit loop: a mutation in the Users UI lands in the audit log and is RENDERED
// (the cheapest full-stack proof: UI -> API -> audit -> read -> render). Reverts the role to leave state
// clean.
//
// ⚠ RE-POINTED FROM THE DASHBOARD TO THE AUDIT LOG, AND THE LOOP IS INTACT. f5f84a8a removed the Overview
// activity feed, which was this test's render surface — not its subject. The subject is "a UI mutation
// becomes a readable audit event", and the Audit Log page is where that is now readable.
//
// ⛔ NOT the same as deleting the test: the read surface changed, the invariant did not. Had no surface
// survived, this would be a capability the product lost and would have been reported as one instead.
test("a role change in the UI appears in the audit log", async ({ page }) => {
  const ORG = "01900000-0000-7000-8000-000000000001"; // seeddata.DemoOrgID
  const MEMBER_ID = "01900000-0000-7000-8000-000000000003"; // seeddata.DemoMemberUserID
  await loginAs(page, OWNER);
  try {
    const roles = await openRoles(page, MEMBER.email);
    await roles.getByRole("checkbox", { name: "admin", exact: true }).check();
    const saved = page.waitForResponse((response) =>
      response.url().endsWith(`/members/${MEMBER_ID}/roles`) &&
      response.request().method() === "PUT",
    );
    await page.getByRole("region", { name: "Person details" }).getByRole("button", { name: "Save roles", exact: true }).click();
    expect((await saved).status()).toBe(204);
    await expect(roles.getByRole("checkbox", { name: "admin", exact: true })).toBeChecked();
    await expect(roles.getByRole("checkbox", { name: "member", exact: true })).toBeChecked();
    await expect(page.getByText("Roles updated.", { exact: true })).toBeVisible();
    await page.getByRole("region", { name: "Person details" }).getByRole("button", { name: "Back to users", exact: true }).click();
    const memberRow = page.getByRole("table", { name: "Members", exact: true }).getByRole("row").filter({ hasText: MEMBER.email });
    await expect(memberRow.getByRole("cell", { name: "admin + member", exact: true })).toBeVisible();

    await page.getByRole("link", { name: "Audit Log" }).click();
    await expect(page).toHaveURL(/\/audit(?:\?|$)/);
    await expect(page.getByRole("combobox", { name: "Actor" })).toBeVisible();
    await expect(page.getByText("member.role_changed").first()).toBeVisible();
  } finally {
    // ALWAYS restore the exact role set so a mid-test failure can't leave the shared
    // seed dirty and poison the (serial) deny-view test. Uses the API directly
    // (the owner's session is shared with the page context) so the revert does
    // not depend on the UI being in a navigable state.
    const restored = await page.request.put(
      `/api/v1/organizations/${ORG}/members/${MEMBER_ID}/roles`,
      {
        headers: { "X-Tunnex-CSRF": "1" },
        data: { roles: ["member"] },
      },
    );
    expect(restored.status()).toBe(204);
  }
});
