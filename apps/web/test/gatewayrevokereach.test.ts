import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { stripJsComments } from "./support/source";

/**
 * ⛔ THE SIXTH INSTANCE OF THE CLASS: A LAYOUT DECISION SILENTLY DELETED A CAPABILITY.
 *
 * `POST /nodes/{nodeId}/revoke` has existed since S11, with a two-step confirm, inside `EnrolCeremony`'s
 * own list. The Gateways page renders that component with `renderList={false}` — it owns the list itself —
 * so the action went off WITH the list, and the tables that replaced it never grew one.
 *
 * ⚠ NOTHING WENT RED. The component still exists, its own tests still pass, and the endpoint is still
 * wired. What broke is REACHABILITY, which no component-scoped test asks about.
 *
 * > ## ⛔ **THE GUARD MUST BE ABOUT THE ACTION BEING REACHABLE, NOT ABOUT A COMPONENT EXISTING** — the
 * > ## component existing is exactly what was true the whole time the control was gone.
 *
 * ⚠ SO IT READS THE PAGE, and it reads it for the CALL rather than for a label: a button wired to nothing
 * would pass a text search. And it survives whatever `renderList` does, because the page's own column is
 * what it asserts.
 */
// ⛔ COMMENTS STRIPPED, AND A CENSUS-OF-CENSUSES CAUGHT THAT I HAD NOT. The doc comment above CONTAINS the
// endpoint path this test hunts for, so a raw read would have matched its own prose — reporting the action
// present because I had described it. The guard would have passed with the button deleted.
const page = stripJsComments(readFileSync("src/pages/Gateways.tsx", "utf8"));

describe("revoking a gateway is reachable from the Gateways page", () => {
  it("⛔ the page itself calls the revoke endpoint — not only the component it switches off", () => {
    expect(
      page.includes("/api/v1/organizations/{orgId}/nodes/{nodeId}/revoke"),
      "The page renders EnrolCeremony with renderList={false}, so any action living only in that " +
        "component is unreachable here. The ceiling notice tells an operator to 'revoke a gateway you no " +
        "longer use' — and revoking genuinely frees a licence slot — so the button has to be on this page.",
    ).toBe(true);
  });

  it("⛔ the action is a COLUMN, so it renders on every table — healthy included", () => {
    // ⚠ THE HEALTHY TABLE IS THE CASE THAT WAS BROKEN. A healthy-but-unused gateway is exactly the one an
    // operator retires to free a slot; an action offered only on "needs attention" would leave the
    // ceiling's own remedy unreachable for the gateways it is about.
    expect(page).toMatch(/key:\s*"actions"/);
    // The columns array feeds every DataTable on the page, so a column cannot be present for one group and
    // absent for another — which is why this is a column rather than a per-group control.
    const columnsAt = page.indexOf("const columns");
    const actionsAt = page.indexOf('key: "actions"');
    expect(actionsAt).toBeGreaterThan(columnsAt);
  });

  it("⚠ an already-revoked gateway is not offered a revoke — there is no un-revoke", () => {
    // ⛔ THE ASSERTION CHANGED SHAPE WHEN DELETE SHIPPED (S12.12 D2), and only the shape. It used to read
    // `status === "revoked" ? null` — the revoked branch rendered NOTHING, which was the right answer while
    // there was nothing a revoked gateway could be offered. There is now: delete. So the branch still must
    // not offer a revoke, and the test says exactly that rather than pinning the literal `null` it happened
    // to be expressed as. A census that matches an implementation detail fails on the refactor and passes on
    // the regression.
    const branchAt = page.indexOf('r.status === "revoked" ?');
    expect(branchAt).toBeGreaterThan(-1);
    const branch = page.slice(branchAt, page.indexOf('confirmRevoke === r.id ?', branchAt));
    expect(branch).not.toMatch(/setConfirmRevoke/);
    expect(branch).toMatch(/setConfirmDelete/);
  });
});
