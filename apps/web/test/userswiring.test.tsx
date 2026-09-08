import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  waitFor,
  cleanup,
  fireEvent,
  within,
} from "@testing-library/react";

// SLICE 7 — Users. Ranked here on the CONSEQUENCE criterion, and the founder's correction stands: this screen
// is not read-only in either sense. It renders roles and it CHANGES what people can do.
//
// THE DECISION UNDER TEST is the sole-owner guard. `isSoleOwner(m) = m.role === "owner" && ownerCount <= 1`
// disables the role control on the last owner, because an organization must always have at least one owner.
// Getting it wrong is not a bad belief — it is a LOCKOUT: demote the last owner and nobody can administer the
// org again, including the person who did it.
//
// `ownerCount` is DERIVED FROM THE LOADED ROSTER, which is what makes it a wiring decision rather than a pure
// one: the guard is only as correct as the list it counts. That is the same shape as WF-S11-10b, where a count
// walked a query that did not filter what the operator assumed it filtered.
//
// QUERY RULES 1-5 BIND: role + accessible name; NETWORK-boundary mocks; decisions not rendering; no viewport
// assumptions; and every waitFor covers EVERY element the assertions touch.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let membersFail = false;
let invitationRows: Array<Record<string, unknown>> = [];
// ── S14.11 controls ────────────────────────────────────────────────────────────────────────────────────────
// `edition` and `devices` are mutable so the SAME assertions can run on both sides of each gate. A gate
// observed at one value cannot be told from a constant (mechanism ⑨ — the S14.6 aria-pressed miss).
let edition = "enterprise";
let devicesFail = false;
// The audience-scoping the API does at the handler, reproduced HERE rather than assumed: below member:manage
// the response contains only the caller's own devices. A mock that returns the whole org to a member would be
// MORE PERMISSIVE THAN THE SUBSTRATE — the fixture-fidelity trap that let a test pin an impossible label in
// S14.10. `whoAmI` drives both the session and the scoping, so they cannot drift apart.
let whoAmI = "u1";
const ALL_DEVICES = [
  { id: "d1", user_id: "u1" },
  { id: "d2", user_id: "u1" },
  { id: "d3", user_id: "u2" },
];
let roster = [
  {
    user_id: "u1",
    email: "owner@acme.test",
    name: "Olive Owner",
    role: "owner",
    email_verified: true,
    status: "active",
  },
  {
    user_id: "u2",
    email: "admin@acme.test",
    name: "Adam Admin",
    role: "admin",
    email_verified: true,
    status: "active",
  },
];

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/auth/me")
          return {
            data: {
              id: whoAmI,
              email: `${whoAmI}@acme.test`,
              email_verified: true,
            },
          };
        if (path === "/api/v1/meta") return { data: { edition } };
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/invitations")) return {data: invitationRows};
        if (path.endsWith("/members")) {
          if (membersFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return { data: roster };
        }
        if (path.endsWith("/devices")) {
          if (devicesFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          // ⛔ THE HANDLER'S AUDIENCE SCOPING, REPRODUCED: ListForOrg for member:manage, ListForUser otherwise.
          const role = roster.find((m) => m.user_id === whoAmI)?.role;
          const scoped =
            role === "owner" || role === "admin"
              ? ALL_DEVICES
              : ALL_DEVICES.filter((d) => d.user_id === whoAmI);
          return { data: scoped };
        }
        if (path.endsWith("/groups")) {
          // The server authorizes PermPolicyView FIRST, then checks the edition — so a member gets `forbidden`
          // on BOTH editions, and only a policy:view holder on the open build gets `edition_required`.
          const role = roster.find((m) => m.user_id === whoAmI)?.role;
          if (role === "member")
            return {
              data: undefined,
              error: { error: { code: "forbidden", message: "no" } },
            };
          if (edition !== "enterprise")
            return {
              data: undefined,
              error: { error: { code: "edition_required", message: "no" } },
            };
          return { data: [{ id: "g1", name: "Engineering" }] };
        }
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import { api } from "../src/lib/api";
import Users from "../src/pages/Users";
import { AuthProvider } from "../src/lib/auth";

// The REAL AuthProvider — stubbing puts the TEST's role gate under assertion, not the PRODUCT's.
const withAuth = (ui: React.ReactElement) =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <MemoryRouter initialEntries={["/users"]}><AuthProvider>
      <OrgProvider>{ui}</OrgProvider>
    </AuthProvider></MemoryRouter>,
  );

beforeEach(() => {
  membersFail = false;
  invitationRows = [];
  edition = "enterprise";
  devicesFail = false;
  whoAmI = "u1";
  roster = [
    {
      user_id: "u1",
      email: "owner@acme.test",
      name: "Olive Owner",
      role: "owner",
      email_verified: true,
      status: "active",
    },
    {
      user_id: "u2",
      email: "admin@acme.test",
      name: "Adam Admin",
      role: "admin",
      email_verified: true,
      status: "active",
    },
  ];
});

describe("Users — wiring: the last owner cannot be demoted", () => {
  it("the SOLE owner's role control is disabled, and says why", async () => {
    withAuth(<Users />);

    // Query rule 5: wait for THE THING ASSERTED. (Not an email — those appear more than once; and not a
    // combobox count — the invite form contributes a third.)
    const soleOwnerControl = await waitFor(() =>
      screen.getByTitle("An organization must always have at least one owner."),
    );
    expect((soleOwnerControl as HTMLSelectElement).disabled).toBe(true);
  });

  it("with TWO owners, neither control is disabled — 'always disabled' must not pass", async () => {
    // The negative half. Without it, disabling every role control satisfies the assertion above while making
    // the screen useless — and a lockout guard that never lets anyone change a role is its own outage.
    roster = [
      {
        user_id: "u1",
        email: "owner@acme.test",
        name: "Olive Owner",
        role: "owner",
        email_verified: true,
        status: "active",
      },
      {
        user_id: "u2",
        email: "second@acme.test",
        name: "Sam Second",
        role: "owner",
        email_verified: true,
        status: "active",
      },
    ];
    withAuth(<Users />);
    // An ABSENCE assertion needs a POSITIVE anchor proving the roster rendered, or it is trivially true against
    // a tree that has not finished — the async form (docs/laws.md). Anchor on the second owner's row.
    // RE-POINTED IN S14.3 SLICE A. `getAllByText(email).length > 0` passed if the address appeared anywhere
    // and said nothing about WHOSE row the role control belonged to. Now the member is a row, and the role
    // control is asserted INSIDE it — which is the assertion the screen actually needs, since a role select
    // wired to the wrong member is the failure that matters here.
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    const row = within(table)
      .getAllByRole("row")
      // queryAllByText, not queryByText: a member with no display name renders the email TWICE in its own
      // cell (as the name and as the address), and `queryBy*` throws on multiple matches. The row predicate
      // only needs "does this row mention them", so the count is irrelevant.
      .find((r) => within(r).queryAllByText("second@acme.test").length > 0)!;
    expect(row, "no row for second@acme.test").toBeTruthy();
    expect(
      within(row).getByLabelText("Roles for second@acme.test", { selector: "summary" }),
    ).toBeTruthy();

    expect(
      screen.queryByTitle(
        "An organization must always have at least one owner.",
      ),
    ).toBeNull();
  });
});

describe("Users — failure path", () => {
  // D1(b). An empty roster on this screen does not read as "no data" — it reads as "this org has no members",
  // which for an org that HAS members is a claim about who can administer it. The guard here is explicit in
  // the product (`members.length === 0 && !error`), so the test asserts that the error wins.
  it("a failed roster load is surfaced and does NOT render as 'no members yet'", async () => {
    membersFail = true;
    withAuth(<Users />);

    await waitFor(() => screen.getByText("Could not load members."));
    expect(screen.queryByText("No members yet.")).toBeNull();
    // AND the table itself is absent, not merely empty. This is the assertion that would have caught the
    // defect this slice introduced and the tier found: converting the roster to a table dropped the page's
    // `&& !error` guard, so a failed load rendered "No members yet." — a claim about who can administer the
    // org, made by a screen that never read anything. `failed` is now a REQUIRED prop on DataTable, so
    // forgetting it is a compile error rather than a review note.
    expect(screen.queryByRole("table", { name: "Members" })).toBeNull();
  });
});

// ══════════════════════════════════════════════════════════════════════════════════════════════════════════
// S14.11 — THE FALSE ZERO AND THE FOUR GATES
//
// These are the two things a founder review must SEE, and neither is provable by a unit test:
//
//   the FALSE ZERO   — the claim is that a member renders NO NUMBER about a colleague's fleet. `deviceCountFor`
//                      returning `{kind:"hidden"}` proves the DECISION; only the DOM proves nothing numeric
//                      reached the page.
//   the FOUR GATES   — the claim is that a gated column is ABSENT, not dimmed. "Absent" is a statement about
//                      the DOM, and `opacity-40` satisfies every pure assertion while leaving the column in
//                      the accessibility tree, in the tab order, and in a screen reader's table announcement.
//
// QUERY RULES 1-5 BIND.
// ══════════════════════════════════════════════════════════════════════════════════════════════════════════

describe("Users — the devices column and the false zero", () => {
  it("an ADMIN viewer gets the column with REAL per-member counts", async () => {
    // The positive half FIRST, so "the column never renders" cannot satisfy the absence test below.
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    expect(
      within(table).getByRole("columnheader", { name: "Devices" }),
    ).toBeTruthy();
    // u1 owns d1+d2, u2 owns d3 — DIFFERENT numbers, so a hardcoded constant fails.
    await waitFor(() => {
      const rows = within(table).getAllByRole("row");
      const owner = rows.find((r) =>
        r.textContent?.includes("owner@acme.test"),
      )!;
      const admin = rows.find((r) =>
        r.textContent?.includes("admin@acme.test"),
      )!;
      expect(within(owner).getByText("2")).toBeTruthy();
      expect(within(admin).getByText("1")).toBeTruthy();
    });
  });

  it("⛔ a MEMBER viewer gets NO DEVICES COLUMN AT ALL — no header, no cell, no zero", async () => {
    // THE DEFECT: /devices is audience-scoped at the handler, so this viewer's response holds only their OWN
    // device. A client-side group-by over it prints `0` against every colleague — a POSITIVE CLAIM about
    // another person's fleet, drawn from a response that was never about them.
    roster = [
      {
        user_id: "u1",
        email: "owner@acme.test",
        name: "Olive Owner",
        role: "owner",
        email_verified: true,
        status: "active",
      },
      {
        user_id: "u3",
        email: "member@acme.test",
        name: "Mel Member",
        role: "member",
        email_verified: true,
        status: "active",
      },
    ];
    whoAmI = "u3";
    withAuth(<Users />);

    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() => within(table).getByText("owner@acme.test"));

    // ABSENT, not dimmed: no columnheader means no <th> in the DOM at all.
    expect(
      within(table).queryByRole("columnheader", { name: "Devices" }),
    ).toBeNull();

    // AND no zero anywhere in the owner's row. This is the assertion that fails if the column is hidden by
    // opacity or the cell rendered a dash-shaped placeholder that reads as "none".
    const ownerRow = within(table)
      .getAllByRole("row")
      .find((r) => r.textContent?.includes("owner@acme.test"))!;
    expect(ownerRow.textContent).not.toMatch(/\b0\b/);
    expect(ownerRow.textContent).not.toMatch(/device/i);
  });

  it("a failed devices read renders 'could not load', NEVER a zero", async () => {
    // `null` devices is not an empty fleet. An admin whose read failed must not be told everyone owns nothing.
    devicesFail = true;
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() =>
      expect(
        within(table).getAllByText("could not load").length,
      ).toBeGreaterThan(0),
    );
    const ownerRow = within(table)
      .getAllByRole("row")
      .find((r) => r.textContent?.includes("owner@acme.test"))!;
    expect(ownerRow.textContent).not.toMatch(/\b0\b/);
  });
});

describe("Users — focused roster", () => {
  it.each(["users", "roles"] as const)("%s has per-user roles without the aggregate role card", async (view) => {
    withAuth(<Users view={view} />);
    const table = await screen.findByRole("table", {name:"Members"});
    expect(within(table).getByRole("columnheader", {name:"Roles"})).toBeTruthy();
    expect(screen.queryByRole("region", {name:"Access posture"})).toBeNull();
  });
  it("ordinary members still see the roster without management controls", async () => {
    whoAmI = "u3";
    withAuth(<Users />);
    const table = await screen.findByRole("table", {name:"Members"});
    expect(within(table).getByRole("columnheader", {name:"Roles"})).toBeTruthy();
    expect(screen.queryByRole("button", {name:"Invite user"})).toBeNull();
    expect(within(table).queryByRole("checkbox", {name:/select/i})).toBeNull();
  });
});

describe("Users — the filter", () => {
  it("filters by email, and its empty state is NOT the roster's", async () => {
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() => within(table).getByText("admin@acme.test"));

    const box = screen.getByRole("searchbox", { name: "Filter Members" });
    fireEvent.change(box, { target: { value: "admin@" } });
    await waitFor(() =>
      expect(screen.queryByText("owner@acme.test")).toBeNull(),
    );
    expect(screen.getByText("admin@acme.test")).toBeTruthy();

    // ⛔ "No members yet." under an active query would tell an admin their org is EMPTY when they simply typed
    // a name that does not match. Two different facts, two different sentences.
    fireEvent.change(box, { target: { value: "zzz-nobody" } });
    await waitFor(() => screen.getByText(/No members match/));
    expect(screen.queryByText("No members yet.")).toBeNull();
  });
});

describe("Users — a member with no name", () => {
  it("⛔ renders the email ONCE, not twice — 144 of 241 users have an empty name", async () => {
    // NOT a corner case, measured: `users.name` is `NOT NULL DEFAULT ''` and `acceptInvitation`'s `name` is
    // OPTIONAL, so anyone who accepts an invite without supplying one has `''`. The cell used to render
    // `{m.name || m.email}` AND `{m.email}` unconditionally, so such a member's row read
    // "nameless@acme.test nameless@acme.test".
    //
    // Found because a MOCK omitted `name` while every seeded fixture member had one. The fixture was LESS
    // representative than the double — the inverse of S14.10's trap, same lesson from the other side.
    roster = [
      {
        user_id: "u1",
        email: "owner@acme.test",
        name: "Olive Owner",
        role: "owner",
        email_verified: true,
        status: "active",
      },
      {
        user_id: "u4",
        email: "nameless@acme.test",
        name: "",
        role: "member",
        email_verified: true,
        status: "active",
      },
    ];
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    // getByText THROWS on more than one match, which is precisely the assertion — exactly one node.
    await waitFor(() => within(table).getByText("nameless@acme.test"));
    expect(within(table).getAllByText("nameless@acme.test")).toHaveLength(1);

    // And the named member still shows BOTH lines, so "only ever render one" cannot satisfy this.
    expect(within(table).getByText("Olive Owner")).toBeTruthy();
    expect(within(table).getAllByText("owner@acme.test")).toHaveLength(1);
  });
});

describe("Users — an empty name AND a long email (the interaction)", () => {
  it("⛔ still renders the address ONCE when it is long enough to wrap", async () => {
    // The founder's check: the original defect was a DOUBLED string, and truncation is where a doubled string
    // hides — the second copy clipped out of view reads as one copy. So the fix is asserted at the length that
    // actually wraps, not only at a short address.
    //
    // Measured on the shipped cell: NO `truncate`, NO `overflow-hidden`, NO `whitespace-nowrap` on either span
    // or the <td>, so the text wraps rather than clipping. This test is what keeps that true — adding
    // `truncate` later would not fail it, but adding a second unconditional email span would.
    const long =
      "nadia.okonkwo-contractor.external@a-very-long-subdomain.example-company.co.uk";
    roster = [
      {
        user_id: "u1",
        email: "owner@acme.test",
        name: "Olive Owner",
        role: "owner",
        email_verified: true,
        status: "active",
      },
      {
        user_id: "u5",
        email: long,
        name: "",
        role: "member",
        email_verified: true,
        status: "active",
      },
    ];
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() => within(table).getByText(long));
    expect(within(table).getAllByText(long)).toHaveLength(1);

    // And the cell is not clipped: no class on the rendered node or its ancestors up to the row hides overflow.
    let node: HTMLElement | null = within(table).getByText(long);
    const clipping: string[] = [];
    while (node && node.tagName !== "TR") {
      const c = node.className || "";
      for (const bad of [
        "truncate",
        "overflow-hidden",
        "whitespace-nowrap",
        "text-ellipsis",
      ])
        if (typeof c === "string" && c.includes(bad))
          clipping.push(`${node.tagName}.${bad}`);
      node = node.parentElement;
    }
    expect(clipping).toEqual([]);
  });
});

describe("Users — the ACTIONS column follows the same rule as Devices", () => {
  it("⛔ a MEMBER gets NO ACTIONS COLUMN — a header with every cell empty is a false claim", async () => {
    // FOUNDER REVIEW FINDING. ACTIONS rendered as a header with every cell empty on the member view — the
    // same class the Devices column avoids. A COLUMN HEADER IS A CLAIM THAT THE COLUMN HAS CONTENT, so an
    // empty ACTIONS tells a member there are actions they cannot see when there are none for them at all.
    roster = [
      {
        user_id: "u1",
        email: "owner@acme.test",
        name: "Olive Owner",
        role: "owner",
        status: "active",
        email_verified: true,
      },
      {
        user_id: "u3",
        email: "member@acme.test",
        name: "Mel Member",
        role: "member",
        status: "active",
        email_verified: true,
      },
    ];
    whoAmI = "u3";
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() => within(table).getByText("Olive Owner"));

    const headers = within(table)
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual(["Member", "State", "Roles"]);
    // ⚠ The verbs moved from an Actions COLUMN to the selection bar, so the affordance to assert is the
    // checkbox. The RULE is untouched: a viewer who can act on nobody is offered nothing to act WITH.
    expect(within(table).queryByRole("checkbox", { name: /select/i })).toBeNull();
    expect(
      within(table).queryByRole("columnheader", { name: "Devices" }),
    ).toBeNull();
  });

  it("an ADMIN keeps the ACTIONS column — 'always absent' must not pass either", async () => {
    withAuth(<Users />); // default roster: u1 owner (me), u2 admin — I can act on u2
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() => within(table).getByText("Adam Admin"));
    expect(within(table).getAllByRole("checkbox").length).toBeGreaterThan(0);
  });

  it("⛔ the test is ANY-ROW-HAS-AN-ACTION, not the viewer's role", async () => {
    // An ADMIN on a roster of OWNERS can act on nobody — canManageMembership(admin, owner, …) is false — so a
    // role-based test would leave them an empty column, reintroducing the defect for a different caller.
    roster = [
      {
        user_id: "u1",
        email: "owner@acme.test",
        name: "Olive Owner",
        role: "owner",
        status: "active",
        email_verified: true,
      },
      {
        user_id: "u2",
        email: "admin@acme.test",
        name: "Adam Admin",
        role: "admin",
        status: "active",
        email_verified: true,
      },
    ];
    whoAmI = "u2"; // I am the admin; the only other row is an owner I cannot manage
    withAuth(<Users />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Members" }),
    );
    await waitFor(() => within(table).getByText("Olive Owner"));
    // ⚠ The verbs moved from an Actions COLUMN to the selection bar, so the affordance to assert is the
    // checkbox. The RULE is untouched: a viewer who can act on nobody is offered nothing to act WITH.
    expect(within(table).queryByRole("checkbox", { name: /select/i })).toBeNull();
    // But the Devices column STAYS — an admin holds member:manage, and that gate is unrelated.
    expect(
      within(table).getByRole("columnheader", { name: "Devices" }),
    ).toBeTruthy();
  });
});

/**
 * ⛔ ONE FILTER PER SCREEN. Users has had its own "Filter members" control, backed by the tested
 * `filterMembers` helper, since long before the shared table grew a filter of its own. When the table gained
 * one, this page rendered BOTH — and two search inputs on one screen compose silently: an operator narrows
 * with the first, narrows again with the second, and the empty result names neither.
 *
 * > **A DUPLICATED CONTROL IS NOT MERELY UNTIDY — IT IS A SECOND, INVISIBLE PREDICATE** on a list whose
 * > emptiness the operator will read as a fact about the org.
 *
 * Found by the founder on screen. This pins it, because the collision arrives from a SHARED component's
 * default and would return the moment another page adopts the table without checking.
 */
describe("Users — exactly one filter control", () => {
  it("⛔ the page renders ONE search input, not the table's as well", async () => {
    withAuth(<Users />);
    await waitFor(() => screen.getByRole("table", { name: "Members" }));
    expect(screen.getAllByRole("searchbox")).toHaveLength(1);
  });

  it("⚠ and the one that survived is the PAGE's — sorting is untouched by its removal", async () => {
    // The negative half: turning the table's filter off must not also disable its sorting, which is a
    // different affordance that happens to be configured next door.
    withAuth(<Users />);
    await waitFor(() => screen.getByRole("table", { name: "Members" }));
    expect(
      screen.getByRole("searchbox", { name: "Filter Members" }),
    ).toBeTruthy();
    const roleHeader = screen.getByRole("columnheader", { name: "Roles" });
    expect(within(roleHeader).queryByRole("button")).not.toBeNull();
  });
});

describe("Users — invitation delivery", () => {
  it("keeps the one-time invitation link visible after creation", async () => {
    vi.mocked(api.POST).mockResolvedValueOnce({
      data: {
        message: "Invitation created.",
        invite_token: "one-time-preview-token",
        delivered: false,
      },
    } as never);

    withAuth(<Users />);
    fireEvent.click(
      await waitFor(() => screen.getByRole("button", { name: "Invite user" })),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Email address" }), {
      target: { value: "new-person@acme.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create invite" }));

    const linkTitle = await waitFor(() => screen.getByText("Invitation link"));
    const linkDialog = linkTitle.parentElement?.parentElement;
    expect(linkDialog).toBeTruthy();
    expect(
      within(linkDialog as HTMLElement).getByText(
        /accept-invite\?token=one-time-preview-token/,
      ),
    ).toBeTruthy();
    expect(
      screen.queryByRole("dialog", { name: "Invite user" }),
    ).toBeNull();
  });
});

describe("Users — complete invite role choices", () => {
  it.each(["ai-admin", "ai-view"])("submits the selected %s starting role", async (role) => {
    withAuth(<Users />);
    fireEvent.click(await screen.findByRole("button", {name:"Invite user"}));
    const select = screen.getByRole("combobox", {name:"Role"});
    expect(within(select).getAllByRole("option").map(o => (o as HTMLOptionElement).value)).toEqual(["owner", "admin", "member", "ai-admin", "ai-view"]);
    fireEvent.change(select, {target:{value:role}});
    fireEvent.change(screen.getByRole("textbox", {name:"Email address"}), {target:{value:"ai-person@example.test"}});
    fireEvent.click(screen.getByRole("button", {name:"Create invite"}));
    await waitFor(() => expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/invitations", expect.objectContaining({body:{email:"ai-person@example.test", role}})));
  });
  it("an admin can invite AI roles but cannot grant owner", async () => {
    whoAmI = "u2";
    withAuth(<Users />);
    fireEvent.click(await screen.findByRole("button", {name:"Invite user"}));
    const select = screen.getByRole("combobox", {name:"Role"});
    expect(within(select).queryByRole("option", {name:"owner"})).toBeNull();
    expect(within(select).getByRole("option", {name:"ai-admin"})).toBeTruthy();
    expect(within(select).getByRole("option", {name:"ai-view"})).toBeTruthy();
  });
});


describe("Invitation resend permissions", () => {
  it.each([['u1', false], ['u2', true]] as const)("owner invitation renewal for %s", async (actor, disabled) => {
    vi.mocked(api.POST).mockClear();
    whoAmI = actor;
    invitationRows = [{id:'owner-invite', email:'owner-invite@example.test', role:'owner',
      created_at:'2026-01-01T00:00:00Z', expires_at:'2099-01-01T00:00:00Z',
      accepted_at:null, revoked_at:null}];
    withAuth(<Users view="invitations" />);
    const row = await screen.findByRole('row', {name:/owner-invite@example.test/});
    fireEvent.click(within(row).getByRole('checkbox'));
    expect((screen.getByRole('button', {name:'Resend'}) as HTMLButtonElement).disabled).toBe(disabled);
    if (disabled) expect(screen.getByRole('button', {name:'Resend'}).getAttribute('title')).toBe('Only an owner can resend an owner invitation.');
    expect(api.POST).not.toHaveBeenCalled();
  });
});
