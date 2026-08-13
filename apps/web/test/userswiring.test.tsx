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
import Users from "../src/pages/Users";
import { AuthProvider } from "../src/lib/auth";

// The REAL AuthProvider — stubbing puts the TEST's role gate under assertion, not the PRODUCT's.
const withAuth = (ui: React.ReactElement) =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <AuthProvider>
      <OrgProvider>{ui}</OrgProvider>
    </AuthProvider>,
  );

beforeEach(() => {
  membersFail = false;
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
      within(row).getByRole("combobox", { name: "Role for second@acme.test" }),
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

describe("Users — the four gates, and WHICH reason each caller is given", () => {
  it("an ENTERPRISE owner sees the group count and NO gate note", async () => {
    withAuth(<Users />);
    await waitFor(() => screen.getByText("Access posture"));
    await waitFor(() =>
      expect(screen.getByText(/1 group in this organization/)).toBeTruthy(),
    );
    // Nothing is withheld from this caller, so no note may appear — a note that always renders explains
    // nothing.
    expect(screen.queryByText(/Enterprise feature/)).toBeNull();
    expect(screen.queryByText(/only shown to admins/)).toBeNull();
  });

  it("⛔ GROUPS IS NOT A STAT TILE — it is not a role tier, and the wireframe has no such tile", async () => {
    // THE RULING. A `Groups 3` tile sitting beside owner/admin/member reads as A FOURTH ROLE TIER. The
    // wireframe's Access posture panel has no Groups stat at all — groups appear only as one axis inside
    // `{{ teamMap }}`, which is D2/held. So the count keeps its own line, named as standing in for the graph.
    withAuth(<Users />);
    await waitFor(() => screen.getByText("Access posture"));
    await waitFor(() => screen.getByText(/1 group in this organization/));

    // The stat row is the <dl>. Its terms are the three role tiers and nothing else.
    const dl = document.querySelector("dl")!;
    // Terms pluralise with their own count ("1 owner" -> `owner`, 0 -> `members`), so match the stem — a
    // literal list would pin one roster's plurals and fail for an unrelated reason.
    const terms = Array.from(dl.querySelectorAll("dt")).map(
      (d) => d.textContent?.toLowerCase() ?? "",
    );
    expect(terms).toHaveLength(3);
    expect(terms.map((t) => t.replace(/s$/, ""))).toEqual([
      "owner",
      "admin",
      "member",
    ]);
    expect(terms.some((t) => t.includes("group"))).toBe(false);

    // And it says what it stands in for, so a reader does not take it for the finished feature.
    expect(screen.getByText(/stands in for it/)).toBeTruthy();
  });

  it("the roster subtitle states WHAT IS COUNTED and shows the deactivated split", async () => {
    // "Role hierarchy across N members" claimed who can act while counting accounts on the roster. Grace is
    // deactivated and cannot sign in, so the roster count and the who-can-act count are different numbers.
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
        user_id: "u9",
        email: "gone@acme.test",
        name: "Gone Away",
        role: "member",
        status: "deactivated",
        email_verified: true,
      },
    ];
    withAuth(<Users />);
    await waitFor(() =>
      expect(
        screen.getByText(
          /2 accounts on the roster, 1 deactivated and unable to sign in/,
        ),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(/Role hierarchy across/)).toBeNull();
    // And the per-role split renders where it exists.
    expect(screen.getByText("1 deactivated")).toBeTruthy();
  });

  it("⛔ an OPEN-EDITION OWNER is told EDITION — the upsell reaches whoever can act on it", async () => {
    edition = "open";
    withAuth(<Users />);
    await waitFor(() => screen.getByText("Access posture"));
    await waitFor(() =>
      expect(
        screen.getByText(/Groups are a Tunnex Enterprise feature/),
      ).toBeTruthy(),
    );
    // An owner IS an admin, so the device-count clause must not appear.
    expect(screen.queryByText(/only shown to admins/)).toBeNull();
  });

  it("⛔ an OPEN-EDITION MEMBER is told their ROLE, and is NEVER sold Enterprise", async () => {
    // The bug the mutation sweep found, at the DOM. Edition-first told this caller "Groups are a Tunnex
    // Enterprise feature" — an upsell to someone whose role would not let them see groups after buying it.
    // The server agrees with the fix: authorize(PermPolicyView) runs BEFORE the `s.policy == nil` check, so
    // this caller's real response is `forbidden`.
    edition = "open";
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
    await waitFor(() => screen.getByText("Access posture"));
    await waitFor(() =>
      expect(
        screen.getByText(/needs policy access, which your role/),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(/Tunnex Enterprise feature/)).toBeNull();
    // Both withheld things are named — the device-count reason is not swallowed by the group one.
    expect(screen.getByText(/only shown to admins/)).toBeTruthy();
  });

  it("the roster stays COHERENT for a member — the S14.5 halt is not repeated in reverse", async () => {
    // The inverse error is hiding what the open edition IS entitled to. A member must still get a usable
    // roster: every colleague, their role, and the role tallies.
    edition = "open";
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
    // ⛔ "Actions" WAS IN THIS LIST AND THAT PINNED THE DEFECT the founder review caught: a member saw an
    // ACTIONS header over cells that were all empty. Coherent means "every column shown has content for
    // this viewer" — not "as many columns as an admin gets".
    for (const h of ["Member", "State", "Role"])
      expect(within(table).getByRole("columnheader", { name: h })).toBeTruthy();
    // ⚠ The verbs moved from an Actions COLUMN to the selection bar, so the affordance to assert is the
    // checkbox. The RULE is untouched: a viewer who can act on nobody is offered nothing to act WITH.
    expect(within(table).queryByRole("checkbox")).toBeNull();
    // And the role tallies render, INCLUDING the zero for admins.
    expect(screen.getByText("0")).toBeTruthy();
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
    expect(headers).toEqual(["Member", "State", "Role"]);
    // ⚠ The verbs moved from an Actions COLUMN to the selection bar, so the affordance to assert is the
    // checkbox. The RULE is untouched: a viewer who can act on nobody is offered nothing to act WITH.
    expect(within(table).queryByRole("checkbox")).toBeNull();
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
    expect(within(table).queryByRole("checkbox")).toBeNull();
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
    const roleHeader = screen.getByRole("columnheader", { name: "Role" });
    expect(within(roleHeader).queryByRole("button")).not.toBeNull();
  });
});
