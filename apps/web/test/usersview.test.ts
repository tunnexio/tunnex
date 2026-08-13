import { describe, expect, it } from "vitest";
import {
  deviceCountFor,
  deviceCountLabel,
  filterMembers,
  groupAccessLabel,
  groupAccessState,
  LAST_OWNER_NOTE,
  roleDistribution,
  roleTallyLabel,
  rosterShape,
  rosterSubtitle,
} from "../src/lib/usersview";
import type { Device, Member } from "../src/lib/api";

// Every two-valued thing is asserted at BOTH values in the SAME test (mechanism ⑨) — the S14.6 aria-pressed
// mutation survived because a test only ever observed one value and could not tell the variable from the
// constant.

const dev = (userId: string, i = 0): Device =>
  ({ id: `d${userId}${i}`, user_id: userId }) as Device;

describe("deviceCountFor — the false zero", () => {
  it("⛔ A MEMBER GETS `hidden`, NEVER A COUNT — the false-zero defect", () => {
    // THE DEFECT THIS TYPE EXISTS FOR. `listDevices` returns own-devices-only below member:manage, so a
    // member's array contains nothing about anyone else. A group-by over it yields a confident `0` — a
    // POSITIVE CLAIM about another person's fleet, drawn from a response that was never about them.
    const c = deviceCountFor({
      role: "member",
      devices: [dev("me")], // the member's OWN device, all the API gave them
      userId: "someone-else",
    });
    expect(c.kind).toBe("hidden");
    // The number must not appear anywhere in the value — not as 0, not as a count of 0.
    expect(JSON.stringify(c)).not.toMatch(/\bn\b|:0/);
  });

  it("an ADMIN gets a real count — both sides of the same gate", () => {
    // Without this arm the assertion above passes against a function that always returns `hidden`.
    const c = deviceCountFor({
      role: "admin",
      devices: [dev("a"), dev("a", 1), dev("b")],
      userId: "a",
    });
    expect(c).toEqual({ kind: "count", n: 2 });
  });

  it("⛔ THE PERMISSION IS CHECKED BEFORE THE DATA", () => {
    // Order matters: checking the array first would let a member's own list produce a count. A member with a
    // FULL array (impossible in production, trivial in a test) must STILL be hidden — the gate is the
    // permission, not the data's shape.
    expect(
      deviceCountFor({
        role: "member",
        devices: [dev("x"), dev("x", 1)],
        userId: "x",
      }).kind,
    ).toBe("hidden");
  });

  it("`unknown` is DISTINCT from `hidden` — allowed-and-failed vs not-allowed", () => {
    // Two different facts: "we could not ask" and "you may not know". Collapsing them would tell an admin
    // their permissions are wrong when the network is.
    const failed = deviceCountFor({
      role: "admin",
      devices: null,
      userId: "a",
    });
    const notAllowed = deviceCountFor({
      role: "member",
      devices: null,
      userId: "a",
    });
    expect(failed.kind).toBe("unknown");
    expect(notAllowed.kind).toBe("hidden");
    expect(failed.kind).not.toBe(notAllowed.kind);
  });

  it("an admin with a genuinely empty list DOES get 0 — absence is knowable when you may look", () => {
    expect(deviceCountFor({ role: "admin", devices: [], userId: "a" })).toEqual(
      {
        kind: "count",
        n: 0,
      },
    );
  });

  it("no label is blank, and `hidden` never implies the member has none", () => {
    const hidden = deviceCountLabel({ kind: "hidden" });
    expect(hidden).toMatch(/not visible/i);
    expect(hidden).not.toMatch(/\b0\b|none|no devices/i);
    for (const c of [
      { kind: "count", n: 0 } as const,
      { kind: "count", n: 1 } as const,
      { kind: "hidden" } as const,
      { kind: "unknown" } as const,
    ])
      expect(deviceCountLabel(c).trim().length).toBeGreaterThan(0);
    // Singular/plural, because "1 devices" on a roster reads as a rendering bug.
    expect(deviceCountLabel({ kind: "count", n: 1 })).toBe("1 device");
    expect(deviceCountLabel({ kind: "count", n: 2 })).toBe("2 devices");
  });
});

// ── THE AUTH COLUMN: NO PRODUCER, SO NO VIEW-MODEL — AND A TRIPWIRE INSTEAD OF A TEST ───────────────────
//
// `authFact()` and its two tests were DELETED (dormant-machinery law: no served field carries
// `password_hash`). A deletion leaves no trace, so this replaces them with something that FIRES when the
// projection arrives.
//
// ⛔ AND IT IS A TYPE-LEVEL ASSERT, NOT A RUNTIME ONE. My first draft was `expect(served).toHaveLength(7)`
// over my own literal — a TAUTOLOGICAL GUARD (S7.5.5 law): it asserts the array I just wrote, and adding a
// field to `Member` would leave it GREEN. Below, an added field makes `UnaccountedMemberField` stop being
// `never`, the conditional resolves to `false`, and assigning `true` to it is a COMPILE error — caught by
// `pnpm typecheck`, which is a web-gate step.
//
// WHEN THIS BREAKS: D1b has landed. Restore the label from docs/S14.11-decisions.md §2.3 —
// `local password` / `no local password` — and DO NOT infer SSO from the org's `sso_configs`.
type UnaccountedMemberField = Exclude<
  keyof Member,
  | "user_id"
  | "email"
  | "name"
  | "role"
  | "status"
  | "email_verified"
  | "joined_at"
  // ⛔ D23: ACCOUNTED FOR, because it has a producer and a consumer. The roster serves the count of live
  // machine credentials this person OWNS, and the deactivate confirmation states what stopping them
  // breaks. Listing it here is the tripwire working as designed — a new Member field must be claimed by
  // something, or it is a projection nobody renders.
  | "machine_credentials"
>;
const _memberHasNoAuthField: UnaccountedMemberField extends never
  ? true
  : false = true;

describe("the AUTH column has no producer", () => {
  it("⛔ the tripwire is a TYPE assert; this test only keeps it referenced", () => {
    // Without a reference the const is dead code a linter may strip, taking the tripwire with it.
    expect(_memberHasNoAuthField).toBe(true);
  });
});

describe("rosterShape — four gates decided once", () => {
  it("an OWNER on enterprise sees everything", () => {
    const s = rosterShape({ role: "owner", isEnterprise: true });
    expect(s).toEqual({
      showDeviceCount: true,
      showGroupDerived: true,
      gateNote: null,
    });
  });

  it("⛔ an OPEN-EDITION MEMBER is told their ROLE, never sold Enterprise", () => {
    // THIS ASSERTED /Enterprise/ ONE COMMIT AGO — the same edition-first bug as `groupAccessState`, in the same
    // file. A member's role would not let them see groups on ANY edition, so naming the edition sells them
    // something that would not help. Permission first, mirroring the server.
    const s = rosterShape({ role: "member", isEnterprise: false });
    expect(s.showGroupDerived).toBe(false);
    expect(s.gateNote).toMatch(/role/);
    expect(s.gateNote).not.toMatch(/Enterprise/);
    expect(s.gateNote).toMatch(/admins/); // and the device-count reason is stated too, not swallowed
  });

  it("⛔ an ENTERPRISE member: also the ROLE — the two editions agree for this caller", () => {
    // The two reasons are NOT interchangeable — one sends an operator to an admin, the other to a purchase
    // decision. Collapsing them into "unavailable" is the reassuring-empty defect wearing a neutral word.
    const s = rosterShape({ role: "member", isEnterprise: true });
    expect(s.gateNote).toMatch(/role/);
    expect(s.gateNote).not.toMatch(/Enterprise/);
  });

  it("⛔ an OPEN-EDITION OWNER is the one told EDITION — and keeps the device count", () => {
    // The upsell reaches whoever can act on it. And the S14.5 halt is NOT repeated in reverse: hiding
    // something the open edition IS entitled to. Device counts are core, so an owner keeps them.
    const s = rosterShape({ role: "owner", isEnterprise: false });
    expect(s.showDeviceCount).toBe(true);
    expect(s.showGroupDerived).toBe(false);
    expect(s.gateNote).toMatch(/Enterprise/);
    expect(s.gateNote).not.toMatch(/admins/); // an owner IS an admin; that clause must not appear
  });
});

describe("groupAccessState — three causes, three answers", () => {
  const base = { role: "owner" as const, groupCount: 3 };

  it("an OPEN-EDITION OWNER is told EDITION — the upsell reaches whoever can act on it", () => {
    // An owner holds policy:view, so they pass the permission line and land on `edition`. That is the caller a
    // purchase decision belongs to, so this is where naming Enterprise is right.
    expect(groupAccessState({ ...base, isEnterprise: false }).kind).toBe(
      "edition",
    );
  });

  it("⛔ AN OPEN-EDITION MEMBER IS TOLD FORBIDDEN, MIRRORING THE SERVER — never the upsell", () => {
    // THIS TEST PINNED THE OPPOSITE ANSWER ONE COMMIT AGO. Mutation M9 (swap the two gate lines) SURVIVED, and
    // I read the survivor as a missing test rather than a wrong order — then wrote a test asserting `edition`
    // here. Measured afterwards, the server disagrees with that:
    //
    //   ListGroups authorizes PermPolicyView, THEN checks `s.policy == nil`
    //   enterprise + member -> 403 forbidden          (live)
    //   open       + owner  -> 403 edition_required   (policy_edition_open_test.go, RoleOwner)
    //
    // So `edition` for this caller both contradicted the server AND advertised Enterprise to someone who
    // would not see groups after buying it — the S14.5 halt shape, forward.
    expect(
      groupAccessState({
        isEnterprise: false,
        role: "member",
        groupCount: null,
      }).kind,
    ).toBe("forbidden");
  });

  it("⛔ A FAILED READ IS `failed`, NEVER `forbidden` — an owner is the discriminator here too", () => {
    // Found by mutation M10 as a DESIGN defect, not a test gap: null returned `forbidden`, so a permitted
    // owner whose read failed was told they lacked access — the defect `DeviceCount.unknown` already
    // prevents one function up. A member cannot show this: they return `forbidden` at the earlier line
    // regardless, which is why no test reached this branch.
    expect(
      groupAccessState({ isEnterprise: true, role: "owner", groupCount: null })
        .kind,
    ).toBe("failed");
    // And `failed` must not read as an empty result either.
    expect(groupAccessLabel({ kind: "failed" })).not.toBe(
      groupAccessLabel({ kind: "none" }),
    );
  });

  it("separates FORBIDDEN from NONE — the whole point", () => {
    // "You cannot see them" and "there are none" are different facts, and a single "no groups" empty state
    // would be wrong in both.
    expect(
      groupAccessState({ isEnterprise: true, role: "member", groupCount: null })
        .kind,
    ).toBe("forbidden");
    expect(
      groupAccessState({ isEnterprise: true, role: "owner", groupCount: 0 })
        .kind,
    ).toBe("none");
  });

  it("renders the count when everything is permitted", () => {
    expect(groupAccessState({ ...base, isEnterprise: true })).toEqual({
      kind: "edges",
      n: 3,
    });
  });

  it("all FIVE arms produce DISTINCT labels and none is blank", () => {
    const labels = [
      groupAccessLabel({ kind: "edges", n: 2 }),
      groupAccessLabel({ kind: "none" }),
      groupAccessLabel({ kind: "forbidden" }),
      groupAccessLabel({ kind: "edition" }),
      groupAccessLabel({ kind: "failed" }),
    ];
    // The count is stated as a number so adding a sixth arm without a label FAILS here rather than passing
    // silently — `.size === labels.length` would be satisfied by any set of distinct labels.
    expect(new Set(labels).size).toBe(5);
    for (const l of labels) expect(l.trim().length).toBeGreaterThan(0);
    // And the two absences must not read alike.
    expect(groupAccessLabel({ kind: "none" })).not.toBe(
      groupAccessLabel({ kind: "forbidden" }),
    );
  });
});

describe("roleDistribution — the one of the panel's three promised facts that is served", () => {
  const m = (
    role: Member["role"],
    status: Member["status"] = "active",
  ): Member => ({ role, status }) as Member;

  it("⛔ INCLUDES ZEROS — an omitted row reads as a role that does not exist", () => {
    const d = roleDistribution([m("owner"), m("member"), m("member")]);
    expect(d).toEqual([
      { role: "owner", n: 1, deactivated: 0 },
      { role: "admin", n: 0, deactivated: 0 },
      { role: "member", n: 2, deactivated: 0 },
    ]);
    // Hierarchy order, not insertion order and not alphabetical (which would put admin first).
    expect(d.map((t) => t.role)).toEqual(["owner", "admin", "member"]);
  });

  it("⛔ COUNTS DEACTIVATED IN `n`, AND REPORTS THEM SEPARATELY — two facts, not one number", () => {
    // The tally counts ACCOUNTS ON THE ROSTER (ruled). `ListOrgMembersWithUser` keeps deactivated rows on
    // purpose, and a deactivated account is refused at login (403 account_deactivated). So `n` must include
    // them — the roster IS 7 — and the split must be visible, or "1 owner" hides an owner who cannot sign in.
    const d = roleDistribution([
      m("owner"),
      m("member"),
      m("member", "deactivated"),
    ]);
    expect(d[2]).toEqual({ role: "member", n: 2, deactivated: 1 });
    expect(d[0]).toEqual({ role: "owner", n: 1, deactivated: 0 });
  });

  it("a DEACTIVATED OWNER is visible in the tally — the case behind the server lockout", () => {
    // An org showing "1 owner" whose only owner cannot sign in is the display half of the CountOwners defect
    // (docs/probes/lockout_probe_test.go.txt). The number stays 1; the split is what tells the truth.
    const d = roleDistribution([m("owner", "deactivated")]);
    expect(d[0]).toEqual({ role: "owner", n: 1, deactivated: 1 });
  });

  it("an empty roster gives three zeros, not an empty list", () => {
    expect(roleDistribution([])).toHaveLength(3);
    expect(roleDistribution([]).every((t) => t.n === 0)).toBe(true);
  });

  it("pluralises, including the zero case", () => {
    // "0 owner" and "1 owners" both read as bugs; the zero takes the plural.
    expect(roleTallyLabel({ role: "owner", n: 0, deactivated: 0 })).toBe(
      "0 owners",
    );
    expect(roleTallyLabel({ role: "owner", n: 1, deactivated: 0 })).toBe(
      "1 owner",
    );
    expect(roleTallyLabel({ role: "admin", n: 2, deactivated: 0 })).toBe(
      "2 admins",
    );
  });
});

describe("rosterSubtitle — states WHAT IS COUNTED, never who can act", () => {
  const m = (status: Member["status"]): Member =>
    ({ role: "member", status }) as Member;

  it("⛔ never claims 'members' who can act — it says accounts on the roster", () => {
    // The first subtitle read "Role hierarchy across N members", which claims WHO CAN ACT while counting
    // something else. This is the whole correction.
    const s = rosterSubtitle([m("active"), m("active")]);
    expect(s).toMatch(/accounts on the roster/);
    expect(s).not.toMatch(/hierarchy|can act/i);
  });

  it("surfaces the deactivated split when it exists, and stays quiet when it does not", () => {
    // Both values of the same condition. "0 deactivated" on the common path is noise that trains people to
    // stop reading the line.
    expect(rosterSubtitle([m("active"), m("deactivated")])).toMatch(
      /2 accounts on the roster, 1 deactivated and unable to sign in/,
    );
    expect(rosterSubtitle([m("active")])).toBe("1 account on the roster");
    expect(rosterSubtitle([m("active")])).not.toMatch(/deactivated/);
  });

  it("singularises the account count", () => {
    expect(rosterSubtitle([m("active")])).toMatch(/^1 account /);
    expect(rosterSubtitle([m("active"), m("active")])).toMatch(/^2 accounts /);
  });
});

describe("LAST_OWNER_NOTE", () => {
  it("promises the server's refusal, never a client-side prediction", () => {
    // S4.7 reactive-403: a client-side owner count is a second authority on a server-owned rule, wrong the
    // moment two admins act at once.
    expect(LAST_OWNER_NOTE).toMatch(/server/i);
    expect(LAST_OWNER_NOTE).toMatch(/verbatim|rather than predicted/i);
  });
});

describe("filterMembers", () => {
  const m = (email: string, name: string, role: Member["role"]): Member =>
    ({ user_id: email, email, name, role }) as Member;
  const rows = [
    m("ada@x.io", "Ada Lovelace", "owner"),
    m("bob@y.io", "Bob Stone", "member"),
  ];

  it("matches email, name and role, and is case-insensitive", () => {
    expect(filterMembers(rows, "ADA").map((r) => r.email)).toEqual([
      "ada@x.io",
    ]);
    expect(filterMembers(rows, "stone").map((r) => r.email)).toEqual([
      "bob@y.io",
    ]);
    expect(filterMembers(rows, "owner").map((r) => r.email)).toEqual([
      "ada@x.io",
    ]);
  });

  it("an empty or whitespace query is the IDENTITY, not a match-nothing", () => {
    // A filter that returns [] on an empty box renders an empty roster on first paint — the reassuring-empty
    // shape produced by the control that is supposed to help.
    expect(filterMembers(rows, "")).toHaveLength(2);
    expect(filterMembers(rows, "   ")).toHaveLength(2);
  });
});
