import type { Device, Member, Role } from "./api";
import { can } from "./rbac";

// usersview — PURE view-model for Users & Roles (S14.11).
//
// ⛔ THE CLASSIFICATION THAT PRODUCED THIS FILE WAS WRONG FOUR TIMES BEFORE IT WAS RIGHT, and the corrections
// are what these functions encode. My first pass grepped `Member`, found no auth source / device count / MFA
// state, and called them absent from the PRODUCT. Measured against the schema and the handlers instead:
//
//   N devices     SERVED         — `listDevices` returns the whole org for PermMemberManage; Device.user_id
//                                  is required. A client-side group-by, not the PEERS class (PEERS had NO field)
//   MFA           CATEGORY TWO   — `user_totp.confirmed` is persisted and NOT NULL; only the Member
//                                  projection is missing. Three fields, not a roadmap
//   AUTH          SPLIT          — `users.password_hash` makes "has a local password" derivable; per-member
//                                  SSO identity is genuinely absent (sso_configs is ORG-level, AuthMethod is
//                                  SESSION-scope)
//   idp-sync      VIA GROUPS     — the markers are per-GROUP, so it inherits PermPolicyView + edition
//
// docs/laws.md → BEFORE RECORDING AN ABSENCE, NAME THE TABLE. A DTO IS A PROJECTION; A SCHEMA IS THE PRODUCT.

// ── THE DEVICE COUNT, AND THE FALSE ZERO IT MUST NEVER RENDER ───────────────────────────────────────────
//
// ⛔ `listDevices` IS AUDIENCE-SCOPED AT THE HANDLER:
//
//     if rbac.Can(role, rbac.PermMemberManage) { ListForOrg(...) } else { ListForUser(...) }
//
// So a MEMBER viewing the roster derives a group-by from a list containing ONLY THEIR OWN devices — and every
// other member would render `0 devices`.
//
//   A FALSE ZERO IS WORSE THAN AN ABSENCE. It is a positive claim about another person's fleet, drawn from a
//   response that was never about them. ABSENCE OF PERMISSION IS NOT ABSENCE OF DATA (ruled on Routed Ranges);
//   this is the same defect with a number instead of a cell.
//
// So the count is a THREE-ARMED value and `hidden` is a first-class arm, never a zero and never a dash-shaped
// "we don't know" that a reader would take for "none".
export type DeviceCount =
  | { kind: "count"; n: number }
  /** The caller lacks member:manage, so the device list is their own — no count about anyone is knowable. */
  | { kind: "hidden" }
  /** The devices read failed. Distinct from `hidden`: we were allowed to ask and could not. */
  | { kind: "unknown" };

export function deviceCountFor(input: {
  role: Role | undefined;
  /** null = the devices read failed or has not resolved. NOT an empty array. */
  devices: Device[] | null;
  userId: string;
}): DeviceCount {
  // ⛔ THE PERMISSION IS CHECKED BEFORE THE DATA, deliberately. Checking the array first would let a member's
  // own-devices list produce a confident `0` for a colleague — the exact false zero this type exists to make
  // unrepresentable.
  if (!can(input.role, "member:manage")) return { kind: "hidden" };
  if (input.devices === null) return { kind: "unknown" };
  return {
    kind: "count",
    n: input.devices.filter((d) => d.user_id === input.userId).length,
  };
}

/** The cell's text. `hidden` says WHOSE limitation it is; it never implies the member has no devices. */
export function deviceCountLabel(c: DeviceCount): string {
  switch (c.kind) {
    case "count":
      return c.n === 1 ? "1 device" : `${c.n} devices`;
    case "hidden":
      return "not visible to you";
    case "unknown":
      return "could not load";
  }
}

// ── THE AUTH LABEL IS NOT HERE, AND ITS ABSENCE IS DELIBERATE ───────────────────────────────────────────
//
// ⛔ I WROTE `authFact(hasPasswordHash)` AND THEN MEASURED THE PAYLOAD THAT WOULD FEED IT:
//
//     GET /organizations/{org}/members  keys served:
//       email · email_verified · joined_at · name · role · status · user_id
//     openapi.yaml Member: `additionalProperties: false`, exactly those seven
//
// **NO SERVED FIELD CARRIES `password_hash`.** So the function was a CONSUMER WITH NO PRODUCER — the
// who-reads-this probe run backwards, and by the DORMANT-MACHINERY LAW (S8.4, where a resolver release-rider
// dormant-until-S8.5 was ripped out rather than parked) it comes OUT rather than waiting for a story.
//
// The §2.3 RULING IT ENCODED IS NOT LOST — it lives in `docs/S14.11-decisions.md` §2.3, which is a decision
// record's job: the label stops at `local password` / `no local password` and NEVER infers SSO, because
// 237 of 241 users have `password_hash IS NULL` and the demo org has NO `sso_configs` row, so "no password ⇒
// SSO" is disproved by the first org anyone opens.
//
// D1b (registered): the AUTH column needs ONE projected boolean. It is the twin of D1's MFA column (three
// fields) and both are HELD for disposition — no spec change made unilaterally.

// ── THE FOUR GATES, DECIDED ONCE ────────────────────────────────────────────────────────────────────────
//
// Four different reasons content on this screen may not render, and deciding them per-cell produced a table of
// blanks in the first draft. Decided ONCE here so the screen has a shape rather than six holes:
//
//   MFA column        a PROJECTION that does not exist (user_totp is persisted; Member does not carry it)
//   N devices         member:manage — and the false zero above
//   idp-sync/locked   PermPolicyView + edition_required
//   teamMap edges     PermPolicyView + edition_required
//
// ⛔ GATED COLUMNS ARE ABSENT FROM THE COLUMN SET, NEVER DIMMED. The edition seam is a RENDER decision, never
// a style (epic rule): a column hidden by opacity is still in the DOM, still announced to a screen reader,
// still reachable by keyboard — "gone only to a sighted mouse user".
//
// ⛔ AND NOT THE S14.5 HALT IN REVERSE. That halt was an upsell shown for a capability the API treated as CORE.
// The inverse error is hiding something the open edition IS entitled to — so ONLY group-derived content is
// edition-gated here. Role, status, joined, email_verified and devices-for-admins are core and always render.
export interface RosterShape {
  /** member:manage — the device count column. */
  showDeviceCount: boolean;
  /** PermPolicyView AND enterprise — the group-derived surfaces (idp-sync marker, the teamMap edges). */
  showGroupDerived: boolean;
  /** One panel-level line naming what this viewer cannot see, or null when they can see everything. */
  gateNote: string | null;
}

export function rosterShape(input: {
  role: Role | undefined;
  isEnterprise: boolean;
}): RosterShape {
  const showDeviceCount = can(input.role, "member:manage");
  const showGroupDerived = input.isEnterprise && can(input.role, "policy:view");

  // ⛔ THE NOTE NAMES THE REASON, AND THE TWO REASONS ARE NOT INTERCHANGEABLE. "You cannot see this" and "this
  // edition does not have it" send an operator to completely different places — an admin and a purchase
  // decision respectively. Collapsing them into "unavailable" is the reassuring-empty defect wearing a
  // neutral word.
  //
  // ⛔ AND THE ORDER IS THE SERVER'S, for the same reason as `groupAccessState`: PERMISSION FIRST. This function
  // had the edition-first bug too — THE SAME DEFECT TWICE IN ONE FILE, which is why the fix is stated at both
  // sites rather than cross-referenced. An open-edition member must not be sold a feature their role would not
  // let them use.
  let gateNote: string | null = null;
  if (!showGroupDerived) {
    gateNote = !can(input.role, "policy:view")
      ? "Group membership needs policy access, which your role does not have."
      : "Group membership is a Tunnex Enterprise feature, so it is not shown here.";
  }
  if (!showDeviceCount) {
    const devices = "Device counts are only shown to admins.";
    gateNote = gateNote === null ? devices : `${gateNote} ${devices}`;
  }
  return { showDeviceCount, showGroupDerived, gateNote };
}

// ── THE GROUP-EDGE EMPTY STATE — THREE CAUSES, THREE ANSWERS ────────────────────────────────────────────
//
// ⛔ A SINGLE "no groups" EMPTY STATE WOULD BE WRONG IN ALL THREE CASES. `policyPort` is nil in the open
// build, so the endpoint 403s for EVERY caller of EVERY role — while a permission failure is about the caller
// and an genuinely empty result is about the data.
export type GroupAccessState =
  | { kind: "edges"; n: number }
  | { kind: "none" }
  | { kind: "forbidden" }
  | { kind: "edition" }
  /**
   * ⛔ FOUND BY MUTATION M10, AND IT WAS A DESIGN DEFECT, NOT A TEST GAP. This arm did not exist: a null
   * `groupCount` returned `forbidden`, so a permitted owner whose READ FAILED was told they lack access.
   * That is precisely what `DeviceCount.unknown` above exists to prevent — **built in one function and
   * omitted in the next one down**, the same shape as the `ON CONFLICT` fix that protected one fixture block
   * and not the block below it.
   */
  | { kind: "failed" };

export function groupAccessState(input: {
  isEnterprise: boolean;
  role: Role | undefined;
  /** null = the read failed or has not resolved. NOT the same as fetching and getting zero. */
  groupCount: number | null;
}): GroupAccessState {
  // ⛔ PERMISSION FIRST, EDITION SECOND — AND THIS ORDER IS THE SERVER'S, NOT A PREFERENCE.
  //
  // My first version had it backwards, and mutation M9 (swap these two lines) SURVIVED. I treated the survivor
  // as a missing test and wrote one pinning my order. It was the ORDER that was wrong. Measured:
  //
  //   ListGroups: `authorize(ctx, req.OrgId, rbac.PermPolicyView)` runs, THEN `if s.policy == nil`
  //   enterprise + member  -> 403 forbidden           (measured live: "you do not have permission")
  //   open       + owner   -> 403 edition_required    (policy_edition_open_test.go, RoleOwner —
  //                                                    its own comment reads "authorize() runs FIRST")
  //
  // So an OPEN-EDITION MEMBER is told `forbidden` by the server, and my edition-first version told them
  // "Groups are a Tunnex Enterprise feature" — AN UPSELL SHOWN TO SOMEONE WHO WOULD NOT SEE GROUPS EVEN AFTER
  // BUYING THEM. That is the S14.5 HALT SHAPE, forward, inside the same function whose comment warns against
  // the reverse of it.
  //
  // The upsell still reaches the person who can act on it: an open-edition OWNER passes this line and lands on
  // `edition`, which is exactly who a purchase decision belongs to.
  if (!can(input.role, "policy:view")) return { kind: "forbidden" };
  if (!input.isEnterprise) return { kind: "edition" };
  if (input.groupCount === null) return { kind: "failed" };
  return input.groupCount === 0
    ? { kind: "none" }
    : { kind: "edges", n: input.groupCount };
}

export function groupAccessLabel(s: GroupAccessState): string {
  switch (s.kind) {
    case "edges":
      return s.n === 1 ? "1 group" : `${s.n} groups`;
    case "none":
      return "No groups yet";
    case "forbidden":
      return "You do not have access to groups";
    case "edition":
      return "Groups are a Tunnex Enterprise feature";
    case "failed":
      return "Groups could not be loaded";
  }
}

// ── THE ACCESS-POSTURE PANEL PROMISES THREE FACTS AND THE PRODUCT SERVES ONE ─────────────────────────────
//
// The wireframe's subtitle is `role hierarchy · MFA coverage · authentication sources`. Measured against the
// payload:
//
//   role hierarchy         SERVED     — `Member.role`, a group-by over rows already loaded
//   MFA coverage           D1  HELD   — `user_totp.confirmed` is persisted but not projected
//   authentication sources D1b HELD   — `users.password_hash` is not projected either
//
// So the panel ships the third of it that is real. Rendering a subtitle that names all three and then showing
// one would be the panel promising what it cannot deliver — and `MFA enrolled 5/7` in particular is a NUMBER,
// which a reader trusts more than prose.
export interface RoleTally {
  role: Role;
  /** Accounts on the roster holding this role — DEACTIVATED INCLUDED. See roleDistribution. */
  n: number;
  /** How many of `n` cannot sign in. Rendered only when non-zero. */
  deactivated: number;
}

/**
 * Counts per role, always in hierarchy order and ALWAYS INCLUDING ZEROS — an org with no admins should read
 * `0 admins`, not omit the row. An omitted row is indistinguishable from a role that does not exist.
 *
 * ⛔ THIS COUNTS ACCOUNTS ON THE ROSTER, DEACTIVATED INCLUDED — ruled, and the SUBTITLE MUST SAY SO.
 *
 * The first version was labelled "Role hierarchy across N members", which claims WHO CAN ACT. It counts
 * something else: `ListOrgMembersWithUser` excludes soft-deleted users but keeps deactivated ones on purpose
 * (its own comment: "deactivated members stay on the roster (status carries that)"), and a deactivated account
 * is refused at login with 403 account_deactivated. So the label promised one fact and the number was another.
 *
 * A roster of 7 with 1 deactivated is TWO FACTS, NOT ONE NUMBER — hence `deactivated` below, rendered only
 * where it is non-zero.
 */
export function roleDistribution(members: Member[]): RoleTally[] {
  const order: Role[] = ["owner", "admin", "member"];
  return order.map((role) => ({
    role,
    n: members.filter((m) => m.role === role).length,
    deactivated: members.filter(
      (m) => m.role === role && m.status === "deactivated",
    ).length,
  }));
}

/**
 * The panel's subtitle. States WHAT IS COUNTED rather than implying who can act, and surfaces the split at
 * panel level so the two facts arrive together.
 */
export function rosterSubtitle(members: Member[]): string {
  const off = members.filter((m) => m.status === "deactivated").length;
  const n = members.length;
  const head = `${n} ${n === 1 ? "account" : "accounts"} on the roster`;
  // The zero case says nothing extra — "0 deactivated" is noise on the common path.
  return off === 0 ? head : `${head}, ${off} deactivated and unable to sign in`;
}

/** `2 owners` / `1 owner` / `0 owners` — the zero is stated, never dropped. */
export function roleTallyLabel(t: RoleTally): string {
  return `${t.n} ${t.n === 1 ? t.role : t.role + "s"}`;
}

// ── LAST-OWNER: MIRRORED FROM THE 403, NEVER PRE-EMPTED ─────────────────────────────────────────────────
//
// ⛔ MY §2.5 RULING WAS "NO CLIENT-SIDE OWNER COUNT" AND THE SCREEN ALREADY HAD ONE — with a rationale written
// next to it. I ruled on the screen's behaviour without reading the screen: the same method error as grepping
// `Member` and concluding the product did not know. THIRD instance of forming a verdict without opening the
// artifact.
//
// Reconciled, because the existing design and the ruling's concern are about DIFFERENT THINGS:
//
//   the DISABLE is client-side  — legitimate: it avoids a pointless round-trip and the tooltip teaches why
//   the REFUSAL is the server's — mutate() renders apiErrorMessage(error, fallback), server text FIRST, and
//                                 refetches on error so a lost race self-corrects (S4.7 reactive-403)
//
// So what the ruling forbids is PREDICTING THE REFUSAL TEXT, not disabling a control. The copy below says that
// accurately — the earlier draft claimed the screen does not predict at all, which was false of the disable.
export const LAST_OWNER_NOTE =
  "An organization must always have at least one owner, so the last owner's role and deactivate controls are disabled. The server refuses the change regardless, and its message is shown verbatim if it ever disagrees with what is disabled here.";

/** Rows a `Filter members…` box keeps — client-side over rows already loaded, no new request. */
export function filterMembers(members: Member[], q: string): Member[] {
  const needle = q.trim().toLowerCase();
  if (needle === "") return members;
  return members.filter(
    (m) =>
      m.email.toLowerCase().includes(needle) ||
      m.name.toLowerCase().includes(needle) ||
      m.role.toLowerCase().includes(needle),
  );
}
