import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  type Device,
  type Member,
  type Org,
  type Role,
} from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { can, canManageMembership } from "../lib/rbac";
import { useAuth } from "../lib/auth";
import {
  Button,
  Card,
  DataTable,
  ErrorText,
  Field,
  Input,
  Modal,
} from "../components/ui";
import { OneTimeSecretModal } from "../components/OneTimeSecret";
import {
  REVOKED_CAUSE_NOTE,
  canResend,
  canRevoke,
  invitationState,
  inviteErrorCopy,
  inviteGate,
  inviterLabel,
  orderInvitations,
  outstandingCount,
  stateLabel,
  type Invitation,
} from "../lib/invitationview";
import {
  deviceCountFor,
  deviceCountLabel,
  groupAccessLabel,
  groupAccessState,
  LAST_OWNER_NOTE,
  roleDistribution,
  roleTallyLabel,
  rosterSubtitle,
  rosterShape,
} from "../lib/usersview";

const ROLES: Role[] = ["owner", "admin", "member"];
const selectCls =
  "rounded-md border border-white/10 bg-ink-900 px-2 py-1 text-sm text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400 disabled:opacity-50";

export default function Users() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5) — the page no longer picks index zero out of a list it
  // fetched itself, which is what made a second organization unreachable.
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  // The server gates every MUTATING permission on the actor's verified email
  // (authorize() -> email_not_verified 403), separately from RBAC. Mirror that
  // here so we don't offer invite/role/deactivate controls that would only 403.
  // The global VerifyEmailBanner (AppShell) is the standing explanation, so we
  // hide rather than repeat a per-control message.
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [org, setOrg] = useState<Org | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [resetTarget, setResetTarget] = useState<Member | null>(null);
  const [resetBusy, setResetBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isEnterprise, setIsEnterprise] = useState(false);
  const [invites, setInvites] = useState<Invitation[] | null>(null);
  const [inviteErr, setInviteErr] = useState<string | null>(null);
  const [inviteBusy, setInviteBusy] = useState<string | null>(null);
  // ⛔ `null` MEANS "NOT LOADED", AND IT IS NOT THE SAME AS `[]`. An empty array is a fetched answer; null is
  // the absence of one, and deviceCountFor / groupAccessState each have a DISTINCT arm for it. Initialising
  // these to `[]` would make a page that has not finished loading claim every member owns nothing.
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [groupCount, setGroupCount] = useState<number | null>(null);

  // My role in this org comes from my own row in the roster — no extra endpoint.
  const myRole = useMemo(
    () => members.find((m) => m.user_id === myId)?.role,
    [members, myId],
  );
  // Owner count drives the last-owner disable (mirrors the server's CountOwners).
  //
  // ⛔ AND IT MIRRORS THE SERVER'S FLAW, DELIBERATELY. `CountOwners` is
  //   SELECT count(*) FROM memberships WHERE org_id=$1 AND role='owner'
  // with NO join to `users`, so a DEACTIVATED owner counts as an owner. Proven reachable (S14.11 probe,
  // docs/probes/lockout_probe_test.go.txt): deactivate owner A, then deactivate owner B — the guard permits
  // both because two owner ROWS exist, and the org ends with 2 owner rows and 0 accounts that can sign in
  // and act. Recovery needs direct database access.
  //
  // ⛔ DO NOT ADD `&& m.status === "active"` HERE. It would make the client a SECOND AUTHORITY that disagrees
  // with the server about who the last owner is — the control would grey out while the server still permits
  // the change, or the reverse. The S4.7 precedent is that the server owns the refusal.
  //
  // THIS LINE FOLLOWS THE SERVER FIX. When CountOwners learns to join `users.status`, this changes with it,
  // in the same change, not before.
  const ownerCount = useMemo(
    () => members.filter((m) => m.role === "owner").length,
    [members],
  );

  async function loadMembers(orgId: string) {
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/members",
      { params: { path: { orgId } } },
    );
    if (error)
      return setError(apiErrorMessage(error, "Could not load members."));
    setMembers(data ?? []);
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Edition comes from /meta, the same source Access.tsx uses — never inferred from whether an
        // enterprise call happened to 403 (which conflates edition with permission, the bug this screen's
        // view-model was fixed for).
        const { data: meta } = await api.GET("/api/v1/meta");
        if (cancelled) return;
        setIsEnterprise(meta?.edition === "enterprise");
        // ⭐ THE ORG-LIST FETCH IS GONE FROM THIS PAGE (S12.5). It existed only to be indexed at zero.
        // OrgProvider reads the list once for the whole shell; a page that re-fetched it would not merely
        // waste a request, it would pick an org the switcher has no way to change.
        const orgErr = null;
        if (cancelled) return;
        if (orgErr)
          return setError(
            apiErrorMessage(orgErr, "Could not load your organizations."),
          );
        // ⛔ LOADING IS NOT ABSENCE (S12.5). The provider resolves the org list asynchronously, so this
        // effect runs once with currentOrg === null before the answer exists. Treating that as "you have no
        // organization" renders a confident, false statement — and because the second pass only sets the
        // data, the stale error stayed on screen BESIDE the correct org name.
        //
        // ⚠ THREE STATES, NOT TWO: still loading (say nothing), the read failed (say THAT), genuinely no
        // membership (say that). Collapsing the first into the third is how a slow network becomes an
        // accusation that the user does not belong here.
        if (orgLoading) return;
        const first = currentOrg;
        if (!first)
          return setError(
            orgFailed
              ? "Could not load your organizations."
              : "You are not a member of any organization yet.",
          );
        setOrg(first);
        if (!cancelled) await loadMembers(first.id);
      } catch {
        if (!cancelled) setError("Could not reach the API.");
      }
    })();
    return () => {
      cancelled = true;
    };
    // ⛔ currentOrg IS A DEPENDENCY, AND ITS ABSENCE WAS A REAL BUG THE TESTS CAUGHT (S12.5).
    //
    // The provider resolves the org list ASYNCHRONOUSLY, so on this effect's first run `currentOrg` is still
    // null. With `[]` deps the effect never ran again: the page rendered "You are not a member of any
    // organization yet" — a confident, wrong statement — and stayed there forever, for every user.
    //
    // ⚠ THE SAME DEPENDENCY ALSO MAKES THE SWITCHER WORK. One line, two properties: without it the page
    // either never loads at all, or loads once and then lies about which tenant it is showing.
  }, [currentOrg]);

  // ⛔ THE TWO GATED READS ARE NOT ISSUED WHEN THEIR GATE FAILS. Firing them anyway would put a 403 into the
  // page's single error surface, so a member's ordinary, correct page load would show an error — and the gate
  // note already says the same thing calmly. Depends on `myRole`, which arrives with the members list, so this
  // effect runs after it rather than in the load above.
  useEffect(() => {
    let cancelled = false;
    if (!org || !myRole) return;
    (async () => {
      if (can(myRole, "member:manage")) {
        const { data, error } = await api.GET(
          "/api/v1/organizations/{orgId}/devices",
          { params: { path: { orgId: org.id } } },
        );
        // A failure leaves `devices` NULL on purpose — deviceCountFor renders "could not load", which is
        // honest, rather than a zero that would read as "this person has no devices".
        if (!cancelled && !error) setDevices(data ?? []);
      }
      if (isEnterprise && can(myRole, "policy:view")) {
        const { data, error } = await api.GET(
          "/api/v1/organizations/{orgId}/groups",
          { params: { path: { orgId: org.id } } },
        );
        if (!cancelled && !error) setGroupCount((data ?? []).length);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [org, myRole, isEnterprise]);

  // The last-owner invariant is deterministic client-side: disable the control
  // that would demote/deactivate the sole owner. The server refusal (409
  // last_owner) stays the real enforcement — see mutate()'s refetch-on-error,
  // which self-corrects a stale roster after a lost race.
  const isSoleOwner = (m: Member) => m.role === "owner" && ownerCount <= 1;

  async function mutate(
    fn: () => Promise<{ error?: unknown }>,
    fallback: string,
  ) {
    if (!org) return;
    setError(null);
    const { error } = await fn();
    if (error) setError(apiErrorMessage(error, fallback));
    // Always refetch: on success to reflect the change, on error (esp. 409
    // last_owner) so the disabled-control state self-corrects if the roster
    // changed underneath us.
    await loadMembers(org.id);
  }

  const changeRole = (m: Member, role: Role) =>
    mutate(
      () =>
        api.PUT("/api/v1/organizations/{orgId}/members/{userId}/role", {
          params: { path: { orgId: org!.id, userId: m.user_id } },
          body: { role },
        }),
      "Could not change the role.",
    );

  /**
   * ⛔ THE WARNING THE DEACTIVATE PATH DID NOT HAVE (D23).
   *
   * Returns false when the operator declines. ⚠ Silent when nobody selected owns a credential — a confirm
   * that always fires is one people click through, and this one has to be read.
   */
  function confirmMachineCredentialLoss(ms: Member[]): boolean {
    const owners = ms.filter((m) => (m.machine_credentials ?? 0) > 0);
    if (owners.length === 0) return true;
    const total = owners.reduce((n, m) => n + (m.machine_credentials ?? 0), 0);
    const who = owners
      .map((m) => `${m.email} (${m.machine_credentials})`)
      .join("\n  ");
    return window.confirm(
      `${total} machine credential${total === 1 ? "" : "s"} will STOP WORKING IMMEDIATELY.\n\n` +
        `  ${who}\n\n` +
        `Machine credentials are owned by a person, and deactivating that person stops every credential ` +
        `they own — including GitOps operators that are reconciling right now, in any organization. ` +
        `Nothing is revoked: reactivating restores them.\n\nDeactivate anyway?`,
    );
  }

  const setActive = (m: Member, activate: boolean) => {
    const path = {
      params: { path: { orgId: org!.id, userId: m.user_id } },
    } as const;
    return mutate(
      () =>
        activate
          ? api.POST(
              "/api/v1/organizations/{orgId}/members/{userId}/reactivate",
              path,
            )
          : api.POST(
              "/api/v1/organizations/{orgId}/members/{userId}/deactivate",
              path,
            ),
      activate
        ? "Could not reactivate the member."
        : "Could not deactivate the member.",
    );
  };

  // ⛔ THE READ THAT MAKES RESEND AND REVOKE REACHABLE. Both are keyed by EMAIL, and until S14.15
  // nothing served the addresses — so an invitation could be created and then never seen, resent or
  // revoked. Gated on the same permission as the verbs it serves.
  const loadInvites = useCallback(async () => {
    if (!org || !myRole || inviteGate(myRole).kind !== "ready") return;
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/invitations",
      { params: { path: { orgId: org.id } } },
    );
    if (error) return setInviteErr(inviteErrorCopy(apiErrorCode(error)));
    setInviteErr(null);
    setInvites((data as Invitation[] | undefined) ?? []);
  }, [org, myRole]);

  useEffect(() => {
    void loadInvites();
  }, [loadInvites]);

  async function inviteAction(kind: "resend" | "revoke", email: string) {
    setInviteBusy(email + kind);
    setInviteErr(null);
    const path =
      kind === "resend"
        ? ("/api/v1/organizations/{orgId}/invitations/resend" as const)
        : ("/api/v1/organizations/{orgId}/invitations/revoke" as const);
    const { error } = await api.POST(path, {
      params: { path: { orgId: org!.id } },
      body: { email },
    });
    setInviteBusy(null);
    if (error) return setInviteErr(inviteErrorCopy(apiErrorCode(error)));
    await loadInvites();
  }

  const shape = rosterShape({ role: myRole, isEnterprise });
  // ⛔ ACTIONS IS ABSENT WHEN NO ROW HAS ONE — the same rule as the Devices column, for the same reason.
  //
  // A COLUMN HEADER IS A CLAIM THAT THE COLUMN HAS CONTENT. On the member view every ACTIONS cell was empty,
  // which tells a member there are actions they cannot see when there are none for them AT ALL. If Devices is
  // absent for lack of permission, ACTIONS is absent for the same reason; shipping one and not the other
  // would undercut the rule the screen is built on.
  //
  // ⛔ AND THE TEST IS "DOES ANY ROW HAVE AN ACTION", NOT "DOES THE VIEWER HOLD A ROLE". An admin on a roster
  // of owners can act on nobody — `canManageMembership(admin, owner, …)` is false — and a role-based test
  // would keep an empty column for them. It mirrors the CELL's own condition exactly, so the two cannot drift.
  const anyRowHasAction = members.some(
    (m) =>
      emailVerified &&
      canManageMembership(myRole, m.role, "") &&
      m.user_id !== myId,
  );
  const groupAccess = groupAccessState({
    isEnterprise,
    role: myRole,
    groupCount,
  });
  // The table filters now, so the page hands it the whole roster.
  const shown = members;

  return (
    <div>
      <h1 className="text-xl font-semibold text-white">Users</h1>
      <p className="text-sm text-slate-400">{org ? org.name : "…"}</p>
      <ErrorText>{error}</ErrorText>

      {/* ⛔ THE ROSTER COMES FIRST. It was FOURTH — below invitations, below a posture panel, below the
          invite form — so the thing this page is named after was the last thing on it, reached only by
          scrolling past three cards. The panels are CONTEXT; the roster is the SUBJECT.

          ⚠ And the invite form now sits directly above the table it adds to, rather than adrift between
          two panels — the same placement rule the Groups screen needed. */}
      {can(myRole, "member:invite") && emailVerified && org && (
        <InviteForm orgId={org.id} onInvited={() => loadMembers(org.id)} />
      )}

      {/* S14.3 slice A: a real <table>. The roster is tabular — person, role, state, actions per row — and as
          <li> blocks the tier could only find a member by matching their email as free text. The role control
          and the action buttons keep their own accessible names, so they stay queryable INSIDE a cell. */}
      <div className="mt-6">
        {/* ⛔ ONE FILTER, AND IT IS THE TABLE'S NOW. The page carried a separate "Filter members" field
            floating above the roster in its own box — disconnected from the thing it narrowed, and a second
            search input the moment the table grew one.

            ⚠ THE SURVIVOR IS THE ONE THAT SEARCHES MORE. `filterMembers` matched name, email and role; the
            table's search runs over every column's `sortValue`, which is those three PLUS state — so
            "deactivated" now finds the deactivated members, which the old box could not. Swapping to the
            weaker control to preserve a helper would have been keeping the test, not the capability. */}
        <DataTable
          caption="Members"
          // ⛔ THE VERBS LEAVE THE ROWS. Deactivate / Reactivate / Reset 2FA were redrawn on every row —
          // three buttons per member, the same three words down the page, crowding out who the member IS.
          //
          // ⚠ `unavailable` carries every rule the per-row version encoded in whether a button RENDERED at
          // all. That was the quieter design: a row with no controls said nothing about why. Now the bar
          // names the reason — you cannot deactivate yourself, you cannot deactivate the last owner, and a
          // member you may not manage says so instead of silently offering nothing.
          // ⛔ GATED ON anyRowHasAction, NOT ON emailVerified — the rule the ACTIONS COLUMN already earned,
          // carried onto the selection bar. The test is "does ANY row have an action", not "does the viewer
          // hold a role": an admin on a roster of owners can act on nobody, and a role-based test would give
          // them checkboxes and a bar of permanently-disabled verbs. Offering a selection you can do nothing
          // with is the same lie the empty Actions column was, wearing a different control.
          rowActions={
            anyRowHasAction
              ? [
                  {
                    key: "deactivate",
                    label: "Deactivate",
                    danger: true,
                    unavailable: (m: Member) =>
                      m.user_id === myId
                        ? // Never on self — it would log you out, which is a footgun, not a feature.
                          "You cannot deactivate your own account."
                        : !canManageMembership(myRole, m.role, "")
                          ? "You cannot manage this member's role."
                          : m.status !== "active"
                            ? "Already deactivated."
                            : isSoleOwner(m)
                              ? "An organization must always have at least one owner."
                              : null,
                    run: (ms: Member[]) => {
                      // ⛔ D23 — SAY WHAT THIS BREAKS, AT THE MOMENT OF THE ACT. A machine credential dies
                      // with its owner's deactivation, and nothing in the product used to say so: a routine
                      // offboarding took down a GitOps pipeline and nobody connected the two acts.
                      //
                      // ⚠ THE COUNT IS SERVED WITH THE ROSTER rather than fetched here, so the sentence
                      // cannot be shown against a stale or missing number. The server refuses the
                      // credentials either way — this exists so the refusal is not a surprise.
                      if (!confirmMachineCredentialLoss(ms)) return;
                      void Promise.all(ms.map((m) => setActive(m, false)));
                    },
                  },
                  {
                    key: "reactivate",
                    label: "Reactivate",
                    unavailable: (m: Member) =>
                      !canManageMembership(myRole, m.role, "")
                        ? "You cannot manage this member's role."
                        : m.status === "active"
                          ? "Already active."
                          : null,
                    run: (ms: Member[]) => {
                      void Promise.all(ms.map((m) => setActive(m, true)));
                    },
                  },
                  {
                    key: "reset2fa",
                    label: "Reset 2FA",
                    // ⚠ Disenroll-only — it clears the member's 2FA and never signs in as them. One at a
                    // time: the confirm names the person, and a bulk 2FA reset is a different dialog.
                    arity: "single",
                    unavailable: (m: Member) =>
                      m.user_id === myId
                        ? "Reset your own 2FA from your account settings."
                        : !canManageMembership(myRole, m.role, "")
                          ? "You cannot manage this member's role."
                          : null,
                    run: (ms: Member[]) => setResetTarget(ms[0]),
                  },
                ]
              : undefined
          }
          rows={shown}
          rowKey={(m) => m.user_id}
          // ⛔ THE FILTER'S EMPTY STATE IS NOT THE ROSTER'S — "No members yet" under an active query would
          // tell an admin their org is empty when they simply typed a name that does not match. That
          // distinction now lives in DataTable, which owns the search and therefore owns the third
          // emptiness; this prop is the GENUINE zero and nothing else.
          empty="No members yet."
          failed={error != null}
          columns={[
            {
              key: "person",
              header: "Member",
              // ⚠ NAME AND EMAIL BOTH, because the cell shows whichever exists — searching for the one it
              // chose not to display must still find the row.
              sortValue: (m) => `${m.name ?? ""} ${m.email}`,
              cell: (m) => {
                // The primary label falls back to the email; the secondary line then has nothing to add.
                const primary = m.name || m.email;
                return (
                  // ⛔ CAPPED AND TRUNCATED. One member with a 70-character address
                  // (oluwaseun.adebayo-contractor.external@a-very-long-subdomain…) stretched the Member
                  // column across half the table and pushed STATE, DEVICES and ROLE into a huddle at the far
                  // right — every other row then read as mostly empty space. A column sized by its worst row
                  // is a column sized by an outlier.
                  //
                  // ⛔ IT WRAPS, IT DOES NOT TRUNCATE — and that is a ruling, not a preference. A doubled
                  // string HIDES behind an ellipsis: the second copy clips out of view and reads as one copy,
                  // which is the exact defect this cell was fixed for and which its test still guards. So the
                  // column is capped and the address WRAPS onto a second line, where it stays fully readable
                  // and a duplicate would still be visible.
                  //
                  // ⚠ STACKED, NOT INLINE: name over email spends the width twice instead of end to end.
                  <span className="flex max-w-[24rem] flex-col">
                    <span className="break-all text-sm text-white">
                      {primary}
                      {m.user_id === myId && (
                        <span className="ml-2 text-xs text-slate-500">
                          (you)
                        </span>
                      )}
                    </span>
                    {/* ⛔ THE EMAIL IS THE SECONDARY LINE ONLY WHEN A NAME TOOK THE PRIMARY ONE. Unconditionally
                      it rendered the address TWICE for a nameless member — and that is not a corner case:
                      `users.name` is `NOT NULL DEFAULT ''` and `acceptInvitation.name` is OPTIONAL, so 144 of
                      241 users in the review database have an empty name.
                      Found because a MOCK omitted `name` while every seeded member had one — the fixture was
                      LESS representative than the double. The inverse of S14.10, where the double was more
                      permissive than the substrate; the lesson is the same one from the other side. */}
                    {primary !== m.email && (
                      <span className="break-all font-mono text-[11px] text-slate-500">
                        {m.email}
                      </span>
                    )}
                  </span>
                );
              },
            },
            {
              key: "state",
              header: "State",
              sortValue: (m) =>
                m.status === "deactivated" ? "deactivated" : "active",
              cell: (m) => (
                <>
                  {m.status === "deactivated" && (
                    <span className="text-xs text-warn">deactivated</span>
                  )}
                  {!m.email_verified && m.status === "active" && (
                    <span className="text-xs text-slate-600">unverified</span>
                  )}
                </>
              ),
            },
            // ⛔ SPLICED IN, NOT DIMMED. `...(cond ? [col] : [])` means a viewer without member:manage gets
            // NO <th> and NO cell — nothing in the DOM, nothing announced, nothing keyboard-reachable. An
            // `opacity-40` column would be "gone only to a sighted mouse user".
            //
            // And the reason it is gated at all is the FALSE ZERO: /devices is audience-scoped at the handler
            // (ListForOrg for member:manage, ListForUser otherwise), so a member's list holds only their own
            // devices and a group-by over it would print `0 devices` against every colleague. Measured live:
            // owner@ sees 13 devices / 2 owners, member@ sees 6 / 1.
            ...(shape.showDeviceCount
              ? [
                  {
                    key: "devices",
                    header: "Devices",
                    numeric: true,
                    cell: (m: Member) => {
                      const c = deviceCountFor({
                        role: myRole,
                        devices,
                        userId: m.user_id,
                      });
                      return (
                        <span
                          className={
                            c.kind === "count"
                              ? "text-sm text-white"
                              : "text-xs text-slate-500"
                          }
                        >
                          {c.kind === "count" ? c.n : deviceCountLabel(c)}
                        </span>
                      );
                    },
                  },
                ]
              : []),
            {
              key: "role",
              header: "Role",
              // ⚠ NOT `numeric`. The role control sits directly after the right-aligned DEVICES count, so
              // without its own left padding a "0" and a <select> render touching — see the numeric padding
              // in DataTable. This column is left-aligned and takes the gap from that side.
              sortValue: (m) => m.role,
              cell: (m) => {
                // Role is editable on any target the actor may manage — INCLUDING self (an owner handing off
                // ownership). The last-owner disable therefore surfaces on the sole owner's OWN role control.
                const canManage =
                  emailVerified && canManageMembership(myRole, m.role, "");
                const assignable = ROLES.filter((r) =>
                  canManageMembership(myRole, m.role, r),
                );
                if (!canManage || assignable.length === 0)
                  return (
                    <span className="text-xs uppercase tracking-wide text-slate-400">
                      {m.role}
                    </span>
                  );
                return (
                  <select
                    className={selectCls}
                    aria-label={`Role for ${m.email}`}
                    value={m.role}
                    disabled={isSoleOwner(m)}
                    title={
                      isSoleOwner(m)
                        ? "An organization must always have at least one owner."
                        : undefined
                    }
                    onChange={(e) => changeRole(m, e.target.value as Role)}
                  >
                    {assignable.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                );
              },
            },
          ]}
        />

        {/* ⚠ CONTEXT, BELOW THE SUBJECT, AND SIDE BY SIDE — two short cards stacked full-width were a screen
          of scrolling to reach a roster. Columns, so a wider display adds a column rather than stretching
          either card. */}
        <div className="mt-6 grid items-start gap-3.5 lg:grid-cols-2">
          {/* ── Pending invitations ───────────────────────────────────────────────────────────────────────────
          ⛔ THE ONLY WRITE-ONLY STATE IN THE PRODUCT THAT IS ITSELF AN ACCESS GRANT. `resendInvitation` and
          `revokeInvitation` are keyed by EMAIL and nothing served the addresses, so an invitation could be
          created and then never seen, resent or revoked — while remaining redeemable into a membership.
          The other write-only items are CONFIGURATION whose effect shows up elsewhere; this one has no
          observable effect until the moment it becomes a member. */}
          {invites !== null && inviteGate(myRole).kind === "ready" && (
            <div className="mt-6">
              <Card>
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-sm font-semibold text-white">
                    Invitations
                  </h2>
                  {/* The count names OUTSTANDING rows only — pending plus expired. An accepted invitation is a
                  member now and is already counted on the roster; counting it here would overstate how many
                  people have a live path into the org, which is the number this panel exists to show. */}
                  <span className="text-xs text-slate-400">
                    {outstandingCount(invites, new Date())} outstanding
                  </span>
                </div>
                {/* ⛔ A TABLE, BECAUSE THE ROW WAS WRAPPING. Email + badge + role + inviter + two buttons on
                  one flex line meant a long address pushed Resend/Revoke onto a second row for SOME
                  invitations and not others — the controls sat in a different place on every row, which is
                  the one thing a list of identical actions must not do.

                  ⚠ EVERY STATE STILL RENDERS, including accepted and revoked. They are the audit trail of
                  who was let in and who was withdrawn, and the "N outstanding" count above already keeps
                  them from inflating the number that matters. */}
                <div className="mt-3">
                  <DataTable<Invitation>
                    caption="Invitations"
                    rows={orderInvitations(invites, new Date())}
                    rowKey={(inv) => inv.id}
                    rowAttrs={(inv) => ({
                      "data-testid": `invite-${inv.id}`,
                      "data-state": invitationState(inv, new Date()),
                    })}
                    failed={false}
                    pageSize={10}
                    empty="No invitations have been created for this organization."
                    // ⛔ CONTROLS APPEAR ONLY WHERE THE SERVER WOULD ACT. Revoke matches
                    // `accepted_at IS NULL AND revoked_at IS NULL`, so on a terminal row it would change
                    // nothing and report success — worse than absent. `unavailable` now says WHICH, where the
                    // old design just omitted the button and left the operator to infer it.
                    rowActions={[
                      {
                        key: "resend",
                        // ⚠ THE IN-FLIGHT STATE SURVIVED THE MOVE. The per-row button read "Resending…" while
                        // the request was open; a bar button that stays enabled and silent invites a second
                        // click and a second email to the same person.
                        label: inviteBusy?.endsWith("resend")
                          ? "Resending…"
                          : "Resend",
                        arity: "single",
                        unavailable: (inv) =>
                          inviteBusy === inv.email + "resend"
                            ? "Resending…"
                            : canResend(invitationState(inv, new Date()))
                              ? null
                              : "Only a pending or expired invitation can be resent.",
                        run: (is) => void inviteAction("resend", is[0].email),
                      },
                      {
                        key: "revoke",
                        label: inviteBusy?.endsWith("revoke")
                          ? "Revoking…"
                          : "Revoke",
                        danger: true,
                        arity: "single",
                        unavailable: (inv) =>
                          inviteBusy === inv.email + "revoke"
                            ? "Revoking…"
                            : canRevoke(invitationState(inv, new Date()))
                              ? null
                              : "This invitation is already accepted or revoked.",
                        run: (is) => void inviteAction("revoke", is[0].email),
                      },
                    ]}
                    columns={[
                      {
                        key: "email",
                        header: "Invitee",
                        sortValue: (inv) => inv.email,
                        cell: (inv) => (
                          <span
                            className="block max-w-[22rem] truncate text-slate-200"
                            title={inv.email}
                          >
                            {inv.email}
                          </span>
                        ),
                      },
                      {
                        key: "state",
                        header: "State",
                        sortValue: (inv) =>
                          stateLabel(invitationState(inv, new Date())),
                        cell: (inv) => {
                          const st = invitationState(inv, new Date());
                          return (
                            <span
                              className={
                                "rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold " +
                                (st === "pending"
                                  ? "border-accent-500/40 bg-accent-500/10 text-accent-400"
                                  : st === "expired"
                                    ? "border-warn/40 bg-warn/10 text-warn"
                                    : "border-slate-700 bg-slate-900 text-slate-500")
                              }
                            >
                              {stateLabel(st)}
                            </span>
                          );
                        },
                      },
                      {
                        key: "role",
                        header: "Role",
                        sortValue: (inv) => inv.role,
                        cell: (inv) => (
                          <span className="text-xs text-slate-500">
                            {inv.role}
                          </span>
                        ),
                      },
                      {
                        key: "inviter",
                        header: "Invited by",
                        // The inviter can be GONE — invited_by_user_id is ON DELETE SET NULL, and the LEFT
                        // JOIN keeps the row rather than hiding an outstanding invitation because its sender
                        // left.
                        sortValue: (inv) => inviterLabel(inv),
                        cell: (inv) => (
                          <span className="text-xs text-slate-600">
                            {inviterLabel(inv)}
                          </span>
                        ),
                      },
                    ]}
                  />
                </div>
                {/* A revocation the operator may not have performed — SupersedePendingInvites clears pending
                invites on a domain-capture JIT join, and the table records no cause. Named, not claimed. */}
                {invites.some((i) => i.revoked_at) && (
                  <p className="mt-3 text-xs text-slate-600">
                    {REVOKED_CAUSE_NOTE}
                  </p>
                )}
                <ErrorText>{inviteErr}</ErrorText>
              </Card>
            </div>
          )}

          {/* ── Access posture ────────────────────────────────────────────────────────────────────────────────
          The wireframe's subtitle promises `role hierarchy · MFA coverage · authentication sources` and the
          product projects ONE of the three. This panel ships that one and NAMES the two it does not have,
          rather than printing a subtitle that promises all three. `MFA enrolled 5/7` in particular is a
          NUMBER, and a reader trusts a number more than prose. */}
          <div className="mt-6">
            <Card>
              <h2 className="text-sm font-semibold text-white">
                Access posture
              </h2>
              {/* ⛔ STATES WHAT IS COUNTED. The first version read "Role hierarchy across N members", which claims
              WHO CAN ACT — and the tally counts accounts on the roster, deactivated included. A roster of 7
              with 1 deactivated is TWO FACTS, NOT ONE NUMBER. */}
              <p className="mt-1 text-xs text-slate-400">
                {rosterSubtitle(members)}
              </p>
              <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
                {roleDistribution(members).map((t) => (
                  <div key={t.role}>
                    {/* The zero is rendered, not dropped: an omitted role reads as a role that does not exist. */}
                    <dt className="text-xs uppercase tracking-wide text-slate-500">
                      {t.role}
                      {t.n === 1 ? "" : "s"}
                    </dt>
                    <dd className="text-lg font-semibold text-white">{t.n}</dd>
                    {/* The split, per role, only where it exists — so "1 owner" cannot hide a deactivated one. */}
                    {t.deactivated > 0 && (
                      <dd className="text-xs text-warn">
                        {t.deactivated} deactivated
                      </dd>
                    )}
                    <span className="sr-only">{roleTallyLabel(t)}</span>
                  </div>
                ))}
              </dl>
              {/* ⛔ THE TWO MISSING FACTS ARE NAMED, NOT OMITTED. Silence here would read as "this org has no MFA
              story", which is false — MFA is enforced and enrollable, it is the per-member PROJECTION that
              does not exist (D1), as with authentication sources (D1b). */}
              {/* ── Groups: OUT OF THE STAT ROW, and registered as a DELIBERATE ADDITION ─────────────────────
              ⛔ THE WIREFRAME HAS NO GROUPS STAT. Its Access posture panel is:
                   title · "role hierarchy · MFA coverage · authentication sources" · {{ teamMap }}
                   · legend (role tiers, MFA enrolled 5/7) · the last-owner copy
              Groups appear ONLY as one axis inside `{{ teamMap }}` — the tripartite role↔user↔group graph,
              which is D2, held, cut on the permission boundary.

              I had put a `Groups 3` tile in the stat row beside owner/admin/member, where a group count reads
              as A FOURTH ROLE TIER — and I did it WITHOUT REGISTERING IT, breaking my own §2.6 rule
              ("additions get the same discipline as cuts") in the story that states the rule.

              THE REASON IT STAYS AT ALL: it is the honest placeholder for the held graph, and it is the only
              thing on this screen that renders the edition/permission seam — the four-gate shape the section
              exists to demonstrate. So it keeps its own line, named as standing in for teamMap.
              Registered: docs/DEFERRAL-REGISTER.md. */}
              <p className="mt-3 border-t border-white/5 pt-3 text-xs text-slate-400">
                <span className="text-slate-500">Group membership</span>{" "}
                {groupAccess.kind === "edges"
                  ? `— ${groupAccessLabel(groupAccess)} in this organization.`
                  : `— ${groupAccessLabel(groupAccess)}.`}{" "}
                <span className="text-slate-500">
                  The role-and-group map is not built yet; this stands in for
                  it.
                </span>
              </p>
              <p className="mt-2 text-xs text-slate-500">
                MFA coverage and authentication sources are not shown per member
                yet: both are enforced by the server but not carried on the
                roster response. Two-factor can still be reset per member from
                the row actions.
              </p>
              {shape.gateNote && (
                <p className="mt-2 text-xs text-slate-400">{shape.gateNote}</p>
              )}
            </Card>
          </div>
        </div>

        {/* ⛔ §2.5 OF THE COMMIT-ONE SAID "NO CLIENT-SIDE OWNER COUNT" AND THE SCREEN ALREADY HAD ONE, with a
            written rationale (see isSoleOwner). I ruled on this screen's behaviour without reading the screen
            — the same method error as grepping `Member` and concluding the product did not know.
            Reconciled rather than overwritten, because the existing design is right and the ruling's CONCERN
            is also right, and they are about different things:
              the DISABLE is client-side  — it stops a pointless round-trip and the tooltip teaches WHY
              the REFUSAL is the server's — mutate() surfaces apiErrorMessage(error, fallback), server text
                                            first, and refetches so a lost race self-corrects
            What §2.5 must forbid is PREDICTING THE REFUSAL TEXT, not disabling a control. */}
        {can(myRole, "member:manage") && (
          <p className="mt-2 text-xs text-slate-500">{LAST_OWNER_NOTE}</p>
        )}
      </div>
      {resetTarget && (
        <Modal
          title="Reset two-factor authentication"
          danger
          onDismiss={() => setResetTarget(null)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setResetTarget(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={doReset} disabled={resetBusy}>
                {resetBusy ? "Resetting…" : "Reset 2FA"}
              </Button>
            </>
          }
        >
          <p className="text-sm text-slate-300">
            Remove two-factor authentication for{" "}
            <span className="font-semibold">{resetTarget.email}</span>?
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Their 2FA and recovery codes are cleared and they will be notified
            by email. If your organization requires MFA, they will be asked to
            set it up again at their next sign-in. This does not sign you in as
            them.
          </p>
        </Modal>
      )}
    </div>
  );

  async function doReset() {
    if (!org || !resetTarget) return;
    const target = resetTarget;
    setResetBusy(true);
    await mutate(
      () =>
        api.POST("/api/v1/organizations/{orgId}/members/{userId}/mfa-reset", {
          params: { path: { orgId: org.id, userId: target.user_id } },
        }),
      "Could not reset the member’s two-factor authentication.",
    );
    setResetBusy(false);
    setResetTarget(null);
  }
}

// InviteForm is enumeration-resistant by construction: the server returns the
// same 202 whether the email is new, already a member, or already has an
// account, and we render one fixed confirmation regardless. Reactivating a
// frozen member is a DIFFERENT verb (the row's Reactivate button) — invite is
// only ever for bringing in a new address.
function InviteForm({
  orgId,
  onInvited,
}: {
  orgId: string;
  onInvited: () => void;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [busy, setBusy] = useState(false);
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // ⛔ WHETHER THIS DEPLOYMENT CAN SEND MAIL AT ALL, ASKED BEFORE THE OPERATOR TYPES AN ADDRESS.
  //
  // `/meta.smtp_configured` has existed for a while and had ZERO web consumers — the third
  // producer-without-consumer this cycle. That absence is exactly how the founder lost a session: the API
  // reported the invitation created, the log said mail was not sent, and no screen anywhere mentioned that
  // mail was off. He found out by not receiving an email.
  //
  // ⚠ THREE STATES, NOT TWO (loading is not absence). `null` means the read has not landed or failed —
  // rendered as silence, never as "mail is off", because a fetch blip must not accuse a working deployment.
  const [mailOn, setMailOn] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    void api.GET("/api/v1/meta").then(({ data }) => {
      if (alive && data && typeof data.smtp_configured === "boolean")
        setMailOn(data.smtp_configured);
    });
    return () => {
      alive = false;
    };
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/invitations",
      {
        params: { path: { orgId } },
        body: { email, role },
      },
    );
    setBusy(false);
    if (error || !data)
      return setErr(apiErrorMessage(error, "Could not create the invitation."));
    setEmail("");
    // Build the accept link from THIS origin (correct host regardless of the API's
    // APP_BASE_URL) and show it once for the admin to copy + hand to the invitee —
    // the delivery path when email isn't configured. The email is best-effort on top.
    setInviteLink(
      `${window.location.origin}/accept-invite?token=${data.invite_token}`,
    );
    onInvited();
  }

  return (
    <form onSubmit={submit} className="mt-6">
      <Card>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[14rem] flex-1">
            <Field label="Invite by email">
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="name@company.com"
              />
            </Field>
          </div>
          <select
            className={selectCls}
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
            aria-label="Role"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <Button type="submit" disabled={busy}>
            {busy ? "Sending…" : "Send invite"}
          </Button>
        </div>
        {/* ⛔ MAIL IS OFF, AND THE SCREEN SAYS SO BEFORE THE CLICK RATHER THAN AFTER THE SILENCE. The
            invitation still works — the link modal is the delivery path — so this is an instruction, not a
            refusal, and it must not read as one. */}
        {mailOn === false && (
          <p className="mt-3 text-cell text-warn">
            Email is not configured on this deployment, so nothing will be sent.
            The invitation is still created and you will get a link to hand over
            yourself. Set SMTP_HOST and restart the API to send mail.
          </p>
        )}
        {/* Success uses the accent, not green (green = liveness only, S4.4). The
            copy is deliberately generic — it never reveals whether the address
            already had an account. */}
        <ErrorText>{err}</ErrorText>
      </Card>
      {inviteLink && (
        <OneTimeSecretModal
          title="Invitation link"
          caption={
            mailOn === false
              ? "Copy this link and send it to the invitee. It works once, expires, and won't be shown again. Email is NOT configured on this deployment, so this link is the only way they will get in."
              : "Copy this link and send it to the invitee. It works once, expires, and won't be shown again. If email is configured, they also received it."
          }
          secret={inviteLink}
          copyLabel="Copy link"
          onDismiss={() => setInviteLink(null)}
        />
      )}
    </form>
  );
}
