import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  type Meta,
  type Org,
  type Member,
  type Role,
  type SsoConfigView,
  type UserGroup,
  type ResizeConflict,
} from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { relativeAge } from "../lib/format";
import { can } from "../lib/rbac";
import {
  FAIL_STATIC_NOTE,
  UNMAP_CONSEQUENCES,
  UNSUPPORTED_NOTE,
  idpConfigState,
  idpErrorCopy,
  idpGate,
  idpGroupIdHelp,
  mappedGroups,
  syncTier,
  tierCopy,
  unmapConfirmSatisfied,
  type IdpConfigState,
  type IdpHealth,
} from "../lib/idpsyncview";
import {
  enabledLabel,
  secretPlaceholder,
  toggleReflectsServer,
} from "../lib/ssoview";
import {
  RESIZE_ATOMIC_NOTE,
  orphanReasonCopy,
  orphanTail,
} from "../lib/poolview";
import { useAuth } from "../lib/auth";
import { Button, Card, ErrorText, Field, Input } from "../components/ui";
import { LicenceCard } from "../components/LicenceCard";
import { MfaSettings } from "../components/MfaSettings";
import { MachineCredentials } from "../components/MachineCredentials";

const PROVIDERS = ["google", "microsoft"] as const;
type Provider = (typeof PROVIDERS)[number];
type SsoView = SsoConfigView;

export default function Settings() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5) — the page no longer picks index zero out of a list it
  // fetched itself, which is what made a second organization unreachable.
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [meta, setMeta] = useState<Meta | null>(null);
  const [org, setOrg] = useState<Org | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // ⭐ THE ORG-LIST FETCH IS GONE FROM THIS PAGE (S12.5). It existed only to be indexed at zero.
        // OrgProvider reads the list once for the whole shell; a page that re-fetched it would not merely
        // waste a request, it would pick an org the switcher has no way to change.
        const orgErr = null;
        const { data: m } = await api.GET("/api/v1/meta");
        if (cancelled) return;
        if (m) setMeta(m);
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
        // My role comes from my own row in the roster (no dedicated endpoint yet).
        const { data: members } = await api.GET(
          "/api/v1/organizations/{orgId}/members",
          {
            params: { path: { orgId: first.id } },
          },
        );
        if (!cancelled)
          setMyRole(
            (members as Member[] | undefined)?.find((mm) => mm.user_id === myId)
              ?.role,
          );
      } catch {
        if (!cancelled) setError("Could not reach the API.");
      }
    })();
    return () => {
      cancelled = true;
    };
    // ⛔ currentOrg IS A DEPENDENCY, AND ITS ABSENCE WAS A REAL BUG (S12.5). The provider resolves the org
    // list asynchronously, so on this effect's first run currentOrg is still null. Without the dependency
    // the effect never ran again and the page rendered "You are not a member of any organization yet" — a
    // confident, wrong statement — permanently, for every user. The same line is what makes the switcher work.
  }, [myId, currentOrg]);

  const isAdmin = can(myRole, "org:update");
  const canMachines = can(myRole, "machine:manage"); // owner-only — the GitOps operator credential panel

  return (
    // ⛔ CAPPED, AND THE CAP IS THE POINT. On a 32" display an uncapped settings page stretches every card to
    // 2000px wide to hold a slug and a checkbox — the text line-length collapses into something unreadable
    // and the eye has to travel the full width for each field. A maximum turns extra viewport into MARGIN.
    <div className="mx-auto max-w-[110rem]">
      <h1 className="text-xl font-semibold text-white">Settings</h1>
      <p className="text-sm text-slate-400">{org ? org.name : "…"}</p>
      <ErrorText>{error}</ErrorText>

      {/* Desktop-only: server connection + sign-out for THIS client (renders nothing
          in the browser build). Above the org sections — it's a device concern, not
          an org-admin one, so it shows regardless of role. */}

      {/* Self-service 2FA is per-USER (OPEN, every edition), so it shows for every signed-in user
          regardless of org role — unlike the org-level enforce toggle below (enterprise, admin). */}
      {/* ⛔ ONE GRID, AUTO-FILLED — and `auto-fill` with a MINIMUM is what stops the stretch. A fixed
          `lg:grid-cols-3` would widen every card to a third of whatever the screen is; this fills the row
          with as many ~24rem columns as fit and leaves the rest as margin. Adding a section later drops it
          into the flow and reflows the row — it does not change the width of anything already there.

          ⚠ THE CARDS ARE `items-start`, NOT STRETCHED TO THE TALLEST IN THE ROW. A three-line card padded
          to the height of a twenty-line neighbour reads as a card with something missing from it. */}
      {/* ⛔ COLUMNS, NOT A GRID — and the previous attempt is why. A CSS grid ALIGNS ROWS: put the
          twenty-line Entra card beside the three-line 2FA card and every short card in that row is followed
          by a hole the height of the tallest one. The screen filled with vertical gaps.

          Multi-column flow packs each card under the previous one in its column and never aligns across
          columns, so height differences cost nothing. It also answers the original constraint the same way
          the grid was meant to: more width adds a COLUMN, it does not widen a card.

          ⚠ EVERY CHILD NEEDS `break-inside-avoid`, or the browser will split a card down the middle across
          a column boundary — which looks exactly like a rendering bug and is the one hazard this layout has.
          The wrapper carries it so no section has to remember. */}
      <div className="mt-6 columns-1 gap-3.5 lg:columns-2 2xl:columns-3">
        {/* ⚠ Owner-only to INSTALL; every member sees the entitlement, because a user who hits a ceiling
            needs to know why without asking an owner. */}
        {org && (
          <div className="mb-3.5 break-inside-avoid">
            <LicenceCard canManage={myRole === "owner"} />
          </div>
        )}
        <div className="mb-3.5 break-inside-avoid">
          <MfaSettings />
        </div>

        {/* Directory sync renders OUTSIDE the `isAdmin` block, on purpose but NOT because of a
          live defect — the honest version, after a mutation survivor sent me to measure.
          Settings gates its org panels on `org:update`; every idp-sync handler gates on
          `policy:manage`. Today those are held by the same user-assignable roles (owner, admin),
          so nesting would change nothing observable. `operator` holds policy:manage WITHOUT
          org:update but is MACHINE-ONLY — `memberships` CHECKs role IN (owner, admin, member),
          so it never renders a UI and cannot make the difference visible.
          It is out here so the panel is governed by ONE gate — its own, matching the server —
          rather than silently ANDed with a different permission that merely happens to coincide.
          `idpGate` is the authority; a test pins the coincidence so a divergence is loud. */}
        {org && (
          <>
            {PROVIDERS.map((pv) => (
              <div key={pv} className="mb-3.5 break-inside-avoid">
                <IdpSyncSection
                  orgId={org.id}
                  provider={pv}
                  role={myRole}
                  isEnterprise={meta?.edition === "enterprise"}
                  canEdit={emailVerified}
                />
              </div>
            ))}
          </>
        )}

        {org && !isAdmin && (
          <Card className="mt-6">
            <p className="text-sm text-slate-400">
              Organization settings are managed by owners and admins.
            </p>
          </Card>
        )}

        {org && isAdmin && (
          <>
            <div className="mb-3.5 break-inside-avoid">
              <OrgSection
                org={org}
                canEdit={emailVerified}
                onSaved={(o) => setOrg(o)}
              />
            </div>
            <div className="mb-3.5 break-inside-avoid">
              <PoolSection
                org={org}
                canEdit={emailVerified}
                onResized={(o) => setOrg(o)}
              />
            </div>
            {/* SSO config is enterprise-only; hidden in the open edition per /meta
              (watch-item b), with a muted note rather than a dead form. */}
            {meta?.edition === "enterprise" ? (
              <div className="mb-3.5 break-inside-avoid">
                <SsoSettings orgId={org.id} canEdit={emailVerified} />
              </div>
            ) : (
              <div className="mb-3.5 break-inside-avoid">
                <Card>
                  <h2 className="text-sm font-semibold text-slate-300">
                    Single sign-on
                  </h2>
                  <p className="mt-1 text-xs text-slate-500">
                    SSO (Google / Microsoft) is a Tunnex Enterprise feature.
                  </p>
                </Card>
              </div>
            )}
            {meta?.edition === "enterprise" ? (
              <div className="mb-3.5 break-inside-avoid">
                <OrgMfaEnforce orgId={org.id} canEdit={emailVerified} />
              </div>
            ) : (
              <div className="mb-3.5 break-inside-avoid">
                <Card>
                  <h2 className="text-sm font-semibold text-slate-300">
                    Require two-factor authentication
                  </h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Org-wide MFA enforcement is a Tunnex Enterprise feature.
                  </p>
                </Card>
              </div>
            )}
            {/* OpenVPN is OPEN (every edition) but OFF by default — unlock-then-opt-in (D-S9.5-OPTIN). */}
            <div className="mb-3.5 break-inside-avoid">
              <OrgOVPNToggle
                org={org}
                canEdit={emailVerified}
                onSaved={(o) => setOrg(o)}
              />
            </div>
            {/* ⛔ FULL WIDTH, BECAUSE IT CONTAINS A TABLE. A data table in a 24rem column is a data table with
              every column truncated — the one section whose content genuinely needs the row. `col-span-full`
              keeps it in the same grid rather than breaking it out into a second layout that would then
              drift from this one. */}
          </>
        )}
      </div>

      {/* ⛔ OUTSIDE THE COLUMNS, BECAUSE A TABLE CANNOT LIVE IN ONE. Multi-column flow has no equivalent of
          `col-span-full` — a wide child inside a column region is simply a child of one column, so the table
          would be squeezed to a third of the page with every column truncated. It sits below, full width,
          which is also where the mockup puts it. */}
      {org && isAdmin && canMachines && (
        <div className="mt-3.5">
          <MachineCredentials orgId={org.id} canManage={canMachines} />
        </div>
      )}

      {/* ⛔ THE CAPABILITY EXISTED AND NOTHING COULD REACH IT. `DELETE /organizations/{id}` has shipped
          since S1 with `org:delete` on it and NO CALL SITE anywhere in the web — one of the 12 genuinely
          unreachable mutating operations the S14.12 census counted. An owner could not delete an
          organization they created by mistake without curl.
          ⚠ OUTSIDE THE COLUMNS AND LAST, deliberately: a destructive verb does not belong beside the name
          field, where a mis-click lands next to routine edits. */}
      {org && (
        <div className="mt-3.5">
          <DangerZone
            org={org}
            canDelete={can(myRole, "org:delete")}
            role={myRole}
          />
        </div>
      )}
    </div>
  );
}

/**
 * Deleting an organization.
 *
 * ⛔ OWNER-ONLY, AND AN ADMIN IS SHOWN WHY RATHER THAN SHOWN NOTHING. `org:delete` is one of the three
 * permissions an owner holds and an admin does not; hiding the section entirely would leave an admin
 * hunting for a control the product does have.
 *
 * ⛔ AND IT REFUSES WHILE THE ORGANIZATION OWNS ANYTHING. Delete here is a SOFT delete — gateways keep
 * carrying traffic on the customer's own servers, devices keep their addresses, machine credentials keep
 * authenticating, all owned by an organization no screen will show again. The server enforces this; this
 * screen reads the same counts from the same function so the two can never describe the state differently.
 */
function DangerZone({
  org,
  canDelete,
  role,
}: {
  org: Org;
  canDelete: boolean;
  role: string | undefined;
}) {
  const [pre, setPre] = useState<{
    deletable: boolean;
    blockers: string[];
  } | null>(null);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!canDelete) return;
    let off = false;
    void api
      .GET("/api/v1/organizations/{orgId}/deletion-preflight", {
        params: { path: { orgId: org.id } },
      })
      .then(({ data }) => {
        // ⚠ THE ARRAY IS DEFAULTED AT THE SEAM. A body without `blockers` crashed the whole Settings page
        // on `.join` — caught by the wiring test, and it is not a test artifact: any proxy, older server
        // or partial response produces the same white screen on the page holding the delete control.
        if (!off && data)
          setPre({ deletable: data.deletable, blockers: data.blockers ?? [] });
      })
      .catch(() => {});
    return () => {
      off = true;
    };
  }, [org.id, canDelete]);

  if (!canDelete) {
    return (
      <Card>
        <h2 className="text-sm font-semibold text-slate-300">
          Delete this organization
        </h2>
        <p className="mt-2 text-sm text-slate-400">
          {/* ⚠ NOT THE SETTINGS-WIDE SENTENCE. Reusing "managed by owners and admins" put a second copy of
              it on the page for a plain member, and the e2e spec that asserts it went strict-mode red —
              correctly: two identical sentences in different sections is a page that cannot be pointed at. */}
          {role === "admin"
            ? "Deleting an organization is reserved for owners."
            : "Only an owner can delete an organization."}
        </p>
      </Card>
    );
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const { error } = await api.DELETE("/api/v1/organizations/{orgId}", {
      params: { path: { orgId: org.id } },
    });
    setBusy(false);
    if (error) {
      // ⚠ THE SERVER'S OWN WORDS. It names every blocker; a generic "could not delete" here would throw
      // away the only sentence that tells the operator what to do next.
      return setErr(apiErrorMessage(error, "Could not delete the organization."));
    }
    // ⛔ A FULL RELOAD, NOT A ROUTER NAVIGATION. The org seam holds the list in memory and has no refresh
    // verb; a client-side route change would leave the just-deleted organization in the switcher and
    // selected — a tenant that no longer exists, on screen, ready to be acted on. Adding a refresh method
    // to the seam for one caller is the wider change; this is the honest small one.
    window.location.assign("/dashboard");
  }

  const blocked = pre !== null && !pre.deletable;
  return (
    <Card className="border-danger/40">
      <h2 className="text-sm font-semibold text-danger">
        Delete this organization
      </h2>
      <p className="mt-2 text-sm text-slate-400">
        This cannot be undone. Members lose access to it immediately; the
        organization stops appearing in the switcher.
      </p>

      {/* ⛔ THE BLOCKERS ARE SHOWN BEFORE THE CONFIRMATION FIELD, NOT AFTER THE ATTEMPT. A refusal that
          arrives only once someone has typed the organization's name to confirm is a refusal met at the
          most dangerous moment — with their attention on getting past it. */}
      {blocked && (
        <div className="mt-3 rounded-card border border-warn/30 bg-warn/5 p-3">
          <p className="text-cell text-ink-body">
            {/* ⚠ THE SERVER'S LIST WHEN IT HAS ONE, A TRUTHFUL SENTENCE WHEN IT DOES NOT. "still has ."
                would be the shape a naive join produces, and it reads as a rendering bug on the one
                screen where the operator most needs to trust what they are told. */}
            {pre.blockers.length > 0
              ? `This organization still has ${pre.blockers.join(", ")}.`
              : "This organization still owns resources."}{" "}
            Remove them first — deleting now would leave them running with no
            organization to manage them from.
          </p>
        </div>
      )}

      <form onSubmit={submit} className="mt-3 flex flex-wrap items-end gap-3">
        <div className="min-w-[14rem] flex-1">
          {/* ⚠ TYPE THE SLUG, NOT "DELETE". The slug is the one string that differs between the org you
              mean and the one you are looking at — and with a switcher in the header, looking at the wrong
              organization is the realistic mistake, not clicking the wrong button. */}
          <Field label={`Type ${org.slug} to confirm`}>
            <Input
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={blocked}
              placeholder={org.slug}
            />
          </Field>
        </div>
        <Button
          type="submit"
          variant="danger"
          disabled={busy || blocked || confirm !== org.slug}
        >
          {busy ? "Deleting…" : "Delete organization"}
        </Button>
      </form>
      <ErrorText>{err}</ErrorText>
    </Card>
  );
}

// OrgMfaEnforce — org-level MFA mandate (enterprise, S7.5.5). Unlock-then-opt-in: default OFF; on
// toggle, unenrolled password users are prompted to enroll at their next sign-in (never locked out).
function OrgMfaEnforce({
  orgId,
  canEdit,
}: {
  orgId: string;
  canEdit: boolean;
}) {
  const [enforce, setEnforce] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/api/v1/organizations/{orgId}/mfa-enforce", {
        params: { path: { orgId } },
      })
      .then(({ data }) => {
        if (!cancelled && data) setEnforce(data.enforce);
      })
      .catch(() => {
        if (!cancelled) setEnforce(false);
      });
    return () => {
      cancelled = true;
    };
  }, [orgId]);

  async function toggle(next: boolean) {
    setBusy(true);
    setError(null);
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/mfa-enforce",
      {
        params: { path: { orgId } },
        body: { enforce: next },
      },
    );
    setBusy(false);
    if (error || !data) {
      setError(apiErrorMessage(error, "Could not update MFA enforcement."));
      return;
    }
    setEnforce(data.enforce);
  }

  return (
    <Card>
      <h2 className="text-sm font-semibold text-slate-300">
        Require two-factor authentication
      </h2>
      <p className="mt-1 text-xs text-slate-400">
        When on, members who sign in with a password must have 2FA — anyone
        without it is prompted to set it up at their next sign-in (no one is
        locked out). SSO sign-ins are governed by your identity provider.
      </p>
      {/* D8 honesty: enforcement is a forward gate, not retroactive. */}
      <p className="mt-1 text-xs text-slate-500">
        Enforcement applies at sign-in, not to sessions already open —
        pre-existing sessions remain valid until they expire naturally. To end
        current sessions immediately, deactivate the member.
      </p>
      {error && (
        <div className="mt-2">
          <ErrorText>{error}</ErrorText>
        </div>
      )}
      <div className="mt-3">
        {enforce === null ? (
          <p className="text-xs text-slate-500">Loading…</p>
        ) : (
          <Button
            variant="ghost"
            disabled={busy || !canEdit}
            onClick={() => toggle(!enforce)}
          >
            {busy
              ? "Saving…"
              : enforce
                ? "Disable requirement"
                : "Require MFA for password sign-ins"}
          </Button>
        )}
      </div>
    </Card>
  );
}

// OrgOVPNToggle is the OpenVPN opt-in (S9.1 D-S9.5-OPTIN) — OPEN edition, org:update-gated, OFF by
// default. This is the operator's on-switch for the whole feature (unlock-then-opt-in): enabling makes
// the OpenVPN capability available on the org's gateways + surfaces the OpenVPN device type in the
// export ceremony. The initial state comes from the org (no separate GET); PUT flips it.
function OrgOVPNToggle({
  org,
  canEdit,
  onSaved,
}: {
  org: Org;
  canEdit: boolean;
  onSaved: (o: Org) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const enabled = org.ovpn_enabled === true;

  async function toggle(next: boolean) {
    setBusy(true);
    setError(null);
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/ovpn-settings",
      {
        params: { path: { orgId: org.id } },
        body: { enabled: next },
      },
    );
    setBusy(false);
    if (error || !data) {
      setError(apiErrorMessage(error, "Could not update OpenVPN."));
      return;
    }
    onSaved({ ...org, ovpn_enabled: data.enabled });
  }

  return (
    <Card>
      <h2 className="text-sm font-semibold text-slate-300">OpenVPN</h2>
      <p className="mt-1 text-xs text-slate-400">
        OpenVPN is <span className="text-slate-300">off by default</span>.
        Enable it where you&rsquo;re migrating an existing OpenVPN fleet —
        devices can then be exported as standard{" "}
        <code className="text-slate-300">.ovpn</code> profiles for the official
        OpenVPN clients. WireGuard is unaffected.
      </p>
      <p className="mt-1 text-xs text-slate-500">
        Turning it off stops the OpenVPN servers on your gateways; issued client
        profiles are not revoked and work again if you re-enable.
      </p>
      {error && (
        <div className="mt-2">
          <ErrorText>{error}</ErrorText>
        </div>
      )}
      <div className="mt-3">
        <Button
          variant="ghost"
          disabled={busy || !canEdit}
          onClick={() => toggle(!enabled)}
        >
          {busy ? "Saving…" : enabled ? "Disable OpenVPN" : "Enable OpenVPN"}
        </Button>
      </div>
    </Card>
  );
}

// isResizeConflict narrows a resize error to the structured 409 (orphan list),
// distinguishing it from the generic error envelope.
function isResizeConflict(e: unknown): e is ResizeConflict {
  return (
    typeof e === "object" && e !== null && "orphans" in e && "orphan_count" in e
  );
}

function PoolSection({
  org,
  canEdit,
  onResized,
}: {
  org: Org;
  canEdit: boolean;
  onResized: (o: Org) => void;
}) {
  const [cidr, setCidr] = useState(org.pool_cidr);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [conflict, setConflict] = useState<ResizeConflict | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setConflict(null);
    setDone(false);
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/pool-cidr",
      {
        params: { path: { orgId: org.id } },
        body: { cidr },
      },
    );
    setBusy(false);
    if (error) {
      // A shrink that would strand devices comes back as the structured 409:
      // render the (capped) list with names + reasons so the refusal is actionable.
      if (isResizeConflict(error)) return setConflict(error);
      return setErr(apiErrorMessage(error, "Could not resize the pool."));
    }
    if (data) {
      onResized(data);
      setCidr(data.pool_cidr);
      setDone(true);
    }
  }

  return (
    <form onSubmit={submit} className="mt-4">
      <Card>
        <h2 className="text-sm font-semibold text-slate-300">Address pool</h2>
        <p className="mt-1 text-xs text-slate-500">
          The WireGuard address range devices are assigned from. Grow to add
          capacity; shrink only within the current range.
        </p>
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <div className="min-w-[12rem] flex-1">
            <Field label="Pool CIDR">
              <Input
                value={cidr}
                onChange={(e) => {
                  setCidr(e.target.value);
                  setDone(false);
                  setConflict(null);
                }}
                required
                disabled={!canEdit}
                placeholder="10.0.0.0/24"
              />
            </Field>
          </div>
          <Button
            type="submit"
            disabled={busy || !canEdit || cidr === org.pool_cidr}
          >
            {busy ? "Resizing…" : "Resize pool"}
          </Button>
        </div>

        {/* Accept-and-surface (S4.5b decision e): the resize succeeds, but existing
            configs embed the old range and are one-time — they can't be re-served. */}
        {done && (
          <p className="mt-3 text-xs text-accent-400">
            Pool resized to <span className="font-mono">{cidr}</span>. Existing
            devices keep their current addresses — to reach addresses in the new
            range, re-issue their configs (revoke + recreate; configs are shown
            once and can’t be re-sent).
          </p>
        )}

        {/* Actionable shrink refusal: which devices block it, and why. */}
        {conflict && (
          <div className="mt-3 rounded-lg border border-danger/40 bg-danger/5 p-3">
            <p className="text-sm text-slate-300">
              Can’t shrink: {conflict.orphan_count} device
              {conflict.orphan_count === 1 ? "" : "s"} must be removed or
              renumbered first.{" "}
              {/* The refusal rolls back inside the transaction (service.go:539 returns
                  BEFORE UpdateOrgPoolCidr at :541), so this is a fact, not reassurance —
                  and without it the operator cannot tell a refusal from a partial resize. */}
              <span className="text-slate-400">{RESIZE_ATOMIC_NOTE}</span>
            </p>
            <ul className="mt-2 space-y-1">
              {conflict.orphans.map((o) => (
                <li
                  key={o.device_id}
                  className="flex items-center justify-between text-xs"
                >
                  <span className="text-slate-300">{o.name}</span>
                  <span className="font-mono text-slate-500">
                    {o.assigned_ip}
                    <span className="ml-2 text-slate-600">
                      {orphanReasonCopy(o.reason)}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
            {orphanTail(conflict.orphan_count, conflict.orphans.length) && (
              <p className="mt-1 text-xs text-slate-600">
                {orphanTail(conflict.orphan_count, conflict.orphans.length)}
              </p>
            )}
          </div>
        )}
        <ErrorText>{err}</ErrorText>
      </Card>
    </form>
  );
}

// IdpSyncSection — directory sync (S14.14). The consuming layer for FIVE endpoints that had
// ZERO call sites: putIdpSyncConfig, getIdpSyncHealth, triggerIdpSync, mapIdpGroup, unmapIdpGroup.
//
// ⛔ GATED ON POLICY PERMISSIONS, NOT ORG ONES — measured from the handlers, not from the screen
// it lives on. An operator with org:update and without policy:manage sees Settings and does not
// see this panel, rather than seeing a control that can only ever 403.
function IdpSyncSection({
  orgId,
  provider,
  role,
  isEnterprise,
  canEdit,
}: {
  orgId: string;
  provider: Provider;
  role: Role | undefined;
  isEnterprise: boolean;
  canEdit: boolean;
}) {
  const gate = idpGate({ role: role ?? null, isEnterprise });
  const [state, setState] = useState<IdpConfigState>({ kind: "unknown" });
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [serviceAccountJSON, setServiceAccountJSON] = useState("");
  const [delegatedAdminEmail, setDelegatedAdminEmail] = useState("");
  const [idpGroupId, setIdpGroupId] = useState("");
  const [newName, setNewName] = useState("");
  const [unmapping, setUnmapping] = useState<UserGroup | null>(null);
  const [confirmText, setConfirmText] = useState("");

  const ready = gate.kind === "ready";

  const load = async (isCancelled: () => boolean) => {
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/idp-sync/{provider}/health",
      { params: { path: { orgId, provider } } },
    );
    if (isCancelled()) return;
    // ⛔ NOT CONFIGURED IS A STATE; A FAILED READ IS NOT. The server answers 404 with a stable
    // `idp_sync_not_configured` (service.go:141), so existence is knowable and only a NON-404
    // failure is `unknown`. Third instance of this shape, first one built right up front.
    setState(
      idpConfigState({
        errorCode: apiErrorCode(error),
        failed: Boolean(error),
        health: (data as IdpHealth | undefined) ?? null,
      }),
    );
    const { data: gs } = await api.GET("/api/v1/organizations/{orgId}/groups", {
      params: { path: { orgId } },
    });
    if (!isCancelled() && gs) setGroups(gs as UserGroup[]);
  };

  useEffect(() => {
    if (!ready) return;
    let cancelled = false;
    void load(() => cancelled);
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, provider, ready]);

  if (gate.kind === "hidden") return null;
  if (gate.kind === "upsell")
    return (
      <Card>
        <h2 className="text-sm font-semibold text-slate-300">
          Directory sync — {providerLabel(provider)}
        </h2>
        <p className="mt-1 text-xs text-slate-500">
          Syncing groups from {providerLabel(provider)} is a Tunnex Enterprise
          feature.
        </p>
      </Card>
    );

  const mapped = mappedGroups(groups, provider);
  const emptyManual = groups.filter((g) => (g.origin ?? "manual") === "manual");

  async function saveConfig(e: FormEvent) {
    e.preventDefault();
    setBusy("config");
    setErr(null);
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/idp-sync/{provider}",
      {
        params: { path: { orgId, provider } },
        body: {
          client_id: clientId,
          client_secret: clientSecret,
          tenant_id: tenantId || undefined,
          service_account_json: serviceAccountJSON || undefined,
          delegated_admin_email: delegatedAdminEmail || undefined,
          enabled: true,
        },
      },
    );
    setBusy(null);
    if (error) return setErr(idpErrorCopy(apiErrorCode(error)));
    setClientSecret(""); // never keep a secret in page state after the write
    setServiceAccountJSON("");
    setShowForm(false);
    await load(() => false);
  }

  async function trigger() {
    setBusy("trigger");
    setErr(null);
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/idp-sync/{provider}/trigger",
      { params: { path: { orgId, provider } } },
    );
    setBusy(null);
    if (error) return setErr(idpErrorCopy(apiErrorCode(error)));
    // ⛔ RENDER WHAT THE SERVER RETURNED, NOT "SYNC COMPLETE". Trigger answers with the resulting
    // HEALTH SNAPSHOT, so a sync that ran and FAILED comes back here as degraded/escalated. A
    // success toast would state an outcome the response contradicts.
    if (data) setState({ kind: "configured", health: data as IdpHealth });
  }

  async function mapGroup(e: FormEvent) {
    e.preventDefault();
    setBusy("map");
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/idp-sync/{provider}/groups",
      {
        params: { path: { orgId, provider } },
        body: { idp_group_id: idpGroupId, name: newName || undefined },
      },
    );
    setBusy(null);
    if (error) return setErr(idpErrorCopy(apiErrorCode(error)));
    setIdpGroupId("");
    setNewName("");
    await load(() => false);
  }

  async function unmap(g: UserGroup) {
    setBusy("unmap");
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/idp-sync/{provider}/groups/{groupId}",
      { params: { path: { orgId, provider, groupId: g.id } } },
    );
    setBusy(null);
    setUnmapping(null);
    setConfirmText("");
    if (error) return setErr(idpErrorCopy(apiErrorCode(error)));
    await load(() => false);
  }

  const tier = state.kind === "configured" ? syncTier(state.health) : null;
  const copy = tier ? tierCopy(tier) : null;

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-semibold text-slate-300">
          Directory sync — {providerLabel(provider)}
        </h2>
        {copy && (
          <span
            data-testid={`idp-tier-${provider}`}
            className={
              "rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold " +
              (tier === "ok"
                ? "border-accent-500/40 bg-accent-500/10 text-accent-400"
                : tier === "degraded"
                  ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                  : "border-danger/50 bg-danger/10 text-danger")
            }
          >
            {copy.label}
          </span>
        )}
      </div>

      {/* ⛔ THE FOURTH ARM, and only the SERVED payload revealed it: the spec enum lists google
          for every idp-sync path, but the server answers 400 provider_not_supported. Rendering a
          Configure form here would offer a credential the server refuses to store. */}
      {state.kind === "unsupported" && (
        <p className="mt-1 text-xs text-slate-500">{UNSUPPORTED_NOTE}</p>
      )}

      {/* ⛔ THE THIRD ARM. A failed read never renders the Configure form — offering it over a
          live credential is the S14.13 destructive path, and this is the same class. */}
      {state.kind === "unknown" && (
        <>
          <p className="mt-2 text-sm text-slate-400">
            Directory-sync status unknown — the health read failed, so we cannot
            tell whether this provider is configured.
          </p>
          <Button
            type="button"
            className="mt-3"
            onClick={() => void load(() => false)}
          >
            Retry
          </Button>
        </>
      )}

      {state.kind === "unconfigured" && !showForm && (
        <>
          <p className="mt-1 text-xs text-slate-500">
            Not configured. Connect {providerLabel(provider)} to sync directory
            groups into Tunnex groups.
          </p>
          <Button
            type="button"
            className="mt-3"
            disabled={!canEdit}
            onClick={() => setShowForm(true)}
          >
            Configure
          </Button>
        </>
      )}

      {state.kind === "configured" && copy && (
        <>
          <p
            className={
              "mt-1 text-xs " + (copy.loud ? "text-danger" : "text-slate-500")
            }
          >
            {copy.text}
          </p>
          {/* Fail-static is the part a health badge cannot carry: a broken sync KEEPS access. */}
          <p className="mt-1 text-xs text-slate-500">{FAIL_STATIC_NOTE}</p>
          {state.health.last_sync_error && (
            <p className="mt-1 break-all font-mono text-xs text-slate-500">
              last error: {state.health.last_sync_error}
            </p>
          )}
          <p className="mt-1 text-xs text-slate-600">
            last successful sync:{" "}
            {state.health.last_sync_at
              ? relativeAge(state.health.last_sync_at)
              : "never"}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button
              type="button"
              disabled={!canEdit || busy === "trigger"}
              onClick={() => void trigger()}
            >
              {busy === "trigger" ? "Syncing…" : "Sync now"}
            </Button>
            <Button
              type="button"
              disabled={!canEdit}
              onClick={() => setShowForm(true)}
            >
              Replace credential
            </Button>
          </div>
        </>
      )}

      {showForm && (
        <form onSubmit={saveConfig} className="mt-3 space-y-3">
          {/* ⛔ WRITE-ONLY STATE, NAMED. There is no GET for this config — client_id, tenant and
              the secret fingerprint come back only from the PUT that wrote them. So the form is
              never pre-filled from the server and does not pretend to show what is stored. */}
          <p className="text-xs text-slate-600">
            Credentials are set, not readable back — this server serves no read
            for the directory-sync credential, so the fields below always start
            empty even when a credential is stored.
          </p>
          {provider === "microsoft" && <Field label={`${providerLabel(provider)} directory client ID`}>
            <Input
              name={`${provider}-idp-client-id`}
              autoComplete="off"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              required
              disabled={!canEdit}
            />
          </Field>}
          {provider === "microsoft" && <Field label={`${providerLabel(provider)} directory client secret`}>
            <Input
              type="password"
              name={`${provider}-idp-client-secret`}
              autoComplete="new-password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              required
              disabled={!canEdit}
              placeholder="••••••••"
            />
          </Field>}
          {provider === "microsoft" && (
            <Field label="Tenant ID (Entra)">
              <Input
                name="microsoft-idp-tenant-id"
                autoComplete="off"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                disabled={!canEdit}
              />
            </Field>
          )}
          {provider === "google" && (
            <>
              <Field label="Google service-account JSON (DWD)">
                <textarea
                  className="min-h-24 w-full rounded-md border border-ink-600 bg-ink-950 p-2 font-mono text-xs text-slate-300"
                  value={serviceAccountJSON}
                  onChange={(e) => setServiceAccountJSON(e.target.value)}
                  required
                  autoComplete="off"
                  spellCheck={false}
                  disabled={!canEdit}
                />
              </Field>
              <Field label="Delegated Workspace admin email">
                <Input
                  type="email"
                  value={delegatedAdminEmail}
                  onChange={(e) => setDelegatedAdminEmail(e.target.value)}
                  required
                  disabled={!canEdit}
                />
              </Field>
            </>
          )}
          <div className="flex gap-2">
            <Button type="submit" disabled={busy === "config" || !canEdit}>
              {busy === "config" ? "Saving…" : "Save credential"}
            </Button>
            <Button type="button" onClick={() => setShowForm(false)}>
              Cancel
            </Button>
          </div>
        </form>
      )}

      {state.kind === "configured" && (
        <div className="mt-4 border-t border-white/5 pt-3">
          <h3 className="text-xs font-semibold text-slate-400">
            Synced groups
          </h3>
          {mapped.length === 0 ? (
            <p className="mt-1 text-xs text-slate-600">
              No directory groups are mapped yet.
            </p>
          ) : (
            <ul className="mt-2 space-y-1">
              {mapped.map((g) => (
                <li
                  key={g.id}
                  className="flex flex-wrap items-center justify-between gap-2 text-xs"
                >
                  <span className="text-slate-300">{g.name}</span>
                  <span className="flex items-center gap-2">
                    <span className="font-mono text-slate-600">
                      {g.idp_group_id}
                    </span>
                    <button
                      type="button"
                      disabled={!canEdit}
                      onClick={() => {
                        setUnmapping(g);
                        setConfirmText("");
                      }}
                      className="rounded border border-danger/40 px-2 py-0.5 text-danger disabled:opacity-50"
                    >
                      Un-map
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}

          <form onSubmit={mapGroup} className="mt-3 space-y-2">
            <Field label="Directory group ID">
              <Input
                value={idpGroupId}
                onChange={(e) => setIdpGroupId(e.target.value)}
                required
                disabled={!canEdit}
              />
            </Field>
            {/* No picker is possible: nothing in the spec lists the directory's groups, so a
                select box would be a control the product cannot populate. Say where to find it. */}
            <p className="text-xs text-slate-600">{idpGroupIdHelp(provider)}</p>
            <Field label="New Tunnex group name (optional)">
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                disabled={!canEdit}
                placeholder="defaults to the directory group ID"
              />
            </Field>
            <p className="text-xs text-slate-600">
              Mapping onto an existing group is only allowed if that group is
              empty — {emptyManual.length} manual group
              {emptyManual.length === 1 ? "" : "s"} exist.
            </p>
            <Button type="submit" disabled={busy === "map" || !canEdit}>
              {busy === "map" ? "Mapping…" : "Map group"}
            </Button>
          </form>
        </div>
      )}

      {/* ⛔ THE UNMAP BLAST RADIUS. Check 7b, one screen over from S14.12's cascade: the verb
          deletes every member, KEEPS the group, and pushes org-wide — so rules using it survive
          and match nobody. No NUMBER is shown: the 204 has no body and the server serves no
          preview, so a client-computed count would be a second source of truth. */}
      {unmapping && (
        <div className="mt-3 rounded-lg border border-danger/40 bg-danger/5 p-3">
          <p className="text-sm text-slate-200">
            Un-map <span className="font-mono">{unmapping.name}</span>?
          </p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-400">
            {UNMAP_CONSEQUENCES.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <div className="mt-3 space-y-2">
            <Field label={`Type ${unmapping.name} to confirm`}>
              <Input
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
              />
            </Field>
            <div className="flex gap-2">
              <Button
                type="button"
                disabled={
                  busy === "unmap" ||
                  !unmapConfirmSatisfied(confirmText, unmapping.name)
                }
                onClick={() => void unmap(unmapping)}
              >
                {busy === "unmap" ? "Un-mapping…" : "Un-map group"}
              </Button>
              <Button type="button" onClick={() => setUnmapping(null)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}

      <ErrorText>{err}</ErrorText>
    </Card>
  );
}

function providerLabel(p: string): string {
  return p === "microsoft" ? "Microsoft Entra" : "Google Workspace";
}

/* Domain Capture was removed from the product. The old implementation is retained only in this
   comment temporarily so the surrounding Settings layout remains easy to review; it is not compiled,
   rendered, or reachable. */
/*
//
// ⛔ THE PANEL RENDERS A STATE THE SERVER WILL NOT SERVE BACK. There is no GET for domain
// claims (openapi.yaml:1793/:1817), so everything below `unknown` is knowledge this session
// created. WRITE_ONLY_NOTE says that out loud rather than letting a reload quietly reset a
// verified domain to "never claimed". See domainview.ts's header for the full disposition.
function DomainSection({
  orgId,
  role,
  isEnterprise,
  canEdit,
  myEmail,
}: {
  orgId: string;
  role: Role | undefined;
  isEnterprise: boolean;
  canEdit: boolean;
  myEmail: string;
}) {
  const gate = domainGate({ role: role ?? null, isEnterprise });
  const ownDomain = normalizeDomain(myEmail.split("@").pop() ?? "");
  const [domain, setDomain] = useState(ownDomain);
  const [claim, setClaim] = useState<DomainClaimState>({ kind: "unknown" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (gate.kind === "hidden") return null;
  if (gate.kind === "upsell")
    return (
      <Card>
        <h2 className="text-sm font-semibold text-slate-300">Domain capture</h2>
        <p className="mt-1 text-xs text-slate-500">
          Capturing an email domain so new signups auto-join this organization
          is a Tunnex Enterprise feature.
        </p>
      </Card>
    );

  const typed = normalizeDomain(domain);
  // Predicted client-side from the SERVER'S rule, so the operator is told before the
  // round-trip — not a second source of truth: the server still refuses if we are wrong.
  const ownershipBlocked = typed !== "" && typed !== ownDomain;
  const step = domainStepIndex(claim);

  async function submitClaim(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/domains",
      { params: { path: { orgId } }, body: { domain: typed } },
    );
    setBusy(false);
    if (error || !data) return setErr(domainErrorCopy(apiErrorCode(error)));
    setClaim({
      kind: "pending",
      domain: typed,
      // The server returns the COMPLETE record value; we never assemble it, so this
      // instruction cannot drift from txtHasToken's exact-equality comparison.
      txt: txtInstruction(typed, data.txt_record),
    });
  }

  async function submitVerify() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/domains/verify",
      { params: { path: { orgId } }, body: { domain: typed } },
    );
    setBusy(false);
    if (error) return setErr(domainErrorCopy(apiErrorCode(error)));
    setClaim({ kind: "verified", domain: typed });
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-semibold text-slate-300">Domain capture</h2>
        {/* ⛔ EXACTLY ONE CHIP IS EVER "CURRENT". Three equal chips are a legend with no
            subject — which is what shipped, because `i <= step` gave only two tiers and at
            `unknown` (step -1) every chip fell into the same one. `unknown` is the DEFAULT
            state here (there is no GET), so that was the common render, not an edge case.
            It now has its own leading chip and anchors the chain. * /}
        <div className="flex items-center gap-1.5">
          {[...(step < 0 ? [NO_CLAIM_CHIP] : []), ...DOMAIN_STEPS].map(
            (label, idx) => {
              // The prepended chip occupies the current slot; the real steps shift by one.
              const i = step < 0 ? idx - 1 : idx;
              const tone = chipTone(i, step);
              return (
                <span key={label} className="flex items-center gap-1.5">
                  {idx > 0 && <span className="text-slate-700">›</span>}
                  <span
                    data-testid={`domain-step-${i}`}
                    data-tone={tone}
                    aria-current={tone === "current" ? "step" : undefined}
                    className={
                      "rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold " +
                      (tone === "done"
                        ? "border-accent-500/30 bg-accent-500/5 text-accent-400/70"
                        : tone === "current"
                          ? "border-accent-400 bg-accent-500/20 text-accent-400 ring-1 ring-accent-400/50"
                          : "border-slate-800 bg-slate-900 text-slate-600")
                    }
                  >
                    {/* Non-colour cue: the design encodes the whole distinction in tone, which
                        a colour-blind operator cannot read. * /}
                    {tone === "done" ? "✓ " : ""}
                    {label}
                  </span>
                </span>
              );
            },
          )}
        </div>
      </div>

      <p className="mt-1 text-xs text-slate-500">{CAPTURE_EFFECT}</p>

      <form
        onSubmit={submitClaim}
        className="mt-3 flex flex-wrap items-end gap-3"
      >
        <div className="min-w-[12rem] flex-1">
          <Field label="Domain">
            <Input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              required
              disabled={!canEdit || busy}
              placeholder="acme.io"
            />
          </Field>
        </div>
        <Button type="submit" disabled={busy || !canEdit || ownershipBlocked}>
          {busy ? "Working…" : "Claim domain"}
        </Button>
      </form>

      {/* The ownership inversion guard, stated BEFORE the attempt (domain.go:100). * /}
      {ownershipBlocked && (
        <p className="mt-2 text-xs text-amber-400">
          You can only claim the domain of your own verified address (
          <span className="font-mono">{ownDomain || "none"}</span>). Claiming{" "}
          <span className="font-mono">{typed}</span> would be refused.
        </p>
      )}

      {claim.kind === "pending" && (
        <div className="mt-3 rounded-lg border border-slate-700 bg-slate-900/60 p-3">
          <p className="text-xs text-slate-400">
            Publish this DNS record, then verify. It is a TXT record on the
            domain itself — not on a <span className="font-mono">_tunnex</span>{" "}
            subdomain.
          </p>
          <dl className="mt-2 space-y-1 text-xs">
            <div className="flex gap-2">
              <dt className="w-16 text-slate-600">NAME</dt>
              <dd className="font-mono text-slate-300">{claim.txt.name}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-16 text-slate-600">TYPE</dt>
              <dd className="font-mono text-slate-300">TXT</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-16 text-slate-600">VALUE</dt>
              <dd className="break-all font-mono text-slate-300">
                {claim.txt.value}
              </dd>
            </div>
          </dl>
          <Button
            type="button"
            className="mt-3"
            onClick={submitVerify}
            disabled={busy}
          >
            {busy ? "Checking DNS…" : "Verify domain"}
          </Button>
        </div>
      )}

      {claim.kind === "verified" && (
        <p className="mt-3 text-xs text-accent-400">
          <span className="font-mono">{claim.domain}</span> is verified. New
          signups on this domain now auto-join this organization.
        </p>
      )}

      <ErrorText>{err}</ErrorText>

      {/* The two facts the wireframe's pill chain cannot carry: the state is not readable
          back, and VERIFIED is not terminal. * /}
      <p className="mt-3 text-xs text-slate-600">{WRITE_ONLY_NOTE}</p>
      {claim.kind !== "unknown" && (
        <p className="mt-1 text-xs text-slate-600">{KEEP_RECORD_NOTE}</p>
      )}
    </Card>
  );
}

*/
function OrgSection({
  org,
  canEdit,
  onSaved,
}: {
  org: Org;
  canEdit: boolean;
  onSaved: (o: Org) => void;
}) {
  const [name, setName] = useState(org.name);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setSaved(false);
    const { data, error } = await api.PATCH("/api/v1/organizations/{orgId}", {
      params: { path: { orgId: org.id } },
      body: { name },
    });
    setBusy(false);
    if (error || !data)
      return setErr(apiErrorMessage(error, "Could not save."));
    setSaved(true);
    onSaved(data);
  }

  return (
    <form onSubmit={submit} className="mt-6">
      <Card>
        <h2 className="text-sm font-semibold text-slate-300">Organization</h2>
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <div className="min-w-[14rem] flex-1">
            <Field label="Name">
              <Input
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setSaved(false);
                }}
                required
                disabled={!canEdit}
              />
            </Field>
          </div>
          <Button
            type="submit"
            disabled={busy || !canEdit || name === org.name}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
        </div>
        {/* Slug is immutable (identity); shown read-only. */}
        <p className="mt-2 font-mono text-xs text-slate-500">
          slug: {org.slug}
        </p>
        {saved && <p className="mt-2 text-xs text-accent-400">Saved.</p>}
        <ErrorText>{err}</ErrorText>
      </Card>
    </form>
  );
}

function SsoSettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  return (
    // ⚠ A SECTION LABEL, NOT A LOOSE HEADING. This block renders TWO provider cards, so the heading names
    // the pair — but outside a card it read as text floating on the page background, which is what the
    // founder saw. Given its own muted, uppercase treatment it reads as a label for the cards beneath it.
    <div className="space-y-3">
      <h2 className="px-1 font-mono text-[10px] uppercase tracking-wide text-ink-tertiary">
        Single sign-on
      </h2>
      {PROVIDERS.map((p) => (
        <SsoProvider key={p} orgId={orgId} provider={p} canEdit={canEdit} />
      ))}
    </div>
  );
}

function SsoProvider({
  orgId,
  provider,
  canEdit,
}: {
  orgId: string;
  provider: Provider;
  canEdit: boolean;
}) {
  const [view, setView] = useState<SsoView | null>(null);
  const [configured, setConfigured] = useState(false);
  // Third arm: the read failed, so neither "configured" nor "not configured" is known.
  const [loadFailed, setLoadFailed] = useState(false);
  // Fourth arm: the plan does not include SSO. Knowable, not unknown — and not retryable.
  const [gated, setGated] = useState(false);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // load fetches the current (non-secret) config. sso_not_configured (404) is the
  // normal "no config yet" state, not an error. Guarded against setState after
  // unmount via the cancelled flag the caller passes.
  async function load(isCancelled: () => boolean) {
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/sso/{provider}",
      {
        params: { path: { orgId, provider } },
      },
    );
    if (isCancelled()) return;
    // ⛔ NOT CONFIGURED IS A STATE. A FAILED READ IS NOT.
    //
    // This branch was `if (error || !data) { setConfigured(false) }` — it collapsed BOTH into "no config
    // yet", so a transient failure rendered the CONFIGURE form on an org that HAS SSO, and an admin could
    // reconfigure from scratch against a live IdP. Ranked destructive in S14.11 and registered unfixed; this
    // screen is its home.
    //
    // The server already distinguishes them and the comment above already SAID SO twelve lines up:
    //   404 + code "sso_not_configured"  -> genuinely not set up
    //   anything else                    -> we could not read it, and we do not know
    //
    // The code was DOCUMENTED at line 541 and DISCARDED at line 553 — prose-versus-behaviour, twelve lines
    // apart, in the file that held the destructive finding.
    if (error) {
      if (apiErrorCode(error) === "sso_not_configured") {
        setConfigured(false); // a real, knowable state
        setLoadFailed(false);
        setGated(false);
        return;
      }
      // ⛔ A REFUSAL THAT NAMES ITSELF IS NOT AN UNKNOWN, AND CALLING IT ONE MISINFORMS TWICE.
      //
      // `edition_required` means the plan does not include SSO — as knowable as `sso_not_configured`, and
      // the server said so in one word. Routed into the unknown arm it rendered "the settings could not be
      // read" beside a RETRY BUTTON THAT CAN NEVER SUCCEED: the operator is told we have a problem reading
      // their config, and invited to keep asking.
      //
      // ⚠ The unknown arm is still right for everything else, and still must not offer Configure. This
      // adds a fourth state rather than widening the third — "we could not read it" and "you are not
      // entitled to it" have different remedies, and only one of them is retryable.
      if (apiErrorCode(error) === "edition_required") {
        setGated(true);
        setLoadFailed(false);
        setConfigured(false);
        return;
      }
      // ⛔ WE DO NOT KNOW. Never offer Configure here — offering it invites the destructive path.
      setLoadFailed(true);
      setGated(false);
      return;
    }
    if (!data) {
      setLoadFailed(true);
      return;
    }
    setLoadFailed(false);
    setView(data);
    setConfigured(true);
    setClientId(data.client_id);
    setEnabled(data.enabled);
    setTenantId(data.tenant_id ?? "");
  }
  useEffect(() => {
    let cancelled = false;
    void load(() => cancelled);
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, provider]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setSaved(false);
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/sso/{provider}",
      {
        params: { path: { orgId, provider } },
        body: {
          client_id: clientId,
          client_secret: clientSecret,
          tenant_id: tenantId || undefined,
          enabled,
        },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not save the SSO config."));
    setClientSecret(""); // never keep the secret in page state after save
    setSaved(true);
    await load(() => false); // refresh to pick up the new fingerprint
  }

  // Display name for the provider — also the label prefix that keeps each provider's fields uniquely named.
  const providerName = provider === "microsoft" ? "Microsoft" : "Google";

  // ⛔ THE PLAN ANSWER COMES FIRST, because it is the only one of the four that is certain and static.
  // ⚠ NO RETRY BUTTON: nothing about this changes by asking again, and a retry offered here trains an
  // operator to treat a definite answer as a flaky one.
  if (gated)
    return (
      <Card>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-white capitalize">
            {provider}
          </h3>
          <span className="text-xs text-slate-500">not in your plan</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          {providerName} SSO is a paid Tunnex capability and this deployment's
          licence does not include it. Existing sign-ins are unaffected.
        </p>
        <a
          href="#licence"
          className="mt-3 inline-block text-xs font-medium text-accent hover:underline"
        >
          Install a licence key
        </a>
      </Card>
    );

  // ⛔ THE THIRD ARM RENDERS INSTEAD OF THE FORM. Offering "Configure" over an unknown state is the
  // destructive path itself: an admin fills it in and overwrites a live IdP config that was there all along.
  // A retry is the only honest control here.
  if (loadFailed)
    return (
      <Card>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-white capitalize">
            {provider}
          </h3>
          <span className="text-xs text-warn">status unknown</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          The current {providerName} SSO settings could not be read, so this
          shows neither “configured” nor “not configured”. Refresh to try again
          — reconfiguring from here could overwrite a live setup.
        </p>
        <div className="mt-3">
          <Button variant="ghost" onClick={() => void load(() => false)}>
            Retry
          </Button>
        </div>
      </Card>
    );

  return (
    <form onSubmit={submit}>
      <Card>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-white capitalize">
            {provider}
          </h3>
          {configured && view && (
            <span className="text-xs text-slate-500">
              {view.enabled ? "enabled" : "disabled"} · updated{" "}
              {relativeAge(view.updated_at)}
            </span>
          )}
        </div>
        <div className="mt-3 space-y-3">
          {/* Labels are PROVIDER-SCOPED (S11-1 class): SsoProvider renders once per provider, so a bare
              "Client ID" would put two controls with the SAME accessible name on the Settings page — a
              screen reader announces them identically and a label-navigating user cannot tell them apart. */}
          {/* ⛔ AN OAuth CLIENT ID IS NOT A USERNAME, AND A CLIENT SECRET IS NOT A PASSWORD.
              Chrome fills the FIRST text+password pair on a page as a login form. This component
              renders once per provider and `google` comes first (PROVIDERS), so Google's pair was
              being filled with the signed-in admin's EMAIL and a SAVED PASSWORD — in
              autofill-blue, on a credential surface, one un-noticed Save away from writing them
              into a live IdP config. The Microsoft pair looked immune only because Chrome fills
              one pair per page; the markup was byte-identical, so this is ORDER, not markup, and
              fixing only the visibly-affected provider would have moved the bug rather than
              removed it. Both are annotated for that reason.
              `new-password` (not `off`) is what actually suppresses saved-password fill in
              Chrome — `off` is widely ignored on password inputs. */}
          {provider === "microsoft" && (
            <Field label={`${providerName} client ID`}>
              <Input
                name={`${provider}-oauth-client-id`}
                autoComplete="off"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                required
                disabled={!canEdit}
              />
            </Field>
          )}
          {/* WRITE-ONLY secret: the current secret is NEVER fetched or shown. We
              display only its keyed fingerprint as proof-of-storage, and the
              input is a "replace" affordance (blank = leave unchanged is not
              supported by the API, so a save requires re-entering it). */}
          {provider === "microsoft" && <Field
            label={
              configured
                ? `${providerName} client secret (enter to replace)`
                : `${providerName} client secret`
            }
          >
            <Input
              type="password"
              name={`${provider}-oauth-client-secret`}
              autoComplete="new-password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              required
              disabled={!canEdit}
              placeholder={secretPlaceholder(configured)}
            />
          </Field>}
          {configured && view?.secret_fingerprint && (
            <p className="font-mono text-xs text-slate-500">
              stored secret fingerprint: {view.secret_fingerprint}
            </p>
          )}
          {provider === "microsoft" && (
            <Field label="Tenant ID (Entra)">
              <Input
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                disabled={!canEdit}
              />
            </Field>
          )}
          {/* ⛔ THE LABEL CHANGES WITH THE ARM, because the control MEANS something different in each.
              Configured: it reflects STORED STATE. Unconfigured: nothing is stored, so it can only be
              an INTENT about the config being created — and calling that "Enabled" asserted a fact
              that did not exist. Google rendered CHECKED + "Enabled" on a provider the server answers
              404 for. */}
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              data-testid={`sso-enabled-${provider}`}
              data-reflects-server={toggleReflectsServer(configured)}
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              disabled={!canEdit}
            />
            {enabledLabel(configured)}
          </label>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <Button type="submit" disabled={busy || !canEdit}>
            {busy ? "Saving…" : configured ? "Replace config" : "Configure"}
          </Button>
          {saved && <span className="text-xs text-accent-400">Saved.</span>}
        </div>
        <ErrorText>{err}</ErrorText>
      </Card>
    </form>
  );
}
