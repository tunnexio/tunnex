import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  loadOne,
  type Meta,
  type Org,
  type Member,
  type Role,
  type SsoConfigView,
  type UserGroup,
  type ResizeConflict,
  type AgentJITAccessSetting,
} from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { OrgSwitcher } from "../components/OrgSwitcher";
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
import {
  Button,
  Card,
  ErrorText,
  Field,
  Input,
  PageHeader,
  SettingDialogRow,
  SettingGroup,
  SettingRow,
  SettingValue,
  Switch,
} from "../components/ui";
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
    setOrg(null);
    setMyRole(undefined);
    setError(null);
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
  }, [myId, currentOrg, orgFailed, orgLoading]);

  const isAdmin = can(myRole, "org:update");
  // ⛔ A TAB WHOSE PANEL WOULD BE EMPTY IS NOT RENDERED. "CUT MEANS ABSENT, NOT HIDDEN" (S14.4): a member who
  // clicks Network and gets a blank card learns only that the product is broken. The gate that decides the
  // panel decides the tab, from one expression, so the two cannot drift.
  const shown = useMemo(
    () =>
      RAIL.filter(
        (r) => (!r.adminOnly || isAdmin) && (!r.needsOrg || org !== null),
      ),
    [isAdmin, org],
  );
  const [section, setSection] = useState<string>(RAIL[0].id);
  // ⚠ FALL BACK WHEN THE SELECTION STOPS EXISTING. Switching to an org where you are a plain member must not
  // leave a tab selected that is no longer in the rail — the panel would vanish and nothing would be active.
  const active = shown.some((r) => r.id === section)
    ? section
    : (shown[0]?.id ?? "");
  const canMachines = can(myRole, "machine:manage"); // owner-only — the GitOps operator credential panel

  if (currentOrg && org?.id !== currentOrg.id) {
    return <p className="text-sm text-slate-400">Loading settings…</p>;
  }

  return (
    // ⛔ NO CAP, AND THAT IS THE FIX RATHER THAN A SMALLER ONE. `max-w-[110rem]` was here to stop fields
    // stretching on a 32" display, but 1760px is wider than the content box ever gets, so it capped nothing
    // and instead OVERFLOWED — 1760 + 48px padding + the 228px sidebar is 2036px of demand against a
    // ~1999px viewport, and `mx-auto` cannot centre what does not fit, so the right edge was shaved off.
    //
    // ⚠ THE WORRY IT ENCODED WAS A ONE-COLUMN WORRY. The rail track is fixed and the content track takes
    // what is left, so a wide screen buys a wider VALUE column, not a 2000px input — and AppShell's stated
    // law is that page bodies fill available width (its own comment records what capping one cost before).
    <div>
      <PageHeader
        title="Settings"
        subtitle="Manage your organization, security, and integrations."
      />
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
      {/* ⛔ ONE COLUMN OF SECTIONS, AND THE PACKING PROBLEM IS GONE RATHER THAN SOLVED.
          Three layouts were tried here in turn — fixed `grid-cols-3` (every card stretched to a third of
          the screen), an auto-fill grid (a grid ALIGNS ROWS, so every short card was followed by a hole the
          height of its tallest neighbour), then multi-column masonry (no holes, but column-major reading
          order, and NO full-width child possible — the credentials table had to be lifted out of the flow
          entirely).

          All three accept the same premise: that these are cards of varying height which must be packed.
          They are ROWS AND GROUPS of settings. Stacked in one column there is nothing to pack, no holes to
          avoid, no `break-inside-avoid` to remember, and a table can simply sit in the flow. The masonry was
          not a bad answer — it was a good answer to a question the page should never have been asking.

          ⚠ The reading order is now the one the sections are written in, so that order is a decision:
          Organization → Network → Authentication → Features → Licence, roughly what an operator sets up
          first to what they revisit least. */}
      {/* ⛔ THE RAIL IS A SECOND TRACK, NOT A SIDEBAR. `minmax(0,…)` on BOTH columns because a grid item
          defaults to `min-width:auto` — a long CIDR or credential name in the right track would otherwise
          push it wider than its share, which is the class of bug that shaved this page's right edge off
          before. Below `lg` the rail is dropped rather than stacked: six labels above the content is six
          rows of chrome before the thing you came for. */}
      <div className="mt-6 grid gap-6 lg:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
        <SettingsRail
          sections={shown}
          active={active}
          onSelect={setSection}
        />
        <div className="flex min-w-0 flex-col gap-3.5">
        {org && isAdmin && active === "organization" && (
          <SettingGroup id="organization" title="Organization"
            tabpanel>
            <OrgSection
              org={org}
              canEdit={emailVerified}
              onSaved={(o) => setOrg(o)}
            />
            <SettingRow
              label="Switch organization & add tenant"
              description="Switch between active organizations or add a new organization."
            >
              <OrgSwitcher />
            </SettingRow>
          </SettingGroup>
        )}

        {org && isAdmin && active === "network" && (
          <SettingGroup id="network" title="Network"
            tabpanel>
            <PoolSection
              org={org}
              canEdit={emailVerified}
              onResized={(o) => setOrg(o)}
            />
          </SettingGroup>
        )}

        {/* ⚠ MIXED GATES, DELIBERATELY IN ONE SECTION. Personal 2FA is per-USER and shows for everyone;
            SSO and enforcement are org-admin; directory sync answers to `idpGate`, its own permission,
            NOT to `org:update` — see the note below. Grouping by SUBJECT is what a reader is looking for;
            each child keeps whatever gate it already had. */}
        {active === "authentication" && (
        <SettingGroup id="authentication" title="Authentication"
            tabpanel>
          {/* ⚠ DIRECT CHILDREN, NOT A WRAPPER. Section draws hairlines BETWEEN its children with
              `divide-y`; a wrapping div collapses all of them into one child and every divider vanishes,
              which is what made these rows float with no separation. */}
          <MfaSettings />

            {org && isAdmin && meta?.edition === "enterprise" && (
              <SsoSettings orgId={org.id} canEdit={emailVerified} />
            )}
            {org && isAdmin && meta?.edition !== "enterprise" && (
              <Card>
                <h3 className="text-sm font-semibold text-slate-300">
                  Single sign-on
                </h3>
                <p className="mt-1 text-xs text-slate-500">
                  SSO (Google / Microsoft) is a Tunnex Enterprise feature.
                </p>
              </Card>
            )}

            {org && isAdmin && meta?.edition === "enterprise" && (
              <OrgMfaEnforce orgId={org.id} canEdit={emailVerified} />
            )}
            {org && isAdmin && meta?.edition !== "enterprise" && (
              <Card>
                <h3 className="text-sm font-semibold text-slate-300">
                  Require two-factor authentication
                </h3>
                <p className="mt-1 text-xs text-slate-500">
                  Org-wide MFA enforcement is a Tunnex Enterprise feature.
                </p>
              </Card>
            )}

            {/* Directory sync renders OUTSIDE the `isAdmin` gate, on purpose but NOT because of a
              live defect — the honest version, after a mutation survivor sent me to measure.
              Settings gates its org panels on `org:update`; every idp-sync handler gates on
              `policy:manage`. Today those are held by the same user-assignable roles (owner, admin),
              so nesting would change nothing observable. `operator` holds policy:manage WITHOUT
              org:update but is MACHINE-ONLY — `memberships` CHECKs role IN (owner, admin, member),
              so it never renders a UI and cannot make the difference visible.
              It is out here so the panel is governed by ONE gate — its own, matching the server —
              rather than silently ANDed with a different permission that merely happens to coincide.
              `idpGate` is the authority; a test pins the coincidence so a divergence is loud. */}
        </SettingGroup>
        )}

        {org && active === "directory" && (
          <SettingGroup id="directory" title="Directory sync"
            tabpanel>
            {PROVIDERS.map((pv) => (
              <IdpSyncSection
                key={pv}
                orgId={org.id}
                provider={pv}
                role={myRole}
                isEnterprise={meta?.edition === "enterprise"}
                canEdit={emailVerified}
              />
            ))}
          </SettingGroup>
        )}

        {org && isAdmin && active === "features" && (
          <SettingGroup id="features" title="Features"
            tabpanel>
            <div className="flex flex-col gap-3.5">
              {/* OpenVPN is OPEN (every edition) but OFF by default — unlock-then-opt-in (D-S9.5-OPTIN). */}
              <OrgOVPNToggle
                org={org}
                canEdit={emailVerified}
                onSaved={(o) => setOrg(o)}
              />
              {meta?.edition === "enterprise" && (
                <AgentPolicyTemplatesToggle
                  org={org}
                  canEdit={emailVerified}
                  onSaved={(o) => setOrg(o)}
                />
              )}
              {meta?.edition === "enterprise" && (
                <AgentJITAccessToggle
                  key={org.id}
                  orgId={org.id}
                  canEdit={emailVerified}
                />
              )}
            </div>
          </SettingGroup>
        )}

        {/* ⚠ Owner-only to INSTALL; every member sees the entitlement, because a user who hits a ceiling
            needs to know why without asking an owner. */}
        {org && active === "licence" && (
          <SettingGroup id="licence" title="Licence &amp; plan"
            tabpanel>
            <LicenceCard canManage={myRole === "owner"} />
            {isAdmin && canMachines && (
              <MachineCredentials orgId={org.id} canManage={canMachines} />
            )}
          </SettingGroup>
        )}

        {org && !isAdmin && (
          <Card>
            <p className="text-sm text-slate-400">
              Organization settings are managed by owners and admins.
            </p>
          </Card>
        )}

        {/* ⛔ THE CAPABILITY EXISTED AND NOTHING COULD REACH IT. `DELETE /organizations/{id}` has shipped
            since S1 with `org:delete` on it and NO CALL SITE anywhere in the web — one of the 12 genuinely
            unreachable mutating operations the S14.12 census counted. An owner could not delete an
            organization they created by mistake without curl.
            ⚠ ITS OWN GROUP, AND LAST: a destructive verb does not belong beside the name field, where a
            mis-click lands among routine edits. */}
        {org && active === "danger" && (
          <SettingGroup id="danger" title="Danger zone"
            tabpanel>
            <DangerZone
              org={org}
              canDelete={can(myRole, "org:delete")}
              role={myRole}
            />
          </SettingGroup>
        )}
        </div>
      </div>
    </div>
  );
}

function AgentPolicyTemplatesToggle({
  org,
  canEdit,
  onSaved,
}: {
  org: Org;
  canEdit: boolean;
  onSaved: (org: Org) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const enabled = org.agent_policy_templates_enabled;

  async function toggle() {
    setBusy(true);
    setErr(null);
    const next = !enabled;
    const result = await api.PUT(
      "/api/v1/organizations/{orgId}/agent-policy-template-settings",
      { params: { path: { orgId: org.id } }, body: { enabled: next } },
    );
    if (result.error) {
      setBusy(false);
      return setErr(
        apiErrorMessage(
          result.error,
          next
            ? "Could not enable agent policy templates."
            : "Could not disable agent policy templates.",
        ),
      );
    }
    const refetch = await api.GET("/api/v1/organizations/{orgId}", {
      params: { path: { orgId: org.id } },
    });
    setBusy(false);
    if (refetch.error || !refetch.data) {
      return setErr("The setting was saved, but the organization could not be refreshed.");
    }
    onSaved(refetch.data);
  }

  return (
    // data-testid stays ON THE ROW: it is the settings seam the F09 tests address, and moving it to the
    // switch would quietly narrow what those tests can reach.
    <SettingRow
      label="Agent groups & policy templates"
      description="Reusable agent-group policy authoring. Creates no access until a template is applied."
      data-testid="agent-policy-template-settings"
      error={err}
    >
      <Switch checked={enabled} disabled={!canEdit || busy} onChange={toggle} />
    </SettingRow>
  );
}

function AgentJITAccessToggle({
  orgId,
  canEdit,
}: {
  orgId: string;
  canEdit: boolean;
}) {
  const [setting, setSetting] = useState<AgentJITAccessSetting | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setLoadError(null);
    const result = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/agent-jit-access-settings", {
        params: { path: { orgId } },
      }),
    );
    if (!result.ok) return setLoadError(result.error);
    setSetting(result.data);
  }

  useEffect(() => {
    void load();
    // orgId keys this component; a new tenant never inherits the prior setting.
  }, [orgId]);

  async function toggle() {
    if (!setting) return;
    setBusy(true);
    setErr(null);
    const response = await api.PUT(
      "/api/v1/organizations/{orgId}/agent-jit-access-settings",
      {
        params: { path: { orgId } },
        body: { enabled: !setting.enabled },
      },
    );
    if (response.error) {
      setBusy(false);
      return setErr(
        apiErrorMessage(response.error, "Could not update JIT agent access."),
      );
    }
    await load();
    setBusy(false);
  }

  return (
    <SettingRow
      label="Just-in-time agent access"
      description="Requests need human approval and create one expiring access rule."
      data-testid="agent-jit-access-settings"
    >
      {/* ⚠ THREE STATES, NOT TWO. A failed load must NOT render a switch: an off-looking switch would be a
          confident claim about a setting we could not read. Retry, loading and the control stay distinct. */}
      {loadError ? (
        <div className="flex flex-col items-end gap-1">
          <ErrorText>{loadError}</ErrorText>
          <Button onClick={() => void load()}>Retry</Button>
        </div>
      ) : setting ? (
        <div className="flex flex-col items-end gap-1">
          <Switch
            label="Just-in-time agent access"
            checked={setting.enabled}
            disabled={!canEdit || busy}
            onChange={toggle}
          />
          <p className="text-xs text-slate-500">
            {setting.pending_requests} pending · {setting.approved_requests}{" "}
            approved
          </p>
          <ErrorText>{err}</ErrorText>
        </div>
      ) : (
        <p className="text-xs text-slate-500">Loading…</p>
      )}
    </SettingRow>
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

  async function submit(e?: React.FormEvent) {
    e?.preventDefault();
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
    // ⛔ THE CONFIRMATION MOVES INTO A DIALOG, AND THE FRICTION IS UNCHANGED. The slug still has to be
    // typed; it is simply not sitting permanently open on a settings page, where a stray Enter in a
    // focused field is one keystroke from deleting a tenant.
    <SettingDialogRow
      label="Delete this organization"
      description="This cannot be undone. Members lose access immediately; the organization stops appearing in the switcher."
      actionLabel="Delete organization…"
      dialogTitle={`Delete ${org.slug}`}
      error={err}
      actions={(close) => (
        <>
          <Button
            variant="ghost"
            onClick={() => {
              setConfirm("");
              setErr(null);
              close();
            }}
          >
            Cancel
          </Button>
          {/* No `close` on success: the handler navigates away from the org entirely. */}
          <Button
            variant="danger"
            disabled={busy || blocked || confirm !== org.slug}
            onClick={() => void submit()}
          >
            {busy ? "Deleting…" : "Delete organization"}
          </Button>
        </>
      )}
    >
      {() => (
        <div className="flex flex-col gap-3">
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
        </div>
      )}
    </SettingDialogRow>
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
    <SettingRow
      label="Require two-factor authentication"
      description="Password sign-ins must have 2FA. Applies at sign-in — open sessions stay valid until they expire."
      error={error}
    >
      {/* ⚠ `null` is NOT "off" — it is "not read yet". Rendering an off switch for an unknown value would
          state, in the one place an admin checks, that enforcement is disabled when it may well be on. */}
      {enforce === null ? (
        <p className="text-xs text-slate-500">Loading…</p>
      ) : (
        <Switch
          label="Require two-factor authentication"
          checked={enforce}
          disabled={busy || !canEdit}
          onChange={(next) => toggle(next)}
        />
      )}
    </SettingRow>
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
    // ⛔ A ROW WITH A SWITCH, NOT A CARD WITH A BUTTON. The state is what the operator cares about, and a
    // button labelled "Enable OpenVPN" makes them read the LABEL to infer the STATE — the button says what
    // will happen next, never what is true now. The switch shows the state and changes it in one control.
    <SettingRow
      label="OpenVPN"
      description="Export devices as .ovpn profiles for official OpenVPN clients. WireGuard is unaffected; turning it off does not revoke issued profiles."
      error={error}
    >
      <Switch
        checked={enabled}
        disabled={busy || !canEdit}
        onChange={(next) => toggle(next)}
      />
    </SettingRow>
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

  // ⛔ THE POOL DIALOG DOES NOT CLOSE ON SAVE, AND THAT IS THE EXCEPTION THAT PROVES THE RULE.
  // A successful resize returns a consequence the operator MUST read — existing devices keep their old
  // addresses and their configs are one-time, so reaching the new range means re-issuing them. Closing on
  // success would dismiss the only place that is ever said. A shrink refusal likewise returns the device
  // list that blocks it. The dialog stays open and Cancel becomes Close.
  async function submit(e?: FormEvent) {
    e?.preventDefault();
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
    <SettingDialogRow
      label="Address pool"
      description="The WireGuard address range assigned to devices."
      value={
        <SettingValue>
          <span className="font-mono">{org.pool_cidr}</span>
        </SettingValue>
      }
      actionLabel="Resize"
      dialogTitle="Resize address pool"
      disabled={!canEdit}
      error={err}
      actions={(close) => (
        <>
          <Button
            variant="ghost"
            onClick={() => {
              setCidr(org.pool_cidr ?? "");
              setConflict(null);
              setDone(false);
              setErr(null);
              close();
            }}
          >
            {done ? "Close" : "Cancel"}
          </Button>
          <Button
            disabled={busy || !canEdit || cidr === org.pool_cidr}
            onClick={() => void submit()}
          >
            {busy ? "Resizing…" : "Resize pool"}
          </Button>
        </>
      )}
    >
      {() => (
        <div className="flex flex-col gap-3">
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
        </div>
      )}
    </SettingDialogRow>
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
    // ⛔ A ROW THAT OPENS A CONSOLE, NOT ONE THAT OPENS A FORM. Directory sync is health + sync-now +
    // credential replacement + group mapping — several independent transactions, not one value with a
    // Save. So the dialog's only action is Close; every control inside keeps its own confirmation, and
    // nothing pretends the panel is a single form that can be "saved".
    <SettingDialogRow
      label={providerLabel(provider)}
      description={`Sync groups for access using ${providerLabel(provider)}.`}
      value={
        copy ? (
          // ⚠ THE TESTID STAYS PUT. `idp-tier-<provider>` is the seam S14.14's tests read to prove the three
          // health tiers are distinguishable; a pill became plain text, and the seam is unchanged.
          <span data-testid={`idp-tier-${provider}`}>
            <SettingValue
              tone={
                tier === "ok" ? "live" : tier === "degraded" ? "warn" : "danger"
              }
            >
              {copy.label}
            </SettingValue>
          </span>
        ) : (
          <SettingValue>Not configured</SettingValue>
        )
      }
      actionLabel={state.kind === "configured" ? "Manage" : "Configure"}
      dialogTitle={`Directory sync — ${providerLabel(provider)}`}
      error={err}
      actions={(close) => (
        <Button variant="ghost" onClick={close}>
          Close
        </Button>
      )}
    >
      {() => (
        <div className="space-y-3">

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
        </div>
      )}
    </SettingDialogRow>
  );
}

function providerLabel(p: string): string {
  return p === "microsoft" ? "Microsoft Entra" : "Google Workspace";
}

/**
 * The section rail — one section at a time.
 *
 * ⛔ SELECTING A SECTION SHOWS ONLY THAT SECTION (founder-directed). The whole page rendered at once was
 * seven cards deep and every visit scrolled past six groups to reach one; this makes the rail the navigation
 * it already looked like.
 *
 * ⚠ THE ACTIVE STATE IS REAL STATE, WHICH IS WHY IT EXISTS AT ALL. The previous version deliberately had NO
 * highlight, because indicating "which section am I looking at" from scroll position needs a layout jsdom
 * cannot render (docs/laws.md: a responsive assertion there asserts nothing). Selection is a value, so the
 * indicator is now checkable — the design's highlight arrives on the mechanism that earns it.
 *
 * A vertical `tablist`, matching the tab pattern already in Access.tsx.
 */
const RAIL: ReadonlyArray<{
  id: string;
  label: string;
  hint: string;
  /** Needs `org:update`; the panel and the tab read this same flag. */
  adminOnly?: boolean;
  /**
   * Panel renders only with a loaded org.
   *
   * ⛔ THIS FIELD IS A BUG FIX. The rail filtered on `adminOnly` alone while six of the seven panels are
   * ALSO `org &&` gated, so before an org resolved, Directory sync / Licence / Danger zone rendered a tab
   * that opened NOTHING — three dead tabs, found by the test written to assert every tab leads somewhere.
   * Both gates now live on the entry, which is the only way the rail and the panel cannot drift.
   */
  needsOrg?: boolean;
  danger?: boolean;
}> = [
  {
    id: "organization",
    needsOrg: true,
    label: "Organization",
    hint: "Manage your organization information and preferences.",
    adminOnly: true,
  },
  {
    id: "network",
    needsOrg: true,
    label: "Network",
    hint: "Configure network settings and address pools.",
    adminOnly: true,
  },
  {
    id: "authentication",
    label: "Authentication",
    hint: "Manage how members sign in and access your resources.",
  },
  {
    id: "directory",
    needsOrg: true,
    label: "Directory sync",
    hint: "Sync users and groups from your identity provider.",
  },
  {
    id: "features",
    needsOrg: true,
    label: "Features",
    hint: "Enable and configure advanced capabilities.",
    adminOnly: true,
  },
  {
    id: "licence",
    needsOrg: true,
    label: "Licence & plan",
    hint: "Manage your licence and subscription.",
  },
  {
    id: "danger",
    needsOrg: true,
    label: "Danger zone",
    hint: "Irreversible and destructive actions for your organization.",
    danger: true,
  },
];

function SettingsRail({
  sections,
  active,
  onSelect,
}: {
  /** Only the sections this role can actually reach — an empty panel is worse than an absent tab. */
  sections: ReadonlyArray<(typeof RAIL)[number]>;
  active: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div
      role="tablist"
      aria-orientation="vertical"
      aria-label="Settings sections"
      className="flex gap-2 overflow-x-auto lg:sticky lg:top-6 lg:flex-col lg:gap-4 lg:overflow-visible"
    >
      {sections.map((s) => {
        const on = s.id === active;
        return (
          <button
            key={s.id}
            type="button"
            role="tab"
            id={`${s.id}-tab`}
            /* ⛔ THE HINT IS VISUAL ONLY. Without this the accessible name concatenated both, so the tab
               announced as "NetworkAddress space devices draw from." — a label a screen-reader user has to
               listen through, and one no test could address by the name a person would call it. */
            aria-label={s.label}
            aria-selected={on}
            aria-controls={s.id}
            onClick={() => onSelect(s.id)}
            /* The left rule is the design's active marker. `border-l-2` is always present and merely
               transparent when inactive, so selecting a tab never shifts the text by two pixels. */
            className={`group shrink-0 border-l-2 pl-3.5 text-left transition-colors duration-fast focus:outline-none ${
              on ? "border-[#B03A45]" : "border-transparent hover:border-white/20"
            }`}
          >
            <span
              className={`block font-mono text-xs font-semibold uppercase tracking-[0.14em] transition-colors ${
                s.danger
                  ? on
                    ? "text-rose-400 font-bold"
                    : "text-rose-500/80 hover:text-rose-400"
                  : on
                    ? "text-white font-bold"
                    : "text-slate-400 group-hover:text-slate-200"
              }`}
            >
              {s.label}
            </span>
            {/* The hint is for choosing between sections, so it is only worth space in the vertical rail. */}
            <span
              className={`mt-1 hidden text-xs leading-relaxed transition-colors lg:block ${
                on
                  ? "text-slate-300 font-normal"
                  : "text-slate-500 group-hover:text-slate-400 font-normal"
              }`}
            >
              {s.hint}
            </span>
          </button>
        );
      })}
    </div>
  );
}

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
  const [err, setErr] = useState<string | null>(null);

  // ⛔ THE DIALOG CLOSES ONLY ON SUCCESS. Closing on click would hide the error the operator needs to read,
  // and leave them believing a rename landed that did not. `onDone` is called after the save is confirmed.
  async function submit(e: FormEvent | undefined, onDone?: () => void) {
    e?.preventDefault();
    setBusy(true);
    setErr(null);
    const { data, error } = await api.PATCH("/api/v1/organizations/{orgId}", {
      params: { path: { orgId: org.id } },
      body: { name },
    });
    setBusy(false);
    if (error || !data)
      return setErr(apiErrorMessage(error, "Could not save."));
    onSaved(data);
    onDone?.();
  }

  return (
    <SettingDialogRow
      label="Organization name"
      description="Displayed in the app and in invitations."
      value={<SettingValue>{org.name}</SettingValue>}
      actionLabel="Edit"
      dialogTitle="Rename organization"
      disabled={!canEdit}
      error={err}
      actions={(close) => (
        <>
          <Button
            variant="ghost"
            onClick={() => {
              setName(org.name);
              setErr(null);
              close();
            }}
          >
            Cancel
          </Button>
          <Button
            disabled={busy || !canEdit || name === org.name}
            onClick={() => void submit(undefined, close)}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
        </>
      )}
    >
      {() => (
        <div className="flex flex-col gap-3">
          <Field label="Name">
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              disabled={!canEdit}
            />
          </Field>
          {/* Slug is immutable (identity); shown read-only. */}
          <p className="font-mono text-xs text-slate-500">slug: {org.slug}</p>
          <ErrorText>{err}</ErrorText>
        </div>
      )}
    </SettingDialogRow>
  );
}

function SsoSettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  // ⚠ THE "SINGLE SIGN-ON" SUB-LABEL IS GONE, AND ITS REASON WENT WITH IT. It existed because this block
  // rendered two CARDS floating on the page background with nothing naming the pair. They are rows inside a
  // named Authentication section now, so the label was a third heading level naming nothing — and each row
  // already says which provider it is.
  return (
    <>
      {PROVIDERS.map((p) => (
        <SsoProvider key={p} orgId={orgId} provider={p} canEdit={canEdit} />
      ))}
    </>
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

  async function submit(e?: FormEvent, onDone?: () => void) {
    e?.preventDefault();
    setBusy(true);
    setErr(null);
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
    await load(() => false); // refresh to pick up the new fingerprint
    onDone?.();
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
    <SettingDialogRow
      label={providerName}
      description={
        provider === "microsoft"
          ? "Client ID, secret and Entra tenant for Microsoft sign-in."
          : "Google Workspace sign-in for this organization."
      }
      value={
        configured && view ? (
          <SettingValue tone={view.enabled ? "live" : "muted"}>
            {view.enabled ? "Enabled" : "Disabled"} ·{" "}
            {relativeAge(view.updated_at)}
          </SettingValue>
        ) : (
          <SettingValue>Not configured</SettingValue>
        )
      }
      actionLabel={configured ? "Replace config" : "Configure"}
      dialogTitle={`${providerName} single sign-on`}
      /* ⚠ A STABLE SEAM, BECAUSE THIS ROW EXISTS TWICE BY CONSTRUCTION. The e2e spec used to reach Google's
         config by "the first Client ID field", relying on PROVIDERS order — which silently becomes the wrong
         row the moment both providers are configured and both offer the same action label. */
      data-testid={`sso-row-${provider}`}
      disabled={!canEdit}
      error={err}
      actions={(close) => (
        <>
          <Button variant="ghost" onClick={close}>
            Cancel
          </Button>
          {/* ⛔ CLOSES ONLY AFTER THE SAVE IS CONFIRMED. The secret is write-only — it is cleared from page
              state on success and can never be re-read — so a dialog that closed optimistically and then
              failed would leave the operator with nothing to retype and no error to explain why. */}
          <Button
            disabled={busy || !canEdit}
            onClick={() => void submit(undefined, close)}
          >
            {busy ? "Saving…" : configured ? "Replace config" : "Configure"}
          </Button>
        </>
      )}
    >
      {() => (
        <div className="space-y-3">
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
      )}
    </SettingDialogRow>
  );
}
