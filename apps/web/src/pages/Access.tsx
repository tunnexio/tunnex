import { useCallback, useEffect, useState } from "react";
import { useOrg } from "../lib/useOrg";
import {
  api,
  type GroupMember,
  apiErrorMessage,
  apiErrorCode,
  loadOne,
  type Loaded,
  type Meta,
  type Org,
  type Member,
  type Role,
  type UserGroup,
  type Resource,
  type Site,
  type K8sService,
  type PolicyRule,
  type ZeroTrustMode,
  type AffectedDevice,
  type DeviceApproval,
  type Device,
  type HealthCheck,
  type CreatePolicyRuleRequest,
} from "../lib/api";
import { useAuth } from "../lib/auth";
import { portLabel } from "../lib/k8sview";
import {
  Button,
  Card,
  ErrorText,
  Field,
  Input,
  Modal,
  Select,
  DataTable,
} from "../components/ui";
import { relativeAge } from "../lib/format";
import { EntityPicker } from "../components/EntityPicker";
import { ComposeGate } from "../components/ComposeGate";
import { LoadRetry } from "../components/LoadRetry";
import {
  accessView,
  modeEnableConfirm,
  policyGate,
  roleFromMembers,
  ruleRow,
  disableConfirmText,
  sectionRender,
  staleNoticeText,
  pruneStaleRuleIds,
  swapRule,
  grantExpiry,
  rulesSummary,
  rulesEmptyState,
  rulesEmptyCopy,
  flowGraphState,
  flowGraphNote,
  flowLayout,
  cascadeConfirmCopy,
  cascadeConfirmSatisfied,
  srcGroupEmptyWarn,
  srcGroupEmptyBadge,
  srcGroupEmptyExplain,
  flowGlyph,
  flowTag,
  type FlowKind,
  ruleBody,
  defaultSrcKind,
  defaultDstKind,
  extendErrorCopy,
  resPortsValid,
  activeMembers,
  canEditRuleInModal,
  grantControls,
  managedGrantWarning,
  type LoadState,
  sourceOptions,
  destinationOptions,
  ruleEffectSummary,
  ruleEffectCaution,
} from "../lib/policyview";
import {
  DIRECTORY_MANAGED_BADGE,
  DIRECTORY_MANAGED_NOTE,
  isDirectoryManaged,
} from "../lib/idpsyncview";
import { ManagedBadge } from "../components/ManagedBadge";
import {
  POSTURE_HONESTY_LINE,
  buildOsVersionParam,
  checkModeOf,
  osVersionCoverage,
  osVersionMins,
  wouldFailCopy,
  type CheckMode,
} from "../lib/postureview";
// swapRule + swapPartialMessage power the create-then-delete rule edit (D-a5) in RuleFormModal.
// Every GET here goes through loadOne — a raw api.GET whose emptiness is user-meaningful is
// review-refused (S7.4a review): a fetch failure must render a legible retry, never a
// reassuring empty state. (LoadRetry — the shared legible-retry affordance — lives in components/LoadRetry.)

export default function Access() {
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [meta, setMeta] = useState<Meta | null>(null);
  const [org, setOrg] = useState<Org | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  // Page-level gating inputs, kept DISTINCT so no signal blanks another (fold-2):
  // - loadError: meta/org fetch failed (can't determine edition) → retry, nothing renderable.
  // - fatal: terminal, non-retryable (no org).
  // - roleError / roleResolved: the members fetch — its failure affects ONLY the enterprise
  //   admin path ([75]); role in-flight must render "loading", never the gate notice ([101]).
  const [loadError, setLoadError] = useState<string | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [roleError, setRoleError] = useState<string | null>(null);
  // S8.5 stale-button fix (one-truth at the React tier): RulesSection and GroupsResourcesSection each hold
  // their OWN copy of the groups list (a cohesive batched load in RulesSection, so lifting just groups would
  // fracture it). subjectsRev is the parent-owned invalidation signal — GroupsResourcesSection bumps it on a
  // group/resource mutation, RulesSection re-loads on the bump — so its subject copies (and the "Add rule"
  // enabled state derived from them) can never go stale behind a group add. Invalidate the copy, not the
  // symptom (patching the disabled expression would leave the stale copy feeding the rule modal too).
  const [subjectsRev, setSubjectsRev] = useState(0);
  const [roleResolved, setRoleResolved] = useState(false);

  const reload = useCallback(async () => {
    setLoadError(null);
    setFatal(null);
    setRoleError(null);
    setRoleResolved(false);
    const mRes = await loadOne(() => api.GET("/api/v1/meta"));
    if (!mRes.ok) return setLoadError(mRes.error); // [67]: surface loadOne's (human) message
    setMeta(mRes.data as Meta);
    // ⛔ THE ORG COMES FROM THE SEAM, NOT FROM INDEX ZERO (S12.5).
    // ⛔ LOADING IS NOT ABSENCE (S12.5). See the note in Dashboard.tsx — three states, not two: still
    // loading (say nothing), the read failed (say THAT), genuinely no membership (say that).
    if (orgLoading) return;
    const first = currentOrg;
    if (!first)
      return setFatal(
        orgFailed
          ? "Could not load your organizations."
          : "You are not a member of any organization yet.",
      );
    setOrg(first);
    const memRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Member[]>;
    const resolved = roleFromMembers(memRes, myId);
    if (resolved.failed)
      return setRoleError(
        memRes.ok ? "Couldn't determine your role." : memRes.error,
      );
    setMyRole(resolved.role);
    setRoleResolved(true);
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, myId]);
  useEffect(() => {
    reload();
  }, [reload]);

  const gate = policyGate({
    role: myRole,
    emailVerified,
    edition: meta?.edition,
  });
  const view = accessView({
    fatal: fatal != null,
    loadError: loadError != null,
    editionReady: meta != null && org != null,
    isEnterprise: gate.isEnterprise,
    roleError: roleError != null,
    roleResolved,
    canView: gate.canView,
    role: myRole,
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: "14px" }}>
        <div>
          <div style={{ font: "700 22px 'Instrument Sans'", color: "#F5F5F5" }}>
            Access policies
          </div>
          <div style={{ font: "400 12px 'Instrument Sans'", color: "#6E6E6B" }}>
            {org ? org.name : "…"} ·{" "}
            <span style={{ color: "#858582" }}>control plane</span>{" "}
            <span style={{ color: "#A9A9A6" }}>● healthy</span>
          </div>
        </div>
        <div style={{ flex: 1 }}></div>
      </div>

      {view === "fatal" && <ErrorText>{fatal}</ErrorText>}
      {view === "load_retry" && (
        <LoadRetry error={loadError ?? "Couldn't load."} onRetry={reload} />
      )}
      {view === "role_retry" && (
        <LoadRetry
          error={roleError ?? "Couldn't determine your role."}
          onRetry={reload}
        />
      )}
      {(view === "loading" || view === "role_loading") && (
        <p className="mt-6 text-sm text-slate-500">Loading…</p>
      )}

      {view === "upsell" && (
        <Card className="mt-6">
          <h2 className="text-sm font-semibold text-slate-300">
            Zero Trust access
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Policy rules, device approval, and default-deny enforcement are a
            Tunnex Enterprise feature.
          </p>
        </Card>
      )}

      {view === "member_gate" && (
        <Card className="mt-6">
          <p className="text-sm text-slate-400">
            Access policies are managed by owners and admins.
          </p>
        </Card>
      )}

      {view === "admin_body" && org && (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <ModeSection orgId={org.id} canManage={gate.canManagePolicy} />
          <RulesSection
            orgId={org.id}
            canManage={gate.canManagePolicy}
            subjectsRev={subjectsRev}
          />
          <GroupsResourcesSection
            orgId={org.id}
            canManage={gate.canManagePolicy}
            onSubjectsChanged={() => setSubjectsRev((v) => v + 1)}
          />
          <DeviceApprovalSection
            orgId={org.id}
            canManage={gate.canManageDevices}
          />
          <PostureChecksSection
            orgId={org.id}
            canManage={gate.canManageDeviceHealth}
          />
        </div>
      )}
    </div>
  );
}

// ── Zero Trust mode ─────────────────────────────────────────────────────────────────
function ModeSection({
  orgId,
  canManage,
}: {
  orgId: string;
  canManage: boolean;
}) {
  const [mode, setMode] = useState<"off" | "enforcing" | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [confirmCount, setConfirmCount] = useState(0);
  const [busy, setBusy] = useState(false);
  const [affected, setAffected] = useState<AffectedDevice[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    const r = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", {
        params: { path: { orgId } },
      }),
    );
    if (!r.ok) {
      setLoadError(r.error); // never hide the toggle on a failure ([5]) — show retry
      return;
    }
    setLoadError(null);
    setMode((r.data as ZeroTrustMode).mode);
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  // [1]+[7]: fetch the rule count FRESH at Enable-click — never a stale/defaulted-0 count that
  // would show the false zero-rules danger gate. A failed count fetch aborts LEGIBLY.
  async function openEnableConfirm() {
    setErr(null);
    const r = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/policies", {
        params: { path: { orgId } },
      }),
    );
    if (!r.ok) return setErr("Couldn't verify the current rule count. retry.");
    setConfirmCount((r.data as PolicyRule[]).length);
    setConfirming(true);
  }

  async function setModeTo(next: "off" | "enforcing") {
    setBusy(true);
    setErr(null);
    setAffected(null);
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/zero-trust-mode",
      {
        params: { path: { orgId } },
        body: { mode: next },
      },
    );
    setBusy(false);
    setConfirming(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not change the mode."));
    const zt = data as ZeroTrustMode | undefined;
    if (zt) {
      setMode(zt.mode);
      if (zt.affected_full_tunnel_devices?.length)
        setAffected(zt.affected_full_tunnel_devices);
    }
  }

  const confirm = modeEnableConfirm(confirmCount);

  return (
    <Card className="mt-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-300">
            Zero Trust mode
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            {mode === "enforcing"
              ? "Enforcing. default-deny; only your allow rules pass."
              : mode === "off"
                ? "Off. legacy full-mesh (all devices reach all devices)."
                : loadError
                  ? "n/a"
                  : "…"}
          </p>
        </div>
        {canManage && mode != null && !loadError && (
          <Button
            variant={mode === "enforcing" ? "ghost" : "primary"}
            disabled={busy}
            onClick={() =>
              mode === "enforcing" ? setModeTo("off") : openEnableConfirm()
            }
          >
            {mode === "enforcing" ? "Disable" : "Enable enforcing"}
          </Button>
        )}
      </div>
      {loadError && <LoadRetry error={loadError} onRetry={load} />}
      <ErrorText>{err}</ErrorText>

      {affected && (
        <div className="mt-3 rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-amber-300">
          Now enforcing. {affected.length} full-tunnel device(s) lost internet
          egress until a rule allows it:
          <span className="text-amber-200">
            {" "}
            {affected.map((d) => d.name).join(", ")}
          </span>
        </div>
      )}

      {confirming && (
        <Modal
          title={confirm.title}
          danger={confirm.danger}
          onDismiss={() => setConfirming(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
              <Button
                variant={confirm.danger ? "danger" : "primary"}
                disabled={busy}
                onClick={() => setModeTo("enforcing")}
              >
                {confirm.confirmLabel}
              </Button>
            </>
          }
        >
          {confirm.body}
        </Modal>
      )}
    </Card>
  );
}

// ── Rules ─────────────────────────────────────────────────────────────────────────────
function RulesSection({
  orgId,
  canManage,
  subjectsRev,
}: {
  orgId: string;
  canManage: boolean;
  subjectsRev: number;
}) {
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [sites, setSites] = useState<Site[]>([]); // S8.2c D5: site rule subjects
  const [services, setServices] = useState<K8sService[]>([]); // S10.3: k8s_service dst subjects
  const [loaded, setLoaded] = useState<LoadState>({
    groupsLoaded: false,
    resourcesLoaded: false,
    membersLoaded: false,
  });
  const [loadError, setLoadError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<PolicyRule | null>(null);
  const [extendingGrant, setExtendingGrant] = useState<PolicyRule | null>(null);
  // F3: the rules pending a disable-confirm. PLURAL since the verbs moved to the selection bar — and
  // disabling five live allows at once is strictly MORE consequential than disabling one, so the ceremony
  // grew with the set rather than being dropped for convenience.
  const [disablingRules, setDisablingRules] = useState<PolicyRule[]>([]);
  // ⛔ DELETE NOW CONFIRMS, AND THAT IS A DELIBERATE ADDITION. Per-row it was one click on one rule; from a
  // selection bar the same click can destroy fifteen. An unconfirmed bulk delete of authorization rules is
  // the kind of control that is only ever wrong once.
  const [deletingRules, setDeletingRules] = useState<PolicyRule[]>([]);
  // SINGLE source of truth for the partial-swap warning: the SET of rule ids a create-then-
  // delete left un-deleted. The notice is DERIVED (staleNoticeText) — no separate state to
  // desync ([291]/[309]/[371]). Pruned ONLY on a successful load (amendment A), per-id (B).
  const [staleRuleIds, setStaleRuleIds] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // S8.3 CP summary line: BOTH derived from real load results (never an empty default) so a failed load
  // can't render the loud "0 rules — all denied". null until the first load resolves.
  const [modeResult, setModeResult] = useState<Loaded<
    "off" | "enforcing"
  > | null>(null);
  const [rulesResult, setRulesResult] = useState<Loaded<number> | null>(null);
  // ⛔ MEMBER COUNTS FOR SOURCE GROUPS ONLY — the bounded half of the coupling.
  // Lazy counts in the Groups panel LOSE the visibly-empty property; src_group_empty restores it HERE, on the
  // rule row, where the operator's attention already is. The fan-out is the DISTINCT SOURCE GROUPS of the
  // rules, not every group — the rules are what need judging.
  // `undefined` = not fetched yet, `null` = fetched and FAILED. Neither warns: "could not check" is not "empty".
  const [srcGroupCounts, setSrcGroupCounts] = useState<
    Map<string, number | null>
  >(new Map());

  const load = useCallback(async () => {
    setErr(null); // [310]: never carry a stale partial-load/mutation error into a fresh load
    const [rr, gr, resr, mr, mo, sr, ksr] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/policies", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/groups", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/resources", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/members", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/sites", {
          params: { path: { orgId } },
        }),
      ), // S8.2c D5: site rule subjects
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/k8s/services", {
          params: { path: { orgId } },
        }),
      ), // S10.3: k8s_service dst subjects
    ]);
    // Summary inputs — set from the SAME results (a rules-load failure → summary shows "failed", never 0).
    setRulesResult(
      rr.ok ? { ok: true, data: (rr.data as PolicyRule[]).length } : rr,
    );
    setModeResult(
      mo.ok
        ? { ok: true, data: (mo.data as ZeroTrustMode).mode }
        : (mo as Loaded<"off" | "enforcing">),
    );
    // The RULES fetch failing means the section cannot render truthfully — show retry, NOT
    // the reassuring "No rules — enforcing denies everything" ([2]). Amendment A: on this
    // FAILED path the stale-rule set is left untouched (the warning persists).
    if (!rr.ok) return setLoadError(rr.error);
    setLoadError(null);
    const freshRules = rr.data as PolicyRule[];
    setRules(freshRules);
    // Bounded: one call per DISTINCT source group actually referenced by a rule.
    const srcIds = [
      ...new Set(
        freshRules
          .filter((r) => (r.src_kind ?? "group") === "group" && r.src_group_id)
          .map((r) => r.src_group_id as string),
      ),
    ];
    void Promise.all(
      srcIds.map(async (gid) => {
        const mr = (await loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", {
            params: { path: { orgId, groupId: gid } },
          }),
        )) as Loaded<GroupMember[]>;
        return [gid, mr.ok ? mr.data.length : null] as const;
      }),
    ).then((pairs) => setSrcGroupCounts(new Map(pairs)));
    setGroups((gr.ok ? (gr.data as UserGroup[]) : []) as UserGroup[]);
    setResources((resr.ok ? (resr.data as Resource[]) : []) as Resource[]);
    setMembers((mr.ok ? (mr.data as Member[]) : []) as Member[]);
    setSites((sr.ok ? (sr.data as Site[]) : []) as Site[]); // D5
    setServices((ksr.ok ? (ksr.data as K8sService[]) : []) as K8sService[]); // S10.3: k8s_service dst subjects
    // D-a6 loaded flags come from the SAME source: a set that FAILED to load → its refs are
    // "unresolved", not "deleted".
    setLoaded({
      groupsLoaded: gr.ok,
      resourcesLoaded: resr.ok,
      membersLoaded: mr.ok,
      sitesLoaded: sr.ok,
      k8sServicesLoaded: ksr.ok,
    }); // sitesLoaded → WF-8; k8sServicesLoaded → S10.3
    setErr(
      gr.ok && resr.ok && mr.ok && sr.ok && ksr.ok
        ? null
        : "Some groups/resources/members/sites/services failed to load. names may show as unresolved. Refresh.",
    ); // ksr.ok: a services-load failure must raise the banner too
    // The ONLY clear path (amendment A: gated on this successful load): drop stale ids no
    // longer present, keep the rest (B).
    setStaleRuleIds((prev) => pruneStaleRuleIds(prev, true, freshRules));
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load, subjectsRev]); // S8.5: re-load when a sibling section mutates groups/resources (stale-button fix)

  const notice = staleNoticeText(staleRuleIds); // DERIVED — no notice state

  async function del(id: string) {
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/policies/{ruleId}",
      {
        params: { path: { orgId, ruleId: id } },
      },
    );
    if (error)
      return setErr(apiErrorMessage(error, "Could not delete the rule."));
    load();
  }

  // F3: toggle a rule enabled/disabled. Disabling withdraws its allow (in-hash push, effective in seconds);
  // ENABLE is one-click (additive/harmless), DISABLE goes through the confirm modal (asymmetric ceremony).
  async function setEnabled(id: string, enabled: boolean) {
    const { error } = await api.PATCH(
      "/api/v1/organizations/{orgId}/policies/{ruleId}",
      {
        params: { path: { orgId, ruleId: id } },
        body: { enabled },
      },
    );
    if (error)
      return setErr(
        apiErrorMessage(
          error,
          enabled
            ? "Could not enable the rule."
            : "Could not disable the rule.",
        ),
      );
    load();
  }

  const view = sectionRender(loadError, notice);

  return (
    <Card className="mt-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-300">Rules</h2>
        {/* TWO seams, both producing ABSENCE, and the ORDER is the decision (S14.2 D3):
            PERMISSION first, WIDTH second. A member who may not manage rules sees nothing — never
            "read-only on this screen size", which would imply a wider window grants what their role does not. */}
        {canManage && !view.showRetry && (
          <ComposeGate surface="Access rules">
            <Button
              onClick={() => setCreating(true)}
              disabled={groups.length === 0 && sites.length === 0}
            >
              Add rule
            </Button>
          </ComposeGate>
        )}
      </div>
      <p className="mt-1 text-xs text-slate-500">
        Allow rules: a source group may reach a destination group or resource.
      </p>

      {/* S8.3 CP: the posture summary line. enforcing+0 is LOUD (a live default-deny with no rules); a
          failed load reads "unavailable", never the reassuring 0-rules message. */}
      {(() => {
        const s = rulesSummary({ modeResult, rulesResult });
        if (s.state === "loading") return null;
        return (
          <p
            className={
              s.loud
                ? "mt-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-1.5 text-sm font-semibold text-danger"
                : `mt-2 text-xs ${s.state === "failed" ? "text-amber-300" : "text-slate-400"}`
            }
          >
            {s.text}
          </p>
        );
      })()}

      {/* [291] legibility signals COMPOSE: the partial-swap notice + a mutation error render at
          TOP LEVEL — a load failure replaces the LIST (content), never a warning. */}
      {view.showNotice && (
        <p className="mt-2 text-xs text-amber-300">{notice}</p>
      )}
      <ErrorText>{err}</ErrorText>
      {view.showRetry && (
        <LoadRetry error={loadError ?? "Couldn't load rules."} onRetry={load} />
      )}

      {view.showContent && (
        <>
          {groups.length === 0 && sites.length === 0 && loaded.groupsLoaded && (
            <p className="mt-2 text-xs text-slate-500">
              Create a group of users or register a site (site-to-site source)
              to add a rule.
            </p>
          )}
          {/* ── ACCESS FLOW ({{ polFlow }}) — built from the handoff's buildPolicyFlow(), not from a screenshot.
              GEOMETRY VERBATIM: canvas 600x312 rx14 over a 16px dot field; node boxes 152x36 rx10 at cx±76,
              columns at LX=95 / RX=505 so the paths own the middle 260px; vertical pitch 68 from cy=54;
              glyph circle r8 at cx-60. EDGES are cubic beziers with HORIZONTAL control points ±130 —
              `M170,sy C300,sy 300,dy 430,dy` — so they leave and arrive flat and read as flows, not chords.
              Temporary grants are DASHED (5 6), allow is solid: the design distinguishes them by dash, not
              by colour. Legend bottom-left, readout bottom-right, both INSIDE the panel.

              ⛔ ORDERING IS THE FIX, NOT THE CURVE. The handoff's own data crosses ZERO times because a human
              ordered the destination column so each source's edge is level or one slot away. Ours was
              insertion order and crossed six times out of nine. Destinations are now placed by the MEAN slot
              of their sources (one barycentric pass), which reproduces the handoff's hand-chosen order on its
              own data. A prettier line over the same tangle would have been worse — it would look deliberate.

              ⛔ AND THE COLUMN IS CAPPED AT THE DESIGN'S OWN FOUR SLOTS. The handoff draws 5 edges over 8
              nodes while its rule table shows 9 rows — it renders a SUBSET, by hand. Above the cap the
              remainder is stated, never silently dropped, and the table below stays authoritative. */}
          {(() => {
            const rows = rules.map((r) => {
              const rr = ruleRow(
                r,
                groups,
                resources,
                members,
                sites,
                loaded,
                services,
              );
              return {
                id: r.id,
                src: rr.src.label,
                dst: rr.dst.label,
                temp: r.expires_at != null,
                // ⛔ FROM THE RULE'S OWN UNION, never inferred from the label.
                srcKind: r.src_kind as FlowKind,
                dstKind: r.dst_kind as FlowKind,
              };
            });
            // Coverage is judged on what the layout ACTUALLY drew, so the gate sees the same number the
            // reader would. Two thresholds on one panel: the count cap (24) and the coverage floor (0.5).
            const probe = flowLayout(rows);
            const g = flowGraphState(rows.length, probe.shown.length);
            if (g.kind !== "draw")
              return (
                <p
                  className="mt-3 text-xs text-slate-500"
                  data-testid="flow-withheld"
                >
                  {flowGraphNote(g)}
                </p>
              );
            const { srcs, dsts, shown, hidden } = flowLayout(rows);
            const si = (l: string) => srcs.findIndex((n) => n.label === l);
            const di = (l: string) => dsts.findIndex((n) => n.label === l);
            const cy = (i: number) => 54 + i * 68;
            const node = (
              n: { label: string; kind: FlowKind },
              i: number,
              isSrc: boolean,
            ) => {
              const cx = isSrc ? 95 : 505;
              return (
                <g key={(isSrc ? "s" : "d") + n.label}>
                  <rect
                    x={cx - 76}
                    y={cy(i) - 18}
                    width="152"
                    height="36"
                    rx="10"
                    fill="var(--tnx-surface-inset)"
                    stroke="var(--tnx-divider)"
                    strokeWidth="1.4"
                  />
                  <circle
                    cx={cx - 60}
                    cy={cy(i)}
                    r="8"
                    fill="var(--tnx-surface)"
                    stroke="var(--tnx-divider)"
                  />
                  <text
                    x={cx - 60}
                    y={cy(i) + 3}
                    textAnchor="middle"
                    style={{ fontSize: "8px" }}
                    className="fill-slate-400"
                  >
                    {flowGlyph(n.kind)}
                  </text>
                  <text
                    x={cx - 46}
                    y={cy(i) - 2}
                    style={{ fontSize: "10px" }}
                    className="fill-slate-200"
                  >
                    {n.label.length > 18
                      ? n.label.slice(0, 17) + "\u2026"
                      : n.label}
                  </text>
                  <text
                    x={cx - 46}
                    y={cy(i) + 9}
                    style={{ fontSize: "7px", letterSpacing: ".08em" }}
                    className="fill-slate-500"
                  >
                    {flowTag(n.kind)}
                  </text>
                </g>
              );
            };
            return (
              <div className="mt-3">
                {/* ⛔ FIXED 600x312 — ONE USER UNIT IS ONE PIXEL. `w-full` on a viewBox scaled the whole
                    drawing to the container (~1900px), magnifying 152x36 boxes to ~490x130 and truncating
                    every name. THE SCALE IS A CONTRACT: same law, same panel shape, second occurrence after
                    the Sites map. width/height are set explicitly and the SVG is centred, never stretched. */}
                <svg
                  width="600"
                  height="312"
                  viewBox="0 0 600 312"
                  className="mx-auto block max-w-full"
                  role="img"
                  aria-label={`Access flow: ${shown.length} of ${rows.length} rules drawn, ${srcs.length} sources to ${dsts.length} destinations`}
                >
                  <defs>
                    <pattern
                      id="tnxPolDots"
                      width="16"
                      height="16"
                      patternUnits="userSpaceOnUse"
                    >
                      <circle
                        cx="1.5"
                        cy="1.5"
                        r="1"
                        fill="var(--tnx-divider)"
                      />
                    </pattern>
                  </defs>
                  <rect
                    x="0"
                    y="0"
                    width="600"
                    height="312"
                    rx="14"
                    fill="url(#tnxPolDots)"
                  />
                  <g className="tnx-flow-edges">
                    {shown.map((r) => {
                      const sy = cy(si(r.src)),
                        dy = cy(di(r.dst));
                      return (
                        <path
                          key={r.id}
                          fill="none"
                          strokeWidth="2"
                          stroke={
                            r.temp ? "var(--tnx-neutral)" : "var(--tnx-accent)"
                          }
                          strokeDasharray={r.temp ? "5 6" : undefined}
                          d={`M170,${sy} C300,${sy} 300,${dy} 430,${dy}`}
                        />
                      );
                    })}
                  </g>
                  {srcs.map((n, i) => node(n, i, true))}
                  {dsts.map((n, i) => node(n, i, false))}
                </svg>
                <div className="mx-auto mt-1 flex max-w-[600px] items-center justify-between text-[10px] text-slate-500">
                  <span>
                    <span className="text-slate-300">&#8212;&#8212;</span>{" "}
                    allow&nbsp;&nbsp;
                    <span className="text-slate-300">- - -</span> temporary
                  </span>
                  <span>
                    {hidden > 0
                      ? `${shown.length} of ${rows.length} flows drawn. ${hidden} more in the table below.`
                      : "All access flows"}
                  </span>
                </div>
              </div>
            );
          })()}
          {/* ⛔ THE RULES TABLE. Converted from a <ul> so it can be searched, sorted and paged like every
              other roster — 15 rules already overflowed a screen, and the list gave no way to find one.

              ⚠ THE BADGE COLOURS STAY. The founder asked for the mockup's SHAPE without its palette, and
              these are not palette: OUTSIDE RANGES, VANISHED, SOURCE GROUP EMPTY and TEMP are the four
              warn-kinds, each meaning "this rule renders as active and compiles to NOTHING". Draining their
              colour would remove the only thing that distinguishes them from decoration. What did go is the
              mockup's decorative green/blue/purple on Active and Managed-by-GitOps, which carried no state
              this product does not already say in words. */}
          {/* ⛔ THE FAILED COPY IS THE PAGE'S JOB, NOT THE TABLE'S — and forgetting it was one edit away.
              DataTable renders NOTHING when `failed`, deliberately, because only the page knows what to
              retry. Converting this list without this block would have replaced "Rules could not be loaded"
              with a blank area: the screen would say nothing at all about a read that failed, which is the
              reassuring-empty defect wearing its quietest possible face. */}
          {rulesEmptyState({
            rulesResult,
            modeResult,
            renderedCount: rules.length,
          }).kind === "failed" && (
            <p className="mt-3 rounded-md border border-danger/40 bg-danger/5 px-3 py-2 text-xs text-danger">
              {
                rulesEmptyCopy(
                  rulesEmptyState({
                    rulesResult,
                    modeResult,
                    renderedCount: rules.length,
                  }),
                ).text
              }
            </p>
          )}
          <div className="mt-3">
            <DataTable<PolicyRule>
              caption="Rules"
              rows={rules}
              rowKey={(r) => r.id}
              // ⛔ THE PAGE OWNS THE EMPTY COPY, because it distinguishes states this component cannot see:
              // an ENFORCING org with zero rules is a lockout warning, not an emptiness.
              failed={
                rulesEmptyState({
                  rulesResult,
                  modeResult,
                  renderedCount: rules.length,
                }).kind === "failed"
              }
              empty={
                <span
                  className={
                    rulesEmptyState({
                      rulesResult,
                      modeResult,
                      renderedCount: rules.length,
                    }).kind === "enforcing_empty"
                      ? "text-xs font-semibold text-warn"
                      : "text-xs text-slate-500"
                  }
                >
                  {
                    rulesEmptyCopy(
                      rulesEmptyState({
                        rulesResult,
                        modeResult,
                        renderedCount: rules.length,
                      }),
                    ).text
                  }
                </span>
              }
              // ⛔ THE VERBS LIVE IN ONE BAR, NOT ON EVERY ROW. Fifteen rules meant forty-five buttons —
              // the same three verbs redrawn fifteen times, crowding out the thing the row is actually
              // about. `unavailable` is what makes that safe rather than merely tidier: a GitOps-managed
              // grant refuses every mutation, and the bar names that BEFORE the click instead of skipping
              // the row afterwards.
              rowActions={
                canManage
                  ? [
                      {
                        key: "edit",
                        label: "Edit",
                        arity: "single",
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : canEditRuleInModal(r)
                              ? null
                              : "This rule's source or destination is not editable here.",
                        run: (rs: PolicyRule[]) => setEditing(rs[0]),
                      },
                      {
                        key: "extend",
                        label: "Extend",
                        arity: "single",
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : grantExpiry(r, Date.now()).extendable
                              ? null
                              : "Only a temporary grant can be extended.",
                        run: (rs: PolicyRule[]) => setExtendingGrant(rs[0]),
                      },
                      {
                        key: "enable",
                        label: "Enable",
                        // F3: enable is ADDITIVE and therefore one click, in bulk as on a single row.
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : r.enabled
                              ? "Already enabled."
                              : null,
                        run: (rs: PolicyRule[]) => {
                          void Promise.all(
                            rs.map((r) => setEnabled(r.id, true)),
                          );
                        },
                      },
                      {
                        key: "disable",
                        label: "Disable",
                        // ⛔ F3'S ASYMMETRIC CEREMONY SURVIVES THE MOVE. Disabling withdraws a live allow in
                        // seconds, so it confirms — and it must still confirm when it is doing so to five
                        // rules at once, which is strictly more consequential than doing it to one.
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : r.enabled
                              ? null
                              : "Already disabled.",
                        run: (rs: PolicyRule[]) => setDisablingRules(rs),
                      },
                      {
                        key: "delete",
                        label: "Delete",
                        danger: true,
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : null,
                        run: (rs: PolicyRule[]) => setDeletingRules(rs),
                      },
                    ]
                  : undefined
              }
              columns={[
                {
                  key: "src",
                  header: "Source",
                  sortValue: (r) =>
                    ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    ).src.label,
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    return (
                      <RefText
                        label={row.src.label}
                        broken={row.src.state !== "ok"}
                      />
                    );
                  },
                },
                {
                  key: "arrow",
                  header: "",
                  cell: () => (
                    <span aria-hidden className="text-slate-600">
                      →
                    </span>
                  ),
                },
                {
                  key: "dst",
                  header: "Destination",
                  sortValue: (r) =>
                    ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    ).dst.label,
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    return (
                      <RefText
                        label={row.dst.label}
                        broken={row.dst.state !== "ok"}
                      />
                    );
                  },
                },
                {
                  key: "status",
                  header: "Status",
                  // ⛔ THE WORD, NOT THE STYLING. A disabled rule used to be signalled by opacity on the
                  // whole row; opacity is invisible to a search and to anyone who cannot see it.
                  sortValue: (r) => (r.enabled ? "active" : "disabled"),
                  cell: (r) =>
                    r.enabled ? (
                      <span className="text-xs text-slate-400">active</span>
                    ) : (
                      /* F3: a disabled rule is shown DISTINCTLY, never hidden — the list must not lie
                         about what is enforcing. */
                      <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-400">
                        disabled
                      </span>
                    ),
                },
                {
                  key: "type",
                  header: "Type",
                  sortValue: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    if (row.managedByOperator) return "managed by gitops";
                    return grantExpiry(r, Date.now()).state === "permanent"
                      ? "standard"
                      : "temporary";
                  },
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    /* S10.2 D2 cond 1: a GitOps-managed grant is badged; its mutation controls are
                       withheld in the actions column. */
                    if (row.managedByOperator) return <ManagedBadge />;
                    const exp = grantExpiry(r, Date.now());
                    return exp.state === "permanent" ? (
                      <span className="text-xs text-slate-600">standard</span>
                    ) : (
                      /* S7.5.4 linger model: a temporary grant shows its window; an EXPIRED grant stays
                         visible (audit history), rendered distinctly — never hidden. */
                      <span
                        className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold ${exp.state === "expired" ? "border-rose-800/50 bg-rose-950/40 text-rose-400" : "border-amber-800/50 bg-amber-950/40 text-amber-300"}`}
                      >
                        TEMP · {exp.label}
                      </span>
                    );
                  },
                },
                {
                  key: "notes",
                  header: "Notes",
                  // ⚠ EVERY WARN KIND IS SEARCHABLE BY ITS OWN WORDS. These are the states an operator most
                  // needs to find — each one means a rule that reads ACTIVE and compiles to NOTHING — and a
                  // badge contributes no text, so without this they would be the least findable rows here.
                  sortValue: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    const empty =
                      (r.src_kind ?? "group") === "group" && r.src_group_id
                        ? srcGroupEmptyBadge(
                            srcGroupEmptyWarn(
                              srcGroupCounts.get(r.src_group_id),
                            ),
                          )
                        : null;
                    return [
                      row.cidrOutsideRanges ? "outside ranges" : "",
                      row.k8sServiceVanished ? "vanished" : "",
                      empty ?? "",
                    ]
                      .filter(Boolean)
                      .join(" ");
                  },
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    const emptyBadge =
                      (r.src_kind ?? "group") === "group" && r.src_group_id
                        ? srcGroupEmptyBadge(
                            srcGroupEmptyWarn(
                              srcGroupCounts.get(r.src_group_id),
                            ),
                          )
                        : null;
                    return (
                      <span className="flex flex-wrap items-center gap-1">
                        {/* S8.7 warn-not-refuse (D1): the SERVER's read-time judgment, rendered verbatim —
                            a CIDR rule matching no current org range. Self-clears when a range lands. */}
                        {row.cidrOutsideRanges && (
                          <span
                            className="rounded-full border border-amber-800/50 bg-amber-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-400"
                            title="This CIDR is inside no current site subnet. the rule matches nothing until the range is declared."
                          >
                            OUTSIDE RANGES
                          </span>
                        )}
                        {/* S10.3 warn-not-refuse: the dst Service was unexposed or its cluster
                            deregistered, so the grant compiles to nothing. Self-clears if it returns. */}
                        {row.k8sServiceVanished && (
                          <span
                            className="rounded-full border border-rose-800/50 bg-rose-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-400"
                            title="The Kubernetes Service this rule reaches is no longer exposed. the grant matches nothing until it is re-exposed."
                          >
                            VANISHED
                          </span>
                        )}
                        {/* ⛔ src_group_empty (S14.12) — measured at compiler.go:399: a group with zero
                            members matches NO device, so this rule COMPILES TO NOTHING while rendering
                            ACTIVE. Derived from the member COUNT, never from group existence, and it does
                            NOT fire while the count is unfetched or failed — "could not check" is not
                            "empty". */}
                        {emptyBadge && (
                          <span
                            className="rounded-full border border-warn/40 bg-warn/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-warn"
                            title={
                              srcGroupEmptyExplain(
                                srcGroupEmptyWarn(
                                  srcGroupCounts.get(r.src_group_id as string),
                                ),
                              ) ?? undefined
                            }
                          >
                            {emptyBadge}
                          </span>
                        )}
                      </span>
                    );
                  },
                },
              ]}
            />
          </div>
        </>
      )}

      {(creating || editing) && (
        <RuleFormModal
          orgId={orgId}
          groups={groups}
          resources={resources}
          members={activeMembers(members)}
          sites={sites}
          services={services}
          editing={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onDone={(staleId) => {
            // A partial swap adds the un-deleted rule id to the set; a clean create adds
            // nothing (so it can never drop a live warning — [371]).
            if (staleId)
              setStaleRuleIds((prev) =>
                prev.includes(staleId) ? prev : [...prev, staleId],
              );
            setCreating(false);
            setEditing(null);
            load();
          }}
        />
      )}
      {extendingGrant && (
        <ExtendGrantModal
          orgId={orgId}
          rule={extendingGrant}
          onClose={() => setExtendingGrant(null)}
          onDone={() => {
            setExtendingGrant(null);
            load();
          }}
        />
      )}
      {/* F3: the disable-confirm — NAMES the rule's own subject→destination + the immediate effect. Only
          disable gets this (enable is one-click). Danger-styled; Cancel or backdrop dismisses. */}
      {disablingRules.length > 0 &&
        (() => {
          const rs = disablingRules;
          const one = rs.length === 1 ? rs[0] : null;
          const row = one
            ? ruleRow(one, groups, resources, members, sites, loaded, services)
            : null;
          return (
            <Modal
              title={
                rs.length === 1
                  ? "Disable rule?"
                  : `Disable ${rs.length} rules?`
              }
              danger
              onDismiss={() => setDisablingRules([])}
              actions={
                <>
                  <Button variant="ghost" onClick={() => setDisablingRules([])}>
                    Cancel
                  </Button>
                  <Button
                    variant="danger"
                    onClick={async () => {
                      setDisablingRules([]);
                      await Promise.all(rs.map((r) => setEnabled(r.id, false)));
                    }}
                  >
                    Disable
                  </Button>
                </>
              }
            >
              {/* ⚠ ONE RULE STILL NAMES ITSELF. The single-rule sentence was specific — which source loses
                  which destination — and a plural rewrite that dropped it would make the common case vaguer
                  in order to serve the rare one. */}
              {row ? (
                <p className="text-sm text-slate-300">
                  {disableConfirmText(row.src.label, row.dst.label)}
                </p>
              ) : (
                <div className="text-sm text-slate-300">
                  <p>
                    These allow rules stop applying within seconds. Access they
                    grant is withdrawn.
                  </p>
                  {/* ⛔ THE SET IS SHOWN, NOT COUNTED. "Disable 5 rules?" asks the operator to trust their
                      own memory of a selection they made across pages and filters. */}
                  <ul className="mt-2 max-h-48 space-y-0.5 overflow-y-auto text-xs text-slate-400">
                    {rs.map((r) => {
                      const rr = ruleRow(
                        r,
                        groups,
                        resources,
                        members,
                        sites,
                        loaded,
                        services,
                      );
                      return (
                        <li key={r.id}>
                          {rr.src.label} → {rr.dst.label}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}
            </Modal>
          );
        })()}

      {deletingRules.length > 0 && (
        <Modal
          title={
            deletingRules.length === 1
              ? "Delete rule?"
              : `Delete ${deletingRules.length} rules?`
          }
          danger
          onDismiss={() => setDeletingRules([])}
          actions={
            <>
              <Button variant="ghost" onClick={() => setDeletingRules([])}>
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={async () => {
                  const rs = deletingRules;
                  setDeletingRules([]);
                  for (const r of rs) await del(r.id);
                }}
              >
                Delete
              </Button>
            </>
          }
        >
          <div className="text-sm text-slate-300">
            <p>
              Deleting is permanent. Disabling keeps the rule and its history —
              prefer it if you may want this access back.
            </p>
            <ul className="mt-2 max-h-48 space-y-0.5 overflow-y-auto text-xs text-slate-400">
              {deletingRules.map((r) => {
                const rr = ruleRow(
                  r,
                  groups,
                  resources,
                  members,
                  sites,
                  loaded,
                  services,
                );
                return (
                  <li key={r.id}>
                    {rr.src.label} → {rr.dst.label}
                  </li>
                );
              })}
            </ul>
          </div>
        </Modal>
      )}
    </Card>
  );
}

// ExtendGrantModal moves a temporary grant's window forward (S7.5.4). A LAPSED grant is
// refused by the server (409 grant_lapsed) — surfaced legibly here, not as a raw error;
// this is a WINDOW BUMP (PUT expires_at), never a delete+recreate.
function ExtendGrantModal({
  orgId,
  rule,
  onClose,
  onDone,
}: {
  orgId: string;
  rule: PolicyRule;
  onClose: () => void;
  onDone: () => void;
}) {
  const now = grantExpiry(rule, Date.now());
  const [when, setWhen] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setErr(null);
    const iso = new Date(when).toISOString();
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/policies/{ruleId}",
      {
        params: { path: { orgId, ruleId: rule.id } },
        body: { expires_at: iso },
      },
    );
    setBusy(false);
    if (error) return setErr(extendErrorCopy(apiErrorCode(error))); // 409 grant_lapsed / not_temporary → legible copy
    onDone();
  }

  return (
    <Modal
      title="Extend grant"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={busy || !when} onClick={submit}>
            Extend
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-slate-400">
          {now.state === "expired"
            ? `This grant ${now.label}. Extending a lapsed grant is refused. create a new grant instead.`
            : `This grant ${now.label}. Move its expiry to a later time (the grant is not re-created. only its window moves).`}
        </p>
        <Field label="New expiry">
          <Input
            type="datetime-local"
            value={when}
            onChange={(e) => setWhen(e.target.value)}
          />
        </Field>
        <ErrorText>{err}</ErrorText>
      </div>
    </Modal>
  );
}

function RefText({ label, broken }: { label: string; broken: boolean }) {
  return broken ? (
    <span className="text-amber-400">⚠ {label}</span>
  ) : (
    <span>{label}</span>
  );
}

// RuleFormModal creates OR edits a rule. Editing = CREATE-THEN-DELETE (D-a5) via swapRule —
// gap-free (allow-only union), never delete-first, with a LEGIBLE partial on delete-fail.
function RuleFormModal({
  orgId,
  groups,
  resources,
  members,
  sites,
  services,
  editing,
  onClose,
  onDone,
}: {
  orgId: string;
  groups: UserGroup[];
  resources: Resource[];
  members: Member[];
  sites: Site[];
  services: K8sService[];
  editing: PolicyRule | null;
  onClose: () => void;
  onDone: (staleRuleId?: string) => void;
}) {
  // S8.2c D5: the modal now CREATES site-source + site-dest rules too (was API-only). src_kind ∈
  // {group,user,site}; dst_kind ∈ {group,resource,site} — all through the same policies API (validation +
  // audit intact; the demo's raw DB insert was the anti-pattern this closes).
  // Review #4: when the org has sites but no groups, defaulting to "group" opens a modal that can't submit
  // (empty group select) until BOTH dropdowns are flipped — a dead end. Default to the kind that's actually
  // available so a fresh site-to-site org can Create immediately.
  const hasGroups = groups.length > 0;
  // ⛔ S15.3 — agents enrolled in this org, offered as a policy SOURCE. Without this the AI-agents screen
  // says an agent "reaches only what it is granted" and nothing could grant it anything: a capability the
  // product had and the operator could not reach.
  const [agents, setAgents] = useState<
    Array<{ device_id: string; name: string; gateway_name: string }>
  >([]);
  const [srcAgent, setSrcAgent] = useState("");
  // ⚠ Enterprise-only endpoint: a 403 is a SUCCESSFUL refusal, so the list simply stays empty and the
  // "AI agent" option is never offered. It must not surface as an error in a rule dialog.
  useEffect(() => {
    let cancelled = false;
    void api
      .GET("/api/v1/organizations/{orgId}/agents", {
        params: { path: { orgId } },
      })
      .then(({ data, error }) => {
        if (cancelled || error || !data) return;
        setAgents(
          data as Array<{
            device_id: string;
            name: string;
            gateway_name: string;
          }>,
        );
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [orgId]);
  const [srcKind, setSrcKind] = useState<
    "group" | "user" | "site" | "cidr" | "agent"
  >(
    defaultSrcKind({
      editingKind:
        editing?.src_kind === "user"
          ? "user"
          : editing?.src_kind === "site"
            ? "site"
            : editing?.src_kind === "cidr"
              ? "cidr"
              : undefined,
      hasGroups,
      hasSites: sites.length > 0,
    }),
  );
  const [src, setSrc] = useState(editing?.src_group_id ?? groups[0]?.id ?? "");
  const [srcUser, setSrcUser] = useState(
    editing?.src_user_id ?? members[0]?.user_id ?? "",
  );
  const [srcSite, setSrcSite] = useState(
    editing?.src_site_id ?? sites[0]?.id ?? "",
  );
  const [srcCidr, setSrcCidr] = useState(editing?.src_cidr ?? ""); // S8.7: literal source CIDR (free-text)
  // Default to the first dst kind that HAS options (re-review #4: the src-side fix left the dst side able to
  // dead-end — a no-groups org with resources/sites opened on "group" with an empty select, un-submittable).
  const [dstKind, setDstKind] = useState<
    "group" | "resource" | "site" | "k8s_service"
  >(
    editing?.dst_kind === "k8s_service"
      ? "k8s_service"
      : defaultDstKind({
          editingKind:
            editing?.dst_kind === "resource"
              ? "resource"
              : editing?.dst_kind === "site"
                ? "site"
                : undefined,
          hasGroups,
          hasResources: resources.length > 0,
          hasSites: sites.length > 0,
        }),
  );
  const [dstGroup, setDstGroup] = useState(
    editing?.dst_group_id ?? groups[0]?.id ?? "",
  );
  const [dstResource, setDstResource] = useState(
    editing?.dst_resource_id ?? resources[0]?.id ?? "",
  );
  const [dstSite, setDstSite] = useState(
    editing?.dst_site_id ?? sites[0]?.id ?? "",
  );
  const [dstK8sService, setDstK8sService] = useState(
    editing?.dst_k8s_service_id ?? services[0]?.id ?? "",
  ); // S10.3
  // Temporary grant: an optional expiry (datetime-local). Empty = permanent.
  // Expiry is a CREATE-only field ([2]/[3] fix): editing a rule is create-then-delete, and a
  // same-(src,dst) edit carrying an expiry collides on the unique index (or resubmits a past
  // expiry). Changing a temporary grant's window goes through Extend (a window bump), not Edit.
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function bodyFor(): CreatePolicyRuleRequest {
    return ruleBody({
      srcKind,
      dstKind,
      src,
      srcUser,
      srcAgent,
      srcSite,
      srcCidr,
      dstGroup,
      dstResource,
      dstSite,
      dstK8sService,
      expiresAt,
      editing: !!editing,
    });
  }

  async function submit() {
    setBusy(true);
    setErr(null);
    // [8]: guard a 2xx-with-no-body — never let (data).id throw and strand busy=true.
    const create = async (): Promise<{ id: string } | { error: unknown }> => {
      const { data, error } = await api.POST(
        "/api/v1/organizations/{orgId}/policies",
        {
          params: { path: { orgId } },
          body: bodyFor(),
        },
      );
      if (error) return { error };
      const id = (data as PolicyRule | undefined)?.id;
      if (!id)
        return { error: { error: { message: "Server returned no rule id." } } };
      return { id };
    };

    if (!editing) {
      const created = await create();
      setBusy(false);
      if ("error" in created)
        return setErr(
          apiErrorMessage(created.error, "Could not create the rule."),
        );
      return onDone();
    }

    const out = await swapRule(editing.id, create, async (id) =>
      api.DELETE("/api/v1/organizations/{orgId}/policies/{ruleId}", {
        params: { path: { orgId, ruleId: id } },
      }),
    );
    setBusy(false);
    if (out.outcome === "create_failed")
      return setErr(
        apiErrorMessage(out.error, "Could not create the new rule."),
      );
    if (out.outcome === "partial") return onDone(out.oldId); // notice derived from the id (staleNoticeText)
    onDone();
  }

  return (
    <Modal
      title={editing ? "Edit rule" : "Add rule"}
      size="wide"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={
              busy ||
              (srcKind === "group"
                ? !src
                : srcKind === "user"
                  ? !srcUser
                  : srcKind === "cidr"
                    ? !srcCidr.trim()
                    : !srcSite) ||
              (dstKind === "group"
                ? !dstGroup
                : dstKind === "resource"
                  ? !dstResource
                  : dstKind === "k8s_service"
                    ? !dstK8sService
                    : !dstSite)
            }
            onClick={submit}
          >
            {editing ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {/* S8.3 CP layout: source + destination each read as a labeled panel (was a flat field list),
            so the "who → what" of a rule is legible at a glance. Layout only — no behavior change. */}
        {/* ⛔ ONE PICKER PER SIDE. Four controls became two, and the KIND stopped being a thing you choose
            first — you look for "Engineering", you do not first decide that Engineering is a Group. The
            cascade let a source type be chosen against any destination type, which is how a site reaching
            itself became creatable; here the other side's choice is reflected in what this side offers.

            ⚠ THE GUARD IS THE SERVER'S (invalid_rule_self_site). This mirrors it — the CLI and the GitOps CR
            path reach the same API and never see this form, so a picker that merely hid the option would be
            guarding one caller of three. What the picker adds is the EXPLANATION. */}
        <EntityPicker
          label="Source"
          placeholder="Search groups, people, sites, agents… or type a CIDR"
          acceptCidr
          value={
            srcKind === "group"
              ? src
              : srcKind === "user"
                ? srcUser
                : srcKind === "site"
                  ? srcSite
                  : srcKind === "agent"
                    ? srcAgent
                    : srcCidr
          }
          options={sourceOptions({
            groups,
            members,
            sites,
            agents,
            dstKind,
            dstSite,
          })}
          onSelect={(o) => {
            setSrcKind(o.kind as typeof srcKind);
            if (o.kind === "group") setSrc(o.value);
            else if (o.kind === "user") setSrcUser(o.value);
            else if (o.kind === "site") setSrcSite(o.value);
            else if (o.kind === "agent") setSrcAgent(o.value);
            else setSrcCidr(o.value);
          }}
        />
        <EntityPicker
          label="Destination"
          placeholder="Search groups, resources, sites, services…"
          value={
            dstKind === "group"
              ? dstGroup
              : dstKind === "resource"
                ? dstResource
                : dstKind === "site"
                  ? dstSite
                  : dstK8sService
          }
          options={destinationOptions({
            groups,
            resources,
            sites,
            services,
            srcKind,
            srcSite,
          })}
          onSelect={(o) => {
            setDstKind(o.kind as typeof dstKind);
            if (o.kind === "group") setDstGroup(o.value);
            else if (o.kind === "resource") setDstResource(o.value);
            else if (o.kind === "site") setDstSite(o.value);
            else setDstK8sService(o.value);
          }}
        />
        {/* ⛔ WHAT THE RULE WILL DO, IN WORDS, BEFORE Create. Two pickers and a button let an operator
            choose two nouns and press go; nothing in that gesture says what the compiler will emit. The gap
            is enormous — "agent rajan → group Contractors" grants ONE MACHINE UNRESTRICTED ACCESS TO EVERY
            DEVICE OWNED BY EVERY CONTRACTOR, because a group destination is port-unscoped by construction
            (compiler.go:442, Protocol: ProtoAny).

            ⚠ A DESCRIPTION, NEVER A REFUSAL. Every pair compiles and every one has a legitimate use. The
            form's job is that the operator cannot be SURPRISED by their own rule. */}
        {(() => {
          const srcLabel =
            sourceOptions({
              groups,
              members,
              sites,
              agents,
              dstKind,
              dstSite,
            }).find(
              (o) =>
                o.kind === srcKind &&
                o.value ===
                  (srcKind === "group"
                    ? src
                    : srcKind === "user"
                      ? srcUser
                      : srcKind === "site"
                        ? srcSite
                        : srcKind === "agent"
                          ? srcAgent
                          : srcCidr),
            )?.label ?? (srcKind === "cidr" ? srcCidr : "");
          const dstLabel =
            destinationOptions({
              groups,
              resources,
              sites,
              services,
              srcKind,
              srcSite,
            }).find(
              (o) =>
                o.kind === dstKind &&
                o.value ===
                  (dstKind === "group"
                    ? dstGroup
                    : dstKind === "resource"
                      ? dstResource
                      : dstKind === "site"
                        ? dstSite
                        : dstK8sService),
            )?.label ?? "";
          if (!srcLabel || !dstLabel) return null;
          const eff = ruleEffectSummary({
            srcKind,
            srcLabel,
            dstKind,
            dstLabel,
          });
          const caution = ruleEffectCaution(srcKind, dstKind);
          return (
            <div
              data-testid="rule-effect"
              className={`rounded-md border px-3 py-2 text-xs ${eff.wide ? "border-warn/40 bg-warn/5 text-warn" : "border-white/10 bg-white/5 text-ink-body"}`}
            >
              {eff.text}
              {/* ⚠ THE EXTRA SENTENCE FOR THE ONE SHAPE THAT IS USUALLY A MISTAKE — attached to it alone,
                  because a caution on every rule is a caution nobody reads. */}
              {caution && (
                <span className="mt-1 block text-ink-secondary">{caution}</span>
              )}
            </div>
          );
        })()}
        {/* Temporary grant (CREATE only): set an expiry to auto-revoke; empty = permanent.
            Editing an existing rule changes its src/dst; change a temporary grant's window
            with Extend (a window bump), not Edit. */}
        {!editing && (
          <Field label="Expires (optional. leave empty for a permanent grant)">
            <Input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </Field>
        )}
        <ErrorText>{err}</ErrorText>
      </div>
    </Modal>
  );
}

// ── Groups & Resources ──────────────────────────────────────────────────────────────
function GroupsResourcesSection({
  orgId,
  canManage,
  onSubjectsChanged,
}: {
  orgId: string;
  canManage: boolean;
  onSubjectsChanged: () => void;
}) {
  const [groups, setGroups] = useState<UserGroup[]>([]);
  // The roster, for the "add a member" picker. A failed read leaves it EMPTY, which hides the picker rather
  // than offering an empty one — the add control is absent, not broken.
  const [orgMembers, setOrgMembers] = useState<Member[]>([]);
  // ⛔ COUNTS ON EVERY ROW, FETCHED LAZILY, REMEMBERED ONCE KNOWN — founder-ruled, REVERSING the earlier
  // on-expansion-only ruling, and the reversal has a reason: the earlier argument was REQUEST COST, and
  // CACHING ANSWERS COST WITHOUT BUYING SILENCE. One fetch per group per session, not per render.
  //   "0 members" IS THE SINGLE MOST IMPORTANT THING THIS PANEL CAN TELL AN OPERATOR, and hiding it behind an
  //   expansion hides the exact state src_group_empty exists to warn about.
  // undefined = not yet fetched (render nothing), null = fetched and FAILED (say so), number = the answer.
  // ⛔ SAME CASCADE AS A GROUP (dst_resource_id ON DELETE CASCADE), so the same typed guard.
  const [confirmRes, setConfirmRes] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const [memberCounts, setMemberCounts] = useState<Map<string, number | null>>(
    new Map(),
  );
  const noteCount = useCallback(
    (gid: string, n: number | null) =>
      setMemberCounts((m) => new Map(m).set(gid, n)),
    [],
  );
  const [resources, setResources] = useState<Resource[]>([]);
  const [groupsError, setGroupsError] = useState<string | null>(null);
  const [resourcesError, setResourcesError] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [newGroup, setNewGroup] = useState("");
  // Feature 1 (port-scoped resources): the resource MODEL + compiler + API already carry protocol + ports
  // end-to-end (resources.port_low/high, compiler.go:417-419); only this form omitted the port inputs — so a
  // rule targeting a resource could only ever grant ALL ports. Ports are OPTIONAL (empty = all ports for the
  // protocol); the server (createResource) is the authoritative validator (both-or-neither, low<=high).
  const [newRes, setNewRes] = useState({
    name: "",
    cidr: "",
    protocol: "any" as "any" | "tcp" | "udp",
    portLow: "",
    portHigh: "",
  });

  const load = useCallback(async () => {
    const [gr, resr, mr] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/groups", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/resources", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/members", {
          params: { path: { orgId } },
        }),
      ),
    ]);
    // Per-column legibility: a failed groups load shows retry in the groups column, not
    // "No groups yet." ([4]); same for resources.
    // The roster feeds the add-a-member picker only. A failed read leaves it EMPTY, which HIDES the picker
    // rather than offering an empty one — an absent control, never a broken one.
    setOrgMembers(mr.ok ? (mr.data as Member[]) : []);
    setGroupsError(gr.ok ? null : gr.error);
    // One pass over the groups, cached in `memberCounts`. Bounded by group count and done ONCE.
    if (gr.ok) {
      void Promise.all(
        (gr.data as UserGroup[]).map(async (g) => {
          const r = (await loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", {
              params: { path: { orgId, groupId: g.id } },
            }),
          )) as Loaded<GroupMember[]>;
          return [g.id, r.ok ? r.data.length : null] as const;
        }),
      ).then((pairs) => setMemberCounts(new Map(pairs)));
    }
    setResourcesError(resr.ok ? null : resr.error);
    if (gr.ok) setGroups(gr.data as UserGroup[]);
    if (resr.ok) setResources(resr.data as Resource[]);
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  async function addGroup() {
    if (!newGroup.trim()) return;
    const { error } = await api.POST("/api/v1/organizations/{orgId}/groups", {
      params: { path: { orgId } },
      body: { name: newGroup.trim() },
    });
    if (error)
      return setErr(apiErrorMessage(error, "Could not create the group."));
    setNewGroup("");
    load();
    onSubjectsChanged(); // S8.5: re-sync RulesSection's subject copy (the stale "Add rule" button)
  }
  async function delGroup(id: string) {
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/groups/{groupId}",
      {
        params: { path: { orgId, groupId: id } },
      },
    );
    if (error)
      return setErr(apiErrorMessage(error, "Could not delete the group."));
    load();
    onSubjectsChanged();
  }
  async function addResource() {
    if (
      !newRes.name.trim() ||
      !newRes.cidr.trim() ||
      !resPortsValid(newRes.portLow, newRes.portHigh)
    )
      return;
    // Both-or-neither: a low with no high is a SINGLE port (high := low); both empty = all ports (omit).
    const loStr = newRes.portLow.trim();
    const hiStr = newRes.portHigh.trim();
    let port_low: number | undefined;
    let port_high: number | undefined;
    if (loStr !== "") {
      port_low = Number(loStr);
      port_high = hiStr === "" ? port_low : Number(hiStr);
    }
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/resources",
      {
        params: { path: { orgId } },
        body: {
          name: newRes.name.trim(),
          cidr: newRes.cidr.trim(),
          protocol: newRes.protocol,
          port_low,
          port_high,
        },
      },
    );
    if (error)
      return setErr(apiErrorMessage(error, "Could not create the resource."));
    setNewRes({
      name: "",
      cidr: "",
      protocol: "any",
      portLow: "",
      portHigh: "",
    });
    load();
    onSubjectsChanged(); // resources are rule destinations — keep RulesSection's copy fresh too
  }
  async function delResource(id: string) {
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/resources/{resourceId}",
      {
        params: { path: { orgId, resourceId: id } },
      },
    );
    if (error)
      return setErr(apiErrorMessage(error, "Could not delete the resource."));
    load();
    onSubjectsChanged();
  }

  // ⛔ THE CASCADE CONFIRM MOVED WITH THE VERB. Deleting a group deletes every rule that names it, so the
  // confirmation is not optional ceremony — and from a selection bar the same click can take several groups
  // and all of their rules at once, which is strictly more consequential than the per-row version was.
  const [deletingGroups, setDeletingGroups] = useState<UserGroup[]>([]);
  // ⛔ TABS, NOT A STACK. Two tables one under the other cost a screen of scrolling to reach the second, and
  // the two are alternatives — an operator is working on groups OR on resources, never reading both at once.
  const [tab, setTab] = useState<"groups" | "resources">("groups");
  // ⛔ EDIT EXISTED IN THE API AND HAD NO CALL SITE. `PATCH .../groups/{id}` and `PATCH .../resources/{id}`
  // have shipped all along; the UI offered only Delete, so renaming a group or correcting a resource's port
  // meant deleting it — which CASCADES every rule that names it — and building it again. A capability the
  // product had and no operator could reach (the absence question, docs/CLAUDE.md).
  const [editingGroup, setEditingGroup] = useState<UserGroup | null>(null);
  const [editingRes, setEditingRes] = useState<Resource | null>(null);

  return (
    <Card className="mt-4">
      <h2 className="text-sm font-semibold text-slate-300">
        Groups &amp; resources
      </h2>
      {/* ⛔ RENAME, NOT DELETE-AND-REBUILD. Deleting a group CASCADES every rule that names it, so without
          this the only way to fix a typo in a group's name was to destroy the access it grants and
          reconstruct it from memory. */}
      {editingGroup && (
        <RenameGroupModal
          orgId={orgId}
          group={editingGroup}
          onClose={() => setEditingGroup(null)}
          onDone={() => {
            setEditingGroup(null);
            load();
            onSubjectsChanged();
          }}
        />
      )}
      {editingRes && (
        <EditResourceModal
          orgId={orgId}
          resource={editingRes}
          onClose={() => setEditingRes(null)}
          onDone={() => {
            setEditingRes(null);
            load();
            onSubjectsChanged();
          }}
        />
      )}
      {deletingGroups.length > 0 && (
        <CascadeDeleteModal
          kind="group"
          name={
            deletingGroups.length === 1
              ? deletingGroups[0].name
              : `${deletingGroups.length} groups`
          }
          onCancel={() => setDeletingGroups([])}
          onConfirm={() => {
            const gs = deletingGroups;
            setDeletingGroups([]);
            void (async () => {
              for (const g of gs) await delGroup(g.id);
            })();
          }}
        />
      )}
      <ErrorText>{err}</ErrorText>
      {/* ⛔ STACKED, NOT SIDE BY SIDE. Two tables in a half-width column each render five columns in the
          space of two — CIDR, protocol and ports would truncate exactly where an operator is comparing them
          against a router config. Each table gets the full row. */}
      {/* ⛔ TABS ABOVE, ADD-FORM ABOVE THE TABLE. Both creation forms used to sit BELOW their list, so on
          an org with ten groups the way to make the eleventh was off the bottom of the card — the primary
          action on the screen, reachable only by scrolling past everything it creates. */}
      <div className="mt-3 flex gap-1 border-b border-white/10">
        {(["groups", "resources"] as const).map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 py-1.5 text-sm capitalize ${
              tab === t
                ? "border-white/60 text-ink-heading"
                : "border-transparent text-ink-tertiary hover:text-slate-300"
            }`}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="mt-3">
        {tab === "groups" && canManage && (
          <div className="mt-2 flex gap-2">
            <Input
              placeholder="Group name"
              value={newGroup}
              onChange={(e) => setNewGroup(e.target.value)}
            />
            <Button onClick={addGroup}>Add</Button>
          </div>
        )}
        {tab === "resources" && canManage && (
          <div className="mt-2 space-y-2">
            <Input
              placeholder="Name"
              value={newRes.name}
              onChange={(e) => setNewRes({ ...newRes, name: e.target.value })}
            />
            <div className="flex gap-2">
              <Input
                placeholder="CIDR e.g. 10.0.5.0/24"
                value={newRes.cidr}
                onChange={(e) => setNewRes({ ...newRes, cidr: e.target.value })}
              />
              <Select
                value={newRes.protocol}
                onChange={(e) =>
                  setNewRes({
                    ...newRes,
                    protocol: e.target.value as "any" | "tcp" | "udp",
                  })
                }
              >
                <option value="any">any</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </Select>
            </div>
            {/* Feature 1: OPTIONAL port scope. Leave blank = all ports for the protocol; a low alone =
                    a single port; low+high = a range. Server is authoritative (createResource validates). */}
            <div className="flex gap-2">
              <Input
                type="number"
                min={1}
                max={65535}
                placeholder="Port (optional)"
                value={newRes.portLow}
                onChange={(e) =>
                  setNewRes({ ...newRes, portLow: e.target.value })
                }
              />
              <Input
                type="number"
                min={1}
                max={65535}
                placeholder="to (range, optional)"
                value={newRes.portHigh}
                onChange={(e) =>
                  setNewRes({ ...newRes, portHigh: e.target.value })
                }
              />
              <Button
                onClick={addResource}
                disabled={!resPortsValid(newRes.portLow, newRes.portHigh)}
              >
                Add
              </Button>
            </div>
            {!resPortsValid(newRes.portLow, newRes.portHigh) && (
              <p className="text-xs text-amber-400">
                Ports must be 1–65535; leave both blank for all ports, or set a
                low ≤ high.
              </p>
            )}
          </div>
        )}
      </div>
      <div className="mt-3 space-y-4">
        {/* ⛔ GROUPS AS A TABLE. Name / members / type / created are the same five facts for every group, and
            an org accumulates them — the list gave no way to search and no way to stop rendering all of them.

            ⚠ WHAT SURVIVED THE CONVERSION, because each was earned: the DIRECTORY badge where the name is
            (the reconciler owns that membership, so say it where the name is), the THREE-ARM member count
            (unfetched renders NOTHING and must never become a 0 nobody asked for; 0 is the loudest state
            here and is styled as a warning, not as metadata), and expansion to manage members. */}
        {/* ⚠ `hidden`, NOT A CSS CLASS, AND THE DIFFERENCE IS THE POINT. `hidden` takes the panel out of
            the accessibility tree and out of find-in-page, so a screen reader and ⌘F see what the eye sees —
            whereas `.opacity-0` or an off-screen class would leave a whole table readable to both while
            invisible, which is the invisible-is-not-absent failure.

            ⚠ The nodes DO stay in the DOM, deliberately: switching tabs keeps each table's filter, sort and
            page rather than resetting the operator's view every time they glance at the other one. */}
        <div hidden={tab !== "groups"}>
          {groupsError ? (
            <LoadRetry error={groupsError} onRetry={load} />
          ) : (
            <>
              <DataTable<UserGroup>
                caption="Groups"
                rows={groups}
                rowKey={(g) => g.id}
                failed={false}
                pageSize={10}
                empty="No groups yet."
                rowActions={
                  canManage
                    ? [
                        {
                          key: "edit",
                          label: "Rename",
                          arity: "single",
                          run: (gs: UserGroup[]) => setEditingGroup(gs[0]),
                        },
                        {
                          key: "delete",
                          label: "Delete",
                          danger: true,
                          // ⚠ A directory-managed group's MEMBERSHIP is owned by the reconciler; the group
                          // itself is still deletable, so nothing is withheld here.
                          run: (gs: UserGroup[]) => setDeletingGroups(gs),
                        },
                      ]
                    : undefined
                }
                expandable={(g) => (
                  <GroupMembersPanel
                    orgId={orgId}
                    group={g}
                    members={orgMembers}
                    canManage={canManage}
                    onCount={noteCount}
                    onMembershipChange={onSubjectsChanged}
                  />
                )}
                columns={[
                  {
                    key: "name",
                    header: "Group name",
                    sortValue: (g) => g.name,
                    cell: (g) => (
                      <span className="flex items-center gap-2">
                        <span className="text-slate-200">{g.name}</span>
                        {isDirectoryManaged(g) && (
                          <span className="rounded-full border border-accent-500/40 bg-accent-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-accent-400">
                            {DIRECTORY_MANAGED_BADGE}
                          </span>
                        )}
                      </span>
                    ),
                  },
                  {
                    key: "members",
                    header: "Members",
                    sortValue: (g) => memberCounts.get(g.id) ?? -1,
                    // ⛔ THE COUNT IS THE WAY IN. Making it the disclosure control means the number an
                    // operator is already looking at is the thing they click, rather than a chevron in a
                    // column that means nothing until used.
                    // ⛔ IT HAD TO LOOK LIKE A CONTROL, AND IT DID NOT. The count was plain text with a
                    // hover underline, so the only way to manage members was to click something that read
                    // as a label — the founder found it by accident, which is the definition of an
                    // undiscoverable affordance. It is now a bordered control with a disclosure caret and
                    // the word "Manage", so what it does is legible without clicking it.
                    cell: (g, { expanded, toggle }) => {
                      const count = memberCounts.get(g.id);
                      return (
                        <button
                          type="button"
                          onClick={toggle}
                          aria-expanded={expanded}
                          title={
                            expanded ? "Hide members" : "View and add members"
                          }
                          className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-2 py-1 text-xs hover:border-white/25 hover:bg-white/10"
                        >
                          <svg
                            aria-hidden
                            viewBox="0 0 10 10"
                            className={`h-2 w-2 shrink-0 text-slate-500 transition-transform ${expanded ? "rotate-90" : ""}`}
                            fill="currentColor"
                          >
                            <path d="M2 0 L8 5 L2 10 Z" />
                          </svg>
                          {/* `undefined` = not yet asked, and renders as a prompt rather than as a 0
                              nobody fetched. */}
                          {count === undefined ? (
                            <span className="text-slate-500">view members</span>
                          ) : count === null ? (
                            <span className="text-warn">
                              members could not be loaded
                            </span>
                          ) : count === 0 ? (
                            <span className="font-semibold text-warn">
                              0 members
                            </span>
                          ) : (
                            <span className="text-slate-400">
                              {count === 1 ? "1 member" : `${count} members`}
                            </span>
                          )}
                          {/* ⚠ The VERB, beside the number. "3 members" alone says what is true; it does
                              not say that clicking is how you change it. */}
                          <span className="text-slate-600">· Manage</span>
                        </button>
                      );
                    },
                  },
                  {
                    key: "type",
                    header: "Type",
                    sortValue: (g) =>
                      isDirectoryManaged(g) ? "directory group" : "user group",
                    cell: (g) => (
                      <span className="text-xs text-slate-500">
                        {isDirectoryManaged(g)
                          ? "Directory group"
                          : "User group"}
                      </span>
                    ),
                  },
                ]}
              />
            </>
          )}
        </div>
        <div hidden={tab !== "resources"}>
          {resourcesError ? (
            <LoadRetry error={resourcesError} onRetry={load} />
          ) : (
            <>
              {/* ⛔ RESOURCES AS A TABLE, with CIDR / protocol / ports in COLUMNS OF THEIR OWN. They were
                  concatenated into one muted string — "10.20.4.0/24 · tcp/5432" — which cannot be sorted,
                  cannot be scanned down, and put the three facts that decide what a rule actually permits
                  into the typography of an afterthought. */}
              <DataTable<Resource>
                caption="Resources"
                rows={resources}
                rowKey={(r) => r.id}
                failed={false}
                pageSize={10}
                empty="No resources yet."
                rowActions={
                  canManage
                    ? [
                        {
                          key: "edit",
                          label: "Edit",
                          arity: "single",
                          run: (rs: Resource[]) => setEditingRes(rs[0]),
                        },
                        {
                          key: "delete",
                          label: "Delete",
                          danger: true,
                          run: (rs: Resource[]) =>
                            setConfirmRes({ id: rs[0].id, name: rs[0].name }),
                          // ⚠ ONE AT A TIME, deliberately. The confirm names the resource and lists the
                          // rules that will go with it; a multi-resource cascade would need a different
                          // dialog, and shipping the verb before that dialog exists would mean confirming
                          // a deletion whose consequences were not shown.
                          arity: "single",
                        },
                      ]
                    : undefined
                }
                columns={[
                  {
                    key: "name",
                    header: "Resource",
                    sortValue: (r) => `${r.name} ${r.label ?? ""}`,
                    cell: (r) => (
                      <span className="flex items-center gap-2">
                        <span className="text-slate-200">{r.name}</span>
                        {/* ⛔ THE OPERATOR'S OWN NOTE (S15.3), RENDERED AS WRITTEN. An ASSERTION, never an
                            inference — the product cannot detect what a destination speaks, and a label the
                            system generated would claim a capability it does not have.
                            ⚠ Only when set: the field is optional and must LOOK optional. */}
                        {r.label && (
                          <span className="rounded border border-line px-1.5 py-0.5 text-[10px] text-ink-secondary">
                            {r.label}
                          </span>
                        )}
                      </span>
                    ),
                  },
                  {
                    key: "cidr",
                    header: "CIDR",
                    sortValue: (r) => r.cidr,
                    cell: (r) => (
                      <span className="font-mono text-xs text-slate-500">
                        {r.cidr}
                      </span>
                    ),
                  },
                  {
                    key: "protocol",
                    header: "Protocol",
                    sortValue: (r) => r.protocol,
                    cell: (r) => (
                      <span className="font-mono text-xs text-slate-500">
                        {r.protocol}
                      </span>
                    ),
                  },
                  {
                    key: "ports",
                    header: "Ports",
                    sortValue: (r) => r.port_low ?? -1,
                    cell: (r) => (
                      <span className="font-mono text-xs text-slate-500">
                        {portLabel(r.port_low, r.port_high)}
                      </span>
                    ),
                  },
                ]}
              />
            </>
          )}
        </div>
      </div>
      {confirmRes && (
        <CascadeDeleteModal
          kind="resource"
          name={confirmRes.name}
          onCancel={() => setConfirmRes(null)}
          onConfirm={() => {
            const id = confirmRes.id;
            setConfirmRes(null);
            void delResource(id);
          }}
        />
      )}
    </Card>
  );
}

// ── Device approval (folded S7.3 admin surface) ─────────────────────────────────────
function DeviceApprovalSection({
  orgId,
  canManage,
}: {
  orgId: string;
  canManage: boolean;
}) {
  const [mode, setMode] = useState<"off" | "on" | null>(null);
  const [modeError, setModeError] = useState<string | null>(null);
  const [pending, setPending] = useState<Device[]>([]);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [dr, pr] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/device-approval", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/devices/pending", {
          params: { path: { orgId } },
        }),
      ),
    ]);
    setModeError(dr.ok ? null : dr.error);
    if (dr.ok) setMode((dr.data as DeviceApproval).mode);
    // [3]: a failed pending fetch must NOT render "No devices awaiting approval" — that hides
    // a device blocked from connecting. Show retry.
    setPendingError(pr.ok ? null : pr.error);
    if (pr.ok) setPending(pr.data as Device[]);
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  async function setApproval(next: "off" | "on") {
    setBusy(true);
    setErr(null);
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/device-approval",
      {
        params: { path: { orgId } },
        body: { mode: next },
      },
    );
    setBusy(false);
    if (error)
      return setErr(
        apiErrorMessage(error, "Could not change device approval."),
      );
    load();
  }
  async function decide(deviceId: string, action: "approve" | "reject") {
    const path =
      action === "approve"
        ? "/api/v1/organizations/{orgId}/devices/{deviceId}/approve"
        : "/api/v1/organizations/{orgId}/devices/{deviceId}/reject";
    const { error } = await api.POST(path, {
      params: { path: { orgId, deviceId } },
    });
    if (error)
      return setErr(apiErrorMessage(error, `Could not ${action} the device.`));
    load();
  }

  return (
    <Card className="mt-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-300">
            Device approval
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            {mode === "on"
              ? "On. new devices enroll pending and cannot connect until approved."
              : mode === "off"
                ? "Off. new devices are active on enrollment."
                : modeError
                  ? "n/a"
                  : "…"}
          </p>
        </div>
        {canManage && mode != null && !modeError && (
          <Button
            variant={mode === "on" ? "ghost" : "primary"}
            disabled={busy}
            onClick={() => setApproval(mode === "on" ? "off" : "on")}
          >
            {mode === "on" ? "Turn off" : "Require approval"}
          </Button>
        )}
      </div>
      {modeError && <LoadRetry error={modeError} onRetry={load} />}
      <ErrorText>{err}</ErrorText>

      {/* ⛔ PENDING DEVICES AS A TABLE. A device awaiting approval is the ONE list here where the operator
          is being asked to make a security decision — and the row gave them a name and an IP with no owner,
          no platform, no age. Approving a device you cannot attribute is approving a device.

          ⚠ The wait is shown because it is the fact that decides urgency: a request from four minutes ago
          and one from nine days ago are different situations wearing the same row. */}
      {pendingError ? (
        <LoadRetry error={pendingError} onRetry={load} />
      ) : (
        <DataTable<Device>
          caption="Pending devices"
          rows={pending}
          rowKey={(d) => d.id}
          failed={false}
          pageSize={10}
          empty="No devices awaiting approval."
          rowActions={
            canManage
              ? [
                  {
                    key: "approve",
                    label: "Approve",
                    run: (ds: Device[]) => {
                      void Promise.all(ds.map((d) => decide(d.id, "approve")));
                    },
                  },
                  {
                    key: "reject",
                    label: "Reject",
                    danger: true,
                    run: (ds: Device[]) => {
                      void Promise.all(ds.map((d) => decide(d.id, "reject")));
                    },
                  },
                ]
              : undefined
          }
          columns={[
            {
              key: "name",
              header: "Device",
              sortValue: (d) => d.name,
              cell: (d) => <span className="text-slate-200">{d.name}</span>,
            },
            {
              key: "ip",
              header: "Address",
              sortValue: (d) => d.assigned_ip ?? "",
              cell: (d) => (
                <span className="font-mono text-xs text-slate-500">
                  {d.assigned_ip}
                </span>
              ),
            },
            {
              key: "waiting",
              header: "Waiting",
              sortValue: (d) => Date.parse(d.created_at),
              cell: (d) => (
                <span className="text-xs text-slate-500">
                  {relativeAge(d.created_at)}
                </span>
              ),
            },
          ]}
        />
      )}
    </Card>
  );
}

// ── Device posture checks (S7.5.3) ───────────────────────────────────────────────────
// Per-check org opt-in (no configured check = off — the unlock-then-opt-in convention).
// Three legibility requirements (the slice-3 rider): (1) per-platform NON-coverage is
// visible (an os_version min for macOS only must SAY Windows is unconstrained), (2) a
// device that doesn't report shows as UNKNOWN, never as a pass (rendered on the Devices
// page), (3) the verbatim honesty line sits HERE, where an admin configures the checks.
function PostureChecksSection({
  orgId,
  canManage,
}: {
  orgId: string;
  canManage: boolean;
}) {
  const [checks, setChecks] = useState<HealthCheck[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saveNote, setSaveNote] = useState<string | null>(null);
  // os_version editor state (min inputs live-preview the coverage indicator).
  const [osMode, setOsMode] = useState<CheckMode>("off");
  const [osMacos, setOsMacos] = useState("");
  const [osWindows, setOsWindows] = useState("");

  const load = useCallback(async () => {
    const r = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/health-checks", {
        params: { path: { orgId } },
      }),
    );
    setLoadError(r.ok ? null : r.error);
    if (r.ok) {
      const list = r.data as HealthCheck[];
      setChecks(list);
      setOsMode(checkModeOf(list, "os_version"));
      const mins = osVersionMins(list.find((c) => c.kind === "os_version"));
      setOsMacos(mins.macos);
      setOsWindows(mins.windows);
    }
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  async function saveCheck(
    kind: HealthCheck["kind"],
    mode: CheckMode,
    param?: Record<string, unknown> | null,
  ) {
    setBusy(true);
    setErr(null);
    setSaveNote(null);
    if (mode === "off") {
      const { error } = await api.DELETE(
        "/api/v1/organizations/{orgId}/health-checks/{checkKind}",
        {
          params: { path: { orgId, checkKind: kind } },
        },
      );
      setBusy(false);
      if (error)
        return setErr(apiErrorMessage(error, "Could not turn the check off."));
      return load();
    }
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/health-checks/{checkKind}",
      {
        params: { path: { orgId, checkKind: kind } },
        body: {
          mode,
          param: (param ?? undefined) as Record<string, never> | undefined,
        },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not save the check."));
    setSaveNote(
      wouldFailCopy(mode, (data as HealthCheck | undefined)?.would_fail_count),
    );
    load();
  }

  function saveOsVersion() {
    if (osMode === "off") return saveCheck("os_version", "off");
    const param = buildOsVersionParam({ macos: osMacos, windows: osWindows });
    if (!param)
      return setErr(
        "Set a minimum version for at least one platform, or turn the check off.",
      );
    return saveCheck("os_version", osMode, param);
  }

  const diskMode = checkModeOf(checks, "disk_encryption");
  const coverage = osVersionCoverage({
    macos: osMode === "off" ? "" : osMacos,
    windows: osMode === "off" ? "" : osWindows,
  });

  return (
    <Card className="mt-4">
      <h2 className="text-sm font-semibold text-slate-300">
        Device posture checks
      </h2>
      <p className="mt-1 text-xs text-slate-500">
        Per-check requirements evaluated on every device self-report.{" "}
        <span className="text-slate-400">warn</span> surfaces a warning;{" "}
        <span className="text-amber-300">require</span> disconnects a
        non-compliant device within seconds of its report.
      </p>
      {/* The honesty line — verbatim, at the point of configuration (D6, locked). */}
      <div className="mt-2 rounded-md border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-400">
        {POSTURE_HONESTY_LINE}
      </div>

      {loadError && <LoadRetry error={loadError} onRetry={load} />}
      <ErrorText>{err}</ErrorText>
      {saveNote && (
        <div className="mt-3 rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-amber-300">
          {saveNote}
        </div>
      )}

      {checks != null && !loadError && (
        <div className="mt-4 space-y-4">
          {/* Disk encryption */}
          <div className="rounded-md bg-white/5 px-3 py-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-200">Disk encryption</p>
                <p className="text-xs text-slate-500">
                  FileVault (macOS) / BitLocker (Windows), as reported by the
                  device.
                </p>
              </div>
              {canManage ? (
                <Select
                  width="auto"
                  value={diskMode}
                  disabled={busy}
                  onChange={(e) =>
                    saveCheck("disk_encryption", e.target.value as CheckMode)
                  }
                >
                  <option value="off">Off</option>
                  <option value="warn">Warn</option>
                  <option value="require">Require</option>
                </Select>
              ) : (
                <span className="text-xs text-slate-400">{diskMode}</span>
              )}
            </div>
            {/* A device that reports the fact as ABSENT (couldn't read it) is UNKNOWN for this
                check — unknown never blocks, and it is not compliance. */}
          </div>

          {/* OS version */}
          <div className="rounded-md bg-white/5 px-3 py-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-200">Minimum OS version</p>
                <p className="text-xs text-slate-500">
                  Per-platform floors; leave a platform empty to not constrain
                  it.
                </p>
              </div>
              {canManage ? (
                <Select
                  width="auto"
                  value={osMode}
                  disabled={busy}
                  onChange={(e) => setOsMode(e.target.value as CheckMode)}
                >
                  <option value="off">Off</option>
                  <option value="warn">Warn</option>
                  <option value="require">Require</option>
                </Select>
              ) : (
                <span className="text-xs text-slate-400">
                  {checkModeOf(checks, "os_version")}
                </span>
              )}
            </div>
            {osMode !== "off" && canManage && (
              <div className="mt-3 flex flex-wrap items-end gap-3">
                <Field label="macOS minimum">
                  <Input
                    value={osMacos}
                    onChange={(e) => setOsMacos(e.target.value)}
                    placeholder="e.g. 14.0"
                  />
                </Field>
                <Field label="Windows minimum">
                  <Input
                    value={osWindows}
                    onChange={(e) => setOsWindows(e.target.value)}
                    placeholder="e.g. 10.0.22631"
                  />
                </Field>
                <Button disabled={busy} onClick={saveOsVersion}>
                  Save
                </Button>
                {/* [6] Windows-version foot-gun: Win 11 reports major 10 (10.0.22000+),
                    so "11.0" would block the whole Windows fleet. Steer to build numbers. */}
                <p className="w-full text-xs text-slate-500">
                  Windows uses build numbers. Windows 11 reports as{" "}
                  <span className="font-mono text-slate-400">10.0.22000</span>,
                  not 11.0. Enter the build (e.g.{" "}
                  <span className="font-mono text-slate-400">10.0.22631</span>{" "}
                  for 23H2); run{" "}
                  <span className="font-mono text-slate-400">winver</span> to
                  check a device.
                </p>
              </div>
            )}
            {/* WF-OVPN-walk-3: "Off" hid the min-version inputs AND the Save button, so the setting
                could not be persisted from the UI (a dead-end). Off has nothing to configure, but it
                still needs its own Save affordance — saveOsVersion() already handles the off case. */}
            {osMode === "off" && canManage && (
              <div className="mt-3">
                <Button disabled={busy} onClick={saveOsVersion}>
                  Save
                </Button>
              </div>
            )}
            {/* THE coverage indicator (ratified rider): every reporting platform is named —
                a constrained platform shows its floor, an unconstrained one SAYS so. Never
                a silent gap. */}
            {osMode !== "off" && (
              <ul className="mt-2 space-y-0.5 text-xs">
                {coverage.map((c) => (
                  <li
                    key={c.platform}
                    className={c.covered ? "text-slate-400" : "text-amber-400"}
                  >
                    {c.label}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

// ⛔ ONE TYPED CONFIRM FOR BOTH CASCADING DELETES. Groups and resources have the SAME cascade
// (ON DELETE CASCADE on src_group_id / dst_group_id / dst_resource_id) and the SAME silence (a 204 with no
// body), so they get the same guard rather than two that can drift apart.
function CascadeDeleteModal({
  kind,
  name,
  onCancel,
  onConfirm,
}: {
  kind: "group" | "resource";
  name: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const [typed, setTyped] = useState("");
  const copy = cascadeConfirmCopy(kind, name);
  const ok = cascadeConfirmSatisfied(typed, name);
  return (
    <Modal
      title={copy.title}
      danger
      onDismiss={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          {/* The control is DISABLED until the name matches — the guard is the typing, not a second click. */}
          <Button variant="danger" disabled={!ok} onClick={onConfirm}>
            Delete {kind}
          </Button>
        </>
      }
    >
      <p className="text-sm text-slate-300">{copy.body}</p>
      <div className="mt-3">
        <Field label={`Type “${copy.typeToConfirm}” to confirm`}>
          <Input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={copy.typeToConfirm}
            autoFocus
          />
        </Field>
      </div>
    </Modal>
  );
}

// ── GROUP MEMBERSHIP — the surface for three endpoints that shipped in S7.5.2 with one consumer ──────────
//
// `addGroupMember` and `removeGroupMember` have existed since S7.5.2 and the web app has NEVER called them.
// A group on this screen was a name and a Delete, while rules above used those same groups as SOURCES — a
// form creating an object nobody could populate, above rules that depend on it being populated.
//
// ⛔ COUNTS ARE LAZY, ON EXPANSION ONLY, AND THE COLLAPSED ROW SHOWS NOTHING RATHER THAN A ZERO IT NEVER
// FETCHED. `UserGroup` carries no count, so an eager count costs ONE REQUEST PER GROUP. Measured on the live
// stack: 3 groups = 65ms; ~433ms at 20; ~1083ms at 50 — on a screen already making 15 reads.
//
//   "WE HAVEN'T ASKED" AND "ZERO MEMBERS" ARE DIFFERENT FACTS, and the second is the dangerous one on a rule
//   source: it reads as "this rule grants nothing" and may be false.
//
// ⛔ AND LAZY COUNTS LOSE THE VISIBLY-EMPTY PROPERTY, which is why `src_group_empty` exists on the RULE ROW —
// it restores it where the operator's attention already is, at no request cost. Two decisions, one problem.
/**
 * The MEMBERS panel for one group — what used to be the expanded half of a list row.
 *
 * ⛔ IT NO LONGER OWNS `open`. The table owns expansion, so this component only exists while the row is
 * expanded and therefore fetches ON MOUNT. That removes the "expanded but never asked" state entirely
 * rather than leaving two places that both think they know whether the members have been loaded.
 */
function GroupMembersPanel({
  orgId,
  group,
  members,
  canManage,
  onCount,
  onMembershipChange,
}: {
  orgId: string;
  group: UserGroup;
  members: Member[];
  canManage: boolean;
  onCount: (groupId: string, n: number | null) => void;
  onMembershipChange: () => void;
}) {
  // THREE ARMS, as everywhere else: null = not asked, {ok:false} = asked and failed, {ok:true} = the answer.
  const [loaded, setLoaded] = useState<Loaded<GroupMember[]> | null>(null);
  const [busy, setBusy] = useState(false);

  const fetchMembers = useCallback(async () => {
    const r = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", {
        params: { path: { orgId, groupId: group.id } },
      }),
    )) as Loaded<GroupMember[]>;
    setLoaded(r);
    onCount(group.id, r.ok ? r.data.length : null); // keep the row's cached count in step with a mutation
  }, [orgId, group.id, onCount]);

  // Mounted means expanded, so ask immediately.
  useEffect(() => {
    void fetchMembers();
  }, [fetchMembers]);

  async function mutateMembership(fn: () => Promise<{ error?: unknown }>) {
    setBusy(true);
    const { error } = await fn();
    setBusy(false);
    if (!error) {
      await fetchMembers();
      onMembershipChange(); // the rule rows read this count for src_group_empty
    }
  }

  // ⛔ MEMBERSHIP OF A SYNCED GROUP IS NOT EDITABLE — AddGroupMember answers 409
  // idp_managed_group (enterprise/policy/service.go:125). The controls below were gated on
  // canManage ALONE, so every Add/Remove on a directory group was a guaranteed refusal.
  const directoryManaged = isDirectoryManaged(group);
  const canEditMembers = canManage && !directoryManaged;
  const rows = loaded?.ok ? loaded.data : [];
  const inGroup = new Set(rows.map((m) => m.user_id));
  const addable = members.filter((m) => !inGroup.has(m.user_id));

  return (
    <div className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-2">
      {/* ⚠ THE PANEL NAMES ITSELF. Expanded content that opens with a bare list of emails leaves the
          operator to infer what they are looking at and what they may do to it. */}
      <p className="mb-1.5 font-mono text-[10px] uppercase tracking-wide text-ink-tertiary">
        Members of {group.name}
      </p>
      {
        <div>
          {loaded === null && (
            <p className="text-xs text-slate-500">Loading members…</p>
          )}
          {loaded && !loaded.ok && (
            <LoadRetry error={loaded.error} onRetry={fetchMembers} />
          )}
          {loaded?.ok && rows.length === 0 && (
            <p className="text-xs text-slate-500">
              No members. Rules using this group as a source match no device and
              grant nothing.
            </p>
          )}
          {loaded?.ok &&
            rows.map((m) => (
              <div
                key={m.user_id}
                className="flex items-center justify-between py-0.5 text-xs"
              >
                <span className="text-slate-300">{m.name || m.email}</span>
                {canEditMembers && (
                  <Button
                    variant="ghost"
                    disabled={busy}
                    onClick={() =>
                      mutateMembership(() =>
                        api.DELETE(
                          "/api/v1/organizations/{orgId}/groups/{groupId}/members/{userId}",
                          {
                            params: {
                              path: {
                                orgId,
                                groupId: group.id,
                                userId: m.user_id,
                              },
                            },
                          },
                        ),
                      )
                    }
                  >
                    Remove
                  </Button>
                )}
              </div>
            ))}
          {directoryManaged && loaded?.ok && (
            <p className="mt-2 text-xs text-slate-500">
              {DIRECTORY_MANAGED_NOTE}
            </p>
          )}
          {canEditMembers && loaded?.ok && addable.length > 0 && (
            <div className="mt-2 flex gap-2">
              <select
                className="rounded-md border border-white/10 bg-ink-900 px-2 py-1 text-xs text-white disabled:opacity-50"
                aria-label={`Add a member to ${group.name}`}
                defaultValue=""
                disabled={busy}
                onChange={(e) => {
                  const userId = e.target.value;
                  if (!userId) return;
                  e.target.value = "";
                  void mutateMembership(() =>
                    api.POST(
                      "/api/v1/organizations/{orgId}/groups/{groupId}/members",
                      {
                        params: { path: { orgId, groupId: group.id } },
                        body: { user_id: userId },
                      },
                    ),
                  );
                }}
              >
                <option value="">Add a member…</option>
                {addable.map((m) => (
                  <option key={m.user_id} value={m.user_id}>
                    {m.name || m.email}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      }
    </div>
  );
}

/**
 * Rename a group.
 *
 * ⚠ THE NAME IS ALL THAT CHANGES, and rules follow it automatically because they reference the group by ID.
 * Said in the dialog, because the alternative an operator would otherwise assume — that renaming might break
 * their rules — is exactly what would push them back to delete-and-rebuild.
 */
function RenameGroupModal({
  orgId,
  group,
  onClose,
  onDone,
}: {
  orgId: string;
  group: UserGroup;
  onClose: () => void;
  onDone: () => void;
}) {
  const [name, setName] = useState(group.name);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setErr(null);
    const { error } = await api.PATCH(
      "/api/v1/organizations/{orgId}/groups/{groupId}",
      {
        params: { path: { orgId, groupId: group.id } },
        body: { name: name.trim() },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not rename the group."));
    onDone();
  }

  return (
    <Modal
      title="Rename group"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={busy || !name.trim() || name.trim() === group.name}
            onClick={() => void save()}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <Field label="Group name">
        <Input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <p className="mt-2 text-xs text-ink-secondary">
        Rules that use this group keep working — they reference it by identity,
        not by name.
      </p>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

/**
 * Edit a resource.
 *
 * ⛔ CHANGING A CIDR OR A PORT CHANGES WHAT EVERY RULE NAMING IT PERMITS, and it does so silently — the rules
 * themselves do not appear to change. That is the one thing this dialog has to say out loud, because the
 * blast radius is invisible from here.
 */
function EditResourceModal({
  orgId,
  resource,
  onClose,
  onDone,
}: {
  orgId: string;
  resource: Resource;
  onClose: () => void;
  onDone: () => void;
}) {
  const [f, setF] = useState({
    name: resource.name,
    cidr: resource.cidr,
    protocol: resource.protocol as "any" | "tcp" | "udp",
    port_low: resource.port_low != null ? String(resource.port_low) : "",
    port_high: resource.port_high != null ? String(resource.port_high) : "",
    label: resource.label ?? "",
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setErr(null);
    const { error } = await api.PATCH(
      "/api/v1/organizations/{orgId}/resources/{resourceId}",
      {
        params: { path: { orgId, resourceId: resource.id } },
        body: {
          name: f.name.trim(),
          cidr: f.cidr.trim(),
          protocol: f.protocol,
          // Blank means "all ports" — sent as null rather than 0, which would be a port nobody asked for.
          port_low: f.port_low.trim() ? Number(f.port_low) : null,
          port_high: f.port_high.trim() ? Number(f.port_high) : null,
          label: f.label.trim() ? f.label.trim() : null,
        },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not update the resource."));
    onDone();
  }

  return (
    <Modal
      title="Edit resource"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={busy || !f.name.trim() || !f.cidr.trim()}
            onClick={() => void save()}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Name">
          <Input
            value={f.name}
            onChange={(e) => setF({ ...f, name: e.target.value })}
          />
        </Field>
        <Field label="CIDR">
          <Input
            value={f.cidr}
            onChange={(e) => setF({ ...f, cidr: e.target.value })}
          />
        </Field>
        <div className="flex gap-2">
          <Field label="Protocol">
            <Select
              value={f.protocol}
              onChange={(e) =>
                setF({
                  ...f,
                  protocol: e.target.value as "any" | "tcp" | "udp",
                })
              }
            >
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </Select>
          </Field>
          <Field label="Port low (blank = all)">
            <Input
              value={f.port_low}
              onChange={(e) => setF({ ...f, port_low: e.target.value })}
            />
          </Field>
          <Field label="Port high">
            <Input
              value={f.port_high}
              onChange={(e) => setF({ ...f, port_high: e.target.value })}
            />
          </Field>
        </div>
        <Field label="Label (optional note)">
          <Input
            value={f.label}
            onChange={(e) => setF({ ...f, label: e.target.value })}
          />
        </Field>
        {/* ⛔ THE INVISIBLE BLAST RADIUS, STATED. */}
        <p className="text-xs text-warn">
          Changing the CIDR, protocol or ports changes what every rule using
          this resource permits. The rules themselves will not look any
          different.
        </p>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}
