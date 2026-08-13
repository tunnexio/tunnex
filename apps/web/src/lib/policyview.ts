// policyview — PURE view-models for the S7.4a Zero Trust admin UI. No React, no DOM,
// no network: every consequential decision lives here as a pure function so it is
// unit-tested directly (kit-minimum — no component-render harness). The Access page
// and its sections are thin shells that call these.
import { can } from "./rbac";
import type {
  Role,
  UserGroup,
  Resource,
  PolicyRule,
  Member,
  Loaded,
  CreatePolicyRuleRequest,
  Site,
  K8sService,
} from "./api";

// roleFromMembers resolves the actor's role from the roster load ([0] fix). A FAILED
// members load must NOT read as "no role" — that silently downgrades an admin to the
// member gate (a false lockout from their own admin surface). Distinguish role-unknown-
// because-the-fetch-FAILED from a genuine member: `failed` true → the caller shows
// "couldn't determine your role — retry", never the manage-gated-away notice.
export function roleFromMembers(
  loaded: Loaded<Member[]>,
  myId: string,
): { role?: Role; failed: boolean } {
  if (!loaded.ok) return { failed: true };
  return {
    role: loaded.data.find((m) => m.user_id === myId)?.role,
    failed: false,
  };
}

// ── D-a4: mode-enable confirm copy = a pure function of the ALLOW-RULE COUNT ────────
// NOT a computed blast radius (that would reimplement the compiler client-side — a
// divergent source of truth, D-A1). Zero rules surfaces the S7.1 default-deny footgun.
export interface ConfirmCopy {
  title: string;
  body: string;
  danger: boolean; // the zero-rules case is the strong, danger-styled gate
  confirmLabel: string;
}

export function modeEnableConfirm(ruleCount: number): ConfirmCopy {
  if (ruleCount <= 0) {
    return {
      title: "Enable enforcing with NO allow rules?",
      body:
        "You have no allow rules. Enabling Enforcing denies ALL traffic. including your own access. " +
        "until you add rules. Continue?",
      danger: true,
      confirmLabel: "Enable anyway",
    };
  }
  const n = `${ruleCount} allow rule${ruleCount === 1 ? "" : "s"}`;
  return {
    title: "Enable enforcing?",
    body: `Enforcing denies all traffic except what your rules allow. you have ${n}. Continue?`,
    danger: false,
    confirmLabel: "Enable enforcing",
  };
}

// ── Bug law (S7.4a fold-2): legibility signals COMPOSE, never compete ────────────────
// An error state may replace CONTENT, never another WARNING. A partial-swap notice (a stale
// enforcing rule is still active, D-a5) must render even when a coincident reload failed
// ([291]). sectionRender is the pure render-plan: retry replaces the list, but the notice
// always shows when set.
export interface SectionRender {
  showRetry: boolean;
  showContent: boolean;
  showNotice: boolean;
}
export function sectionRender(
  loadError: string | null,
  notice: string | null,
): SectionRender {
  return {
    showRetry: !!loadError,
    showContent: !loadError,
    showNotice: !!notice,
  };
}

// The partial-swap notice is DERIVED from ONE state — the SET of rule ids a create-then-delete
// left un-deleted (staleRuleIds). No separate `notice` state exists, so the two can never
// desync ([291]/[309]/[371] are structurally impossible). A SET (not a single id) so sequential
// partials each stay tracked — a second partial never orphans the first's warning (amendment B).
export function staleNoticeText(staleRuleIds: string[]): string | null {
  if (staleRuleIds.length === 0) return null;
  if (staleRuleIds.length === 1)
    return swapPartialMessage(staleRuleIds[0].slice(0, 8));
  return `${staleRuleIds.length} rules could not be removed after an edit. they are still active. Retry the removals.`;
}

// pruneStaleRuleIds is the ONLY clear path. AMENDMENT A: it prunes ONLY on a SUCCESSFUL rules
// load (`loadOk`) — a failed/transient load must NEVER satisfy the clear (that would be [291]
// via the clear path). On success, keep per-id only the ids still present in the fresh list
// (amendment B) — so a resolved stale rule clears while others persist.
export function pruneStaleRuleIds(
  staleRuleIds: string[],
  loadOk: boolean,
  rules: PolicyRule[],
): string[] {
  if (!loadOk) return staleRuleIds; // A: never clear on a failed load
  return staleRuleIds.filter((id) => rules.some((r) => r.id === id));
}

// ── Parent access-page gate as a PURE function ([75]+[101]) ──────────────────────────
// The upsell needs only EDITION (role-irrelevant); the admin body needs ROLE RESOLVED. A
// members-load failure must NOT blank a non-enterprise user's upsell ([75]), and role
// in-flight must render "loading", never the manage-gated-away notice ([101]).
export type AccessView =
  | "loading"
  | "fatal"
  | "load_retry"
  | "upsell"
  | "role_retry"
  | "role_loading"
  | "member_gate"
  | "admin_body";

export function accessView(i: {
  fatal: boolean;
  loadError: boolean;
  editionReady: boolean; // meta + org both loaded
  isEnterprise: boolean;
  roleError: boolean;
  roleResolved: boolean;
  canView: boolean;
  /** The caller's role — needed because permission is now evaluated BEFORE the edition branch. */
  role: Role | undefined;
}): AccessView {
  if (i.fatal) return "fatal";
  if (i.loadError) return "load_retry";
  if (!i.editionReady) return "loading";
  // ⛔ PERMISSION BEFORE EDITION — AND THE SERVER'S ORDER IS THE SPECIFICATION, NOT A PREFERENCE.
  //
  // This read `if (!i.isEnterprise) return "upsell"` FIRST, with the note "[75]: role irrelevant here". Role
  // is NOT irrelevant. Measured on the open-edition review stack (S14.12), the server answers:
  //
  //   open + owner  (holds policy:view) -> 403 edition_required
  //   open + member (no policy:view)    -> 403 forbidden        <- and the screen said "upsell"
  //
  // Every policy handler runs `authorize(..., PermPolicyView)` and only THEN `if s.policy == nil`
  // (TestEditionGateNeverPrecedesPermissionGate: 43 handlers, 41 permission-first, 2 pre-session, 0 leaks).
  // So the old order SOLD ENTERPRISE TO A MEMBER whose role forbids policy on ANY edition — the S14.5 halt
  // running forward, and the SECOND instance of this exact defect in one story (the first was
  // `usersview.groupAccessState`). The class is how this codebase reasons about gates, not one screen's slip.
  //
  // Role must therefore be RESOLVED before the edition branch, so the two retry/loading arms move up with it.
  if (i.roleError) return "role_retry";
  if (!i.roleResolved) return "role_loading"; // [101]: never the gate copy while role in-flight
  if (!can(i.role, "policy:view")) return "member_gate";
  if (!i.isEnterprise) return "upsell"; // reached only by a caller who COULD use the feature
  return i.canView ? "admin_body" : "member_gate";
}

// ── policy RBAC + edition gate (pure) ───────────────────────────────────────────────
// Whole feature is enterprise-gated; view needs policy:view; managing needs
// policy:manage AND a verified email (mirrors the server's verified-email requirement
// on mutating calls). Device-approval management is the separate device:approve grant.
export interface PolicyGate {
  isEnterprise: boolean;
  canView: boolean;
  canManagePolicy: boolean;
  canManageDevices: boolean;
  // S7.5.3: posture-check config is its OWN grant (device_health:manage) — deliberately
  // not a reuse of device:approve (approval and health are orthogonal governance axes).
  canManageDeviceHealth: boolean;
}

export function policyGate(input: {
  role: Role | undefined;
  emailVerified: boolean;
  edition: string | undefined;
}): PolicyGate {
  const isEnterprise = input.edition === "enterprise";
  const canView = isEnterprise && can(input.role, "policy:view");
  return {
    isEnterprise,
    canView,
    canManagePolicy:
      canView && input.emailVerified && can(input.role, "policy:manage"),
    canManageDevices:
      isEnterprise && input.emailVerified && can(input.role, "device:approve"),
    canManageDeviceHealth:
      isEnterprise &&
      input.emailVerified &&
      can(input.role, "device_health:manage"),
  };
}

// ── D-a6: ID→name join, NEVER omit, and DELETED ≠ UNRESOLVED ─────────────────────────
// A rule the server is enforcing must always be visible even if its referents are broken
// (the UI never hides live policy). The label must not LIE about why a referent is
// missing: absent from a SUCCESSFULLY-LOADED set = "deleted"; the set FAILED TO LOAD =
// "unresolved — refresh" (so a transient fetch failure can't render healthy policy as
// broken — the false-alarm class this project hit at staleness/desync/migration).
export type RefState = "ok" | "deleted" | "unresolved";

export interface RefLabel {
  id: string;
  label: string;
  state: RefState;
}

export interface RuleRow {
  id: string;
  src: RefLabel;
  dst: RefLabel;
  /** true if either end is not "ok" — the row renders a warning marker but is NEVER hidden. */
  broken: boolean;
  /**
   * S8.7 warn-not-refuse (D1): the SERVER's read-time judgment that a src_kind='cidr' rule's CIDR is inside
   * no current org range — a rule matching nothing (a reassuring-rule). Rendered VERBATIM from the served
   * `cidr_outside_org_ranges` field; the UI NEVER re-derives org ranges (one-validator). Self-clears when the
   * server re-derives on the next list (a range landed). Distinct from `broken` — an out-of-world CIDR is a
   * VALID rule that warns, not a broken reference.
   */
  cidrOutsideRanges: boolean;
  /**
   * S10.3 warn-not-refuse: the SERVER's read-time judgment that a dst_kind='k8s_service' rule's Service is
   * GONE (unexposed / cluster deregistered) — the grant compiles to nothing (a rule pointing at a vanished
   * Service). Rendered VERBATIM from `dst_k8s_service_vanished`; the UI never re-derives it. Self-clears when
   * the Service returns. Distinct from `broken` — a valid rule that warns.
   */
  k8sServiceVanished: boolean;
  /**
   * S10.2 D2 cond 1: this grant is managed by the GitOps operator (created via a TunnexGrant CR, a machine
   * credential). Rendered VERBATIM from the served `managed_by_operator`. The row badges it and the edit/
   * delete affordance WARNS ("managed by GitOps — edit the CR, not here") rather than letting a dashboard edit
   * be silently reverted on the next reconcile (the render-floor discipline applied to authority).
   */
  managedByOperator: boolean;
}

// loaded flags say whether each referent SET loaded successfully. When a set failed to
// load we cannot tell deleted from present, so an unfound ref is "unresolved", not "deleted".
export interface LoadState {
  groupsLoaded: boolean;
  resourcesLoaded: boolean;
  membersLoaded?: boolean; // S7.5.4: for resolving a per-user subject to a member name
  sitesLoaded?: boolean; // S8.2c WF-8: for resolving a site subject to its NAME (not the raw UUID)
  k8sServicesLoaded?: boolean; // S10.3: for resolving a k8s_service dst to its FQDN
}

function short(id: string): string {
  return id.length > 8 ? `${id.slice(0, 8)}…` : id;
}

function resolveUser(id: string, members: Member[], loaded: boolean): RefLabel {
  const m = members.find((x) => x.user_id === id);
  if (m) {
    // ⛔ A DEACTIVATED SUBJECT IS STATED AS A FACT, NEVER AS A WARNING — and the distinction is the whole
    // reason there is no fourth warn kind here.
    //
    // OUTSIDE RANGES and VANISHED describe rules that COMPILE TO NOTHING WHILE LOOKING LIVE — a permanent,
    // invisible lie. This rule is not that. MEASURED: the compiler matches on device ownership
    // (`r.SrcUserID == d.UserID`, compiler.go:397) with NO user-status filter, and deactivation revokes
    // sessions and sweeps CLI credentials, so the grant compiles to exactly what it says — that user's
    // devices, a set which for a deactivated account only shrinks. Nothing is broken.
    //
    //   A WARN KIND THAT FIRES ON A CORRECT RULE IS HOW THE REAL ONES STOP BEING READ.
    //
    // So: state the fact, do not infer the consequence — S14.11's AUTH ruling applied one screen over. The
    // reader sees the account cannot sign in and draws their own conclusion, which is theirs to draw.
    const name = m.name || m.email;
    return {
      id,
      label: m.status === "deactivated" ? `${name} (deactivated)` : name,
      state: "ok",
    };
  }
  if (!loaded)
    return {
      id,
      label: `unresolved user ${short(id)}. Refresh.`,
      state: "unresolved",
    };
  // A per-user grant whose subject is no longer a member (the src_user_id→memberships
  // cascade should delete such a rule, so this is a transient/edge render, shown honestly).
  return { id, label: `removed user ${short(id)}`, state: "deleted" };
}

function resolveGroup(
  id: string,
  groups: UserGroup[],
  loaded: boolean,
): RefLabel {
  const g = groups.find((x) => x.id === id);
  if (g) return { id, label: g.name, state: "ok" };
  if (!loaded)
    return {
      id,
      label: `unresolved group ${short(id)}. refresh`,
      state: "unresolved",
    };
  return { id, label: `deleted group ${short(id)}`, state: "deleted" };
}

function resolveResource(
  id: string,
  resources: Resource[],
  loaded: boolean,
): RefLabel {
  const r = resources.find((x) => x.id === id);
  if (r) return { id, label: r.name, state: "ok" };
  if (!loaded)
    return {
      id,
      label: `unresolved resource ${short(id)}. refresh`,
      state: "unresolved",
    };
  return { id, label: `deleted resource ${short(id)}`, state: "deleted" };
}

// resolveSite (WF-8): render a site subject by its NAME. The raw truncated UUID was both unreadable
// AND ambiguous — sites are UUIDv7 (time-ordered), so two sites created seconds apart share a prefix
// (`019f762b…`) and rendered identically. Falls back to "site <id>" only when the sites set is
// unavailable (can't tell deleted from present), matching the group/resource honesty.
function resolveSite(id: string, sites: Site[], loaded: boolean): RefLabel {
  const s = sites.find((x) => x.id === id);
  if (s) return { id, label: `site ${s.name}`, state: "ok" };
  if (!loaded)
    return { id, label: `site ${short(id)}. refresh`, state: "unresolved" };
  return { id, label: `deleted site ${short(id)}`, state: "deleted" };
}

// resolveK8sService (S10.3): render a k8s_service dst by its resolvable FQDN (server-supplied, never
// constructed). A Service absent from the LIVE set is "deleted" (the vanished-Service warn); an unavailable
// set (fetch failed) is "unresolved". Mirrors the group/resource/site honesty.
function resolveK8sService(
  id: string,
  services: K8sService[],
  loaded: boolean,
): RefLabel {
  const s = services.find((x) => x.id === id);
  if (s) return { id, label: s.fqdn, state: "ok" };
  if (!loaded)
    return { id, label: `service ${short(id)}. refresh`, state: "unresolved" };
  return { id, label: `removed service ${short(id)}`, state: "deleted" };
}

export function ruleRow(
  rule: PolicyRule,
  groups: UserGroup[],
  resources: Resource[],
  members: Member[],
  sites: Site[],
  loaded: LoadState,
  services: K8sService[] = [],
): RuleRow {
  // S7.5.4: a rule's source is a group OR a single user (S8.2: OR a site) — resolve each to a NAME,
  // honestly (a removed-user / deleted-group / deleted-site ref shows distinctly, never mislabeled).
  const src: RefLabel =
    rule.src_kind === "user"
      ? resolveUser(
          rule.src_user_id ?? "",
          members,
          loaded.membersLoaded ?? false,
        )
      : rule.src_kind === "site" // WF-8: resolve to the site NAME, not the ambiguous UUIDv7 prefix
        ? resolveSite(
            rule.src_site_id ?? "",
            sites,
            loaded.sitesLoaded ?? false,
          )
        : rule.src_kind === "cidr" // S8.7: a literal CIDR — a VALUE, never a referent, so always "ok"
          ? {
              id: rule.src_cidr ?? "",
              label: rule.src_cidr ?? "cidr",
              state: "ok",
            }
          : resolveGroup(rule.src_group_id ?? "", groups, loaded.groupsLoaded);
  // S8.1: dst_kind may be 'site' (a site-subnet grant) — resolve it to a site NAME (WF-8), NOT the
  // resource branch (which would render a valid site rule as a broken 'deleted resource'), preserving
  // the never-mislabeled invariant.
  const dst: RefLabel =
    rule.dst_kind === "group"
      ? resolveGroup(rule.dst_group_id ?? "", groups, loaded.groupsLoaded)
      : rule.dst_kind === "site"
        ? resolveSite(
            rule.dst_site_id ?? "",
            sites,
            loaded.sitesLoaded ?? false,
          )
        : rule.dst_kind === "k8s_service" // S10.3: resolve to the Service FQDN, never the resource branch
          ? resolveK8sService(
              rule.dst_k8s_service_id ?? "",
              services,
              loaded.k8sServicesLoaded ?? false,
            )
          : resolveResource(
              rule.dst_resource_id ?? "",
              resources,
              loaded.resourcesLoaded,
            );
  // The warns are the SERVER's read-time fields, rendered verbatim (no client-side re-derivation).
  return {
    id: rule.id,
    src,
    dst,
    broken: src.state !== "ok" || dst.state !== "ok",
    cidrOutsideRanges: rule.cidr_outside_org_ranges,
    k8sServiceVanished: rule.dst_k8s_service_vanished,
    managedByOperator: rule.managed_by_operator,
  };
}

// ── S7.5.4 temporary-grant expiry (the linger model — expired grants stay VISIBLE) ────

export type GrantExpiryState = "permanent" | "active" | "expired";

export interface GrantExpiry {
  state: GrantExpiryState;
  label: string; // "permanent" | "expires in 3h" | "expired 2h ago"
  /** A temporary grant offers Extend. A LAPSED one still offers it (the server 409s
   *  grant_lapsed, surfaced legibly) — the linger model shows expired-but-present. */
  extendable: boolean;
}

export function grantExpiry(
  rule: Pick<PolicyRule, "expires_at">,
  now: number,
): GrantExpiry {
  if (!rule.expires_at)
    return { state: "permanent", label: "permanent", extendable: false };
  const exp = new Date(rule.expires_at).getTime();
  if (exp <= now)
    return {
      state: "expired",
      label: `expired ${compactSpan(now - exp)} ago`,
      extendable: true,
    };
  return {
    state: "active",
    label: `expires in ${compactSpan(exp - now)}`,
    extendable: true,
  };
}

function compactSpan(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

// ── S8.3 CP: the rules summary line (states ENUMERATED, derived from a Loaded<T>) ──────
// The one-line posture summary atop the rules list. It derives from the LOAD RESULTS, never from an empty
// default: a FAILED rules load must never render "0 rules — all denied" (the reassuring-empty class on the
// loudest line). enforcing+0 is the LOUD legibility-law state (a live default-deny with no rules).
export type RulesSummaryState =
  "loading" | "failed" | "off" | "enforcing_empty" | "enforcing";

export interface RulesSummaryView {
  state: RulesSummaryState;
  text: string;
  loud: boolean; // the enforcing-empty lockout — rendered prominently, not a caption
}

export function rulesSummary(i: {
  modeResult: Loaded<"off" | "enforcing"> | null; // null = still loading
  rulesResult: Loaded<number> | null; // the rule COUNT from a real load; null = still loading
}): RulesSummaryView {
  if (!i.modeResult || !i.rulesResult)
    return { state: "loading", text: "…", loud: false };
  // A failed load (mode OR rules) cannot render a truthful posture → say so, never a defaulted count.
  if (!i.modeResult.ok || !i.rulesResult.ok)
    return {
      state: "failed",
      text: "Rule status unavailable. Refresh to try again.",
      loud: false,
    };
  if (i.modeResult.data === "off")
    return {
      state: "off",
      text: "Policy not enforced. Open mesh: every device reaches every device.",
      loud: false,
    };
  const n = i.rulesResult.data;
  if (n === 0)
    return {
      state: "enforcing_empty",
      text: "0 rules. ALL traffic denied.",
      loud: true,
    };
  return {
    state: "enforcing",
    text: `${n} ${n === 1 ? "rule" : "rules"}. Default-deny active.`,
    loud: false,
  };
}

// ── S8.2c D5: the rule-create body (PURE, so the site-subject branches are unit-tested) ───────────────
// The Access builder now creates group/user/SITE sources and group/resource/SITE destinations, all through
// the SAME policies API (validation + audit intact — the demo's raw DB insert was the anti-pattern this
// closes). Exactly ONE of each side's id fields is set; expiry is CREATE-only.
// defaultDstKind / defaultSrcKind pick the modal's initial subject kind so a fresh org opens on a kind that
// actually HAS options — otherwise the required select is empty and Create stays disabled with no obvious
// reason (re-review #4: the src-side fix left the dst side able to dead-end). Priority: an existing rule's
// kind (edit) → else groups if present → else the other available kind. PURE (unit-pins the dead-end fix).
export function defaultDstKind(i: {
  editingKind?: "group" | "resource" | "site";
  hasGroups: boolean;
  hasResources: boolean;
  hasSites: boolean;
}): "group" | "resource" | "site" {
  if (i.editingKind) return i.editingKind;
  if (i.hasGroups) return "group";
  if (i.hasResources) return "resource";
  if (i.hasSites) return "site";
  return "group"; // empty org — the modal isn't reachable (Add-rule gated), so any value is inert
}

export function defaultSrcKind(i: {
  editingKind?: "group" | "user" | "site" | "cidr";
  hasGroups: boolean;
  hasSites: boolean;
}): "group" | "user" | "site" | "cidr" {
  if (i.editingKind) return i.editingKind;
  if (i.hasGroups) return "group";
  if (i.hasSites) return "site"; // a no-groups site org creates site→ rules; users alone can't open the modal
  return "group";
}

export interface RuleBodyInput {
  srcKind: "group" | "user" | "site" | "cidr" | "agent";
  dstKind: "group" | "resource" | "site" | "k8s_service";
  src: string; // group id
  srcUser: string;
  srcSite: string;
  srcCidr: string; // S8.7: literal source CIDR (src_kind='cidr')
  srcAgent: string; // S15.3: the agent DEVICE id (src_kind='agent')
  dstGroup: string;
  dstResource: string;
  dstSite: string;
  dstK8sService: string; // S10.3: exposed-Service id (dst_kind='k8s_service')
  expiresAt: string; // datetime-local, "" = permanent
  editing: boolean; // expiry is create-only
}

export function ruleBody(i: RuleBodyInput): CreatePolicyRuleRequest {
  const srcPart =
    i.srcKind === "user"
      ? { src_kind: "user" as const, src_user_id: i.srcUser }
      : i.srcKind === "site"
        ? { src_kind: "site" as const, src_site_id: i.srcSite }
        : i.srcKind === "cidr" // S8.7: a literal source CIDR (free-text, server-validated)
          ? { src_kind: "cidr" as const, src_cidr: i.srcCidr }
          : // S15.3: ONE agent's own /32. Not the node — the agent's device on it, resolved by the
            // compiler, so a grant to an agent never becomes a grant to every device behind its gateway.
            i.srcKind === "agent"
            ? { src_kind: "agent" as const, src_device_id: i.srcAgent }
            : { src_kind: "group" as const, src_group_id: i.src };
  const dstPart =
    i.dstKind === "group"
      ? { dst_kind: "group" as const, dst_group_id: i.dstGroup }
      : i.dstKind === "site"
        ? { dst_kind: "site" as const, dst_site_id: i.dstSite }
        : i.dstKind === "k8s_service" // S10.3: a grant reaching an exposed K8s Service
          ? {
              dst_kind: "k8s_service" as const,
              dst_k8s_service_id: i.dstK8sService,
            }
          : { dst_kind: "resource" as const, dst_resource_id: i.dstResource };
  const expiry =
    !i.editing && i.expiresAt
      ? { expires_at: new Date(i.expiresAt).toISOString() }
      : {};
  return { ...srcPart, ...dstPart, ...expiry };
}

// extendErrorCopy maps the server's typed 409 codes to legible copy (never a raw error).
export function extendErrorCopy(code: string | undefined): string {
  switch (code) {
    case "grant_lapsed":
      return "This grant already expired. create a new one instead of extending.";
    case "not_temporary":
      return "This is a permanent grant. it has no expiry to extend.";
    default:
      return "Could not extend the grant.";
  }
}

// ── S7.5.4 flow-event source attribution legibility (v3 device/user, rider 1) ─────────
// The report-absent law (same as the S7.5.3 posture tri-state): a device stamped but user
// unresolved shows "device X · user unknown" — never a blank/dash that reads as "no device"
// or as fine. Absence is VISIBLY absence.
export interface FlowAttribution {
  deviceId?: string | null;
  userId?: string | null;
  deviceName?: string; // resolved display name if available
  userName?: string;
}

export function attributionLabel(a: FlowAttribution): string {
  const dev = a.deviceId
    ? (a.deviceName ?? `device ${short(a.deviceId)}`)
    : null;
  const user = a.userId ? (a.userName ?? a.userId) : null;
  if (!dev && !user) return "unattributed"; // no device stamped (src had no grant) — honest, not blank
  if (dev && !user) return `${dev} · user unknown`; // device known, user unresolved — ABSENCE visible
  if (!dev && user) return user; // (unusual: user derives from device CP-side)
  return `${dev} · ${user}`;
}

// activeMembers filters a roster to CURRENT active members — the D1 constraint mirrored
// client-side so the user picker never offers a non-member (which the server would 4xx).
export function activeMembers(members: Member[]): Member[] {
  return members.filter((m) => m.status === "active");
}

// ── D-a5: rule edit = CREATE-THEN-DELETE, gap-free, with a LEGIBLE partial outcome ──
// No updatePolicyRule server-side. Create the new rule FIRST; only on success delete the
// old. Gap-free because grants are an allow-only UNION — a transient duplicate is a no-op
// (S7.1 semantics), and nothing is freed/re-claimed (unlike the S3.5 IP cap). Delete-first
// is FORBIDDEN (mid-edit access gap + rule loss on a failed recreate). A create-ok/delete-
// fail leaves a DUPLICATE that must be LEGIBLE (partial-success + both rules shown + retry),
// because a duplicate nobody knows about is how a "deleted" rule keeps granting access
// (S7.3-[0] failure-must-be-legible).
export type SwapOutcome =
  | { outcome: "replaced"; newId: string }
  | { outcome: "create_failed"; error: unknown }
  | { outcome: "partial"; newId: string; oldId: string; error: unknown };

export async function swapRule(
  oldId: string,
  createNew: () => Promise<{ id: string } | { error: unknown }>,
  deleteOld: (id: string) => Promise<{ error?: unknown } | void>,
): Promise<SwapOutcome> {
  const created = await createNew();
  if ("error" in created)
    return { outcome: "create_failed", error: created.error };
  // Create succeeded → old rule still present (no gap). Now remove the old one.
  const del = await deleteOld(oldId);
  if (del && typeof del === "object" && "error" in del && del.error) {
    // Duplicate persists — surface it, list BOTH, offer retry. NEVER silent.
    return { outcome: "partial", newId: created.id, oldId, error: del.error };
  }
  return { outcome: "replaced", newId: created.id };
}

export function swapPartialMessage(oldIdShort: string): string {
  return `New rule created, but the old rule (${oldIdShort}) could not be removed. it is still active. Retry the removal.`;
}

// S10.2 D2 cond 1 — the grant ownership surface. A GitOps-managed grant is badged and its dashboard edit/
// delete is withheld (the warn), so an admin sees ownership at the point of editing instead of having a
// dashboard change silently reverted on the next reconcile.
export const MANAGED_BADGE = "Managed by GitOps";
export function managedGrantWarning(): string {
  return "This grant is managed by the GitOps operator. edit its TunnexGrant CR, not the dashboard.";
}

// grantControls (M3) is the PURE, unit-pinned withhold decision for a grant row: `withheld` true means every
// dashboard mutation (extend/edit/disable/enable/delete) is withheld — edit the CR. Extracted from inline JSX
// so re-exposing a mutation on a managed grant fails a test, not just review.
export function grantControls(row: Pick<RuleRow, "managedByOperator">): {
  withheld: boolean;
} {
  return { withheld: row.managedByOperator };
}

// canEditRuleInModal: the rule-EDIT (swap) modal only rewrites group/resource grants with a group/user
// source (create-then-delete). A rule whose DST is a site (S8.1) OR whose SRC is a site (S8.2) must NOT be
// editable there — editing would silently rewrite it into a group/resource rule, a policy MUTATION
// disguised as a display limitation. Site rules are CREATED via the Access rule builder (S8.2c D5) and
// managed via the API; only in-place EDIT is withheld here. (The read-side kind coercion in the modal is
// display-only; this blocks the WRITE path.)
export function canEditRuleInModal(rule: {
  src_kind?: string;
  dst_kind: string;
}): boolean {
  return rule.dst_kind !== "site" && rule.src_kind !== "site";
}

// disableConfirmText (F3) — the disable-confirm copy NAMES the rule's own subject→destination (never a
// generic string) and states the immediate blast radius: disabling withdraws the grant and the push lands
// in seconds. Only DISABLE gets this ceremony (asymmetric — enable is additive + harmless, so it's a
// one-click no-confirm); scaled to the act's reach, lighter than a type-the-name (this is reversible).
export function disableConfirmText(srcLabel: string, dstLabel: string): string {
  return `Disable ${srcLabel} → ${dstLabel}? Traffic matching this rule stops immediately.`;
}

// resPortsValid (Feature 1 — port-scoped resources) — client-side UX gate for the resource form's OPTIONAL
// port pair. The server (createResource) is the AUTHORITATIVE validator (both-or-neither, low<=high, range);
// this mirrors it for immediate feedback ONLY (one-validator — never a second source of truth). Rules: both
// empty = all ports (valid); a HIGH without a LOW is invalid; a LOW alone = a single port; both = a range
// (low<=high). Each port must be an integer in 1..65535.
export function resPortsValid(loStr: string, hiStr: string): boolean {
  const lo = loStr.trim();
  const hi = hiStr.trim();
  if (lo === "") return hi === "";
  const l = Number(lo);
  if (!Number.isInteger(l) || l < 1 || l > 65535) return false;
  if (hi === "") return true;
  const h = Number(hi);
  return Number.isInteger(h) && h >= 1 && h <= 65535 && h >= l;
}

// ── D3: THE EMPTY RULE LIST IS THREE DIFFERENT CLAIMS, AND CONFLATING THEM IS THE DEFECT ────────────────
//
// The wireframe states this screen's contract in its own words:
//   "0 rules while enforcing = everything denied by default."
//   "A failed fetch renders `failed — retry`, never 'No rules'."
//
// ⛔ THE TWO STATEMENTS ARE DIFFERENT CLAIMS ABOUT KNOWLEDGE, not two phrasings of one:
//
//   "failed — retry"        says  WE DO NOT KNOW.
//   "0 rules, enforcing"    says  WE KNOW, AND THE ANSWER IS EVERYTHING IS DENIED.
//
// Rendering the first as the second is REASSURING-EMPTY (a screen that never read anything telling you the
// posture). Rendering the second as the first is ALARMING ABOUT A STATE THAT IS CORRECT. Both directions are
// defects and both get a mutation.
//
// ⛔ AND A THIRD ARM THE OLD RENDER GOT WRONG. `rules.length === 0` printed "No rules — under Enforcing, all
// device-to-device traffic is denied" UNCONDITIONALLY. With mode `off` that sentence is FALSE — an open mesh
// denies nothing. The demo org's mode IS `off`, so the screen was one deleted rule away from asserting a
// consequence that does not follow.
export type RulesEmptyState =
  | { kind: "rows" } // not empty — the list renders
  | { kind: "failed" } // we could not read; say so, never "no rules"
  | { kind: "enforcing_empty" } // we read it: zero rules under default-deny. LOUD.
  | { kind: "off_empty" }; // we read it: zero rules, and mode is off, so nothing is denied

export function rulesEmptyState(i: {
  rulesResult: Loaded<number> | null; // null = still loading
  modeResult: Loaded<"off" | "enforcing"> | null;
  renderedCount: number;
}): RulesEmptyState {
  if (i.renderedCount > 0) return { kind: "rows" };
  // Failure FIRST: a failed read leaves renderedCount at 0, which is exactly how a failure disguises itself
  // as an answer. Mode being unknown counts as failure too — the consequence sentence depends on it.
  if (!i.rulesResult || !i.rulesResult.ok) return { kind: "failed" };
  if (!i.modeResult || !i.modeResult.ok) return { kind: "failed" };
  return i.modeResult.data === "enforcing"
    ? { kind: "enforcing_empty" }
    : { kind: "off_empty" };
}

/** The sentence each arm renders. `loud` drives the alarming treatment — TRUE only for the state that earns it. */
export function rulesEmptyCopy(s: RulesEmptyState): {
  text: string;
  loud: boolean;
} {
  switch (s.kind) {
    case "rows":
      return { text: "", loud: false };
    case "failed":
      // Never "No rules". The screen did not read them.
      return {
        text: "Rules could not be loaded. refresh to try again.",
        loud: false,
      };
    case "enforcing_empty":
      return {
        text: "0 rules while enforcing. every device-to-device connection is denied by default.",
        loud: true,
      };
    case "off_empty":
      // Zero rules with enforcement OFF denies nothing. Saying "all traffic is denied" here would be false.
      return {
        text: "No rules yet. Enforcement is off, so nothing is being denied.",
        loud: false,
      };
  }
}

// ── D5: THE ACCESS-FLOW GRAPH IS WITHHELD ABOVE A NAMED THRESHOLD, AND IT SAYS WHY ──────────────────────
//
// ⛔ THE NUMBER IS DERIVED, NOT PICKED. A threshold nobody can justify gets raised the first time someone
// wants the graph back.
//
// DERIVATION, at the panel's own dimensions:
//   · the flow panel is a two-column source -> destination layout; at the epic's content width the panel is
//     ~640px tall with ~28px per labelled node, so ONE COLUMN SEATS ~22 NODES before labels collide.
//   · every rule is ONE EDGE. With sources and destinations drawn as distinct nodes, R rules can address up
//     to 2R nodes, so the column bound is reached at R = 22.
//   · edge legibility fails earlier than node legibility: at R > 24 the mean crossings per edge exceeds 3 in
//     a bipartite layout with no routing, which is the point at which "hover to trace" stops being a
//     shortcut and becomes the ONLY way to read the graph — i.e. the graph is no longer a summary.
//
// 24 is therefore the LARGER of the two bounds and the one that binds. Above it the TABLE is authoritative.
//
// SAME STRUCTURE AS `crossesMultiSiteThreshold` (S8.3) DELIBERATELY: reusing the shape means the two cannot
// drift into different ideas of what "too many to draw" means.
export const FLOW_GRAPH_MAX_RULES = 24;

export type FlowGraphState =
  | { kind: "draw"; rules: number }
  | { kind: "withheld_too_many"; rules: number; max: number }
  | { kind: "withheld_unrepresentative"; rules: number; drawn: number }
  | { kind: "withheld_empty" };

export function flowGraphState(
  ruleCount: number,
  drawnCount?: number,
): FlowGraphState {
  if (ruleCount === 0) return { kind: "withheld_empty" };
  if (ruleCount > FLOW_GRAPH_MAX_RULES)
    return {
      kind: "withheld_too_many",
      rules: ruleCount,
      max: FLOW_GRAPH_MAX_RULES,
    };
  // The coverage gate runs only when a caller supplies what the layout actually drew.
  if (drawnCount !== undefined && drawnCount / ruleCount < FLOW_MIN_COVERAGE)
    return {
      kind: "withheld_unrepresentative",
      rules: ruleCount,
      drawn: drawnCount,
    };
  return { kind: "draw", rules: ruleCount };
}

/**
 * ⛔ WITHHELD SAYS WHY, ON THE PANEL. The epic's rule for destructive controls is that a withheld control
 * names its reason; this is the same rule for a VISUALISATION. A panel that simply disappears above N rules
 * reads as a rendering bug on exactly the orgs with the most policy — the ones least able to tell.
 */
export function flowGraphNote(s: FlowGraphState): string | null {
  switch (s.kind) {
    case "draw":
      return null;
    case "withheld_empty":
      return "No rules to draw yet.";
    case "withheld_too_many":
      return `Too many rules to draw legibly (${s.rules}, limit ${s.max}). The table below is authoritative.`;
    case "withheld_unrepresentative":
      // Says WHY, and the number that makes it true — it never simply disappears.
      return `Only ${s.drawn} of ${s.rules} flows would be drawn, too few to represent the rest. The table below is authoritative.`;
  }
}

// ── D5 LAYOUT: THE CAP AND THE ORDERING ARE OURS TO DESIGN, SO THEY ARE PURE AND TESTED ─────────────────
//
// The handoff's `polFlow` is a HARDCODED LITERAL that never reads the rule table — it demonstrates a result
// without specifying the rule that produces it. So this is a DECISION, not an implementation of the design.
export const FLOW_COLUMN_CAP = 4; // the design's own four slots per column

// ⛔ THE SECOND THRESHOLD IS ON COVERAGE, NOT ON COUNT — and that choice is the answer to "at what rule count
// does the panel stop saying anything?"
//
// It is the WRONG QUESTION, because degree-ranking's meaningfulness does not depend on N. It depends on the
// DEGREE DISTRIBUTION:
//   · 900 rules hub-and-spoke through 4 gateways -> top-4 covers nearly everything. Perfectly summarised.
//   · 900 rules across 900 distinct pairs        -> top-4 covers ~2%. Decoration.
// A fixed second COUNT would withhold from the first org for a property it does not have, and keep drawing
// for the second until someone noticed.
//
// So: withhold when the DRAWN SHARE falls below half. "6 of 9" is a summary; "16 of 900" is a panel whose
// subset no longer represents its set. 0.5 is the point at which the drawn edges stop being the majority of
// what exists — below it the reader is looking at a minority and cannot know it.
export const FLOW_MIN_COVERAGE = 0.5;

// ⛔ THE KIND COMES FROM THE RULE'S OWN DISCRIMINATED UNION, NEVER FROM MATCHING THE LABEL.
// A label-matching heuristic rendered every resource as USER: `members.some(m => label.startsWith(m.name))`
// is ALWAYS TRUE when any member has an empty name — and `users.name` is NOT NULL DEFAULT '' with 144 such
// rows. So the fixture added one slice earlier made the guess match everything.
//   A WRONG TYPE TAG IS NOT STYLING. It is a FALSE CLAIM ABOUT WHAT A RULE POINTS AT.
// `policy_rules` already enforces the union in two CHECK constraints; read it instead of inferring it.
export type FlowKind =
  "group" | "user" | "site" | "cidr" | "resource" | "k8s_service";
export interface FlowEdge {
  id: string;
  src: string;
  dst: string;
  temp: boolean;
  srcKind: FlowKind;
  dstKind: FlowKind;
}

/** Single letter in the glyph circle. Every arm of BOTH unions, exhaustively. */
export function flowGlyph(k: FlowKind): string {
  switch (k) {
    case "group":
      return "G";
    case "user":
      return "U";
    case "site":
      return "S";
    case "cidr":
      return "C";
    case "resource":
      return "R";
    case "k8s_service":
      return "K";
  }
}

/** The tag line under the name. */
export function flowTag(k: FlowKind): string {
  return k === "k8s_service" ? "K8S SERVICE" : k.toUpperCase();
}
export interface FlowNode {
  label: string;
  kind: FlowKind;
}
export interface FlowLayout {
  srcs: FlowNode[];
  dsts: FlowNode[];
  shown: FlowEdge[];
  hidden: number;
}

/**
 * Columns capped by EDGE DEGREE (the nodes carrying the most policy are what a reader came for), then
 * destinations ordered BARYCENTRICALLY — each sits at the mean slot of the sources reaching it.
 *
 * ⛔ A CAP WITHOUT ORDERING STILL TANGLES AT 4x4. The design's zero crossings are not incidental: `d_eng` is
 * in slot 3 precisely so `oncall-grp` fans up one row instead of across. Ordering is the fix, not the curve —
 * a bezier over an unordered set would look deliberate.
 */
export function flowLayout(
  edges: FlowEdge[],
  cap = FLOW_COLUMN_CAP,
): FlowLayout {
  const deg = (l: string, k: "src" | "dst") =>
    edges.filter((e) => e[k] === l).length;
  const kindOfSrc = new Map(edges.map((e) => [e.src, e.srcKind]));
  const kindOfDst = new Map(edges.map((e) => [e.dst, e.dstKind]));
  let srcLabels = [...new Set(edges.map((e) => e.src))]
    .sort((a, b) => deg(b, "src") - deg(a, "src"))
    .slice(0, cap);
  const si = (l: string) => srcLabels.indexOf(l);
  let dstLabels = [...new Set(edges.map((e) => e.dst))]
    .sort((a, b) => deg(b, "dst") - deg(a, "dst"))
    .slice(0, cap);

  // ⛔ MEASURED, THEN FIXED. The first version ordered ONE side ONCE: sources were pinned by degree and only
  // destinations got a barycentric pass. On the live 11-rule fixture that gave 3 crossings against insertion
  // order's 8 — real, but short.
  //
  // DEGREE PICKS *WHO* APPEARS; IT MUST NOT ALSO PIN *WHERE*. Selection and placement are different
  // decisions, and conflating them left half the graph unordered. So: select by degree (above), then order
  // BOTH columns by ALTERNATING barycentric passes until they stop moving.
  //
  // Four passes is the cap: barycentric ordering converges quickly and can cycle, so an iteration limit is
  // required, not optional.
  let srcOrder = [...srcLabels];
  const meanOf = (label: string, side: "src" | "dst", other: string[]) => {
    const idx = edges
      .filter((e) => e[side] === label)
      .map((e) => other.indexOf(side === "src" ? e.dst : e.src))
      .filter((i) => i >= 0);
    return idx.length
      ? idx.reduce((a, b) => a + b, 0) / idx.length
      : Number.MAX_SAFE_INTEGER;
  };
  for (let pass = 0; pass < 4; pass++) {
    dstLabels = [...dstLabels].sort(
      (a, b) => meanOf(a, "dst", srcOrder) - meanOf(b, "dst", srcOrder),
    );
    srcOrder = [...srcOrder].sort(
      (a, b) => meanOf(a, "src", dstLabels) - meanOf(b, "src", dstLabels),
    );
  }
  srcLabels = srcOrder;

  const shown = edges.filter(
    (e) => si(e.src) >= 0 && dstLabels.indexOf(e.dst) >= 0,
  );
  return {
    srcs: srcLabels.map((l) => ({ label: l, kind: kindOfSrc.get(l)! })),
    dsts: dstLabels.map((l) => ({ label: l, kind: kindOfDst.get(l)! })),
    shown,
    hidden: edges.length - shown.length,
  };
}

/** How many edge pairs cross, given a layout. Used by the test to prove ordering does work. */
export function flowCrossings(l: FlowLayout): number {
  const si = (x: string) => l.srcs.findIndex((n) => n.label === x);
  const di = (x: string) => l.dsts.findIndex((n) => n.label === x);
  let n = 0;
  for (let i = 0; i < l.shown.length; i++)
    for (let j = i + 1; j < l.shown.length; j++) {
      const a = l.shown[i],
        b = l.shown[j];
      if ((si(a.src) - si(b.src)) * (di(a.dst) - di(b.dst)) < 0) n++;
    }
  return n;
}

// ── src_group_empty: THE FOURTH WARN KIND, AND IT EARNS ITSELF BY THE TEST THAT REFUSED THE LAST ONE ─────
//
// S14.11 refused a warn badge for a per-user grant naming a DEACTIVATED user, on this discriminator:
// OUTSIDE RANGES and VANISHED describe rules that COMPILE TO NOTHING WHILE LOOKING LIVE — a permanent,
// invisible lie — and the deactivated grant compiles to exactly what it says (that user's devices, a set that
// only shrinks). Nothing was broken, so no badge.
//
// THE SAME DISCRIMINATOR ADMITS THIS ONE. Measured at `compiler.go:399`:
//
//     matched = owner[r.SrcGroupID]      // owner = the device owner's group set
//     if !matched { continue }
//
// A group with ZERO members matches NO device, so the rule compiles to nothing while rendering as ACTIVE.
// That is the VANISHED family exactly, and the design's own sentence applies: "nothing here is hidden; a rule
// that can't do what it says is shown saying so."
//
//   ⛔ REFUSING ONE CANDIDATE AND ADMITTING ANOTHER ON THE SAME CRITERION IS WHAT SHOWS THE CRITERION HAS
//   CONTENT. A test that only ever admits is not a test.
//
// ⛔ AND IT DERIVES FROM THE MEMBER COUNT, NEVER FROM GROUP EXISTENCE — with a third arm for the count we do
// not have. "Could not check" is not "empty": warning on a failed member load would call a working rule
// broken, which is the false-zero defect one level over.
export type GroupEmptyWarn = "empty" | "populated" | "unknown";

export function srcGroupEmptyWarn(
  memberCount: number | null | undefined,
): GroupEmptyWarn {
  if (memberCount === null || memberCount === undefined) return "unknown"; // not fetched, or the read failed
  return memberCount === 0 ? "empty" : "populated";
}

/** Badge text. `unknown` and `populated` BOTH render nothing — for different reasons, neither of them a warn. */
export function srcGroupEmptyBadge(w: GroupEmptyWarn): string | null {
  return w === "empty" ? "SOURCE GROUP EMPTY" : null;
}

export function srcGroupEmptyExplain(w: GroupEmptyWarn): string | null {
  return w === "empty"
    ? "This rule's source group has no members, so it matches no device and grants nothing. Add members to the group, or delete the rule."
    : null;
}

// ── CASCADE CONFIRM: NAME THE RISK, NEVER ASSERT A COUNT THE SERVER HAS NOT GIVEN ───────────────────────
//
// ⛔ MEASURED, AND IT IS THE MOST DESTRUCTIVE UNGUARDED VERB FOUND IN THIS EPIC:
//
//     policy_rules_src_group_id_fkey     ON DELETE CASCADE
//     policy_rules_dst_group_id_fkey     ON DELETE CASCADE
//     policy_rules_dst_resource_id_fkey  ON DELETE CASCADE
//
// Deleting a group or a resource SILENTLY DELETES EVERY RULE REFERENCING IT. The rules do not orphan and do
// not compile to nothing — THE ROWS VANISH. `DeleteGroup` authorizes, checks the edition, and deletes; the
// 204 carries no body, so the server never says how many it took. An operator removing a stale group can
// destroy access rules they never saw.
//
// ⛔ AND WE CANNOT NAME THE COUNT HONESTLY TODAY. The wireframe's pattern is "Removing ap-lan deletes 2 rules
// referencing it… Counts come from the server's cascade preview." THERE IS NO CASCADE-PREVIEW ENDPOINT
// (measured: zero operationIds mention it). Computing the count client-side from the loaded rules would be a
// SECOND SOURCE OF TRUTH about what the server is about to do — wrong the moment two admins act at once, and
// refused everywhere else this epic (the last-owner 403, the reactive-403 precedent).
//
// So: state the RISK, which is certain, and omit the NUMBER, which we do not own. Registered: a server
// cascade-preview endpoint, after which this copy names counts the server itself computed.
export function cascadeConfirmCopy(
  kind: "group" | "resource",
  name: string,
): {
  title: string;
  body: string;
  typeToConfirm: string;
} {
  const what = kind === "group" ? "group" : "resource";
  const role =
    kind === "group" ? "a rule source or destination" : "a rule destination";
  return {
    title: `Delete ${what} “${name}”?`,
    body:
      `Deleting this ${what} also deletes every access rule that uses it as ${role}. ` +
      `Those rules are removed outright — they do not remain as broken rules you can review afterwards. ` +
      `This cannot be undone.`,
    typeToConfirm: name,
  };
}

/** The typed guard: the name must match EXACTLY. Trimmed, because a trailing space is a typo, not a refusal. */
export function cascadeConfirmSatisfied(typed: string, name: string): boolean {
  return typed.trim() === name;
}

// ── S15.4: the rule form's two option lists ────────────────────────────────────────────────────────────
//
// ⛔ PURE, AND SEPARATE FROM THE PICKER, because these encode the VALIDITY RULES and those must be testable
// without rendering anything. The matrix they implement is measured from the compiler in
// `docs/rule-validity-matrix.md`; nothing here is derived from what the old form happened to offer.

export interface RuleOption {
  value: string;
  kind: string;
  tag: string;
  label: string;
  detail?: string;
  unavailable?: string;
  /**
   * ⛔ THE SECTION IS WHERE PORT SCOPE BECOMES VISIBLE, and port scope is the most consequential fact in
   * this model. `compiler.go:442`/`:458` emit `Protocol: ProtoAny` for group and site destinations — a
   * device and a LAN are L3, so there is no port to narrow. A flat list of nine options hides that; a
   * heading that says "all ports" cannot.
   */
  section: string;
}

/**
 * ⛔ THE ONE SENTENCE THE FORM EXISTS TO PREVENT, and it mirrors the server's `invalid_rule_self_site`.
 *
 * A site cannot be both ends: two hosts on one LAN are switched locally, so their traffic never enters that
 * gateway's forward chain and the compiled allow can never match. Unlike OUTSIDE RANGES this cannot
 * self-clear — there is no future world in which it starts working — which is why the API REFUSES it rather
 * than warning, and why the option is shown-but-disabled here rather than hidden.
 *
 * ⚠ SHOWN, NOT HIDDEN. An option that silently vanishes when you change the other side teaches nothing; one
 * that says why teaches the rule.
 */
export const SELF_SITE_REASON = "a site cannot reach itself";

/**
 * ⛔ THE TWO DESTINATION SECTIONS, AND THE HEADINGS CARRY THE FACT THE TAG CANNOT.
 *
 * Port scope is a property of the destination KIND, not a field on the rule: there is no way to narrow a
 * group destination to one port, and no way to widen a resource past its declared ones. Choosing the noun IS
 * choosing the scope, so the noun has to be presented under a heading that says which.
 */
export const DST_SCOPED = "Services — port-scoped";
export const DST_WIDE = "Networks & devices — ALL ports";

export function sourceOptions(i: {
  groups: Array<{ id: string; name: string }>;
  members: Array<{ user_id: string; email: string; name?: string }>;
  sites: Array<{ id: string; name: string }>;
  agents: Array<{ device_id: string; name: string; gateway_name: string }>;
  dstKind: string;
  dstSite: string;
}): RuleOption[] {
  return [
    ...i.groups.map((g) => ({
      value: g.id,
      kind: "group",
      tag: "group",
      label: g.name,
      section: "People",
    })),
    ...i.members.map((m) => ({
      value: m.user_id,
      kind: "user",
      tag: "person",
      section: "People",
      label: m.name || m.email,
      // ⚠ The email rides along even when a display name exists: it is what an operator searches by, and it
      // is the only disambiguator between two people with the same name.
      detail: m.name ? m.email : undefined,
    })),
    ...i.sites.map((s) => ({
      value: s.id,
      kind: "site",
      tag: "site",
      label: s.name,
      section: "Networks",
      unavailable:
        i.dstKind === "site" && i.dstSite === s.id
          ? SELF_SITE_REASON
          : undefined,
    })),
    ...i.agents.map((a) => ({
      value: a.device_id,
      kind: "agent",
      tag: "agent",
      label: a.name,
      detail: `via ${a.gateway_name}`,
      // ⛔ ITS OWN SECTION. An agent is a MACHINE principal and exactly one device — filing it under People
      // would suggest it has an owner carrying it, and filing it under Networks would suggest a subnet.
      section: "Machines",
    })),
  ];
}

export function destinationOptions(i: {
  groups: Array<{ id: string; name: string }>;
  resources: Array<{ id: string; name: string }>;
  sites: Array<{ id: string; name: string }>;
  services: Array<{ id: string; name: string }>;
  srcKind: string;
  srcSite: string;
}): RuleOption[] {
  return [
    // ⛔ SERVICES FIRST, because they are the port-scoped ones and the ones an operator usually wants.
    ...i.resources.map((r) => ({
      value: r.id,
      kind: "resource",
      tag: "resource",
      label: r.name,
      section: DST_SCOPED,
    })),
    ...i.services.map((s) => ({
      value: s.id,
      kind: "k8s_service",
      tag: "k8s",
      label: s.name,
      section: DST_SCOPED,
    })),
    ...i.groups.map((g) => ({
      value: g.id,
      kind: "group",
      tag: "group",
      label: g.name,
      section: DST_WIDE,
    })),
    ...i.sites.map((s) => ({
      value: s.id,
      kind: "site",
      tag: "site",
      label: s.name,
      section: DST_WIDE,
      unavailable:
        i.srcKind === "site" && i.srcSite === s.id
          ? SELF_SITE_REASON
          : undefined,
    })),
  ];
}

/**
 * ⛔ WHAT THE RULE WILL ACTUALLY DO, IN WORDS, BEFORE IT IS CREATED.
 *
 * Two pickers and a Create button let an operator choose two nouns and press go. Nothing in that gesture
 * says what the compiler will emit — and the gap between "agent rajan → group Contractors" and what it means
 * is enormous:
 *
 * > **A GROUP OR SITE DESTINATION IS PORT-UNSCOPED BY CONSTRUCTION.** `compiler.go:442` and `:458` emit
 * > `Protocol: ProtoAny` — device-to-device and LAN destinations are L3, so there is no port to narrow. Only
 * > a resource or a Kubernetes Service carries protocol and ports.
 *
 * So "agent → group" grants ONE MACHINE UNRESTRICTED ACCESS TO EVERY DEVICE OWNED BY EVERY MEMBER of that
 * group. That may be exactly what someone wants; it must not be something they discover afterwards.
 *
 * ⚠ THIS IS A DESCRIPTION, NEVER A REFUSAL. Every pair below compiles and every one has a legitimate use.
 * The render floor still binds: the verb is REACH, and nothing here claims detection or per-tool control.
 */
export function ruleEffectSummary(i: {
  srcKind: string;
  srcLabel: string;
  dstKind: string;
  dstLabel: string;
}): { text: string; wide: boolean } {
  const subject =
    i.srcKind === "agent"
      ? `AI agent ${i.srcLabel}`
      : i.srcKind === "user"
        ? i.srcLabel
        : i.srcKind === "site"
          ? `every host on site ${i.srcLabel}`
          : i.srcKind === "cidr"
            ? `any host in ${i.srcLabel}`
            : `every device of ${i.srcLabel}`;

  // ⛔ `wide` marks the port-unscoped destinations. It drives a warning, never a block.
  const wide = i.dstKind === "group" || i.dstKind === "site";
  const object =
    i.dstKind === "group"
      ? `every device belonging to every member of ${i.dstLabel}`
      : i.dstKind === "site"
        ? `every host on site ${i.dstLabel}`
        : i.dstKind === "k8s_service"
          ? `the Kubernetes Service ${i.dstLabel}`
          : i.dstLabel;

  const scope = wide
    ? " on ALL ports and protocols"
    : i.dstKind === "resource"
      ? " on that resource's declared ports only"
      : " on that Service's declared ports only";

  return { text: `${subject} will be able to reach ${object}${scope}.`, wide };
}

/**
 * ⚠ THE EXTRA SENTENCE FOR THE SHAPE THAT SURPRISES PEOPLE, and only for it — a caution attached to every
 * rule is one nobody reads.
 *
 * A non-human principal granted unrestricted access to humans' own devices is backwards for almost every
 * intent: an agent normally needs SERVICES, which are port-scoped. Said as a question about intent, not as a
 * verdict about safety, because the grant is legitimate when it is deliberate.
 */
export function ruleEffectCaution(
  srcKind: string,
  dstKind: string,
): string | null {
  if (srcKind === "agent" && (dstKind === "group" || dstKind === "site")) {
    return "This gives a machine principal unrestricted access to people's own devices. If the agent needs a service, name that service as the destination instead — a resource is port-scoped, a group is not.";
  }
  return null;
}
