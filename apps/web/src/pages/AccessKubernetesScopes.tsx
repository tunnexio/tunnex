import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { Link } from "react-router-dom";
import { AccessTabRail } from "../components/AccessTabRail";
import {
  Button,
  Card,
  EmptyState,
  ErrorText,
  Field,
  Input,
  Loading,
  Modal,
  PageHeader,
  Select,
} from "../components/ui";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  listItems,
  loadOne,
  type K8sCluster,
  type K8sService,
  type Member,
  type Role,
  type Site,
  type UserGroup,
} from "../lib/api";
import { useAuth } from "../lib/auth";
import { relativeAge } from "../lib/format";
import { can } from "../lib/rbac";
import { useOrg } from "../lib/useOrg";

type ScopeSettings = components["schemas"]["K8sClusterScopeSettings"];
type Scope = components["schemas"]["K8sClusterScope"];
type ScopeSource = components["schemas"]["K8sClusterScopeSource"];
type CreateScopeSource = components["schemas"]["CreateK8sClusterScopeSource"];
type Candidate = components["schemas"]["K8sClusterScopeCandidate"];
type Membership = components["schemas"]["K8sClusterScopeMembership"];
type Agent = components["schemas"]["Agent"];

type SourceOption = { kind: Exclude<CreateScopeSource["kind"], "cidr">; id: string; label: string };
type Detail = { ruleId: string; candidates: Candidate[]; memberships: Membership[]; candidateCursor?: string | null; membershipCursor?: string | null };

type Confirm =
  | { kind: "setting"; enabled: boolean }
  | { kind: "active"; scope: Scope; active: boolean }
  | { kind: "delete"; scope: Scope }
  | { kind: "decision"; membership: Membership; decision: "approved" | "rejected" }
  | null;

function exactChild(service: K8sService): boolean {
  return (service.protocol === "tcp" || service.protocol === "udp") &&
    service.port_low != null && service.port_high === service.port_low;
}

function sourceLabel(source: ScopeSource, options: SourceOption[]): string {
  if (source.kind === "cidr") return source.cidr || "Unknown CIDR";
  return options.find((option) => option.kind === source.kind && option.id === source.id)?.label
    ?? `${source.kind} · ${source.id ?? "unavailable"}`;
}

function clusterLabel(clusterId: string, clusters: K8sCluster[]): string {
  return clusters.find((cluster) => cluster.id === clusterId)?.name ?? `Cluster ${clusterId}`;
}

function protocolPort(value: { protocol: string; port: number }): string {
  return `${value.protocol.toUpperCase()} ${value.port}`;
}

function scopeExpired(scope: Scope): boolean {
  return Boolean(scope.expires_at && Date.parse(scope.expires_at) <= Date.now());
}

function inactiveReasonLabel(reason: Candidate["inactive_reason"] | Membership["inactive_reason"]): string {
  return ({
    edition_locked: "Current plan does not unlock enforcement.",
    not_selected: "This creation-time candidate was not selected.",
    pending: "Human approval is pending.",
    rejected: "This membership was permanently rejected.",
    scope_disabled: "The scope is disabled.",
    organization_disabled: "The organization opt-in is disabled.",
    rule_disabled: "The underlying policy rule is disabled.",
    rule_expired: "The scope has expired.",
    inventory_stale: "Connected-agent inventory is stale.",
    inventory_unavailable: "Connected-agent inventory is unavailable.",
    identity_changed: "The exact Kubernetes Service identity changed.",
  } as const)[reason as Exclude<typeof reason, null | undefined>] ?? "This exact child is currently ineffective.";
}

function StatePill({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "positive" | "attention" | "danger" | "neutral" }) {
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] font-medium ${
    tone === "positive" ? "border-emerald-700/50 bg-emerald-950/50 text-emerald-300" :
      tone === "attention" ? "border-amber-700/50 bg-amber-950/40 text-amber-300" :
        tone === "danger" ? "border-rose-700/50 bg-rose-950/40 text-rose-300" :
          "border-white/10 bg-white/5 text-ink-tertiary"
  }`}>{children}</span>;
}

function permissionRole(members: Member[], userId: string): Role | undefined {
  return members.find((member) => member.user_id === userId && member.status === "active")?.role;
}

export default function AccessKubernetesScopes() {
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const userId = state.status === "authed" ? state.user.id : "";
  const [role, setRole] = useState<Role>();
  const [permissionState, setPermissionState] = useState<"loading" | "allowed" | "denied" | "error">("loading");
  const [settings, setSettings] = useState<ScopeSettings | null>(null);
  const [scopes, setScopes] = useState<Scope[] | null>(null);
  const [queue, setQueue] = useState<Membership[] | null>(null);
  const [queueCursor, setQueueCursor] = useState<string | null | undefined>();
  const [clusters, setClusters] = useState<K8sCluster[] | null>(null);
  const [services, setServices] = useState<K8sService[] | null>(null);
  const [sources, setSources] = useState<SourceOption[]>([]);
  const [loadError, setLoadError] = useState("");
  const [queueError, setQueueError] = useState("");
  const [auxiliaryError, setAuxiliaryError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedRuleId, setSelectedRuleId] = useState("");
  const [detail, setDetail] = useState<Detail | null>(null);
  const [detailError, setDetailError] = useState("");
  const [confirm, setConfirm] = useState<Confirm>(null);
  const loadEpoch = useRef(0);
  const detailEpoch = useRef(0);
  const detailRef = useRef<Detail | null>(null);
  const queueEpoch = useRef(0);

  const canView = can(role, "k8s_scope:view") && can(role, "policy:view");
  const canManageSetting = can(role, "k8s_scope:manage");
  const canManageScope = can(role, "k8s_scope:manage");
  const canCreateScope = canManageScope && can(role, "policy:manage");
  const canApprove = can(role, "k8s_scope:approve");

  const loadAll = useCallback(async () => {
    const epoch = ++loadEpoch.current;
    queueEpoch.current += 1;
    detailEpoch.current += 1;
    detailRef.current = null;
    setLoadError("");
    setQueueError("");
    setAuxiliaryError("");
    setSettings(null);
    setScopes(null);
    setQueue(null);
    setClusters(null);
    setServices(null);
    setSources([]);
    setRole(undefined);
    setPermissionState("loading");
    if (orgLoading) return;
    if (!org || !userId) {
      setPermissionState(orgFailed ? "error" : "denied");
      return;
    }
    const memberResult = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }));
    if (epoch !== loadEpoch.current) return;
    if (!memberResult.ok) {
      setLoadError(memberResult.error);
      setPermissionState("error");
      return;
    }
    const nextRole = permissionRole(memberResult.data as Member[], userId);
    setRole(nextRole);
    if (!(can(nextRole, "k8s_scope:view") && can(nextRole, "policy:view"))) {
      setPermissionState("denied");
      return;
    }
    setPermissionState("allowed");
    const [settingResult, scopeResult, queueResult, clusterResult, serviceResult, groupResult, siteResult, agentResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scope-settings", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scopes", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scope-review-queue", { params: { path: { orgId: org.id }, query: { limit: 100 } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/clusters", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/services", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId: org.id } } })),
    ]);
    if (epoch !== loadEpoch.current) return;
    if (!settingResult.ok || !scopeResult.ok) {
      setLoadError([settingResult, scopeResult].find((result) => !result.ok)?.error ?? "Could not load Kubernetes scope governance.");
      return;
    }
    setSettings(settingResult.data);
    setScopes(scopeResult.data);
    setClusters(clusterResult.ok ? clusterResult.data : null);
    setServices(serviceResult.ok ? serviceResult.data : null);
    if (queueResult.ok) {
      setQueue(queueResult.data.items);
      setQueueCursor(queueResult.data.next_cursor);
    } else {
      setQueueError(queueResult.error);
    }
    const sourceErrors = [clusterResult, serviceResult, groupResult, siteResult, agentResult].filter((result) => !result.ok);
    if (sourceErrors.length > 0) setAuxiliaryError("Some cluster, Service, or source choices are unavailable. Preserved scopes remain readable, but creation is disabled until every required inventory loads.");
    const groupOptions: SourceOption[] = groupResult.ok ? (groupResult.data as UserGroup[]).map((group) => ({ kind: "group", id: group.id, label: group.name })) : [];
    const userOptions: SourceOption[] = (memberResult.data as Member[]).filter((member) => member.status === "active").map((member) => ({ kind: "user", id: member.user_id, label: member.name || member.email }));
    const siteOptions: SourceOption[] = siteResult.ok ? (siteResult.data as Site[]).map((site) => ({ kind: "site", id: site.id, label: site.name })) : [];
    const agentOptions: SourceOption[] = agentResult.ok ? (listItems(agentResult.data) as Agent[]).map((agent) => ({ kind: "agent", id: agent.device_id, label: agent.name })) : [];
    setSources([...groupOptions, ...userOptions, ...siteOptions, ...agentOptions]);
  }, [org?.id, orgFailed, orgLoading, userId]);

  useEffect(() => {
    void loadAll();
    return () => { loadEpoch.current += 1; };
  }, [loadAll]);

  const loadDetail = useCallback(async (scope: Scope, append = false) => {
    if (!org) return;
    const epoch = ++detailEpoch.current;
    setDetailError("");
    if (!append) {
      detailRef.current = null;
      setDetail(null);
    }
    const previous = append && detailRef.current?.ruleId === scope.rule_id ? detailRef.current : null;
    const candidateCursor = previous?.candidateCursor ?? undefined;
    const membershipCursor = previous?.membershipCursor ?? undefined;
    const loadCandidates = !append || !previous || Boolean(candidateCursor);
    const loadMemberships = !append || !previous || Boolean(membershipCursor);
    const [candidateResult, membershipResult] = await Promise.all([
      loadCandidates
        ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}/initial-candidates", { params: { path: { orgId: org.id, ruleId: scope.rule_id }, query: { cursor: candidateCursor, limit: 100 } } }))
        : Promise.resolve({ ok: true as const, data: { items: [] as Candidate[], next_cursor: undefined } }),
      loadMemberships
        ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}/memberships", { params: { path: { orgId: org.id, ruleId: scope.rule_id }, query: { cursor: membershipCursor, limit: 100 } } }))
        : Promise.resolve({ ok: true as const, data: { items: [] as Membership[], next_cursor: undefined } }),
    ]);
    if (epoch !== detailEpoch.current || scope.rule_id !== selectedRuleId) return;
    if (!candidateResult.ok || !membershipResult.ok) {
      setDetailError(!candidateResult.ok ? candidateResult.error : membershipResult.ok ? "" : membershipResult.error);
      return;
    }
    const next: Detail = {
      ruleId: scope.rule_id,
      candidates: append ? [...(previous?.candidates ?? []), ...candidateResult.data.items] : candidateResult.data.items,
      memberships: append ? [...(previous?.memberships ?? []), ...membershipResult.data.items] : membershipResult.data.items,
      candidateCursor: candidateResult.data.next_cursor,
      membershipCursor: membershipResult.data.next_cursor,
    };
    detailRef.current = next;
    setDetail(next);
  }, [org?.id, selectedRuleId]);

  useEffect(() => {
    const scope = scopes?.find((item) => item.rule_id === selectedRuleId);
    if (scope) void loadDetail(scope);
    else {
      detailEpoch.current += 1;
      detailRef.current = null;
      setDetail(null);
    }
  }, [selectedRuleId, scopes]);

  const handleMutationError = useCallback(async (error: unknown, fallback: string) => {
    const code = apiErrorCode(error);
    if (code?.includes("revision") || code?.includes("conflict")) {
      setNotice("This scope changed in another session. Latest server state has been reloaded; review it before retrying.");
      await loadAll();
    } else setLoadError(apiErrorMessage(error, fallback));
  }, [loadAll]);

  async function toggleSetting(enabled: boolean) {
    if (!org || !settings) return;
    setBusy(true);
    try {
      const response = await api.PUT("/api/v1/organizations/{orgId}/k8s/cluster-scope-settings", {
        params: { path: { orgId: org.id } },
        body: { enabled, expected_revision: settings.revision },
      });
      if (response.error) {
        await handleMutationError(response.error, "Could not change the organization setting.");
        return;
      }
      setConfirm(null);
      setNotice(enabled ? "Cluster scopes are enabled. Existing live approvals may resume." : "Cluster scopes are disabled. Scope-derived access was withdrawn; decisions were preserved.");
      await loadAll();
    } finally {
      setBusy(false);
    }
  }

  async function toggleScope(scope: Scope, active: boolean) {
    if (!org) return;
    setBusy(true);
    try {
      const response = await api.PUT("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}", {
        params: { path: { orgId: org.id, ruleId: scope.rule_id } },
        body: { active, expected_revision: scope.revision },
      });
      if (response.error) {
        await handleMutationError(response.error, `Could not ${active ? "enable" : "disable"} the scope.`);
        return;
      }
      setConfirm(null);
      setNotice(active ? "Scope enabled. Only still-current approved exact children can grant access." : "Scope disabled. Derived access was withdrawn; decisions were preserved for recovery.");
      await loadAll();
    } finally {
      setBusy(false);
    }
  }

  async function deleteScope(scope: Scope) {
    if (!org) return;
    setBusy(true);
    try {
      const response = await api.DELETE("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}", {
        params: { path: { orgId: org.id, ruleId: scope.rule_id }, query: { expected_revision: scope.revision } },
      });
      if (response.error) {
        await handleMutationError(response.error, "Could not delete the scope.");
        return;
      }
      setConfirm(null);
      setSelectedRuleId("");
      setNotice("Scope and live membership rows were deleted. Append-only audit evidence remains; recovery requires creating a new scope.");
      await loadAll();
    } finally {
      setBusy(false);
    }
  }

  async function decide(membership: Membership, decision: "approved" | "rejected") {
    if (!org) return;
    setBusy(true);
    try {
      const response = await api.POST("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}/memberships/{serviceChildId}/decision", {
        params: { path: { orgId: org.id, ruleId: membership.rule_id, serviceChildId: membership.service_child_id } },
        body: { decision },
      });
      if (response.error) {
        await handleMutationError(response.error, `Could not ${decision === "approved" ? "approve" : "reject"} the membership.`);
        return;
      }
      setConfirm(null);
      setNotice(decision === "approved" ? "Exact child approved. It grants only while the scope, organization setting, entitlement, and child identity remain active." : "Membership permanently rejected. It grants nothing; recovery requires a new scope or a future explicit-inclusion flow.");
      await loadAll();
    } finally {
      setBusy(false);
    }
  }

  async function loadMoreQueue() {
    if (!org || !queueCursor) return;
    const epoch = ++queueEpoch.current;
    const loadAllGeneration = loadEpoch.current;
    const cursor = queueCursor;
    setBusy(true);
    try {
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scope-review-queue", { params: { path: { orgId: org.id }, query: { cursor, limit: 100 } } }));
      if (epoch !== queueEpoch.current || loadAllGeneration !== loadEpoch.current) return;
      if (!result.ok) return setQueueError(result.error);
      setQueue((current) => [...(current ?? []), ...result.data.items]);
      setQueueCursor(result.data.next_cursor);
    } finally {
      if (epoch === queueEpoch.current) setBusy(false);
    }
  }

  const header = <><PageHeader title="Kubernetes access scopes" subtitle={org ? `${org.name} · approval-gated exact Service access` : "Access governance"} /><AccessTabRail /></>;
  if (permissionState === "loading") return <div className="space-y-5">{header}<Card><Loading label="Checking Kubernetes scope permissions…" /></Card></div>;
  if (permissionState === "denied") return <div className="space-y-5">{header}<Card><p role="alert" className="text-cell text-ink-tertiary">Kubernetes scope governance is available only to authorized Access administrators.</p><Link className="mt-3 inline-block text-sm font-medium text-accent-400 hover:underline" to="/access">Return to Access policies</Link></Card></div>;
  if (permissionState === "error") return <div className="space-y-5">{header}<Card><ErrorText>{loadError || "Could not verify Kubernetes scope permissions."}</ErrorText><Button className="mt-3" onClick={() => void loadAll()}>Retry</Button></Card></div>;
  if (!canView) return null;

  return <div className="space-y-5" data-testid="k8s-scope-governance">
    {header}
    {notice && <div role="status" className="rounded-md border border-accent-400/30 bg-white/[.04] px-4 py-3 text-sm text-ink-secondary">{notice}</div>}
    {loadError && <Card><ErrorText>{loadError}</ErrorText><Button className="mt-3" onClick={() => void loadAll()}>Reload server state</Button></Card>}
    {!loadError && (!settings || !scopes) && <Card><Loading label="Loading preserved scopes and review state…" /></Card>}
    {!loadError && settings && scopes && <>
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <Card className="overflow-hidden">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-2xl">
              <div className="flex flex-wrap items-center gap-2"><h2 className="text-base font-semibold text-ink-heading">Organization opt-in</h2><StatePill tone={settings.effective ? "positive" : settings.entitlement_unlocked ? "attention" : "neutral"}>{settings.effective ? "Effective" : settings.enabled ? "Unavailable" : "Off"}</StatePill></div>
              <p className="mt-2 text-sm text-ink-tertiary">A licence unlocks this capability but never enables it. Turning it off withdraws every scope-derived allow immediately and preserves decisions for recovery.</p>
            </div>
            {canManageSetting && (settings.entitlement_unlocked || settings.enabled) && <Button variant={settings.enabled ? "ghost" : "primary"} disabled={busy} onClick={() => setConfirm({ kind: "setting", enabled: !settings.enabled })}>{settings.enabled ? "Disable for organization" : "Enable for organization"}</Button>}
          </div>
          <dl className="mt-5 grid gap-3 border-t border-white/10 pt-4 text-sm sm:grid-cols-3"><div><dt className="text-ink-tertiary">Licensed</dt><dd className="mt-1 text-ink-heading">{settings.entitlement_unlocked ? "Available" : "Not in current plan"}</dd></div><div><dt className="text-ink-tertiary">Explicit opt-in</dt><dd className="mt-1 text-ink-heading">{settings.enabled ? "Enabled" : "Disabled"}</dd></div><div><dt className="text-ink-tertiary">Revision</dt><dd className="mt-1 font-mono text-ink-heading">{settings.revision}</dd></div></dl>
        </Card>
        <Card>
          <h2 className="text-sm font-semibold text-ink-heading">Exact-child boundary</h2>
          <p className="mt-2 text-sm text-ink-tertiary">A scope never grants a namespace, cluster, Pod, Node, CIDR, or sibling port. Only individually approved, still-current protocol/port children compile.</p>
          <p className="mt-3 text-xs text-ink-tertiary">Rejected decisions are permanent. Disabled scopes and the organization opt-in are reversible.</p>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(20rem,.7fr)]">
        <Card>
          <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-base font-semibold text-ink-heading">Cluster scopes</h2><p className="mt-1 text-sm text-ink-tertiary">Each scope binds one Access source to explicitly approved exact Service children.</p></div>{canCreateScope && <Button disabled={busy || !settings.effective || Boolean(auxiliaryError) || !clusters || !services} onClick={() => setCreateOpen(true)}>Create scope</Button>}</div>
          {!settings.effective && <p className="mt-4 rounded-md border border-amber-700/30 bg-amber-950/20 px-3 py-2 text-xs text-amber-200">Creation and approval are unavailable while the organization setting or entitlement is inactive. Preserved scopes remain readable.</p>}
          {auxiliaryError && <ErrorText>{auxiliaryError}</ErrorText>}
          {scopes.length === 0 ? <div className="mt-4"><EmptyState>No cluster scopes exist. Creating one starts with zero Services selected.</EmptyState></div> : <div className="mt-4 space-y-2">{scopes.map((scope) => { const expired = scopeExpired(scope); const effective = scope.active && settings.effective && !expired; return <button key={scope.rule_id} type="button" aria-pressed={selectedRuleId === scope.rule_id} onClick={() => setSelectedRuleId(scope.rule_id)} className={`w-full rounded-md border p-3 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400 ${selectedRuleId === scope.rule_id ? "border-accent-400/60 bg-white/[.06]" : "border-white/10 hover:bg-white/[.03]"}`}><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium text-ink-heading">{clusterLabel(scope.cluster_id, clusters ?? [])}</span><StatePill tone={effective ? "positive" : expired ? "danger" : scope.active ? "attention" : "neutral"}>{effective ? "Active" : expired ? "Expired · ineffective" : scope.active ? "Active · ineffective" : "Disabled"}</StatePill></div><p className="mt-1 text-sm text-ink-secondary">{sourceLabel(scope.source, sources)}</p><p className="mt-2 text-xs text-ink-tertiary">{scope.initial_candidate_count} initially offered · revision {scope.revision} · created {relativeAge(scope.created_at)}{scope.expires_at ? ` · expires ${relativeAge(scope.expires_at)}` : " · no expiry"}</p></button>; })}</div>}
        </Card>

        <Card>
          <div className="flex items-center justify-between gap-3"><div><h2 className="text-base font-semibold text-ink-heading">Pending review</h2><p className="mt-1 text-sm text-ink-tertiary">Only Services exposed after scope creation appear here.</p></div>{queue !== null && <StatePill tone={queue.length ? "attention" : "neutral"}>{queue.length ? `${queue.length} loaded` : "None"}</StatePill>}</div>
          {queueError ? <div className="mt-4"><ErrorText>{queueError}</ErrorText><Button className="mt-3" onClick={() => void loadAll()}>Retry queue</Button></div> : queue === null ? <div className="mt-4"><Loading label="Loading pending reviews…" /></div> : queue.length === 0 ? <div className="mt-4"><EmptyState>No later-exposure decisions are pending.</EmptyState></div> : <div className="mt-4 space-y-3">{queue.map((membership) => <MembershipRow key={`${membership.rule_id}:${membership.service_child_id}`} membership={membership} canApprove={canApprove && settings.effective} onDecision={(decision) => setConfirm({ kind: "decision", membership, decision })} />)}{queueCursor && <Button variant="ghost" disabled={busy} onClick={() => void loadMoreQueue()}>Load more pending reviews</Button>}</div>}
        </Card>
      </section>

      {selectedRuleId && <ScopeDetail scope={scopes.find((scope) => scope.rule_id === selectedRuleId) ?? null} settings={settings} detail={detail?.ruleId === selectedRuleId ? detail : null} error={detailError} clusters={clusters ?? []} sources={sources} canManage={canManageScope} busy={busy} onReload={(scope) => void loadDetail(scope)} onLoadMore={(scope) => void loadDetail(scope, true)} onActive={(scope, active) => setConfirm({ kind: "active", scope, active })} onDelete={(scope) => setConfirm({ kind: "delete", scope })} />}
    </>}

    {createOpen && canCreateScope && settings && clusters && services && <CreateScopeModal orgId={org?.id ?? ""} clusters={clusters} services={services} sources={sources} busy={busy} onDismiss={() => { if (!busy) setCreateOpen(false); }} onBusy={setBusy} onError={setLoadError} onCreated={async (scope) => { setCreateOpen(false); setSelectedRuleId(scope.rule_id); setNotice("Scope created. Only the exact children explicitly selected in the review step were initially approved."); await loadAll(); }} />}
    {confirm && <ConfirmModal confirm={confirm} busy={busy} onDismiss={() => { if (!busy) setConfirm(null); }} onSetting={toggleSetting} onActive={toggleScope} onDelete={deleteScope} onDecision={decide} />}
  </div>;
}

function MembershipRow({ membership, canApprove, onDecision }: { membership: Membership; canApprove: boolean; onDecision: (decision: "approved" | "rejected") => void }) {
  return <article className="rounded-md border border-white/10 bg-black/10 p-3"><div className="flex flex-wrap items-start justify-between gap-2"><div><p className="text-sm font-medium text-ink-heading">{membership.namespace}/{membership.service}</p><p className="mt-1 font-mono text-xs text-ink-secondary">{protocolPort(membership)}</p></div><div className="flex gap-2"><StatePill tone={membership.effective ? "positive" : !membership.current ? "danger" : membership.status === "pending" ? "attention" : "neutral"}>{membership.effective ? "Effective" : membership.current ? membership.status : "Vanished"}</StatePill><StatePill>{membership.origin}</StatePill></div></div>{!membership.current && <p className="mt-2 text-xs text-rose-300">The exact child no longer maps to its original live Service identity. It grants nothing; history is retained.</p>}{membership.effective === false && membership.inactive_reason && <p className="mt-2 text-xs text-amber-200">{inactiveReasonLabel(membership.inactive_reason)}</p>}{membership.status === "pending" && canApprove && <div className="mt-3 flex gap-2"><Button size="sm" onClick={() => onDecision("approved")}>Review approval</Button><Button size="sm" variant="danger" onClick={() => onDecision("rejected")}>Review rejection</Button></div>}{membership.decided_at && <p className="mt-2 text-xs text-ink-tertiary">Decided {relativeAge(membership.decided_at)}</p>}</article>;
}

function ScopeDetail({ scope, settings, detail, error, clusters, sources, canManage, busy, onReload, onLoadMore, onActive, onDelete }: { scope: Scope | null; settings: ScopeSettings; detail: Detail | null; error: string; clusters: K8sCluster[]; sources: SourceOption[]; canManage: boolean; busy: boolean; onReload: (scope: Scope) => void; onLoadMore: (scope: Scope) => void; onActive: (scope: Scope, active: boolean) => void; onDelete: (scope: Scope) => void }) {
  if (!scope) return null;
  const expired = scopeExpired(scope);
  const effective = scope.active && settings.effective && !expired;
  return <Card><div className="flex flex-wrap items-start justify-between gap-4"><div><div className="flex flex-wrap items-center gap-2"><h2 className="text-base font-semibold text-ink-heading">Scope detail</h2><StatePill tone={effective ? "positive" : expired ? "danger" : scope.active ? "attention" : "neutral"}>{effective ? "Active" : expired ? "Expired and ineffective" : scope.active ? "Active but ineffective" : "Disabled"}</StatePill></div><p className="mt-1 text-sm text-ink-secondary">{clusterLabel(scope.cluster_id, clusters)} · {sourceLabel(scope.source, sources)}</p><p className="mt-1 font-mono text-xs text-ink-tertiary">Rule {scope.rule_id} · revision {scope.revision}</p><p className="mt-1 text-xs text-ink-tertiary">{scope.expires_at ? <span title={scope.expires_at}>Expires {relativeAge(scope.expires_at)}</span> : "No expiry"}</p>{scope.active && !effective && <p className="mt-2 text-xs text-amber-200">Stored active state is preserved, but it currently grants nothing because {expired ? "the scope has expired" : "the organization opt-in or entitlement is inactive"}.</p>}</div>{canManage && <div className="flex flex-wrap gap-2"><Button variant="ghost" disabled={busy || (settings.effective === false && !scope.active) || (expired && !scope.active)} onClick={() => onActive(scope, !scope.active)}>{scope.active ? "Disable scope" : "Enable scope"}</Button><Button variant="danger" disabled={busy} onClick={() => onDelete(scope)}>Delete scope</Button></div>}</div>
    {error ? <div className="mt-4"><ErrorText>{error}</ErrorText><Button className="mt-3" onClick={() => onReload(scope)}>Retry detail</Button></div> : detail === null ? <div className="mt-4"><Loading label="Loading initial evidence and membership history…" /></div> : <div className="mt-5 grid gap-5 lg:grid-cols-2"><section><h3 className="text-sm font-semibold text-ink-heading">Initial candidate evidence</h3><p className="mt-1 text-xs text-ink-tertiary">Immutable creation-time snapshot. Unselected rows were offered, not rejected.</p><div className="mt-3 space-y-2">{detail.candidates.length === 0 ? <EmptyState>No exact children were offered when this scope was created.</EmptyState> : detail.candidates.map((candidate) => <div key={candidate.service_child_id} className="flex items-start justify-between gap-3 rounded-md border border-white/10 p-3"><div><p className="text-sm text-ink-heading">{candidate.namespace}/{candidate.service}</p><p className="mt-1 font-mono text-xs text-ink-tertiary">{protocolPort(candidate)}</p>{candidate.effective === false && candidate.inactive_reason && <p className="mt-1 text-xs text-amber-200">{inactiveReasonLabel(candidate.inactive_reason)}</p>}</div><div className="flex gap-2"><StatePill tone={candidate.effective ? "positive" : candidate.selected ? "attention" : "neutral"}>{candidate.effective ? "Effective" : candidate.selected ? "Selected · ineffective" : "Not selected"}</StatePill>{candidate.current === false && <StatePill tone="danger">Vanished</StatePill>}</div></div>)}</div></section><section><h3 className="text-sm font-semibold text-ink-heading">Membership history</h3><p className="mt-1 text-xs text-ink-tertiary">Pending, approved, rejected, effective, and vanished states remain distinct.</p><div className="mt-3 space-y-2">{detail.memberships.length === 0 ? <EmptyState>No memberships exist for this scope.</EmptyState> : detail.memberships.map((membership) => <MembershipRow key={membership.service_child_id} membership={membership} canApprove={false} onDecision={() => {}} />)}</div></section>{(detail.candidateCursor || detail.membershipCursor) && <Button variant="ghost" disabled={busy} onClick={() => onLoadMore(scope)}>Load more history</Button>}</div>}
  </Card>;
}

function CreateScopeModal({ orgId, clusters, services, sources, busy, onDismiss, onBusy, onError, onCreated }: { orgId: string; clusters: K8sCluster[]; services: K8sService[]; sources: SourceOption[]; busy: boolean; onDismiss: () => void; onBusy: (busy: boolean) => void; onError: (error: string) => void; onCreated: (scope: Scope) => Promise<void> }) {
  const [clusterId, setClusterId] = useState("");
  const [sourceKind, setSourceKind] = useState<CreateScopeSource["kind"]>("group");
  const [sourceId, setSourceId] = useState("");
  const [cidr, setCidr] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [expiresAt, setExpiresAt] = useState("");
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [localError, setLocalError] = useState("");
  const sourceOptions = sources.filter((option) => option.kind === sourceKind);
  const candidates = useMemo(() => services.filter((service) => service.cluster_id === clusterId && exactChild(service)).sort((a, b) => `${a.namespace}/${a.name}/${a.protocol}/${a.port_low}`.localeCompare(`${b.namespace}/${b.name}/${b.protocol}/${b.port_low}`)), [clusterId, services]);
  const sourceReady = sourceKind === "cidr" ? cidr.trim().length > 0 : sourceId.length > 0;

  async function submit() {
    if (!clusterId || !sourceReady) return;
    onBusy(true);
    setLocalError("");
    try {
      const source: CreateScopeSource = sourceKind === "cidr" ? { kind: "cidr", cidr: cidr.trim() } : { kind: sourceKind, id: sourceId };
      const response = await api.POST("/api/v1/organizations/{orgId}/k8s/cluster-scopes", { params: { path: { orgId } }, body: { cluster_id: clusterId, source, initial_service_child_ids: selected, expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined } });
      if (response.error || !response.data) {
        const message = apiErrorMessage(response.error, "Could not create the scope. Current candidates may have changed; close and reload before retrying.");
        setLocalError(message);
        onError(message);
        return;
      }
      await onCreated(response.data);
    } finally {
      onBusy(false);
    }
  }

  return <Modal title="Create Kubernetes access scope" size="wide" onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={step === 1 ? onDismiss : () => setStep((step - 1) as 1 | 2)}>Back</Button>{step < 3 ? <Button disabled={step === 1 ? !clusterId || !sourceReady : false} onClick={() => setStep((step + 1) as 2 | 3)}>Continue</Button> : <Button disabled={busy || !clusterId || !sourceReady || selected.length > 100} onClick={() => void submit()}>{busy ? "Creating…" : "Create scope"}</Button>}</>}>
    <div className="space-y-5"><div className="flex gap-2" aria-label={`Step ${step} of 3`}>{[1, 2, 3].map((value) => <span key={value} className={`h-1.5 flex-1 rounded-full ${value <= step ? "bg-accent-400" : "bg-white/10"}`} />)}</div><ErrorText>{localError}</ErrorText>{step === 1 && <><div><h3 className="text-sm font-semibold text-ink-heading">1. Cluster and Access source</h3><p className="mt-1 text-sm text-ink-tertiary">Choose one enrolled cluster and the identity that may reach approved exact children.</p></div><div className="grid gap-4 sm:grid-cols-2"><Field label="Enrolled cluster"><Select autoFocus value={clusterId} onChange={(event) => { setClusterId(event.target.value); setSelected([]); }}><option value="">Choose a cluster…</option>{clusters.map((cluster) => <option key={cluster.id} value={cluster.id}>{cluster.name} · {cluster.platform.replace(/_/g, " ")}</option>)}</Select></Field><Field label="Source type"><Select value={sourceKind} onChange={(event) => { setSourceKind(event.target.value as CreateScopeSource["kind"]); setSourceId(""); setCidr(""); }}><option value="group">Group</option><option value="user">User</option><option value="site">Site</option><option value="agent">Agent</option><option value="cidr">Exact CIDR</option></Select></Field></div>{sourceKind === "cidr" ? <Field label="Source CIDR"><Input value={cidr} placeholder="10.20.0.0/24" onChange={(event) => setCidr(event.target.value)} /></Field> : <Field label={`${sourceKind[0].toUpperCase()}${sourceKind.slice(1)}`}><Select value={sourceId} onChange={(event) => setSourceId(event.target.value)}><option value="">Choose a current {sourceKind}…</option>{sourceOptions.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</Select></Field>}<Field label="Expires at (optional)"><Input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></Field></>}{step === 2 && <><div><h3 className="text-sm font-semibold text-ink-heading">2. Select initial exact children</h3><p className="mt-1 text-sm text-ink-tertiary">Nothing is selected by default. Unselected current children are recorded as offered, not rejected.</p></div><div className="flex items-center justify-between text-xs text-ink-tertiary"><span>{candidates.length} current exact children</span><span>{selected.length} selected · maximum 100</span></div>{candidates.length === 0 ? <EmptyState>No current exposed TCP/UDP exact-port children are available in this cluster. Expose verified Services in Kubernetes first.</EmptyState> : <fieldset className="max-h-[23rem] space-y-2 overflow-y-auto pr-1"><legend className="sr-only">Initial exact Service children</legend>{candidates.map((service) => { const checked = selected.includes(service.id); return <label key={service.id} className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 ${checked ? "border-accent-400/60 bg-white/[.06]" : "border-white/10 hover:bg-white/[.03]"}`}><input type="checkbox" className="mt-1 h-4 w-4 accent-current" checked={checked} onChange={() => setSelected((current) => checked ? current.filter((id) => id !== service.id) : current.length < 100 ? [...current, service.id] : current)} /><span><span className="block text-sm font-medium text-ink-heading">{service.namespace}/{service.name}</span><span className="mt-1 block font-mono text-xs text-ink-tertiary">{service.protocol.toUpperCase()} {service.port_low} · {service.fqdn}</span></span></label>; })}</fieldset>}</>}{step === 3 && <><div><h3 className="text-sm font-semibold text-ink-heading">3. Review exact authority</h3><p className="mt-1 text-sm text-ink-tertiary">Creating approves only the selected exact children in one server transaction. No namespace, sibling port, ClusterIP, Pod, Node, or provider account is granted.</p></div><dl className="grid gap-3 rounded-md border border-white/10 p-4 text-sm sm:grid-cols-2"><div><dt className="text-ink-tertiary">Cluster</dt><dd className="mt-1 text-ink-heading">{clusters.find((cluster) => cluster.id === clusterId)?.name}</dd></div><div><dt className="text-ink-tertiary">Source</dt><dd className="mt-1 text-ink-heading">{sourceKind === "cidr" ? cidr : sourceOptions.find((option) => option.id === sourceId)?.label}</dd></div><div><dt className="text-ink-tertiary">Initially approved</dt><dd className="mt-1 text-ink-heading">{selected.length} exact {selected.length === 1 ? "child" : "children"}</dd></div><div><dt className="text-ink-tertiary">Unselected</dt><dd className="mt-1 text-ink-heading">{Math.max(0, candidates.length - selected.length)} offered, no membership</dd></div></dl>{selected.length === 0 && <p className="rounded-md border border-amber-700/30 bg-amber-950/20 px-3 py-2 text-xs text-amber-200">This is valid: the scope begins with no approved Service children. Later exposures enter the human review queue.</p>}</>}</div>
  </Modal>;
}

function ConfirmModal({ confirm, busy, onDismiss, onSetting, onActive, onDelete, onDecision }: { confirm: Exclude<Confirm, null>; busy: boolean; onDismiss: () => void; onSetting: (enabled: boolean) => Promise<void>; onActive: (scope: Scope, active: boolean) => Promise<void>; onDelete: (scope: Scope) => Promise<void>; onDecision: (membership: Membership, decision: "approved" | "rejected") => Promise<void> }) {
  if (confirm.kind === "setting") return <Modal title={`${confirm.enabled ? "Enable" : "Disable"} cluster scopes for this organization?`} danger={!confirm.enabled} onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant={confirm.enabled ? "primary" : "danger"} disabled={busy} onClick={() => void onSetting(confirm.enabled)}>{busy ? "Saving…" : confirm.enabled ? "Enable scopes" : "Disable and withdraw"}</Button></>}><p className="text-sm text-ink-tertiary">{confirm.enabled ? "This makes still-current approved children eligible to grant again. It does not create a scope or approve a pending child. The change is audited and reversible." : "This immediately withdraws all scope-derived access for the organization. Scopes, decisions, and audit evidence are preserved; re-enabling can restore only still-current approvals."}</p></Modal>;
  if (confirm.kind === "active") return <Modal title={`${confirm.active ? "Enable" : "Disable"} this scope?`} danger={!confirm.active} onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant={confirm.active ? "primary" : "danger"} disabled={busy} onClick={() => void onActive(confirm.scope, confirm.active)}>{busy ? "Saving…" : confirm.active ? "Enable scope" : "Disable and withdraw"}</Button></>}><p className="text-sm text-ink-tertiary">{confirm.active ? "Only still-current, approved exact children can grant. The organization opt-in and entitlement must also be active. This transition is audited and reversible." : "All access derived from this scope is withdrawn. Membership decisions and audit evidence remain, so an authorized administrator can enable it again."}</p></Modal>;
  if (confirm.kind === "delete") return <Modal title="Permanently delete this scope?" danger onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void onDelete(confirm.scope)}>{busy ? "Deleting…" : "Delete permanently"}</Button></>}><div className="space-y-2 text-sm text-ink-tertiary"><p>Live scope and membership rows are removed and derived access is withdrawn. This operation has no rollback.</p><p>Append-only audit evidence remains. Recovery requires creating a new scope and explicitly selecting current exact children again.</p></div></Modal>;
  const reject = confirm.decision === "rejected";
  return <Modal title={`${reject ? "Reject" : "Approve"} this exact child?`} danger={reject} onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant={reject ? "danger" : "primary"} disabled={busy} onClick={() => void onDecision(confirm.membership, confirm.decision)}>{busy ? "Saving decision…" : reject ? "Reject permanently" : "Approve exact child"}</Button></>}><div className="space-y-2 text-sm text-ink-tertiary"><p>{confirm.membership.namespace}/{confirm.membership.service} · {protocolPort(confirm.membership)}</p><p>{reject ? "Rejection is permanent for this membership and grants nothing. Recovery requires a new scope or the future explicit-inclusion flow. The decision is audited." : "Approval applies only to this protocol/port child while its exact identity, scope, setting, and entitlement remain current. The decision is audited and cannot be changed to rejected later."}</p></div></Modal>;
}
