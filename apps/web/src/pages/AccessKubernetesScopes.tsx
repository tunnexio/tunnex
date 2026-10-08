import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { Link } from "react-router-dom";
import { AccessTabRail } from "../components/AccessTabRail";
import "../access-policies-resources.css";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { ResourceSummary } from "../components/ResourceSummary";
import { NetworkDetailList } from "../components/NetworkDetailList";
import {
  Button,
  DataTable,
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
  return <span className={`access-scope-state access-scope-state-${tone}`}>{children}</span>;
}

function permissionRole(members: Member[], userId: string): Role | undefined {
  return members.find((member) => member.user_id === userId && member.status === "active")?.role;
}

export default function AccessKubernetesScopes() {
  const { org } = useOrg();
  const { state } = useAuth();
  return <KubernetesScopesWorkspace key={`${org?.id ?? ""}:${state.status === "authed" ? state.user.id : ""}`} />;
}

function KubernetesScopesWorkspace() {
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
  const [view, setView] = useState<"scopes" | "queue">("scopes");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const mutationLock = useRef(false), alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; detailEpoch.current++; queueEpoch.current++; }; }, []);

  const canView = can(role, "k8s_scope:view") && can(role, "policy:view");
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
    if (!org) return false;
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
    if (epoch !== detailEpoch.current || scope.rule_id !== selectedRuleId) return false;
    if (!candidateResult.ok || !membershipResult.ok) {
      setDetailError(!candidateResult.ok ? candidateResult.error : membershipResult.ok ? "" : membershipResult.error);
      return false;
    }
    const next: Detail = {
      ruleId: scope.rule_id,
      candidates: [...new Map([...(append ? previous?.candidates ?? [] : []), ...candidateResult.data.items].map((item) => [item.service_child_id, item])).values()],
      memberships: [...new Map([...(append ? previous?.memberships ?? [] : []), ...membershipResult.data.items].map((item) => [item.service_child_id, item])).values()],
      candidateCursor: candidateResult.data.next_cursor,
      membershipCursor: membershipResult.data.next_cursor,
    };
    detailRef.current = next;
    setDetail(next);
    return true;
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
      setConfirm(null);
      setNotice("This scope changed in another session. Latest server state has been reloaded; review it before retrying.");
      await loadAll();
    } else setLoadError(apiErrorMessage(error, fallback));
  }, [loadAll]);

  async function toggleScope(scope: Scope, active: boolean) {
    if (!org || !canManageScope || mutationLock.current || !alive.current) return;
    mutationLock.current = true;
    setBusy(true);
    try {
      const response = await api.PUT("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}", {
        params: { path: { orgId: org.id, ruleId: scope.rule_id } },
        body: { active, expected_revision: scope.revision },
      });
      if (!alive.current) return;
      if (response.error) {
        await handleMutationError(response.error, `Could not ${active ? "enable" : "disable"} the scope.`);
        return;
      }
      setConfirm(null);
      setNotice(active ? "Scope enabled. Only still-current approved exact children can grant access." : "Scope disabled. Derived access was withdrawn; decisions were preserved for recovery.");
      await loadAll();
    } catch { if (alive.current) setLoadError("Could not reach the API. Reload saved state before retrying; the change was not confirmed."); } finally {
      mutationLock.current = false; if (alive.current) setBusy(false);
    }
  }

  async function deleteScope(scope: Scope) {
    if (!org || !canManageScope || mutationLock.current || !alive.current) return;
    mutationLock.current = true;
    setBusy(true);
    try {
      const response = await api.DELETE("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}", {
        params: { path: { orgId: org.id, ruleId: scope.rule_id }, query: { expected_revision: scope.revision } },
      });
      if (!alive.current) return;
      if (response.error) {
        await handleMutationError(response.error, "Could not delete the scope.");
        return;
      }
      setConfirm(null);
      setSelectedRuleId("");
      setNotice("Scope and live membership rows were deleted. Append-only audit evidence remains; recovery requires creating a new scope.");
      await loadAll();
    } catch { if (alive.current) setLoadError("Could not reach the API. Reload saved state before retrying; the change was not confirmed."); } finally {
      mutationLock.current = false; if (alive.current) setBusy(false);
    }
  }

  async function decide(membership: Membership, decision: "approved" | "rejected") {
    if (!org || !canApprove || !settings?.effective || (decision === "approved" && membership.current !== true) || mutationLock.current || !alive.current) return;
    mutationLock.current = true;
    setBusy(true);
    try {
      const response = await api.POST("/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}/memberships/{serviceChildId}/decision", {
        params: { path: { orgId: org.id, ruleId: membership.rule_id, serviceChildId: membership.service_child_id } },
        body: { decision },
      });
      if (!alive.current) return;
      if (response.error) {
        await handleMutationError(response.error, `Could not ${decision === "approved" ? "approve" : "reject"} the membership.`);
        return;
      }
      setConfirm(null);
      setNotice(decision === "approved" ? "Exact child approved. It grants only while the scope, organization setting, entitlement, and child identity remain active." : "Membership permanently rejected. It grants nothing; recovery requires a new scope or a future explicit-inclusion flow.");
      await loadAll();
    } catch { if (alive.current) setLoadError("Could not reach the API. Reload saved state before retrying; the change was not confirmed."); } finally {
      mutationLock.current = false; if (alive.current) setBusy(false);
    }
  }

  async function loadMoreQueue() {
    if (!org || !queueCursor || busy) return false;
    const epoch = ++queueEpoch.current;
    const loadAllGeneration = loadEpoch.current;
    const cursor = queueCursor;
    setQueueError(""); setBusy(true);
    try {
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scope-review-queue", { params: { path: { orgId: org.id }, query: { cursor, limit: 100 } } }));
      if (epoch !== queueEpoch.current || loadAllGeneration !== loadEpoch.current) return false;
      if (!result.ok) { setQueueError(result.error); return false; }
      if (result.data.next_cursor === cursor) { setQueueError("The review cursor did not advance. Reload server state before retrying."); return false; }
      setQueue((current) => [...new Map([...(current ?? []), ...result.data.items].map((item) => [`${item.rule_id}:${item.service_child_id}`, item])).values()]);
      setQueueCursor(result.data.next_cursor);
      return true;
    } finally {
      if (epoch === queueEpoch.current) setBusy(false);
    }
  }

  const header = <><PageHeader navigationTitle title="Kubernetes access scopes" /><AccessTabRail includeKubernetesScopes={canView} actions={permissionState === "allowed" ? <><Button variant="ghost" disabled={busy} onClick={() => { setPage(1); void loadAll(); }}>Refresh scopes</Button>{canCreateScope && settings && scopes && <Button disabled={busy || !settings.effective || Boolean(auxiliaryError) || !clusters || !services} onClick={() => setCreateOpen(true)}>Create scope</Button>}</> : undefined} /></>;
  const shellClass = "network-management access-scopes-workspace space-y-5";
  if (permissionState === "loading") return <div className={shellClass}>{header}<Loading label="Checking Kubernetes scope permissions…" /></div>;
  if (permissionState === "denied") return <div className={shellClass}>{header}<p role="alert" className="access-resource-copy">Kubernetes scope governance is available only to authorized Access administrators.</p><Link className="access-resource-link" to="/access">Return to Access policies</Link></div>;
  if (permissionState === "error") return <div className={shellClass}>{header}<ErrorText>{loadError || "Could not verify Kubernetes scope permissions."}</ErrorText><Button variant="ghost" onClick={() => void loadAll()}>Retry</Button></div>;
  if (!canView) return null;
  const matchedScopes = (scopes ?? []).filter((scope) => `${clusterLabel(scope.cluster_id, clusters ?? [])} ${sourceLabel(scope.source, sources)}`.toLowerCase().includes(query.trim().toLowerCase()));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(matchedScopes.length / pageSize)));
  const visibleScopes = matchedScopes.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const scopeState = (scope: Scope) => scopeExpired(scope) ? "Expired · ineffective" : scope.active ? settings?.effective ? "Active" : "Active · ineffective" : "Disabled";
  return <div className={shellClass} data-testid="k8s-scope-governance">
    {header}
    {notice && <p role="status" className="access-scope-notice">{notice}</p>}
    {loadError && <><ErrorText>{loadError}</ErrorText><Button variant="ghost" onClick={() => void loadAll()}>Reload server state</Button></>}
    {!loadError && (!settings || !scopes) && <Loading label="Loading preserved scopes and review state…" />}
    {!loadError && settings && scopes && <div className="access-resource-content">
      {!selectedRuleId ? <>
        <div className="access-scope-status"><div className="access-scope-status-copy"><span>Organization opt-in</span><StatePill tone={settings.effective ? "positive" : settings.entitlement_unlocked ? "attention" : "neutral"}>{settings.effective ? "Effective" : settings.enabled ? "Unavailable" : "Off"}</StatePill>{!settings.entitlement_unlocked && <span className="access-resource-context">Not in current plan</span>}</div><Link className="features-link" to="/settings?section=features&feature=kubernetes-scopes">Manage in Features</Link></div>
        {!settings.effective && <p role="status" className="access-resource-copy">Creation and approval are unavailable while the organization setting or entitlement is inactive. Preserved scopes remain readable.</p>}
        {auxiliaryError && <ErrorText>{auxiliaryError}</ErrorText>}
        {queueError && <ErrorText>{queueError}</ErrorText>}
        <div className="access-scope-tabs" role="group" aria-label="Kubernetes scope views"><button disabled={busy} aria-pressed={view === "scopes"} onClick={() => setView("scopes")}>Cluster scopes</button><button disabled={busy} aria-pressed={view === "queue"} onClick={() => setView("queue")}>Pending review</button></div>
        {view === "scopes" ? <>
          <div className="access-resource-toolbar"><Input aria-label="Search cluster scopes" placeholder="Search cluster or source" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} /></div>
          <DataTable variant="flat" caption="Kubernetes cluster scopes" rows={visibleScopes} rowKey={(scope) => scope.rule_id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={query ? "No matching scopes" : "No cluster scopes yet"} description={query ? "Try another cluster or source." : "Creating a scope starts with zero Services selected."} action={query ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />} columns={[
            { key: "scope", header: "Cluster / source", cell: (scope) => <div className="access-resource-cell"><button className="access-resource-name" aria-label={`${clusterLabel(scope.cluster_id, clusters ?? [])} ${scopeState(scope)}`} onClick={() => setSelectedRuleId(scope.rule_id)}>{clusterLabel(scope.cluster_id, clusters ?? [])}</button><small>{sourceLabel(scope.source, sources)}</small></div> },
            { key: "state", header: "State", cell: (scope) => <StatePill tone={scopeExpired(scope) ? "danger" : scope.active && settings.effective ? "positive" : "neutral"}>{scopeState(scope)}</StatePill> },
            { key: "expiry", header: "Expires", cell: (scope) => scope.expires_at ? <span title={scope.expires_at}>{relativeAge(scope.expires_at)}</span> : "No expiry" },
            { key: "actions", header: "Actions", cell: (scope) => <AppAccessRowMenu label={`Actions for scope ${clusterLabel(scope.cluster_id, clusters ?? [])}`} actions={[{ key: "detail", label: "View scope", onSelect: () => setSelectedRuleId(scope.rule_id) }, ...(canManageScope ? [{ key: "active", label: scope.active ? "Disable scope" : "Enable scope", disabledReason: busy ? "Wait for the current action." : !scope.active && (!settings.effective || scopeExpired(scope)) ? "Organization enforcement must be active and the scope unexpired." : undefined, onSelect: () => setConfirm({ kind: "active", scope, active: !scope.active }) }, { key: "delete", label: "Delete scope", danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => setConfirm({ kind: "delete", scope }) }] : [])]} /> },
          ]} />
          <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={visibleScopes.length} hasNext={currentPage * pageSize < matchedScopes.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
        </> : queue === null ? queueError ? <Button variant="ghost" onClick={() => void loadAll()}>Retry queue</Button> : <Loading label="Loading pending reviews…" /> : queue.length === 0 && !queueCursor ? <AppAccessEmptyState icon={null} title="No later-exposure decisions are pending." /> : <ScopeEvidenceList label="Pending reviews" items={queue} searchText={(membership) => `${membership.namespace}/${membership.service} ${membership.protocol} ${membership.port}`} hasMore={Boolean(queueCursor)} busy={busy} onLoadMore={loadMoreQueue} renderItem={(membership) => <li key={`${membership.rule_id}:${membership.service_child_id}`}><MembershipRow membership={membership} busy={busy} canApprove={canApprove && settings.effective} onDecision={(decision) => setConfirm({ kind: "decision", membership, decision })} /></li>} />}
        <details className="access-resource-help"><summary>Scope authority and organization setting</summary><p>A licence unlocks this capability and requires explicit organization opt-in. Turning it off withdraws scope-derived access and preserves decisions. A scope grants only individually approved, still-current Service protocol/port children; it grants no namespace, cluster, Pod, Node, CIDR, or sibling port. Rejection is permanent; disabled scopes and opt-in are reversible.</p><p>Setting revision {settings.revision}. Explicit opt-in: {settings.enabled ? "Enabled" : "Disabled"}. Licensed: {settings.entitlement_unlocked ? "Available" : "Not in current plan"}.</p></details>
      </> : <ScopeDetail scope={scopes.find((scope) => scope.rule_id === selectedRuleId) ?? null} settings={settings} detail={detail?.ruleId === selectedRuleId ? detail : null} error={detailError} clusters={clusters ?? []} sources={sources} canManage={canManageScope} busy={busy} onBack={() => setSelectedRuleId("")} onReload={(scope) => { void loadDetail(scope); }} onLoadMore={(scope) => loadDetail(scope, true)} onActive={(scope, active) => setConfirm({ kind: "active", scope, active })} onDelete={(scope) => setConfirm({ kind: "delete", scope })} />}
    </div>}
    {createOpen && canCreateScope && settings && settings.effective && !auxiliaryError && clusters && services && <CreateScopeModal orgId={org?.id ?? ""} clusters={clusters} services={services} sources={sources} busy={busy} onDismiss={() => { if (!busy) setCreateOpen(false); }} onBusy={setBusy} onError={setLoadError} onCreated={async (scope) => { setCreateOpen(false); setSelectedRuleId(scope.rule_id); setNotice("Scope created. Only the exact children explicitly selected in the review step were initially approved."); await loadAll(); }} />}
    {confirm && <ConfirmModal confirm={confirm} error={loadError} busy={busy} onDismiss={() => { if (!busy) setConfirm(null); }} onActive={toggleScope} onDelete={deleteScope} onDecision={decide} />}
  </div>;
}

function ScopeEvidenceList<T>({ label, items, searchText, renderItem, hasMore, busy, onLoadMore }: { label: string; items: T[]; searchText: (item: T) => string; renderItem: (item: T) => React.ReactNode; hasMore: boolean; busy: boolean; onLoadMore: () => Promise<boolean> }) {
  const [query, setQuery] = useState(""), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [loading, setLoading] = useState(false);
  const filtered = items.filter((item) => searchText(item).toLowerCase().includes(query.trim().toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages), visible = filtered.slice((current - 1) * pageSize, current * pageSize);
  const next = async () => { if (current < pages) { setPage(current + 1); return; } if (!hasMore || loading) return; setLoading(true); try { if (await onLoadMore()) setPage(current + 1); } finally { setLoading(false); } };
  return <div className="access-resource-content">{(items.length > 10 || query) && <Input aria-label={`Search loaded ${label.toLowerCase()}`} placeholder={`Search loaded ${label.toLowerCase()}`} value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} />}{filtered.length ? <ul aria-label={label}>{visible.map(renderItem)}</ul> : <p className="access-resource-copy">No matching loaded rows.</p>}<AppAccessPagination maxOffset={null} page={current} pageSize={pageSize} count={visible.length} hasNext={current < pages || hasMore} busy={busy || loading} onPageChange={(requested) => requested > current ? void next() : setPage(requested)} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} previousLabel={`Previous ${label.toLowerCase()}`} nextLabel={`Next ${label.toLowerCase()}`} /></div>;
}

function MembershipRow({ membership, canApprove, busy, onDecision }: { membership: Membership; canApprove: boolean; busy: boolean; onDecision: (decision: "approved" | "rejected") => void }) {
  return <article className="access-scope-member"><div><span>{membership.namespace}/{membership.service}<small> · {protocolPort(membership)}</small></span><div><StatePill tone={membership.effective ? "positive" : !membership.current ? "danger" : membership.status === "pending" ? "attention" : "neutral"}>{membership.effective ? "Effective" : membership.current ? membership.status : "Vanished"}</StatePill>{membership.status === "pending" && canApprove && <AppAccessRowMenu label={`Actions for ${membership.namespace}/${membership.service} ${protocolPort(membership)}`} actions={[{ key: "approve", label: "Review approval", disabledReason: busy ? "Wait for the current action." : !membership.current ? "This exact Service identity is no longer current." : undefined, onSelect: () => onDecision("approved") }, { key: "reject", label: "Review rejection", danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => onDecision("rejected") }]} />}</div></div><small>{membership.origin}{membership.decided_at ? ` · decided ${relativeAge(membership.decided_at)}` : ""}</small>{!membership.current && <p className="access-resource-copy">The exact child no longer maps to its original live Service identity. It grants nothing; history is retained.</p>}{membership.effective === false && membership.inactive_reason && <p className="access-resource-copy">{inactiveReasonLabel(membership.inactive_reason)}</p>}</article>;
}

function ScopeDetail({ scope, settings, detail, error, clusters, sources, canManage, busy, onBack, onReload, onLoadMore, onActive, onDelete }: { scope: Scope | null; settings: ScopeSettings; detail: Detail | null; error: string; clusters: K8sCluster[]; sources: SourceOption[]; canManage: boolean; busy: boolean; onBack: () => void; onReload: (scope: Scope) => void; onLoadMore: (scope: Scope) => Promise<boolean>; onActive: (scope: Scope, active: boolean) => void; onDelete: (scope: Scope) => void }) {
  const [view, setView] = useState<"memberships" | "candidates">("memberships");
  if (!scope) return <AppAccessEmptyState icon={null} title="Scope unavailable" action={<Button variant="ghost" onClick={onBack}>Back to scopes</Button>} />;
  const expired = scopeExpired(scope), effective = scope.active && settings.effective && !expired;
  return <div className="access-resource-content">
    <nav aria-label="Breadcrumb" className="access-resource-breadcrumb"><button disabled={busy} onClick={onBack}>Kubernetes scopes</button><span aria-hidden="true">/</span><span aria-current="page">{clusterLabel(scope.cluster_id, clusters)}</span></nav>
    <div className="access-resource-heading"><div><h2>{clusterLabel(scope.cluster_id, clusters)}</h2></div><div className="access-resource-actions"><Button variant="ghost" disabled={busy} onClick={() => onReload(scope)}>Refresh detail</Button>{canManage && <AppAccessRowMenu label="Scope actions" actions={[{ key: "active", label: scope.active ? "Disable scope" : "Enable scope", disabledReason: busy ? "Wait for the current action." : !scope.active && (!settings.effective || expired) ? "Organization enforcement must be active and the scope unexpired." : undefined, onSelect: () => onActive(scope, !scope.active) }, { key: "delete", label: "Delete scope", danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => onDelete(scope) }]} />}</div></div>
    <ResourceSummary title="Scope settings"><dl className="tnx-resource-facts tnx-resource-facts-three"><div><dt>Source</dt><dd>{sourceLabel(scope.source, sources)}</dd></div><div><dt>State</dt><dd><StatePill tone={effective ? "positive" : expired ? "danger" : scope.active ? "attention" : "neutral"}>{effective ? "Active" : expired ? "Expired and ineffective" : scope.active ? "Active but ineffective" : "Disabled"}</StatePill></dd></div><div><dt>Expiry</dt><dd>{scope.expires_at ? <span title={scope.expires_at}>Expires {relativeAge(scope.expires_at)}</span> : "No expiry"}</dd></div><div><dt>Revision</dt><dd>{scope.revision}</dd></div></dl></ResourceSummary>
    {scope.active && !effective && <p className="access-resource-copy">Stored active state is preserved, but it currently grants nothing because {expired ? "the scope has expired" : "the organization opt-in or entitlement is inactive"}.</p>}
    {error && <ErrorText>{error}</ErrorText>}
    {detail === null ? error ? <Button variant="ghost" onClick={() => onReload(scope)}>Retry detail</Button> : <Loading label="Loading initial evidence and membership history…" /> : <>
      <div className="access-scope-tabs" role="group" aria-label="Scope evidence views"><button disabled={busy} aria-pressed={view === "memberships"} onClick={() => setView("memberships")}>Membership history</button><button disabled={busy} aria-pressed={view === "candidates"} onClick={() => setView("candidates")}>Initial candidate evidence</button></div>
      {view === "memberships" ? detail.memberships.length === 0 && !detail.membershipCursor ? <AppAccessEmptyState icon={null} title="No memberships exist for this scope." /> : <ScopeEvidenceList key={`${scope.rule_id}:memberships`} label="Membership history" items={detail.memberships} searchText={(membership) => `${membership.namespace}/${membership.service} ${membership.protocol} ${membership.port} ${membership.status}`} hasMore={Boolean(detail.membershipCursor)} busy={busy} onLoadMore={() => onLoadMore(scope)} renderItem={(membership) => <li key={membership.service_child_id}><MembershipRow membership={membership} canApprove={false} busy={busy} onDecision={() => {}} /></li>} />
      : <><p className="access-resource-copy">Immutable creation-time snapshot. Unselected rows were offered, not rejected.</p>{detail.candidates.length === 0 && !detail.candidateCursor ? <AppAccessEmptyState icon={null} title="No exact children were offered when this scope was created." /> : <ScopeEvidenceList key={`${scope.rule_id}:candidates`} label="Initial candidate evidence" items={detail.candidates} searchText={(candidate) => `${candidate.namespace}/${candidate.service} ${candidate.protocol} ${candidate.port}`} hasMore={Boolean(detail.candidateCursor)} busy={busy} onLoadMore={() => onLoadMore(scope)} renderItem={(candidate) => <li key={candidate.service_child_id} className="access-scope-member"><div><span>{candidate.namespace}/{candidate.service}<small> · {protocolPort(candidate)}</small></span><StatePill tone={candidate.effective ? "positive" : candidate.selected ? "attention" : "neutral"}>{candidate.effective ? "Effective" : candidate.selected ? "Selected · ineffective" : "Not selected"}</StatePill></div>{candidate.current === false && <StatePill tone="danger">Vanished</StatePill>}{candidate.effective === false && candidate.inactive_reason && <p className="access-resource-copy">{inactiveReasonLabel(candidate.inactive_reason)}</p>}</li>} />}</>}
    </>}
    <details className="access-resource-help"><summary>Scope identity and authority</summary><p>Rule {scope.rule_id}. {scope.initial_candidate_count} initial candidates offered · created {relativeAge(scope.created_at)}. Only individually approved, still-current Service protocol/port children grant access while this scope, organization opt-in, and entitlement are active. Rejected decisions remain permanent.</p></details>
  </div>;
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
  const [uncertain, setUncertain] = useState(false);
  const locked = useRef(false), alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const sourceOptions = sources.filter((option) => option.kind === sourceKind);
  const candidates = useMemo(() => services.filter((service) => service.cluster_id === clusterId && exactChild(service)).sort((a, b) => `${a.namespace}/${a.name}/${a.protocol}/${a.port_low}`.localeCompare(`${b.namespace}/${b.name}/${b.protocol}/${b.port_low}`)), [clusterId, services]);
  const sourceReady = sourceKind === "cidr" ? cidr.trim().length > 0 : sourceId.length > 0;

  async function submit() {
    if (locked.current || uncertain || !alive.current || !clusterId || !sourceReady || selected.length > 100) return;
    locked.current = true;
    onBusy(true);
    setLocalError("");
    try {
      const source: CreateScopeSource = sourceKind === "cidr" ? { kind: "cidr", cidr: cidr.trim() } : { kind: sourceKind, id: sourceId };
      const response = await api.POST("/api/v1/organizations/{orgId}/k8s/cluster-scopes", { params: { path: { orgId } }, body: { cluster_id: clusterId, source, initial_service_child_ids: selected, expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined } });
      if (!alive.current) return;
      if (response.error || !response.data) {
        const message = apiErrorMessage(response.error, "Could not create the scope. Current candidates may have changed; close and reload before retrying.");
        setLocalError(message);
        onError(message);
        return;
      }
      await onCreated(response.data);
    } catch { if (alive.current) { const message = "Creation was not confirmed. Close and reload server state before retrying."; setUncertain(true); setLocalError(message); onError(message); } } finally {
      locked.current = false; onBusy(false);
    }
  }

  return <Modal title="Create Kubernetes access scope" placement="right" size="enrollment" showClose onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={step === 1 ? onDismiss : () => setStep((step - 1) as 1 | 2)}>Back</Button>{step < 3 ? <Button disabled={busy || (step === 1 && (!clusterId || !sourceReady))} onClick={() => setStep((step + 1) as 2 | 3)}>Continue</Button> : <Button disabled={busy || uncertain || !clusterId || !sourceReady || selected.length > 100} onClick={() => void submit()}>{busy ? "Creating…" : "Create scope"}</Button>}</>}>
    <div className="access-scope-editor"><p aria-label={`Step ${step} of 3`}>Step {step} of 3</p><ErrorText>{localError}</ErrorText>
      {step === 1 && <><h3>Cluster and Access source</h3><Field label="Enrolled cluster"><Select autoFocus disabled={busy} value={clusterId} onChange={(event) => { setClusterId(event.target.value); setSelected([]); }}><option value="">Choose a cluster…</option>{clusters.map((cluster) => <option key={cluster.id} value={cluster.id}>{cluster.name} · {cluster.platform.replace(/_/g, " ")}</option>)}</Select></Field><Field label="Source type"><Select disabled={busy} value={sourceKind} onChange={(event) => { setSourceKind(event.target.value as CreateScopeSource["kind"]); setSourceId(""); setCidr(""); }}><option value="group">Group</option><option value="user">User</option><option value="site">Site</option><option value="agent">Agent</option><option value="cidr">Exact CIDR</option></Select></Field>{sourceKind === "cidr" ? <Field label="Source CIDR"><Input disabled={busy} value={cidr} placeholder="10.20.0.0/24" onChange={(event) => setCidr(event.target.value)} /></Field> : <Field label={`${sourceKind[0].toUpperCase()}${sourceKind.slice(1)}`}><Select disabled={busy} value={sourceId} onChange={(event) => setSourceId(event.target.value)}><option value="">Choose a current {sourceKind}…</option>{sourceOptions.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</Select></Field>}<details><summary>Expiry</summary><Field label="Expires at (optional)"><Input disabled={busy} type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></Field></details></>}
      {step === 2 && <><h3>Select initial exact children</h3><p>Nothing is selected by default. Unselected children are recorded as offered, not rejected.</p><p>{candidates.length} current exact children · {selected.length} selected · maximum 100</p>{candidates.length === 0 ? <AppAccessEmptyState icon={null} title="No current exposed exact-port children" description="Expose verified TCP/UDP Services in Kubernetes first." /> : <fieldset><legend className="sr-only">Initial exact Service children</legend><NetworkDetailList label="Initial exact Service children" items={candidates} searchText={(service) => `${service.namespace}/${service.name} ${service.protocol} ${service.port_low} ${service.fqdn}`} renderItem={(service) => { const checked = selected.includes(service.id); return <li key={service.id}><label><input type="checkbox" aria-label={`${service.namespace}/${service.name} ${service.protocol.toUpperCase()} ${service.port_low}`} checked={checked} disabled={busy || (!checked && selected.length >= 100)} onChange={() => setSelected((current) => checked ? current.filter((id) => id !== service.id) : current.length < 100 ? [...current, service.id] : current)} /><span>{service.namespace}/{service.name}<small>{service.protocol.toUpperCase()} {service.port_low} · {service.fqdn}</small></span></label></li>; }} /></fieldset>}</>}
      {step === 3 && <><h3>Review exact authority</h3><p>Creating approves only the selected exact children in one transaction. No namespace, sibling port, ClusterIP, Pod, Node, or provider account is granted.</p><dl className="access-scope-review-facts tnx-resource-facts"><DetailFact label="Cluster" value={clusters.find((cluster) => cluster.id === clusterId)?.name ?? clusterId} /><DetailFact label="Source" value={sourceKind === "cidr" ? cidr : sourceOptions.find((option) => option.id === sourceId)?.label ?? sourceId} /><DetailFact label="Initially approved" value={`${selected.length} exact ${selected.length === 1 ? "child" : "children"}`} /><DetailFact label="Unselected" value={`${Math.max(0, candidates.length - selected.length)} offered, no membership`} /></dl>{selected.length === 0 && <p>This scope begins with no approved Service children. Later exposures enter the human review queue.</p>}</>}
    </div>
  </Modal>;
}

function DetailFact({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }

function ConfirmModal({ confirm, error, busy, onDismiss, onActive, onDelete, onDecision }: { confirm: Exclude<Confirm, null>; error: string; busy: boolean; onDismiss: () => void; onActive: (scope: Scope, active: boolean) => Promise<void>; onDelete: (scope: Scope) => Promise<void>; onDecision: (membership: Membership, decision: "approved" | "rejected") => Promise<void> }) {
  if (confirm.kind === "active") return <Modal showClose title={`${confirm.active ? "Enable" : "Disable"} this scope?`} danger={!confirm.active} onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant={confirm.active ? "primary" : "danger"} disabled={busy} onClick={() => void onActive(confirm.scope, confirm.active)}>{busy ? "Saving…" : confirm.active ? "Enable scope" : "Disable and withdraw"}</Button></>}><><ErrorText>{error}</ErrorText><p className="text-sm text-ink-tertiary">{confirm.active ? "Only still-current, approved exact children can grant. The organization opt-in and entitlement must also be active. This transition is audited and reversible." : "All access derived from this scope is withdrawn. Membership decisions and audit evidence remain, so an authorized administrator can enable it again."}</p></></Modal>;
  if (confirm.kind === "delete") return <Modal showClose title="Permanently delete this scope?" danger onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void onDelete(confirm.scope)}>{busy ? "Deleting…" : "Delete permanently"}</Button></>}><div className="space-y-2 text-sm text-ink-tertiary"><ErrorText>{error}</ErrorText><p>Live scope and membership rows are removed and derived access is withdrawn. This operation has no rollback.</p><p>Append-only audit evidence remains. Recovery requires creating a new scope and explicitly selecting current exact children again.</p></div></Modal>;
  const reject = confirm.decision === "rejected";
  return <Modal showClose title={`${reject ? "Reject" : "Approve"} this exact child?`} danger={reject} onDismiss={onDismiss} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant={reject ? "danger" : "primary"} disabled={busy} onClick={() => void onDecision(confirm.membership, confirm.decision)}>{busy ? "Saving decision…" : reject ? "Reject permanently" : "Approve exact child"}</Button></>}><div className="space-y-2 text-sm text-ink-tertiary"><ErrorText>{error}</ErrorText><p>{confirm.membership.namespace}/{confirm.membership.service} · {protocolPort(confirm.membership)}</p><p>{reject ? "Rejection is permanent for this membership and grants nothing. Recovery requires a new scope or the future explicit-inclusion flow. The decision is audited." : "Approval applies only to this protocol/port child while its exact identity, scope, setting, and entitlement remain current. The decision is audited and cannot be changed to rejected later."}</p></div></Modal>;
}
