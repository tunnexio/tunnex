import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { type components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { can } from "../lib/rbac";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { Button, Field, Input, Loading, Modal, Select, RefreshButton } from "./ui";
import { HelpTooltip, modelDisplayName } from "./HelpTooltip";
import { toast } from "./Toasts";
import { AIChatPlayground } from "./AIChatPlayground";
import { AIModelConnectionDetails } from "./AIModelConnectionDetails";
import AppAccessRowMenu from "./AppAccessRowMenu";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessEmptyState from "./AppAccessEmptyState";
import { AIGatewayOffBanner, useAIGatewayStatus } from "./AIGatewayOffBanner";
import "./ai-gateway-access.css";
type S = components["schemas"];
type Capabilities = { view: boolean; manage: boolean; agents: boolean; workloadsView:boolean; workloadsManage:boolean; serverAdmin: boolean };

export function AIAccessGate({ children }: { children: (orgId: string, access: Capabilities) => ReactNode }) {
  const { org } = useOrg(); const { state } = useAuth();
  const user = state.status === "authed" ? state.user.id : "";
  const writable = state.status === "authed" && state.user.email_verified === true && !state.user.must_change_password;
  const serverAdmin = state.status === "authed" && Boolean(state.user.cp_admin);
  const scope = `${org?.id}/${user}/${writable}/${serverAdmin}`;
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ scope: string; access?: Capabilities } | null>(null);
  useEffect(() => {
    let active = true; setResult(null);
    if (!org || !user) return;
    void api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }).then(({ data, error }) => {
      if (!active) return;
      const member = !error && data?.find((m) => m.user_id === user);
      const roles = member ? member.roles ?? [member.role] : [];
      setResult({ scope, ...(member ? { access: { view: can(roles, "ai_gateway:view"), manage: writable && can(roles, "ai_gateway:manage"), agents: writable && can(roles, "agent_template:manage"),workloadsView:can(roles,"ai_workload:view"),workloadsManage:writable && can(roles,"ai_workload:manage"), serverAdmin } } : {}) });
    }).catch(() => { if (active) setResult({ scope }); });
    return () => { active = false; };
  }, [scope, attempt]);
  if (!org || !result || result.scope !== scope) return <Loading label="Checking AI access…" />;
  if (!result.access) return <div className="ai-secondary-empty"><p role="alert">Could not check AI access.</p><Button variant="ghost" onClick={() => setAttempt((v) => v + 1)}>Retry permissions</Button></div>;
  return <>{children(org.id, result.access)}</>;
}

type GroupAccessProps = { orgId: string; canManage: boolean; initialConnection?: string; initialModel?: string; dialogOnly?: boolean; onDone?: () => void };

export function AIGroupAccess(props: GroupAccessProps) {
  const { state } = useAuth();
  const user = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : "anonymous";
  return <GroupAccessPanel key={`${props.orgId}:${user}:${props.canManage}`} {...props} />;
}

function GroupAccessPanel({ orgId, canManage, initialConnection = "", initialModel = "", dialogOnly = false, onDone }: GroupAccessProps) {
  const { state } = useAuth();
  const userId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const serverAdmin = state.status === "authed" && Boolean(state.user.cp_admin);
  const gateway = useAIGatewayStatus(orgId);
  const scope = `${orgId}/${userId}`;
  const currentScope = useRef(scope); currentScope.current = scope;
  const alive = useRef(true), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const [grantOpen, setGrantOpen] = useState(dialogOnly || Boolean(initialModel));
  const [createGroupOpen, setCreateGroupOpen] = useState(false), [groupName, setGroupName] = useState("");
  const [groupPermission, setGroupPermission] = useState<{ scope: string; allowed: boolean | null } | null>(null);
  const [permissionAttempt, setPermissionAttempt] = useState(0), [groupRefreshFailed, setGroupRefreshFailed] = useState(false);
  const creationAllowed = groupPermission?.scope === scope ? groupPermission.allowed : undefined;
  const [query, setQuery] = useState(""), [modelFilter, setModelFilter] = useState(""), [modelQuery, setModelQuery] = useState("");
  const [expanded, setExpanded] = useState<string[]>([]);
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [revokeGrant, setRevokeGrant] = useState<S["AIUserModelGrant"] | null>(null);
  const [limitGroup, setLimitGroup] = useState<{ id: string; name: string } | null>(null), [limitInput, setLimitInput] = useState(""), [limitError, setLimitError] = useState("");
  const closeGrant = () => { setGrantOpen(false); setCreateGroupOpen(false); setGroupName(""); setModelQuery(""); setSelections([]); onDone?.(); };
  const [data, setData] = useState<{ groups: S["AIUserGroup"][]; grants: S["AIUserModelGrant"][]; providers: S["AIProviderConnection"][] } | null>(null);
  const [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [group, setGroup] = useState(""), [selections, setSelections] = useState<string[]>(initialConnection && initialModel ? [JSON.stringify([initialConnection, initialModel])] : []);
  useEffect(() => {
    if (!grantOpen || !canManage) return;
    let active = true;
    setGroupPermission(null);
    if (!userId || !emailVerified) { setGroupPermission({ scope, allowed: false }); return; }
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })).then((result) => {
      if (!active) return;
      if (!result.ok) { setGroupPermission({ scope, allowed: null }); return; }
      const member = result.data.find((m) => m.user_id === userId);
      setGroupPermission({ scope, allowed: can(member?.roles ?? (member ? [member.role] : []), "policy:manage") });
    });
    return () => { active = false; };
  }, [scope, emailVerified, grantOpen, canManage, permissionAttempt]);
  useEffect(() => {
    let active = true;
    const params = { params: { path: { orgId } } };
    void Promise.all([api.GET("/api/v1/organizations/{orgId}/ai-gateway/user-groups", params), api.GET("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", params), api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", params)]).then(([g, a, p]) => {
      if (!active) return;
      if (g.error || a.error || p.error || !g.data || !a.data || !p.data) throw Error();
      setData({ groups: g.data, grants: a.data, providers: p.data.items }); setGroupRefreshFailed(false);
    }).catch(() => { if (active) setError("Could not load group access. Retry to refresh the saved state."); });
    return () => { active = false; };
  }, [orgId, attempt]);
  const models = data?.providers.filter((p) => p.enabled && p.status === "applied" && p.revision === p.applied_revision).flatMap((p) => p.models.map((model) => ({ key: JSON.stringify([p.id, model]), model, connection: p.id, name: p.name }))) ?? [];
  // A model this group already holds through an enabled grant is shown as granted and not sent again.
  const heldByGroup = (m: { connection: string; model: string }) => !!group && !!data?.grants.some((g) => g.group_id === group && g.connection_id === m.connection && g.model === m.model && g.enabled);
  const selected = models.filter((m) => selections.includes(m.key) && !heldByGroup(m));
  const toggleModel = (key: string, on: boolean) => setSelections((current) => on ? [...current.filter((k) => k !== key), key] : current.filter((k) => k !== key));
  // One row per group (AI-CATALOG-1). A search matching the group name keeps all its models; a search
  // matching only model names keeps just those models. The model filter keeps groups that hold that model.
  const groupRows = (() => {
    const rows = new Map<string, { key: string; groupId: string | null; name: string; grants: S["AIUserModelGrant"][] }>();
    for (const grant of data?.grants ?? []) {
      const key = grant.group_id ?? `deleted:${grant.group_name ?? ""}`;
      const row = rows.get(key) ?? { key, groupId: grant.group_id ?? null, name: grant.group_name || "Deleted group", grants: [] };
      row.grants.push(grant); rows.set(key, row);
    }
    const q = query.trim().toLowerCase();
    return [...rows.values()].map((row) => {
      const byModel = modelFilter ? row.grants.filter((g) => g.model === modelFilter) : row.grants;
      const shown = !q || row.name.toLowerCase().includes(q) ? byModel : byModel.filter((g) => g.model.toLowerCase().includes(q));
      return { ...row, grants: [...shown].sort((a, b) => a.model.localeCompare(b.model)) };
    }).filter((row) => row.grants.length).sort((a, b) => a.name.localeCompare(b.name));
  })();
  const grantedModels = [...new Set((data?.grants ?? []).map((g) => g.model))].sort();
  const currentPage = Math.min(page, Math.max(1, Math.ceil(groupRows.length / pageSize)));
  const visibleRows = groupRows.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const filtering = Boolean(query || modelFilter);
  const visibleChoices = models.filter((m) => `${m.model} ${m.name}`.toLowerCase().includes(modelQuery.trim().toLowerCase()));
  async function refreshGroups(createdId?: string) {
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ai-gateway/user-groups", { params: { path: { orgId } } }));
    if (!alive.current || currentScope.current !== scope) return;
    if (!result.ok || (createdId && !result.data.some((g) => g.id === createdId))) {
      setGroupRefreshFailed(true);
      setError(createdId ? "Group created, but the inventory could not be refreshed. Refresh groups before granting access." : "Could not refresh groups. Try again before creating or granting access.");
      return;
    }
    setData((d) => d ? { ...d, groups: result.data } : d); setGroupRefreshFailed(false);
  }
  async function createGroup() {
    const name = groupName.trim();
    if (locked.current || !alive.current || !canManage || creationAllowed !== true || groupRefreshFailed || !name || name.length > 100) return;
    locked.current = true;
    setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } }, body: { name } });
      if (!alive.current || currentScope.current !== scope) return;
      if (result.error || !result.data) {
        const uncertain = !result.error || !result.response || result.response.status >= 500;
        setError(uncertain ? "Could not confirm group creation. Refresh groups before retrying." : apiErrorMessage(result.error, "Could not create the user group."));
        if (uncertain) setGroupRefreshFailed(true);
        return;
      }
      const created = result.data;
      setData((d) => d ? { ...d, groups: [...d.groups.filter((g) => g.id !== created.id), { id: created.id, name: created.name, members: created.member_count, daily_usd_threshold: null, limit_revision: 0 }] } : d);
      setGroup(created.id); setGroupName(""); setCreateGroupOpen(false);
      toast.success("User group created");
      await refreshGroups(created.id);
    } catch {
      if (alive.current && currentScope.current === scope) { setError("Could not reach the API. Refresh groups to check whether the group was created before retrying."); setGroupRefreshFailed(true); }
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  async function save(groupId: string, connectionId: string, model: string, enabled: boolean) {
    if (locked.current || !alive.current || !canManage || !data) return;
    const old = data.grants.find((g) => g.group_id === groupId && g.connection_id === connectionId && g.model === model);
    locked.current = true; setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", { params: { path: { orgId } }, body: { group_id: groupId, connection_id: connectionId, model, enabled, expected_revision: old?.revision ?? 0 } });
      if (!alive.current || currentScope.current !== scope) return;
      if (result.error || !result.data) throw Error();
      const grant = result.data;
      setData((d) => d ? { ...d, grants: [...d.grants.filter((g) => g.id !== grant.id), grant] } : d);
      if (grant.status === "applied") { toast.success("Model access granted"); closeGrant(); }
      else if (!enabled) toast.success("Model access revoked");
      else setError("Access is saved but not active yet. Provisioning will retry; refresh to check its state.");
    } catch { if (alive.current) setError("Could not apply this change. Refresh the saved state before retrying."); }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  // The API takes one grant per call; several models are granted one after another. Each grant stands on
  // its own, so a failure leaves only the models that did not apply selected for a retry.
  async function grantMany(groupId: string, picks: typeof selected) {
    if (locked.current || !alive.current || !canManage || !data || !picks.length) return;
    const startScope = scope;
    locked.current = true; setBusy(true); setError("");
    const failed: typeof picks = [], pending: typeof picks = [], saved: S["AIUserModelGrant"][] = [];
    try {
      for (const pick of picks) {
        if (!alive.current || currentScope.current !== startScope) return;
        const old = data.grants.find((g) => g.group_id === groupId && g.connection_id === pick.connection && g.model === pick.model);
        try {
          const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", { params: { path: { orgId } }, body: { group_id: groupId, connection_id: pick.connection, model: pick.model, enabled: true, expected_revision: old?.revision ?? 0 } });
          if (!alive.current || currentScope.current !== startScope) return;
          if (result.error || !result.data) { failed.push(pick); continue; }
          saved.push(result.data);
          if (result.data.status !== "applied") pending.push(pick);
        } catch { failed.push(pick); }
      }
      if (!alive.current || currentScope.current !== startScope) return;
      setData((d) => d ? { ...d, grants: [...d.grants.filter((g) => !saved.some((s) => s.id === g.id)), ...saved] } : d);
      if (!failed.length && !pending.length) { toast.success(picks.length === 1 ? "Model access granted" : `Model access granted to ${picks.length} models`); closeGrant(); return; }
      setSelections(failed.map((m) => m.key));
      const names = (list: typeof picks) => list.map((m) => modelDisplayName(m.model)).join(", ");
      const messages = [];
      if (failed.length) messages.push(`Granted ${picks.length - failed.length} of ${picks.length} model${picks.length === 1 ? "" : "s"}. Could not apply: ${names(failed)}. Refresh the saved state, then retry the models still selected.`);
      if (pending.length) messages.push(`Access is saved but not active yet for ${names(pending)}. Provisioning will retry; refresh to check its state.`);
      setError(messages.join(" "));
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  // A user group's daily cost limit is a soft threshold shared by all its members (AI-CATALOG-1).
  const groupLimit = (groupId: string | null) => groupId ? data?.groups.find((g) => g.id === groupId)?.daily_usd_threshold ?? null : null;
  const limitValue = limitInput.trim() === "" ? NaN : Number(limitInput);
  const limitValid = Number.isFinite(limitValue) && limitValue > 0 && limitValue <= 100000;
  function openLimit(groupId: string, name: string) {
    const current = groupLimit(groupId);
    setLimitGroup({ id: groupId, name }); setLimitInput(current == null ? "" : String(current)); setLimitError("");
  }
  async function saveLimit(value: number | null) {
    const target = limitGroup;
    const saved = target && data?.groups.find((g) => g.id === target.id);
    if (locked.current || !alive.current || !canManage || !target) return;
    if (!saved) { setLimitError("This group is no longer in the list. Refresh access and try again."); return; }
    const startScope = scope;
    locked.current = true; setBusy(true); setLimitError("");
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/user-groups/{groupId}/cost-limit", { params: { path: { orgId, groupId: target.id } }, body: { daily_usd_threshold: value, expected_revision: saved.limit_revision } });
      if (!alive.current || currentScope.current !== startScope) return;
      if (result.error || !result.data) {
        if (result.response?.status !== 409) { setLimitError(apiErrorMessage(result.error, "Could not save the daily cost limit.")); return; }
        // Someone else saved first: load the current limit so the next save is made against it.
        const latest = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ai-gateway/user-groups", { params: { path: { orgId } } }));
        if (!alive.current || currentScope.current !== startScope) return;
        if (!latest.ok) { setLimitError("Someone else changed this limit. Refresh access to load it before saving again."); return; }
        const current = latest.data.find((g) => g.id === target.id);
        setData((d) => d ? { ...d, groups: latest.data } : d);
        setLimitInput(current?.daily_usd_threshold == null ? "" : String(current.daily_usd_threshold));
        setLimitError("Someone else changed this limit. The latest value is loaded; review it and save again.");
        return;
      }
      const updated = result.data;
      setData((d) => d ? { ...d, groups: d.groups.map((g) => g.id === updated.id ? updated : g) } : d);
      toast.success(value == null ? "Daily cost limit removed" : "Daily cost limit saved");
      setLimitGroup(null);
    } catch { if (alive.current) setLimitError("Could not reach the API. Refresh access to check the saved limit before retrying."); }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  const limitDialog = limitGroup && canManage && <Modal title="Daily cost limit" showClose onDismiss={() => !busy && setLimitGroup(null)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setLimitGroup(null)}>Cancel</Button>{groupLimit(limitGroup.id) != null && <Button variant="ghost" disabled={busy} onClick={() => void saveLimit(null)}>Remove limit</Button>}<Button disabled={busy || !limitValid} onClick={() => void saveLimit(limitValue)}>{busy ? "Saving…" : "Save"}</Button></>}>
    <div className="grid gap-4">
      {limitError && <p role="alert" className="text-danger">{limitError}</p>}
      <p>Daily soft threshold for <strong>{limitGroup.name}</strong>, shared by all its members across all of its models.</p>
      <Field label="Daily limit (USD)"><Input type="number" inputMode="decimal" min="0.01" max="100000" step="0.01" placeholder="No limit" value={limitInput} disabled={busy} onChange={(e) => setLimitInput(e.target.value)} /></Field>
      {limitInput.trim() !== "" && !limitValid && <p className="text-sm text-danger">Enter an amount greater than 0 and at most 100000.</p>}
      <p className="text-sm text-ink-tertiary">Counted from midnight UTC on usage the gateway has already seen, so calls running at the same time can go over it. Once it is reached, new requests through this group are refused until midnight UTC. While a limit is set, models without a price are refused, unless AI Gateway settings allow them or an administrator sets a price in Models &amp; endpoints.</p>
    </div>
  </Modal>;
  const grantDialog = grantOpen && canManage && <Modal title="Grant model access" placement="right" size="enrollment" showClose onDismiss={() => !busy && closeGrant()} actions={<><Button variant="ghost" disabled={busy} onClick={closeGrant}>Cancel</Button><Button disabled={busy || createGroupOpen || groupRefreshFailed || !selected.length || !data?.groups.some((g) => g.id === group)} onClick={() => void grantMany(group, selected)}>{busy ? "Saving…" : selected.length > 1 ? `Grant access to ${selected.length} models` : "Grant model access"}</Button></>}>
    <div className="ai-access-editor">
    {error && <p role="alert" className="text-danger">{error}</p>}
    {!data ? error ? <Button variant="ghost" onClick={() => { setError(""); setAttempt((value) => value + 1); }}>Retry access inventory</Button> : <Loading label="Loading groups and models…" /> : <div className="grid gap-5">
      <Field label="User group"><Select value={group} onChange={(e) => setGroup(e.target.value)} disabled={busy}><option value="">Select a group</option>{data.groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.members})</option>)}</Select></Field>
      {createGroupOpen ? <div className="space-y-3 rounded-md border border-line p-3">
        <Field label="New group name"><Input autoFocus maxLength={100} value={groupName} disabled={busy} onChange={(e) => setGroupName(e.target.value)} /></Field>
        <div className="flex flex-wrap gap-2"><Button disabled={busy || creationAllowed !== true || groupRefreshFailed || !groupName.trim() || groupName.trim().length > 100} onClick={() => void createGroup()}>Create user group</Button><Button variant="ghost" disabled={busy} onClick={() => { setCreateGroupOpen(false); setGroupName(""); setError(""); }}>Cancel group creation</Button></div>
        <p className="text-xs text-ink-tertiary">Add members later in Users &amp; Groups.</p>
      </div> : <Button variant="ghost" disabled={busy || creationAllowed !== true || groupRefreshFailed} onClick={() => { setCreateGroupOpen(true); setError(""); }}>Create user group</Button>}
      {creationAllowed === false && <p className="text-sm text-ink-tertiary">{emailVerified ? "An owner or administrator must create user groups." : "Verify your email to create a user group."}</p>}
      {creationAllowed === null && <p role="alert">Could not check group creation permissions. <Button variant="ghost" disabled={busy} onClick={() => setPermissionAttempt((n) => n + 1)}>Retry group permissions</Button></p>}
      {groupRefreshFailed && <RefreshButton label="Refresh groups" disabled={busy} onClick={async () => { setBusy(true); setError(""); try { await refreshGroups(); } finally { setBusy(false); } }} />}
      <fieldset className="ai-access-models"><legend>Models</legend>{models.length > 6 && <div className="mb-2 flex flex-wrap items-center gap-2"><Input aria-label="Search models to grant" placeholder="Search models" value={modelQuery} disabled={busy} onChange={(e) => setModelQuery(e.target.value)} /><Button variant="ghost" size="sm" disabled={busy || !visibleChoices.some((m) => !heldByGroup(m) && !selections.includes(m.key))} onClick={() => setSelections((current) => [...new Set([...current, ...visibleChoices.filter((m) => !heldByGroup(m)).map((m) => m.key)])])}>Select all shown</Button></div>}{models.length ? visibleChoices.length ? <ul className="grid gap-2">{visibleChoices.map((m) => { const held = heldByGroup(m); return <li key={m.key}><label className="flex items-center gap-2"><input type="checkbox" checked={held || selections.includes(m.key)} disabled={busy || held} onChange={(e) => toggleModel(m.key, e.target.checked)} /><span title={m.model}>{modelDisplayName(m.model)} · {m.name}</span>{held && <small className="text-ink-tertiary">Already granted</small>}</label></li>; })}</ul> : <p>No model matches this search.</p> : <p>No configured model is ready to grant.</p>}{selections.length > 0 && <p className="mt-2 text-sm text-ink-tertiary">{selected.length} selected</p>}</fieldset>
      {!data.groups.length && <p>No user groups yet.</p>}
      <p className="ai-access-context">Members use their Tunnex login <HelpTooltip label="How model access works">The provider key stays in the gateway. Removing a grant blocks new requests; accepted requests may finish.</HelpTooltip></p>
    </div>}
    </div>
  </Modal>;
  if (dialogOnly) return grantDialog;
  return <section className="ai-model-access ai-secondary-workspace" aria-label="Group model access">
    <div className="ai-secondary-toolbar">
      <Input aria-label="Search model access" placeholder="Search groups or models" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} />
      {grantedModels.length > 1 && <Select aria-label="Filter by model" value={modelFilter} onChange={(event) => { setModelFilter(event.target.value); setPage(1); }}><option value="">All models</option>{grantedModels.map((m) => <option key={m} value={m}>{modelDisplayName(m)}</option>)}</Select>}
      <div className="ai-secondary-actions"><RefreshButton label="Refresh access" disabled={busy} onClick={() => { setError(""); gateway.reload(); setAttempt((n) => n + 1); }} />{canManage && <Button disabled={!data || busy} onClick={() => setGrantOpen(true)}>Grant access</Button>}</div>
    </div>
    <AIGatewayOffBanner orgId={orgId} gateway={gateway} canManage={canManage} serverAdmin={serverAdmin} onChanged={() => { setError(""); setAttempt((n) => n + 1); }} />
    {/* While the banner says why nothing loads, a load error beside it would only repeat it less clearly. */}
    {error && !grantOpen && !(gateway.off && !data) && <p role="alert">{error}</p>}
    {!data ? !error && <Loading label="Loading groups and models…" /> : visibleRows.length ? <div className="ai-secondary-table-scroll"><table className="ai-compact-table">
      <caption className="sr-only">User group model grants</caption>
      <thead><tr><th scope="col">Group</th><th scope="col">Models</th><th scope="col">Access</th>{canManage && <th scope="col" className="ai-secondary-action-column"><span className="sr-only">Actions</span></th>}</tr></thead>
      <tbody>{visibleRows.map((row) => {
        const open = expanded.includes(row.key);
        const active = row.grants.filter((g) => g.enabled && g.group_id && g.status === "applied").length;
        const pending = row.grants.filter((g) => g.enabled && g.group_id && g.status !== "applied").length;
        const revoked = row.grants.length - active - pending;
        const limit = groupLimit(row.groupId);
        const summary = [active && `${active} active`, pending && `${pending} pending`, revoked && `${revoked} revoked`, limit != null && `limit $${limit}/day`].filter(Boolean).join(" · ");
        const chips = row.grants.slice(0, 3).map((g) => modelDisplayName(g.model));
        return <Fragment key={row.key}><tr>
          <td><button type="button" className="ai-item-button" aria-expanded={open} aria-label={`${open ? "Hide" : "Show"} models for ${row.name}`} onClick={() => setExpanded((list) => open ? list.filter((k) => k !== row.key) : [...list, row.key])}>{row.name}</button>{!row.groupId && " (deleted)"}</td>
          <td title={row.grants.map((g) => g.model).join("\n")}>{chips.join(", ")}{row.grants.length > 3 && ` +${row.grants.length - 3} more`}</td>
          <td><span className="ai-secondary-status">{summary}</span></td>
          {canManage && <td><AppAccessRowMenu label={`Group actions for ${row.name}`} actions={[
            { key: "models", label: open ? "Hide models" : "Show models", onSelect: () => setExpanded((list) => open ? list.filter((k) => k !== row.key) : [...list, row.key]) },
            { key: "grant", label: "Grant more models", disabledReason: busy ? "Wait for the current change to finish." : !row.groupId ? "This group was deleted." : undefined, onSelect: () => { if (!row.groupId || busy) return; setGroup(row.groupId); setSelections([]); setGrantOpen(true); } },
            { key: "limit", label: "Set daily cost limit", disabledReason: busy ? "Wait for the current change to finish." : !row.groupId ? "This group was deleted." : undefined, onSelect: () => { if (!row.groupId || busy) return; openLimit(row.groupId, row.name); } },
          ]} /></td>}
        </tr>
        {open && <tr className="ai-access-group-models"><td colSpan={canManage ? 4 : 3}><ul aria-label={`Models for ${row.name}`} className="grid gap-1">{row.grants.map((grant) => <li key={grant.id} className="flex flex-wrap items-center justify-between gap-2">
          <span title={grant.model}>{modelDisplayName(grant.model)}</span>
          <span className="flex items-center gap-2"><span className="ai-secondary-status">{grant.enabled && grant.group_id ? grant.status : "Revoked"}</span>
          {canManage && <AppAccessRowMenu label={`Actions for ${grant.group_name ?? "Deleted group"} · ${modelDisplayName(grant.model)}`} actions={[{
            key: grant.enabled ? "revoke" : "restore", label: grant.enabled ? "Revoke access" : "Restore access", danger: grant.enabled,
            disabledReason: busy ? "Wait for the current change to finish." : !grant.group_id ? "This group was deleted." : undefined,
            onSelect: () => { if (!grant.group_id || busy) return; if (grant.enabled) setRevokeGrant(grant); else void save(grant.group_id, grant.connection_id, grant.model, true); },
          }]} />}</span>
        </li>)}</ul></td></tr>}
        </Fragment>;
      })}</tbody>
    </table></div> : <AppAccessEmptyState icon={null} title={filtering ? "No matching model access" : "No model access granted."} description={filtering ? "Try another group or model." : "Grant a configured model to a user group."} action={filtering ? <Button variant="ghost" onClick={() => { setQuery(""); setModelFilter(""); setPage(1); }}>Clear filters</Button> : undefined} />}
    {data && <AppAccessPagination page={currentPage} pageSize={pageSize} count={visibleRows.length} hasNext={currentPage * pageSize < groupRows.length} maxOffset={null} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />}
    {grantDialog}
    {limitDialog}
    {revokeGrant && <Modal title="Revoke model access?" showClose onDismiss={() => !busy && setRevokeGrant(null)} actions={<><Button disabled={busy} onClick={() => setRevokeGrant(null)}>Cancel</Button><Button disabled={busy} onClick={async () => { if (!revokeGrant.group_id) return; await save(revokeGrant.group_id, revokeGrant.connection_id, revokeGrant.model, false); setRevokeGrant(null); }}>{busy ? "Revoking…" : "Confirm revoke"}</Button></>}><p>Revoke <strong>{modelDisplayName(revokeGrant.model)}</strong> access for <strong>{revokeGrant.group_name}</strong>?</p><p className="mt-3 text-sm text-ink-tertiary">Members will lose access through this grant. Other grants remain in effect. Requests already accepted may finish.</p></Modal>}
  </section>;
}

export function AIUseModel({ orgId, canManage = false, serverAdmin = false }: { orgId: string; canManage?: boolean; serverAdmin?: boolean }) {
  const gateway = useAIGatewayStatus(orgId);
  const [models, setModels] = useState<S["AIUserModel"][] | null>(null);
  // Whether the organization has any model at all. Only a manager can read that; null means not known.
  const [configured, setConfigured] = useState<number | null | undefined>(undefined);
  const [model, setModel] = useState("");
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [detailsOpen, setDetailsOpen] = useState(false);
  useEffect(() => {
    let active = true;
    setError("");
    void api.GET("/api/v1/organizations/{orgId}/ai-gateway/my-models", { params: { path: { orgId } } }).then(({ data, error }) => {
      if (!active) return;
      if (error || !data) throw Error();
      setModels(data); setModel(m => data.some(v => v.model === m) ? m : data[0]?.model ?? "");
    }).catch(() => { if (active) setError("Could not load your models. Try refreshing."); });
    return () => { active = false; };
  }, [orgId, attempt]);
  const none = models !== null && models.length === 0;
  useEffect(() => {
    let active = true;
    setConfigured(none && canManage ? undefined : null);
    if (!none || !canManage) return;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } } })).then((result) => {
      if (active) setConfigured(result.ok && Array.isArray(result.data?.items) ? result.data.items.reduce((total, connection) => total + (connection.models?.length ?? 0), 0) : null);
    });
    return () => { active = false; };
  }, [orgId, none, canManage, attempt]);
  const selected = models?.find(m => m.model === model);
  // "No models available" is a claim about the organization: only made when the gateway is on and has none.
  const empty = configured === undefined ? null : configured === 0
    ? <AppAccessEmptyState icon={null} title="No models available" description="AI Gateway is on, but no model has been added yet. Add a model, then grant it to a user group." action={<Link className="ai-gateway-off-link" to="/ai-gateway/models/new">Add a model</Link>} />
    : canManage
      ? <AppAccessEmptyState icon={null} title="No model is granted to you yet" description="A model reaches the playground once it is granted to one of your user groups." action={<Link className="ai-gateway-off-link" to="/ai-gateway/access">Grant model access</Link>} />
      : <AppAccessEmptyState icon={null} title="No model is granted to you yet" description="Ask an organization owner or administrator to grant a model to one of your user groups." />;
  return <section className="ai-playground ai-secondary-workspace" aria-label="Use a model">
    <div className="ai-secondary-toolbar ai-playground-model-toolbar">
      {models && models.length > 0 && <Field label="Model"><Select value={model} onChange={(event) => setModel(event.target.value)}>{models.map((entry) => <option key={entry.model} value={entry.model}>{modelDisplayName(entry.model)} · {entry.mode}</option>)}</Select></Field>}
      <div className="ai-secondary-actions">{selected && <Button variant="ghost" onClick={() => setDetailsOpen(true)}>Connection &amp; code</Button>}<RefreshButton label="Refresh" onClick={() => { gateway.reload(); setAttempt((n) => n + 1); }} /></div>
    </div>
    <AIGatewayOffBanner orgId={orgId} gateway={gateway} canManage={canManage} serverAdmin={serverAdmin} onChanged={() => setAttempt((n) => n + 1)} />
    {error && !gateway.off && <p role="alert">{error}</p>}
    {models === null ? !error && !gateway.off && <Loading label="Loading your models…" /> : !models.length ? !gateway.off && !gateway.loading && empty : <>
      {selected?.mode === "chat" ? <AIChatPlayground key={`${orgId}:${model}`} orgId={orgId} model={model} /> : <div className="ai-secondary-empty"><h3>Use this model in your application</h3><p>This model supports {selected?.mode.replace(/_/g, " ")}. The conversation playground and VPN connection examples support chat models.</p><Button variant="ghost" onClick={() => setDetailsOpen(true)}>Connection availability</Button></div>}
      {detailsOpen && <Modal title="Connection & code" placement="right" size="enrollment" showClose onDismiss={() => setDetailsOpen(false)}><div className="ai-access-connection"><AIModelConnectionDetails key={`${orgId}:${model}`} orgId={orgId} model={model} mode={selected?.mode} /></div></Modal>}
    </>}
  </section>;
}

type AgentAccessData = {
  /** Agent groups are switched off for the organization: nothing here can be granted until they are on. */
  groupsOff: boolean;
  groups: S["AgentGroup"][]; agents: { id: string; name: string }[];
  teams: S["AITeamPolicy"][]; assignments: S["AIAssignment"][]; providers: S["AIProviderConnection"][];
};
const agentAccessState: Record<S["AIAssignment"]["status"], string> = { applied: "Active", pending: "Starting", error: "Not applied yet", disabled: "Revoked" };
const usable = (c: S["AIProviderConnection"]) => c.enabled && c.status === "applied" && c.revision === c.applied_revision;
const modelsLabel = (models: readonly string[]) => models.length === 1 ? modelDisplayName(models[0]) : `${models.length} models`;

/** Model access for agents and agent groups, on the page where it is granted for everyone else. */
export function AIAgentAccess(props: { orgId: string; canManage: boolean; serverAdmin?: boolean }) {
  return <AgentAccessPanel key={`${props.orgId}:${props.canManage}`} {...props} />;
}

function AgentAccessPanel({ orgId, canManage, serverAdmin = false }: { orgId: string; canManage: boolean; serverAdmin?: boolean }) {
  const gateway = useAIGatewayStatus(orgId);
  const alive = useRef(true), serial = useRef(0), locked = useRef(false);
  const [data, setData] = useState<AgentAccessData | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [query, setQuery] = useState(""), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [grantGroup, setGrantGroup] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<S["AIAssignment"] | null>(null);
  async function reload() {
    const n = ++serial.current;
    setLoading(true); setError("");
    try {
      const params = { params: { path: { orgId } } };
      const [g, t, a, p] = await Promise.all([
        api.GET("/api/v1/organizations/{orgId}/agent-groups", params),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/teams", params),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/agents", params),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", params),
      ]);
      // Names only: a list that cannot be read leaves agents shown by their group membership.
      const agents: { id: string; name: string }[] = [];
      let cursor: string | undefined;
      for (let pageNumber = 0; pageNumber < 10; pageNumber++) {
        const d = await api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId }, query: { limit: 100, ...(cursor ? { cursor } : {}) } } });
        if (d.error || !d.data || !Array.isArray(d.data.items)) break;
        agents.push(...d.data.items.map((agent) => ({ id: agent.device_id, name: agent.name })));
        if (!d.data.next_cursor || d.data.next_cursor === cursor) break;
        cursor = d.data.next_cursor;
      }
      if (!alive.current || n !== serial.current) return;
      const groupsOff = apiErrorCode(g.error) === "opt_in_required";
      if ((g.error && !groupsOff) || t.error || a.error || p.error || !Array.isArray(t.data) || !Array.isArray(a.data) || !p.data || !Array.isArray(p.data.items) || (!groupsOff && !Array.isArray(g.data))) throw Error();
      setData({ groupsOff, groups: g.data ?? [], agents, teams: t.data, assignments: a.data, providers: p.data.items });
    } catch {
      if (alive.current && n === serial.current) setError("Could not load model access for agents. Refresh to try again.");
    } finally { if (alive.current && n === serial.current) setLoading(false); }
  }
  useEffect(() => { alive.current = true; void reload(); return () => { alive.current = false; serial.current++; }; }, [orgId]);
  const groupName = (id: string) => data?.groups.find((g) => g.id === id)?.name ?? "Deleted agent group";
  const agentName = (id: string) => data?.agents.find((agent) => agent.id === id)?.name ?? `Agent ${id.slice(0, 8)}`;
  async function setAgentAccess(assignment: S["AIAssignment"], enabled: boolean) {
    if (locked.current || !canManage) return;
    locked.current = true; setBusy(true); setError("");
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}", { params: { path: { orgId, deviceId: assignment.device_id } }, body: { team_id: assignment.team_id, enabled, models_override: assignment.models_override, expected_revision: assignment.revision } });
      if (!alive.current) return;
      const failure = result.error || !result.data ? apiErrorMessage(result.error, "Could not save this change. Refresh and try again.") : "";
      if (!failure) toast.success(enabled ? "Model access restored" : "Model access revoked");
      await reload();
      if (alive.current && failure) setError(failure);
    } catch { if (alive.current) setError("Could not reach the server. Refresh to see what was saved."); }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  type Row = { key: string; name: string; search: string } & ({ kind: "group"; team: S["AITeamPolicy"] } | { kind: "agent"; assignment: S["AIAssignment"] });
  const rows: Row[] = !data ? [] : [
    ...data.teams.map((team): Row => ({ kind: "group", team, key: `group:${team.team_id}`, name: groupName(team.team_id), search: `${groupName(team.team_id)} ${team.models.join(" ")}` })),
    ...data.assignments.map((assignment): Row => ({ kind: "agent", assignment, key: `agent:${assignment.device_id}`, name: agentName(assignment.device_id), search: `${agentName(assignment.device_id)} ${groupName(assignment.team_id)} ${assignment.models_override.join(" ")}` })),
  ];
  const matching = rows.filter((row) => row.search.toLowerCase().includes(query.trim().toLowerCase()));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(matching.length / pageSize)));
  const visible = matching.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const wait = busy ? "Wait for the current change to finish." : undefined;
  return <section className="ai-model-access ai-secondary-workspace" aria-label="Agent model access">
    <div className="ai-secondary-toolbar">
      <Input aria-label="Search agent model access" placeholder="Search agents, agent groups or models" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} />
      <div className="ai-secondary-actions"><RefreshButton label="Refresh access" disabled={busy || loading} onClick={() => { gateway.reload(); void reload(); }} />{canManage && <Button disabled={!data || data.groupsOff || busy || loading} onClick={() => setGrantGroup("")}>Grant access</Button>}</div>
    </div>
    <AIGatewayOffBanner orgId={orgId} gateway={gateway} canManage={canManage} serverAdmin={serverAdmin} onChanged={() => void reload()} />
    {error && grantGroup === null && !(gateway.off && !data) && <p role="alert">{error}</p>}
    {!data ? loading && <Loading label="Loading agents and agent groups…" />
      : data.groupsOff ? <AppAccessEmptyState icon={null} title="Agent groups are turned off" description="An agent gets model access through its agent group. Turn agent groups on, then grant access here." action={<Link className="ai-gateway-off-link" to="/agents/groups">Open agent groups</Link>} />
      : visible.length ? <div className="ai-secondary-table-scroll"><table className="ai-compact-table">
        <caption className="sr-only">Agents and agent groups with model access</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Models</th><th scope="col">State</th>{canManage && <th scope="col" className="ai-secondary-action-column"><span className="sr-only">Actions</span></th>}</tr></thead>
        <tbody>{visible.map((row) => {
          if (row.kind === "group") {
            const agents = data.assignments.filter((a) => a.team_id === row.team.team_id && a.enabled).length;
            return <tr key={row.key}>
              <td>{row.name}</td><td>Agent group</td>
              <td title={row.team.models.map(modelDisplayName).join(", ")}>{modelsLabel(row.team.models)}</td>
              <td><span className="ai-secondary-status">{agents === 1 ? "1 agent has access" : `${agents} agents have access`}</span></td>
              {canManage && <td><AppAccessRowMenu label={`Actions for agent group ${row.name}`} actions={[{ key: "edit", label: "Change models or agents", disabledReason: wait, onSelect: () => setGrantGroup(row.team.team_id) }]} /></td>}
            </tr>;
          }
          const a = row.assignment, team = data.teams.find((t) => t.team_id === a.team_id);
          const models = a.models_override.length ? a.models_override : team?.models ?? [];
          return <tr key={row.key}>
            <td>{row.name}<small className="block text-ink-tertiary">In {groupName(a.team_id)}</small></td><td>Agent</td>
            <td title={models.map(modelDisplayName).join(", ")}>{models.length ? modelsLabel(models) : "None"}</td>
            <td><span className="ai-secondary-status">{a.enabled ? agentAccessState[a.status] ?? a.status : "Revoked"}</span></td>
            {canManage && <td><AppAccessRowMenu label={`Actions for agent ${row.name}`} actions={[{
              key: a.enabled ? "revoke" : "restore", label: a.enabled ? "Revoke access" : "Restore access", danger: a.enabled, disabledReason: wait,
              onSelect: () => { if (busy) return; if (a.enabled) setRevoking(a); else void setAgentAccess(a, true); },
            }]} /></td>}
          </tr>;
        })}</tbody>
      </table></div>
      : <AppAccessEmptyState icon={null} title={query ? "No matching agents or agent groups" : "No agent has model access yet"} description={query ? "Try another agent, agent group or model." : "Choose an agent group, the models it may use, and which of its agents get them."} action={query ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />}
    {data && !data.groupsOff && <AppAccessPagination page={currentPage} pageSize={pageSize} count={visible.length} hasNext={currentPage * pageSize < matching.length} maxOffset={null} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />}
    {data && canManage && grantGroup !== null && <AgentGrantDialog key={grantGroup} orgId={orgId} data={data} initialGroup={grantGroup} agentName={agentName} onClose={(saved) => { setGrantGroup(null); if (saved) void reload(); }} />}
    {revoking && <Modal title="Revoke model access?" showClose onDismiss={() => !busy && setRevoking(null)} actions={<><Button disabled={busy} onClick={() => setRevoking(null)}>Cancel</Button><Button disabled={busy} onClick={async () => { await setAgentAccess(revoking, false); setRevoking(null); }}>{busy ? "Revoking…" : "Confirm revoke"}</Button></>}><p>Revoke model access for the agent <strong>{agentName(revoking.device_id)}</strong>?</p><p className="mt-3 text-sm text-ink-tertiary">New requests from this agent are refused. Requests already accepted may finish. Other agents in {groupName(revoking.team_id)} keep their access.</p></Modal>}
  </section>;
}

type GroupMembers = { state: "idle" | "loading" | "error" } | { state: "ready"; items: S["AgentGroupMember"][] };

function AgentGrantDialog({ orgId, data, initialGroup, agentName, onClose }: { orgId: string; data: AgentAccessData; initialGroup: string; agentName: (id: string) => string; onClose: (saved: boolean) => void }) {
  const alive = useRef(true), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const [groupId, setGroupId] = useState(initialGroup);
  const team = data.teams.find((t) => t.team_id === groupId);
  const [models, setModels] = useState<string[]>(team?.models ?? []);
  const [budget, setBudget] = useState(team?.daily_cost_limit == null ? "" : String(team.daily_cost_limit));
  const [members, setMembers] = useState<GroupMembers>({ state: "idle" });
  const [chosen, setChosen] = useState<string[]>([]);
  const [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState(""), [saved, setSaved] = useState(false);
  const hasAccess = (deviceId: string) => data.assignments.some((a) => a.device_id === deviceId && a.team_id === groupId && a.enabled);
  useEffect(() => {
    let live = true;
    setMembers(groupId ? { state: "loading" } : { state: "idle" }); setChosen([]);
    if (!groupId) return;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", { params: { path: { orgId, groupId } } })).then((result) => {
      if (!live) return;
      if (!result.ok || !Array.isArray(result.data)) { setMembers({ state: "error" }); return; }
      const items = result.data.filter((member) => member.status === "active");
      setMembers({ state: "ready", items }); setChosen(items.filter((member) => hasAccess(member.device_id)).map((member) => member.device_id));
    });
    return () => { live = false; };
  }, [orgId, groupId, attempt]);
  function chooseGroup(id: string) {
    const next = data.teams.find((t) => t.team_id === id);
    setGroupId(id); setModels(next?.models ?? []); setBudget(next?.daily_cost_limit == null ? "" : String(next.daily_cost_limit)); setError("");
  }
  const ready = data.providers.filter(usable);
  const available = [...new Set([...ready.flatMap((c) => c.models), ...(team?.models ?? [])])];
  // The policy names the credentials that serve its models. Keep any reference the server administrator set up.
  const owned = new Set(data.providers.map((c) => c.key_id));
  const keys = [...new Set([...ready.filter((c) => c.models.some((model) => models.includes(model))).map((c) => c.key_id), ...(team?.key_ids ?? []).filter((id) => !owned.has(id))])].slice(0, 8);
  const limit = budget.trim() === "" ? null : Number(budget);
  const budgetValid = limit === null || (Number.isFinite(limit) && limit > 0 && limit <= 100000);
  const policyChanged = !team || team.daily_cost_limit !== limit && !(team.daily_cost_limit == null && limit === null) || team.models.length !== models.length || team.models.some((model) => !models.includes(model));
  const valid = !!groupId && models.length > 0 && models.length <= 32 && keys.length > 0 && budgetValid && members.state === "ready";
  async function save() {
    if (locked.current || !valid || members.state !== "ready") return;
    locked.current = true; setBusy(true); setError("");
    let wrote = false;
    try {
      if (policyChanged) {
        const result = await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/teams/{teamId}", { params: { path: { orgId, teamId: groupId } }, body: { models, key_ids: keys, daily_cost_limit: limit, expected_revision: team?.revision ?? 0 } });
        if (result.error || !result.data) throw Error(apiErrorMessage(result.error, "Could not save the models for this agent group."));
        wrote = true;
      }
      for (const member of members.items) {
        const current = data.assignments.find((a) => a.device_id === member.device_id);
        const want = chosen.includes(member.device_id), has = !!current && current.team_id === groupId && current.enabled;
        if (want === has) continue;
        if (!want && current?.team_id !== groupId) continue;
        const sameGroup = current?.team_id === groupId;
        const result = await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}", { params: { path: { orgId, deviceId: member.device_id } }, body: { team_id: groupId, enabled: want, models_override: sameGroup ? current.models_override.filter((model) => !want || models.includes(model)) : [], expected_revision: current?.revision ?? 0 } });
        if (result.error || !result.data) throw Error(apiErrorMessage(result.error, `Could not save access for ${member.name}.`));
        wrote = true;
      }
      if (!alive.current) return;
      toast.success("Agent model access saved");
      onClose(true);
    } catch (failure) {
      if (!alive.current) return;
      if (wrote) setSaved(true);
      setError(`${failure instanceof Error && failure.message ? failure.message : "Could not reach the server."}${wrote ? " Earlier changes in this dialog were saved." : ""} Close and refresh before trying again.`);
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  const toggle = (list: string[], id: string, on: boolean) => on ? [...new Set([...list, id])] : list.filter((value) => value !== id);
  return <Modal title="Grant model access to agents" placement="right" size="enrollment" showClose onDismiss={() => !busy && onClose(saved)} actions={<><Button variant="ghost" disabled={busy} onClick={() => onClose(saved)}>Cancel</Button><Button disabled={busy || !valid || saved} onClick={() => void save()}>{busy ? "Saving…" : "Save agent access"}</Button></>}>
    <div className="ai-access-editor grid gap-5">
      {error && <p role="alert" className="text-danger">{error}</p>}
      <Field label="Agent group"><Select value={groupId} disabled={busy} onChange={(event) => chooseGroup(event.target.value)}><option value="">Select an agent group</option>{data.groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.member_count})</option>)}</Select></Field>
      {!data.groups.length && <p>No agent groups yet. <Link className="ai-gateway-off-link" to="/agents/groups">Create an agent group</Link>, add agents to it, then grant access here.</p>}
      {groupId && <>
        <fieldset><legend className="mb-2 text-sm text-ink-heading">Models this group may use</legend>
          {available.length ? <ul className="ai-agent-grant-list">{available.map((model) => <li key={model}><label><input type="checkbox" checked={models.includes(model)} disabled={busy || (!models.includes(model) && models.length >= 32)} onChange={(event) => setModels(toggle(models, model, event.target.checked))} /><span title={model}>{modelDisplayName(model)}</span></label></li>)}</ul>
            : <p className="text-sm text-ink-tertiary">No model is ready yet. <Link className="ai-gateway-off-link" to="/ai-gateway/models/new">Add a model</Link> first.</p>}
          {models.length > 0 && keys.length === 0 && <p className="mt-2 text-sm text-danger">The chosen models have no provider credential that is ready. Check LLM credentials.</p>}
        </fieldset>
        <fieldset><legend className="mb-2 text-sm text-ink-heading">Agents that get access</legend>
          {members.state === "loading" ? <Loading size="inline" label="Loading the agents in this group…" />
            : members.state === "error" ? <p role="alert">Could not load the agents in this group. <Button variant="ghost" disabled={busy} onClick={() => setAttempt((n) => n + 1)}>Retry agents</Button></p>
            : members.state === "ready" && members.items.length ? <ul className="ai-agent-grant-list">{members.items.map((member) => {
              const other = data.assignments.find((a) => a.device_id === member.device_id && a.team_id !== groupId && a.enabled);
              const otherName = other ? data.groups.find((g) => g.id === other.team_id)?.name ?? "another agent group" : "";
              return <li key={member.device_id}><label><input type="checkbox" checked={chosen.includes(member.device_id)} disabled={busy} onChange={(event) => setChosen(toggle(chosen, member.device_id, event.target.checked))} /><span>{member.name || agentName(member.device_id)}{other && <small>Uses the models of {otherName} now. Saving moves it to this group.</small>}</span></label></li>;
            })}</ul>
            : members.state === "ready" ? <p className="text-sm text-ink-tertiary">This group has no active agents. <Link className="ai-gateway-off-link" to="/agents/groups">Add agents to the group</Link> first.</p> : null}
          <p className="mt-2 text-xs text-ink-tertiary">Clearing an agent that has access revokes it when you save.</p>
        </fieldset>
        <Field label="Daily budget for this group in USD (optional)"><Input type="number" min="0" max="100000" step="any" value={budget} disabled={busy} onChange={(event) => setBudget(event.target.value)} /></Field>
        {!budgetValid && <p className="text-sm text-danger">Enter an amount above 0 and up to 100000, or leave it empty.</p>}
        <p className="ai-access-context">Shared by every agent in the group <HelpTooltip label="How the daily budget works">Counted from midnight UTC against what the gateway observed. It is a soft limit, not an exact cap: requests already running can pass it.</HelpTooltip></p>
      </>}
    </div>
  </Modal>;
}
