import { useEffect, useRef, useState, type ReactNode } from "react";
import { type components } from "@tunnex/shared";
import { api, apiErrorMessage, loadOne } from "../lib/api";
import { can } from "../lib/rbac";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { Button, Field, Input, Loading, Modal, Select } from "./ui";
import { HelpTooltip, modelDisplayName } from "./HelpTooltip";
import { toast } from "./Toasts";
import { AIChatPlayground } from "./AIChatPlayground";
import { AIModelConnectionDetails } from "./AIModelConnectionDetails";
import AppAccessRowMenu from "./AppAccessRowMenu";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessEmptyState from "./AppAccessEmptyState";
import "./ai-gateway-access.css";
type S = components["schemas"];
type Capabilities = { view: boolean; manage: boolean; agents: boolean; workloadsView:boolean; workloadsManage:boolean };

export function AIAccessGate({ children }: { children: (orgId: string, access: Capabilities) => ReactNode }) {
  const { org } = useOrg(); const { state } = useAuth();
  const user = state.status === "authed" ? state.user.id : "";
  const writable = state.status === "authed" && state.user.email_verified === true && !state.user.must_change_password;
  const scope = `${org?.id}/${user}/${writable}`;
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ scope: string; access?: Capabilities } | null>(null);
  useEffect(() => {
    let active = true; setResult(null);
    if (!org || !user) return;
    void api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }).then(({ data, error }) => {
      if (!active) return;
      const member = !error && data?.find((m) => m.user_id === user);
      const roles = member ? member.roles ?? [member.role] : [];
      setResult({ scope, ...(member ? { access: { view: can(roles, "ai_gateway:view"), manage: writable && can(roles, "ai_gateway:manage"), agents: writable && can(roles, "agent_template:manage"),workloadsView:can(roles,"ai_workload:view"),workloadsManage:writable && can(roles,"ai_workload:manage") } } : {}) });
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
  const scope = `${orgId}/${userId}`;
  const currentScope = useRef(scope); currentScope.current = scope;
  const alive = useRef(true), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const [grantOpen, setGrantOpen] = useState(dialogOnly || Boolean(initialModel));
  const [createGroupOpen, setCreateGroupOpen] = useState(false), [groupName, setGroupName] = useState("");
  const [groupPermission, setGroupPermission] = useState<{ scope: string; allowed: boolean | null } | null>(null);
  const [permissionAttempt, setPermissionAttempt] = useState(0), [groupRefreshFailed, setGroupRefreshFailed] = useState(false);
  const creationAllowed = groupPermission?.scope === scope ? groupPermission.allowed : undefined;
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [revokeGrant, setRevokeGrant] = useState<S["AIUserModelGrant"] | null>(null);
  const closeGrant = () => { setGrantOpen(false); setCreateGroupOpen(false); setGroupName(""); onDone?.(); };
  const [data, setData] = useState<{ groups: S["AIUserGroup"][]; grants: S["AIUserModelGrant"][]; providers: S["AIProviderConnection"][] } | null>(null);
  const [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [group, setGroup] = useState(""), [selection, setSelection] = useState(initialConnection && initialModel ? JSON.stringify([initialConnection, initialModel]) : "");
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
  const selected = models.find((m) => m.key === selection);
  const matchingGrants = data?.grants.filter((grant) => `${grant.group_name} ${grant.model}`.toLowerCase().includes(query.trim().toLowerCase())) ?? [];
  const currentPage = Math.min(page, Math.max(1, Math.ceil(matchingGrants.length / pageSize)));
  const visibleGrants = matchingGrants.slice((currentPage - 1) * pageSize, currentPage * pageSize);
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
      setData((d) => d ? { ...d, groups: [...d.groups.filter((g) => g.id !== created.id), { id: created.id, name: created.name, members: created.member_count }] } : d);
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
  const grantDialog = grantOpen && canManage && <Modal title="Grant model access" placement="right" size="enrollment" showClose onDismiss={() => !busy && closeGrant()} actions={<><Button variant="ghost" disabled={busy} onClick={closeGrant}>Cancel</Button><Button disabled={busy || createGroupOpen || groupRefreshFailed || !selected || !data?.groups.some((g) => g.id === group)} onClick={() => selected && void save(group, selected.connection, selected.model, true)}>{busy ? "Saving…" : "Grant model access"}</Button></>}>
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
      {groupRefreshFailed && <Button disabled={busy} onClick={async () => { setBusy(true); setError(""); try { await refreshGroups(); } finally { setBusy(false); } }}>Refresh groups</Button>}
      <Field label="Model"><Select value={selection} onChange={(e) => setSelection(e.target.value)} disabled={busy}><option value="">Select a configured model</option>{models.map((m) => <option key={m.key} value={m.key}>{modelDisplayName(m.model)} · {m.name}</option>)}</Select></Field>
      {!data.groups.length && <p>No user groups yet.</p>}
      <p className="ai-access-context">Members use their Tunnex login <HelpTooltip label="How model access works">The provider key stays in the gateway. Removing a grant blocks new requests; accepted requests may finish.</HelpTooltip></p>
    </div>}
    </div>
  </Modal>;
  if (dialogOnly) return grantDialog;
  return <section className="ai-model-access ai-secondary-workspace" aria-label="Group model access">
    <div className="ai-secondary-toolbar">
      <Input aria-label="Search model access" placeholder="Search groups or models" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} />
      <div className="ai-secondary-actions"><Button variant="ghost" disabled={busy} onClick={() => { setError(""); setAttempt((n) => n + 1); }}>Refresh access</Button>{canManage && <Button disabled={!data || busy} onClick={() => setGrantOpen(true)}>Grant access</Button>}</div>
    </div>
    {error && !grantOpen && <p role="alert">{error}</p>}
    {!data ? !error && <Loading label="Loading groups and models…" /> : visibleGrants.length ? <div className="ai-secondary-table-scroll"><table className="ai-compact-table">
      <caption className="sr-only">User group model grants</caption>
      <thead><tr><th scope="col">Group</th><th scope="col">Model</th><th scope="col">State</th>{canManage && <th scope="col" className="ai-secondary-action-column"><span className="sr-only">Actions</span></th>}</tr></thead>
      <tbody>{visibleGrants.map((grant) => <tr key={grant.id}>
        <td>{grant.group_name || "Deleted group"}{!grant.group_id && " (deleted)"}</td>
        <td title={grant.model}>{modelDisplayName(grant.model)}</td>
        <td><span className="ai-secondary-status">{grant.enabled && grant.group_id ? grant.status : "Revoked"}</span></td>
        {canManage && <td><AppAccessRowMenu label={`Actions for ${grant.group_name ?? "Deleted group"} · ${modelDisplayName(grant.model)}`} actions={[{
          key: grant.enabled ? "revoke" : "restore", label: grant.enabled ? "Revoke access" : "Restore access", danger: grant.enabled,
          disabledReason: busy ? "Wait for the current change to finish." : !grant.group_id ? "This group was deleted." : undefined,
          onSelect: () => { if (!grant.group_id || busy) return; if (grant.enabled) setRevokeGrant(grant); else void save(grant.group_id, grant.connection_id, grant.model, true); },
        }]} /></td>}
      </tr>)}</tbody>
    </table></div> : <AppAccessEmptyState icon={null} title={matchingGrants.length || query ? "No matching model access" : "No model access granted."} description={query ? "Try another group or model." : "Grant a configured model to a user group."} action={query ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />}
    {data && <AppAccessPagination page={currentPage} pageSize={pageSize} count={visibleGrants.length} hasNext={currentPage * pageSize < matchingGrants.length} maxOffset={null} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />}
    {grantDialog}
    {revokeGrant && <Modal title="Revoke model access?" showClose onDismiss={() => !busy && setRevokeGrant(null)} actions={<><Button disabled={busy} onClick={() => setRevokeGrant(null)}>Cancel</Button><Button disabled={busy} onClick={async () => { if (!revokeGrant.group_id) return; await save(revokeGrant.group_id, revokeGrant.connection_id, revokeGrant.model, false); setRevokeGrant(null); }}>{busy ? "Revoking…" : "Confirm revoke"}</Button></>}><p>Revoke <strong>{modelDisplayName(revokeGrant.model)}</strong> access for <strong>{revokeGrant.group_name}</strong>?</p><p className="mt-3 text-sm text-ink-tertiary">Members will lose access through this grant. Other grants remain in effect. Requests already accepted may finish.</p></Modal>}
  </section>;
}

export function AIUseModel({ orgId }: { orgId: string }) {
  const [models, setModels] = useState<S["AIUserModel"][] | null>(null);
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
  const selected = models?.find(m => m.model === model);
  return <section className="ai-playground ai-secondary-workspace" aria-label="Use a model">
    <div className="ai-secondary-toolbar ai-playground-model-toolbar">
      {models && models.length > 0 && <Field label="Model"><Select value={model} onChange={(event) => setModel(event.target.value)}>{models.map((entry) => <option key={entry.model} value={entry.model}>{modelDisplayName(entry.model)} · {entry.mode}</option>)}</Select></Field>}
      <div className="ai-secondary-actions">{selected && <Button variant="ghost" onClick={() => setDetailsOpen(true)}>Connection &amp; code</Button>}<Button variant="ghost" onClick={() => setAttempt((n) => n + 1)}>Refresh</Button></div>
    </div>
    {error && <p role="alert">{error}</p>}
    {models === null ? !error && <Loading label="Loading your models…" /> : !models.length ? <AppAccessEmptyState icon={null} title="No models available" description="Ask your administrator to grant model access to your user group." /> : <>
      {selected?.mode === "chat" ? <AIChatPlayground key={`${orgId}:${model}`} orgId={orgId} model={model} /> : <div className="ai-secondary-empty"><h3>Use this model in your application</h3><p>This model supports {selected?.mode.replace(/_/g, " ")}. The conversation playground and VPN connection examples support chat models.</p><Button variant="ghost" onClick={() => setDetailsOpen(true)}>Connection availability</Button></div>}
      {detailsOpen && <Modal title="Connection & code" placement="right" size="enrollment" showClose onDismiss={() => setDetailsOpen(false)}><div className="ai-access-connection"><AIModelConnectionDetails key={`${orgId}:${model}`} orgId={orgId} model={model} mode={selected?.mode} /></div></Modal>}
    </>}
  </section>;
}
