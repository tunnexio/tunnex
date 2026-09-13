import { useEffect, useState, type ReactNode } from "react";
import { type components } from "@tunnex/shared";
import { api } from "../lib/api";
import { can } from "../lib/rbac";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { Button, Card, Field, Input, Loading, Modal, Select } from "./ui";
import { HelpTooltip, modelDisplayName } from "./HelpTooltip";
import { toast } from "./Toasts";
import { AIChatPlayground } from "./AIChatPlayground";
import { AIModelConnectionDetails } from "./AIModelConnectionDetails";
type S = components["schemas"];
type Capabilities = { view: boolean; manage: boolean; agents: boolean; workloadsView:boolean; workloadsManage:boolean };

export function AIAccessGate({ children }: { children: (orgId: string, access: Capabilities) => ReactNode }) {
  const { org } = useOrg(); const { state } = useAuth();
  const user = state.status === "authed" ? state.user.id : "";
  const scope = `${org?.id}/${user}`;
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ scope: string; access?: Capabilities } | null>(null);
  useEffect(() => {
    let active = true; setResult(null);
    if (!org || !user) return;
    void api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }).then(({ data, error }) => {
      if (!active) return;
      const member = !error && data?.find((m) => m.user_id === user);
      const roles = member ? member.roles ?? [member.role] : [];
      setResult({ scope, ...(member ? { access: { view: can(roles, "ai_gateway:view"), manage: can(roles, "ai_gateway:manage"), agents: can(roles, "agent_template:manage"),workloadsView:can(roles,"ai_workload:view"),workloadsManage:can(roles,"ai_workload:manage") } } : {}) });
    }).catch(() => { if (active) setResult({ scope }); });
    return () => { active = false; };
  }, [scope, attempt]);
  if (!org || !result || result.scope !== scope) return <Loading label="Checking AI access…" />;
  if (!result.access) return <Card><p role="alert">Could not check AI access.</p><Button onClick={() => setAttempt((v) => v + 1)}>Retry permissions</Button></Card>;
  return <>{children(org.id, result.access)}</>;
}

export function AIGroupAccess({ orgId, canManage, initialConnection = "", initialModel = "", dialogOnly = false, onDone }: { orgId: string; canManage: boolean; initialConnection?: string; initialModel?: string; dialogOnly?: boolean; onDone?: () => void }) {
  const [grantOpen, setGrantOpen] = useState(dialogOnly || Boolean(initialModel));
  const [query, setQuery] = useState("");
  const [selectedGrant, setSelectedGrant] = useState("");
  const [revokeGrant, setRevokeGrant] = useState<S["AIUserModelGrant"] | null>(null);
  const closeGrant = () => { setGrantOpen(false); onDone?.(); };
  const [data, setData] = useState<{ groups: S["AIUserGroup"][]; grants: S["AIUserModelGrant"][]; providers: S["AIProviderConnection"][] } | null>(null);
  const [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [group, setGroup] = useState(""), [selection, setSelection] = useState(initialConnection && initialModel ? JSON.stringify([initialConnection, initialModel]) : "");
  useEffect(() => {
    let active = true;
    const params = { params: { path: { orgId } } };
    void Promise.all([api.GET("/api/v1/organizations/{orgId}/ai-gateway/user-groups", params), api.GET("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", params), api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", params)]).then(([g, a, p]) => {
      if (!active) return;
      if (g.error || a.error || p.error || !g.data || !a.data || !p.data) throw Error();
      setData({ groups: g.data, grants: a.data, providers: p.data.items });
    }).catch(() => { if (active) setError("Could not load group access. Retry to refresh the saved state."); });
    return () => { active = false; };
  }, [orgId, attempt]);
  const models = data?.providers.filter((p) => p.enabled && p.status === "applied" && p.revision === p.applied_revision).flatMap((p) => p.models.map((model) => ({ key: JSON.stringify([p.id, model]), model, connection: p.id, name: p.name }))) ?? [];
  const selected = models.find((m) => m.key === selection);
  const activeGrant = data?.grants.find(g => g.id === selectedGrant);
  async function save(groupId: string, connectionId: string, model: string, enabled: boolean) {
    if (busy || !canManage || !data) return;
    const old = data.grants.find((g) => g.group_id === groupId && g.connection_id === connectionId && g.model === model);
    setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", { params: { path: { orgId } }, body: { group_id: groupId, connection_id: connectionId, model, enabled, expected_revision: old?.revision ?? 0 } });
      if (result.error || !result.data) throw Error();
      const grant = result.data;
      setData((d) => d ? { ...d, grants: [...d.grants.filter((g) => g.id !== grant.id), grant] } : d);
      if (grant.status === "applied") { toast.success("Model access granted"); closeGrant(); }
      else if (!enabled) toast.success("Model access revoked");
      else setError("Access is saved but not active yet. Provisioning will retry; refresh to check its state.");
    } catch { setError("Could not apply this change. Refresh the saved state before retrying."); }
    finally { setBusy(false); }
  }
  const grantDialog = grantOpen && canManage && <Modal title="Grant model access" showClose onDismiss={() => !busy && closeGrant()} actions={<><Button variant="ghost" disabled={busy} onClick={closeGrant}>Cancel</Button><Button disabled={busy || !selected || !data?.groups.some((g) => g.id === group)} onClick={() => selected && void save(group, selected.connection, selected.model, true)}>{busy ? "Saving…" : "Grant model access"}</Button></>}>
    {error && <p role="alert" className="text-danger">{error}</p>}
    {!data ? <Loading label="Loading groups and models…" /> : <div className="grid gap-5">
      <Field label="User group"><Select value={group} onChange={(e) => setGroup(e.target.value)} disabled={busy}><option value="">Select a group</option>{data.groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.members})</option>)}</Select></Field>
      <Field label="Model"><Select value={selection} onChange={(e) => setSelection(e.target.value)} disabled={busy}><option value="">Select a configured model</option>{models.map((m) => <option key={m.key} value={m.key}>{modelDisplayName(m.model)} · {m.name}</option>)}</Select></Field>
      {!data.groups.length && <p>Create a user group in Users & Groups first.</p>}
      <HelpTooltip label="How model access works">Members use their Tunnex login. The provider key stays in the gateway. Removing a grant blocks new requests; accepted requests may finish.</HelpTooltip>
    </div>}
  </Modal>;
  if (dialogOnly) return grantDialog;
  return <section className="ai-model-access" aria-label="Group model access"><Card>
    <div className="ai-inventory-toolbar"><h2>Model access<span className="ai-inventory-count">{data?.grants.length ?? 0}</span><HelpTooltip label="About group model access">Grant models to user groups. Members use their existing Tunnex login.</HelpTooltip></h2><div className="ai-inventory-actions"><Button disabled={busy} onClick={() => { setError(""); setAttempt((n) => n + 1); }}>Refresh access</Button>{canManage && <Button onClick={() => setGrantOpen(true)}>Grant access</Button>}</div></div>
    {error && !grantOpen && <p role="alert">{error}</p>}
    <Input aria-label="Search model access" className="ai-inventory-search" placeholder="Search groups or models" value={query} onChange={(e) => { setQuery(e.target.value); setSelectedGrant(""); }} />
    {canManage && <div className="ai-inventory-toolbar"><span className="text-sm text-ink-tertiary">{activeGrant ? `${activeGrant.group_name ?? "Deleted group"} · ${modelDisplayName(activeGrant.model)}` : "Select a grant to manage access"}</span><Button disabled={busy || !activeGrant?.group_id} onClick={() => { if (!activeGrant?.group_id) return; if (activeGrant.enabled) setRevokeGrant(activeGrant); else void save(activeGrant.group_id, activeGrant.connection_id, activeGrant.model, true); }}>{activeGrant?.enabled ? "Revoke access" : "Restore access"}</Button></div>}
    {!data ? <Loading label="Loading groups and models…" /> : <div className="overflow-x-auto"><table className="ai-compact-table"><caption className="sr-only">User group model grants</caption><thead><tr>{(canManage ? ["Select", "Group", "Model", "State"] : ["Group", "Model", "State"]).map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{data.grants.filter((g) => `${g.group_name} ${g.model}`.toLowerCase().includes(query.toLowerCase())).map((g) => <tr key={g.id} aria-selected={selectedGrant === g.id}>{canManage && <td><input type="radio" name="model-access-grant" aria-label={`Select ${g.group_name} ${modelDisplayName(g.model)}`} checked={selectedGrant === g.id} disabled={busy || !g.group_id} onChange={() => setSelectedGrant(g.id)} /></td>}<td>{g.group_name}{!g.group_id && " (deleted)"}</td><td title={g.model}>{modelDisplayName(g.model)}</td><td>{g.enabled && g.group_id ? g.status : "Revoked"}</td></tr>)}</tbody></table>{!data.grants.length && <p className="p-6 text-center text-sm">No model access granted.</p>}</div>}
  </Card>{grantDialog}{revokeGrant && <Modal title="Revoke model access?" showClose onDismiss={() => !busy && setRevokeGrant(null)} actions={<><Button disabled={busy} onClick={() => setRevokeGrant(null)}>Cancel</Button><Button disabled={busy} onClick={async () => { if (!revokeGrant.group_id) return; await save(revokeGrant.group_id, revokeGrant.connection_id, revokeGrant.model, false); setRevokeGrant(null); }}>{busy ? "Revoking…" : "Confirm revoke"}</Button></>}><p>Revoke <strong>{modelDisplayName(revokeGrant.model)}</strong> access for <strong>{revokeGrant.group_name}</strong>?</p><p className="mt-3 text-sm text-ink-tertiary">Members will lose access through this grant. Other grants remain in effect. Requests already accepted may finish.</p></Modal>}</section>;
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
  return <section className="ai-playground" aria-label="Use a model">
    <header className="ai-chat-toolbar"><div><h2>Playground</h2><p>Choose a model and start a conversation using your Tunnex access.</p></div><Button onClick={() => setAttempt(n => n + 1)}>Refresh</Button></header>
    {error && <p role="alert">{error}</p>}
    {models === null ? !error && <Loading label="Loading your models…" /> : !models.length ? <Card>No models are available yet. Ask your administrator to grant model access to your user group.</Card> : <>
      <div className="ai-chat-toolbar"><Field label="Model"><Select value={model} onChange={e => setModel(e.target.value)}>{models.map(m => <option key={m.model} value={m.model}>{modelDisplayName(m.model)} · {m.mode}</option>)}</Select></Field><Button onClick={() => setDetailsOpen(true)}>Connection & code</Button></div>
      {selected?.mode === "chat" ? <AIChatPlayground key={`${orgId}:${model}`} orgId={orgId} model={model} /> : <Card><h3>Use this model in your application</h3><p>This model supports {selected?.mode.replace(/_/g, " ")}. Open Connection & code for its endpoint and a ready-to-use example. The conversation playground supports chat models.</p><Button onClick={() => setDetailsOpen(true)}>View connection example</Button></Card>}
      {detailsOpen && <Modal title="Connection & code" size="wide" showClose onDismiss={() => setDetailsOpen(false)}><AIModelConnectionDetails key={`${orgId}:${model}`} orgId={orgId} model={model} mode={selected?.mode} /></Modal>}
    </>}
  </section>;
}

