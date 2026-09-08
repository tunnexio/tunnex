import { useEffect, useState, type ReactNode } from "react";
import { getApiOrigin, type components } from "@tunnex/shared";
import { api } from "../lib/api";
import { can } from "../lib/rbac";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { Button, Card, Field, Loading, Select } from "./ui";
import { toast } from "./Toasts";
type S = components["schemas"];
type Capabilities = { view: boolean; manage: boolean; agents: boolean };

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
      setResult({ scope, ...(member ? { access: { view: can(roles, "ai_gateway:view"), manage: can(roles, "ai_gateway:manage"), agents: can(roles, "agent_template:manage") } } : {}) });
    }).catch(() => { if (active) setResult({ scope }); });
    return () => { active = false; };
  }, [scope, attempt]);
  if (!org || !result || result.scope !== scope) return <Loading label="Checking AI access…" />;
  if (!result.access) return <Card><p role="alert">Could not check AI access.</p><Button onClick={() => setAttempt((v) => v + 1)}>Retry permissions</Button></Card>;
  return <>{children(org.id, result.access)}</>;
}

export function AIGroupAccess({ orgId, canManage }: { orgId: string; canManage: boolean }) {
  const [data, setData] = useState<{ groups: S["AIUserGroup"][]; grants: S["AIUserModelGrant"][]; providers: S["AIProviderConnection"][] } | null>(null);
  const [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [group, setGroup] = useState(""), [selection, setSelection] = useState("");
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
  async function save(groupId: string, connectionId: string, model: string, enabled: boolean) {
    if (busy || !canManage || !data) return;
    const old = data.grants.find((g) => g.group_id === groupId && g.connection_id === connectionId && g.model === model);
    setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/user-model-grants", { params: { path: { orgId } }, body: { group_id: groupId, connection_id: connectionId, model, enabled, expected_revision: old?.revision ?? 0 } });
      if (result.error || !result.data) throw Error();
      const grant = result.data;
      setData((d) => d ? { ...d, grants: [...d.grants.filter((g) => g.id !== grant.id), grant] } : d);
      if (grant.status === "applied") toast.success("Model access granted");
      else if (!enabled) toast.success("Model access revoked");
      else setError("Access is saved but not active yet. Provisioning will retry; refresh to check its state.");
    } catch { setError("Could not apply this change. Refresh the saved state before retrying."); }
    finally { setBusy(false); }
  }
  return <section className="space-y-5" aria-label="Group model access"><Card>
    <h2 className="text-xl font-semibold">Group access</h2><p className="my-2 text-sm text-ink-tertiary">Grant a model to a user group. Members call it with their Tunnex login; the provider key stays in the gateway.</p>
    {error && <p role="alert">{error}</p>}
    <Button disabled={busy} onClick={() => { setError(""); setAttempt((n) => n + 1); }}>Refresh access</Button>
    {!data ? <Loading label="Loading groups and models…" /> : canManage && <div className="mt-5 grid gap-4 md:grid-cols-2">
      <Field label="User group"><Select value={group} onChange={(e) => setGroup(e.target.value)} disabled={busy}><option value="">Select a group</option>{data.groups.map((g) => <option key={g.id} value={g.id}>{g.name} · {g.members} users</option>)}</Select></Field>
      <Field label="Model"><Select value={selection} onChange={(e) => setSelection(e.target.value)} disabled={busy}><option value="">Select a configured model</option>{models.map((m) => <option key={m.key} value={m.key}>{m.model} · {m.name}</option>)}</Select></Field>
      {!data.groups.length && <p>Create a user group and add its members in Access Policies first.</p>}
      <div><Button disabled={busy || !selected || !data.groups.some((g) => g.id === group)} onClick={() => selected && void save(group, selected.connection, selected.model, true)}>Grant model access</Button></div>
    </div>}
  </Card>{data && <Card><div className="overflow-x-auto"><table className="w-full text-left text-sm"><caption className="sr-only">User group model grants</caption><thead><tr>{["Group", "Model", "State", "Actions"].map((h) => <th className="border-b border-white/10 p-3" key={h}>{h}</th>)}</tr></thead><tbody>{data.grants.map((g) => <tr key={g.id}><td className="p-3">{g.group_name}{!g.group_id && " (deleted)"}</td><td className="p-3 break-all"><code>{g.model}</code></td><td className="p-3">{g.enabled && g.group_id ? g.status : "Revoked"}</td><td className="p-3">{canManage && g.group_id && <Button disabled={busy} onClick={() => void save(g.group_id!, g.connection_id, g.model, !g.enabled)}>{g.enabled ? "Revoke access" : "Grant access"}</Button>}</td></tr>)}</tbody></table></div>{!data.grants.length && <p>No group grants yet.</p>}<p className="mt-3 text-xs text-ink-tertiary">Revoking access or removing a group member blocks their next request. Requests already accepted may finish.</p></Card>}</section>;
}

const routes: Record<S["AIModelMode"], string> = { chat: "chat/completions", completion: "completions", embedding: "embeddings", audio_speech: "audio/speech", audio_transcription: "audio/transcriptions", image_generation: "images/generations", video_generation: "videos", rerank: "rerank" };
const shellQuote = (s: string) => "'" + s.replace(/'/g, "'\\''") + "'";
export function AIUseModel({ orgId }: { orgId: string }) {
  const [models, setModels] = useState<S["AIUserModel"][] | null>(null), [model, setModel] = useState("");
  const [prompt, setPrompt] = useState("Say hello in one sentence."), [output, setOutput] = useState(""), [error, setError] = useState("");
  const [busy, setBusy] = useState(false), [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    void api.GET("/api/v1/organizations/{orgId}/ai-gateway/my-models", { params: { path: { orgId } } }).then(({ data, error }) => {
      if (!active) return; if (error || !data) throw Error(); setModels(data); setModel((m) => data.some((v) => v.model === m) ? m : data[0]?.model ?? "");
    }).catch(() => { if (active) setError("Could not load your models. Refresh access or sign in again."); });
    return () => { active = false; };
  }, [orgId, attempt]);
  const selected = models?.find((m) => m.model === model);
  const origin = getApiOrigin() ?? window.location.origin;
  const base = `${origin}/api/v1/organizations/${orgId}/ai-gateway/inference/v1`;
  const endpoint = `${base}/${routes[selected?.mode ?? "chat"]}`;
  async function call() {
    if (busy || !selected || selected.mode !== "chat" || !prompt.trim()) return;
    setBusy(true); setError(""); setOutput("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/inference/v1/chat/completions", { params: { path: { orgId } }, body: { model, messages: [{ role: "user", content: prompt }], max_tokens: 256, stream: false } });
      if (result.error || !result.data) { setError(`Request failed (HTTP ${result.response.status}). Refresh your model access and try again.`); return; }
      setOutput(JSON.stringify(result.data, null, 2)); toast.success(`HTTP ${result.response.status} — Model responded`);
    } catch { setError("Could not reach the gateway. Check your connection and sign in again if needed."); }
    finally { setBusy(false); }
  }
  return <section className="space-y-5" aria-label="Use a model"><Card><h2 className="text-xl font-semibold">Use model</h2><p className="my-2 text-sm text-ink-tertiary">Your Tunnex login gives access to models granted to your user groups. No provider API key is needed.</p>
    {error && <p role="alert">{error}</p>}<Button disabled={busy} onClick={() => { setError(""); setAttempt((n) => n + 1); }}>Refresh my models</Button>
    {models === null ? <Loading label="Loading your models…" /> : !models.length ? <p className="mt-4">No models are available to you yet. Ask your AI admin to grant a model to your user group and enable the gateway.</p> : <div className="mt-5 space-y-5"><Field label="Your model"><Select value={model} disabled={busy} onChange={(e) => { setModel(e.target.value); setOutput(""); }}>{models.map((m) => <option key={m.model} value={m.model}>{m.model}</option>)}</Select></Field>
      <div><h3>API endpoint</h3><code className="block mt-2 break-all text-sm">{endpoint}</code><Button onClick={() => void navigator.clipboard.writeText(endpoint).then(() => toast.success("Endpoint copied")).catch(() => setError("Could not copy. Select the endpoint text to copy it."))}>Copy endpoint</Button></div>
      <div><h3>Call from your terminal</h3><pre className="mt-2 overflow-x-auto rounded-lg bg-ink-900 p-4 text-xs">{`tunnex login --server ${shellQuote(origin)}\ntunnex ai models --org ${orgId}${selected?.mode === "chat" ? `\ntunnex ai chat --org ${orgId} --model ${shellQuote(model)} --prompt 'Hello'` : ""}`}</pre><p className="mt-2 text-xs text-ink-tertiary">The CLI uses your saved Tunnex login. API clients authenticate with the same Tunnex login credential; browser calls use your session.</p></div>
      {selected?.mode === "chat" && <><Field label="Message"><textarea className="w-full rounded-lg border border-white/10 bg-ink-900 p-3 text-sm" rows={3} maxLength={8000} value={prompt} disabled={busy} onChange={(e) => setPrompt(e.target.value)} /></Field><Button disabled={busy || !prompt.trim()} onClick={() => void call()}>{busy ? "Calling model…" : "Call model"}</Button></>}
    </div>}
  </Card>{output && <Card><h3>Model response</h3><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap text-sm">{output}</pre></Card>}</section>;
}
