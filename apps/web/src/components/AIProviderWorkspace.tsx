import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Field, Input } from "./ui";
import "./ai-provider-workspace.css";
type S = components["schemas"];
export type AIProviderConnection = S["AIProviderConnection"];
const uniqueLines = (v: string) => [...new Set(v.split("\n").map((s) => s.trim()).filter(Boolean))];
export function AIProviderWorkspace({ orgId }: { orgId: string }) {
  return <ProviderWorkspace key={orgId} orgId={orgId} />;
}
function ProviderWorkspace({ orgId }: { orgId: string }) {
  const [inventory, setInventory] = useState<S["AIProviderList"] | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [editing, setEditing] = useState<AIProviderConnection | "new" | null>(null);
  const [removing, setRemoving] = useState<AIProviderConnection | null>(null);
  const alive = useRef(true), serial = useRef(0);
  async function reload() {
    const n = ++serial.current;
    setLoading(true);
    try {
      const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } } });
      if (!alive.current || n !== serial.current) return;
      if (r.error || !r.data) throw Error();
      setInventory(r.data);
    } catch { if (alive.current && n === serial.current) setError("Could not load provider connections. Retry to refresh authoritative state."); }
    finally { if (alive.current && n === serial.current) setLoading(false); }
  }
  useEffect(() => { alive.current = true; void reload(); return () => { alive.current = false; serial.current++; }; }, [orgId]);
  async function mutate(call: () => Promise<{ data?: unknown; error?: unknown; response: Response }>, success: string) {
    if (busy) return false;
    setBusy(true); setError(""); setNotice("");
    let ok = false;
    try {
      const r = await call();
      if (!alive.current) return false;
      if (r.error) {
        setError(r.response.status === 409 ? "This connection changed or is referenced by a team policy. Refresh and update those policies before removing models or deleting the connection." : "The operation could not be completed. Check the connection state; an uncertain key update requires entering the API key again.");
      } else { setNotice(success); ok = true; }
      await reload();
    } catch { if (alive.current) { setError("Could not reach the API. Refresh to check saved state. Enter the API key again if an update did not finish."); await reload(); } }
    finally { if (alive.current) setBusy(false); }
    return ok;
  }
  async function save(body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) {
    // Close before awaiting: no submitted secret remains in a form or its state.
    setEditing(null);
    await mutate(() => connection
      ? api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: connection.id } }, body: body as S["AIProviderUpdate"] })
      : api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } }, body: body as S["AIProviderCreate"] }), "Connection saved. Review its synchronization state before assigning access.");
  }
  return <section className="ai-provider-workspace" aria-label="Provider connections">
    <header className="ai-provider-heading"><div><p className="ai-provider-eyebrow">AI GATEWAY / PROVIDERS</p><h2>Providers & models</h2><p>Connect OpenRouter once. Keep provider credentials off your agents.</p></div><Button disabled={loading || busy || !inventory?.management_available} onClick={() => { setEditing("new"); setRemoving(null); }}>Add provider</Button></header>
    {error && <p role="alert" className="ai-provider-alert">{error}</p>}
    {notice && <p role="status" className="ai-provider-notice">{notice}</p>}
    {loading && !inventory ? <p role="status">Loading provider connections…</p> : !inventory ? <Button onClick={() => { setError(""); void reload(); }}>Retry provider connections</Button> : <>
      {!inventory.management_available && <div className="ai-provider-panel"><h3>Provider management requires installation setup</h3><p>Your installation administrator must enable database-owned provider configuration before adding or changing connections here. Existing operator-managed policy references remain available in Configuration.</p></div>}
      <div className="ai-provider-panel ai-provider-table-scroll"><div className="ai-provider-panel-heading"><h3>Provider connections</h3><span>{inventory.items.length} connections · OpenRouter</span></div>
        {!inventory.items.length ? <div className="ai-provider-empty"><h3>No provider connections yet</h3><p>Add an OpenRouter connection, choose exact models, then assign it to a team in Configuration.</p></div> : <table><caption className="sr-only">Configured provider connections</caption><thead><tr><th>Connection</th><th>Models</th><th>State</th><th>Credential check</th><th>Actions</th></tr></thead><tbody>{inventory.items.map((c) => <tr key={c.id}><th scope="row"><strong>{c.name}</strong><small>OpenRouter</small><code>{c.key_id}</code></th><td><details><summary>{c.models.length} models</summary><ul>{c.models.map((m) => <li key={m}>{m}</li>)}</ul></details></td><td><span className={`ai-provider-pill ai-provider-pill-${c.status}`}>{c.status}</span><small>Desired {c.revision} · applied {c.applied_revision}</small><small>{c.enabled ? "Access enabled" : "Access disabled"}</small></td><td><span className={`ai-provider-pill ai-provider-pill-${c.last_test_status}`}>{c.last_test_status}</span><small>{c.last_test_at ? new Date(c.last_test_at).toLocaleString() : "No check recorded"}</small></td><td><div className="ai-provider-row-actions"><Button disabled={busy || !inventory.management_available} onClick={() => { setEditing(c); setRemoving(null); }}>Edit {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Credential check completed. Review its recorded result; success does not prove every model's inference entitlement.")}>Test {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { provider: c.provider, name: c.name, models: c.models, enabled: !c.enabled, expected_revision: c.revision } }), "Connection state updated. Disabling blocks new requests; accepted streams may finish within 30 seconds.")}>{c.enabled ? "Disable" : "Enable"} {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => { setRemoving(c); setEditing(null); }}>Delete {c.name}</Button></div></td></tr>)}</tbody></table>}
      </div>
      {inventory.legacy_key_ids.length > 0 && <div className="ai-provider-panel"><h3>Existing operator-managed references</h3><p>These references belong to this organization. Their credentials and model scope remain managed by the installation administrator.</p><div className="ai-provider-tags">{inventory.legacy_key_ids.map((id) => <code key={id}>{id}</code>)}</div></div>}
      <p className="ai-provider-footnote">Credential tests use provider catalog/authentication requests, not inference. No model tokens are generated. Only OpenRouter is qualified in this release.</p>
      {removing && <div className="ai-provider-panel" role="region" aria-label="Delete provider connection"><h3>Delete {removing.name}?</h3><p>Remove this connection from every team policy first. The server refuses deletion while references remain. Usage history is preserved; only this provider connection is removed.</p><div className="ai-provider-form-actions"><Button disabled={busy} onClick={() => setRemoving(null)}>Cancel deletion</Button><Button disabled={busy} onClick={async () => { const c = removing; if (await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Provider connection deleted. Usage history is retained.")) setRemoving(null); }}>Confirm deletion</Button></div></div>}
      {editing && <ProviderEditor key={typeof editing === "string" ? "new" : `${editing.id}:${editing.revision}`} orgId={orgId} connection={editing === "new" ? undefined : editing} busy={busy} onCancel={() => setEditing(null)} onSave={save} />}
      <Button disabled={loading || busy} onClick={() => { setError(""); void reload(); }}>Refresh providers</Button>
    </>}
  </section>;
}
function ProviderEditor({ orgId, connection, busy, onSave, onCancel }: { orgId: string; connection?: AIProviderConnection; busy: boolean; onSave: (body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState(connection?.name ?? ""), [secret, setSecret] = useState(""), [models, setModels] = useState(connection?.models.join("\n") ?? ""), [enabled, setEnabled] = useState(connection?.enabled ?? true);
  const [query, setQuery] = useState(""), [catalog, setCatalog] = useState<S["AIProviderModelList"] | null>(null), [catalogError, setCatalogError] = useState(""), [searching, setSearching] = useState(false);
  const active = useRef(true), searchSerial = useRef(0);
  useEffect(() => { active.current = true; return () => { active.current = false; searchSerial.current++; }; }, []);
  async function search(offset = 0) {
    const n = ++searchSerial.current;
    setSearching(true); setCatalogError("");
    try {
      const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/models", { params: { path: { orgId }, query: { query: query.trim(), limit: 50, offset } } });
      if (!active.current || n !== searchSerial.current) return;
      if (r.error || !r.data) throw Error();
      setCatalog(r.data);
    } catch { if (active.current && n === searchSerial.current) { setCatalog(null); setCatalogError("Model suggestions are unavailable. You can still enter exact OpenRouter model IDs below."); } }
    finally { if (active.current && n === searchSerial.current) setSearching(false); }
  }
  const chosen = uniqueLines(models);
  const valid = name.trim().length > 0 && name.trim().length <= 80 && chosen.length > 0 && chosen.length <= 32 && chosen.every((m) => m.startsWith("openrouter/") && m.length > 11 && m.length <= 256 && !/\s/.test(m)) && (connection && !secret || secret.length > 0 && secret.length <= 4096 && !/\s/.test(secret));
  return <form className="ai-provider-panel ai-provider-editor" aria-label={connection ? "Edit provider connection" : "Add provider connection"} onSubmit={(event) => { event.preventDefault(); if (!valid || busy) return; const body = { provider: "openrouter" as const, name: name.trim(), models: chosen, enabled, ...(secret ? { api_key: secret } : {}) }; setSecret(""); void onSave(connection ? { ...body, expected_revision: connection.revision } : { ...body, api_key: secret }, connection); }}>
    <div className="ai-provider-panel-heading"><h3>{connection ? "Edit connection / rotate key" : "Connect OpenRouter"}</h3><span>Write-only credentials</span></div>
    <div className="ai-provider-form-grid"><Field label="Connection name"><Input value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder="Engineering OpenRouter" /></Field><Field label={connection ? "Replacement API key (optional)" : "OpenRouter API key"}><Input type="password" autoComplete="new-password" spellCheck={false} value={secret} maxLength={4096} onChange={(e) => setSecret(e.target.value)} placeholder={connection ? "Leave blank to keep the current key" : "Enter your provider key"} /></Field></div>
    <p>Only the private gateway stores this key. It is never returned to this form. For an uncertain update, enter the key again and save.</p>
    <div className="ai-provider-catalog"><div className="ai-provider-catalog-search"><Field label="Search model catalog"><Input value={query} maxLength={100} onChange={(e) => { setQuery(e.target.value); searchSerial.current++; setSearching(false); setCatalog(null); }} placeholder="Search model name" /></Field><Button type="button" disabled={searching} onClick={() => void search()}>{searching ? "Searching…" : "Search models"}</Button></div>{catalogError && <p role="alert">{catalogError}</p>}{catalog && <><p>{catalog.total} matching models · showing {catalog.items.length ? catalog.offset + 1 : 0}–{catalog.offset + catalog.items.length}</p><div className="ai-provider-catalog-items">{catalog.items.map((m) => <label key={m.id}><input type="checkbox" checked={chosen.includes(m.id)} disabled={!chosen.includes(m.id) && chosen.length >= 32} onChange={(e) => setModels((e.target.checked ? [...chosen, m.id] : chosen.filter((id) => id !== m.id)).join("\n"))} /><span>{m.name}<small>{m.id}</small></span></label>)}</div><div className="ai-provider-form-actions"><Button type="button" disabled={searching || catalog.offset === 0} onClick={() => void search(Math.max(0, catalog.offset - catalog.limit))}>Previous models</Button><Button type="button" disabled={searching || catalog.offset + catalog.limit >= catalog.total || catalog.offset + catalog.limit > 10000} onClick={() => void search(catalog.offset + catalog.limit)}>Next models</Button></div></>}</div>
    <Field label="Exact model IDs (one per line)"><textarea value={models} rows={4} onChange={(e) => setModels(e.target.value)} placeholder="openrouter/openai/gpt-4o-mini" /></Field><p>{chosen.length}/32 models selected. Suggestions do not prove this key can run every model.</p>
    <label className="ai-provider-enabled"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enable this connection for authorized team policies</label><p>Organization AI access remains a separate default-off setting.</p><div className="ai-provider-form-actions"><Button type="button" disabled={busy} onClick={onCancel}>Cancel provider edit</Button><Button type="submit" disabled={busy || !valid}>{connection ? "Save connection" : "Create connection"}</Button></div>
  </form>;
}
