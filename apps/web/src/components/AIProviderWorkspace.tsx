import { useEffect, useId, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Badge, Button, Field, Input, Modal } from "./ui";
import "./ai-provider-workspace.css";
import { EntityPicker } from "./EntityPicker";
import { ProviderLogo } from "./ProviderLogo";
type S = components["schemas"];
export type AIProviderConnection = S["AIProviderConnection"];
type Definition = S["AIProviderDefinition"];
const uniqueLines = (v: string) => [...new Set(v.split("\n").map((s) => s.trim()).filter(Boolean))];
export function AIProviderWorkspace({ orgId }: { orgId: string }) {
  return <ProviderWorkspace key={orgId} orgId={orgId} />;
}
function ProviderWorkspace({ orgId }: { orgId: string }) {
  const [inventory, setInventory] = useState<S["AIProviderList"] | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [editing, setEditing] = useState<AIProviderConnection | "new" | "model" | null>(null);
  const [view, setView] = useState<"connections" | "models">("connections");
  const [modelSearch, setModelSearch] = useState(""), [modelProvider, setModelProvider] = useState("");
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
  const definitions = inventory?.definitions ?? [];
  const providerName = (id: string) => definitions.find((d) => d.id === id)?.name ?? id;
  const modelRows = (inventory?.items ?? []).flatMap((connection) => connection.models.map((model) => ({ connection, model }))).filter(({ connection, model }) => (!modelProvider || connection.provider === modelProvider) && `${model} ${connection.name}`.toLowerCase().includes(modelSearch.toLowerCase()));
  return <section className="ai-provider-workspace" aria-label="Provider connections">
    <header className="ai-provider-heading"><div><p className="ai-provider-eyebrow">AI GATEWAY / PROVIDERS</p><h2>Providers & models</h2><p>Connect your providers. Manage exact models and keep credentials off your agents.</p></div><Button disabled={loading || busy || !inventory?.management_available || !definitions.length} onClick={() => { setEditing("new"); setRemoving(null); }}>Add provider</Button></header>
    {error && <p role="alert" className="ai-provider-alert">{error}</p>}
    {notice && <p role="status" className="ai-provider-notice">{notice}</p>}
    {loading && !inventory ? <p role="status">Loading provider connections…</p> : !inventory ? <Button onClick={() => { setError(""); void reload(); }}>Retry provider connections</Button> : <>
      {inventory.management_available && !definitions.length && <p className="ai-provider-notice">This API does not expose supported provider definitions. Existing connections remain editable; update the control plane before adding providers.</p>}
      {!inventory.management_available && <div className="ai-provider-panel"><h3>Provider management requires installation setup</h3><p>Your installation administrator must enable database-owned provider configuration before adding or changing connections here. Existing operator-managed policy references remain available in Configuration.</p></div>}
      <div className="ai-provider-view-tabs" role="tablist" aria-label="Provider inventory view"><button role="tab" aria-selected={view === "connections"} onClick={() => setView("connections")}>Connections <span>{inventory.items.length}</span></button><button role="tab" aria-selected={view === "models"} onClick={() => setView("models")}>Models <span>{inventory.items.reduce((n, c) => n + c.models.length, 0)}</span></button></div>
      {view === "models" && <div className="ai-provider-panel"><div className="ai-provider-panel-heading"><div><h3>Models & endpoints</h3><p>Exact API model IDs, backed by your organization's provider connections.</p></div><Button disabled={busy || !inventory.management_available || !definitions.length} onClick={() => setEditing("model")}>Add model</Button></div><div className="ai-provider-model-filters"><Field label="Search configured models"><Input value={modelSearch} onChange={(e) => setModelSearch(e.target.value)} placeholder="Model ID or connection name" /></Field><Field label="Filter models by provider"><select value={modelProvider} onChange={(e) => setModelProvider(e.target.value)}><option value="">All providers</option>{[...new Set(inventory.items.map((c) => c.provider))].map((id) => <option key={id} value={id}>{providerName(id)}</option>)}</select></Field></div><div className="ai-provider-table-scroll"><table><caption className="sr-only">Configured models</caption><thead><tr><th>API model ID</th><th>Provider</th><th>Connection</th><th>State</th><th>Actions</th></tr></thead><tbody>{modelRows.map(({ connection: c, model }) => <tr key={`${c.id}:${model}`}><th scope="row"><code>{model}</code></th><td>{providerName(c.provider)}</td><td>{c.name}</td><td><Badge tone={c.status === "error" ? "danger" : c.status === "pending" ? "warn" : "neutral"}>{c.status}</Badge></td><td><div className="ai-provider-row-actions"><Button disabled={busy || !inventory.management_available} onClick={() => setEditing(c)} aria-label={`Edit ${model} on ${c.name}`}>Edit</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Connection credential check completed. This does not test model inference entitlement.")} aria-label={`Test connection for ${model} on ${c.name}`}>Test connection</Button></div></td></tr>)}</tbody></table></div>{!modelRows.length && <p className="ai-provider-empty">No configured models match this view. Add a model or adjust your filters.</p>}</div>}
      {view === "connections" && <div className="ai-provider-panel ai-provider-table-scroll"><div className="ai-provider-panel-heading"><h3>Provider connections</h3><span>{inventory.items.length} connections</span></div>
        {!inventory.items.length ? <div className="ai-provider-empty"><h3>No provider connections yet</h3><p>Add a provider connection, choose exact models, then assign it to a team in Configuration.</p></div> : <table><caption className="sr-only">Configured provider connections</caption><thead><tr><th>Connection</th><th>Models</th><th>State</th><th>Credential check</th><th>Actions</th></tr></thead><tbody>{inventory.items.map((c) => <tr key={c.id}><th scope="row"><strong>{c.name}</strong><small>{providerName(c.provider)}</small><code>{c.key_id}</code></th><td><details><summary>{c.models.length} models</summary><ul>{c.models.map((m) => <li key={m}>{m}</li>)}</ul></details></td><td><Badge tone={c.status === "error" ? "danger" : c.status === "pending" ? "warn" : "neutral"}>{c.status}</Badge><small>Desired {c.revision} · applied {c.applied_revision}</small><small>{c.enabled ? "Access enabled" : "Access disabled"}</small></td><td><Badge tone={c.last_test_status === "failed" ? "danger" : "neutral"}>{c.last_test_status}</Badge><small>{c.last_test_at ? new Date(c.last_test_at).toLocaleString() : "No check recorded"}</small></td><td><div className="ai-provider-row-actions"><Button disabled={busy || !inventory.management_available} onClick={() => { setEditing(c); setRemoving(null); }}>Edit {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Credential check completed. Review its recorded result; success does not prove every model's inference entitlement.")}>Test {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { provider: c.provider, ...(c.endpoint_url ? { endpoint_url: c.endpoint_url } : {}), name: c.name, models: c.models, enabled: !c.enabled, expected_revision: c.revision } }), "Connection state updated. Disabling blocks new requests; accepted streams may finish within 30 seconds.")}>{c.enabled ? "Disable" : "Enable"} {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => { setRemoving(c); setEditing(null); }}>Delete {c.name}</Button></div></td></tr>)}</tbody></table>}
      </div>}
      {inventory.legacy_key_ids.length > 0 && <div className="ai-provider-panel"><h3>Existing operator-managed references</h3><p>These references belong to this organization. Their credentials and model scope remain managed by the installation administrator.</p><div className="ai-provider-tags">{inventory.legacy_key_ids.map((id) => <code key={id}>{id}</code>)}</div></div>}
      <p className="ai-provider-footnote">Credential tests use provider catalog/authentication requests, not inference. No model tokens are generated. A successful check does not prove model inference entitlement.</p>
      {removing && <div className="ai-provider-panel" role="region" aria-label="Delete provider connection"><h3>Delete {removing.name}?</h3><p>Remove this connection from every team policy first. The server refuses deletion while references remain. Usage history is preserved; only this provider connection is removed.</p><div className="ai-provider-form-actions"><Button disabled={busy} onClick={() => setRemoving(null)}>Cancel deletion</Button><Button disabled={busy} onClick={async () => { const c = removing; if (await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Provider connection deleted. Usage history is retained.")) setRemoving(null); }}>Confirm deletion</Button></div></div>}
      {editing && <ProviderEditor key={typeof editing === "string" ? "new" : `${editing.id}:${editing.revision}`} orgId={orgId} connection={typeof editing === "string" ? undefined : editing} definitions={definitions} customAvailable={inventory.custom_available ?? false} endpoints={inventory.custom_endpoints ?? []} connections={inventory.items} modelOnly={editing === "model"} busy={busy} onCancel={() => setEditing(null)} onSave={save} />}
      <Button disabled={loading || busy} onClick={() => { setError(""); void reload(); }}>Refresh providers</Button>
    </>}
  </section>;
}
function ProviderEditor({ orgId, connection: initialConnection, definitions, customAvailable, endpoints, connections, modelOnly, busy, onSave, onCancel }: { orgId: string; connection?: AIProviderConnection; definitions: Definition[]; customAvailable: boolean; endpoints: NonNullable<S["AIProviderList"]["custom_endpoints"]>; connections: AIProviderConnection[]; modelOnly: boolean; busy: boolean; onSave: (body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) => Promise<void>; onCancel: () => void }) {
  const [provider, setProvider] = useState<AIProviderConnection["provider"] | undefined>(initialConnection?.provider);
  const [endpoint, setEndpoint] = useState(initialConnection?.endpoint_url ?? "");
  const [existingID, setExistingID] = useState("");
  const connection = initialConnection ?? (modelOnly ? connections.find((c) => c.id === existingID && c.provider === provider) : undefined);
  const definition = definitions.find((d) => d.id === provider);
  const providerLabel = definition?.name ?? initialConnection?.provider ?? "Select a provider";
  const formId = useId();
  const [name, setName] = useState(connection?.name ?? ""), [secret, setSecret] = useState(""), [models, setModels] = useState(connection?.models.join("\n") ?? ""), [enabled, setEnabled] = useState(connection?.enabled ?? true);
  const [query, setQuery] = useState(""), [catalog, setCatalog] = useState<S["AIProviderModelList"] | null>(null), [catalogError, setCatalogError] = useState(""), [searching, setSearching] = useState(false);
  const active = useRef(true), searchSerial = useRef(0);
  useEffect(() => { active.current = true; return () => { active.current = false; searchSerial.current++; }; }, []);
  async function search(offset = 0) {
    if (!provider || provider === "custom" && !connection) return;
    const n = ++searchSerial.current;
    setSearching(true); setCatalogError("");
    try {
      const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/models", { params: { path: { orgId }, query: { provider, ...(provider === "custom" && connection ? { connection_id: connection.id } : {}), query: query.trim(), limit: 50, offset } } });
      if (!active.current || n !== searchSerial.current) return;
      if (r.error || !r.data) throw Error();
      setCatalog(r.data);
    } catch { if (active.current && n === searchSerial.current) { setCatalog(null); setCatalogError("Model suggestions are unavailable. You can still enter exact provider/model IDs below."); } }
    finally { if (active.current && n === searchSerial.current) setSearching(false); }
  }
  function switchProvider(next: AIProviderConnection["provider"]) {
    if (next === provider) return;
    setProvider(next); setEndpoint(""); setSecret(""); setModels(""); setExistingID(""); setQuery(""); setCatalog(null); setCatalogError(""); setSearching(false); searchSerial.current++;
  }
  const chosen = uniqueLines(models);
  const finalModels = modelOnly && connection ? [...new Set([...connection.models, ...chosen])] : chosen;
  const validModel = (model: string) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$/.test(model)) return false;
    if (provider !== "custom") return model.startsWith(`${provider}/`) && model.length > (provider?.length ?? 0) + 1;
    if (/^custom-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\//.test(model)) return !!connection && model.startsWith(`custom-${connection.id}/`) && model.length > connection.id.length + 8;
    return true;
  };
  const selectedEndpoint = connection?.endpoint_url ?? endpoint;
  const valid = (provider !== "custom" || customAvailable && !!selectedEndpoint && endpoints.some((e) => e.url === selectedEndpoint)) && !!provider && (!!connection || !!definition) && (connection && modelOnly || name.trim().length > 0 && name.trim().length <= 80) && chosen.length > 0 && finalModels.length <= 32 && chosen.every(validModel) && (connection && !secret || secret.length > 0 && secret.length <= 4096 && !/\s/.test(secret));
  return <Modal title={modelOnly ? "Add model" : connection ? "Edit provider" : "Add provider"} placement="right" size="wide" showClose onDismiss={onCancel} actions={<><Button variant="ghost" type="button" disabled={busy} onClick={onCancel}>Cancel provider edit</Button><Button form={formId} type="submit" disabled={busy || !valid}>{modelOnly && connection ? "Add models to connection" : connection ? "Save connection" : "Create connection"}</Button></>}>
    <div className="ai-provider-workspace"><form id={formId} className="ai-provider-editor" aria-label={connection ? "Edit provider connection" : "Add provider connection"} onSubmit={(event) => { event.preventDefault(); if (!valid || busy || !provider) return; const body = { provider, ...(provider === "custom" ? { endpoint_url: selectedEndpoint } : {}), name: modelOnly && connection ? connection.name : name.trim(), models: finalModels, enabled: modelOnly && connection ? connection.enabled : enabled, ...(secret ? { api_key: secret } : {}) }; setSecret(""); void onSave(connection ? { ...body, expected_revision: connection.revision } : { ...body, api_key: secret }, connection); }}>
    <div className="ai-provider-panel-heading"><h3>{modelOnly ? "Add models to your gateway" : connection ? "Edit connection / rotate key" : "Connect a provider"}</h3><Badge>{providerLabel}</Badge></div>
    {initialConnection ? <p className="ai-provider-fixed-brand"><ProviderLogo provider={initialConnection.provider} />Provider: {providerLabel}. A connection's provider cannot be changed.</p> : <div className="ai-provider-picker"><EntityPicker label="Provider" value={provider ?? ""} placeholder="Select a provider" options={definitions.map((d) => ({ value: d.id, kind: "provider", tag: "", label: d.name, icon: <ProviderLogo provider={d.id} />, unavailable: d.id === "custom" && !customAvailable ? "Installation setup required" : undefined }))} onSelect={(option) => { const selected = definitions.find((d) => d.id === option.value); if (selected) switchProvider(selected.id); }} /></div>}
    {definitions.some((d) => d.id === "custom") && !customAvailable && <p>Custom providers require an installation-approved endpoint and secure egress setup.</p>}
    {provider === "custom" && (connection ? <><Field label="Upstream endpoint"><Input readOnly value={connection.endpoint_url ?? ""} /></Field><p>The endpoint cannot be changed for this connection.</p></> : <Field label="Approved upstream endpoint"><select value={endpoint} onChange={(e) => { setEndpoint(e.target.value); setSecret(""); setModels(""); }}><option value="">Select an approved endpoint</option>{endpoints.map((e) => <option key={e.url} value={e.url}>{e.name} · {e.url}</option>)}</select></Field>)}
    {modelOnly && <><Field label="Credential connection"><select value={existingID} onChange={(e) => { setExistingID(e.target.value); setSecret(""); setModels(""); setCatalog(null); setCatalogError(""); setSearching(false); searchSerial.current++; }}><option value="">Create a new connection</option>{connections.filter((c) => c.provider === provider && (c.status === "applied" && c.applied_revision === c.revision || c.status === "disabled")).map((c) => <option key={c.id} value={c.id}>{c.name} · {c.status}</option>)}</select></Field><p>Pending or failed connections need their key re-entered through Edit before reuse.</p>{connection && <p>Reuse {connection.name} without re-entering its API key. Existing models are preserved.</p>}</>}
    {!(modelOnly && connection) && <><div className="ai-provider-form-grid"><Field label="Connection name"><Input autoFocus value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder="e.g. Engineering AI" /></Field><Field label={connection ? "Replacement API key (optional)" : "API key"}><Input type="password" autoComplete="new-password" spellCheck={false} value={secret} maxLength={4096} onChange={(e) => setSecret(e.target.value)} placeholder={connection ? "Leave blank to keep the current key" : "Enter your provider key"} /></Field></div>
    <p>Keys are stored securely and never shown again. If a key update fails, enter the key again and save.</p></>}
    {provider === "custom" && !connection && <p>Enter upstream model names below. Catalog suggestions become available after creating the connection.</p>}
    <div className="ai-provider-catalog"><div className="ai-provider-catalog-search"><Field label="Search model catalog"><Input value={query} maxLength={100} onChange={(e) => { setQuery(e.target.value); searchSerial.current++; setSearching(false); setCatalog(null); }} placeholder="Search model name" /></Field><Button type="button" disabled={searching || !definition || provider === "custom" && !connection} onClick={() => void search()}>{searching ? "Searching…" : "Search models"}</Button></div>{catalogError && <p role="alert">{catalogError}</p>}{catalog && <><p>{catalog.total} matching models · showing {catalog.items.length ? catalog.offset + 1 : 0}–{catalog.offset + catalog.items.length}</p><div className="ai-provider-catalog-items">{catalog.items.map((m) => <label key={m.id}><input type="checkbox" checked={chosen.includes(m.id)} disabled={!chosen.includes(m.id) && chosen.length >= 32} onChange={(e) => setModels((e.target.checked ? [...chosen, m.id] : chosen.filter((id) => id !== m.id)).join("\n"))} /><span>{m.name}<small>{m.id}</small></span></label>)}</div><div className="ai-provider-form-actions"><Button type="button" disabled={searching || catalog.offset === 0} onClick={() => void search(Math.max(0, catalog.offset - catalog.limit))}>Previous models</Button><Button type="button" disabled={searching || catalog.offset + catalog.limit >= catalog.total || catalog.offset + catalog.limit > 10000} onClick={() => void search(catalog.offset + catalog.limit)}>Next models</Button></div></>}</div>
    <Field label="Exact model IDs (one per line)"><textarea value={models} rows={4} onChange={(e) => setModels(e.target.value)} placeholder={definition?.model_placeholder ?? "Select a provider first"} /></Field><p>{finalModels.length}/32 models selected. Suggestions do not prove this key can run every model.</p>
    {!(modelOnly && connection) && <><label className="ai-provider-enabled"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enable this connection for authorized team policies</label><p>Organization AI access remains a separate default-off setting.</p></>}
  </form></div>
  </Modal>;
}
