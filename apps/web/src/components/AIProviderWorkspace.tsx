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
// Display-only: native routing remains fixed by apps/ai-bridge/worker.py ORIGINS.
const nativeAPIBase: Record<string, string> = {
  openai: "https://api.openai.com/v1", anthropic: "https://api.anthropic.com",
  gemini: "https://generativelanguage.googleapis.com", openrouter: "https://openrouter.ai/api/v1",
  groq: "https://api.groq.com/openai/v1", mistral: "https://api.mistral.ai/v1",
  cerebras: "https://api.cerebras.ai/v1", xai: "https://api.x.ai/v1", deepseek: "https://api.deepseek.com",
};
const uniqueLines = (v: string) => [...new Set(v.split("\n").map((s) => s.trim()).filter(Boolean))];
function endpointBase(value: string): string {
  try {
    const url = new URL(value.trim());
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) return "";
    return `${url.origin}${url.pathname.replace(/\/+$/, "").replace(/\/v1$/, "")}`;
  } catch { return ""; }
}
export function AIProviderWorkspace({ orgId }: { orgId: string }) {
  return <ProviderWorkspace key={orgId} orgId={orgId} />;
}
function ProviderWorkspace({ orgId }: { orgId: string }) {
  const [inventory, setInventory] = useState<S["AIProviderList"] | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [editing, setEditing] = useState<AIProviderConnection | null>(null);
  const [view, setView] = useState<"connections" | "models" | "add">("models");
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
    setEditing(null); setView("models");
    await mutate(() => connection
      ? api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: connection.id } }, body: body as S["AIProviderUpdate"] })
      : api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } }, body: body as S["AIProviderCreate"] }), "Model and credentials saved. Review synchronization state before assigning access.");
  }
  function changeView(next: typeof view) { setView(next); setEditing(null); setRemoving(null); }
  const definitions = inventory?.definitions ?? [];
  const providerName = (id: string) => definitions.find((d) => d.id === id)?.name ?? id;
  const modelRows = (inventory?.items ?? []).flatMap((connection) => connection.models.map((model) => ({ connection, model }))).filter(({ connection, model }) => (!modelProvider || connection.provider === modelProvider) && `${model} ${connection.name}`.toLowerCase().includes(modelSearch.toLowerCase()));
  return <section className="ai-provider-workspace" aria-label="Models and endpoints">
    <header className="ai-provider-heading"><div><p className="ai-provider-eyebrow">AI GATEWAY / MODELS</p><h2>Models & endpoints</h2><p>Add a model with your provider credentials, then grant your teams access.</p></div></header>
    {error && <p role="alert" className="ai-provider-alert">{error}</p>}
    {notice && <p role="status" className="ai-provider-notice">{notice}</p>}
    {loading && !inventory ? <p role="status">Loading provider connections…</p> : !inventory ? <Button onClick={() => { setError(""); void reload(); }}>Retry provider connections</Button> : <>
      {inventory.management_available && !definitions.length && <p className="ai-provider-notice">This API does not expose supported provider definitions. Existing connections remain editable; update the control plane before adding providers.</p>}
      {!inventory.management_available && <div className="ai-provider-panel"><h3>Provider management requires installation setup</h3><p>Your installation administrator must enable database-owned provider configuration before adding or changing connections here. Existing operator-managed policy references remain available in Configuration.</p></div>}
      <div className="ai-provider-view-tabs" role="tablist" aria-label="Model management view"><button role="tab" aria-selected={view === "models"} onClick={() => changeView("models")}>All Models <span>{inventory.items.reduce((n, c) => n + c.models.length, 0)}</span></button><button role="tab" aria-selected={view === "add"} disabled={loading || busy || !inventory.management_available || !definitions.length} onClick={() => changeView("add")}>Add Model</button><button role="tab" aria-selected={view === "connections"} onClick={() => changeView("connections")}>LLM Credentials <span>{inventory.items.length}</span></button></div>
      {view === "models" && <div className="ai-provider-panel ai-provider-model-table"><div className="ai-provider-panel-heading"><div><h3>All Models</h3><p>Models available through your gateway. Credentials can be reused across models from the same provider.</p></div></div><div className="ai-provider-model-filters"><Field label="Search configured models"><Input value={modelSearch} onChange={(e) => setModelSearch(e.target.value)} placeholder="Model ID or credential name" /></Field><Field label="Filter models by provider"><select value={modelProvider} onChange={(e) => setModelProvider(e.target.value)}><option value="">All providers</option>{[...new Set(inventory.items.map((c) => c.provider))].map((id) => <option key={id} value={id}>{providerName(id)}</option>)}</select></Field></div><div className="ai-provider-table-scroll"><table><caption className="sr-only">Configured models</caption><thead><tr><th>API model ID</th><th>Provider</th><th>Credential</th><th>State</th><th>Actions</th></tr></thead><tbody>{modelRows.map(({ connection: c, model }) => <tr key={`${c.id}:${model}`}><th scope="row"><code>{model}</code></th><td><span className="ai-provider-table-brand"><ProviderLogo provider={c.provider} />{providerName(c.provider)}</span></td><td>{c.name}</td><td><Badge tone={c.status === "error" ? "danger" : c.status === "pending" ? "warn" : "neutral"}>{c.status}</Badge></td><td><div className="ai-provider-row-actions"><Button disabled={busy || !inventory.management_available} onClick={() => setEditing(c)} aria-label={`Edit ${model} on ${c.name}`}>Edit</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Catalog/connection check completed. Public catalogs may not validate API keys. Success does not prove model inference access.")} aria-label={`Check catalog for ${model} on ${c.name}`}>Check catalog</Button></div></td></tr>)}</tbody></table></div>{!modelRows.length && <p className="ai-provider-empty">No configured models match this view. Add a model or adjust your filters.</p>}</div>}
      {view === "connections" && <div className="ai-provider-panel ai-provider-table-scroll"><div className="ai-provider-panel-heading"><div><h3>LLM Credentials</h3><p>Saved provider keys and endpoints. Editing or disabling credentials affects every model using them.</p></div><span>{inventory.items.length} credentials</span></div>
        {!inventory.items.length ? <div className="ai-provider-empty"><h3>No saved credentials yet</h3><p>Use Add Model to save credentials and select models together, then assign access in Configuration.</p></div> : <table><caption className="sr-only">Saved LLM credentials</caption><thead><tr><th>Credential</th><th>Models</th><th>State</th><th>Catalog check</th><th>Actions</th></tr></thead><tbody>{inventory.items.map((c) => <tr key={c.id}><th scope="row"><strong>{c.name}</strong><small className="ai-provider-table-brand"><ProviderLogo provider={c.provider} />{providerName(c.provider)}</small><code>{c.key_id}</code></th><td><details><summary>{c.models.length} models</summary><ul>{c.models.map((m) => <li key={m}>{m}</li>)}</ul></details></td><td><Badge tone={c.status === "error" ? "danger" : c.status === "pending" ? "warn" : "neutral"}>{c.status}</Badge><small>Desired {c.revision} · applied {c.applied_revision}</small><small>{c.enabled ? "Access enabled" : "Access disabled"}</small></td><td><Badge tone={c.last_test_status === "failed" ? "danger" : "neutral"}>{c.last_test_status}</Badge><small>{c.last_test_at ? new Date(c.last_test_at).toLocaleString() : "No catalog check recorded"}</small></td><td><div className="ai-provider-row-actions"><Button disabled={busy || !inventory.management_available} onClick={() => { setEditing(c); setRemoving(null); }}>Edit {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Catalog/connection check completed. Public catalogs may not validate API keys. Success does not prove model inference access.")}>Check catalog {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => void mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { provider: c.provider, ...(c.endpoint_url ? { endpoint_url: c.endpoint_url } : {}), name: c.name, models: c.models, enabled: !c.enabled, expected_revision: c.revision } }), "Credential state updated. Disabling blocks new requests for every model using these credentials; accepted streams may finish within 30 seconds.")}>{c.enabled ? "Disable" : "Enable"} {c.name}</Button><Button disabled={busy || !inventory.management_available} onClick={() => { setRemoving(c); setEditing(null); }}>Delete {c.name}</Button></div></td></tr>)}</tbody></table>}
      </div>}
      {view !== "add" && inventory.legacy_key_ids.length > 0 && <div className="ai-provider-panel"><h3>Existing operator-managed references</h3><p>These references belong to this organization. Their credentials and model scope remain managed by the installation administrator.</p><div className="ai-provider-tags">{inventory.legacy_key_ids.map((id) => <code key={id}>{id}</code>)}</div></div>}
      {view !== "add" && <p className="ai-provider-footnote">Catalog/connection checks generate no model tokens. Public catalogs may not validate API keys. Success does not prove model inference access.</p>}
      {removing && <div className="ai-provider-panel" role="region" aria-label="Delete provider connection"><h3>Delete {removing.name}?</h3><p>Remove this connection from every team policy first. The server refuses deletion while references remain. Usage history is preserved. These credentials and all their configured models are removed.</p><div className="ai-provider-form-actions"><Button disabled={busy} onClick={() => setRemoving(null)}>Cancel deletion</Button><Button disabled={busy} onClick={async () => { const c = removing; if (await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Provider connection deleted. Usage history is retained.")) setRemoving(null); }}>Confirm deletion</Button></div></div>}
      {(editing || view === "add") && <ProviderEditor key={editing ? `${editing.id}:${editing.revision}` : "new"} orgId={orgId} connection={editing ?? undefined} definitions={definitions} testAvailable={inventory.test_available ?? false} sagemakerAvailable={inventory.sagemaker_available ?? false} sagemakerEndpoints={inventory.sagemaker_endpoints ?? []} customAvailable={inventory.custom_available ?? false} endpoints={inventory.custom_endpoints ?? []} connections={inventory.items} modelOnly={!editing} busy={busy} onCancel={() => editing ? setEditing(null) : changeView("models")} onSave={save} />}
      {view !== "add" && <Button disabled={loading || busy} onClick={() => { setError(""); void reload(); }}>Refresh models and credentials</Button>}
    </>}
  </section>;
}
function ProviderEditor({ orgId, connection: initialConnection, definitions, testAvailable, sagemakerAvailable, sagemakerEndpoints, customAvailable, endpoints, connections, modelOnly, busy, onSave, onCancel }: { orgId: string; connection?: AIProviderConnection; definitions: Definition[]; testAvailable: boolean; sagemakerAvailable: boolean; sagemakerEndpoints: NonNullable<S["AIProviderList"]["sagemaker_endpoints"]>; customAvailable: boolean; endpoints: NonNullable<S["AIProviderList"]["custom_endpoints"]>; connections: AIProviderConnection[]; modelOnly: boolean; busy: boolean; onSave: (body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) => Promise<void>; onCancel: () => void }) {
  const [provider, setProvider] = useState<AIProviderConnection["provider"] | undefined>(initialConnection?.provider);
  const [endpoint, setEndpoint] = useState(initialConnection?.endpoint_url ?? "");
  const [existingID, setExistingID] = useState("");
  const connection = initialConnection ?? (modelOnly ? connections.find((c) => c.id === existingID && c.provider === provider) : undefined);
  const usesBridge = provider === "custom" || provider === "sagemaker";
  const approvedEndpoints = provider === "sagemaker" ? sagemakerEndpoints : endpoints;
  const bridgeAvailable = provider === "sagemaker" ? sagemakerAvailable : customAvailable;
  const definition = definitions.find((d) => d.id === provider);
  const providerLabel = definition?.name ?? initialConnection?.provider ?? "Select a provider";
  const formId = useId();
  const [name, setName] = useState(connection?.name ?? ""), [secret, setSecret] = useState(""), [models, setModels] = useState(connection?.models.join("\n") ?? ""), [enabled, setEnabled] = useState(connection?.enabled ?? true);
  const [manualModel, setManualModel] = useState("");
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [query, setQuery] = useState(""), [catalog, setCatalog] = useState<S["AIProviderModelList"] | null>(null), [catalogError, setCatalogError] = useState(""), [searching, setSearching] = useState(false);
  const active = useRef(true), searchSerial = useRef(0);
  useEffect(() => { active.current = true; return () => { active.current = false; searchSerial.current++; }; }, []);
  async function search(offset = 0) {
    if (!provider || usesBridge && !connection) return;
    const n = ++searchSerial.current;
    setSearching(true); setCatalogError(""); setCatalogOpen(true);
    try {
      const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/models", { params: { path: { orgId }, query: { provider, ...(usesBridge && connection ? { connection_id: connection.id } : {}), query: query.trim(), limit: 50, offset } } });
      if (!active.current || n !== searchSerial.current) return;
      if (r.error || !r.data) throw Error();
      setCatalog(r.data);
    } catch { if (active.current && n === searchSerial.current) { setCatalog(null); setCatalogError("Model suggestions are unavailable. You can still enter exact provider/model IDs below."); } }
    finally { if (active.current && n === searchSerial.current) setSearching(false); }
  }
  function switchProvider(next: AIProviderConnection["provider"]) {
    if (next === provider) return;
    setProvider(next); setManualModel(""); setCatalogOpen(false); setEndpoint(""); setSecret(""); setModels(""); setExistingID(""); setQuery(""); setCatalog(null); setCatalogError(""); setSearching(false); searchSerial.current++;
  }
  const chosen = uniqueLines(models);
  const finalModels = modelOnly && connection ? [...new Set([...connection.models, ...chosen])] : chosen;
  const validModel = (model: string) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$/.test(model)) return false;
    if (!usesBridge) return model.startsWith(`${provider}/`) && model.length > (provider?.length ?? 0) + 1;
    if (/^custom-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\//.test(model)) return !!connection && model.startsWith(`custom-${connection.id}/`) && model.length > connection.id.length + 8;
    return true;
  };
  const enteredBase = endpointBase(endpoint);
  const selectedEndpoint = connection?.endpoint_url ?? (approvedEndpoints.find((e) => endpointBase(e.url) === enteredBase)?.url ?? enteredBase);
  const endpointApproved = !!selectedEndpoint && approvedEndpoints.some((e) => e.url === selectedEndpoint);
  const savedName = name.trim() || connection?.name || (provider && chosen.length ? `${providerLabel} · ${chosen[0]}`.slice(0, 80) : "");
  const valid = (!usesBridge || bridgeAvailable && endpointApproved) && !!provider && (!!connection || !!definition) && (name.trim().length <= 80) && chosen.length > 0 && finalModels.length <= 32 && chosen.every(validModel) && (connection && !secret || secret.length > 0 && secret.length <= 4096 && !/\s/.test(secret));
  const [testing, setTesting] = useState(false), [testStatus, setTestStatus] = useState<"idle" | "success" | "error">("idle");
  const [testedAt, setTestedAt] = useState(0);
  const testGeneration = useRef(0);
  useEffect(() => { testGeneration.current++; setTestStatus("idle"); setTestedAt(0); setTesting(false); return () => { testGeneration.current++; }; }, [provider, secret, selectedEndpoint, models, existingID]);
  useEffect(() => { if (!testedAt) return; const timer = window.setTimeout(() => { setTestStatus("idle"); setTestedAt(0); }, Math.max(0, testedAt + 300000 - Date.now())); return () => window.clearTimeout(timer); }, [testedAt]);
  const needsTest = !connection || !!secret;
  const canSave = valid && (!needsTest || testStatus === "success" && Date.now() - testedAt < 300000);
  async function testConnection() {
    if (!provider || !valid || !secret || !testAvailable || testing) return;
    const generation = ++testGeneration.current;
    setTesting(true); setTestStatus("idle"); setTestedAt(0);
    const model = usesBridge && connection ? chosen[0].replace(`custom-${connection.id}/`, "") : chosen[0];
    try {
      const r = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/test-connection", { params: { path: { orgId } }, body: { provider, model, api_key: secret, ...(usesBridge ? { endpoint_url: selectedEndpoint } : {}) } });
      if (!active.current || generation !== testGeneration.current) return;
      const success = !r.error && r.data?.status === "success";
      setTestStatus(success ? "success" : "error"); if (success) setTestedAt(Date.now());
    } catch { if (active.current && generation === testGeneration.current) setTestStatus("error"); }
    finally { if (active.current && generation === testGeneration.current) setTesting(false); }
  }
  const actions = <><Button variant="ghost" type="button" disabled={busy} onClick={onCancel}>Cancel</Button>{needsTest && <Button type="button" disabled={busy || testing || !valid || !testAvailable} onClick={() => void testConnection()}>{testing ? "Testing connection…" : "Test Connect"}</Button>}<Button form={formId} type="submit" disabled={busy || !canSave}>{modelOnly ? "Add Model" : "Save credentials"}</Button></>;
  const editor = (
    <div className="ai-provider-workspace"><form id={formId} className="ai-provider-editor" aria-label={modelOnly ? "Add model" : "Edit credentials"} onSubmit={(event) => { event.preventDefault(); if (!canSave || busy || !provider) return; const body = { provider, ...(usesBridge ? { endpoint_url: selectedEndpoint } : {}), name: modelOnly && connection ? connection.name : savedName, models: finalModels, enabled: modelOnly && connection ? connection.enabled : enabled, ...(secret ? { api_key: secret } : {}) }; setSecret(""); void onSave(connection ? { ...body, expected_revision: connection.revision } : { ...body, api_key: secret }, connection); }}>
    <div className="ai-provider-panel-heading"><h3>{modelOnly ? "Model configuration" : "Edit credentials / rotate key"}</h3><Badge>{providerLabel}</Badge></div>
    {initialConnection ? <p className="ai-provider-fixed-brand"><ProviderLogo provider={initialConnection.provider} />Provider: {providerLabel}. A connection's provider cannot be changed.</p> : <div className="ai-provider-picker"><EntityPicker label="Provider" value={provider ?? ""} placeholder="Select a provider" options={definitions.map((d) => ({ value: d.id, kind: "provider", tag: (d.id === "custom" && !customAvailable || d.id === "sagemaker" && !sagemakerAvailable) ? "Setup required" : "", label: d.name, icon: <ProviderLogo provider={d.id} /> }))} onSelect={(option) => { const selected = definitions.find((d) => d.id === option.value); if (selected) switchProvider(selected.id); }} /></div>}
    {definitions.some((d) => d.id === "custom") && !customAvailable && <p>Custom providers require an installation-approved endpoint and secure egress setup.</p>}
    {usesBridge && !connection && <p>Enter upstream model names below. Catalog suggestions become available after creating the connection.</p>}
    <div className="ai-provider-catalog ai-provider-model-dropdown" onKeyDown={(e) => { if (e.key === "Escape" && catalogOpen) { e.stopPropagation(); setCatalogOpen(false); } }}><div className="ai-provider-catalog-search"><Field label="Search model catalog"><Input value={query} maxLength={100} onChange={(e) => { setQuery(e.target.value); searchSerial.current++; setSearching(false); setCatalog(null); }} placeholder="Search model name" /></Field><Button type="button" disabled={searching || !definition || usesBridge && !connection} onClick={() => void search()}>{searching ? "Searching…" : "Search models"}</Button></div>{catalogError && <p role="alert">{catalogError}</p>}{catalogOpen && catalog && <div className="ai-provider-model-options" role="region" aria-label="Model suggestions"><p>{catalog.total} matching models · showing {catalog.items.length ? catalog.offset + 1 : 0}–{catalog.offset + catalog.items.length}</p><div className="ai-provider-catalog-items">{catalog.items.map((m) => <label key={m.id}><input type="checkbox" checked={chosen.includes(m.id)} disabled={!chosen.includes(m.id) && chosen.length >= 32} onChange={(e) => setModels((e.target.checked ? [...chosen, m.id] : chosen.filter((id) => id !== m.id)).join("\n"))} /><span>{m.name}<small>{m.id}</small></span></label>)}</div><div className="ai-provider-form-actions"><Button type="button" disabled={searching || catalog.offset === 0} onClick={() => void search(Math.max(0, catalog.offset - catalog.limit))}>Previous models</Button><Button type="button" disabled={searching || catalog.offset + catalog.limit >= catalog.total || catalog.offset + catalog.limit > 10000} onClick={() => void search(catalog.offset + catalog.limit)}>Next models</Button><Button type="button" onClick={() => setCatalogOpen(false)}>Done selecting models</Button></div></div>}</div>
    <div className="ai-provider-selected-models" aria-label="Selected models">{chosen.map((model) => <span key={model}><code>{model}</code><button type="button" aria-label={`Remove model ${model}`} onClick={() => setModels(chosen.filter((m) => m !== model).join("\n"))}>×</button></span>)}</div>
    <div className="ai-provider-manual-model"><Field label="Exact model name"><Input value={manualModel} maxLength={255} disabled={!provider} onChange={(e) => setManualModel(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (validModel(manualModel.trim()) && !chosen.includes(manualModel.trim()) && finalModels.length < 32) { setModels([...chosen, manualModel.trim()].join("\n")); setManualModel(""); } } }} placeholder={definition?.model_placeholder ?? "Select a provider first"} /></Field><Button type="button" disabled={!provider || !validModel(manualModel.trim()) || chosen.includes(manualModel.trim()) || finalModels.length >= 32} onClick={() => { setModels([...chosen, manualModel.trim()].join("\n")); setManualModel(""); }}>Add exact model</Button></div><p className="ai-provider-model-help">{finalModels.length}/32 models · Chat completions. {provider === "sagemaker" ? "Use exact model aliases configured on the bridge; no wildcards." : "Exact API names only; no aliases or wildcards."}</p>

    <div className="ai-provider-mappings"><span>Model mappings</span><div className="ai-provider-table-scroll"><table><caption className="sr-only">Model mapping preview</caption><thead><tr><th>Gateway model name</th><th>Upstream model name</th></tr></thead><tbody>{chosen.map((model) => {
      const prefix = connection ? `custom-${connection.id}/` : "";
      const upstream = usesBridge ? (prefix && model.startsWith(prefix) ? model.slice(prefix.length) : model) : model.slice((provider?.length ?? 0) + 1);
      const gateway = usesBridge ? (connection ? `${prefix}${upstream}` : "Assigned when saved") : model;
      return <tr key={model}><td>{gateway}</td><td>{upstream}</td></tr>;
    })}</tbody></table>{!chosen.length && <p className="ai-provider-mapping-empty">Select models to preview their names.</p>}{usesBridge && !connection && <p>Gateway model names are assigned when these credentials are saved.</p>}</div></div>
    <Field label="Mode"><Input readOnly value="Chat — /chat/completions" /></Field>

    {modelOnly && <><Field label="Existing Credentials"><select value={existingID} onChange={(e) => { setExistingID(e.target.value); setManualModel(""); setCatalogOpen(false); setSecret(""); if (usesBridge) setModels(""); setCatalog(null); setCatalogError(""); setSearching(false); searchSerial.current++; }}><option value="">None — enter new credentials below</option>{connections.filter((c) => c.provider === provider && (c.status === "applied" && c.applied_revision === c.revision || c.status === "disabled")).map((c) => <option key={c.id} value={c.id}>{c.name} · {c.status}</option>)}</select></Field><p>Choose saved credentials, or enter a new API key below. Pending or failed credentials need their key re-entered in LLM Credentials before reuse.</p>{connection && <p>Using {connection.name}. Its API key stays private and existing models are preserved.</p>}</>}

    {usesBridge && (connection ? <><Field label="Upstream endpoint"><Input readOnly value={connection.endpoint_url ?? ""} /></Field><p>The endpoint cannot be changed for this connection.</p></> : <div className="ai-provider-endpoint-entry">
      <Field label="API base URL"><Input type="url" value={endpoint} maxLength={2048} onChange={(e) => { setEndpoint(e.target.value); setSecret(""); }} placeholder="https://inference.example.com/v1" autoComplete="off" spellCheck={false} /></Field>
      <p>{provider === "sagemaker" ? "Enter your private LiteLLM bridge URL. AWS region, endpoint and IAM settings stay on that bridge; use its scoped gateway key." : "Enter an OpenAI-compatible API base URL. A trailing /v1 is optional."}</p>
      {!!approvedEndpoints.length && <Field label="Approved upstream endpoint"><select value={endpointApproved ? selectedEndpoint : ""} onChange={(e) => { setEndpoint(e.target.value); setSecret(""); }}><option value="">Or choose an approved endpoint</option>{approvedEndpoints.map((e) => <option key={e.url} value={e.url}>{e.name} · {e.url}</option>)}</select></Field>}
      {!bridgeAvailable ? <p role="alert">Installation setup required: approve this endpoint and configure secure egress before testing.</p> : endpoint.trim() && !enteredBase ? <p role="alert">Enter an HTTP or HTTPS base URL without embedded credentials, query parameters or a fragment.</p> : endpoint.trim() && !endpointApproved ? <p role="alert">This endpoint is not approved for this provider. Ask your installation administrator to add its URL and network allowlist before testing.</p> : endpointApproved ? <p>Test request: <code>{selectedEndpoint.replace(/\/+$/, "")}/v1/chat/completions</code></p> : null}
    </div>)}
    {provider && !usesBridge && <><Field label="API base URL"><Input readOnly value={nativeAPIBase[provider] ?? ""} placeholder="Standard provider endpoint" /></Field><p>{providerLabel} uses this standard API endpoint. For a different OpenAI-compatible API URL, choose Custom provider.</p></>}

    {!(modelOnly && connection) && <><div className="ai-provider-form-grid"><Field label="Credential name (optional)"><Input value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={savedName || "Generated from provider and model"} /></Field><Field label={connection ? "Replacement API key (optional)" : provider === "sagemaker" ? "Gateway API key" : "API key"}><Input type="password" autoComplete="new-password" spellCheck={false} value={secret} maxLength={4096} onChange={(e) => setSecret(e.target.value)} placeholder={connection ? "Leave blank to keep the current key" : provider === "sagemaker" ? "Enter your scoped gateway key" : "Enter your provider key"} /></Field></div>
    <p>Keys are stored securely and never shown again. If a key update fails, enter the key again and save.</p></>}

    {!(modelOnly && connection) && <><label className="ai-provider-enabled"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enable this connection for authorized team policies</label><p>Organization AI access remains a separate default-off setting.</p></>}
    {needsTest && <div className="ai-provider-preflight"><p>A small inference request tests the first selected model only; charges may apply and are excluded from gateway usage totals. Success does not certify the other selected models. Results expire after five minutes.</p>{!testAvailable && <p>Test Connect requires installation setup of the private LiteLLM bridge.</p>}{testStatus === "success" && <p role="status">Test succeeded for {chosen[0]}. You can now save this model configuration.</p>}{testStatus === "error" && <p role="alert">Connection test failed. Check the model, endpoint and credentials, then retry.</p>}</div>}
  </form></div>
  );
  return modelOnly ? <section className="ai-provider-inline" role="tabpanel" aria-label="Add Model"><h3>Add Model</h3><div className="ai-provider-inline-card">{editor}<div className="ai-provider-inline-actions">{actions}</div></div></section> : <Modal title="Edit credentials" placement="right" size="wide" showClose onDismiss={onCancel} actions={actions}>{editor}</Modal>;
}
