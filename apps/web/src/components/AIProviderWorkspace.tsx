import { useEffect, useId, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Badge, Button, Field, Input, Modal } from "./ui";
import "./ai-provider-workspace.css";
import { EntityPicker } from "./EntityPicker";
import { ProviderLogo } from "./ProviderLogo";
import { toast } from "./Toasts";
import { parseFoundryEndpoint } from "../lib/aiFoundryEndpoint";
import { aiProbeFailure } from "../lib/aiProbeFailure";
import { AIModelConnectionDetails } from "./AIModelConnectionDetails";
type S = components["schemas"];
export type AIProviderConnection = S["AIProviderConnection"];
type Definition = S["AIProviderDefinition"];
type ModelMode = S["AIModelMode"];
const modelModes: { value: ModelMode; label: string }[] = [
  { value: "chat", label: "Chat — /chat/completions" },
  { value: "completion", label: "Completion — /completions" },
  { value: "embedding", label: "Embedding — /embeddings" },
  { value: "audio_speech", label: "Audio speech — /audio/speech" },
  { value: "audio_transcription", label: "Audio transcription — /audio/transcriptions" },
  { value: "image_generation", label: "Image generation — /images/generations" },
  { value: "video_generation", label: "Video generation — /videos" },
  { value: "rerank", label: "Rerank — /rerank" },
];
const modeLabel = (mode: ModelMode) => modelModes.find((item) => item.value === mode)?.label ?? mode;
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
type WorkspaceView = "connections" | "models" | "add";
type WorkspaceProps = {
  orgId: string; canManage?: boolean; view?: WorkspaceView;
  onViewChange?: (view: WorkspaceView) => void;
  onGrantAccess?: (connection: string, model: string) => void;
};
export function AIProviderWorkspace(props: WorkspaceProps) {
  return <ProviderWorkspace key={props.orgId} {...props} />;
}
function ProviderWorkspace({ orgId, canManage = true, view: routeView, onViewChange, onGrantAccess }: WorkspaceProps) {
  const [inventory, setInventory] = useState<S["AIProviderList"] | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [editing, setEditing] = useState<AIProviderConnection | "new" | null>(null);
  const [localView, setLocalView] = useState<WorkspaceView>("models");
  const view = routeView ?? localView;
  const setView = (next: WorkspaceView) => { setLocalView(next); onViewChange?.(next); };
  useEffect(() => { setEditing(null); setRemoving(null); }, [routeView]);
  const [connectionModel, setConnectionModel] = useState<string | null>(null);
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
    if (busy || !canManage) return false;
    setBusy(true); setError(""); setNotice("");
    let ok = false;
    try {
      const r = await call();
      if (!alive.current) return false;
      if (r.error) {
        setError(r.response.status === 409 ? "This connection changed or is referenced by a team policy or user group grant. Refresh and update those grants before removing models, changing their mode or deleting the connection." : "The operation could not be completed. Check the connection state; an uncertain key update requires entering the API key again.");
      } else { setNotice(success); ok = true; }
      await reload();
    } catch { if (alive.current) { setError("Could not reach the API. Refresh to check saved state. Enter the API key again if an update did not finish."); await reload(); } }
    finally { if (alive.current) setBusy(false); }
    return ok;
  }
  async function save(body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) {
    // Close before awaiting: no submitted secret remains in a form or its state.
    setEditing(null); setView(view === "connections" ? "connections" : "models");
    let saved: AIProviderConnection | undefined;
    const ok = await mutate(async () => {
      const result = connection
        ? await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: connection.id } }, body: body as S["AIProviderUpdate"] })
        : await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } }, body: body as S["AIProviderCreate"] });
      saved = result.data;
      return result;
    }, "Model and credentials saved. Review synchronization state before assigning access.");
    if (ok && saved?.models.length) setConnectionModel(saved.models[0]);
  }
  function changeView(next: typeof view) { setView(next); setEditing(null); setRemoving(null); }
  const definitions = inventory?.definitions ?? [];
  const providerName = (id: string) => definitions.find((d) => d.id === id)?.name ?? id;
  const modelRows = (inventory?.items ?? []).flatMap((connection) => connection.models.map((model) => ({ connection, model }))).filter(({ connection, model }) => (!modelProvider || connection.provider === modelProvider) && `${model} ${connection.name}`.toLowerCase().includes(modelSearch.toLowerCase()));
  return <section className="ai-provider-workspace" aria-label="Models and endpoints">
    <header className="ai-provider-heading"><div><h2>{view === "connections" ? "LLM credentials" : view === "add" ? "Add Model" : "Models & endpoints"}</h2><p>{view === "connections" ? "Manage reusable provider keys and endpoints." : "Add a model with your provider credentials, then grant your groups access."}</p></div>{routeView && view === "models" && canManage && <Button disabled={loading || busy || !inventory?.management_available || !definitions.length} onClick={() => changeView("add")}>Add Model</Button>}</header>
    {error && <p role="alert" className="ai-provider-alert">{error}</p>}
    {notice && <p role="status" className="ai-provider-notice">{notice}</p>}
    {connectionModel && <Modal title="Model connection details" onDismiss={() => setConnectionModel(null)} showClose actions={<Button onClick={() => setConnectionModel(null)}>Close</Button>}><Field label="Model ID"><select value={connectionModel} onChange={event => setConnectionModel(event.target.value)}>{[...new Set([connectionModel, ...(inventory?.items ?? []).flatMap(c => c.models)])].map(model => <option key={model} value={model}>{model}</option>)}</select></Field><AIModelConnectionDetails key={connectionModel} orgId={orgId} model={connectionModel} mode={inventory?.items.find(c => c.models.includes(connectionModel))?.model_modes?.[connectionModel] ?? "chat"} /></Modal>}
    {loading && !inventory ? <p role="status">Loading provider connections…</p> : !inventory ? <Button onClick={() => { setError(""); void reload(); }}>Retry provider connections</Button> : <>
      {inventory.management_available && !definitions.length && <p className="ai-provider-notice">This API does not expose supported provider definitions. Existing connections remain editable; update the control plane before adding providers.</p>}
      {!inventory.management_available && <div className="ai-provider-panel"><h3>Provider management requires installation setup</h3><p>Your installation administrator must enable database-owned provider configuration before adding or changing connections here. Existing operator-managed policy references remain available under AI Agents → Model access.</p></div>}
      {!routeView && <div className="ai-provider-view-tabs" role="tablist" aria-label="Model management view"><button role="tab" aria-selected={view === "models"} onClick={() => changeView("models")}>All Models <span>{inventory.items.reduce((n, c) => n + c.models.length, 0)}</span></button><button role="tab" aria-selected={view === "add"} disabled={loading || busy || !canManage || !inventory.management_available || !definitions.length} onClick={() => changeView("add")}>Add Model</button><button role="tab" aria-selected={view === "connections"} onClick={() => changeView("connections")}>LLM Credentials <span>{inventory.items.length}</span></button></div>}
      {view === "models" && <div className="ai-provider-panel ai-provider-model-table"><div className="ai-provider-panel-heading"><div><h3>All Models</h3><p>Models available through your gateway. Credentials can be reused across models from the same provider.</p></div></div><div className="ai-provider-model-filters"><Field label="Search configured models"><Input value={modelSearch} onChange={(e) => setModelSearch(e.target.value)} placeholder="Model ID or credential name" /></Field><Field label="Filter models by provider"><select value={modelProvider} onChange={(e) => setModelProvider(e.target.value)}><option value="">All providers</option>{[...new Set(inventory.items.map((c) => c.provider))].map((id) => <option key={id} value={id}>{providerName(id)}</option>)}</select></Field></div><div className="ai-provider-table-scroll"><table><caption className="sr-only">Configured models</caption><thead><tr><th>API model ID</th><th>Provider</th><th>Mode</th><th>Credential</th><th>State</th><th>Actions</th></tr></thead><tbody>{modelRows.map(({ connection: c, model }) => <tr key={`${c.id}:${model}`}><th scope="row"><code>{model}</code></th><td><span className="ai-provider-table-brand"><ProviderLogo provider={c.provider} />{providerName(c.provider)}</span></td><td>{modeLabel(c.model_modes?.[model] ?? "chat")}</td><td>{c.name}</td><td><Badge tone={c.status === "error" ? "danger" : c.status === "pending" ? "warn" : "neutral"}>{c.status}</Badge></td><td><div className="ai-provider-row-actions"><Button onClick={() => setConnectionModel(model)} aria-label={`Connection details for ${model}`}>Use model</Button>{onGrantAccess && <Button size="sm" disabled={busy || !canManage || !c.enabled || c.status !== "applied" || c.revision !== c.applied_revision} onClick={() => onGrantAccess(c.id, model)} aria-label={`Grant access to ${model} on ${c.name}`}>Grant access</Button>}<Button disabled={busy || !canManage || !inventory.management_available} onClick={() => setEditing(c)} aria-label={`Edit ${model} on ${c.name}`}>Edit</Button><Button disabled={busy || !canManage || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Catalog/connection check completed. Public catalogs may not validate API keys. Success does not prove model inference access.")} aria-label={`Check catalog for ${model} on ${c.name}`}>Check catalog</Button></div></td></tr>)}</tbody></table></div>{!modelRows.length && <p className="ai-provider-empty">No configured models match this view. Add a model or adjust your filters.</p>}</div>}
      {view === "connections" && <div className="ai-provider-panel ai-provider-table-scroll"><div className="ai-provider-panel-heading"><div><h3>LLM Credentials</h3><p>Saved provider keys and endpoints. Editing or disabling credentials affects every model using them.</p></div><div className="ai-provider-credential-actions"><span>{inventory.items.length} credentials</span><Button disabled={loading || busy || !canManage || !inventory.management_available || !definitions.length} onClick={() => { setEditing("new"); setRemoving(null); }}>Add Credentials</Button></div></div>
        {!inventory.items.length ? <div className="ai-provider-empty"><h3>No saved credentials yet</h3><p>Use Add Credentials to save a provider key with its model scope, or add a model and credentials together in Add Model.</p></div> : <table><caption className="sr-only">Saved LLM credentials</caption><thead><tr><th>Credential</th><th>Models</th><th>State</th><th>Catalog check</th><th>Actions</th></tr></thead><tbody>{inventory.items.map((c) => <tr key={c.id}><th scope="row"><strong>{c.name}</strong><small className="ai-provider-table-brand"><ProviderLogo provider={c.provider} />{providerName(c.provider)}</small><code>{c.key_id}</code></th><td><details><summary>{c.models.length} models</summary><ul>{c.models.map((m) => <li key={m}>{m}</li>)}</ul></details></td><td><Badge tone={c.status === "error" ? "danger" : c.status === "pending" ? "warn" : "neutral"}>{c.status}</Badge><small>Desired {c.revision} · applied {c.applied_revision}</small><small>{c.enabled ? "Access enabled" : "Access disabled"}</small></td><td><Badge tone={c.last_test_status === "failed" ? "danger" : "neutral"}>{c.last_test_status}</Badge><small>{c.last_test_at ? new Date(c.last_test_at).toLocaleString() : "No catalog check recorded"}</small></td><td><div className="ai-provider-row-actions"><Button disabled={busy || !canManage || !inventory.management_available} onClick={() => { setEditing(c); setRemoving(null); }}>Edit {c.name}</Button><Button disabled={busy || !canManage || !inventory.management_available} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Catalog/connection check completed. Public catalogs may not validate API keys. Success does not prove model inference access.")}>Check catalog {c.name}</Button><Button disabled={busy || !canManage || !inventory.management_available} onClick={() => void mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { provider: c.provider, ...(c.endpoint_url ? { endpoint_url: c.endpoint_url } : {}), name: c.name, models: c.models, enabled: !c.enabled, expected_revision: c.revision } }), "Credential state updated. Disabling blocks new requests for every model using these credentials; accepted streams may finish within 30 seconds.")}>{c.enabled ? "Disable" : "Enable"} {c.name}</Button><Button disabled={busy || !canManage || !inventory.management_available} onClick={() => { setRemoving(c); setEditing(null); }}>Delete {c.name}</Button></div></td></tr>)}</tbody></table>}
      </div>}
      {view !== "add" && inventory.legacy_key_ids.length > 0 && <div className="ai-provider-panel"><h3>Existing operator-managed references</h3><p>These references belong to this organization. Their credentials and model scope remain managed by the installation administrator.</p><div className="ai-provider-tags">{inventory.legacy_key_ids.map((id) => <code key={id}>{id}</code>)}</div></div>}
      {view !== "add" && <p className="ai-provider-footnote">Catalog/connection checks generate no model tokens. Public catalogs may not validate API keys. Success does not prove model inference access.</p>}
      {removing && <div className="ai-provider-panel" role="region" aria-label="Delete provider connection"><h3>Delete {removing.name}?</h3><p>Remove this connection from every team policy first. The server refuses deletion while references remain. Usage history is preserved. These credentials and all their configured models are removed.</p><div className="ai-provider-form-actions"><Button disabled={busy} onClick={() => setRemoving(null)}>Cancel deletion</Button><Button disabled={busy} onClick={async () => { const c = removing; if (await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Provider connection deleted. Usage history is retained.")) setRemoving(null); }}>Confirm deletion</Button></div></div>}
      {(editing || view === "add") && <ProviderEditor key={editing === "new" ? "new-credentials" : editing ? `${editing.id}:${editing.revision}` : "new-model"} orgId={orgId} connection={editing === "new" ? undefined : editing ?? undefined} definitions={definitions} supportedModes={inventory.supported_modes ?? ["chat"]} testAvailable={inventory.test_available ?? false} publicEndpointsAvailable={inventory.public_endpoints_available ?? false} foundryAvailable={inventory.foundry_available ?? false} foundryEndpoints={inventory.foundry_endpoints ?? []} sagemakerAvailable={inventory.sagemaker_available ?? false} sagemakerEndpoints={inventory.sagemaker_endpoints ?? []} customAvailable={inventory.custom_available ?? false} endpoints={inventory.custom_endpoints ?? []} connections={inventory.items} modelOnly={!editing} showInlineTitle={!routeView} busy={busy} onCancel={() => editing ? setEditing(null) : changeView("models")} onSave={save} />}
      {view !== "add" && <Button disabled={loading || busy} onClick={() => { setError(""); void reload(); }}>Refresh models and credentials</Button>}
    </>}
  </section>;
}
function ProviderEditor({ orgId, connection: initialConnection, definitions, supportedModes, testAvailable, publicEndpointsAvailable, foundryAvailable, foundryEndpoints, sagemakerAvailable, sagemakerEndpoints, customAvailable, endpoints, connections, modelOnly, showInlineTitle, busy, onSave, onCancel }: { orgId: string; connection?: AIProviderConnection; definitions: Definition[]; supportedModes: ModelMode[]; testAvailable: boolean; publicEndpointsAvailable: boolean; foundryAvailable: boolean; foundryEndpoints: NonNullable<S["AIProviderList"]["foundry_endpoints"]>; sagemakerAvailable: boolean; sagemakerEndpoints: NonNullable<S["AIProviderList"]["sagemaker_endpoints"]>; customAvailable: boolean; endpoints: NonNullable<S["AIProviderList"]["custom_endpoints"]>; connections: AIProviderConnection[]; modelOnly: boolean; showInlineTitle: boolean; busy: boolean; onSave: (body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) => Promise<void>; onCancel: () => void }) {
  const [provider, setProvider] = useState<AIProviderConnection["provider"] | undefined>(initialConnection?.provider);
  const [endpoint, setEndpoint] = useState(initialConnection?.endpoint_url ?? "");
  const [existingID, setExistingID] = useState("");
  const connection = initialConnection ?? (modelOnly ? connections.find((c) => c.id === existingID && c.provider === provider) : undefined);
  const usesEndpoint = provider === "custom" || provider === "sagemaker" || provider === "azure_foundry";
  const approvedEndpoints = provider === "azure_foundry" ? foundryEndpoints : provider === "sagemaker" ? sagemakerEndpoints : endpoints;
  const publicEndpointProvider = publicEndpointsAvailable && (provider === "custom" || provider === "azure_foundry");
  const endpointAvailable = publicEndpointProvider || (provider === "azure_foundry" ? foundryAvailable : provider === "sagemaker" ? sagemakerAvailable : customAvailable);
  const definition = definitions.find((d) => d.id === provider);
  const providerLabel = definition?.name ?? initialConnection?.provider ?? "Select a provider";
  const formId = useId();
  const [name, setName] = useState(connection?.name ?? ""), [secret, setSecret] = useState(""), [models, setModels] = useState(connection?.models.join("\n") ?? ""), [enabled, setEnabled] = useState(connection?.enabled ?? true);
  const [mode, setMode] = useState<ModelMode>(initialConnection?.model_modes?.[initialConnection.models[0]] ?? "chat");
  const [selectedModes, setSelectedModes] = useState<Record<string, ModelMode>>(initialConnection?.model_modes ?? {});
  const [manualModel, setManualModel] = useState("");
  const [catalogOpen, setCatalogOpen] = useState(false), [catalogDismissed, setCatalogDismissed] = useState(false);
  const [query, setQuery] = useState(""), [catalog, setCatalog] = useState<S["AIProviderModelList"] | null>(null), [catalogError, setCatalogError] = useState(""), [searching, setSearching] = useState(false);
  const active = useRef(true), searchSerial = useRef(0);
  useEffect(() => { active.current = true; return () => { active.current = false; searchSerial.current++; }; }, []);
  async function search(offset = 0) {
    if (!provider || !canSearch) return;
    const n = ++searchSerial.current;
    setSearching(true); setCatalogError(""); setCatalogOpen(true);
    try {
      const r = draftCatalog
        ? await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/model-catalog", { params: { path: { orgId } }, body: { provider, api_key: secret, endpoint_url: selectedEndpoint, query: query.trim(), mode, limit: 50, offset } })
        : await api.GET("/api/v1/organizations/{orgId}/ai-gateway/models", { params: { path: { orgId }, query: { provider, ...(usesEndpoint && connection ? { connection_id: connection.id } : {}), query: query.trim(), mode, limit: 50, offset } } });
      if (!active.current || n !== searchSerial.current) return;
      if (r.error || !r.data) throw Error();
      setCatalog(r.data);
    } catch { if (active.current && n === searchSerial.current) { setCatalog(null); setCatalogError("Model suggestions are unavailable. Enter the exact model or Azure deployment name manually below."); } }
    finally { if (active.current && n === searchSerial.current) setSearching(false); }
  }
  function switchProvider(next: AIProviderConnection["provider"]) {
    if (next === provider) return;
    setProvider(next); setSelectedModes({}); setManualModel(""); setCatalogOpen(false); setCatalogDismissed(false); setEndpoint(""); setSecret(""); setModels(""); setExistingID(""); setQuery(""); setCatalog(null); setCatalogError(""); setSearching(false); searchSerial.current++;
  }
  function selectCredentials(id: string) {
    const saved = connections.find((c) => c.id === id);
    if (saved) {
      if (saved.provider !== provider) { setModels(""); setSelectedModes({}); setMode("chat"); setQuery(""); }
      setProvider(saved.provider);
    }
    setExistingID(id); setSecret(""); setEndpoint(""); setName(""); setManualModel("");
    if (usesEndpoint || saved?.endpoint_url) setModels("");
    setCatalogOpen(false); setCatalogDismissed(false); setCatalog(null); setCatalogError(""); setSearching(false); searchSerial.current++;
  }
  const chosen = uniqueLines(models);
  const canonicalModel = (model: string) => usesEndpoint && connection && !model.startsWith(`custom-${connection.id}/`) ? `custom-${connection.id}/${model}` : model;
  const finalModels = modelOnly && connection ? [...connection.models, ...chosen.filter((model) => !connection.models.some((saved) => canonicalModel(saved) === canonicalModel(model)))] : chosen;
  const modelMode = (model: string): ModelMode => {
    const retained = modelOnly && connection?.models.find((saved) => canonicalModel(saved) === canonicalModel(model));
    return retained && connection ? connection.model_modes?.[retained] ?? "chat" : selectedModes[model] ?? (initialConnection?.models.includes(model) ? "chat" : mode);
  };
  function changeMode(next: ModelMode) {
    setMode(next); setCatalogDismissed(false); searchSerial.current++; setCatalog(null); setCatalogOpen(false); setSearching(false);
    if (!initialConnection) setSelectedModes(Object.fromEntries(chosen.map((model) => [model, next])));
  }
  function addModel(model: string) {
    if (!validModel(model) || chosen.includes(model) || finalModels.length >= 32) return;
    setModels([...chosen, model].join("\n")); setSelectedModes((current) => ({ ...current, [model]: mode }));
  }
  const validModel = (model: string) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$/.test(model)) return false;
    if (!usesEndpoint) return model.startsWith(`${provider}/`) && model.length > (provider?.length ?? 0) + 1;
    if (/^custom-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\//.test(model)) return !!connection && model.startsWith(`custom-${connection.id}/`) && model.length > connection.id.length + 8;
    return true;
  };
  const foundryInput = provider === "azure_foundry" ? parseFoundryEndpoint(endpoint) : null;
  const enteredBase = provider === "azure_foundry" ? foundryInput?.base ?? "" : endpointBase(endpoint);
  const selectedEndpoint = connection?.endpoint_url ?? (approvedEndpoints.find((e) => endpointBase(e.url) === enteredBase)?.url ?? enteredBase);
  const foundryFormatValid = provider !== "azure_foundry" || /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)\/(?:openai|anthropic)$/.test(selectedEndpoint);
  const anthropicEndpoint = provider === "azure_foundry" && selectedEndpoint.endsWith("/anthropic");
  const registeredEndpoint = [...endpoints, ...foundryEndpoints, ...sagemakerEndpoints].some((e) => endpointBase(e.url) === selectedEndpoint);
  const publicHTTPS = (() => { try { const u = new URL(selectedEndpoint); return u.protocol === "https:" && !u.port; } catch { return false; } })();
  const endpointApproved = !!selectedEndpoint && (approvedEndpoints.some((e) => e.url === selectedEndpoint) || publicEndpointProvider && publicHTTPS && !registeredEndpoint);
  const endpointReady = endpointAvailable && endpointApproved && foundryFormatValid;
  const secretValid = secret.length > 0 && secret.length <= 4096 && !/\s/.test(secret);
  const draftCatalog = (provider === "custom" || provider === "sagemaker") && !connection;
  const canSearch = !!definition && supportedModes.includes(mode) && (!draftCatalog || endpointReady && secretValid);
  const searchEndpoint = draftCatalog ? selectedEndpoint : "";
  const searchSecret = draftCatalog ? secret : "";
  const searchConnection = usesEndpoint && connection ? connection.id : "";
  useEffect(() => { searchSerial.current++; setCatalog(null); setCatalogError(""); setCatalogOpen(false); setSearching(false); }, [provider, mode, searchEndpoint, searchSecret, searchConnection]);
  useEffect(() => {
    if (!canSearch || catalogDismissed) return;
    const timer = window.setTimeout(() => { void search(0); }, 500);
    return () => window.clearTimeout(timer);
  }, [provider, query, mode, canSearch, searchEndpoint, searchSecret, searchConnection, catalogDismissed]);
  const savedName = name.trim() || connection?.name || (provider && chosen.length ? `${providerLabel} · ${chosen[0]}`.slice(0, 80) : "");
  const validationIssues: string[] = [];
  if (!provider || !connection && !definition) validationIssues.push("Select a provider from the dropdown.");
  if (usesEndpoint && !endpointReady) {
    if (!endpointAvailable) validationIssues.push("Configure secure provider egress before testing this endpoint.");
    else if (!selectedEndpoint) validationIssues.push("Enter a valid Upstream API Base.");
    else if (!foundryFormatValid) validationIssues.push("Use an Azure HTTPS URL ending /openai/v1 or /anthropic/v1/messages.");
    else validationIssues.push("Configure network access for this endpoint, or use an available public HTTPS endpoint.");
  }
  if (provider === "azure_foundry" && !connection && foundryInput) {
    if (foundryInput.deployment && chosen[0] !== foundryInput.deployment) validationIssues.push(`The pasted URL targets deployment ${foundryInput.deployment}. Select it as the first model, or enter the resource base URL for your selected models.`);
    if (chosen.length && foundryInput.mode && modelMode(chosen[0]) !== foundryInput.mode) validationIssues.push(`The pasted URL uses ${modeLabel(foundryInput.mode)}. Match the Mode selection, or enter the resource base URL.`);
  }
  if (anthropicEndpoint && (mode !== "chat" || chosen.some((model) => modelMode(model) !== "chat"))) validationIssues.push("The Anthropic Messages endpoint supports Chat mode. Choose Chat to test this deployment.");
  if ((provider === "custom" || provider === "sagemaker") && parseFoundryEndpoint(endpoint)?.base.endsWith("/anthropic")) validationIssues.push("Choose Azure AI Foundry for this Anthropic Messages endpoint.");
  if (name.trim().length > 80) validationIssues.push("Use at most 80 characters for the credential name.");
  if (!chosen.length) validationIssues.push(manualModel.trim()
    ? validModel(manualModel.trim()) ? "Click Add exact model to include the entered model." : "Enter a valid exact model name matching the selected provider, then click Add exact model."
    : "Select a model from the catalog, or enter its exact name and click Add exact model.");
  if (finalModels.length > 32) validationIssues.push("Select at most 32 models, including models already using these credentials.");
  if (chosen.some((model) => !validModel(model))) validationIssues.push("Remove model names that do not match the selected provider.");
  if ((!connection || secret) && !secretValid) validationIssues.push(!secret
    ? "Enter the API key. If you changed the endpoint, enter the key again."
    : /\s/.test(secret) ? "The API key contains whitespace. Remove spaces or line breaks." : "Use an API key of at most 4096 characters.");
  const valid = validationIssues.length === 0;
  const [testing, setTesting] = useState(false), [testStatus, setTestStatus] = useState<"idle" | "success" | "error">("idle");
  const [testFailure, setTestFailure] = useState(() => aiProbeFailure(200));
  const [testedAt, setTestedAt] = useState(0);
  const testGeneration = useRef(0);
  useEffect(() => { testGeneration.current++; setTestStatus("idle"); setTestedAt(0); setTesting(false); return () => { testGeneration.current++; }; }, [provider, secret, selectedEndpoint, models, existingID, mode, selectedModes, connection?.revision, connection?.applied_revision, connection?.enabled, connection?.status]);
  useEffect(() => { if (!testedAt) return; const timer = window.setTimeout(() => { setTestStatus("idle"); setTestedAt(0); }, Math.max(0, testedAt + 300000 - Date.now())); return () => window.clearTimeout(timer); }, [testedAt]);
  const probeMode = chosen.length ? modelMode(chosen[0]) : mode;
  const needsTest = modelOnly || !connection || !!secret;
  const testBlockers = [...validationIssues,
    ...(!testAvailable ? ["Test Connect requires installation setup of the private LiteLLM bridge."] : []),
    ...(!supportedModes.includes(probeMode) ? ["This installation does not support the selected model mode."] : []),
    ...(connection && !secret && (!connection.enabled || connection.status !== "applied" || connection.revision !== connection.applied_revision) ? ["Enable these credentials and wait for them to finish applying before testing."] : [])];
  const testHelpId = `${formId}-test-help`;
  const canSave = valid && (!needsTest || supportedModes.includes(probeMode)) && (!needsTest || testStatus === "success" && Date.now() - testedAt < 300000);
  async function testConnection() {
    if (!provider || testBlockers.length > 0 || testing) return;
    const generation = ++testGeneration.current;
    setTesting(true); setTestStatus("idle"); setTestedAt(0);
    const model = usesEndpoint && connection ? chosen[0].replace(`custom-${connection.id}/`, "") : chosen[0];
    try {
      const r = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/test-connection", { params: { path: { orgId } }, body: { provider, model, mode: probeMode, ...(connection && !secret ? { connection_id: connection.id, expected_revision: connection.revision } : { api_key: secret, ...(usesEndpoint ? { endpoint_url: selectedEndpoint } : {}) }) } });
      if (!active.current || generation !== testGeneration.current) return;
      const success = !r.error && r.response?.status === 200 && r.data?.status === "success";
      setTestStatus(success ? "success" : "error");
      if (success) { setTestedAt(Date.now()); toast.success("Test connection successful · HTTP 200", { description: `${chosen[0]} · ${modeLabel(probeMode)}` }); }
      else { const notice = aiProbeFailure(r.response?.status, r.data?.failure); setTestFailure(notice); toast.error(notice.title, { description: notice.description }); }
    } catch { if (active.current && generation === testGeneration.current) { setTestStatus("error"); const notice = aiProbeFailure(); setTestFailure(notice); toast.error(notice.title, { description: notice.description }); } }
    finally { if (active.current && generation === testGeneration.current) setTesting(false); }
  }
  const actions = <><Button variant="ghost" type="button" disabled={busy} onClick={onCancel}>Cancel</Button>{needsTest && <Button type="button" disabled={busy || testing || testBlockers.length > 0} aria-describedby={testBlockers.length ? testHelpId : undefined} onClick={() => void testConnection()}>{testing ? "Testing connection…" : "Test Connect"}</Button>}<Button form={formId} type="submit" disabled={busy || !canSave}>{modelOnly ? "Add Model" : connection ? "Save credentials" : "Create credentials"}</Button></>;
  const editor = (
    <div className="ai-provider-workspace"><form id={formId} className="ai-provider-editor" aria-label={modelOnly ? "Add model" : connection ? "Edit credentials" : "Add credentials"} onSubmit={(event) => { event.preventDefault(); if (!canSave || busy || !provider) return; const body = { provider, ...(usesEndpoint ? { endpoint_url: selectedEndpoint } : {}), name: modelOnly && connection ? connection.name : savedName, models: finalModels, model_modes: Object.fromEntries(finalModels.map((model) => [model, modelMode(model)])), enabled: modelOnly && connection ? connection.enabled : enabled, ...(secret ? { api_key: secret } : {}) }; setSecret(""); void onSave(connection ? { ...body, expected_revision: connection.revision } : { ...body, api_key: secret }, connection); }}>
    <div className="ai-provider-panel-heading"><h3>{modelOnly ? "Model configuration" : connection ? "Edit credentials / rotate key" : "New credentials"}</h3><Badge>{providerLabel}</Badge></div>
    {!modelOnly && !connection && <p>Credentials are scoped to models. Select at least one model before testing and creating credentials.</p>}
    {initialConnection ? <p className="ai-provider-fixed-brand"><ProviderLogo provider={initialConnection.provider} />Provider: {providerLabel}. A connection's provider cannot be changed.</p> : <div className="ai-provider-picker"><EntityPicker label="Provider" value={provider ?? ""} placeholder="Select a provider" options={definitions.map((d) => ({ value: d.id, kind: "provider", tag: (d.id === "custom" && !customAvailable && !publicEndpointsAvailable || d.id === "sagemaker" && !sagemakerAvailable || d.id === "azure_foundry" && !foundryAvailable && !publicEndpointsAvailable) ? "Setup required" : "", label: d.name, icon: <ProviderLogo provider={d.id} /> }))} onSelect={(option) => { const selected = definitions.find((d) => d.id === option.value); if (selected) switchProvider(selected.id); }} /></div>}
    {definitions.some((d) => d.id === "custom") && !customAvailable && !publicEndpointsAvailable && <p>Custom providers require an installation-approved endpoint and secure egress setup.</p>}
    {provider === "azure_foundry" && <p>Connect Azure-hosted models, including Claude, Llama, DeepSeek, Phi, Mistral and GPT, using your deployment name and Azure API key. For Claude, paste the Anthropic Messages endpoint from Azure (/anthropic/v1/messages); other models use /openai/v1. The endpoint selects the protocol.</p>}
    {provider === "azure_foundry" && !connection && <p>Search LiteLLM model suggestions. Use your Azure deployment name if it differs; catalog entries do not confirm deployment access.</p>}
    {draftCatalog && <p>Search the upstream catalog with your endpoint and API key, or enter an exact model or deployment name below. Catalog suggestions do not prove model access or Azure deployment names.</p>}
    <div className="ai-provider-catalog ai-provider-model-dropdown" onKeyDown={(e) => { if (e.key === "Escape" && catalogOpen) { e.stopPropagation(); setCatalogOpen(false); setCatalogDismissed(true); } }}><div className="ai-provider-catalog-search"><Field label="Search model catalog"><Input value={query} maxLength={100} onFocus={() => setCatalogDismissed(false)} onChange={(e) => { setQuery(e.target.value); setCatalogDismissed(false); searchSerial.current++; setSearching(false); setCatalog(null); setCatalogError(""); }} placeholder="Search model name" /></Field></div>{searching && <p role="status">Searching models…</p>}{draftCatalog && !canSearch && <p>{!endpointReady ? "Enter a supported endpoint to search models. Public HTTPS endpoints are checked automatically when public egress is available; private endpoints need configured network access." : "Enter the provider API key to search models. No model selection is required."}</p>}{catalogError && <p role="alert">{catalogError}</p>}{catalogOpen && catalog && <div className="ai-provider-model-options" role="region" aria-label="Model suggestions"><p>{catalog.total} matching models · showing {catalog.items.length ? catalog.offset + 1 : 0}–{catalog.offset + catalog.items.length}</p><div className="ai-provider-catalog-items">{catalog.items.map((m) => <label key={m.id}><input type="checkbox" checked={chosen.includes(m.id)} disabled={!chosen.includes(m.id) && chosen.length >= 32} onChange={(e) => e.target.checked ? addModel(m.id) : setModels(chosen.filter((id) => id !== m.id).join("\n"))} /><span>{m.name}<small>{m.id}</small></span></label>)}</div><div className="ai-provider-form-actions"><Button type="button" disabled={searching || catalog.offset === 0} onClick={() => void search(Math.max(0, catalog.offset - catalog.limit))}>Previous models</Button><Button type="button" disabled={searching || catalog.offset + catalog.limit >= catalog.total || catalog.offset + catalog.limit > 10000} onClick={() => void search(catalog.offset + catalog.limit)}>Next models</Button><Button type="button" onClick={() => { setCatalogOpen(false); setCatalogDismissed(true); }}>Done selecting models</Button></div></div>}</div>
    <div className="ai-provider-selected-models" aria-label="Selected models">{chosen.map((model) => <span key={model}><code>{model}</code><button type="button" aria-label={`Remove model ${model}`} onClick={() => setModels(chosen.filter((m) => m !== model).join("\n"))}>×</button></span>)}</div>
    <div className="ai-provider-manual-model"><Field label="Exact model name"><Input value={manualModel} maxLength={255} disabled={!provider} onChange={(e) => setManualModel(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (validModel(manualModel.trim()) && !chosen.includes(manualModel.trim()) && finalModels.length < 32) { addModel(manualModel.trim()); setManualModel(""); } } }} placeholder={definition?.model_placeholder ?? "Select a provider first"} /></Field><Button type="button" disabled={!provider || !validModel(manualModel.trim()) || chosen.includes(manualModel.trim()) || finalModels.length >= 32} onClick={() => { addModel(manualModel.trim()); setManualModel(""); }}>Add exact model</Button></div><p className="ai-provider-model-help">{finalModels.length}/32 models · {modeLabel(mode)}. {provider === "sagemaker" ? "Use exact model aliases configured on the bridge; no wildcards." : "Exact API names only; no aliases or wildcards."}</p>

    <div className="ai-provider-mappings"><span>Model mappings</span><div className="ai-provider-table-scroll"><table><caption className="sr-only">Model mapping preview</caption><thead><tr><th>Gateway model name</th><th>Upstream model name</th>{initialConnection && <th>Mode</th>}</tr></thead><tbody>{chosen.map((model) => {
      const prefix = connection ? `custom-${connection.id}/` : "";
      const upstream = usesEndpoint ? (prefix && model.startsWith(prefix) ? model.slice(prefix.length) : model) : model.slice((provider?.length ?? 0) + 1);
      const gateway = usesEndpoint ? (connection ? `${prefix}${upstream}` : "Assigned when saved") : model;
      return <tr key={model}><td>{gateway}</td><td>{upstream}</td>{initialConnection && <td><select aria-label={`Mode for ${model}`} value={modelMode(model)} onChange={(e) => setSelectedModes((current) => ({ ...current, [model]: e.target.value as ModelMode }))}>{modelModes.map((item) => <option key={item.value} value={item.value} disabled={!supportedModes.includes(item.value)}>{item.label}{!supportedModes.includes(item.value) ? " — unavailable" : ""}</option>)}</select></td>}</tr>;
    })}</tbody></table>{!chosen.length && <p className="ai-provider-mapping-empty">Select models to preview their names.</p>}{usesEndpoint && !connection && <p>Gateway model names are assigned when these credentials are saved.</p>}</div></div>
    <Field label="Mode"><select value={mode} onChange={(e) => changeMode(e.target.value as ModelMode)}>{modelModes.map((item) => <option key={item.value} value={item.value} disabled={!supportedModes.includes(item.value)}>{item.label}{!supportedModes.includes(item.value) ? " — unavailable" : ""}</option>)}</select></Field>
    <p>Select the operation your model supports. Test Connect checks the chosen model and mode. Referenced models must be removed from team policies before changing their mode.</p>

    {modelOnly && <><Field label="Existing Credentials"><select value={existingID} onChange={(e) => selectCredentials(e.target.value)}><option value="">None — enter new credentials below</option>{connections.filter((c) => (!provider || c.provider === provider) && (c.status === "applied" && c.applied_revision === c.revision || c.status === "disabled")).map((c) => <option key={c.id} value={c.id}>{c.name} · {definitions.find((d) => d.id === c.provider)?.name ?? c.provider} · {c.status}</option>)}</select></Field><p>Choose saved credentials to select their provider automatically, or enter new credentials below. Pending or failed credentials need their key re-entered in LLM Credentials before reuse.</p>{connection && <p>Using {connection.name}. Its API key stays private and existing models are preserved.</p>}</>}

    {!(modelOnly && connection) && <>
    {usesEndpoint && (connection ? <><Field label="Upstream API Base"><Input readOnly value={connection.endpoint_url ?? ""} /></Field><p>The endpoint cannot be changed for this connection.</p></> : <div className="ai-provider-endpoint-entry">
      <Field label="Upstream API Base"><Input type="url" value={endpoint} maxLength={2048} onChange={(e) => { setEndpoint(e.target.value); setSecret(""); }} placeholder={provider === "azure_foundry" ? "https://resource.services.ai.azure.com/openai/v1" : "https://inference.example.com/v1"} autoComplete="off" spellCheck={false} /></Field>
      <p>{provider === "azure_foundry" ? "Paste your Azure endpoint: /anthropic/v1/messages for Claude, or /openai/v1 for OpenAI-compatible deployments. Azure portal deployment URLs are also accepted." : provider === "sagemaker" ? "Enter your private LiteLLM bridge URL. AWS region, endpoint and IAM settings stay on that bridge; use its scoped gateway key." : "Enter an OpenAI-compatible API base URL. A trailing /v1 is optional."}</p>
      {foundryInput?.legacy && <p role="status">Imported Azure deployment URL. The api-version query is replaced by v1 implicit versioning; the deployment name is sent as the model.</p>}
      {publicEndpointProvider && <p>Public HTTPS endpoints are checked automatically. Private/internal endpoints need configured network access.</p>}
      {!endpointAvailable ? <p role="alert">Installation setup required: configure secure provider egress before testing.</p> : endpoint.trim() && !enteredBase ? <p role="alert">{provider === "azure_foundry" ? "Enter an Azure resource URL or recognized deployment request URL. Only api-version is accepted on legacy deployment URLs; embedded credentials, fragments and other protocols are not supported." : "Enter an HTTP or HTTPS base URL without embedded credentials, query parameters or a fragment."}</p> : endpoint.trim() && !foundryFormatValid ? <p role="alert">Use an Azure HTTPS URL ending /openai/v1 or /anthropic/v1/messages.</p> : endpoint.trim() && !endpointApproved ? <p role="alert">This endpoint needs configured network access for this provider. Use a public HTTPS endpoint when available, or ask your installation administrator to configure private access.</p> : endpointApproved ? <p>Test request: <code>{selectedEndpoint.replace(/\/+$/, "")}/v1{anthropicEndpoint ? "/messages" : modeLabel(probeMode).split(" — ")[1]}</code></p> : null}
    </div>)}
    {!usesEndpoint && <><Field label="Upstream API Base"><Input readOnly disabled={!provider} value={provider ? nativeAPIBase[provider] ?? "" : ""} placeholder={provider ? "Standard provider endpoint" : "Select a provider to configure its API endpoint"} /></Field>{provider ? <div className="ai-provider-endpoint-help"><p>{providerLabel} uses this standard API endpoint. For a different OpenAI-compatible API URL, use Custom provider.</p>{!connection && definitions.some((d) => d.id === "custom") && <Button type="button" onClick={() => switchProvider("custom")}>Use custom endpoint</Button>}</div> : <p>Select a provider to configure its API endpoint.</p>}</>}

    </>}

    {!(modelOnly && connection) && <><div className="ai-provider-form-grid"><Field label="Credential name (optional)"><Input value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={savedName || "Generated from provider and model"} /></Field><Field label={connection ? "Replacement API key (optional)" : provider === "sagemaker" ? "Gateway API key" : provider === "azure_foundry" ? "Azure API key" : "API key"}><Input type="password" autoComplete="new-password" spellCheck={false} value={secret} maxLength={4096} onChange={(e) => setSecret(e.target.value)} placeholder={connection ? "Leave blank to keep the current key" : provider === "sagemaker" ? "Enter your scoped gateway key" : provider === "azure_foundry" ? "Enter your Azure API key" : "Enter your provider key"} /></Field></div>
    <p>Keys are stored securely and never shown again. If a key update fails, enter the key again and save.</p></>}

    {!(modelOnly && connection) && <><label className="ai-provider-enabled"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enable this connection for authorized team policies</label><p>Organization AI access remains a separate default-off setting.</p></>}
    {needsTest && <div className="ai-provider-preflight"><p>A small {modeLabel(probeMode)} request tests the first selected model only; charges may apply and are excluded from gateway usage totals. Success does not certify the other selected models. Results expire after five minutes.</p>{testBlockers.length > 0 && <div id={testHelpId} role="status" aria-label="Test Connect requirements"><p>To enable Test Connect:</p><ul>{testBlockers.map((message) => <li key={message}>{message}</li>)}</ul></div>}{testStatus === "success" && <p role="status">Test succeeded for {chosen[0]} ({modeLabel(probeMode)}). {probeMode === "video_generation" ? "Video job accepted; generation is not yet complete." : "You can now save this model configuration."}</p>}{testStatus === "error" && <p role="alert">{testFailure.title}. {testFailure.description}</p>}</div>}
  </form></div>
  );
  return modelOnly ? <section className="ai-provider-inline" role="tabpanel" aria-label="Add Model">{showInlineTitle && <h3>Add Model</h3>}<div className="ai-provider-inline-card">{editor}<div className="ai-provider-inline-actions">{actions}</div></div></section> : <Modal title={connection ? "Edit credentials" : "Add Credentials"} placement="right" size="wide" showClose onDismiss={onCancel} actions={actions}>{editor}</Modal>;
}
