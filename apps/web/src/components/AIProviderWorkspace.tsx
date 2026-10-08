import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Field, Input, Modal } from "./ui";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "./AppAccessRowMenu";
import { NetworkDetailList } from "./NetworkDetailList";
import "../ai-gateway-workspace.css";
import "./ai-provider-workspace.css";
import { HelpTooltip, modelDisplayName } from "./HelpTooltip";
import { EntityPicker } from "./EntityPicker";
import { parseFoundryEndpoint } from "../lib/aiFoundryEndpoint";
import { aiProbeFailure } from "../lib/aiProbeFailure";
import { aiGatewayPrerequisite } from "../lib/aiGatewayPrerequisite";
import { AIGroupAccess } from "./AIUserAccess";
import { AIModelConnectionDetails } from "./AIModelConnectionDetails";
import { ProviderLogo } from "./ProviderLogo";
import { ResourceSummary } from "./ResourceSummary";
type S = components["schemas"];
export type AIProviderConnection = S["AIProviderConnection"];
type Definition = S["AIProviderDefinition"];
type ModelMode = S["AIModelMode"];
const modelModes: { value: ModelMode; label: string }[] = [
  { value: "chat", label: "Chat, /chat/completions" },
  { value: "completion", label: "Completion, /completions" },
  { value: "embedding", label: "Embedding, /embeddings" },
  { value: "audio_speech", label: "Audio speech, /audio/speech" },
  { value: "audio_transcription", label: "Audio transcription, /audio/transcriptions" },
  { value: "image_generation", label: "Image generation, /images/generations" },
  { value: "video_generation", label: "Video generation, /videos" },
  { value: "rerank", label: "Rerank, /rerank" },
];
const modeLabel = (mode: ModelMode) => modelModes.find((item) => item.value === mode)?.label ?? mode;
// Display-only: native routing uses the private Bifrost provider adapters.
const nativeAPIBase: Record<string, string> = {
  openai: "https://api.openai.com/v1", anthropic: "https://api.anthropic.com",
  gemini: "https://generativelanguage.googleapis.com", openrouter: "https://openrouter.ai/api/v1",
  groq: "https://api.groq.com/openai/v1", mistral: "https://api.mistral.ai/v1",
  cerebras: "https://api.cerebras.ai/v1", xai: "https://api.x.ai/v1", deepseek: "https://api.deepseek.com",
};
const uniqueLines = (v: string) => [...new Set(v.split("\n").map((s) => s.trim()).filter(Boolean))];
function endpointBase(value: string): string {
  if (value.length > 2048 || /[%\\\s?#@]/.test(value)) return "";
  try {
    const url = new URL(value.trim());
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.hostname.endsWith(".")) return "";
    const path = url.pathname.replace(/\/+$/, "").replace(/\/v1$/, "");
    if (path.includes("//") || path.split("/").some((part) => part === "v1") || /\/(?:\.|\.\.)(?:\/|$)/.test(value)) return "";
    return `${url.origin}${path}`;
  } catch { return ""; }
}
type WorkspaceView = "connections" | "models" | "add";
type WorkspaceProps = {
  orgId: string; canManage?: boolean; canManageTransport?: boolean; view?: WorkspaceView;
  onViewChange?: (view: WorkspaceView) => void;
  onGrantAccess?: (connection: string, model: string) => void;
};
export function AIProviderWorkspace(props: WorkspaceProps) {
  return <ProviderWorkspace key={`${props.orgId}:${props.canManage ?? true}`} {...props} />;
}
function ProviderWorkspace({ orgId, canManage = true, canManageTransport = false, view: routeView, onViewChange, onGrantAccess }: WorkspaceProps) {
  const [credentialSearch, setCredentialSearch] = useState("");
  const [credentialProvider, setCredentialProvider] = useState("");
  const [accessAfterSave, setAccessAfterSave] = useState<AIProviderConnection | null>(null);
  const [grantAfterSave, setGrantAfterSave] = useState(false);
  const [credentialDetails, setCredentialDetails] = useState<AIProviderConnection | null>(null);
  const [inventory, setInventory] = useState<S["AIProviderList"] | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [httpsRequired, setHTTPSRequired] = useState(false);
  const transportMessage = canManageTransport
    ? "AI Gateway access over HTTP is disabled. Use HTTPS, or enable Allow AI Gateway over HTTP in Settings → AI Gateway transport."
    : "AI Gateway access over HTTP is disabled. Use HTTPS, or ask your server administrator to enable Allow AI Gateway over HTTP in Settings → AI Gateway transport.";
  const drafts = useRef<Record<string, EditorDraft>>({});
  const [editing, setEditing] = useState<AIProviderConnection | "new" | null>(null);
  const [localView, setLocalView] = useState<WorkspaceView>("models");
  const view = routeView ?? localView;
  const setView = (next: WorkspaceView) => { setLocalView(next); onViewChange?.(next); };
  useEffect(() => { setEditing(null); setRemoving(null); setCredentialDetails(null); setConnectionModel(null); }, [routeView]);
  useEffect(() => { if (!canManage) { setEditing(null); setRemoving(null); setAccessAfterSave(null); setGrantAfterSave(false); drafts.current = {}; } }, [canManage]);
  const [connectionModel, setConnectionModel] = useState<{ model: string; connectionId: string } | null>(null);
  const [detailSection, setDetailSection] = useState<"overview" | "connection" | "models">("overview");
  const [modelPage, setModelPage] = useState(1), [credentialPage, setCredentialPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [modelSearch, setModelSearch] = useState(""), [modelProvider, setModelProvider] = useState("");
  const [removing, setRemoving] = useState<AIProviderConnection | null>(null);
  const alive = useRef(true), serial = useRef(0);
  async function reload() {
    const n = ++serial.current;
    setLoading(true);
    setHTTPSRequired(false);
    try {
      const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } } });
      if (!alive.current || n !== serial.current) return;
      if (r.error || !r.data) {
        if (r.error?.error?.code === "ai_https_required") {
          setInventory(null);
          setHTTPSRequired(true);
          setError(transportMessage);
          return;
        }
        if (r.response.status === 503) {
          const settings = await api.GET("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId } } });
          if (!alive.current || n !== serial.current) return;
          if (settings.data && !settings.data.available) {
            setInventory(null);
            const needsHTTPS = settings.data.unavailable_reason === "https_required";
            setHTTPSRequired(needsHTTPS);
            setError(needsHTTPS ? transportMessage : aiGatewayPrerequisite(settings.data));
            return;
          }
        }
        throw Error();
      }
      setInventory(r.data);
      setError("");
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
      const failure = r.error ? r.response.status === 409 ? "This connection changed or is referenced by a team policy or user group grant. Refresh and update those grants before removing models, changing their mode or deleting the connection." : "The operation could not be completed. Check the connection state; an uncertain key update requires entering the API key again." : "";
      if (!r.error) { setNotice(success); ok = true; }
      await reload();
      if (alive.current && failure) setError(failure);
    } catch { if (alive.current) { await reload(); if (alive.current) setError("Could not reach the API. Refresh to check saved state. Enter the API key again if an update did not finish."); } }
    finally { if (alive.current) setBusy(false); }
    return ok;
  }
  async function save(body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) {
    drafts.current = {};
    // Close before awaiting: no submitted secret remains in a form or its state.
    setEditing(null); setView(view === "connections" ? "connections" : "models");
    let saved: AIProviderConnection | undefined;
    const ok = await mutate(async () => {
      const result = connection
        ? await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: connection.id } }, body: body as S["AIProviderUpdate"] })
        : await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers", { params: { path: { orgId } }, body: body as S["AIProviderCreate"] });
      saved = result.data;
      return result;
    }, view === "add" ? "Models saved." : "Credentials saved.");
    if (ok && saved?.models.length) {
      if (view === "add") setAccessAfterSave(saved);
      else { setConnectionModel({model: saved.models[0], connectionId: saved.id}); setDetailSection("connection"); }
    }
  }
  function changeView(next: typeof view) { setView(next); setEditing(null); setRemoving(null); setCredentialDetails(null); setConnectionModel(null); }
  const definitions = inventory?.definitions ?? [];
  const providerName = (id: string) => definitions.find((d) => d.id === id)?.name ?? id;
  const providerBrand = (id: string) => <span className="ai-gateway-provider-brand"><ProviderLogo provider={id} /><span>{providerName(id)}</span></span>;
  const modelRows = (inventory?.items ?? []).flatMap((connection) => connection.models.map((model) => ({ connection, model }))).filter(({ connection, model }) => (!modelProvider || connection.provider === modelProvider) && `${model} ${connection.name}`.toLowerCase().includes(modelSearch.toLowerCase()));
  const credentialRows = (inventory?.items ?? []).filter(c => (!credentialProvider || c.provider === credentialProvider) && `${c.name} ${c.provider}`.toLowerCase().includes(credentialSearch.toLowerCase()));
  const displayedModelPage = Math.min(modelPage, Math.max(1, Math.ceil(modelRows.length / pageSize)));
  const displayedCredentialPage = Math.min(credentialPage, Math.max(1, Math.ceil(credentialRows.length / pageSize)));
  const visibleModels = modelRows.slice((displayedModelPage - 1) * pageSize, displayedModelPage * pageSize);
  const visibleCredentials = credentialRows.slice((displayedCredentialPage - 1) * pageSize, displayedCredentialPage * pageSize);
  const managementBlock = loading || busy ? "An update is in progress." : !inventory?.management_available ? "Provider management requires installation setup." : null;
  const inspectedConnection = inventory?.items.find(c => c.id === (connectionModel?.connectionId ?? credentialDetails?.id));
  const inspectedModel = connectionModel && inspectedConnection?.models.includes(connectionModel.model) ? connectionModel.model : null;
  const openModel = (c: AIProviderConnection, model: string, section: "overview" | "connection" = "overview") => { setCredentialDetails(null); setConnectionModel({ model, connectionId: c.id }); setDetailSection(section); };
  const openCredential = (c: AIProviderConnection) => { setConnectionModel(null); setCredentialDetails(c); setDetailSection("overview"); };
  const checkCatalog = (c: AIProviderConnection) => void mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}/test", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Catalog check completed.");
  const toggleCredential = (c: AIProviderConnection) => void mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { provider: c.provider, ...(c.endpoint_url ? { endpoint_url: c.endpoint_url } : {}), name: c.name, models: c.models, enabled: !c.enabled, expected_revision: c.revision } }), "Credential state updated.");
  const connectionState = (c: AIProviderConnection) => !c.enabled ? "Disabled" : c.status === "applied" && c.revision !== c.applied_revision ? "Pending revision" : c.status === "applied" ? "Applied" : c.status === "pending" ? "Pending" : c.status === "error" ? "Error" : c.status;
  const stateTag = (c: AIProviderConnection) => <span className={`ai-gateway-state ${c.status === "error" ? "ai-gateway-state-error" : c.enabled && (c.status === "pending" || c.revision !== c.applied_revision) ? "ai-gateway-state-pending" : ""}`}>{connectionState(c)}</span>;
  const credentialActions = (c: AIProviderConnection): AppAccessRowMenuAction[] => [
    { key: "details", label: "View credentials", onSelect: () => openCredential(c) },
    ...(canManage ? [
      { key: "edit", label: "Edit credentials", disabledReason: managementBlock, onSelect: () => setEditing(c) },
      { key: "check", label: "Check catalog", disabledReason: managementBlock, onSelect: () => checkCatalog(c) },
      { key: "toggle", label: c.enabled ? "Disable" : "Enable", disabledReason: managementBlock, onSelect: () => toggleCredential(c) },
      { key: "delete", label: "Delete credentials", danger: true, disabledReason: managementBlock, onSelect: () => setRemoving(c) },
    ] : []),
  ];
  const modelActions = (c: AIProviderConnection, model: string): AppAccessRowMenuAction[] => [
    { key: "details", label: "View model", onSelect: () => openModel(c, model) },
    { key: "use", label: "Use model", disabledReason: loading || busy ? "An update is in progress." : null, onSelect: () => openModel(c, model, "connection") },
    ...(onGrantAccess && canManage ? [{ key: "grant", label: "Grant access", disabledReason: loading || busy ? "An update is in progress." : !c.enabled || c.status !== "applied" || c.revision !== c.applied_revision ? "Apply and enable these credentials before granting access." : null, onSelect: () => onGrantAccess(c.id, model) }] : []),
    ...(canManage ? [
      { key: "edit", label: "Edit credentials", disabledReason: managementBlock, onSelect: () => setEditing(c) },
      { key: "check", label: "Check catalog", disabledReason: managementBlock, onSelect: () => checkCatalog(c) },
    ] : []),
  ];
  const modelTable = (rows: typeof modelRows) => <div className="ai-gateway-table-scroll"><table className="ai-gateway-table"><caption className="sr-only">Configured models</caption><thead><tr><th>Model</th><th>Provider · mode</th><th>Credential</th><th>State</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{rows.map(({ connection: c, model }) => <tr key={`${c.id}:${model}`}><th scope="row"><button className="ai-item-button" title={model} aria-label={`View model ${model}`} onClick={() => openModel(c, model)}>{modelDisplayName(model)}</button></th><td><span className="ai-gateway-provider-identity"><ProviderLogo provider={c.provider} /><span><span>{providerName(c.provider)}</span><small>{modeLabel(c.model_modes?.[model] ?? "chat").split(", ")[0]}</small></span></span></td><td><button className="ai-item-button ai-gateway-muted" onClick={() => openCredential(c)}>{c.name}</button></td><td>{stateTag(c)}</td><td><AppAccessRowMenu label={`Model actions for ${model} · ${c.name}`} actions={modelActions(c, model)} /></td></tr>)}</tbody></table></div>;
  const pager = (kind: "models" | "credentials") => { const isModels = kind === "models", rows = isModels ? visibleModels : visibleCredentials, page = isModels ? displayedModelPage : displayedCredentialPage, total = isModels ? modelRows.length : credentialRows.length; return <AppAccessPagination page={page} pageSize={pageSize} count={rows.length} hasNext={page * pageSize < total} busy={loading || busy} maxOffset={null} onPageChange={isModels ? setModelPage : setCredentialPage} onPageSizeChange={size => { setPageSize(size); setModelPage(1); setCredentialPage(1); }} />; };
  return <section className="ai-provider-workspace ai-gateway-provider" aria-label="Models and endpoints">
    <header className="ai-gateway-toolbar"><span className="ai-gateway-count">{inventory ? view === "connections" ? `${credentialRows.length} credential${credentialRows.length === 1 ? "" : "s"}` : `${modelRows.length} model${modelRows.length === 1 ? "" : "s"}` : ""}</span><div className="ai-inventory-actions"><Button variant="ghost" size="sm" disabled={loading || busy} onClick={() => { setError(""); void reload(); }}>Refresh</Button>{view !== "connections" && canManage && <Button disabled={loading || busy || !inventory?.management_available || !definitions.length} onClick={() => changeView("add")}>Add Model</Button>}{view === "connections" && canManage && <Button disabled={loading || busy || !inventory?.management_available || !definitions.length} onClick={() => setEditing("new")}>Add Credentials</Button>}</div></header>
    {error && !editing && !removing && <div className="ai-gateway-error"><p role="alert">{error}{httpsRequired && canManageTransport && <> <Link to="/settings?section=ai-transport">Open transport settings</Link></>}</p>{!inventory && !loading && <Button variant="ghost" size="sm" onClick={() => { setError(""); void reload(); }}>Retry provider connections</Button>}</div>}
    {notice && <p role="status" className="ai-gateway-notice">{notice}</p>}
    {loading && !inventory ? <p role="status" className="ai-gateway-loading">Loading provider connections…</p> : inventory && <>
      {inventory.management_available && !definitions.length && <p className="ai-gateway-notice">Supported provider definitions are unavailable. Existing credentials remain editable.</p>}
      {!inventory.management_available && <div className="ai-gateway-empty"><h3>Provider setup required</h3><p>Ask your installation administrator to enable provider configuration. Existing operator policies remain in AI Agents.</p></div>}
      {!routeView && <nav className="ai-provider-view-tabs" role="tablist" aria-label="Model management view"><button role="tab" aria-selected={view !== "connections"} onClick={() => changeView("models")}>Models</button><button role="tab" aria-selected={view === "connections"} onClick={() => changeView("connections")}>LLM Credentials</button></nav>}
      {inspectedConnection && (credentialDetails || inspectedModel) ? <section className="ai-gateway-detail" aria-label={inspectedModel ? `${inspectedModel} model` : `${inspectedConnection.name} credentials`}>
        <nav className="ai-gateway-breadcrumb" aria-label="AI Gateway breadcrumb"><button onClick={() => { setConnectionModel(null); setCredentialDetails(null); }}>{view === "connections" ? "LLM credentials" : "Models"}</button><span aria-hidden="true">/</span><span>{inspectedModel ? modelDisplayName(inspectedModel) : inspectedConnection.name}</span></nav>
        <header className="ai-gateway-detail-header"><div><h2>{inspectedModel ? modelDisplayName(inspectedModel) : inspectedConnection.name}</h2><p className="ai-gateway-provider-context">{providerBrand(inspectedConnection.provider)}{inspectedModel && <span>· {modeLabel(inspectedConnection.model_modes?.[inspectedModel] ?? "chat").split(", ")[0]}</span>}</p></div>{stateTag(inspectedConnection)}<AppAccessRowMenu label={inspectedModel ? `Model actions for ${inspectedModel} · ${inspectedConnection.name}` : `Credential actions for ${inspectedConnection.name}`} actions={inspectedModel ? modelActions(inspectedConnection, inspectedModel) : credentialActions(inspectedConnection)} /></header>
        <div className="ai-gateway-detail-layout"><nav className="ai-gateway-detail-rail" aria-label="AI Gateway detail sections"><button aria-current={detailSection === "overview" ? "step" : undefined} onClick={() => setDetailSection("overview")}>Overview</button>{inspectedModel ? <button aria-current={detailSection === "connection" ? "step" : undefined} onClick={() => setDetailSection("connection")}>Connection</button> : <button aria-current={detailSection === "models" ? "step" : undefined} onClick={() => setDetailSection("models")}>Models</button>}</nav><div className="ai-gateway-stage">
          {detailSection === "connection" && inspectedModel ? <><h3>Connection</h3><AIModelConnectionDetails key={`${inspectedConnection.id}:${inspectedModel}`} orgId={orgId} model={inspectedModel} mode={inspectedConnection.model_modes?.[inspectedModel] ?? "chat"} /></> : detailSection === "models" && !inspectedModel ? <><h3>Models</h3><NetworkDetailList label="Credential models" items={inspectedConnection.models} searchText={model => model} renderItem={model => <li key={model}><button className="ai-gateway-model-link" title={model} onClick={() => openModel(inspectedConnection, model)}>{modelDisplayName(model)}<small>{modeLabel(inspectedConnection.model_modes?.[model] ?? "chat").split(", ")[0]}</small></button></li>} /></> : <ResourceSummary title="Overview" className="ai-gateway-resource-summary" footer={inspectedModel && <div className="ai-gateway-stage-actions"><Button variant="ghost" onClick={() => setDetailSection("connection")}>Connection &amp; code</Button>{onGrantAccess && canManage && <Button disabled={loading || busy || !inspectedConnection.enabled || inspectedConnection.status !== "applied" || inspectedConnection.revision !== inspectedConnection.applied_revision} onClick={() => onGrantAccess(inspectedConnection.id, inspectedModel)}>Grant access</Button>}</div>}>
            <dl className="ai-gateway-facts tnx-resource-facts">
              {inspectedModel && <div className="tnx-resource-fact-wide"><dt>Model ID</dt><dd><code>{inspectedModel}</code></dd></div>}
              {inspectedModel && <div><dt>Credential</dt><dd>{inspectedConnection.name}</dd></div>}
              {inspectedConnection.endpoint_url && <div className="tnx-resource-fact-wide"><dt>Endpoint</dt><dd><code>{inspectedConnection.endpoint_url}</code></dd></div>}
              {!inspectedModel && <div><dt>Models</dt><dd>{inspectedConnection.models.length}</dd></div>}
              <div><dt>Catalog check</dt><dd>{inspectedConnection.last_test_status}{inspectedConnection.last_test_at && <small>{new Date(inspectedConnection.last_test_at).toLocaleString()}</small>}</dd></div>
            </dl><details className="ai-gateway-disclosure"><summary>Configuration details</summary><dl className="ai-gateway-facts tnx-resource-facts"><div className="tnx-resource-fact-wide"><dt>Key ID</dt><dd><code>{inspectedConnection.key_id}</code></dd></div><div><dt>Revision</dt><dd>{inspectedConnection.revision} requested · {inspectedConnection.applied_revision} applied</dd></div></dl><p>Applied configuration and catalog checks do not confirm inference access.</p>{!inspectedModel && <p>Disabling these credentials blocks new requests for every associated model. Accepted streams may finish within 30 seconds.</p>}</details>
          </ResourceSummary>}
        </div></div>
      </section> : view !== "connections" ? <>
        <div className="ai-gateway-filters"><Input aria-label="Search configured models" value={modelSearch} onChange={e => { setModelSearch(e.target.value); setModelPage(1); }} placeholder="Search models or credentials" /><select aria-label="Filter models by provider" value={modelProvider} onChange={e => { setModelProvider(e.target.value); setModelPage(1); }}><option value="">All providers</option>{[...new Set(inventory.items.map(c => c.provider))].map(id => <option key={id} value={id}>{providerName(id)}</option>)}</select></div>
        {modelRows.length ? <>{modelTable(visibleModels)}{pager("models")}</> : <div className="ai-gateway-empty"><h3>{inventory.items.some(c => c.models.length) ? "No matching models" : "Add your first model"}</h3><p>{inventory.items.some(c => c.models.length) ? "Try another model, credential, or provider." : "Connect a provider, choose a model, then grant access."}</p>{modelSearch || modelProvider ? <Button variant="ghost" onClick={() => { setModelSearch(""); setModelProvider(""); setModelPage(1); }}>Clear filters</Button> : canManage && <Button disabled={!!managementBlock || !definitions.length} onClick={() => changeView("add")}>Add Model</Button>}</div>}
      </> : <>
        <div className="ai-gateway-filters"><Input aria-label="Search credentials" value={credentialSearch} onChange={e => { setCredentialSearch(e.target.value); setCredentialPage(1); }} placeholder="Search credentials or providers" /><select aria-label="Filter credentials by provider" value={credentialProvider} onChange={e => { setCredentialProvider(e.target.value); setCredentialPage(1); }}><option value="">All providers</option>{[...new Set(inventory.items.map(c => c.provider))].map(id => <option key={id} value={id}>{providerName(id)}</option>)}</select></div>
        {credentialRows.length ? <><div className="ai-gateway-table-scroll"><table className="ai-gateway-table"><caption className="sr-only">Saved LLM credentials</caption><thead><tr><th>Credential</th><th>Provider</th><th>Models</th><th>State</th><th>Catalog check</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{visibleCredentials.map(c => <tr key={c.id}><th scope="row"><button className="ai-item-button" onClick={() => openCredential(c)}>{c.name}</button></th><td>{providerBrand(c.provider)}</td><td>{c.models.length}</td><td>{stateTag(c)}</td><td title={c.last_test_at ? new Date(c.last_test_at).toLocaleString() : "No catalog check recorded"}><span className={c.last_test_status === "failed" ? "ai-gateway-state-error" : ""}>{c.last_test_status}</span></td><td><AppAccessRowMenu label={`Credential actions for ${c.name}`} actions={credentialActions(c)} /></td></tr>)}</tbody></table></div>{pager("credentials")}</> : <div className="ai-gateway-empty"><h3>{inventory.items.length ? "No matching credentials" : "Connect a provider"}</h3><p>{inventory.items.length ? "Try another credential name or provider." : "Save provider credentials to reuse them across models."}</p>{credentialSearch || credentialProvider ? <Button variant="ghost" onClick={() => { setCredentialSearch(""); setCredentialProvider(""); setCredentialPage(1); }}>Clear filters</Button> : canManage && <Button disabled={!!managementBlock || !definitions.length} onClick={() => setEditing("new")}>Add Credentials</Button>}</div>}
      </>}
      {view !== "add" && inventory.legacy_key_ids.length > 0 && <details className="ai-gateway-disclosure"><summary>Operator-managed references · {inventory.legacy_key_ids.length}</summary><p>Credentials and model scope are managed by your installation administrator.</p><div className="ai-provider-tags">{inventory.legacy_key_ids.map(id => <code key={id}>{id}</code>)}</div></details>}
      {removing && canManage && <Modal title={`Delete ${removing.name}?`} placement="right" showClose danger onDismiss={() => !busy && setRemoving(null)} actions={<><Button disabled={busy} onClick={() => setRemoving(null)}>Cancel deletion</Button><Button disabled={busy || loading} onClick={async () => { const c = removing; if (await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/ai-gateway/providers/{connectionId}", { params: { path: { orgId, connectionId: c.id } }, body: { expected_revision: c.revision } }), "Provider connection deleted. Usage history is retained.")) { setRemoving(null); setCredentialDetails(null); setConnectionModel(null); } }}>Confirm deletion</Button></>}><div className="ai-gateway-action-form">{error && <p role="alert">{error}</p>}<p>Delete these credentials and all {removing.models.length} configured models?</p><p>Remove all team policies and group grants that reference this connection first. Usage history is retained.</p></div></Modal>}
      {accessAfterSave && !grantAfterSave && <Modal title="Models saved" placement="right" showClose onDismiss={() => setAccessAfterSave(null)} actions={<><Button onClick={() => setAccessAfterSave(null)}>Later</Button><Button onClick={() => setGrantAfterSave(true)}>Grant access</Button></>}><div className="ai-gateway-action-form"><p>Choose a user group to make these models available in Playground.</p></div></Modal>}
      {accessAfterSave && grantAfterSave && <AIGroupAccess orgId={orgId} canManage={canManage} dialogOnly initialConnection={accessAfterSave.id} initialModel={accessAfterSave.models[accessAfterSave.models.length - 1]} onDone={() => { setAccessAfterSave(null); setGrantAfterSave(false); }} />}
      {canManage && (editing || view === "add") && <ProviderEditor draft={drafts.current[editing === "new" ? "new" : editing?.id ?? "model"]} key={editing === "new" ? "new-credentials" : editing ? `${editing.id}:${editing.revision}` : "new-model"} error={error} orgId={orgId} connection={editing === "new" ? undefined : editing ?? undefined} definitions={definitions} supportedModes={inventory.supported_modes ?? ["chat"]} testAvailable={inventory.test_available ?? false} publicEndpointsAvailable={inventory.public_endpoints_available ?? false} foundryAvailable={inventory.foundry_available ?? false} foundryEndpoints={inventory.foundry_endpoints ?? []} sagemakerAvailable={inventory.sagemaker_available ?? false} sagemakerEndpoints={inventory.sagemaker_endpoints ?? []} customAvailable={inventory.custom_available ?? false} endpoints={inventory.custom_endpoints ?? []} connections={inventory.items} modelOnly={!editing} busy={busy} onCancel={draft => { drafts.current[editing === "new" ? "new" : editing?.id ?? "model"] = { ...draft, secret: "" }; editing ? setEditing(null) : changeView("models"); }} onSave={save} />}
    </>}
  </section>;
}

type EditorDraft = { step: number; provider?: AIProviderConnection["provider"]; endpoint: string; existingID: string; name: string; secret: string; models: string; enabled: boolean; mode: ModelMode; selectedModes: Record<string, ModelMode>; manualModel: string; query: string };

function ProviderEditor({ draft, error, orgId, connection: initialConnection, definitions, supportedModes, testAvailable, publicEndpointsAvailable, foundryAvailable, foundryEndpoints, sagemakerAvailable, sagemakerEndpoints, customAvailable, endpoints, connections, modelOnly, busy, onSave, onCancel }: { draft?: EditorDraft; error: string; orgId: string; connection?: AIProviderConnection; definitions: Definition[]; supportedModes: ModelMode[]; testAvailable: boolean; publicEndpointsAvailable: boolean; foundryAvailable: boolean; foundryEndpoints: NonNullable<S["AIProviderList"]["foundry_endpoints"]>; sagemakerAvailable: boolean; sagemakerEndpoints: NonNullable<S["AIProviderList"]["sagemaker_endpoints"]>; customAvailable: boolean; endpoints: NonNullable<S["AIProviderList"]["custom_endpoints"]>; connections: AIProviderConnection[]; modelOnly: boolean; busy: boolean; onSave: (body: S["AIProviderCreate"] | S["AIProviderUpdate"], connection?: AIProviderConnection) => Promise<void>; onCancel: (draft: EditorDraft) => void }) {
  const wizard = modelOnly;
  const [step, setStep] = useState(draft?.step ?? 0);
  const steps = ["Provider", "Credentials", "Models", "Review & test"];
  const [provider, setProvider] = useState<AIProviderConnection["provider"] | undefined>(draft?.provider ?? initialConnection?.provider);
  const [endpoint, setEndpoint] = useState(draft?.endpoint ?? initialConnection?.endpoint_url ?? "");
  const [existingID, setExistingID] = useState(draft?.existingID ?? "");
  const connection = initialConnection ?? (modelOnly ? connections.find((c) => c.id === existingID && c.provider === provider) : undefined);
  const usesEndpoint = provider === "custom" || provider === "sagemaker" || provider === "azure_foundry";
  const approvedEndpoints = provider === "azure_foundry" ? foundryEndpoints : provider === "sagemaker" ? sagemakerEndpoints : endpoints;
  const publicEndpointProvider = publicEndpointsAvailable && usesEndpoint;
  const endpointAvailable = publicEndpointProvider || (provider === "azure_foundry" ? foundryAvailable : provider === "sagemaker" ? sagemakerAvailable : customAvailable);
  const definition = definitions.find((d) => d.id === provider);
  const providerLabel = definition?.name ?? initialConnection?.provider ?? "Select a provider";
  const formId = useId();
  const [name, setName] = useState(draft?.name ?? connection?.name ?? ""), [secret, setSecret] = useState(draft?.secret ?? ""), [models, setModels] = useState(draft?.models ?? connection?.models.join("\n") ?? ""), [enabled, setEnabled] = useState(draft?.enabled ?? connection?.enabled ?? true);
  const [mode, setMode] = useState<ModelMode>(draft?.mode ?? initialConnection?.model_modes?.[initialConnection.models[0]] ?? "chat");
  const [selectedModes, setSelectedModes] = useState<Record<string, ModelMode>>(draft?.selectedModes ?? initialConnection?.model_modes ?? {});
  const [catalogFocused, setCatalogFocused] = useState(false);
  const catalogRequest = useRef(false);
  const [catalogPageSize, setCatalogPageSize] = useState(50);
  const [manualModel, setManualModel] = useState(draft?.manualModel ?? "");
  const [catalogOpen, setCatalogOpen] = useState(false), [catalogDismissed, setCatalogDismissed] = useState(false);
  const [query, setQuery] = useState(draft?.query ?? ""), [catalog, setCatalog] = useState<S["AIProviderModelList"] | null>(null), [catalogError, setCatalogError] = useState(""), [searching, setSearching] = useState(false);
  const active = useRef(true), searchSerial = useRef(0);
  useEffect(() => { active.current = true; return () => { active.current = false; searchSerial.current++; }; }, []);
  async function search(offset = 0, limit = catalogPageSize) {
    if (!provider || !canSearch || offset > 0 && catalogRequest.current) return;
    catalogRequest.current = true;
    const n = ++searchSerial.current;
    setSearching(true); setCatalogError(""); setCatalogOpen(true);
    try {
      const r = draftCatalog
        ? await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/model-catalog", { params: { path: { orgId } }, body: { provider, api_key: secret, endpoint_url: usesEndpoint ? selectedEndpoint : "", query: query.trim(), mode, limit, offset } })
        : await api.GET("/api/v1/organizations/{orgId}/ai-gateway/models", { params: { path: { orgId }, query: { provider, ...(usesEndpoint && connection ? { connection_id: connection.id } : {}), query: query.trim(), mode, limit, offset } } });
      if (!active.current || n !== searchSerial.current) return;
      if (r.error || !r.data) throw Error();
      const page = r.data;
      setCatalog(page);
    } catch { if (active.current && n === searchSerial.current) { setCatalog(null); setCatalogError("Model suggestions are unavailable. Enter the exact model or Azure deployment name manually below."); } }
    finally { if (active.current && n === searchSerial.current) { setSearching(false); catalogRequest.current = false; } }
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
  const chosen = modelOnly ? uniqueLines(models) : initialConnection?.models ?? [];
  const canonicalModel = (model: string) => usesEndpoint && connection && !model.startsWith(`custom-${connection.id}/`) ? `custom-${connection.id}/${model}` : model;
  const finalModels = modelOnly && connection ? [...connection.models, ...chosen.filter((model) => !connection.models.some((saved) => canonicalModel(saved) === canonicalModel(model)))] : chosen;
  const modelMode = (model: string): ModelMode => {
    const retained = modelOnly && connection?.models.find((saved) => canonicalModel(saved) === canonicalModel(model));
    return retained && connection ? connection.model_modes?.[retained] ?? "chat" : selectedModes[model] ?? (initialConnection?.models.includes(model) ? "chat" : mode);
  };
  function changeMode(next: ModelMode) {
    setMode(next); setCatalogDismissed(false); searchSerial.current++; setCatalog(null); setCatalogOpen(false); setSearching(false);

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
  const draftCatalog = !!provider && provider !== "azure_foundry" && !connection;
  const canSearch = !!definition && supportedModes.includes(mode) && (!draftCatalog || (!usesEndpoint || endpointReady) && secretValid);
  const searchEndpoint = draftCatalog ? selectedEndpoint : "";
  const searchSecret = draftCatalog ? secret : "";
  const searchConnection = usesEndpoint && connection ? connection.id : "";
  useEffect(() => { searchSerial.current++; setCatalog(null); setCatalogError(""); setCatalogOpen(false); setSearching(false); }, [provider, mode, searchEndpoint, searchSecret, searchConnection]);
  useEffect(() => {
    if (!canSearch || catalogDismissed) return;
    const timer = window.setTimeout(() => { void search(0); }, 500);
    return () => window.clearTimeout(timer);
  }, [provider, query, mode, canSearch, searchEndpoint, searchSecret, searchConnection, catalogDismissed]);
  const savedName = name.trim() || connection?.name || (provider ? `${providerLabel}`.slice(0, 80) : "");
  const validationIssues: string[] = [];
  if (!provider || !connection && !definition) validationIssues.push("Select a provider.");
  if (usesEndpoint && (!selectedEndpoint || !foundryFormatValid)) {
    if (!selectedEndpoint) validationIssues.push("Enter a valid Upstream API Base.");
    else if (!foundryFormatValid) validationIssues.push("Use an Azure HTTPS URL ending /openai/v1 or /anthropic/v1/messages.");
  }
  if (modelOnly && provider === "azure_foundry" && !connection && foundryInput) {
    if (foundryInput.deployment && chosen[0] !== foundryInput.deployment) validationIssues.push(`The pasted URL targets deployment ${foundryInput.deployment}. Select it as the first model, or enter the resource base URL for your selected models.`);
    if (chosen.length && foundryInput.mode && modelMode(chosen[0]) !== foundryInput.mode) validationIssues.push(`The pasted URL uses ${modeLabel(foundryInput.mode)}. Match the Mode selection, or enter the resource base URL.`);
  }
  if (anthropicEndpoint && (mode !== "chat" || chosen.some((model) => modelMode(model) !== "chat"))) validationIssues.push("The Anthropic Messages endpoint supports Chat mode. Choose Chat to test this deployment.");
  if ((provider === "custom" || provider === "sagemaker") && parseFoundryEndpoint(endpoint)?.base.endsWith("/anthropic")) validationIssues.push("Choose Azure AI Foundry for this Anthropic Messages endpoint.");
  if (name.trim().length > 80) validationIssues.push("Use at most 80 characters for the credential name.");
  if (modelOnly && !chosen.length) validationIssues.push(manualModel.trim()
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
  const [modelResults, setModelResults] = useState<Record<string, string>>({});
  const testGeneration = useRef(0);
  useEffect(() => { testGeneration.current++; setModelResults({}); setTestStatus("idle"); setTestedAt(0); setTesting(false); return () => { testGeneration.current++; }; }, [provider, secret, selectedEndpoint, models, existingID, mode, selectedModes, connection?.revision, connection?.applied_revision, connection?.enabled, connection?.status]);
  useEffect(() => { if (!testedAt) return; const timer = window.setTimeout(() => { setTestStatus("idle"); setTestedAt(0); }, Math.max(0, testedAt + 300000 - Date.now())); return () => window.clearTimeout(timer); }, [testedAt]);
  const probeMode = chosen.length ? modelMode(chosen[0]) : mode;
  const needsTest = modelOnly;
  // Capabilities and installation policy may have changed since inventory was
  // loaded. A valid test request lets the API return the current setup verdict.
  const testBlockers = validationIssues;
  const testHelpId = `${formId}-test-help`;
  const canSave = valid && (!needsTest || supportedModes.includes(probeMode)) && (!needsTest || testStatus === "success" && Date.now() - testedAt < 300000);
  async function testConnection() {
    if (!provider || testBlockers.length > 0 || testing) return;
    const generation = ++testGeneration.current;
    setTesting(true); setTestStatus("idle");
    let allPassed = true;
    try {
      for (const selected of chosen) {
        if (modelResults[selected] === "Passed" && Date.now() - testedAt < 300000) continue;
        if (!active.current || generation !== testGeneration.current) return;
        setModelResults(current => ({ ...current, [selected]: "Testing…" }));
        const model = usesEndpoint && connection ? selected.replace(`custom-${connection.id}/`, "") : selected;
        try {
          const r = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/providers/test-connection", { params: { path: { orgId } }, body: { provider, model, mode: modelMode(selected), ...(connection && !secret ? { connection_id: connection.id, expected_revision: connection.revision } : { api_key: secret, ...(usesEndpoint ? { endpoint_url: selectedEndpoint } : {}) }) } });
          if (!active.current || generation !== testGeneration.current) return;
          const success = !r.error && r.response?.status === 200 && r.data?.status === "success";
          const notice = aiProbeFailure(r.response?.status, r.data?.failure, r.error?.error?.code);
          setModelResults(current => ({ ...current, [selected]: success ? "Passed" : notice.title + ". " + notice.description }));
          if (success && !testedAt) setTestedAt(Date.now());
          if (!success) { allPassed = false; setTestFailure(notice); if (r.response?.status === 429) break; }
        } catch {
          if (!active.current || generation !== testGeneration.current) return;
          allPassed = false;
          const notice = aiProbeFailure();
          setTestFailure(notice);
          setModelResults(current => ({ ...current, [selected]: notice.title + ". " + notice.description }));
        }
      }
      setTestStatus(allPassed ? "success" : "error");
      if (allPassed && !testedAt) setTestedAt(Date.now());
    } finally { if (active.current && generation === testGeneration.current) setTesting(false); }
  }

  const nextAllowed = step === 0 ? Boolean(provider && (definition || initialConnection)) : step === 1 ? (!usesEndpoint || !!selectedEndpoint && foundryFormatValid) && (connection && !secret || secretValid) && name.trim().length <= 80 : valid;
  const dismiss = () => onCancel({ step, provider, endpoint, existingID, name, secret, models, enabled, mode, selectedModes, manualModel, query });
  const actions = <><Button variant="ghost" type="button" disabled={busy} onClick={dismiss}>Cancel</Button>{wizard && step > 0 && <Button variant="ghost" type="button" disabled={busy || testing} onClick={() => setStep(step - 1)}>Back</Button>}{wizard && step < 3 ? <Button type="button" disabled={busy || !nextAllowed} onClick={() => setStep(step + 1)}>Continue</Button> : <>{needsTest && <Button variant="ghost" type="button" disabled={busy || testing || testBlockers.length > 0} aria-describedby={testBlockers.length ? testHelpId : undefined} onClick={() => void testConnection()}>{testing ? "Testing connection…" : "Test Connect"}</Button>}<Button form={formId} type="submit" disabled={busy || !canSave}>{modelOnly ? "Add Model" : connection ? "Save credentials" : "Create credentials"}</Button></>}</>;
  const editor = (
    <div className="ai-provider-workspace"><form id={formId} className="ai-provider-editor ai-gateway-editor" aria-label={modelOnly ? "Add model" : connection ? "Edit credentials" : "Add credentials"} onSubmit={(event) => { event.preventDefault(); if (!canSave || busy || !provider || wizard && step !== 3) return; const body = { provider, ...(usesEndpoint ? { endpoint_url: selectedEndpoint } : {}), name: modelOnly && connection ? connection.name : savedName, models: finalModels, model_modes: Object.fromEntries(finalModels.map((model) => [model, modelMode(model)])), enabled: modelOnly && connection ? connection.enabled : enabled, ...(secret ? { api_key: secret } : {}) }; setSecret(""); void onSave(connection ? { ...body, expected_revision: connection.revision } : { ...body, api_key: secret }, connection); }}>

    {modelOnly && !testAvailable && <p role="status">The testing service may need installation setup. Test Connect will report its current availability.</p>}
    {wizard && <ol className="ai-wizard-steps" aria-label="Credential setup progress">{steps.map((label, index) => <li key={label}><button type="button" aria-current={step === index ? "step" : undefined} disabled={busy || testing || index > step} onClick={() => setStep(index)}><span>{index + 1}</span>{label}</button></li>)}</ol>}
    <div className="ai-wizard-section" hidden={wizard && step !== 0}>

    {initialConnection ? <div className="ai-provider-fixed-brand"><ProviderLogo provider={initialConnection.provider} /><strong>{providerLabel}</strong><HelpTooltip label="About this provider">A connection's provider cannot be changed.</HelpTooltip></div> : <div className="ai-provider-picker"><EntityPicker label="Provider" value={provider ?? ""} placeholder="Select a provider" options={definitions.map((d) => ({ value: d.id, icon: <ProviderLogo provider={d.id} />, kind: "provider", tag: modelOnly && (d.id === "custom" && !customAvailable && !publicEndpointsAvailable || d.id === "sagemaker" && !sagemakerAvailable && !publicEndpointsAvailable || d.id === "azure_foundry" && !foundryAvailable && !publicEndpointsAvailable) ? "Setup required" : "", label: d.name }))} onSelect={(option) => { const selected = definitions.find((d) => d.id === option.value); if (selected) switchProvider(selected.id); }} /></div>}
    {modelOnly && <div className="ai-gateway-existing"><Field label="Existing Credentials"><select value={existingID} onChange={(e) => selectCredentials(e.target.value)}><option value="">New credentials</option>{connections.filter((c) => (!provider || c.provider === provider) && (c.status === "applied" && c.applied_revision === c.revision || c.status === "disabled")).map((c) => <option key={c.id} value={c.id}>{c.name} · {definitions.find((d) => d.id === c.provider)?.name ?? c.provider} · {c.status}</option>)}</select></Field><p>Use saved credentials, or choose a provider for a new connection.</p></div>}
    {modelOnly && provider === "custom" && !customAvailable && !publicEndpointsAvailable && <p>Custom providers require an installation-approved endpoint and secure egress setup.</p>}
    {provider === "azure_foundry" ? <div className="flex items-center gap-2 text-sm text-ink-tertiary"><span>Azure setup help</span><HelpTooltip label="Azure setup help">Use your Azure endpoint and API key. Claude uses the Anthropic Messages endpoint; OpenAI-compatible deployments use /openai/v1. When selecting models, enter your Azure deployment name if it differs from the catalog name. A connection test confirms access.</HelpTooltip></div> : draftCatalog && <div className="flex items-center gap-2 text-sm text-ink-tertiary"><span>Finding your model</span><HelpTooltip label="Finding your model">Search the provider catalog or enter an exact model name. A connection test confirms access to the selected model.</HelpTooltip></div>}
    </div>
    <div className="ai-wizard-section" hidden={wizard && step !== 1}>
    {modelOnly && connection && <><dl className="ai-wizard-review tnx-resource-facts"><div><dt>Credential</dt><dd>{connection.name}</dd></div><div><dt>API key</dt><dd>Stored securely</dd></div><div><dt>Models</dt><dd>{connection.models.length} already configured</dd></div><div><dt>State</dt><dd>{connection.enabled ? connection.status : "Disabled"}</dd></div></dl><p>Existing models stay included. The stored API key stays private.</p></>}

    {!(modelOnly && connection) && <>
    {usesEndpoint && (connection ? <><Field label="Upstream API Base"><Input readOnly value={connection.endpoint_url ?? ""} /></Field><p>The endpoint cannot be changed for this connection.</p></> : <div className="ai-provider-endpoint-entry">
      <Field label="Upstream API Base"><Input type="url" value={endpoint} maxLength={2048} onChange={(e) => { setEndpoint(e.target.value); setSecret(""); }} placeholder={provider === "azure_foundry" ? "https://resource.services.ai.azure.com/openai/v1" : "https://inference.example.com/v1"} autoComplete="off" spellCheck={false} /></Field>
      <p>{provider === "azure_foundry" ? "Paste your Azure endpoint: /anthropic/v1/messages for Claude, or /openai/v1 for OpenAI-compatible deployments. Azure portal deployment URLs are also accepted." : provider === "sagemaker" ? "Enter the SageMaker binding URL supplied by your installation administrator and its scoped client key. AWS region, endpoint and IAM credentials stay on the private AI backend." : "Enter an OpenAI-compatible API base URL. A trailing /v1 is optional."}</p>
      {foundryInput?.legacy && <p role="status">Imported Azure deployment URL. The api-version query is replaced by v1 implicit versioning; the deployment name is sent as the model.</p>}
      {publicEndpointProvider && <HelpTooltip>Public HTTPS endpoints are checked automatically. Private/internal endpoints need configured network access.</HelpTooltip>}
      {endpoint.trim() && !enteredBase ? <p role="alert">{provider === "azure_foundry" ? "Enter an Azure resource URL or recognized deployment request URL. Only api-version is accepted on legacy deployment URLs; embedded credentials, fragments and other protocols are not supported." : "Enter an HTTP or HTTPS base URL without embedded credentials, query parameters or a fragment."}</p> : endpoint.trim() && !foundryFormatValid ? <p role="alert">Use an Azure HTTPS URL ending /openai/v1 or /anthropic/v1/messages.</p> : modelOnly && endpoint.trim() && !endpointReady ? <p role="status">This endpoint may need installation network setup. Test Connect will report its current availability.</p> : modelOnly && endpointApproved ? <p>Test request: <code>{selectedEndpoint.replace(/\/+$/, "")}/v1{anthropicEndpoint ? "/messages" : modeLabel(probeMode).split(", ")[1]}</code></p> : null}
    </div>)}
    {!usesEndpoint && <><Field label="Upstream API Base"><Input readOnly disabled={!provider} value={provider ? nativeAPIBase[provider] ?? "" : ""} placeholder={provider ? "Standard provider endpoint" : "Select a provider to configure its API endpoint"} /></Field>{provider ? <div className="ai-provider-endpoint-help"><p>{providerLabel} uses its standard API endpoint.</p>{!connection && definitions.some((d) => d.id === "custom") && <Button type="button" onClick={() => switchProvider("custom")}>Use custom endpoint</Button>}</div> : <p>Select a provider to configure its API endpoint.</p>}</>}

    </>}

    {!(modelOnly && connection) && <><div className="ai-provider-form-grid"><Field label="Credential name (optional)"><Input value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={savedName || "Generated from provider and model"} /></Field><Field help={<HelpTooltip label="About API keys">Keys are stored securely and never shown again. If a key update fails, enter the key again and save.</HelpTooltip>} label={connection ? "Replacement API key (optional)" : provider === "sagemaker" ? "Gateway API key" : provider === "azure_foundry" ? "Azure API key" : "API key"}><Input type="password" autoComplete="new-password" spellCheck={false} value={secret} maxLength={4096} onChange={(e) => setSecret(e.target.value)} placeholder={connection ? "Leave blank to keep the current key" : provider === "sagemaker" ? "Enter your scoped gateway key" : provider === "azure_foundry" ? "Enter your Azure API key" : "Enter your provider key"} /></Field></div>
    </>}

    {!(modelOnly && connection) && <div className="ai-provider-access-toggle"><label className="ai-provider-enabled"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enable these credentials</label><HelpTooltip label="About connection access">Organization AI access remains a separate default-off setting.</HelpTooltip></div>}
    </div>
    <div className="ai-wizard-section" hidden={!modelOnly || step !== 2}>
    {usesEndpoint && !endpointReady && <p role="status">This endpoint may need installation network setup. You can check it with Test Connect. Activation requires a successful test.</p>}
    <div className="ai-model-choice-heading"><strong>Models <span>{chosen.length}/32 selected</span></strong><HelpTooltip label="Selecting models">Select multiple models from the catalog. Your selections stay when searching or changing pages. Remove a selected chip to deselect it.</HelpTooltip></div>
    <div className="ai-provider-selected-models" aria-label="Selected models">{chosen.map((model) => <span key={model}><code title={model}>{modelDisplayName(model)}</code><button type="button" aria-label={`Remove model ${model}`} onClick={() => setModels(chosen.filter((m) => m !== model).join("\n"))}>×</button></span>)}</div>
    <Field label="Catalog mode" help={<HelpTooltip>Filter suggestions and set the default for newly added models. Each selected model has its own mode below. One credential can serve chat, images, embeddings and other supported operations.</HelpTooltip>}><select value={mode} onChange={(e) => changeMode(e.target.value as ModelMode)}>{modelModes.map((item) => <option key={item.value} value={item.value} disabled={!supportedModes.includes(item.value)}>{item.label.split(", ")[0]}{!supportedModes.includes(item.value) ? ", unavailable" : ""}</option>)}</select></Field>
    <div className="ai-provider-catalog ai-provider-model-dropdown" onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setCatalogFocused(false); }} onKeyDown={(e) => { if (e.key === "Escape" && catalogOpen) { e.stopPropagation(); setCatalogOpen(false); setCatalogDismissed(true); } }}><div className="ai-provider-catalog-search"><Field label="Search model catalog"><Input value={query} maxLength={100} onFocus={() => { setCatalogFocused(true); setCatalogDismissed(false); if (catalog) setCatalogOpen(true); }} onChange={(e) => { setQuery(e.target.value); setCatalogDismissed(false); searchSerial.current++; setSearching(false); setCatalog(null); setCatalogError(""); }} placeholder="Search model name" /></Field></div>{searching && <p role="status">Searching models…</p>}{draftCatalog && !canSearch && <p>{usesEndpoint && !endpointReady ? "Enter a supported endpoint to search models. Public HTTPS endpoints are checked automatically when public egress is available; private endpoints need configured network access." : "Enter the provider API key to search models. No model selection is required."}</p>}{catalogError && <p role="alert">{catalogError}</p>}{catalogFocused && catalogOpen && catalog && <div className="ai-provider-model-options" role="region" aria-label="Model suggestions"><p>{draftCatalog ? "Provider catalog" : "Unverified catalog suggestions"}<HelpTooltip>Catalog entries do not confirm access or current availability. Each selected model must pass a connection test before saving. Select the operation you intend to use; unsupported model and operation combinations will fail validation.</HelpTooltip></p><p>{catalog.total} matching models</p><div className="ai-provider-catalog-items">{catalog.items.map((m) => <label key={m.id} className={chosen.includes(m.id) ? "ai-model-option-selected" : undefined}><input type="checkbox" checked={chosen.includes(m.id)} disabled={!chosen.includes(m.id) && chosen.length >= 32} onChange={(e) => e.target.checked ? addModel(m.id) : setModels(chosen.filter((id) => id !== m.id).join("\n"))} /><span title={m.id}>{m.name}<small className="sr-only">{m.id}</small></span></label>)}</div><AppAccessPagination page={Math.floor(catalog.offset / catalog.limit) + 1} pageSize={catalog.limit} count={catalog.items.length} hasNext={catalog.offset + catalog.limit < catalog.total} busy={searching} onPageChange={page => void search((page - 1) * catalog.limit)} onPageSizeChange={size => { setCatalogPageSize(size); void search(0, size); }} previousLabel="Previous model suggestions" nextLabel="Next model suggestions" /><div className="ai-provider-form-actions"><Button type="button" onClick={() => { setCatalogOpen(false); setCatalogDismissed(true); }} aria-label="Done selecting models">Done ({chosen.length} selected)</Button></div></div>}</div>
    <details className="ai-manual-disclosure"><summary>Model not listed? Add manually</summary><div className="ai-provider-manual-model"><Field label="Exact model name"><Input value={manualModel} maxLength={255} disabled={!provider} onChange={(e) => setManualModel(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (validModel(manualModel.trim()) && !chosen.includes(manualModel.trim()) && finalModels.length < 32) { addModel(manualModel.trim()); setManualModel(""); } } }} placeholder={definition?.model_placeholder ?? "Select a provider first"} /></Field><Button type="button" disabled={!provider || !validModel(manualModel.trim()) || chosen.includes(manualModel.trim()) || finalModels.length >= 32} onClick={() => { addModel(manualModel.trim()); setManualModel(""); }}>Add exact model</Button></div></details><p className="ai-provider-model-help">{finalModels.length}/32 models. {provider === "sagemaker" ? "Use exact model aliases configured for this SageMaker binding; no wildcards." : "Exact API names only; no aliases or wildcards."}</p>

    <details className="ai-provider-mappings ai-gateway-disclosure"><summary>Model mappings</summary><div className="ai-provider-table-scroll"><table><caption className="sr-only">Model mapping preview</caption><thead><tr><th>Gateway model name</th><th>Upstream model name</th><th>Mode</th></tr></thead><tbody>{chosen.map((model) => {
      const prefix = connection ? `custom-${connection.id}/` : "";
      const upstream = usesEndpoint ? (prefix && model.startsWith(prefix) ? model.slice(prefix.length) : model) : model.slice((provider?.length ?? 0) + 1);
      const gateway = usesEndpoint ? (connection ? `${prefix}${upstream}` : "Assigned when saved") : model;
      return <tr key={model}><td title={gateway}>{modelDisplayName(gateway)}</td><td>{upstream}</td><td><select aria-label={`Mode for ${model}`} value={modelMode(model)} onChange={(e) => setSelectedModes((current) => ({ ...current, [model]: e.target.value as ModelMode }))}>{modelModes.map((item) => <option key={item.value} value={item.value} disabled={!supportedModes.includes(item.value)}>{item.label.split(", ")[0]}{!supportedModes.includes(item.value) ? ", unavailable" : ""}</option>)}</select></td></tr>;
    })}</tbody></table>{!chosen.length && <p className="ai-provider-mapping-empty">Select models to preview their names.</p>}{usesEndpoint && !connection && <p>Gateway model names are assigned when these credentials are saved.</p>}</div></details>


    </div>
    {wizard && step === 2 && chosen.length > 0 && !valid && <div role="alert"><ul>{validationIssues.map(issue => <li key={issue}>{issue}</li>)}</ul></div>}
    <div className="ai-wizard-section" hidden={!modelOnly || step !== 3}>
    {wizard && <dl className="ai-wizard-review tnx-resource-facts"><div><dt>Provider</dt><dd><span className="ai-gateway-provider-brand">{provider && <ProviderLogo provider={provider} />}<span>{providerLabel}</span></span></dd></div><div><dt>Credential</dt><dd>{savedName}</dd></div><div className="tnx-resource-fact-wide"><dt>Models</dt><dd>{finalModels.map(model => `${modelDisplayName(model)} (${modeLabel(modelMode(model)).split(", ")[0]})`).join(", ")}</dd></div><div><dt>Credentials</dt><dd>{(modelOnly && connection ? connection.enabled : enabled) ? "Enabled" : "Disabled"}</dd></div></dl>}
    {needsTest && <div className="ai-provider-preflight"><p>Tests every selected model. Provider charges may apply.<HelpTooltip>Each model receives one request for its selected operation. Tests are excluded from gateway usage totals. Results expire after five minutes. A successful video test confirms job acceptance only.</HelpTooltip></p><ul aria-label="Model test results">{chosen.map(model => <li key={model}><strong>{modelDisplayName(model)}</strong> · {modeLabel(modelMode(model)).split(", ")[0]} · {modelResults[model] ?? "Not tested"}</li>)}</ul>{testBlockers.length > 0 && <div id={testHelpId} role="status" aria-label="Test Connect requirements"><p>To enable Test Connect:</p><ul>{testBlockers.map((message) => <li key={message}>{message}</li>)}</ul></div>}{testStatus === "success" && <p role="status">Test succeeded for all {chosen.length} selected models. {probeMode === "video_generation" ? "Video job accepted; generation is not yet complete." : "You can now save this model configuration."}</p>}{testStatus === "error" && <p role="alert">{testFailure.title}. {testFailure.description}</p>}</div>}
    </div>
  </form></div>
  );
  return <Modal title={modelOnly ? "Add Model" : connection ? "Edit credentials" : "Add Credentials"} placement="right" size="wide" showClose onDismiss={dismiss} actions={actions}>{error && <p role="alert" className="ai-provider-alert">{error}</p>}{editor}</Modal>;
}
