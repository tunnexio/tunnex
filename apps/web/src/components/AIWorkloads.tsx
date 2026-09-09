import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { api, loadOne } from "../lib/api";
import { Badge, Button, Card, DataTable, Field, Input, Loading, Modal, Select } from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";
import { toast } from "./Toasts";
import "./ai-provider-workspace.css";

type S = components["schemas"];
type Workload = S["AIWorkload"];
type Model = S["AIWorkloadModel"];
type EnrollmentKey = S["AIWorkloadEnrollmentKey"];
type Inventory = { workloads: Workload[]; providers: S["AIProviderConnection"][] };
const workloadPath = "/api/v1/organizations/{orgId}/ai-gateway/workloads";
const keyPath = "/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/enrollment-keys";
const instancePath = "/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/instances";
const command = "tunnex workload run --config /run/secrets/tunnex/workload.json -- python agent.py";
const date = (value: string) => new Date(value).toLocaleString();
const modelKey = (m: Model) => JSON.stringify([m.connection_id, m.model]);
const stateLabel = (w: Workload) => !w.enabled ? "Disabled" : w.status === "applied" && w.applied_revision === w.revision ? "Applied" : w.status === "error" ? "Provisioning failed" : w.status === "revoked" ? "Revoked" : "Pending provisioning";

function download(filename: string, contents: string) {
  const url = URL.createObjectURL(new Blob([contents], { type: "text/plain;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function AIWorkloads(props: { orgId: string; canManage: boolean }) {
  // Remount on tenant or permission changes, discarding pending dialogs and secrets.
  return <WorkloadsPanel key={`${props.orgId}:${props.canManage}`} {...props} />;
}

function WorkloadsPanel({ orgId, canManage }: { orgId: string; canManage: boolean }) {
  const [data, setData] = useState<Inventory | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState("");
  const [search, setSearch] = useState("");
  const [editor, setEditor] = useState<Workload | "new" | null>(null);
  const alive = useRef(true), generation = useRef(0);
  async function reload() {
    const n = ++generation.current;
    setLoading(true);
    const params = { params: { path: { orgId } } };
    const [w, p] = await Promise.all([
      loadOne(() => api.GET(workloadPath, params)),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", params)),
    ]);
    if (!alive.current || n !== generation.current) return;
    if (!w.ok || !p.ok) {
      setError("Could not load workloads and configured models. Refresh to try again.");
      setData(null);
    } else {
      setData({ workloads: w.data, providers: p.data.items });
      setSelectedId((id) => w.data.some((v) => v.id === id) ? id : "");
    }
    setLoading(false);
  }
  useEffect(() => {
    alive.current = true; void reload();
    return () => { alive.current = false; generation.current++; };
  }, [orgId]);
  const selected = data?.workloads.find((w) => w.id === selectedId);
  const rows = data?.workloads.filter((w) => `${w.name} ${w.models.map((m) => m.model).join(" ")} ${stateLabel(w)}`.toLowerCase().includes(search.trim().toLowerCase())) ?? [];
  return <section aria-label="Workload model access" className="space-y-5">
    {error && <p role="alert" className="ai-provider-alert">{error}</p>}
    {!canManage && <p className="text-sm text-ink-secondary">Read-only access. An AI administrator manages workloads and enrollment.</p>}
    {selected ? <WorkloadDetail key={`${orgId}:${selected.id}`} orgId={orgId} workload={selected} providers={data!.providers} canManage={canManage} refreshing={loading} onBack={() => setSelectedId("")} onEdit={() => setEditor(selected)} onRefresh={async () => { setError(""); await reload(); }} /> : <>
      <div className="ai-provider-panel-heading">
        <div><h2 className="text-title font-semibold text-ink-heading">Workloads</h2><p className="mt-1 text-sm text-ink-secondary">Model access for your applications and their replicas.</p></div>
        <div className="flex flex-wrap gap-2"><Button disabled={loading || editor !== null} onClick={() => { setError(""); void reload(); }}>Refresh workloads</Button>{canManage && <Button disabled={!data || loading} onClick={() => setEditor("new")}>Create workload</Button>}</div>
      </div>
      <Card>
        <div className="mb-4 max-w-md"><Field label="Search workloads"><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Workload name or model" /></Field></div>
        {loading ? <Loading label="Loading workloads…" /> : data && <DataTable caption="Workloads" rows={rows} rowKey={(w) => w.id} failed={false} filterable={false}
          empty={data.workloads.length ? "No workloads match your search." : "No workloads yet. Create one, choose its models, then connect your application."}
          columns={[
            { key: "name", header: "Workload", sortValue: (w) => w.name, cell: (w) => <button className="text-left font-medium text-ink-heading underline decoration-ink-secondary underline-offset-4" aria-label={`Open ${w.name}`} onClick={() => setSelectedId(w.id)}>{w.name}</button> },
            { key: "models", header: "Models", sortValue: (w) => w.models.length, cell: (w) => w.models.length },
            { key: "state", header: "Access state", sortValue: stateLabel, cell: (w) => <Badge tone="neutral">{stateLabel(w)}</Badge> },
            { key: "threshold", header: "Daily soft threshold", cell: (w) => w.daily_usd_threshold == null ? "None" : `$${w.daily_usd_threshold}` },
          ]} />}
      </Card>
    </>}
    {editor && data && canManage && <WorkloadEditor orgId={orgId} workload={editor === "new" ? undefined : editor} providers={data.providers} onDismiss={() => setEditor(null)} onConflict={() => {
      if (!alive.current) return;
      setEditor(null); setError("Another administrator changed this workload. Saved state has been refreshed; reopen Edit access to review and retry."); void reload();
    }} onSaved={(w) => {
      if (!alive.current) return;
      generation.current++;
      setData((current) => current ? { ...current, workloads: [...current.workloads.filter((v) => v.id !== w.id), w] } : current);
      setSelectedId(w.id); setEditor(null); setLoading(false); setError("");
      if (w.enabled && (w.status === "error" || w.status === "revoked")) setError("The workload was saved, but access is unavailable. Check its provisioning state before connecting.");
      else toast.success(!w.enabled ? "Workload disabled" : stateLabel(w) === "Applied" ? "Workload access applied" : "Workload saved; provisioning is pending");
    }} />}
  </section>;
}

function WorkloadEditor({ orgId, workload, providers, onDismiss, onSaved, onConflict }: {
  orgId: string; workload?: Workload; providers: S["AIProviderConnection"][];
  onDismiss: () => void; onSaved: (w: Workload) => void; onConflict: () => void;
}) {
  const formId = useId();
  const [name, setName] = useState(workload?.name ?? "");
  const [enabled, setEnabled] = useState(workload?.enabled ?? true);
  const [models, setModels] = useState<Model[]>(workload?.models ?? []);
  const [threshold, setThreshold] = useState(workload?.daily_usd_threshold?.toString() ?? "");
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const available = providers.filter((p) => p.enabled && p.status === "applied" && p.revision === p.applied_revision).flatMap((p) => p.models.map((model) => ({ connection_id: p.id, model, mode: p.model_modes?.[model] ?? "chat", name: p.name, available: true })));
  const choices = [...available, ...(workload?.models ?? []).filter((m) => !available.some((v) => modelKey(v) === modelKey(m))).map((m) => ({ ...m, name: "Unavailable connection", available: false }))];
  function configuredMode(model: Model) {
    const credential = providers.find((p) => p.id === model.connection_id && p.models.includes(model.model));
    return credential ? credential.model_modes?.[model.model] ?? "chat" : undefined;
  }
  const outdatedModes = models.filter((m) => configuredMode(m) !== undefined && configuredMode(m) !== m.mode);
  const visibleChoices = choices.filter((m) => `${m.model} ${m.name}`.toLowerCase().includes(search.trim().toLowerCase()));
  const credentials = new Set(models.map((m) => m.connection_id));
  const modelsValid = models.length <= 32 && credentials.size <= 8 && new Set(models.map((m) => m.model)).size === models.length;
  const thresholdValid = threshold.trim() === "" || Number.isFinite(Number(threshold)) && Number(threshold) > 0 && Number(threshold) <= 100000;
  const valid = !!name.trim() && name.trim().length <= 100 && thresholdValid && modelsValid && outdatedModes.length === 0;
  async function save(event: FormEvent) {
    event.preventDefault(); if (busy || !valid) return;
    setBusy(true); setError("");
    const body: S["AIWorkloadInput"] = { name: name.trim(), enabled, models, daily_usd_threshold: threshold.trim() === "" ? null : Number(threshold), expected_revision: workload?.revision ?? 0 };
    try {
      const result = workload
        ? await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}", { params: { path: { orgId, workloadId: workload.id } }, body })
        : await api.POST(workloadPath, { params: { path: { orgId } }, body });
      if (!alive.current) return;
      if (result.response?.status === 409) { onConflict(); return; }
      if (result.error || !result.data) { setError("Could not save workload access. Check the configured models and refresh before retrying."); return; }
      onSaved(result.data);
    } catch { if (alive.current) setError("Could not confirm the change. Refresh workloads before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title={workload ? "Edit workload access" : "Create workload"} placement="right" size="wide" showClose onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button type="button" disabled={busy} onClick={onDismiss}>Cancel</Button><Button type="submit" form={formId} disabled={busy || !valid}>{busy ? "Saving…" : workload ? "Save workload" : "Create workload"}</Button></>}>
    <form id={formId} onSubmit={(event) => void save(event)} className="ai-provider-editor">
      <Field label="Workload name"><Input autoFocus maxLength={100} required value={name} disabled={busy} placeholder="production/support-bot" onChange={(event) => setName(event.target.value)} /></Field>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} disabled={busy} onChange={(event) => setEnabled(event.target.checked)} />Enable workload access</label>
      {!enabled && <p className="ai-provider-notice">Disabling blocks new enrollments and model calls, and permanently revokes every enrollment key. To connect new replicas, create new enrollment keys after re-enabling. Existing instances need fresh tokens; old tokens stay invalid. Accepted requests may finish.</p>}
      <fieldset className="space-y-3"><legend className="mb-2 text-sm font-semibold">Allowed configured models</legend><p className="text-xs text-ink-secondary">Choose up to 32 models across 8 credentials. Each model uses one credential. With none selected, model calls are denied.</p>
        <Field label="Search models"><Input value={search} disabled={busy} onChange={(event) => setSearch(event.target.value)} placeholder="Model ID or credential name" /></Field>
        <p className="text-xs text-ink-secondary">{models.length} / 32 models · {credentials.size} / 8 credentials</p>
        <div className="ai-config-provider-options max-h-64 overflow-y-auto">{visibleChoices.map((m) => {
          const selected = models.find((v) => modelKey(v) === modelKey(m));
          const checked = !!selected;
          const currentMode = configuredMode(m) ?? m.mode;
          const outdated = selected && selected.mode !== currentMode;
          const reason = checked ? "" : !m.available ? "Restore this credential to select it." : models.some((v) => v.model === m.model) ? "Selected with another credential. Remove that selection to switch." : models.length >= 32 ? "32-model limit reached." : !credentials.has(m.connection_id) && credentials.size >= 8 ? "8-credential limit reached." : "";
          return <label key={modelKey(m)}><input type="checkbox" aria-label={`${m.model} on ${m.name}`} checked={checked} disabled={busy || !!reason} onChange={(event) => {
            const add = event.target.checked;
            setModels((current) => {
              if (!add) return current.filter((v) => modelKey(v) !== modelKey(m));
              const used = new Set(current.map((v) => v.connection_id));
              if (!m.available || current.length >= 32 || current.some((v) => v.model === m.model) || !used.has(m.connection_id) && used.size >= 8) return current;
              return [...current, { connection_id: m.connection_id, model: m.model, mode: m.mode }];
            });
          }} /><span className="min-w-0 break-all">{m.model}<small>{m.name}{!outdated && ` · ${m.mode.replace(/_/g, " ")}`}</small>{outdated && <small>Saved mode: {selected.mode.replace(/_/g, " ")}. Current mode: {currentMode.replace(/_/g, " ")}. Remove and reselect this model to use its current mode.</small>}{reason && <small>{reason}</small>}{checked && !m.available && <small>Remove this unavailable grant or restore its credential.</small>}</span></label>;
        })}{!visibleChoices.length && <p className="text-sm text-ink-secondary">{choices.length ? "No models match your search." : "No applied credentials are available. Configure a model in Models & endpoints first."}</p>}</div>
        {!modelsValid && <p role="alert" className="text-sm text-danger">Select at most 32 models across 8 credentials, using one credential per model.</p>}
        {outdatedModes.length > 0 && <p role="alert" className="text-sm text-danger">Some selected models use an outdated mode. Remove and reselect them before saving.</p>}
      </fieldset>
      <Field label="Daily USD soft threshold (optional)"><Input type="number" min="0.000000001" max="100000" step="any" value={threshold} disabled={busy} placeholder="No threshold" onChange={(event) => setThreshold(event.target.value)} /></Field>
      <p className="text-xs text-ink-secondary">Observed spend is shared across all instances and resets at midnight UTC. New calls are refused at the threshold; concurrent calls may overshoot. Missing price or cost data can also block calls.</p>
      {!thresholdValid && <p role="alert" className="text-sm text-danger">Enter a positive USD amount up to 100,000, or leave it empty.</p>}
      {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    </form>
  </Modal>;
}

function WorkloadDetail({ orgId, workload, providers, canManage, refreshing, onBack, onEdit, onRefresh }: {
  orgId: string; workload: Workload; providers: S["AIProviderConnection"][]; canManage: boolean; refreshing: boolean;
  onBack: () => void; onEdit: () => void; onRefresh: () => Promise<void>;
}) {
  const tabs = ["Overview", "Enrollment keys", "Instances"] as const;
  const [tab, setTab] = useState<typeof tabs[number]>("Overview");
  const tabId = useId();
  const [keys, setKeys] = useState<S["AIWorkloadKeyPage"] | null>(null), [instances, setInstances] = useState<S["AIWorkloadInstancePage"] | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [moreKeys, setMoreKeys] = useState(false), [moreInstances, setMoreInstances] = useState(false);
  const [createKey, setCreateKey] = useState(false), [secret, setSecret] = useState<S["AIWorkloadKeySecret"] | null>(null);
  const [revokeKey, setRevokeKey] = useState<EnrollmentKey | null>(null), [revokeInstances, setRevokeInstances] = useState(false);
  const [revokeInstance, setRevokeInstance] = useState<S["AIWorkloadInstance"] | null>(null);
  const alive = useRef(true), generation = useRef(0);
  const path = { orgId, workloadId: workload.id };
  async function reload() {
    const n = ++generation.current; setLoading(true); setMoreKeys(false); setMoreInstances(false);
    const [k, i] = await Promise.all([loadOne(() => api.GET(keyPath, { params: { path, query: { limit: 50 } } })), loadOne(() => api.GET(instancePath, { params: { path, query: { limit: 50 } } }))]);
    if (!alive.current || n !== generation.current) return;
    setKeys(k.ok ? k.data : null); setInstances(i.ok ? i.data : null);
    if (!k.ok || !i.ok) setError("Could not load enrollment keys or instances. Refresh connection details to retry.");
    setLoading(false);
  }
  useEffect(() => { alive.current = true; void reload(); return () => { alive.current = false; generation.current++; }; }, [orgId, workload.id, workload.revision, workload.enabled]);
  async function refresh() {
    setError("");
    await onRefresh();
    if (alive.current) await reload();
  }
  async function nextKeys() {
    if (!keys?.next_cursor || moreKeys || loading || busy) return;
    const after = keys.next_cursor, n = generation.current; setMoreKeys(true);
    const result = await loadOne(() => api.GET(keyPath, { params: { path, query: { after, limit: 50 } } }));
    if (!alive.current || n !== generation.current) return;
    if (!result.ok || result.data.next_cursor === after) setError("Could not load more enrollment keys. Retry loading more keys.");
    else setKeys((current) => current ? { ...result.data, items: [...new Map([...current.items, ...result.data.items].map((item) => [item.id, item])).values()] } : current);
    setMoreKeys(false);
  }
  async function nextInstances() {
    if (!instances?.next_cursor || moreInstances || loading || busy) return;
    const after = instances.next_cursor, n = generation.current; setMoreInstances(true);
    const result = await loadOne(() => api.GET(instancePath, { params: { path, query: { after, limit: 50 } } }));
    if (!alive.current || n !== generation.current) return;
    if (!result.ok || result.data.next_cursor === after) setError("Could not load more instances. Retry loading more instances.");
    else setInstances((current) => current ? { ...result.data, items: [...new Map([...current.items, ...result.data.items].map((item) => [item.id, item])).values()] } : current);
    setMoreInstances(false);
  }
  async function revoke() {
    if (!canManage || busy || !revokeKey && !revokeInstance) return;
    setBusy(true); setError("");
    try {
      const result = revokeKey
        ? await api.POST("/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/enrollment-keys/{keyId}/revoke", { params: { path: { ...path, keyId: revokeKey.id } }, body: { revoke_instances: revokeInstances } })
        : await api.POST("/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/instances/{instanceId}/revoke", { params: { path: { ...path, instanceId: revokeInstance!.id } } });
      if (!alive.current) return;
      if (result.error || result.response.status !== 204) { setError("Could not confirm revocation. Refresh connection details before retrying."); return; }
      toast.success(revokeKey ? revokeInstances ? "Enrollment key and its instances revoked" : "Enrollment key revoked" : "Instance revoked");
      setRevokeKey(null); setRevokeInstance(null); await reload();
    } catch { if (alive.current) setError("Could not confirm revocation. Refresh connection details before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  const config = JSON.stringify({ server: window.location.origin, enrollment_key_file: "/run/secrets/tunnex/enrollment-key", state_directory: "/var/lib/tunnex-workload" }, null, 2) + "\n";
  const instructions = `Connect ${workload.name}\n\nProvision workload.json and the enrollment-key file as regular, non-symlink files with permissions 0600, owned by the application user. Each replica needs its own private writable state directory (0700); never share or image instance keys. If your deployment secret store provides symlinks, provision protected regular files before starting the CLI.\n\n${config}\n${command}\n\nPermitted configured models:\n${workload.models.map((m) => `${m.model} (${m.mode})`).join("\n")}\n\nUse a reusable enrollment key for autoscaling. Before expiry, create a replacement, update the provisioned secret, verify a fresh replica enrolls, then revoke the previous key. Revoking an enrollment key alone does not revoke existing instances. Disabling the workload permanently revokes every enrollment key; create replacement keys after re-enabling.\n`;
  const locked = busy || loading || refreshing || createKey || !!secret || !!revokeKey || !!revokeInstance;
  return <section aria-label={`Connection details for ${workload.name}`} className="space-y-5">
    <Button aria-label="Back to workloads" disabled={busy || createKey || !!secret || !!revokeKey || !!revokeInstance} onClick={onBack}>← Back to workloads</Button>
    <div className="ai-provider-panel-heading">
      <div className="min-w-0"><h2 className="break-words text-title font-semibold text-ink-heading">{workload.name}</h2><div className="mt-2"><Badge tone="neutral">{stateLabel(workload)}</Badge></div></div>
      <div className="flex flex-wrap gap-2"><Button disabled={locked} onClick={() => void refresh()}>Refresh workload</Button>{canManage && <Button disabled={locked} onClick={onEdit}>Edit access</Button>}</div>
    </div>
    {!workload.enabled && <p className="ai-provider-notice">This workload is disabled and its enrollment keys are permanently revoked. After re-enabling, create new enrollment keys for new replicas. Existing instances require fresh tokens.</p>}
    {workload.enabled && stateLabel(workload) !== "Applied" && <p className="ai-provider-notice">The saved policy is not applied. Model access is unavailable until provisioning succeeds. Use Refresh workload to check its state.</p>}
    {error && <p role="alert" className="ai-provider-alert">{error}</p>}
    <div className="ai-provider-view-tabs" role="tablist" aria-label="Workload details">
      {tabs.map((label, index) => <button key={label} type="button" role="tab" id={`${tabId}-tab-${index}`} aria-controls={`${tabId}-panel-${index}`} aria-selected={tab === label} tabIndex={tab === label ? 0 : -1} onClick={() => setTab(label)} onKeyDown={(event) => {
        const next = event.key === "ArrowRight" ? (index + 1) % tabs.length : event.key === "ArrowLeft" ? (index + tabs.length - 1) % tabs.length : event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : -1;
        if (next >= 0) { event.preventDefault(); setTab(tabs[next]); document.getElementById(`${tabId}-tab-${next}`)?.focus(); }
      }}>{label}</button>)}
    </div>
    <div role="tabpanel" id={`${tabId}-panel-${tabs.indexOf(tab)}`} aria-labelledby={`${tabId}-tab-${tabs.indexOf(tab)}`} className="space-y-5">
      {tab === "Overview" && <>
        <Card>
          <div className="mb-4"><h3 className="font-semibold text-ink-heading">Model access</h3><p className="mt-1 text-sm text-ink-secondary">Every replica inherits these models.{workload.daily_usd_threshold != null && ` Daily soft threshold: $${workload.daily_usd_threshold}, shared across replicas.`}</p></div>
          <DataTable caption="Allowed workload models" rows={workload.models} rowKey={modelKey} failed={false} filterable={false} empty="No models selected. Model calls are denied." columns={[
            { key: "model", header: "API model ID", cell: (m) => <code className="break-all text-xs">{m.model}</code> },
            { key: "credential", header: "Credential", cell: (m) => providers.find((p) => p.id === m.connection_id)?.name ?? "Unavailable credential" },
            { key: "mode", header: "Mode", cell: (m) => m.mode.replace(/_/g, " ") },
          ]} />
        </Card>
        <Card>
          <h3 className="font-semibold text-ink-heading">Connect application</h3>
          <p className="mt-1 text-sm text-ink-secondary">Create an enrollment key, download the configuration, then start your application with the Tunnex CLI.</p>
          <div className="my-4 flex flex-wrap gap-2"><Button onClick={() => setTab("Enrollment keys")}>Manage enrollment keys</Button><Button onClick={() => download("workload.json", config)}>Download configuration</Button><Button onClick={() => download("workload-instructions.txt", instructions)}>Download instructions</Button></div>
          <pre className="overflow-x-auto rounded-md border border-line bg-surface-inset p-3 text-xs text-ink-body">{command}</pre>
          <details className="mt-4 text-sm text-ink-secondary"><summary className="cursor-pointer text-ink-heading">Deployment setup</summary><div className="mt-3 space-y-3">
            <p>Provision configuration and enrollment secrets as regular files owned by the application user (0600). Give each replica its own private state directory (0700); never share or copy instance keys.</p>
            <p>The configuration references /run/secrets/tunnex/enrollment-key. Deliver that secret separately through your deployment secret store. If it mounts symlinks, provision protected regular files before starting the CLI.</p>
            <p>Gateway endpoint: <code className="break-all">{window.location.origin}/ai/v1</code>. No human login or network device is required.</p>
          </div></details>
        </Card>
      </>}
      {tab === "Enrollment keys" && <Card>
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3"><div><h3 className="font-semibold text-ink-heading">Enrollment keys</h3><p className="mt-1 text-sm text-ink-secondary">Introduce new replicas. Existing instances keep their own credentials.</p></div>{canManage && <Button disabled={locked || !workload.enabled} onClick={() => setCreateKey(true)}>Create enrollment key</Button>}</div>
        {loading ? <Loading label="Loading enrollment keys…" /> : keys && <>
          <DataTable caption="Enrollment keys" rows={keys.items} rowKey={(k) => k.id} failed={false} filterable={false} pageSize={0} empty="No enrollment keys yet." columns={[
            { key: "name", header: "Name", cell: (k) => <><span className="font-medium text-ink-heading">{k.name}</span><code className="mt-1 block break-all text-xs text-ink-secondary">{k.id}</code></> },
            { key: "type", header: "Type", cell: (k) => <>{k.reusable ? "Reusable" : "Single-use"}<span className="block text-xs text-ink-secondary">{k.ephemeral ? "Ephemeral instances" : "Durable instances"}</span></> },
            { key: "uses", header: "Uses", cell: (k) => `${k.uses} / ${k.max_uses === 0 ? "Unlimited" : k.max_uses}` },
            { key: "expiry", header: "Expires", cell: (k) => date(k.expires_at) },
            { key: "state", header: "State", cell: (k) => <Badge tone="neutral">{k.revoked_at ? "Revoked" : new Date(k.expires_at).getTime() <= Date.now() ? "Expired" : k.max_uses > 0 && k.uses >= k.max_uses ? "Exhausted" : "Active"}</Badge> },
            ...(canManage ? [{ key: "actions", header: "Actions", cell: (k: EnrollmentKey) => <Button size="sm" variant="danger" disabled={busy || refreshing} aria-label={k.revoked_at ? `Revoke instances from ${k.name}` : `Revoke enrollment key ${k.name}`} onClick={() => { setRevokeInstances(!!k.revoked_at); setRevokeKey(k); }}>{k.revoked_at ? "Revoke instances" : "Revoke key"}</Button> }] : []),
          ]} />
          {keys.next_cursor && <Button className="mt-3" disabled={moreKeys || busy} onClick={() => void nextKeys()}>{moreKeys ? "Loading keys…" : "Load more keys"}</Button>}
        </>}
        <details className="mt-4 text-sm text-ink-secondary"><summary className="cursor-pointer text-ink-heading">Rotate an enrollment key</summary><p className="mt-3">Before expiry, create a replacement key, update your deployment secret, verify a fresh replica, then revoke the old key. Total uses count successful enrollments, not active replicas.</p></details>
      </Card>}
      {tab === "Instances" && <Card>
        <div className="mb-4"><h3 className="font-semibold text-ink-heading">Instances</h3><p className="mt-1 text-sm text-ink-secondary">Each replica has its own identity. Offline reports contact state; revocation blocks its next authentication and request.</p></div>
        {loading ? <Loading label="Loading instances…" /> : instances && <>
          <DataTable caption="Workload instances" rows={instances.items} rowKey={(i) => i.id} failed={false} filterable={false} pageSize={0} empty="Awaiting enrollment. No instances have joined this workload." columns={[
            { key: "id", header: "Instance", cell: (i) => <code className="break-all text-xs">{i.id}</code> },
            { key: "origin", header: "Enrollment key", cell: (i) => <>{keys?.items.find((k) => k.id === i.enrollment_key_id)?.name}<code className="mt-1 block break-all text-xs text-ink-secondary">{i.enrollment_key_id}</code></> },
            { key: "lifecycle", header: "Lifecycle", cell: (i) => i.ephemeral ? "Ephemeral" : "Durable" },
            { key: "state", header: "State", cell: (i) => <Badge tone="neutral">{i.state}</Badge> },
            { key: "contact", header: "Last authenticated contact", cell: (i) => date(i.last_contact_at) },
            ...(canManage ? [{ key: "actions", header: "Actions", cell: (i: S["AIWorkloadInstance"]) => (i.state === "active" || i.state === "offline") ? <Button size="sm" variant="danger" disabled={busy || refreshing} aria-label={`Revoke instance ${i.id}`} onClick={() => setRevokeInstance(i)}>Revoke</Button> : null }] : []),
          ]} />
          {instances.next_cursor && <Button className="mt-3" disabled={moreInstances || busy} onClick={() => void nextInstances()}>{moreInstances ? "Loading instances…" : "Load more instances"}</Button>}
        </>}
      </Card>}
    </div>
    {createKey && canManage && <EnrollmentKeyEditor orgId={orgId} workloadId={workload.id} onDismiss={() => setCreateKey(false)} onCreated={(value) => { if (!alive.current) return; setSecret(value); setCreateKey(false); void reload(); }} />}
    {secret && canManage && <OneTimeSecretModal title="Save enrollment key" caption="Shown once. Deliver it through your deployment’s secret store. Never put it in command arguments, logs or an image." secret={secret.secret} downloadFilename="enrollment-key" copyLabel="Copy key" requireAck="I saved this key securely." onDismiss={() => setSecret(null)}><p className="mt-3 text-xs text-ink-secondary">{secret.key.name} · expires {date(secret.key.expires_at)}. The configuration references /run/secrets/tunnex/enrollment-key.</p></OneTimeSecretModal>}
    {(revokeKey || revokeInstance) && canManage && <Modal title={revokeKey?.revoked_at ? "Revoke enrolled instances" : revokeKey ? "Revoke enrollment key" : "Revoke instance"} danger onDismiss={() => { if (!busy) { setRevokeKey(null); setRevokeInstance(null); } }} actions={<><Button disabled={busy} onClick={() => { setRevokeKey(null); setRevokeInstance(null); }}>Cancel</Button><Button disabled={busy} onClick={() => void revoke()}>{busy ? "Revoking…" : "Confirm revocation"}</Button></>}>
      {revokeKey ? <div className="space-y-3 text-sm">
        {revokeKey.revoked_at ? <p>This enrollment key is already revoked. Revoke every instance introduced by {revokeKey.name}? Instances enrolled with other keys continue.</p> : <><p>Revoke {revokeKey.name} to stop new enrollments. Existing instances keep their credentials unless you also revoke them.</p><label className="flex items-start gap-2"><input className="mt-1" type="checkbox" checked={revokeInstances} disabled={busy} onChange={(event) => setRevokeInstances(event.target.checked)} />Also revoke every instance enrolled with this key</label></>}
        {revokeInstances && <p className="text-ink-secondary">All instances introduced by this key will lose access. Instances enrolled with other keys continue.</p>}
      </div> : <p className="text-sm">Revoke instance <code>{revokeInstance?.id}</code>? Its next token issuance and model request will be denied. Other replicas continue. A valid reusable enrollment key can still introduce new instances.</p>}
      {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
    </Modal>}
  </section>;
}

function EnrollmentKeyEditor({ orgId, workloadId, onDismiss, onCreated }: { orgId: string; workloadId: string; onDismiss: () => void; onCreated: (value: S["AIWorkloadKeySecret"]) => void }) {
  const formId = useId();
  const [name, setName] = useState("Autoscaling deployment"), [reusable, setReusable] = useState(true), [ephemeral, setEphemeral] = useState(true);
  const [days, setDays] = useState("30"), [maxUses, setMaxUses] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const useLimit = reusable ? maxUses.trim() === "" ? 0 : Number(maxUses) : 1;
  const validity = reusable ? Number(days) : 1;
  const valid = !!name.trim() && Number.isInteger(validity) && validity >= 1 && validity <= 90 && Number.isSafeInteger(useLimit) && useLimit >= 0;
  async function create(event: FormEvent) {
    event.preventDefault(); if (busy || !valid) return;
    setBusy(true); setError("");
    const body: S["AIWorkloadKeyInput"] = { name: name.trim(), reusable, ephemeral, expires_at: new Date(Date.now() + validity * 86400000).toISOString(), max_uses: useLimit };
    try {
      const result = await api.POST(keyPath, { params: { path: { orgId, workloadId } }, body });
      if (!alive.current) return;
      if (result.error || !result.data) { setError("Could not confirm key creation. Refresh enrollment keys before creating another."); return; }
      onCreated(result.data);
    } catch { if (alive.current) setError("Could not confirm key creation. Refresh enrollment keys before creating another."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title="Create enrollment key" placement="right" showClose onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button type="button" disabled={busy} onClick={onDismiss}>Cancel</Button><Button type="submit" form={formId} disabled={busy || !valid}>{busy ? "Creating…" : "Create key"}</Button></>}><form id={formId} onSubmit={(event) => void create(event)} className="space-y-4">
    <Field label="Key name"><Input maxLength={100} required value={name} disabled={busy} onChange={(event) => setName(event.target.value)} /></Field>
    <Field label="Enrollment type"><Select value={reusable ? "reusable" : "single"} disabled={busy} onChange={(event) => { const value = event.target.value === "reusable"; setReusable(value); setDays(value ? "30" : "1"); setName(value ? "Autoscaling deployment" : "Single instance"); }}><option value="reusable">Autoscaling deployment · reusable</option><option value="single">Single instance · one use</option></Select></Field>
    {reusable ? <><Field label="Validity in days"><Input type="number" min={1} max={90} step={1} required value={days} disabled={busy} onChange={(event) => setDays(event.target.value)} /></Field><Field label="Total enrollment limit (optional)"><Input type="number" min={0} step={1} value={maxUses} disabled={busy} placeholder="Unlimited" onChange={(event) => setMaxUses(event.target.value)} /></Field><p className="text-xs text-ink-secondary">Leave empty or use zero for unlimited successful enrollments during the key lifetime. This is not a concurrent replica limit.</p></> : <p className="text-sm">Expires in 24 hours and permits one successful enrollment. Use a reusable key for autoscaling.</p>}
    <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="checkbox" checked={ephemeral} disabled={busy} onChange={(event) => setEphemeral(event.target.checked)} />Create ephemeral instances</label><p className="text-xs text-ink-secondary">Ephemeral instances follow the deployment’s inactivity retirement policy. Durable instances remain until explicitly retired or revoked.</p>
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
  </form></Modal>;
}
