import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { Badge, Button, Card, DataTable, Field, Input, Loading, Modal, RefreshButton, Switch, type BadgeTone } from "./ui";
import { toast } from "./Toasts";
import AppAccessRowMenu from "./AppAccessRowMenu";
import AppAccessEmptyState from "./AppAccessEmptyState";
import { downloadInternalCA, expiresSoon, internalEndpointsPath, isIPv4, isIPv4CIDR, parseList, staticKeySettingsPath } from "./AIWorkloadStaticKeys";

type S = components["schemas"];
type Endpoint = S["AIInternalEndpoint"];
type TLSMode = S["AIInternalEndpointTLSMode"];
const endpointPath = "/api/v1/organizations/{orgId}/ai-gateway/internal-endpoints/{nodeId}" as const;
const date = (value: string) => new Date(value).toLocaleString();
const area = "min-h-20 w-full rounded-md border border-line bg-transparent px-3 py-2 font-mono text-xs text-ink-heading placeholder:text-ink-secondary disabled:opacity-50";
export const UPGRADE_MESSAGE = "Upgrade this gateway to use the internal AI endpoint";

export function endpointStatus(e: Endpoint): { label: string; tone: BadgeTone } {
  if (!e.supported) return { label: UPGRADE_MESSAGE, tone: "warn" };
  if (!e.endpoint) return { label: "Not set up", tone: "neutral" };
  if (!e.endpoint.enabled) return { label: "Turned off", tone: "neutral" };
  if (e.error) return { label: `Error: ${e.error}`, tone: "danger" };
  if (e.ready) return { label: "Ready", tone: "ok" };
  return { label: "Not serving", tone: "warn" };
}

function endpointError(result: { error?: unknown; response?: Response }, fallback: string): string {
  const code = apiErrorCode(result.error), status = result.response?.status;
  if (code === "ai_internal_endpoint_unsupported") return `${UPGRADE_MESSAGE}.`;
  if (code === "ai_internal_endpoint_address_unapproved") return "Use the gateway's tunnel address, or one address inside an approved subnet of the gateway's site.";
  if (status === 409) return "Someone else changed this endpoint. The list was refreshed; review it and try again.";
  if (status === 400) return apiErrorMessage(result.error, "Check the endpoint settings and try again.");
  return fallback;
}

export function AIInternalEndpointSettings(props: { orgId: string; canEdit: boolean }) {
  return <EndpointSettings key={`${props.orgId}:${props.canEdit}`} {...props} />;
}

function EndpointSettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [endpoints, setEndpoints] = useState<Endpoint[] | null>(null);
  const [publicAllowed, setPublicAllowed] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true), [error, setError] = useState(""), [switchBusy, setSwitchBusy] = useState(false), [switchError, setSwitchError] = useState("");
  const [editor, setEditor] = useState<Endpoint | null>(null), [remove, setRemove] = useState<Endpoint | null>(null), [rowBusy, setRowBusy] = useState(false);
  const [caBusy, setCaBusy] = useState(false), [caError, setCaError] = useState("");
  const alive = useRef(true), generation = useRef(0);
  async function reload() {
    const n = ++generation.current; setLoading(true); setError("");
    const [e, s] = await Promise.all([
      loadOne(() => api.GET(internalEndpointsPath, { params: { path: { orgId } } })),
      loadOne(() => api.GET(staticKeySettingsPath, { params: { path: { orgId } } })),
    ]);
    if (!alive.current || n !== generation.current) return;
    setEndpoints(e.ok && Array.isArray(e.data.items) ? e.data.items : null);
    setPublicAllowed(s.ok && typeof s.data.public_static_keys_allowed === "boolean" ? s.data.public_static_keys_allowed : null);
    if (!e.ok || !s.ok) setError("Could not load the internal AI endpoint settings. Refresh to try again.");
    setLoading(false);
  }
  useEffect(() => { alive.current = true; void reload(); return () => { alive.current = false; generation.current++; }; }, [orgId]);
  // The API keys page links here; the section exists only after the first load.
  useEffect(() => { if (!loading && window.location.hash === "#internal-ai-endpoint") document.getElementById("internal-ai-endpoint")?.scrollIntoView?.({ block: "start" }); }, [loading]);
  async function setPublic(value: boolean) {
    if (!canEdit || switchBusy || publicAllowed === null) return;
    setSwitchBusy(true); setSwitchError("");
    try {
      const result = await api.PUT(staticKeySettingsPath, { params: { path: { orgId } }, body: { public_static_keys_allowed: value } });
      if (!alive.current) return;
      if (result.error || !result.data) setSwitchError(apiErrorMessage(result.error, "Could not save the setting. Try again."));
      else { setPublicAllowed(result.data.public_static_keys_allowed); toast.success(result.data.public_static_keys_allowed ? "Public static keys allowed" : "Public static keys turned off"); }
    } catch { if (alive.current) setSwitchError("Could not confirm the change. Refresh to check the saved setting."); }
    finally { if (alive.current) setSwitchBusy(false); }
  }
  async function toggle(e: Endpoint) {
    const c = e.endpoint;
    if (!canEdit || !c || rowBusy) return;
    setRowBusy(true); setError("");
    try {
      const body: S["AIInternalEndpointInput"] = { enabled: !c.enabled, listen_addresses: c.listen_addresses, port: c.port, dns_name: c.dns_name ?? null, source_cidrs: c.source_cidrs, tls_mode: c.tls_mode, expected_revision: c.revision };
      const result = await api.PUT(endpointPath, { params: { path: { orgId, nodeId: e.node_id } }, body });
      if (!alive.current) return;
      if (result.error || !result.data) { setError(endpointError(result, "Could not save the endpoint. Refresh and try again.")); if (result.response?.status === 409) void reload(); return; }
      toast.success(c.enabled ? "Internal AI endpoint turned off" : "Internal AI endpoint turned on");
      await reload();
    } catch { if (alive.current) setError("Could not confirm the change. Refresh to check the saved endpoint."); }
    finally { if (alive.current) setRowBusy(false); }
  }
  async function downloadCA() {
    if (caBusy) return;
    setCaBusy(true); setCaError("");
    const message = await downloadInternalCA(orgId);
    if (!alive.current) return;
    setCaError(message); setCaBusy(false);
  }
  const busy = loading || rowBusy || !!editor || !!remove;
  return <>
    <Card className="ai-setting-card">
      <section id="internal-ai-endpoint" aria-labelledby="internal-ai-endpoint-title" className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="ai-setting-copy"><h3 id="internal-ai-endpoint-title">Internal AI endpoint</h3><p>A gateway serves model requests over HTTPS on a private address, for workload API keys used inside your network. Keys for inside your network work only here.</p></div>
          <div className="flex flex-wrap gap-2"><Button variant="ghost" disabled={caBusy} onClick={() => void downloadCA()}>{caBusy ? "Downloading…" : "Download CA certificate"}</Button><RefreshButton label="Refresh internal AI endpoint" disabled={busy} onClick={() => void reload()} /></div>
        </div>
        {!canEdit && <p className="text-sm text-ink-secondary">Read-only. An AI Gateway administrator sets up the internal AI endpoint.</p>}
        {caError && <p role="alert" className="text-sm text-danger">{caError}</p>}
        {error && <p role="alert" className="ai-provider-alert">{error}</p>}
        {loading ? <Loading label="Loading internal AI endpoint…" /> : endpoints && <DataTable caption="Internal AI endpoint by gateway" rows={endpoints} rowKey={(e) => e.node_id} failed={false} filterable={false} pageSize={0}
          empty={<AppAccessEmptyState icon={null} title="No gateways yet" description="Add a gateway first. Any gateway in this organization can serve the internal AI endpoint." />}
          columns={[
            { key: "gateway", header: "Gateway", cell: (e) => <span className="font-medium text-ink-heading">{e.node_name}</span> },
            { key: "status", header: "Status", cell: (e) => { const s = endpointStatus(e); return <Badge tone={s.tone}>{s.label}</Badge>; } },
            { key: "address", header: "Address", cell: (e) => e.endpoint ? <span className="font-mono text-xs">{e.endpoint.listen_addresses.join(", ")} · port {e.endpoint.port}{e.endpoint.dns_name && <span className="block">{e.endpoint.dns_name}</span>}</span> : <span className="text-ink-secondary">None</span> },
            { key: "sources", header: "Source ranges", cell: (e) => e.endpoint ? <span className="break-all font-mono text-xs">{e.endpoint.source_cidrs.join(", ")}</span> : <span className="text-ink-secondary">None</span> },
            { key: "cert", header: "Certificate", cell: (e) => e.endpoint ? <>{e.endpoint.tls_mode === "custom" ? "My own certificate files" : "Tunnex private CA"}{e.certificate_not_after && <span className="block text-xs text-ink-secondary">Expires {date(e.certificate_not_after)}</span>}{expiresSoon(e.certificate_not_after) && <span className="mt-1 block"><Badge tone="warn">Expires soon</Badge></span>}</> : <span className="text-ink-secondary">None</span> },
            { key: "url", header: "URL", cell: (e) => e.url ? <code className="break-all text-xs">{e.url}</code> : <span className="text-ink-secondary">None yet</span> },
            ...(canEdit ? [{ key: "actions", header: "Actions", cell: (e: Endpoint) => {
              const reason = busy ? "Finish the current action first." : undefined;
              const actions = [
                ...(e.supported ? [{ key: "edit", label: e.endpoint ? "Edit endpoint" : "Set up endpoint", disabledReason: reason, onSelect: () => setEditor(e) }] : []),
                ...(e.supported && e.endpoint ? [{ key: "toggle", label: e.endpoint.enabled ? "Turn off" : "Turn on", disabledReason: reason, onSelect: () => void toggle(e) }] : []),
                ...(e.endpoint ? [{ key: "remove", label: "Remove endpoint", danger: true, disabledReason: reason, onSelect: () => setRemove(e) }] : []),
              ];
              return actions.length ? <AppAccessRowMenu label={`Actions for internal AI endpoint on ${e.node_name}`} actions={actions} /> : null;
            } }] : []),
          ]} />}
      </section>
    </Card>
    <Card className="ai-setting-card">
      <div className="ai-setting-row">
        <div className="ai-setting-copy"><h3 id="public-static-keys-title">Allow public static keys</h3><p>Lets workload API keys work on this console's public AI endpoint, for SaaS tools that cannot reach your network. Off keeps every API key inside your network.</p></div>
        <div className="ai-setting-actions">{publicAllowed === null ? (loading ? null : <span className="text-sm text-ink-secondary">Unavailable</span>)
          : canEdit ? <Switch label="Allow public static keys" checked={publicAllowed} disabled={switchBusy} onChange={(value) => void setPublic(value)} />
          : <span role="status" className={`ai-setting-state ${publicAllowed ? "is-on" : ""}`}>{publicAllowed ? "On" : "Off"}</span>}</div>
      </div>
      {publicAllowed && <p className="mt-3 text-sm text-ink-secondary">Turning this off stops new public keys from being created, and existing public keys are refused.</p>}
      {switchError && <p role="alert" className="mt-3 text-sm text-danger">{switchError}</p>}
    </Card>
    {editor && canEdit && <EndpointEditor orgId={orgId} target={editor} onDismiss={() => setEditor(null)}
      onConflict={(message) => { if (!alive.current) return; setEditor(null); setError(message); void reload(); }}
      onSaved={() => { if (!alive.current) return; setEditor(null); toast.success("Internal AI endpoint saved"); void reload(); }} />}
    {remove && canEdit && <RemoveDialog orgId={orgId} target={remove} onDismiss={() => setRemove(null)} onRemoved={() => { if (!alive.current) return; setRemove(null); toast.success("Internal AI endpoint removed"); void reload(); }} />}
  </>;
}

function EndpointEditor({ orgId, target, onDismiss, onSaved, onConflict }: { orgId: string; target: Endpoint; onDismiss: () => void; onSaved: () => void; onConflict: (message: string) => void }) {
  const formId = useId(), tlsName = useId();
  const c = target.endpoint;
  const tunnel = target.tunnel_address ?? "";
  const [useTunnel, setUseTunnel] = useState(c ? !!tunnel && c.listen_addresses.includes(tunnel) : !!tunnel);
  const [lan, setLan] = useState(c?.listen_addresses.find((a) => a !== tunnel) ?? "");
  const [port, setPort] = useState(String(c?.port ?? 9443));
  const [dns, setDns] = useState(c?.dns_name ?? "");
  const [ranges, setRanges] = useState((c?.source_cidrs ?? []).join("\n"));
  const [tls, setTls] = useState<TLSMode>(c?.tls_mode ?? "tunnex_ca");
  const [enabled, setEnabled] = useState(c?.enabled ?? true);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const addresses = [...(useTunnel && tunnel ? [tunnel] : []), ...(target.has_site && lan.trim() ? [lan.trim()] : [])];
  const lanValid = !lan.trim() || isIPv4(lan.trim());
  const portNumber = Number(port);
  const portValid = Number.isInteger(portNumber) && portNumber >= 1024 && portNumber <= 65535;
  const dnsValid = !dns.trim() || dns.trim().length <= 253 && /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(dns.trim());
  const cidrs = parseList(ranges);
  const badRange = cidrs.find((v) => !isIPv4CIDR(v));
  const valid = addresses.length >= 1 && addresses.length <= 2 && lanValid && portValid && dnsValid && cidrs.length >= 1 && cidrs.length <= 32 && !badRange;
  async function save(event: FormEvent) {
    event.preventDefault(); if (busy || !valid) return;
    setBusy(true); setError("");
    const body: S["AIInternalEndpointInput"] = { enabled, listen_addresses: addresses, port: portNumber, dns_name: dns.trim() || null, source_cidrs: cidrs, tls_mode: tls, expected_revision: c?.revision ?? 0 };
    try {
      const result = await api.PUT(endpointPath, { params: { path: { orgId, nodeId: target.node_id } }, body });
      if (!alive.current) return;
      if (result.error || !result.data) {
        const message = endpointError(result, "Could not save the endpoint. Refresh and try again.");
        if (result.response?.status === 409 && !apiErrorCode(result.error)?.startsWith("ai_internal_endpoint_")) onConflict(message); else setError(message);
        return;
      }
      onSaved();
    } catch { if (alive.current) setError("Could not confirm the change. Refresh to check the saved endpoint."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title={`Internal AI endpoint on ${target.node_name}`} placement="right" showClose onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button type="button" disabled={busy} onClick={onDismiss}>Cancel</Button><Button type="submit" form={formId} disabled={busy || !valid}>{busy ? "Saving…" : "Save endpoint"}</Button></>}>
    <form id={formId} onSubmit={(event) => void save(event)} className="ai-workload-key-editor space-y-5">
      <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="checkbox" checked={enabled} disabled={busy} onChange={(event) => setEnabled(event.target.checked)} />Serve the internal AI endpoint on this gateway</label>
      <fieldset className="space-y-2"><legend className="mb-1 text-sm font-semibold">Addresses</legend>
        <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="checkbox" checked={useTunnel} disabled={busy || !tunnel} onChange={(event) => setUseTunnel(event.target.checked)} /><span>Tunnel address {tunnel ? <code>{tunnel}</code> : "(not available)"}<span className="block text-xs text-ink-secondary">Every VPN device can reach it.</span></span></label>
        {target.has_site ? <><Field label="LAN address (optional)"><Input value={lan} disabled={busy} placeholder="10.20.1.10" onChange={(event) => setLan(event.target.value)} /></Field>
          <p className="text-xs text-ink-secondary">One address on the gateway inside an approved subnet of its site, for LAN and site-to-site callers.</p></>
          : <p className="text-xs text-ink-secondary">This gateway is not part of a site, so it can listen only on its tunnel address.</p>}
        {!lanValid && <p role="alert" className="text-sm text-danger">Enter one IPv4 address, such as 10.20.1.10.</p>}
        {addresses.length === 0 && <p role="alert" className="text-sm text-danger">Choose at least one address.</p>}
      </fieldset>
      <Field label="Port"><Input type="number" min={1024} max={65535} step={1} required value={port} disabled={busy} onChange={(event) => setPort(event.target.value)} /></Field>
      {!portValid && <p role="alert" className="text-sm text-danger">Enter a port from 1024 to 65535.</p>}
      <Field label="DNS name (optional)"><Input value={dns} disabled={busy} placeholder="ai.internal.example.com" onChange={(event) => setDns(event.target.value)} /></Field>
      {!dnsValid && <p role="alert" className="text-sm text-danger">Enter a DNS name, such as ai.internal.example.com, or leave it empty.</p>}
      <Field label="Source ranges"><textarea className={area} required value={ranges} disabled={busy} placeholder="10.20.0.0/16" onChange={(event) => setRanges(event.target.value)} /></Field>
      <p className="text-xs text-ink-secondary">Private ranges allowed to connect, one per line. Other callers are dropped before TLS. If traffic passes source NAT, every caller behind it looks the same.</p>
      {badRange && <p role="alert" className="text-sm text-danger">{badRange} is not a range. Use the form 10.20.0.0/16.</p>}
      {cidrs.length > 32 && <p role="alert" className="text-sm text-danger">Use at most 32 ranges.</p>}
      <p role="note" className="ai-provider-notice text-warn">Open TCP {portValid ? portNumber : "<port>"} from these ranges in your firewall. Traffic to this port is not covered by access rules.</p>
      <fieldset className="space-y-2"><legend className="mb-1 text-sm font-semibold">Certificate</legend>
        <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="radio" name={tlsName} checked={tls === "tunnex_ca"} disabled={busy} onChange={() => setTls("tunnex_ca")} /><span>Tunnex private CA (recommended)<span className="block text-xs text-ink-secondary">The gateway gets a certificate from your organization's private CA and renews it. Tools must trust the CA certificate.</span></span></label>
        <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="radio" name={tlsName} checked={tls === "custom"} disabled={busy} onChange={() => setTls("custom")} /><span>My own certificate files<span className="block text-xs text-ink-secondary">Put <code>tls-cert.pem</code> and <code>tls-key.pem</code> in <code>/var/lib/tunnex-node/ai-internal/</code> on the gateway host, mode 0600. The private key never leaves the gateway.</span></span></label>
      </fieldset>
      {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    </form>
  </Modal>;
}

function RemoveDialog({ orgId, target, onDismiss, onRemoved }: { orgId: string; target: Endpoint; onDismiss: () => void; onRemoved: () => void }) {
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function confirm() {
    if (busy) return;
    setBusy(true); setError("");
    try {
      const result = await api.DELETE(endpointPath, { params: { path: { orgId, nodeId: target.node_id } } });
      if (!alive.current) return;
      if (result.error || result.response?.status !== 204) { setError("Could not confirm the endpoint was removed. Refresh and try again."); return; }
      onRemoved();
    } catch { if (alive.current) setError("Could not confirm the endpoint was removed. Refresh and try again."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title="Remove internal AI endpoint" danger onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button disabled={busy} onClick={onDismiss}>Cancel</Button><Button disabled={busy} onClick={() => void confirm()}>{busy ? "Removing…" : "Remove endpoint"}</Button></>}>
    <p className="text-sm">Remove the internal AI endpoint from {target.node_name}? Requests to it are refused at once. Internal API keys keep working on other gateways that serve the endpoint.</p>
    {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
  </Modal>;
}
