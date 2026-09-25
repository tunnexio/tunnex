import "../network-workspaces.css";
import { useCallback, useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, loadOne, type Node, type Site, type SiteSubnet } from "../lib/api";
import { Button, Card, DataTable, ErrorText, Field, Input, Modal, Select } from "./ui";
import { IPsecTunnelHealth } from "./IPsecTunnelHealth";
import { IPsecRotateKeys, canRotateIPsecKeys } from "./IPsecRotateKeys";

type Connection = components["schemas"]["IPsecConnection"];
type Settings = components["schemas"]["IPsecSettings"];
type Configuration = components["schemas"]["IPsecConfigurationCheckInput"];
type CreateInput = components["schemas"]["IPsecProviderCreateInput"];
type Provider = components["schemas"]["IPsecProviderConfiguration"];
type Eligibility = { eligible: boolean; reason: "eligible" | "opt_in_required" | "gateway_unavailable" | "unsupported" | "report_stale" };
type Props = { createRequest?: number; onCreateHandled?: () => void; onRequestCreate?: () => void; orgId: string; userId: string; emailVerified: boolean; role?: string; sites: Site[] };
function connectionStatus(item: Connection): string {
  if (item.cleanup_state === "pending") return "Cleanup pending";
  if (item.desired_intent === "deleted") return item.cleanup_state === "retained_guard" ? "Removed · guard retained" : item.finalized_at ? "Removed" : "Cleanup pending";
  if (item.desired_intent === "enabled") return item.application_state === "applied" ? "Applied" : "Applying";
  return item.cleanup_state === "retained_guard" ? "Disabled · guard retained" : "Disabled";
}
const eligibilityText: Record<Eligibility["reason"], string> = {
  eligible: "Gateway supports storing this configuration.", opt_in_required: "Enable IPsec for this organization first.",
  gateway_unavailable: "Choose an active gateway on this network.", unsupported: "This gateway does not support IPsec yet.", report_stale: "Gateway capability report is out of date. Refresh after it reports again.",
};
function useLifetime() {
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  return alive;
}

/** Secret drafts belong to one exact user/organization/authority lifetime. */
export function IPsecWorkspace(props: Props) {
  return <IPsecSession key={`${props.orgId}:${props.userId}:${props.emailVerified}:${props.role ?? ""}`} {...props} />;
}
function IPsecSession({ orgId, emailVerified, role, sites, createRequest = 0, onRequestCreate, onCreateHandled }: Props) {
  const manage = emailVerified && (role === "owner" || role === "admin");
  const alive = useLifetime();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [items, setItems] = useState<Connection[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(createRequest > 0);
  useEffect(() => { if (createRequest > 0) { setCreating(true); onCreateHandled?.(); } }, [createRequest, onCreateHandled]);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Connection | null>(null);
  const [rotating, setRotating] = useState<Connection | null>(null);
  const [notice, setNotice] = useState("");
  const [changing, setChanging] = useState<Connection | null>(null);
  const [ready, setReady] = useState<Record<string, boolean>>({});
  useEffect(() => {
    let cancelled = false; setReady({});
    if (!manage || !settings?.enabled) return;
    void Promise.all(items.filter(item => item.desired_intent === "disabled" && item.cleanup_state !== "pending" && item.site_id && item.gateway_node_id).map(async item => {
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: item.site_id!, gateway_node_id: item.gateway_node_id! } } }));
      return [item.id, result.ok && result.data.eligible] as const;
    })).then(values => { if (!cancelled) setReady(Object.fromEntries(values)); });
    return () => { cancelled = true; };
  }, [orgId, items, manage, settings?.enabled]);
  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    const [setting, page] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections", { params: { path: { orgId }, query: { limit: 50 } } })),
    ]);
    if (!alive.current) return;
    setLoading(false);
    setSettings(setting.ok ? setting.data : null);
    if (page.ok) { setItems(page.data.items); setNext(page.data.next_cursor ?? null); }
    if (!setting.ok || !page.ok) setError("Could not load IPsec configuration. Try again.");
  }, [orgId, alive]);
  useEffect(() => { void refresh(); }, [refresh]);
  async function enable() {
    if (!manage || !settings || busy) return;
    setBusy(true); setError("");
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId } }, body: { enabled: true, expected_revision: settings.revision } });
      if (!alive.current) return;
      if (result.error || !result.data) { await refresh(); if (alive.current) setError("Settings changed or could not be saved. Review and try again."); }
      else setSettings(result.data);
    } catch { if (alive.current) setError("Could not confirm the setting change. Refresh before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  async function more() {
    if (!next || busy) return;
    setBusy(true);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections", { params: { path: { orgId }, query: { limit: 50, after: next } } }));
    if (!alive.current) return;
    setBusy(false);
    if (!result.ok) { setError("Could not load more connections. Try again."); return; }
    setItems(old => [...old, ...result.data.items.filter(item => !old.some(previous => previous.id === item.id))]);
    setNext(result.data.next_cursor ?? null);
  }
  return <div className="network-management space-y-5">
    <div className="flex items-center justify-between gap-4">
      <div><h2 className="text-lg font-semibold text-ink-heading">IPsec VPN connections</h2><p className="text-sm text-ink-secondary">IPsec · AWS</p></div>
      <div className="flex gap-2">
        <Button variant="ghost" disabled={loading || busy} onClick={() => void refresh()}>Refresh</Button>
        {manage && settings && !onRequestCreate && <Button disabled={!settings.enabled || busy} onClick={() => setCreating(true)}>New connection</Button>}
      </div>
    </div>
    {settings && !settings.enabled && <Card><div className="flex items-center justify-between gap-4"><span className="text-sm text-ink-secondary">IPsec is off for this organization.</span>{manage && <Button disabled={busy} onClick={() => void enable()}>Enable IPsec</Button>}</div></Card>}
    <ErrorText>{error}</ErrorText>
    {notice && <p role="status" className="text-sm text-ink-secondary">{notice}</p>}
    {loading ? <p role="status" className="text-sm text-ink-secondary">Loading IPsec configurations…</p> : <>
      {!error && items.length === 0 && <Card><p className="text-sm text-ink-secondary">No IPsec connections configured.</p></Card>}
      {items.length > 0 && <Card className="space-y-4">
        <div className="flex items-center justify-between gap-3"><h3 className="font-semibold text-ink-heading">Connections</h3><span className="text-sm text-ink-secondary">{items.length}{next ? "+" : ""} loaded</span></div>
        <Input aria-label="Search VPN connections" placeholder="Find a connection" value={search} onChange={event => setSearch(event.target.value)} />
        <DataTable<Connection> caption="IPsec connections" rows={items.filter(item => `${item.name} ${sites.find(site => site.id === item.site_id)?.name ?? ""}`.toLowerCase().includes(search.toLowerCase()))} rowKey={item => item.id} failed={!!error} filterable={false} empty="No IPsec connections configured." columns={[
          { key: "name", header: "Connection", cell: item => <button aria-pressed={selected === item.id} className={`text-left font-medium hover:underline ${selected === item.id ? "text-accent" : "text-ink-heading"}`} onClick={() => setSelected(item.id)}>{item.name}</button> },
          { key: "network", header: "Local network", cell: item => sites.find(site => site.id === item.site_id)?.name ?? "Network unavailable" },
          { key: "state", header: "Configuration", cell: item => <><span title={item.cleanup_state === "retained_guard" ? "Tunnel traffic is stopped. Safety guard remains; network ranges stay reserved." : item.application_state === "applied" ? "Gateway applied this revision. End-to-end traffic is not verified." : undefined} className="rounded border border-line px-2 py-1 text-xs text-ink-secondary">{connectionStatus(item)}</span></> },
          { key: "actions", header: "Actions", cell: item => <div className="flex flex-wrap justify-end gap-2">
        {manage && item.desired_intent === "enabled" && <Button variant="ghost" size="sm" aria-label={`Disable ${item.name}`} onClick={() => setChanging(item)}>Disable</Button>}
        {manage && item.desired_intent === "disabled" && item.cleanup_state !== "pending" && ready[item.id] && <Button variant="ghost" size="sm" aria-label={`Enable ${item.name}`} onClick={() => setChanging(item)}>Enable</Button>}
        {manage && canRotateIPsecKeys(item) && <Button variant="ghost" size="sm" aria-label={`Rotate keys for ${item.name}`} onClick={() => { setNotice(""); setRotating(item); }}>Rotate keys</Button>}
        {manage && item.desired_intent !== "deleted" && <Button variant="ghost" size="sm" aria-label={`Delete ${item.name}`} onClick={() => setDeleting(item)}>Delete</Button>}
          </div> },
        ]} />
      </Card>}
      {next && <Button variant="ghost" disabled={busy} onClick={() => void more()}>Load more</Button>}
    </>}
    {selected && <ProviderReadback key={selected} orgId={orgId} id={selected} name={items.find(item => item.id === selected)?.name ?? "Connection details"} onClose={() => setSelected(null)} />}
    {manage && creating && settings?.enabled && <ConnectionForm orgId={orgId} sites={sites} onCancel={() => setCreating(false)} onSaved={id => { if (!alive.current) return; setCreating(false); setSelected(id); void refresh(); }} />}
    {manage && changing && <ChangeIntent orgId={orgId} connection={changing} onClose={() => setChanging(null)} onChanged={() => { if (!alive.current) return; setChanging(null); void refresh(); }} />}
    {manage && rotating && <IPsecRotateKeys key={rotating.id} orgId={orgId} connection={rotating} onClose={() => setRotating(null)} onSaved={() => { if (!alive.current) return; setRotating(null); setNotice("Keys saved. Update your remote VPN, then enable this connection."); void refresh(); }} />}
    {manage && deleting && <DeleteConnection orgId={orgId} connection={deleting} onClose={() => setDeleting(null)} onDeleted={() => { if (!alive.current) return; setDeleting(null); setSelected(null); void refresh(); }} />}
  </div>;
}
function ProviderReadback({ orgId, id, name, onClose }: { orgId: string; id: string; name: string; onClose: () => void }) {
  const [tab, setTab] = useState("tunnels");
  const [result, setResult] = useState<Provider | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { let cancelled = false; void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId: id } } })).then(value => { if (cancelled) return; if (value.ok) setResult(value.data); else setError("No provider configuration could be loaded for this record."); }); return () => { cancelled = true; }; }, [orgId, id]);
  return <Card><div className="mb-3 flex justify-between"><h3 className="font-semibold text-ink-heading">{name}</h3><Button size="sm" variant="ghost" onClick={onClose}>Close details</Button></div>
    <ErrorText>{error}</ErrorText>{!result && !error && <p role="status">Loading configuration…</p>}
    {result && <><p className="mb-3 text-xs text-ink-secondary">AWS · IPv4 static · revision {result.configuration_revision}</p>
      <div role="tablist" aria-label="Connection details" className="mb-5 flex gap-6 border-b border-line">{[["tunnels", "Tunnel details"], ["details", "Details"]].map(([value, label]) => <button key={value} id={`ipsec-${id}-${value}-tab`} role="tab" tabIndex={tab === value ? 0 : -1} onKeyDown={event => { if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) { event.preventDefault(); const next = event.key === "Home" ? "tunnels" : event.key === "End" ? "details" : tab === "tunnels" ? "details" : "tunnels"; setTab(next); document.getElementById(`ipsec-${id}-${next}-tab`)?.focus(); } }} aria-selected={tab === value} aria-controls={`ipsec-${id}-${value}-panel`} onClick={() => setTab(value)} className={`border-b-2 px-1 py-3 text-sm font-medium ${tab === value ? "border-current text-ink-heading" : "border-transparent text-ink-secondary"}`}>{label}</button>)}</div>
      {!result.configuration ? <p className="text-sm text-ink-secondary">Configuration removed. Identity retained.</p> : <div className="space-y-4">
        <div role="tabpanel" id={`ipsec-${id}-details-panel`} aria-labelledby={`ipsec-${id}-details-tab`} hidden={tab !== "details"}><h4 className="mb-4 font-medium text-ink-heading">Stored configuration</h4><dl className="grid grid-cols-3 gap-4 text-sm"><div><dt className="text-ink-secondary">Customer public IP</dt><dd>{result.configuration.customer_outside_address}</dd></div><div><dt className="text-ink-secondary">Local networks</dt>{result.configuration.local_prefixes.map(value => <dd key={value}>{value}</dd>)}</div><div><dt className="text-ink-secondary">Remote networks</dt>{result.configuration.remote_prefixes.map(value => <dd key={value}>{value}</dd>)}</div></dl></div>
        <div role="tabpanel" id={`ipsec-${id}-tunnels-panel`} aria-labelledby={`ipsec-${id}-tunnels-tab`} hidden={tab !== "tunnels"}><IPsecTunnelHealth orgId={orgId} connectionId={id} tunnels={result.configuration.tunnels} /></div>
      </div>}</>}
  </Card>;
}
function ChangeIntent({ orgId, connection, onClose, onChanged }: { orgId: string; connection: Connection; onClose: () => void; onChanged: () => void }) {
  const alive = useLifetime(); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const intent = connection.desired_intent === "enabled" ? "disabled" : "enabled";
  const label = intent === "enabled" ? "Enable" : "Disable";
  async function change() {
    if (busy || !Number.isSafeInteger(connection.desired_revision)) return;
    setBusy(true); setError("");
    try {
      if (intent === "enabled") {
        const siteId = connection.site_id, gatewayId = connection.gateway_node_id;
        if (!siteId || !gatewayId) { setError("Gateway assignment is unavailable. Close and refresh."); return; }
        const checked = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: siteId, gateway_node_id: gatewayId } } }));
        if (!alive.current) return;
        if (!checked.ok || !checked.data.eligible) { setError("Gateway readiness changed. Close and refresh before enabling."); return; }
      }
      const result = await api.PUT("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/intent", { params: { path: { orgId, connectionId: connection.id }, header: { "If-Match": `"${connection.desired_revision}"` } }, body: { intent } });
      if (!alive.current) return;
      if (result.error || !result.data) setError("Could not confirm the change. Close and refresh before retrying."); else onChanged();
    } catch { if (alive.current) setError("Could not confirm the change. Close and refresh before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title={`${label} connection?`} onDismiss={onClose} actions={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={busy || !Number.isSafeInteger(connection.desired_revision)} onClick={() => void change()}>{label} connection</Button></>}><p>{connection.name}</p><p className="mt-2 text-sm text-ink-secondary">{intent === "enabled" ? "Apply this configuration on its gateway. Access policies control which traffic is allowed." : "Stop tunnel traffic. Gateway cleanup may remain pending while the gateway is offline."}</p><ErrorText>{error}</ErrorText></Modal>;
}
function DeleteConnection({ orgId, connection, onClose, onDeleted }: { orgId: string; connection: Connection; onClose: () => void; onDeleted: () => void }) {
  const alive = useLifetime(); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function remove() {
    if (busy || !Number.isSafeInteger(connection.desired_revision)) return;
    setBusy(true); setError("");
    try { const result = await api.DELETE("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId, connectionId: connection.id }, header: { "If-Match": `"${connection.desired_revision}"` } } }); if (!alive.current) return; if (result.error || !result.data) setError("Could not confirm deletion. Close and refresh before retrying."); else onDeleted(); }
    catch { if (alive.current) setError("Could not confirm deletion. Close and refresh before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title="Delete connection?" onDismiss={onClose} actions={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="danger" disabled={busy || !Number.isSafeInteger(connection.desired_revision)} onClick={() => void remove()}>Delete connection</Button></>}><p>{connection.name}</p><p className="mt-2 text-sm text-ink-secondary">Removes the tunnel and credentials after gateway cleanup. Safety guards and reserved ranges remain for previously delivered tunnels.</p><ErrorText>{error}</ErrorText></Modal>;
}
const blankTunnel = (): Configuration["tunnels"][number] => ({ outside_address: "", inside_cidr: "", customer_inside_address: "", cloud_inside_address: "", psk: "" });
function ConnectionForm({ orgId, sites, onCancel, onSaved }: { orgId: string; sites: Site[]; onCancel: () => void; onSaved: (id: string) => void }) {
  const alive = useLifetime();
  const [ids] = useState(() => ({ id: crypto.randomUUID(), tunnels: [crypto.randomUUID(), crypto.randomUUID()] }));
  const [step, setStep] = useState(1); const [name, setName] = useState(""); const [site, setSite] = useState(""); const [gateway, setGateway] = useState("");
  const [nodes, setNodes] = useState<Node[]>([]); const [subnets, setSubnets] = useState<SiteSubnet[]>([]); const [local, setLocal] = useState<string[]>([]);
  const [customer, setCustomer] = useState(""); const [remote, setRemote] = useState(""); const [tunnels, setTunnels] = useState(() => [blankTunnel(), blankTunnel()]);
  const [eligibility, setEligibility] = useState<{ key: string; value: Eligibility } | null>(null); const [checking, setChecking] = useState(false); const [checkAttempt, setCheckAttempt] = useState(0);
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false);
  const frozen = useRef<CreateInput | null>(null); const saving = useRef(false);
  const pair = `${site}:${gateway}`;
  useEffect(() => { let cancelled = false; void loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } })).then(result => { if (cancelled) return; if (result.ok) setNodes(result.data); else setError("Could not load gateways. Close and try again."); }); return () => { cancelled = true; }; }, [orgId]);
  useEffect(() => { let cancelled = false; setSubnets([]); setLocal([]); if (site) void loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", { params: { path: { orgId, siteId: site } } })).then(result => { if (cancelled) return; if (result.ok) setSubnets(result.data.filter(subnet => subnet.status === "approved")); else setError("Could not load approved ranges. Choose the network again."); }); return () => { cancelled = true; }; }, [orgId, site]);
  useEffect(() => { let cancelled = false; setEligibility(null); if (!site || !gateway) { setChecking(false); return; } setChecking(true); void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: site, gateway_node_id: gateway } } })).then(result => { if (cancelled) return; setChecking(false); if (result.ok) setEligibility({ key: pair, value: result.data }); else setError("Could not check gateway support. Try again."); }); return () => { cancelled = true; }; }, [orgId, site, gateway, pair, checkAttempt]);
  useEffect(() => () => { frozen.current = null; }, []);
  const currentEligibility = eligibility?.key === pair ? eligibility.value : null;
  const selectedGateways = nodes.filter(node => node.site_id === site && node.status === "active");
  const prepared = name.trim() && site && selectedGateways.some(node => node.id === gateway) && local.length && customer && remote.trim();
  function cancel() { frozen.current = null; setTunnels([blankTunnel(), blankTunnel()]); onCancel(); }
  async function recover(id: string) {
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId, connectionId: id } } }));
    if (!alive.current) return false;
    if (result.ok) { frozen.current = null; setTunnels([blankTunnel(), blankTunnel()]); onSaved(id); return true; }
    return false;
  }
  async function save() {
    if (saving.current || (!uncertain && (!prepared || !currentEligibility?.eligible))) return;
    saving.current = true; setBusy(true); setError("");
    let posted = false;
    const input: CreateInput = frozen.current ?? { id: ids.id, name, site_id: site, gateway_node_id: gateway, tunnel_ids: ids.tunnels, configuration: { mode: "ipv4-static", customer_outside_address: customer, local_prefixes: local, remote_prefixes: remote.split(/[\s,]+/).filter(Boolean), tunnels: tunnels.map(tunnel => ({ ...tunnel })) } };
    try {
      // Resolve an earlier write before testing whether a new write is currently allowed.
      if (uncertain && await recover(input.id)) return;
      if (!alive.current) return;
      // Recheck immediately before each attempt; UI readiness never grants authority.
      const eligibilityResult = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: input.site_id, gateway_node_id: input.gateway_node_id } } }));
      if (!alive.current) return;
      if (!eligibilityResult.ok || !eligibilityResult.data.eligible) { setEligibility(eligibilityResult.ok ? { key: pair, value: eligibilityResult.data } : null); setError("Gateway readiness changed. Check support before saving."); return; }
      const checked = await api.POST("/api/v1/organizations/{orgId}/ipsec/configuration-check", { params: { path: { orgId } }, body: input.configuration });
      if (!alive.current) return;
      if (checked.error || !checked.data?.valid) { setError("Check the addresses, ranges and credentials before saving."); return; }
      frozen.current = input; posted = true;
      const result = await api.POST("/api/v1/organizations/{orgId}/ipsec/connections", { params: { path: { orgId } }, body: input });
      if (!alive.current) return;
      if (result.data && !result.error) { frozen.current = null; setTunnels([blankTunnel(), blankTunnel()]); onSaved(result.data.id); return; }
      if (result.response?.status === 409 && await recover(input.id)) return;
      if (!uncertain && result.response && result.response.status < 500 && result.response.status !== 409) { frozen.current = null; setUncertain(false); setError("Configuration was not saved. Review gateway support, network ownership and conflicts."); }
      else { setUncertain(true); setError("Save result unknown. Retry uses the same connection ID."); }
    } catch {
      if (!alive.current) return;
      if (posted) { if (await recover(input.id)) return; if (!alive.current) return; setUncertain(true); setError("Save result unknown. Retry uses the same connection ID."); }
      else setError("Could not check the configuration. Try again.");
    } finally { saving.current = false; if (alive.current) setBusy(false); }
  }
  return <Modal title="New IPsec connection" size="workspace" onDismiss={cancel}>
    <form onSubmit={event => { event.preventDefault(); if (step === 1) { if (prepared) setStep(2); } else void save(); }} autoComplete="off" className="space-y-5">
      <div className="flex gap-3 text-sm"><span className={step === 1 ? "font-semibold text-ink-heading" : "text-ink-secondary"}>1 · Networks</span><span className={step === 2 ? "font-semibold text-ink-heading" : "text-ink-secondary"}>2 · Tunnels</span></div>
      <fieldset disabled={busy || uncertain} className="space-y-4">
        {step === 1 ? <>
          <Field label="Name"><Input required value={name} maxLength={255} onChange={event => setName(event.target.value)} placeholder="Office to AWS" /></Field>
          <div className="grid grid-cols-2 gap-4"><Field label="Local network"><Select required value={site} onChange={event => { setSite(event.target.value); setGateway(""); setLocal([]); setSubnets([]); setEligibility(null); }}><option value="">Choose a network</option>{sites.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</Select></Field>
            <Field label="Gateway"><Select required value={gateway} onChange={event => { setGateway(event.target.value); setEligibility(null); }}><option value="">Choose a gateway</option>{selectedGateways.map(node => <option key={node.id} value={node.id}>{node.name}</option>)}</Select></Field></div>
          <fieldset><legend className="mb-2 text-sm text-ink-secondary">Approved local ranges</legend><div className="flex flex-wrap gap-3">{subnets.map(subnet => <label key={subnet.id} className="flex items-center gap-2 rounded border border-line px-3 py-2 text-sm"><input type="checkbox" checked={local.includes(subnet.cidr)} onChange={event => setLocal(old => event.target.checked ? [...old, subnet.cidr] : old.filter(value => value !== subnet.cidr))} />{subnet.cidr}</label>)}</div>{site && subnets.length === 0 && <p className="text-xs text-ink-secondary">No approved ranges available.</p>}</fieldset>
          <div className="grid grid-cols-2 gap-4"><Field label="Customer public IP"><Input required value={customer} onChange={event => setCustomer(event.target.value)} placeholder="Public gateway or NAT IP" /></Field><Field label="Remote network ranges"><Input required value={remote} onChange={event => setRemote(event.target.value)} placeholder="CIDRs, separated by commas" /></Field></div>
        </> : <div className="grid grid-cols-2 gap-4">{tunnels.map((tunnel, i) => <div key={i} className="space-y-3 rounded border border-line p-4"><h3 className="font-semibold">Tunnel {i + 1}</h3>{([
          ["outside_address", "outside IP"], ["inside_cidr", "inside CIDR"], ["customer_inside_address", "customer IP"], ["cloud_inside_address", "cloud IP"], ["psk", "PSK"],
        ] as const).map(([field, label]) => <Field key={field} label={`Tunnel ${i + 1} ${label}`}><Input required type={field === "psk" ? "password" : "text"} autoComplete={field === "psk" ? "new-password" : "off"} spellCheck={false} value={tunnel[field]} onChange={event => setTunnels(old => old.map((value, n) => n === i ? { ...value, [field]: event.target.value } : value))} /></Field>)}</div>)}</div>}
      </fieldset>
      <div className="flex items-center justify-between gap-3 text-sm"><p role="status" className="text-ink-secondary">{checking ? "Checking gateway support…" : currentEligibility ? eligibilityText[currentEligibility.reason] : "Choose a network and gateway to check support."}</p>{site && gateway && <Button type="button" variant="ghost" size="sm" disabled={busy || checking} onClick={() => setCheckAttempt(value => value + 1)}>Check support</Button>}</div>
      <ErrorText>{error}</ErrorText>
      <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={cancel}>Cancel</Button>{step === 2 && !uncertain && <Button type="button" variant="ghost" disabled={busy} onClick={() => setStep(1)}>Back</Button>}{step === 1 ? <Button type="submit" disabled={!prepared || busy}>Next: tunnels</Button> : <Button type="submit" disabled={busy || (!uncertain && (checking || !currentEligibility?.eligible))}>{busy ? "Saving…" : uncertain ? "Retry save" : "Save disabled connection"}</Button>}</div>
    </form>
  </Modal>;
}
