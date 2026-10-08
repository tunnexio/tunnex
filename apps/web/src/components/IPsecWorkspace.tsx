import "../network-workspaces.css";
import "../ipsec-workspace.css";
import { ResourceSummary } from "./ResourceSummary";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, loadOne, type Node, type Site, type SiteSubnet } from "../lib/api";
import { Button, DataTable, ErrorText, Field, Input, Modal, Select } from "./ui";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "./AppAccessRowMenu";
import { appAccessPageSizes } from "./AppAccessPagination";
import { IPsecTunnelHealth } from "./IPsecTunnelHealth";
import { IPsecRotateKeys, canRotateIPsecKeys } from "./IPsecRotateKeys";

type Connection = components["schemas"]["IPsecConnection"];
type Settings = components["schemas"]["IPsecSettings"];
type Configuration = components["schemas"]["IPsecConfigurationCheckInput"];
type CreateInput = components["schemas"]["IPsecProviderCreateInput"];
type Provider = components["schemas"]["IPsecProviderConfiguration"];
type ConnectionPage = components["schemas"]["IPsecConnectionPage"];
type Eligibility = { eligible: boolean; reason: "eligible" | "opt_in_required" | "gateway_unavailable" | "unsupported" | "report_stale" };
type Props = { createRequest?: number; onCreateHandled?: () => void; onRequestCreate?: () => void; orgId: string; userId: string; emailVerified: boolean; role?: string; sites: Site[] };
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const nullableString = (value: unknown) => value === null || typeof value === "string";
function validSettings(value: unknown): value is Settings {
  return object(value) && typeof value.enabled === "boolean" && typeof value.revision === "number" && Number.isSafeInteger(value.revision) && value.revision >= 0;
}
function validConnectionPage(value: unknown, orgId: string): value is ConnectionPage {
  return object(value) && Array.isArray(value.items) && nullableString(value.next_cursor) && value.next_cursor !== "" && value.items.every(item =>
    object(item) && typeof item.id === "string" && item.id.length > 0 && item.org_id === orgId && typeof item.name === "string"
    && nullableString(item.site_id) && nullableString(item.gateway_node_id)
    && typeof item.historical_site_id === "string" && typeof item.historical_gateway_node_id === "string"
    && typeof item.desired_revision === "number" && Number.isSafeInteger(item.desired_revision) && item.desired_revision >= 1
    && ["disabled", "enabled", "deleted"].includes(String(item.desired_intent))
    && ["not_applied", "pending", "applied"].includes(String(item.application_state))
    && ["not_required", "pending", "retained_guard"].includes(String(item.cleanup_state))
    && nullableString(item.deleted_at) && nullableString(item.finalized_at)
    && typeof item.created_at === "string" && Number.isFinite(Date.parse(item.created_at))
    && typeof item.updated_at === "string" && Number.isFinite(Date.parse(item.updated_at)));
}
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
  const [pageSize, setPageSize] = useState(20);
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const requestSequence = useRef(0);
  const failedPage = useRef<{ cursor: string | undefined; limit: number; history: (string | undefined)[] } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(createRequest > 0);
  useEffect(() => { if (createRequest > 0) { setCreating(true); onCreateHandled?.(); } }, [createRequest, onCreateHandled]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState<{ id: string; name: string } | null>(null);
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
  const loadPage = useCallback(async (cursor: string | undefined, limit: number, history: (string | undefined)[]) => {
    const request = ++requestSequence.current;
    failedPage.current = null;
    setLoading(true); setError("");
    const [setting, page] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections", { params: { path: { orgId }, query: { limit, ...(cursor ? { after: cursor } : {}) } } })),
    ]);
    if (!alive.current || request !== requestSequence.current) return;
    setLoading(false);
    const settingValid = setting.ok && validSettings(setting.data);
    const pageValid = page.ok && validConnectionPage(page.data, orgId);
    const cursorAdvances = pageValid && (!page.data.next_cursor || !history.includes(page.data.next_cursor));
    setSettings(settingValid ? setting.data : null);
    if (pageValid && cursorAdvances) {
      setItems(page.data.items.filter((item, index, pageItems) => pageItems.findIndex(other => other.id === item.id) === index));
      setNext(page.data.next_cursor ?? null);
      setCursors(history);
    }
    if (!settingValid || !pageValid || !cursorAdvances) {
      failedPage.current = { cursor, limit, history };
      setError(setting.ok && page.ok ? "The server returned incomplete or non-advancing IPsec inventory. Retry to reload this page." : "Could not load IPsec configuration. Try again.");
    }
  }, [orgId, alive]);
  const refresh = useCallback(() => loadPage(undefined, pageSize, [undefined]), [loadPage, pageSize]);
  useEffect(() => { void refresh(); }, [refresh]);
  function changePage(direction: "previous" | "next") {
    if (loading || (direction === "next" ? !next : cursors.length <= 1)) return;
    const history = direction === "next" ? [...cursors, next!] : cursors.slice(0, -1);
    void loadPage(history.at(-1), pageSize, history);
  }
  function changePageSize(size: number) {
    if (loading || !appAccessPageSizes.includes(size as typeof appAccessPageSizes[number]) || size === pageSize) return;
    // Withdraw an in-flight old-page response before React runs the size-change effect.
    requestSequence.current += 1;
    setLoading(true);
    setPageSize(size);
  }
  const groups = [
    { key: "all", label: "All connections", matches: (_item: Connection) => true },
    { key: "enabled", label: "Enabled", matches: (item: Connection) => item.desired_intent === "enabled" },
    { key: "disabled", label: "Disabled", matches: (item: Connection) => item.desired_intent === "disabled" },
    { key: "deleted", label: "Removed", matches: (item: Connection) => item.desired_intent === "deleted" },
  ];
  const visible = items.filter(item => groups.find(group => group.key === filter)!.matches(item) && `${item.name} ${sites.find(site => site.id === item.site_id)?.name ?? ""}`.toLowerCase().includes(search.trim().toLowerCase()));
  const hasOtherPages = cursors.length > 1 || Boolean(next);
  function rowActions(item: Connection): AppAccessRowMenuAction[] {
    const actions: AppAccessRowMenuAction[] = [{ key: "details", label: "Connection details", onSelect: () => setSelected({ id: item.id, name: item.name }) }];
    if (manage && item.desired_intent === "enabled") actions.push({ key: "disable", label: `Disable ${item.name}`, onSelect: () => setChanging(item) });
    if (manage && item.desired_intent === "disabled" && item.cleanup_state !== "pending" && ready[item.id]) actions.push({ key: "enable", label: `Enable ${item.name}`, onSelect: () => setChanging(item) });
    if (manage && canRotateIPsecKeys(item)) actions.push({ key: "rotate", label: `Rotate keys for ${item.name}`, onSelect: () => { setNotice(""); setRotating(item); } });
    if (manage && item.desired_intent !== "deleted") actions.push({ key: "delete", label: `Delete ${item.name}`, danger: true, onSelect: () => setDeleting(item) });
    return actions;
  }
  return <div className="network-management ipsec-workspace">
    <h2 className="sr-only">IPsec VPN connections</h2>
    {notice && <p role="status" className="text-sm text-ink-secondary">{notice}</p>}
    {selected ? <ProviderReadback key={selected.id} orgId={orgId} id={selected.id} name={selected.name} onClose={() => setSelected(null)} /> : <>
      <div className="ipsec-toolbar">
        <div className="ipsec-inventory-toolbar">
          <Input aria-label="Search VPN connections" placeholder="Search this page…" value={search} onChange={event => setSearch(event.target.value)} />
          <Select aria-label="Connection status" value={filter} onChange={event => setFilter(event.target.value)}>{groups.map(group => <option key={group.key} value={group.key}>{group.label} ({items.filter(group.matches).length})</option>)}</Select>
          <span className="ipsec-filter-scope">This page</span>
        </div>
        <div className="ipsec-toolbar-actions">
          <Button variant="ghost" disabled={loading} onClick={() => void refresh()}>Refresh</Button>
          {manage && settings && !onRequestCreate && <Button disabled={!settings.enabled || loading} onClick={() => setCreating(true)}>New connection</Button>}
        </div>
      </div>
      {settings && <div className="ipsec-opt-in features-referral"><p>IPsec is {settings.enabled ? "enabled" : "off"} for this organization.</p>{manage && <Link to="/settings?section=features&feature=ipsec">Manage in Features</Link>}</div>}
      <ErrorText>{error}</ErrorText>
      {error && <Button variant="ghost" disabled={loading} onClick={() => { const failed = failedPage.current; void (failed ? loadPage(failed.cursor, failed.limit, failed.history) : refresh()); }}>Retry connections</Button>}
      {loading ? <p role="status" className="text-sm text-ink-secondary">Loading IPsec configurations…</p> : !error && <>
      {visible.length === 0 ? <div className="ipsec-empty" role="status">
        <h3>{search || filter !== "all" ? "No connections match your filters." : cursors.length > 1 ? "No connections on this page" : "No IPsec connections configured."}</h3>
        {search || filter !== "all" ? <Button variant="ghost" onClick={() => { setSearch(""); setFilter("all"); }}>Clear filters</Button> : <>
          <p>{cursors.length > 1 ? "Return to the previous page or refresh the inventory." : !manage ? "An administrator can configure a cloud VPN." : !settings?.enabled ? "Enable IPsec to add a cloud VPN." : onRequestCreate ? "Use Create connection to choose an IPsec provider." : "Choose a local gateway and enter your AWS VPN details. New connections are saved disabled."}</p>
          {manage && settings?.enabled && !onRequestCreate && <Button variant="ghost" onClick={() => setCreating(true)}>Create IPsec connection</Button>}
        </>}
      </div> : <div className="ipsec-inventory">
        <DataTable<Connection> caption="IPsec connections" variant="flat" rows={visible} pageSize={0} rowKey={item => item.id} failed={false} filterable={false} empty="No connections on this page." columns={[
          { key: "name", header: "Connection", cell: item => <button className="ipsec-connection-name" onClick={() => setSelected({ id: item.id, name: item.name })}>{item.name}</button> },
          { key: "network", header: "Local network", cell: item => sites.find(site => site.id === item.site_id)?.name ?? "Network unavailable" },
          { key: "state", header: "Configuration", cell: item => <><span title={item.cleanup_state === "retained_guard" ? "Tunnel traffic is stopped. Safety guard remains; network ranges stay reserved." : item.application_state === "applied" ? "Gateway applied this revision. End-to-end traffic is not verified." : undefined} className={`ipsec-state ${item.cleanup_state === "pending" || (item.desired_intent === "enabled" && item.application_state !== "applied") ? "ipsec-state-pending" : item.desired_intent === "enabled" ? "ipsec-state-applied" : ""}`}>{connectionStatus(item)}</span></> },
          { key: "actions", header: "Actions", cell: item => <div className="ipsec-row-actions"><AppAccessRowMenu label={`Connection actions for ${item.name}`} actions={rowActions(item)} /></div> },
        ]} />
        <p className="ipsec-inventory-note">Applied describes gateway configuration. Open connection details for reported tunnel health.</p>
      </div>}
      {(hasOtherPages || items.length > 10) && <nav className="ipsec-pagination" aria-label="IPsec connection pagination">
        <span>{visible.length} of {items.length} on this page</span>
        <div className="ipsec-pagination-controls"><span>Rows per page</span><Select aria-label="Rows per page" width="auto" value={String(pageSize)} disabled={loading} onChange={event => changePageSize(Number(event.target.value))}>{appAccessPageSizes.map(size => <option key={size} value={size}>{size}</option>)}</Select>
          {hasOtherPages && <><span>Page {cursors.length}</span><Button variant="ghost" aria-label="Previous connections" disabled={loading || cursors.length <= 1} onClick={() => changePage("previous")}>Previous</Button><Button variant="ghost" aria-label="Next connections" disabled={loading || !next} onClick={() => changePage("next")}>Next</Button></>}
        </div>
      </nav>}
      </>}
    </>}
    {manage && creating && settings?.enabled && <ConnectionForm orgId={orgId} sites={sites} onCancel={() => setCreating(false)} onSaved={(id, name) => { if (!alive.current) return; setCreating(false); setSelected({ id, name }); void refresh(); }} />}
    {manage && changing && <ChangeIntent orgId={orgId} connection={changing} onClose={() => setChanging(null)} onChanged={() => { if (!alive.current) return; setChanging(null); void refresh(); }} />}
    {manage && rotating && <IPsecRotateKeys key={rotating.id} orgId={orgId} connection={rotating} onClose={() => setRotating(null)} onSaved={() => { if (!alive.current) return; setRotating(null); setNotice("Keys saved. Update your remote VPN, then enable this connection."); void refresh(); }} />}
    {manage && deleting && <DeleteConnection orgId={orgId} connection={deleting} onClose={() => setDeleting(null)} onDeleted={() => { if (!alive.current) return; setDeleting(null); setSelected(null); void refresh(); }} />}
  </div>;
}
function ProviderReadback({ orgId, id, name, onClose }: { orgId: string; id: string; name: string; onClose: () => void }) {
  const [result, setResult] = useState<Provider | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => { let cancelled = false; setResult(null); setError(""); void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId: id } } })).then(value => { if (cancelled) return; if (value.ok) setResult(value.data); else setError("No provider configuration could be loaded for this record."); }); return () => { cancelled = true; }; }, [orgId, id, attempt]);
  return <section className="ipsec-details" aria-label={`${name} details`}>
    <nav className="ipsec-breadcrumbs" aria-label="IPsec connection breadcrumb"><button onClick={onClose}>Back to connections</button><span aria-hidden="true">/</span><span aria-current="page">{name}</span></nav>
    <div className="ipsec-detail-heading"><h3>{name}</h3>{result && <span>AWS · IPv4 static · revision {result.configuration_revision}</span>}</div>
    <ErrorText>{error}</ErrorText>{!result && !error && <p role="status">Loading configuration…</p>}
    {error && <Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry configuration</Button>}
    {result && <>
      {!result.configuration ? <p className="text-sm text-ink-secondary">Configuration removed. Identity retained.</p> : <div className="space-y-4">
        <ResourceSummary title="Stored configuration" headingLevel={4}><dl className="tnx-resource-facts tnx-resource-facts-three"><div><dt>Customer public IP</dt><dd>{result.configuration.customer_outside_address}</dd></div><div><dt>Local networks</dt>{result.configuration.local_prefixes.map(value => <dd key={value}>{value}</dd>)}</div><div><dt>Remote networks</dt>{result.configuration.remote_prefixes.map(value => <dd key={value}>{value}</dd>)}</div></dl></ResourceSummary>
        <div><IPsecTunnelHealth orgId={orgId} connectionId={id} tunnels={result.configuration.tunnels} /></div>
      </div>}</>}
  </section>;
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
function ConnectionForm({ orgId, sites, onCancel, onSaved }: { orgId: string; sites: Site[]; onCancel: () => void; onSaved: (id: string, name: string) => void }) {
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
    if (result.ok) { frozen.current = null; setTunnels([blankTunnel(), blankTunnel()]); onSaved(id, result.data.name); return true; }
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
      if (result.data && !result.error) { frozen.current = null; setTunnels([blankTunnel(), blankTunnel()]); onSaved(result.data.id, result.data.name); return; }
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
    <form onSubmit={event => { event.preventDefault(); if (step === 1) { if (prepared) setStep(2); } else void save(); }} autoComplete="off" className="ipsec-setup-form">
      <ol className="ipsec-setup-steps" aria-label="IPsec setup steps"><li aria-current={step === 1 ? "step" : undefined}><span aria-hidden="true">1</span>Networks</li><li aria-current={step === 2 ? "step" : undefined}><span aria-hidden="true">2</span>Tunnels</li></ol>
      <p className="ipsec-setup-intro">{step === 1 ? "Choose an approved local range and an AWS VPN endpoint." : "Enter both tunnel configurations from your AWS VPN. This connection will be saved disabled."}</p>
      <fieldset disabled={busy || uncertain} className="ipsec-setup-fields">
        {step === 1 ? <>
          <Field label="Name"><Input required value={name} maxLength={255} onChange={event => setName(event.target.value)} placeholder="Office to AWS" /></Field>
          <div className="ipsec-setup-grid"><Field label="Local network"><Select required value={site} onChange={event => { setSite(event.target.value); setGateway(""); setLocal([]); setSubnets([]); setEligibility(null); }}><option value="">Choose a network</option>{sites.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</Select></Field>
            <Field label="Gateway"><Select required value={gateway} onChange={event => { setGateway(event.target.value); setEligibility(null); }}><option value="">Choose a gateway</option>{selectedGateways.map(node => <option key={node.id} value={node.id}>{node.name}</option>)}</Select></Field></div>
          <fieldset className="ipsec-local-ranges"><legend>Approved local ranges</legend><div>{subnets.map(subnet => <label key={subnet.id}><input type="checkbox" checked={local.includes(subnet.cidr)} onChange={event => setLocal(old => event.target.checked ? [...old, subnet.cidr] : old.filter(value => value !== subnet.cidr))} />{subnet.cidr}</label>)}</div>{site && subnets.length === 0 && <p className="text-xs text-ink-secondary">No approved ranges available.</p>}</fieldset>
          <div className="ipsec-setup-grid"><Field label="Customer public IP"><Input required value={customer} onChange={event => setCustomer(event.target.value)} placeholder="Public gateway or NAT IP" /></Field><Field label="Remote network ranges"><Input required value={remote} onChange={event => setRemote(event.target.value)} placeholder="CIDRs, separated by commas" /></Field></div>
        </> : <div className="ipsec-setup-grid">{tunnels.map((tunnel, i) => <div key={i} className="ipsec-tunnel-fields"><h3>Tunnel {i + 1}</h3>{([
          ["outside_address", "outside IP"], ["inside_cidr", "inside CIDR"], ["customer_inside_address", "customer IP"], ["cloud_inside_address", "cloud IP"], ["psk", "PSK"],
        ] as const).map(([field, label]) => <Field key={field} label={`Tunnel ${i + 1} ${label}`}><Input required type={field === "psk" ? "password" : "text"} autoComplete={field === "psk" ? "new-password" : "off"} spellCheck={false} value={tunnel[field]} onChange={event => setTunnels(old => old.map((value, n) => n === i ? { ...value, [field]: event.target.value } : value))} /></Field>)}</div>)}</div>}
      </fieldset>
      <div className="ipsec-setup-readiness"><p role="status" className="text-ink-secondary">{checking ? "Checking gateway support…" : currentEligibility ? eligibilityText[currentEligibility.reason] : "Choose a network and gateway to check support."}</p>{site && gateway && <Button type="button" variant="ghost" size="sm" disabled={busy || checking} onClick={() => setCheckAttempt(value => value + 1)}>Check support</Button>}</div>
      <ErrorText>{error}</ErrorText>
      <div className="ipsec-setup-actions"><Button type="button" variant="ghost" onClick={cancel}>Cancel</Button>{step === 2 && !uncertain && <Button type="button" variant="ghost" disabled={busy} onClick={() => setStep(1)}>Back</Button>}{step === 1 ? <Button type="submit" disabled={!prepared || busy}>Next: tunnels</Button> : <Button type="submit" disabled={busy || (!uncertain && (checking || !currentEligibility?.eligible))}>{busy ? "Saving…" : uncertain ? "Retry save" : "Save disabled connection"}</Button>}</div>
    </form>
  </Modal>;
}
