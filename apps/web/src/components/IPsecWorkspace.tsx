import "../network-workspaces.css";
import "../ipsec-workspace.css";
import { ResourceSummary } from "./ResourceSummary";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, loadOne, type Member, type Node, type Site, type SiteSubnet } from "../lib/api";
import { PrivateDNSResolvers } from "./PrivateDNSResolvers";
import { Button, DataTable, ErrorText, Field, Input, Modal, Select, RefreshButton } from "./ui";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "./AppAccessRowMenu";
import { appAccessPageSizes } from "./AppAccessPagination";
import { AWS_GENERIC_MAX_BYTES, AWS_REQUIRED_CRYPTO, AWSImportError, parseAWSGeneric } from "../lib/awsVpnImport";
import { IPsecTunnelHealth } from "./IPsecTunnelHealth";
import { IPsecRotateKeys, canRotateIPsecKeys } from "./IPsecRotateKeys";

type Connection = components["schemas"]["IPsecConnection"];
type Settings = components["schemas"]["IPsecSettings"];
type Configuration = components["schemas"]["IPsecConfigurationCheckInput"];
type CreateInput = components["schemas"]["IPsecProviderCreateInput"];
type Provider = components["schemas"]["IPsecProviderConfiguration"];
type ConnectionPage = components["schemas"]["IPsecConnectionPage"];
type Eligibility = components["schemas"]["IPsecEligibility"];
function canEnableConfiguration(provider: Provider, eligibility: Eligibility): boolean {
  if (!eligibility.eligible) return false;
  if (provider.profile_id === "aws-static-ipv4-v1" && provider.configuration?.mode === "ipv4-static") return true;
  if (provider.profile_id === "gcp-classic-static-ipv4-v1") return provider.configuration?.mode === "ipv4-static" && provider.configuration.tunnels.length === 1 && eligibility.gcp_classic?.eligible === true;
  if (provider.profile_id === "gcp-ha-bgp-ipv4-v1") return provider.configuration?.mode === "ipv4-bgp" && provider.configuration.tunnels.length === 2 && eligibility.bgp?.eligible === true && eligibility.gcp_ha?.eligible === true;
  if (["azure-active-active-bgp-ipv4-v1", "azure-active-active-static-ipv4-v1", "azure-active-standby-bgp-ipv4-v1", "azure-active-standby-static-ipv4-v1"].includes(provider.profile_id)) {
    const expected = provider.profile_id.startsWith("azure-active-standby-") ? 1 : 2;
    const dynamic = provider.profile_id.endsWith("-bgp-ipv4-v1");
    return provider.configuration?.tunnels.length === expected && provider.configuration.mode === (dynamic ? "ipv4-bgp" : "ipv4-static") && (dynamic ? eligibility.bgp?.eligible === true && eligibility.azure_bgp?.eligible === true : eligibility.azure_static?.eligible === true);
  }
  return provider.profile_id === "aws-bgp-ipv4-v1" && provider.configuration?.mode === "ipv4-bgp" && eligibility.bgp?.eligible === true;
}
function privateASN(value: string): boolean {
  const n = Number(value);
  return /^\d+$/.test(value) && Number.isSafeInteger(n) && ((n >= 64512 && n <= 65534) || (n >= 4200000000 && n <= 4294967294));
}
export type IPsecCreateProfile = "aws" | "gcp-ha-bgp-ipv4-v1" | "gcp-classic-static-ipv4-v1" | "azure-active-active-bgp-ipv4-v1" | "azure-active-active-static-ipv4-v1" | "azure-active-standby-bgp-ipv4-v1" | "azure-active-standby-static-ipv4-v1";
const createProfiles: { id: IPsecCreateProfile; label: string }[] = [
  { id: "aws", label: "AWS Site-to-Site VPN" },
  { id: "gcp-ha-bgp-ipv4-v1", label: "Google Cloud HA VPN · BGP" },
  { id: "gcp-classic-static-ipv4-v1", label: "Google Cloud Classic VPN · static" },
  { id: "azure-active-active-bgp-ipv4-v1", label: "Azure active-active · BGP" },
  { id: "azure-active-active-static-ipv4-v1", label: "Azure active-active · static" },
  { id: "azure-active-standby-bgp-ipv4-v1", label: "Azure active-standby · BGP" },
  { id: "azure-active-standby-static-ipv4-v1", label: "Azure active-standby · static" },
];
type AzureSKU = "VpnGw1" | "VpnGw2" | "VpnGw3" | "VpnGw4" | "VpnGw5" | "VpnGw1AZ" | "VpnGw2AZ" | "VpnGw3AZ" | "VpnGw4AZ" | "VpnGw5AZ";
function singleTunnel(profile: string) { return profile === "gcp-classic-static-ipv4-v1" || profile.startsWith("azure-active-standby-"); }
function initialMode(profile: string): Configuration["mode"] { return profile.endsWith("-bgp-ipv4-v1") ? "ipv4-bgp" : "ipv4-static"; }
function providerName(profile: string) { return profile.startsWith("azure-") ? "Azure" : profile.startsWith("gcp-") ? "Google Cloud" : "AWS"; }
export function azureSettingsReview(provider: Provider) {
  const config = provider.configuration;
  if (!provider.profile_id.startsWith("azure-") || !config?.azure) return null;
  return { profile_id: provider.profile_id, configuration_revision: provider.configuration_revision,
    azure: { gateway_sku: config.azure.gateway_sku, vpn_type: config.azure.vpn_type,
      ike_version: config.azure.ike_version, custom_policy: config.azure.custom_policy,
      use_policy_based_traffic_selectors: config.azure.use_policy_based_traffic_selectors, nat_enabled: config.azure.nat_enabled },
    mode: config.mode, customer_outside_address: config.customer_outside_address,
    local_prefixes: config.local_prefixes, remote_prefixes: config.remote_prefixes,
    ...(config.bgp ? { bgp: { local_asn: config.bgp.local_asn, remote_asn: config.bgp.remote_asn, router_id: config.bgp.router_id, maximum_prefixes: config.bgp.maximum_prefixes } } : {}),
    tunnels: config.tunnels.map((tunnel, index) => ({ slot: index + 1, outside_address: tunnel.outside_address,
      inside_cidr: tunnel.inside_cidr, customer_inside_address: tunnel.customer_inside_address, cloud_inside_address: tunnel.cloud_inside_address })) };
}
function remoteASNLabel(profile: string) { return profile.startsWith("azure-") ? "Azure gateway ASN" : profile.startsWith("gcp-") ? "Cloud Router ASN" : "AWS ASN"; }
type Props = { initialProfile?: IPsecCreateProfile; createRequest?: number; onCreateHandled?: () => void; onRequestCreate?: () => void; orgId: string; userId: string; emailVerified: boolean; role?: string; sites: Site[] };
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
function IPsecSession({ orgId, emailVerified, role, sites, initialProfile = "aws", createRequest = 0, onRequestCreate, onCreateHandled }: Props) {
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
      const [result, provider] = await Promise.all([
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: item.site_id!, gateway_node_id: item.gateway_node_id! } } })),
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId: item.id } } })),
      ]);
      return [item.id, result.ok && provider.ok && canEnableConfiguration(provider.data, result.data)] as const;
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
    {selected ? <ProviderReadback key={selected.id} orgId={orgId} id={selected.id} name={selected.name} role={role as Member["role"]} connection={items.find(item => item.id === selected.id)} onClose={() => setSelected(null)} /> : <>
      <div className="ipsec-toolbar">
        <div className="ipsec-inventory-toolbar">
          <Input aria-label="Search VPN connections" placeholder="Search this page…" value={search} onChange={event => setSearch(event.target.value)} />
          <Select aria-label="Connection status" value={filter} onChange={event => setFilter(event.target.value)}>{groups.map(group => <option key={group.key} value={group.key}>{group.label} ({items.filter(group.matches).length})</option>)}</Select>
          <span className="ipsec-filter-scope">This page</span>
        </div>
        <div className="ipsec-toolbar-actions">
          <RefreshButton label="Refresh" disabled={loading} onClick={() => void refresh()} />
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
          <p>{cursors.length > 1 ? "Return to the previous page or refresh the inventory." : !manage ? "An administrator can configure a cloud VPN." : !settings?.enabled ? "Enable IPsec to add a cloud VPN." : onRequestCreate ? "Use Create connection to choose an IPsec provider." : "Choose a local gateway and enter your cloud VPN details. New connections are saved disabled."}</p>
          {manage && settings?.enabled && !onRequestCreate && <Button variant="ghost" onClick={() => setCreating(true)}>Create IPsec connection</Button>}
        </>}
      </div> : <div className="ipsec-inventory">
        <DataTable<Connection> caption="IPsec connections" variant="flat" rows={visible} pageSize={0} rowKey={item => item.id} failed={false} filterable={false} empty="No connections on this page." columns={[
          { key: "name", header: "Connection", cell: item => <button className="ipsec-connection-name" onClick={() => setSelected({ id: item.id, name: item.name })}>{item.name}</button> },
          { key: "network", header: "Local network", cell: item => sites.find(site => site.id === item.site_id)?.name ?? "Network unavailable" },
          { key: "state", header: "Configuration", cell: item => <><span title={item.desired_intent !== "enabled" && item.cleanup_state === "retained_guard" ? "Tunnel traffic is stopped. Safety guard remains; network ranges stay reserved." : item.application_state === "applied" ? "Gateway applied this revision. End-to-end traffic is not verified." : undefined} className={`ipsec-state ${item.cleanup_state === "pending" || (item.desired_intent === "enabled" && item.application_state !== "applied") ? "ipsec-state-pending" : item.desired_intent === "enabled" ? "ipsec-state-applied" : ""}`}>{connectionStatus(item)}</span></> },
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
    {manage && creating && settings?.enabled && <ConnectionForm key={initialProfile} initialProfile={initialProfile} orgId={orgId} sites={sites} onCancel={() => setCreating(false)} onSaved={(id, name, enable) => { if (!alive.current) return; setCreating(false); setSelected({ id, name }); if (enable) setChanging(enable); void refresh(); }} />}
    {manage && changing && <ChangeIntent orgId={orgId} connection={changing} onClose={() => setChanging(null)} onChanged={() => { if (!alive.current) return; setChanging(null); void refresh(); }} />}
    {manage && rotating && <IPsecRotateKeys key={rotating.id} orgId={orgId} connection={rotating} onClose={() => setRotating(null)} onSaved={() => { if (!alive.current) return; setRotating(null); setNotice("Keys saved. Update your remote VPN, then enable this connection."); void refresh(); }} />}
    {manage && deleting && <DeleteConnection orgId={orgId} connection={deleting} onClose={() => setDeleting(null)} onDeleted={() => { if (!alive.current) return; setDeleting(null); setSelected(null); void refresh(); }} />}
  </div>;
}
function ProviderReadback({ orgId, id, name, role, connection, onClose }: { orgId: string; id: string; name: string; role: Member["role"] | undefined; connection?: Connection; onClose: () => void }) {
  const [result, setResult] = useState<Provider | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [dnsOpen, setDNSOpen] = useState(false);
  useEffect(() => { let cancelled = false; setResult(null); setError(""); void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId: id } } })).then(value => { if (cancelled) return; if (value.ok) setResult(value.data); else setError("No provider configuration could be loaded for this record."); }); return () => { cancelled = true; }; }, [orgId, id, attempt]);
  return <section className="ipsec-details" aria-label={`${name} details`}>
    <nav className="ipsec-breadcrumbs" aria-label="IPsec connection breadcrumb"><button onClick={onClose}>Back to connections</button><span aria-hidden="true">/</span><span aria-current="page">{name}</span></nav>
    <div className="ipsec-detail-heading"><h3>{name}</h3>{result && <span>{providerName(result.profile_id)} · {result.configuration?.mode === "ipv4-bgp" ? "IPv4 BGP" : "IPv4 static"} · revision {result.configuration_revision}</span>}</div>
    <ErrorText>{error}</ErrorText>{!result && !error && <p role="status">Loading configuration…</p>}
    {error && <Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry configuration</Button>}
    {result && <>
      {azureSettingsReview(result) && <a className="text-sm text-ink-secondary underline" download={`${id}-azure-settings.json`} href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(azureSettingsReview(result), null, 2))}`}>Download nonsecret Azure settings review</a>}
      {!result.configuration ? <p className="text-sm text-ink-secondary">Configuration removed. Identity retained.</p> : <div className="space-y-4">
        <ResourceSummary title="Stored configuration" headingLevel={4}><dl className="tnx-resource-facts tnx-resource-facts-three"><div><dt>Customer public IP</dt><dd>{result.configuration.customer_outside_address}</dd></div><div><dt>Local networks</dt>{result.configuration.local_prefixes.map(value => <dd key={value}>{value}</dd>)}</div><div><dt>Remote networks</dt>{result.configuration.remote_prefixes.map(value => <dd key={value}>{value}</dd>)}</div></dl>
          {result.configuration.bgp && <dl className="mt-4 grid grid-cols-1 gap-4 text-sm sm:grid-cols-4">{[
            ["Customer ASN", result.configuration.bgp.local_asn], [remoteASNLabel(result.profile_id), result.configuration.bgp.remote_asn],
            ["Router ID", result.configuration.bgp.router_id], ["Maximum prefixes per peer", result.configuration.bgp.maximum_prefixes],
          ].map(([label, value]) => <div key={label}><dt className="text-ink-secondary">{label}</dt><dd className="font-mono">{value}</dd></div>)}</dl>}
        </ResourceSummary>
        {result.profile_id.startsWith("azure-") && result.configuration.azure && <ResourceSummary title="Stored Azure gateway contract" headingLevel={4}><dl className="tnx-resource-facts tnx-resource-facts-three"><div><dt>Gateway SKU</dt><dd>{result.configuration.azure.gateway_sku}</dd></div><div><dt>VPN and IKE</dt><dd>{result.configuration.azure.vpn_type} · IKEv{result.configuration.azure.ike_version}</dd></div><div><dt>Custom policy</dt><dd>AES256 / SHA256 / DHGroup14 · ESP AES256 / SHA256 / PFS2048</dd></div><div><dt>Topology</dt><dd>{result.configuration.tunnels.length === 1 ? "Active-standby" : "Active-active"}</dd></div><div><dt>NAT rules</dt><dd>Disabled</dd></div><div><dt>Policy-based selectors</dt><dd>Disabled</dd></div></dl></ResourceSummary>}
        <div><IPsecTunnelHealth orgId={orgId} connectionId={id} tunnels={result.configuration.tunnels} mode={result.configuration.mode === "ipv4-bgp" ? "ipv4-bgp" : "ipv4-static"} approvedRemotePrefixes={result.configuration.remote_prefixes} profileId={result.profile_id} /></div>
        {connection?.site_id && connection.gateway_node_id && connection.desired_intent !== "deleted" && <details className="s2s-disclosure" open={dnsOpen} onToggle={event => setDNSOpen(event.currentTarget.open)}>
          <summary>DNS records and forwarding</summary>
          <div className="mt-3 space-y-3"><p className="text-sm text-ink-secondary">Manage DNS for this connection's network and gateway. Use DNS records for an IP or load balancer hostname, or forward a private zone to its DNS server. DNS answers need separate application permissions and a working tunnel route.</p>
            {dnsOpen && <PrivateDNSResolvers orgId={orgId} role={role} scope={{ siteId: connection.site_id, gatewayId: connection.gateway_node_id }} />}
          </div>
        </details>}
      </div>}</>}
  </section>;
}
function ChangeIntent({ orgId, connection, onClose, onChanged }: { orgId: string; connection: Connection; onClose: () => void; onChanged: () => void }) {
  const alive = useLifetime(); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const intent = connection.desired_intent === "enabled" ? "disabled" : "enabled";
  const label = intent === "enabled" ? "Enable" : "Disable";
  async function change() {
    if (busy || error || !Number.isSafeInteger(connection.desired_revision)) return;
    setBusy(true); setError("");
    try {
      if (intent === "enabled") {
        const siteId = connection.site_id, gatewayId = connection.gateway_node_id;
        if (!siteId || !gatewayId) { setError("Gateway assignment is unavailable. Close and refresh."); return; }
        const [checked, provider] = await Promise.all([
          loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: siteId, gateway_node_id: gatewayId } } })),
          loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId: connection.id } } })),
        ]);
        if (!alive.current) return;
        if (!checked.ok || !provider.ok || !canEnableConfiguration(provider.data, checked.data)) { setError("Gateway readiness changed. Close and refresh before enabling."); return; }
      }
      const result = await api.PUT("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/intent", { params: { path: { orgId, connectionId: connection.id }, header: { "If-Match": `"${connection.desired_revision}"` } }, body: { intent } });
      if (!alive.current) return;
      if (result.error || !result.data) setError("Could not confirm the change. Close and refresh before retrying."); else onChanged();
    } catch { if (alive.current) setError("Could not confirm the change. Close and refresh before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title={`${label} connection?`} onDismiss={onClose} actions={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={busy || !!error || !Number.isSafeInteger(connection.desired_revision)} onClick={() => void change()}>{label} connection</Button></>}><p>{connection.name}</p><p className="mt-2 text-sm text-ink-secondary">{intent === "enabled" ? "Apply this configuration on its gateway. Access policies control which traffic is allowed." : "Stop tunnel traffic. Gateway cleanup may remain pending while the gateway is offline."}</p><ErrorText>{error}</ErrorText></Modal>;
}
function DeleteConnection({ orgId, connection, onClose, onDeleted }: { orgId: string; connection: Connection; onClose: () => void; onDeleted: () => void }) {
  const alive = useLifetime(); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function remove() {
    if (busy || error || !Number.isSafeInteger(connection.desired_revision)) return;
    setBusy(true); setError("");
    try { const result = await api.DELETE("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId, connectionId: connection.id }, header: { "If-Match": `"${connection.desired_revision}"` } } }); if (!alive.current) return; if (result.error || !result.data) setError("Could not confirm deletion. Close and refresh before retrying."); else onDeleted(); }
    catch { if (alive.current) setError("Could not confirm deletion. Close and refresh before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title="Delete connection?" onDismiss={onClose} actions={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="danger" disabled={busy || !!error || !Number.isSafeInteger(connection.desired_revision)} onClick={() => void remove()}>Delete connection</Button></>}><p>{connection.name}</p><p className="mt-2 text-sm text-ink-secondary">Removes the tunnel and credentials after gateway cleanup. Safety guards and reserved ranges remain for previously delivered tunnels.</p><ErrorText>{error}</ErrorText></Modal>;
}
const blankTunnel = (): Configuration["tunnels"][number] => ({ outside_address: "", inside_cidr: "", customer_inside_address: "", cloud_inside_address: "", psk: "" });
function ConnectionForm({ orgId, sites, initialProfile = "aws", onCancel, onSaved }: { initialProfile?: IPsecCreateProfile; orgId: string; sites: Site[]; onCancel: () => void; onSaved: (id: string, name: string, enable?: Connection) => void }) {
  const alive = useLifetime();
  const [ids] = useState(() => ({ id: crypto.randomUUID(), tunnels: [crypto.randomUUID(), crypto.randomUUID()] }));
  const [step, setStep] = useState(1); const [name, setName] = useState(""); const [site, setSite] = useState(""); const [gateway, setGateway] = useState("");
  const [nodes, setNodes] = useState<Node[]>([]); const [subnets, setSubnets] = useState<SiteSubnet[]>([]); const [local, setLocal] = useState<string[]>([]);
  const [customer, setCustomer] = useState(""); const [remote, setRemote] = useState(""); const [tunnels, setTunnels] = useState(() => singleTunnel(initialProfile) ? [blankTunnel()] : [blankTunnel(), blankTunnel()]);
  const [profile, setProfile] = useState<IPsecCreateProfile>(initialProfile);
  const gcp = profile.startsWith("gcp-");
  const azure = profile.startsWith("azure-");
  const oneTunnel = singleTunnel(profile);
  const [importing, setImporting] = useState(false);
  const [awsImport, setAWSImport] = useState<{ cryptoMatches: boolean } | null>(null);
  const [awsAcknowledged, setAWSAcknowledged] = useState(false);
  const connectAfterSave = useRef(false);
  const [azureSKU, setAzureSKU] = useState<AzureSKU>("VpnGw1AZ");
  const classic = profile === "gcp-classic-static-ipv4-v1";
  const [mode, setMode] = useState<Configuration["mode"]>(initialMode(initialProfile));
  const [localASN, setLocalASN] = useState("65000"); const [remoteASN, setRemoteASN] = useState(initialProfile.startsWith("azure-") ? "65515" : "64512");
  const [routerID, setRouterID] = useState(""); const [maximumPrefixes, setMaximumPrefixes] = useState("64");
  const [eligibility, setEligibility] = useState<{ key: string; value: Eligibility } | null>(null); const [checking, setChecking] = useState(false); const [checkAttempt, setCheckAttempt] = useState(0);
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false);
  const frozen = useRef<CreateInput | null>(null); const saving = useRef(false);
  const pair = `${site}:${gateway}`;
  const importContext = useRef({ pair, revision: 0 });
  if (importContext.current.pair !== pair) importContext.current = { pair, revision: importContext.current.revision + 1 };
  useEffect(() => { let cancelled = false; void loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } })).then(result => { if (cancelled) return; if (result.ok) setNodes(result.data); else setError("Could not load gateways. Close and try again."); }); return () => { cancelled = true; }; }, [orgId]);
  useEffect(() => { let cancelled = false; setSubnets([]); setLocal([]); if (site) void loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", { params: { path: { orgId, siteId: site } } })).then(result => { if (cancelled) return; if (result.ok) setSubnets(result.data.filter(subnet => subnet.status === "approved")); else setError("Could not load approved ranges. Choose the network again."); }); return () => { cancelled = true; }; }, [orgId, site]);
  useEffect(() => { let cancelled = false; setEligibility(null); if (!site || !gateway) { setChecking(false); return; } setChecking(true); void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: site, gateway_node_id: gateway } } })).then(result => { if (cancelled) return; setChecking(false); if (result.ok) setEligibility({ key: pair, value: result.data }); else setError("Could not check gateway support. Try again."); }); return () => { cancelled = true; }; }, [orgId, site, gateway, pair, checkAttempt]);
  useEffect(() => () => { frozen.current = null; }, []);
  const currentEligibility = eligibility?.key === pair ? eligibility.value : null;
  const selectedGateways = nodes.filter(node => node.site_id === site && node.status === "active");
  const bgpPrepared = mode === "ipv4-static" || (privateASN(localASN) && (privateASN(remoteASN) || (profile === "aws" && remoteASN === "7224") || (azure && remoteASN === "65515")) && Number(localASN) !== Number(remoteASN) && routerID.trim() && /^\d+$/.test(maximumPrefixes) && Number(maximumPrefixes) >= 1 && Number(maximumPrefixes) <= 64);
  const prepared = name.trim() && site && selectedGateways.some(node => node.id === gateway) && local.length && customer && remote.trim() && bgpPrepared;
  async function importAWS(file: File | undefined) {
    if (profile !== "aws" || !file || importing) return;
    const context = importContext.current.revision;
    setError(""); setImporting(true); setAWSAcknowledged(false); connectAfterSave.current = false;
    try {
      if (!file.size || file.size > AWS_GENERIC_MAX_BYTES) throw new AWSImportError("Choose a nonempty AWS Generic text file no larger than 64 KiB.");
      const imported = parseAWSGeneric(await file.text());
      if (!alive.current || context !== importContext.current.revision) return;
      setAWSImport({ cryptoMatches: imported.cryptoMatches });
      setName(old => old.trim() ? old : imported.name);
      setMode(imported.mode); setCustomer(imported.customerOutsideAddress); setTunnels(imported.tunnels);
      if (imported.bgp) {
        setLocalASN(String(imported.bgp.localASN)); setRemoteASN(String(imported.bgp.remoteASN));
        setRouterID(old => old.trim() ? old : imported.customerOutsideAddress);
      }
    } catch (error) {
      if (alive.current && context === importContext.current.revision) setError(error instanceof AWSImportError ? error.message : "AWS file could not be read. Choose the downloaded Generic text file or enter the settings manually.");
    } finally { if (alive.current) setImporting(false); }
  }
  async function importAzure(file: File | undefined) {
    if (!azure || !file || importing || !site || !gateway) return;
    setError(""); setImporting(true);
    try {
      if (file.size > 65536 || file.size === 0) throw new Error();
      const input: unknown = JSON.parse(await file.text());
      if (!object(input) || typeof input.profile_id !== "string" || !["azure-active-active-bgp-ipv4-v1", "azure-active-active-static-ipv4-v1", "azure-active-standby-bgp-ipv4-v1", "azure-active-standby-static-ipv4-v1"].includes(input.profile_id)) throw new Error();
      const allowed = ["profile_id", "azure", "mode", "transport_version", "tunnel_count", "bgp", "customer_outside_address", "local_prefixes", "remote_prefixes", "tunnels"];
      if (Object.keys(input).some(key => !allowed.includes(key)) || !Array.isArray(input.local_prefixes) || input.local_prefixes.length === 0 || !input.local_prefixes.every(prefix => typeof prefix === "string" && subnets.some(subnet => subnet.cidr === prefix)) || !Array.isArray(input.remote_prefixes) || !input.remote_prefixes.every(prefix => typeof prefix === "string") || typeof input.customer_outside_address !== "string" || !object(input.azure)) throw new Error();
      const contract = input.azure;
      if (Object.keys(contract).length !== 6 || Object.keys(contract).some(key => !["gateway_sku", "vpn_type", "ike_version", "custom_policy", "use_policy_based_traffic_selectors", "nat_enabled"].includes(key)) || !["VpnGw1", "VpnGw2", "VpnGw3", "VpnGw4", "VpnGw5", "VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ"].includes(String(contract.gateway_sku)) || contract.vpn_type !== "RouteBased" || contract.ike_version !== 2 || contract.custom_policy !== "aes256-sha256-dh14-pfs2048" || contract.use_policy_based_traffic_selectors !== false || contract.nat_enabled !== false) throw new Error();
      if (input.mode === "ipv4-bgp" && (!object(input.bgp) || Object.keys(input.bgp).length !== 4 || Object.keys(input.bgp).some(key => !["local_asn", "remote_asn", "router_id", "maximum_prefixes"].includes(key)) || !Number.isSafeInteger(input.bgp.local_asn) || !Number.isSafeInteger(input.bgp.remote_asn) || !Number.isSafeInteger(input.bgp.maximum_prefixes) || typeof input.bgp.router_id !== "string")) throw new Error();
      if (input.mode === "ipv4-static" && input.bgp !== undefined) throw new Error();
      const count = singleTunnel(input.profile_id) ? 1 : 2;
      if (count === 2 && Array.isArray(input.tunnels) && object(input.tunnels[0]) && object(input.tunnels[1]) && input.tunnels[0].psk !== input.tunnels[1].psk) throw new Error();
      if (input.mode === "ipv4-bgp" && Array.isArray(input.tunnels)) {
        const customerAddress = object(input.tunnels[0]) ? input.tunnels[0].customer_inside_address : null;
        if (typeof customerAddress !== "string" || !/^169\.254\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})$/.test(customerAddress) || !input.tunnels.every(tunnel => object(tunnel) && tunnel.customer_inside_address === customerAddress && tunnel.inside_cidr === `${customerAddress}/32`)) throw new Error();
      }
      if (count === 1 && (input.transport_version !== 1 || input.tunnel_count !== 1)) throw new Error();
      if (input.mode !== initialMode(input.profile_id) || !Array.isArray(input.tunnels) || input.tunnels.length !== count || !input.tunnels.every(tunnel => object(tunnel) && Object.keys(tunnel).every(key => ["outside_address", "inside_cidr", "customer_inside_address", "cloud_inside_address", "psk"].includes(key)) && ["outside_address", "inside_cidr", "customer_inside_address", "cloud_inside_address", "psk"].every(key => typeof tunnel[key] === "string"))) throw new Error();
      // The shared validator owns detailed cryptography, ASN, APIPA and transport contracts.
      const configuration = input as unknown as Configuration;
      const checked = await api.POST("/api/v1/organizations/{orgId}/ipsec/configuration-check", { params: { path: { orgId } }, body: configuration });
      if (!alive.current) return;
      if (checked.error || checked.data?.valid !== true) throw new Error();
      setProfile(input.profile_id as IPsecCreateProfile); setMode(configuration.mode); setAzureSKU(configuration.azure!.gateway_sku as AzureSKU);
      setCustomer(configuration.customer_outside_address); setLocal(configuration.local_prefixes); setRemote(configuration.remote_prefixes.join(", "));
      setTunnels(configuration.tunnels.map(tunnel => ({ ...tunnel })));
      if (configuration.bgp) { setLocalASN(String(configuration.bgp.local_asn)); setRemoteASN(String(configuration.bgp.remote_asn)); setRouterID(configuration.bgp.router_id); setMaximumPrefixes(String(configuration.bgp.maximum_prefixes)); }
    } catch { if (alive.current) setError("Azure JSON was not imported. Use a supported Tunnex Azure configuration with this network's approved local ranges, matching topology and complete gateway settings."); }
    finally { if (alive.current) setImporting(false); }
  }
  function cancel() { frozen.current = null; setTunnels(oneTunnel ? [blankTunnel()] : [blankTunnel(), blankTunnel()]); onCancel(); }
  function finishSaved(connection: Connection) {
    // Creation is finished before activation begins. The existing intent dialog owns
    // all later retries, so an uncertain enable can never create another connection.
    const requested = connectAfterSave.current;
    const expected = frozen.current;
    const enable = requested && connection.id === expected?.id && connection.org_id === orgId && connection.site_id === expected?.site_id && connection.gateway_node_id === expected?.gateway_node_id && connection.desired_intent === "disabled" && connection.cleanup_state === "not_required" && !connection.deleted_at ? connection : undefined;
    frozen.current = null; connectAfterSave.current = false;
    setTunnels(oneTunnel ? [blankTunnel()] : [blankTunnel(), blankTunnel()]);
    onSaved(connection.id, connection.name, enable);
  }
  async function recover(id: string) {
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId, connectionId: id } } }));
    if (!alive.current) return false;
    if (result.ok) { finishSaved(result.data); return true; }
    return false;
  }
  async function save(connect = false) {
    if (saving.current || (!uncertain && (!prepared || !currentEligibility?.eligible))) return;
    if (!uncertain) {
      if (connect && (!awsImport || !awsAcknowledged || (mode === "ipv4-bgp" && !currentEligibility?.bgp?.eligible))) return;
      connectAfterSave.current = connect;
    }
    if (!uncertain && azure && !oneTunnel && tunnels[0]?.psk !== tunnels[1]?.psk) { setError("Azure active-active tunnels share one connection and must use the same PSK."); return; }
    if (!uncertain && azure && mode === "ipv4-bgp" && tunnels.some(tunnel => tunnel.customer_inside_address !== tunnels[0]?.customer_inside_address || tunnel.inside_cidr !== `${tunnel.customer_inside_address}/32`)) { setError("Azure BGP requires the same customer APIPA address and its /32 on every tunnel, with distinct Azure peer addresses."); return; }
    saving.current = true; setBusy(true); setError("");
    let posted = false;
    const input: CreateInput = frozen.current ?? { id: ids.id, name, site_id: site, gateway_node_id: gateway, tunnel_ids: ids.tunnels.slice(0, oneTunnel ? 1 : 2), configuration: { mode, ...(azure ? { azure: { gateway_sku: azureSKU, vpn_type: "RouteBased", ike_version: 2, custom_policy: "aes256-sha256-dh14-pfs2048", use_policy_based_traffic_selectors: false, nat_enabled: false } } : {}), ...(azure && oneTunnel ? { transport_version: 1, tunnel_count: 1 } : {}), ...(profile === "aws" ? {} : { profile_id: profile }), ...(mode === "ipv4-bgp" ? { bgp: { local_asn: Number(localASN), remote_asn: Number(remoteASN), router_id: routerID.trim(), maximum_prefixes: Number(maximumPrefixes) } } : {}), customer_outside_address: customer, local_prefixes: local, remote_prefixes: remote.split(/[\s,]+/).filter(Boolean), tunnels: tunnels.map(tunnel => ({ ...tunnel })) } };
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
      if (checked.error || !checked.data?.valid) { setError(input.configuration.mode === "ipv4-bgp" ? "Check BGP settings, addresses, ranges and credentials before saving." : "Check the addresses, ranges and credentials before saving."); return; }
      frozen.current = input; posted = true;
      const result = await api.POST("/api/v1/organizations/{orgId}/ipsec/connections", { params: { path: { orgId } }, body: input });
      if (!alive.current) return;
      if (result.data && !result.error) { finishSaved(result.data); return; }
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
      <p className="ipsec-setup-intro">{step === 1 ? "Choose an approved local range and cloud VPN profile." : "Enter the cloud tunnel endpoints. This connection will be saved disabled."}</p>
      <fieldset disabled={busy || uncertain || importing} className="ipsec-setup-fields" onChange={() => { setAWSAcknowledged(false); if (!uncertain) connectAfterSave.current = false; }}>
        {step === 1 ? <>
          <Field label="Name"><Input required value={name} maxLength={255} onChange={event => setName(event.target.value)} placeholder="Office to cloud" /></Field>
          {profile === "aws" && <Field label="Import AWS Generic configuration"><Input aria-label="Import AWS Generic configuration" type="file" accept=".txt,text/plain" onChange={event => { const file = event.target.files?.[0]; event.target.value = ""; void importAWS(file); }} /><p className="text-xs text-ink-secondary">Upload the AWS Generic .txt download (up to 64 KiB) to fill both tunnels and routing settings. Supports IPv4 static or BGP with a Virtual Private Gateway or Transit Gateway. Select your local network, approved ranges and remote ranges below; this upload does not create an AWS attachment.</p></Field>}
          {azure && <Field label="Import Tunnex Azure JSON"><Input aria-label="Import Tunnex Azure JSON" type="file" accept=".json,application/json" disabled={!site || !gateway || importing} onChange={event => { const file = event.target.files?.[0]; event.target.value = ""; void importAzure(file); }} /><p className="text-xs text-ink-secondary">Select a network and gateway first. Imports are limited to 64 KiB and only prefill this disabled configuration draft. Native Azure exports are not supported.</p></Field>}
          <Field label="Cloud VPN profile"><Select value={profile} onChange={event => { const selected = event.target.value as typeof profile; if (!createProfiles.some(option => option.id === selected && providerName(option.id) === providerName(initialProfile))) return; setProfile(selected); setMode(initialMode(selected)); setRemoteASN(selected.startsWith("azure-") ? "65515" : "64512"); setTunnels(singleTunnel(selected) ? [blankTunnel()] : [blankTunnel(), blankTunnel()]); }}>{createProfiles.filter(option => providerName(option.id) === providerName(initialProfile)).map(option => <option key={option.id} value={option.id}>{option.label}</option>)}</Select></Field>
          {gcp && <p className="text-xs text-ink-secondary">{classic ? "Classic uses one route-based static tunnel. Configure exact local and remote routes plus the cloud return route. Inside BGP addresses do not apply." : "Use two HA VPN tunnel endpoints, one on each Google Cloud interface (0 and 1), with Cloud Router BGP. A single local gateway does not provide host redundancy or an availability SLA."}</p>}
          {azure && <Field label="Azure VPN Gateway SKU"><Select value={azureSKU} onChange={event => setAzureSKU(event.target.value as AzureSKU)}>{["VpnGw1", "VpnGw2", "VpnGw3", "VpnGw4", "VpnGw5", "VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ"].map(sku => <option key={sku} value={sku}>{sku}</option>)}</Select></Field>}
          {azure && <p className="text-xs text-ink-secondary">Use a route-based Azure VPN Gateway with {oneTunnel ? "one public endpoint on an active-standby gateway" : "two public endpoints on an active-active gateway"}. Select the actual Azure gateway SKU. IKEv2, route-based selectors and no NAT rules are required. Match the custom IKE/IPsec policy: AES256, SHA256, DHGroup14; ESP AES256, SHA256, PFS2048. {mode === "ipv4-bgp" ? "Use one customer APIPA address with its /32 on both tunnels and a distinct Azure peer address per instance in 169.254.21.0–169.254.22.255. The peer addresses need not share a subnet. Tunnex initiates BGP." : "Inside addresses below are local Tunnex runtime /30 addresses; Azure does not assign them for static routing."} Active-active tunnels must use the same PSK because they share one Azure connection. A single Tunnex gateway does not provide host redundancy.</p>}
          <Field label="Routing"><Select disabled={gcp || azure} value={mode} onChange={event => setMode(event.target.value as Configuration["mode"])}><option value="ipv4-static">Static routes</option><option value="ipv4-bgp">Dynamic routing (BGP)</option></Select></Field>
          <div className="ipsec-setup-grid"><Field label="Local network"><Select required value={site} onChange={event => { setSite(event.target.value); setGateway(""); setLocal([]); setSubnets([]); setEligibility(null); }}><option value="">Choose a network</option>{sites.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</Select></Field>
            <Field label="Gateway"><Select required value={gateway} onChange={event => { setGateway(event.target.value); setEligibility(null); }}><option value="">Choose a gateway</option>{selectedGateways.map(node => <option key={node.id} value={node.id}>{node.name}</option>)}</Select></Field></div>
          <fieldset className="ipsec-local-ranges"><legend>Approved local ranges</legend><div>{subnets.map(subnet => <label key={subnet.id}><input type="checkbox" checked={local.includes(subnet.cidr)} onChange={event => setLocal(old => event.target.checked ? [...old, subnet.cidr] : old.filter(value => value !== subnet.cidr))} />{subnet.cidr}</label>)}</div>{site && subnets.length === 0 && <p className="text-xs text-ink-secondary">No approved ranges available.</p>}</fieldset>
          <div className="ipsec-setup-grid"><Field label="Customer public IP"><Input required value={customer} onChange={event => setCustomer(event.target.value)} placeholder="Public gateway or NAT IP" /></Field><div><Field label="Remote network ranges"><Input required value={remote} onChange={event => setRemote(event.target.value)} placeholder="CIDRs, separated by commas" aria-describedby={`ipsec-remote-ranges-help-${ids.id}`} /></Field><p id={`ipsec-remote-ranges-help-${ids.id}`} className="mt-1 text-xs text-ink-secondary">Enter one or more CIDRs, separated by commas. Example: 10.180.0.0/16, 10.181.0.0/16.</p></div></div>
          {mode === "ipv4-bgp" && <fieldset className="space-y-3"><legend className="font-medium text-ink-heading">BGP settings</legend>
            <div className="ipsec-setup-grid">
              <Field label="Customer ASN"><Input type="number" required min={64512} max={4294967294} step={1} value={localASN} onChange={event => setLocalASN(event.target.value)} /></Field>
              <Field label={remoteASNLabel(profile)}><Input type="number" required min={1} max={4294967294} step={1} value={remoteASN} onChange={event => setRemoteASN(event.target.value)} /></Field>
              <Field label="Router ID"><Input aria-label="Router ID" required maxLength={15} value={routerID} onChange={event => setRouterID(event.target.value)} placeholder="Stable IPv4 router ID" />{awsImport && <p className="text-xs text-ink-secondary">Defaults to the imported customer public IP when empty. Keep a stable, unique IPv4 router ID.</p>}</Field>
              <Field label="Maximum prefixes per peer"><Input type="number" required min={1} max={64} step={1} value={maximumPrefixes} onChange={event => setMaximumPrefixes(event.target.value)} /></Field>
            </div>
            <p className="text-xs text-ink-secondary">Approved local ranges are advertised. Only the exact remote ranges above are accepted. Learning routes does not grant application access.</p>
          </fieldset>}
        </> : <><section aria-label="Connection review" className="space-y-3 rounded border border-line bg-surface-inset p-4">
          <h3 className="font-semibold text-ink-heading">Review connection</h3>
          <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2"><div><dt className="text-ink-secondary">Profile</dt><dd>{azure ? `Azure ${oneTunnel ? "active-standby" : "active-active"}` : classic ? "Google Cloud Classic VPN" : gcp ? "Google Cloud HA VPN" : "AWS Site-to-Site VPN"}</dd></div><div><dt className="text-ink-secondary">Routing</dt><dd>{mode === "ipv4-bgp" ? "Dynamic routing (BGP)" : "Static routes"}</dd></div><div><dt className="text-ink-secondary">Connection</dt><dd>{name}</dd></div><div><dt className="text-ink-secondary">Local ranges</dt><dd>{local.join(", ")}</dd></div><div><dt className="text-ink-secondary">Remote ranges</dt><dd>{remote}</dd></div></dl>
          {mode === "ipv4-bgp" && <p className="text-sm text-ink-secondary">Customer ASN {localASN} · {azure ? "Azure gateway" : gcp ? "Cloud Router" : "AWS"} ASN {remoteASN} · Router ID {routerID} · Maximum {maximumPrefixes} prefixes per peer</p>}
          <p className="text-xs text-ink-secondary">This connection is saved disabled. Access policies control traffic when you enable it.</p>
        </section><div className="ipsec-setup-grid">{tunnels.map((tunnel, i) => <div key={i} className="ipsec-tunnel-fields"><h3>Tunnel {i + 1}{gcp && !classic ? ` · GCP interface ${i}` : ""}</h3>{([
          ["outside_address", "outside IP"], ["inside_cidr", "inside CIDR"], ["customer_inside_address", "customer IP"], ["cloud_inside_address", "cloud IP"], ["psk", "PSK"],
        ] as const).filter(([field]) => !classic || field === "outside_address" || field === "psk").map(([field, label]) => <Field key={field} label={`Tunnel ${i + 1} ${azure && mode === "ipv4-static" && field !== "outside_address" && field !== "psk" ? "Tunnex runtime " : ""}${label}`}><Input required type={field === "psk" ? "password" : "text"} autoComplete={field === "psk" ? "new-password" : "off"} spellCheck={false} value={tunnel[field]} onChange={event => setTunnels(old => old.map((value, n) => n === i ? { ...value, [field]: event.target.value } : value))} /></Field>)}</div>)}</div></>}
      </fieldset>
      {awsImport && <section aria-label="AWS import review" className="space-y-2 rounded border border-line bg-surface-inset p-3 text-sm">
        <p>{awsImport.cryptoMatches ? "The template lists Tunnex’s required algorithms. Actual AWS tunnel options and negotiated health still need verification." : "The template lists algorithms different from Tunnex’s required profile. AWS Generic downloads can describe minimum examples; those algorithms are not imported."}</p>
        <p>Required profile: {AWS_REQUIRED_CRYPTO}. Tunnel addresses and PSKs were imported; access ranges remain your explicit choices.</p>
        {step === 2 && <><label className="flex items-start gap-2"><input type="checkbox" checked={awsAcknowledged} disabled={busy || uncertain || importing} onChange={event => setAWSAcknowledged(event.target.checked)} /><span>I have verified that both AWS tunnels allow Tunnex’s required IKEv2, AES256, SHA256 and DH/PFS group 14 profile.</span></label><p className="text-xs text-ink-secondary">Save disabled, or choose Create and connect for a final enable confirmation. The saved connection remains available if enabling fails. Reported tunnel health confirms connection status.</p></>}
      </section>}
      <div className="ipsec-setup-readiness"><p role="status" className="text-ink-secondary">{checking ? "Checking gateway support…" : currentEligibility ? eligibilityText[currentEligibility.reason] : "Choose a network and gateway to check support."}</p>{site && gateway && <Button type="button" variant="ghost" size="sm" disabled={busy || checking} onClick={() => setCheckAttempt(value => value + 1)}>Check support</Button>}</div>
      {mode === "ipv4-bgp" && currentEligibility?.eligible && !currentEligibility.bgp?.eligible && <p role="status" className="text-xs text-ink-secondary">You can save this BGP configuration disabled. Enabling requires a gateway with fresh BGP support.</p>}
      {gcp && !classic && currentEligibility?.eligible && !currentEligibility.gcp_ha?.eligible && <p role="status" className="text-xs text-ink-secondary">You can save this HA configuration disabled. Enabling requires fresh Google Cloud HA VPN support from this gateway.</p>}
      {classic && currentEligibility?.eligible && !currentEligibility.gcp_classic?.eligible && <p role="status" className="text-xs text-ink-secondary">You can save this Classic configuration disabled. Enabling requires fresh Google Cloud Classic VPN support from this gateway.</p>}
      {azure && currentEligibility?.eligible && !(mode === "ipv4-bgp" ? currentEligibility.azure_bgp?.eligible : currentEligibility.azure_static?.eligible) && <p role="status" className="text-xs text-ink-secondary">You can save this Azure configuration disabled. Enabling requires fresh Azure support from this gateway.</p>}
      <ErrorText>{error}</ErrorText>
      <div className="ipsec-setup-actions"><Button type="button" variant="ghost" onClick={cancel}>Cancel</Button>{step === 2 && !uncertain && <Button type="button" variant="ghost" disabled={busy} onClick={() => setStep(1)}>Back</Button>}{step === 1 ? <Button type="submit" disabled={!prepared || busy || importing}>Next: tunnels</Button> : <Button type="submit" disabled={busy || importing || (!uncertain && (checking || !currentEligibility?.eligible))}>{busy ? "Saving…" : uncertain ? "Retry save" : "Save disabled connection"}</Button>}{step === 2 && awsImport && !uncertain && <Button type="button" disabled={busy || importing || checking || !currentEligibility?.eligible || !awsAcknowledged || (mode === "ipv4-bgp" && !currentEligibility?.bgp?.eligible)} onClick={() => void save(true)}>Create and connect…</Button>}</div>
    </form>
  </Modal>;
}
