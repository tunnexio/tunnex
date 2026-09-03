import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FaAws } from "react-icons/fa";
import { SiGooglecloud } from "react-icons/si";
import { VscAzure } from "react-icons/vsc";
import { Icon, type IconName } from "./Icon";
import { LoadRetry } from "./LoadRetry";
import { Button, Card, ErrorText, Field, Input, Loading, Modal, Select } from "./ui";
import { api, apiErrorCode, apiErrorMessage, loadOne, type FQDNResolverContextConfig, type FQDNResolverEndpoint, type FQDNResolverProfile, type FQDNResolverProfileRequest, type FQDNResolverProvider, type Member, type Node, type Site } from "../lib/api";
import { can } from "../lib/rbac";

const providers: Array<{ id: FQDNResolverProvider; name: string; icon?: IconName; guidance: string }> = [
  { id: "aws", name: "AWS", guidance: "Route 53 Resolver inbound endpoint or VPC DNS forwarder reachable from this gateway." },
  { id: "azure", name: "Microsoft Azure", guidance: "Azure DNS Private Resolver inbound endpoint or private DNS forwarder reachable from this gateway." },
  { id: "google_cloud", name: "Google Cloud", guidance: "Cloud DNS inbound or forwarding resolver endpoint reachable from this gateway." },
  { id: "on_premises", name: "On-premises", icon: "building-2", guidance: "Private DNS resolver reachable from this gateway path." },
];
const providerFor = (id?: string | null) => providers.find((provider) => provider.id === id);
const emptyEndpoint = (): FQDNResolverEndpoint => ({ address: "", port: 53, transport: "udp" });
const emptyProfile = (): FQDNResolverProfileRequest => ({ name: "", provider_hint: "aws", zone_suffixes: [""], endpoints: [emptyEndpoint()] });

export function providerName(id?: string | null) { return providerFor(id)?.name ?? "On-premises"; }
export function resolverProfiles(config: FQDNResolverContextConfig): FQDNResolverProfile[] {
  if (config.profiles?.length) return config.profiles;
  return [{
    id: config.id,
    name: `${providerName(config.provider_hint)} private DNS`,
    provider_hint: config.provider_hint ?? "on_premises",
    zone_suffixes: [],
    endpoints: config.endpoints ?? [],
    legacy_default: true,
  }];
}

export type ResolverProfileMatch = { profile: FQDNResolverProfile; matchedSuffix: string };

/** Mirrors the server's label-boundary, longest-suffix selection for preview only. */
export function matchResolverProfile(hostname: string, config: FQDNResolverContextConfig): ResolverProfileMatch | null {
  const normalizedHostname = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!normalizedHostname) return null;

  let selected: ResolverProfileMatch | null = null;
  let legacy: FQDNResolverProfile | null = null;
  const owners = new Map<string, string>();
  for (const profile of resolverProfiles(config)) {
    if (profile.legacy_default) {
      if (legacy) return null;
      legacy = profile;
    }
    for (const rawSuffix of profile.zone_suffixes) {
      const suffix = rawSuffix.trim().toLowerCase().replace(/\.$/, "");
      if (!suffix) return null;
      const owner = owners.get(suffix);
      if (owner && owner !== profile.id) return null;
      owners.set(suffix, profile.id);
      if (normalizedHostname !== suffix && !normalizedHostname.endsWith(`.${suffix}`)) continue;
      if (!selected || suffix.length > selected.matchedSuffix.length) {
        selected = { profile, matchedSuffix: suffix };
      } else if (suffix.length === selected.matchedSuffix.length && profile.id !== selected.profile.id) {
        return null;
      }
    }
  }
  return selected ?? (legacy ? { profile: legacy, matchedSuffix: "" } : null);
}

export function ProviderMark({ provider }: { provider?: string | null }) {
  const item = providerFor(provider) ?? providers[3];
  const mark = item.id === "aws" ? <FaAws size={20} color="#ff9900" /> : item.id === "azure" ? <VscAzure size={20} color="#0089d6" /> : item.id === "google_cloud" ? <SiGooglecloud size={20} color="#4285f4" /> : <Icon name={item.icon ?? "building-2"} size={18} />;
  return <span aria-hidden="true" className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-white/[.06] text-ink-emphasis">{mark}</span>;
}

export function PrivateDNSResolvers({ orgId, role }: { orgId: string; role: Member["role"] | undefined }) {
  const canView = can(role, "fqdn_resource:view"), canManage = can(role, "fqdn_resource:manage");
  const [sites, setSites] = useState<Site[] | null>(null), [nodes, setNodes] = useState<Node[] | null>(null);
  const [inventoryError, setInventoryError] = useState(""), [siteId, setSiteId] = useState(""), [gatewayId, setGatewayId] = useState("");
  const [config, setConfig] = useState<FQDNResolverContextConfig | null>(null), [configLoading, setConfigLoading] = useState(false), [configError, setConfigError] = useState(""), [missing, setMissing] = useState(false);
  const [dialog, setDialog] = useState<"configure" | "delete" | null>(null), [profiles, setProfiles] = useState<FQDNResolverProfileRequest[]>([emptyProfile()]), [busy, setBusy] = useState(false);
  const request = useRef(0);
  const gateways = useMemo(() => (nodes ?? []).filter((node) => node.status === "active" && node.site_id === siteId), [nodes, siteId]);
  const selectedSite = sites?.find((site) => site.id === siteId), selectedGateway = nodes?.find((node) => node.id === gatewayId);
  const configProfiles = config ? resolverProfiles(config) : [];

  const loadInventory = useCallback(async () => {
    if (!canView) return;
    setInventoryError(""); setSites(null); setNodes(null);
    const [siteResult, nodeResult] = await Promise.all([loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId } } })), loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } }))]);
    if (!siteResult.ok) return setInventoryError(siteResult.error); if (!nodeResult.ok) return setInventoryError(nodeResult.error);
    const loadedSites = siteResult.data as Site[], loadedNodes = nodeResult.data as Node[]; setSites(loadedSites); setNodes(loadedNodes);
    const first = loadedSites.find((site) => loadedNodes.some((node) => node.status === "active" && node.site_id === site.id));
    setSiteId((current) => current && loadedSites.some((site) => site.id === current) ? current : first?.id ?? "");
  }, [canView, orgId]);
  useEffect(() => { void loadInventory(); }, [loadInventory]);
  useEffect(() => { if (!nodes || !siteId) return setGatewayId(""); const available = nodes.filter((node) => node.status === "active" && node.site_id === siteId); setGatewayId((current) => available.some((node) => node.id === current) ? current : available[0]?.id ?? ""); }, [nodes, siteId]);
  const loadConfig = useCallback(async () => {
    const sequence = ++request.current; setConfig(null); setMissing(false); setConfigError(""); if (!siteId || !gatewayId) return; setConfigLoading(true);
    try { const result = await api.GET("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", { params: { path: { orgId, siteId, gatewayId } } }); if (sequence !== request.current) return; if (result.error) { if (apiErrorCode(result.error) === "fqdn_resolver_config_not_found") setMissing(true); else setConfigError(apiErrorMessage(result.error, "Could not load this resolver context.")); return; } if (result.data) setConfig(result.data); }
    catch { if (sequence === request.current) setConfigError("Could not reach the API."); } finally { if (sequence === request.current) setConfigLoading(false); }
  }, [gatewayId, orgId, siteId]);
  useEffect(() => { void loadConfig(); }, [loadConfig]);

  const openConfigure = () => {
    const current = configProfiles.map((profile) => ({ name: profile.legacy_default ? providerName(profile.provider_hint) + " private DNS" : profile.name, provider_hint: profile.provider_hint, zone_suffixes: profile.legacy_default ? [""] : [...profile.zone_suffixes], endpoints: profile.endpoints.map((endpoint) => ({ ...endpoint })) }));
    setProfiles(current?.length ? current : [emptyProfile()]); setConfigError(""); setDialog("configure");
  };
  const suffixes = profiles.flatMap((profile) => profile.zone_suffixes.map((suffix) => suffix.trim().toLowerCase()).filter(Boolean));
  const duplicates = new Set(suffixes).size !== suffixes.length;
  const profilesValid = profiles.length >= 1 && profiles.length <= 16 && !duplicates && profiles.every((profile) => profile.name.trim() && profile.zone_suffixes.length >= 1 && profile.zone_suffixes.every((suffix) => suffix.trim() && !suffix.includes("*") && !suffix.startsWith(".") && !suffix.endsWith(".")) && profile.endpoints.length >= 1 && profile.endpoints.length <= 8 && profile.endpoints.every((endpoint) => endpoint.address.trim() && Number(endpoint.port) >= 1 && Number(endpoint.port) <= 65535));
  const updateProfile = (index: number, next: Partial<FQDNResolverProfileRequest>) => setProfiles((current) => current.map((profile, position) => position === index ? { ...profile, ...next } : profile));
  const updateEndpoint = (profileIndex: number, endpointIndex: number, next: Partial<FQDNResolverEndpoint>) => setProfiles((current) => current.map((profile, position) => position !== profileIndex ? profile : { ...profile, endpoints: profile.endpoints.map((endpoint, index) => index === endpointIndex ? { ...endpoint, ...next } : endpoint) }));
  async function save() {
    if (!profilesValid || !siteId || !gatewayId) return; setBusy(true); setConfigError("");
    const body = { profiles: profiles.map((profile) => ({ ...profile, name: profile.name.trim(), zone_suffixes: profile.zone_suffixes.map((suffix) => suffix.trim().toLowerCase()), endpoints: profile.endpoints.map((endpoint) => ({ ...endpoint, address: endpoint.address.trim(), port: Number(endpoint.port) })) })) };
    try { const result = await api.PUT("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", { params: { path: { orgId, siteId, gatewayId } }, body }); if (result.error) return setConfigError(apiErrorMessage(result.error, "Could not activate these DNS profiles.")); setDialog(null); await loadConfig(); }
    catch { setConfigError("Could not reach the API. Your changes were not confirmed."); } finally { setBusy(false); }
  }
  async function remove() { if (!siteId || !gatewayId) return; setBusy(true); setConfigError(""); try { const result = await api.DELETE("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", { params: { path: { orgId, siteId, gatewayId } } }); if (result.error) return setConfigError(apiErrorMessage(result.error, "Could not remove this resolver context.")); setDialog(null); await loadConfig(); } catch { setConfigError("Could not reach the API."); } finally { setBusy(false); } }
  if (!canView) return null;

  return <Card><section aria-labelledby="private-dns-heading" className="space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 id="private-dns-heading" className="text-lg font-semibold text-ink-heading">Private DNS resolvers</h2><p className="mt-1 text-sm text-ink-tertiary">One path, multiple DNS zones · most-specific zone wins</p></div>{canManage && config && <div className="flex items-center gap-1"><Button size="sm" variant="ghost" onClick={openConfigure}>Edit profiles</Button><button className="inline-flex min-h-8 items-center rounded-md px-2.5 text-xs font-medium text-danger hover:bg-danger/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400" aria-label="Remove resolver" onClick={() => setDialog("delete")}>Remove</button></div>}</div>
    {inventoryError ? <LoadRetry error={"Could not load Sites and Gateways: " + inventoryError} onRetry={() => void loadInventory()} /> : sites === null || nodes === null ? <Loading label="Loading resolver paths…" /> : <><div className="grid max-w-4xl gap-2 sm:grid-cols-2"><Field label="Site"><Select value={siteId} onChange={(event) => setSiteId(event.target.value)}><option value="">Select a Site</option>{sites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}</Select></Field><Field label="Gateway"><Select value={gatewayId} disabled={!siteId} onChange={(event) => setGatewayId(event.target.value)}><option value="">Select a Gateway</option>{gateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}</Select></Field></div>
      {!siteId || !gatewayId ? <p className="rounded-md border border-line px-3 py-2 text-sm text-ink-tertiary">Select an active Site and Gateway.</p> : configLoading ? <Loading label="Loading private DNS resolvers…" /> : configError && dialog === null ? <LoadRetry error={configError} onRetry={() => void loadConfig()} /> : config ? <div className="overflow-hidden rounded-md border border-white/10"><div className="flex flex-wrap items-center justify-between gap-2 bg-white/[.025] px-3 py-2 text-xs"><span className="text-ink-tertiary">{configProfiles.length} {configProfiles.length === 1 ? "profile" : "profiles"} · version {config.version}</span><span className="inline-flex items-center gap-1.5 font-medium text-ok"><span className="h-1.5 w-1.5 rounded-full bg-ok" aria-hidden="true" />Active</span></div><div className="divide-y divide-white/10">{configProfiles.map((profile) => <article key={profile.id} className="grid gap-3 px-3 py-3 sm:grid-cols-[minmax(180px,.8fr)_minmax(180px,1fr)_minmax(220px,1.4fr)] sm:items-center"><div className="flex min-w-0 items-center gap-3"><ProviderMark provider={profile.provider_hint} /><div className="min-w-0"><p className="truncate font-semibold text-ink-heading">{profile.name}</p><p className="truncate text-xs text-ink-tertiary">{providerName(profile.provider_hint)}</p></div></div><div className="min-w-0"><p className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">DNS zones</p><p className="mt-1 truncate text-sm text-ink-body" title={profile.legacy_default ? "Legacy catch-all" : profile.zone_suffixes.join(", ")}>{profile.legacy_default ? "Legacy catch-all" : profile.zone_suffixes.join(" · ")}</p></div><div className="min-w-0"><p className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">Endpoints</p><ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1">{profile.endpoints.map((endpoint) => <li key={endpoint.address+endpoint.port+endpoint.transport} className="font-mono text-xs text-ink-body">{endpoint.address}:{endpoint.port} <span className="text-ink-tertiary">· {endpoint.transport.toUpperCase()}</span></li>)}</ul></div></article>)}</div></div> : missing ? <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line px-3 py-2"><p className="text-sm text-ink-tertiary">No resolver profiles for {selectedSite?.name} · {selectedGateway?.name}.</p>{canManage && <Button size="sm" onClick={openConfigure}>Configure profiles</Button>}</div> : null}</>}

    {dialog === "configure" && <Modal size="wide" title={config ? "Activate new DNS profile version" : "Configure private DNS profiles"} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !profilesValid} onClick={() => void save()}>Activate profiles</Button></>}><div className="space-y-4"><p className="text-xs text-ink-tertiary">Most-specific DNS zone wins. If no zone matches, Tunnex fails closed and sends no DNS request. Profiles are never fallback targets for one another.</p><ErrorText>{configError}</ErrorText>{profiles.map((profile, profileIndex) => <fieldset key={profileIndex} className="space-y-3 rounded-md border border-line p-4"><legend className="px-1 text-sm font-semibold text-ink-heading">Profile {profileIndex+1}</legend><div className="grid gap-3 sm:grid-cols-2"><Field label="Profile name"><Input value={profile.name} placeholder="AWS production" onChange={(event) => updateProfile(profileIndex,{name:event.target.value})} /></Field><Field label="Provider"><Select aria-label={"Profile "+(profileIndex+1)+" provider"} value={profile.provider_hint} onChange={(event) => updateProfile(profileIndex,{provider_hint:event.target.value as FQDNResolverProvider})}>{providers.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field></div><div className="flex items-center gap-2 rounded-inset bg-white/[.04] px-3 py-2"><ProviderMark provider={profile.provider_hint} /><p className="text-xs text-ink-tertiary">{providerFor(profile.provider_hint)?.guidance}</p></div><Field label="DNS zone suffixes"><Input aria-label={"Profile "+(profileIndex+1)+" DNS zone suffixes"} placeholder="internal.example.com, corp.example.com" value={profile.zone_suffixes.join(", ")} onChange={(event) => updateProfile(profileIndex,{zone_suffixes:event.target.value.split(",").map((value)=>value.trim())})} /></Field><p className="text-xs text-ink-tertiary">Enter comma-separated suffixes without wildcards. Subdomains match automatically.</p><div className="space-y-2">{profile.endpoints.map((endpoint, endpointIndex) => <div key={endpointIndex} className="grid gap-2 rounded-inset border border-line p-3 sm:grid-cols-[minmax(0,1fr)_120px_100px_auto]"><Input aria-label={`Profile ${profileIndex+1} endpoint ${endpointIndex+1} IP`} placeholder="10.20.0.53" value={endpoint.address} onChange={(event) => updateEndpoint(profileIndex,endpointIndex,{address:event.target.value})} /><Select aria-label={`Profile ${profileIndex+1} endpoint ${endpointIndex+1} transport`} value={endpoint.transport} onChange={(event) => updateEndpoint(profileIndex,endpointIndex,{transport:event.target.value as "udp"|"tcp"})}><option value="udp">UDP</option><option value="tcp">TCP</option></Select><Input aria-label={`Profile ${profileIndex+1} endpoint ${endpointIndex+1} port`} inputMode="numeric" value={String(endpoint.port)} onChange={(event) => updateEndpoint(profileIndex,endpointIndex,{port:Number(event.target.value)})} />{profile.endpoints.length>1 && <Button size="sm" variant="ghost" aria-label={`Remove profile ${profileIndex+1} endpoint ${endpointIndex+1}`} onClick={() => updateProfile(profileIndex,{endpoints:profile.endpoints.filter((_,i)=>i!==endpointIndex)})}>Remove</Button>}</div>)}</div><div className="flex flex-wrap gap-2">{profile.endpoints.length<8 && <Button size="sm" variant="ghost" onClick={() => updateProfile(profileIndex,{endpoints:[...profile.endpoints,emptyEndpoint()]})}>Add endpoint</Button>}{profiles.length>1 && <Button size="sm" variant="ghost" aria-label={`Remove profile ${profileIndex+1}`} onClick={() => setProfiles((current)=>current.filter((_,i)=>i!==profileIndex))}>Remove profile</Button>}</div></fieldset>)}{profiles.length<16 && <Button size="sm" variant="ghost" onClick={() => setProfiles((current)=>[...current,emptyProfile()])}>Add provider profile</Button>}{duplicates && <ErrorText>Each DNS zone suffix can belong to only one profile.</ErrorText>}{!profilesValid && !duplicates && <ErrorText>Complete every profile with a name, one or more zone suffixes, and valid literal endpoints.</ErrorText>}<div className="rounded-inset border border-line px-3 py-2 text-xs text-ink-tertiary"><strong className="text-ink-heading">Resolver path:</strong> {selectedSite?.name} → {selectedGateway?.name}. Cloud accounts and zones are not discovered or provisioned.</div></div></Modal>}
    {dialog === "delete" && config && <Modal title="Remove private DNS resolvers?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>Remove resolver</Button></>}><p className="text-cell text-ink-tertiary">FQDN resources on this path will fail closed.</p><ErrorText>{configError}</ErrorText></Modal>}
  </section></Card>;
}
