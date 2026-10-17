import type { components } from "@tunnex/shared";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorCode, apiErrorMessage, loadOne, type FQDNResolverContextConfig, type Member, type Node, type PolicyRule, type Site, type UserGroup } from "../lib/api";
import { hostnameDNSPlan, matchesHostnameResource, normalizedHostname, validHostname, type HostnameRecord, type HostnameResource } from "../lib/hostnameAccess";
import { ruleBody, sourceOptions } from "../lib/policyview";
import { matchResolverProfile } from "../lib/privateDNSProfiles";
import { EntityPicker, type PickerOption } from "./EntityPicker";
import { FQDNEnforcementSetting } from "./FQDNEnforcementSetting";
import { ModeSection } from "../pages/Access";
import { PrivateDNSCNAMEUpstreams, defaultCNAMEUpstreams, validCNAMEUpstreams } from "./PrivateDNSCNAMEUpstreams";
import { Button, ErrorText, Field, Input, Loading, Modal, Select } from "./ui";

type Connection = components["schemas"]["IPsecConnection"];
type Configuration = components["schemas"]["IPsecProviderConfiguration"];
type Subject = { kind: "user" | "group"; id: string; label: string };
type Props = { orgId: string; role: Member["role"]; site: Site; gateway: Node; connectionId?: string; record?: HostnameRecord; onClose: () => void; onSaved: () => void; onEditDNS?: () => void };
const enabledConnection = (item: Connection, site: string, gateway: string) => item.site_id === site && item.gateway_node_id === gateway
  && item.desired_intent === "enabled" && !item.deleted_at && !item.finalized_at && item.cleanup_state !== "pending";
const supportedConfiguration = (value: Configuration | null) => value?.profile_id === "aws-bgp-ipv4-v1"
  && value.configuration?.mode === "ipv4-bgp" && value.configuration_revision === 1;
const matchingRule = (rule: PolicyRule, subject: Subject, id: string) => rule.dst_kind === "fqdn_resource" && rule.dst_fqdn_resource_id === id
  && rule.src_kind === subject.kind && (subject.kind === "user" ? rule.src_user_id === subject.id : rule.src_group_id === subject.id)
  && rule.enabled && (!rule.expires_at || Date.parse(rule.expires_at) > Date.now());
function failure(error: unknown, fallback: string) {
  switch (apiErrorCode(error)) {
    case "fqdn_application_gateway_unsupported": return "This gateway has not reported current hostname-access support. Update the gateway, wait for its next report, then refresh prerequisites.";
    case "fqdn_application_path_unavailable": return "The selected connection or its configuration changed. Close this drawer and reopen it from the current connection.";
    default: return apiErrorMessage(error, fallback);
  }
}

/** One scoped editor; existing DNS, resources and policy remain the authorities.
 * Confirmed stages survive retries. An ambiguous write stops rather than replaying
 * a resource/rule POST whose result the browser cannot prove. */
export function HostnameAccessDialog({ orgId, role, site, gateway, connectionId: scopedConnection, record, onClose, onSaved, onEditDNS }: Props) {
  const [name, setName] = useState(record?.name ?? ""), [hostname, setHostname] = useState(record?.name ?? "");
  const [target, setTarget] = useState(record?.value ?? "");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp"), [port, setPort] = useState("443");
  const [upstreams, setUpstreams] = useState(defaultCNAMEUpstreams);
  const [existingDNS, setExistingDNS] = useState<FQDNResolverContextConfig | null>(null);
  const [members, setMembers] = useState<Member[]>([]), [groups, setGroups] = useState<UserGroup[]>([]), [subjects, setSubjects] = useState<Subject[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]), [connectionId, setConnectionId] = useState(scopedConnection ?? ""), [configuration, setConfiguration] = useState<Configuration | null>(null);
  const [loading, setLoading] = useState(true), [pathLoading, setPathLoading] = useState(false), [loadError, setLoadError] = useState(""), [pathError, setPathError] = useState("");
  const [supported, setSupported] = useState(false), [fqdnEnabled, setFQDNEnabled] = useState(false), [enforcing, setEnforcing] = useState(false);
  const [busy, setBusy] = useState(false), [started, setStarted] = useState(false), [uncertain, setUncertain] = useState(false), [error, setError] = useState("");
  const [progress, setProgress] = useState(""), [resource, setResource] = useState<HostnameResource | null>(null), [complete, setComplete] = useState(false);
  const alive = useRef(true), saving = useRef(false), committedStage = useRef(false), inventoryEpoch = useRef(0), pathEpoch = useRef(0), resourceId = useRef<string | null>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; inventoryEpoch.current++; pathEpoch.current++; }; }, []);
  const reload = useCallback(async () => {
    const epoch = ++inventoryEpoch.current; setLoading(true); setLoadError(""); setSupported(false);
    try {
      const [people, teams, eligibility, setting, mode, dns] = await Promise.all([
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })),
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } } })),
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/eligibility", { params: { path: { orgId }, query: { site_id: site.id, gateway_node_id: gateway.id } } })),
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/setting", { params: { path: { orgId } } })),
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", { params: { path: { orgId } } })),
        api.GET("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", { params: { path: { orgId, siteId: site.id, gatewayId: gateway.id } } }),
      ]);
      if (!alive.current || epoch !== inventoryEpoch.current) return;
      if (!people.ok || !teams.ok || !eligibility.ok || !setting.ok || !mode.ok || !Array.isArray(people.data) || !Array.isArray(teams.data)
        || typeof setting.data.enabled !== "boolean" || !["off", "enforcing"].includes(mode.data.mode)) throw new Error("Could not verify people, groups and access prerequisites. Refresh before saving.");
      if ((dns.error && apiErrorCode(dns.error) !== "fqdn_resolver_config_not_found") || (!dns.error && !dns.data?.id)) throw new Error("Could not verify this gateway's DNS profiles. Refresh before saving.");
      setExistingDNS(dns.data ?? null);
      setMembers((people.data as Member[]).filter(member => member.status === "active")); setGroups(teams.data as UserGroup[]);
      setSupported(eligibility.data.desktop_fqdn_supported === true);
      setFQDNEnabled(setting.data.enabled); setEnforcing(mode.data.mode === "enforcing");
      const rows: Connection[] = []; let after: string | undefined; const seen = new Set<string>();
      do {
        const result = await api.GET("/api/v1/organizations/{orgId}/ipsec/connections", { params: { path: { orgId }, query: { limit: 100, ...(after ? { after } : {}) } } });
        if (result.error || !Array.isArray(result.data?.items)) throw new Error("Could not load connections. Refresh before saving.");
        rows.push(...result.data.items); after = result.data.next_cursor ?? undefined;
        if (after && seen.has(after)) throw new Error("Could not finish loading connections.");
        if (after) seen.add(after);
      } while (after);
      if (!alive.current || epoch !== inventoryEpoch.current) return;
      const eligible = rows.filter(item => enabledConnection(item, site.id, gateway.id)); setConnections(eligible);
      setConnectionId(current => scopedConnection ?? (eligible.some(item => item.id === current) ? current : eligible.length === 1 ? eligible[0].id : ""));
    } catch (cause) { if (alive.current && epoch === inventoryEpoch.current) setLoadError(cause instanceof Error ? cause.message : "Could not load access prerequisites."); }
    finally { if (alive.current && epoch === inventoryEpoch.current) setLoading(false); }
  }, [orgId, site.id, gateway.id, scopedConnection]);
  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => {
    const epoch = ++pathEpoch.current; setConfiguration(null); setPathError("");
    if (!connectionId || !connections.some(item => item.id === connectionId)) { setPathLoading(false); return; }
    setPathLoading(true);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId } } })).then(result => {
      if (!alive.current || epoch !== pathEpoch.current) return;
      setPathLoading(false);
      if (!result.ok) setPathError(result.error); else setConfiguration(result.data);
    });
  }, [orgId, connectionId, connections]);
  const options = sourceOptions({ groups, members, sites: [], agents: [], dstKind: "fqdn_resource", dstSite: "" })
    .filter(option => !subjects.some(subject => subject.kind === option.kind && subject.id === option.value))
    .map(option => ({ ...option, value: `${option.kind}:${option.value}` }));
  function addSubject(option: PickerOption) {
    const kind = option.kind; if (kind !== "user" && kind !== "group") return;
    const id = option.value.slice(kind.length + 1);
    setSubjects(current => current.some(subject => subject.kind === kind && subject.id === id) ? current : [...current, { kind, id, label: option.label }]);
  }
  const existingProfile = existingDNS ? matchResolverProfile(hostname, existingDNS)?.profile : undefined;
  const recordDNSReady = existingProfile ? !existingProfile.legacy_default && !!existingProfile.static_records?.length && existingProfile.endpoints.length > 0 && validCNAMEUpstreams(existingProfile.endpoints) : upstreams.length > 0 && validCNAMEUpstreams(upstreams);
  const valid = name.trim() && validHostname(hostname) && validHostname(target) && (!record || record.type === "CNAME") && subjects.length > 0 && subjects.every(subject => subject.kind === "user" ? members.some(member => member.user_id === subject.id) : groups.some(group => group.id === subject.id))
    && /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535 && supportedConfiguration(configuration)
    && recordDNSReady;
  async function refreshResource(id: string) {
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } } }));
    if (!alive.current) return;
    if (result.ok && Array.isArray(result.data)) setResource((result.data as HostnameResource[]).find(item => item.id === id) ?? null);
    else setError("Saved, but the latest resolver status is unavailable. Refresh status before testing.");
  }
  async function save() {
    if (!alive.current || saving.current || loading || pathLoading || loadError || pathError || !supported || !valid || uncertain || complete || !configuration) return;
    saving.current = true; setBusy(true); setStarted(true); setError("");
    let writeUnconfirmed = false;
    try {
      const contextPath = { orgId, siteId: site.id, gatewayId: gateway.id };
      const path = { connection_id: connectionId, configuration_revision: 1 as const };
      setProgress("Checking the current connection and DNS record…");
      const currentConnection = await api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId, connectionId } } });
      if (!alive.current) return;
      if (currentConnection.error || !currentConnection.data || currentConnection.data.id !== connectionId || !enabledConnection(currentConnection.data, site.id, gateway.id)) throw new Error("This connection is no longer enabled on the selected network and gateway. Close and reopen this drawer before saving.");
      const currentPath = await api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/configuration", { params: { path: { orgId, connectionId } } });
      if (!alive.current) return;
      if (currentPath.error || !supportedConfiguration(currentPath.data ?? null) || currentPath.data?.configuration_revision !== path.configuration_revision) throw new Error("The connection configuration changed. Close and reopen this drawer before saving.");
      const dns = await api.GET("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", { params: { path: contextPath } });
      if (!alive.current) return;
      if (dns.error && apiErrorCode(dns.error) !== "fqdn_resolver_config_not_found") throw new Error(failure(dns.error, "Could not verify current DNS records."));
      if (!dns.error && !dns.data?.id) throw new Error("The server did not confirm the current DNS configuration. No changes were made.");
      const recordValue: HostnameRecord = { name: normalizedHostname(hostname), type: "CNAME", value: normalizedHostname(target), ttl: record?.ttl ?? 300 };
      const profiles = hostnameDNSPlan(dns.data ?? null, recordValue, upstreams, record);
      if (profiles) {
        setProgress("Saving the DNS record…"); writeUnconfirmed = true;
        const saved = await api.PUT("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", { params: { path: contextPath }, body: { profiles } });
        if (!alive.current) return;
        if (saved.error) { writeUnconfirmed = false; throw new Error(failure(saved.error, "Could not save the DNS record.")); }
        if (!saved.data?.id) throw new Error("The DNS save was not confirmed.");
        writeUnconfirmed = false; committedStage.current = true;
      }
      const inventory = await api.GET("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } } });
      if (!alive.current) return;
      if (inventory.error || !Array.isArray(inventory.data)) throw new Error("Could not verify existing hostname resources. DNS is saved; retry to continue.");
      const matching = (inventory.data as HostnameResource[]).filter(item => matchesHostnameResource(item, hostname, site.id, gateway.id, path, protocol, Number(port)));
      if (matching.length > 1) throw new Error("Multiple resources match this hostname and service. Review them in Access resources before adding a grant.");
      let selected = matching[0];
      if (resourceId.current && selected?.id !== resourceId.current) throw new Error("The saved resource changed. Review it in Access resources before continuing.");
      if (!selected) {
        setProgress("Creating the hostname resource…"); writeUnconfirmed = true;
        const body = { name: name.trim(), fqdn: normalizedHostname(hostname), protocol, port_low: Number(port), port_high: Number(port), resolver_context: { site_id: site.id, gateway_id: gateway.id }, application_ipsec_path: path };
        const saved = await api.POST("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } }, body });
        if (!alive.current) return;
        if (saved.error) { writeUnconfirmed = false; throw new Error(failure(saved.error, "Could not save the hostname resource. DNS is saved.")); }
        if (!saved.data?.id) throw new Error("The resource save was not confirmed.");
        selected = saved.data as HostnameResource; writeUnconfirmed = false;
      }
      resourceId.current = selected.id; committedStage.current = true; setResource(selected);
      const policies = await api.GET("/api/v1/organizations/{orgId}/policies", { params: { path: { orgId } } });
      if (!alive.current) return;
      if (policies.error || !Array.isArray(policies.data)) throw new Error("The hostname resource is saved. Could not verify existing grants; retry to continue.");
      for (const subject of subjects) {
        if ((policies.data as PolicyRule[]).some(rule => matchingRule(rule, subject, selected.id))) continue;
        setProgress(`Granting ${subject.label} access…`); writeUnconfirmed = true;
        const body = ruleBody({ srcKind: subject.kind, src: subject.kind === "group" ? subject.id : "", srcUser: subject.kind === "user" ? subject.id : "", srcSite: "", srcCidr: "", srcAgent: "", dstKind: "fqdn_resource", dstFQDNResource: selected.id, dstGroup: "", dstResource: "", dstSite: "", dstK8sService: "", expiresAt: "", editing: false });
        const saved = await api.POST("/api/v1/organizations/{orgId}/policies", { params: { path: { orgId } }, body });
        if (!alive.current) return;
        if (saved.error) { writeUnconfirmed = false; throw new Error(failure(saved.error, `Could not grant ${subject.label} access. Confirmed earlier steps are saved; retry continues the remaining grants.`)); }
        if (!saved.data?.id) throw new Error(`The grant for ${subject.label} was not confirmed.`);
        writeUnconfirmed = false;
      }
      setComplete(true); setProgress("DNS, hostname resource and access rules saved."); onSaved();
      await refreshResource(selected.id);
    } catch (cause) {
      if (alive.current) { setUncertain(writeUnconfirmed); setError((cause instanceof Error ? cause.message : "Could not complete hostname access.") + (writeUnconfirmed ? " Stop here and review the saved DNS, resource and rules before trying again; the request may have completed." : "")); }
    } finally { saving.current = false; if (alive.current) { setBusy(false); if (!committedStage.current && !writeUnconfirmed) setStarted(false); } }
  }
  return <Modal placement="right" size="enrollment" showClose title={record ? "Grant hostname access" : "Add hostname access"} onDismiss={() => { if (!busy) onClose(); }} actions={<><Button variant="ghost" disabled={busy} onClick={onClose}>{complete ? "Done" : "Close"}</Button>{!complete && <Button disabled={busy || loading || pathLoading || !valid || !supported || !!loadError || !!pathError || uncertain} onClick={() => void save()}>{busy ? "Saving…" : started ? "Continue saving" : "Save hostname access"}</Button>}</>}>
    <div className="space-y-5">
      <p className="text-sm text-ink-tertiary">Give selected people access to a private hostname through this connection. DNS and access rules are saved together in this flow.</p>
      <div className="rounded-inset border border-line p-3 text-sm"><strong>{site.name}</strong><span className="text-ink-tertiary"> → {gateway.name}</span></div>
      {loading ? <Loading label="Checking access prerequisites…" /> : loadError ? <ErrorText>{loadError}</ErrorText> : !supported ? <ErrorText>This gateway has not reported current hostname-access support. Update the gateway and wait for its next report, then refresh prerequisites.</ErrorText> : <p className="text-xs text-ink-tertiary">Gateway supports desktop hostname access. Traffic is limited to the connection's approved remote IPv4 ranges.</p>}
      {!busy && <Button size="sm" variant="ghost" onClick={() => void reload()}>Refresh prerequisites</Button>}
      <fieldset disabled={busy || started} className="space-y-4 disabled:opacity-75">
        <Field label="Connection"><Select value={connectionId} disabled={!!scopedConnection} onChange={event => setConnectionId(event.target.value)}><option value="">Select an enabled connection</option>{connections.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field>
        {pathLoading ? <Loading label="Checking connection…" /> : pathError ? <ErrorText>{pathError}</ErrorText> : configuration && !supportedConfiguration(configuration) ? <ErrorText>Desktop hostname access currently requires an AWS BGP connection.</ErrorText> : configuration && <p className="text-xs text-ink-tertiary">Approved application ranges: {configuration.configuration?.remote_prefixes.join(", ")}. The target must resolve to addresses within these ranges.</p>}
        <Field label="Display name"><Input value={name} maxLength={128} placeholder="Production web app" onChange={event => setName(event.target.value)} /></Field>
        <Field label="Private hostname"><Input value={hostname} disabled={!!record} placeholder="app.internal.example.com" onChange={event => { setHostname(event.target.value); if (!name || name === hostname) setName(event.target.value); }} /></Field>
        <Field label="Target hostname"><Input value={target} placeholder="internal-load-balancer.example.net" onChange={event => setTarget(event.target.value)} /></Field>
        <p className="text-xs text-ink-tertiary">Creates a CNAME alias to the application's DNS name. A and AAAA records remain available in the DNS profile editor.</p>
        {existingProfile ? <div className="space-y-2 rounded-inset border border-line p-3 text-xs text-ink-tertiary"><p>Uses DNS profile <strong>{existingProfile.name}</strong>. Target DNS servers: {existingProfile.endpoints.map(endpoint => endpoint.address).join(", ") || "not configured"}. Existing DNS settings are preserved.</p>{!recordDNSReady && <><ErrorText>This flow needs managed CNAME records with target lookup enabled. Update this DNS profile first.</ErrorText>{onEditDNS && <Button size="sm" variant="ghost" onClick={onEditDNS}>Edit DNS profile</Button>}</>}</div> : <PrivateDNSCNAMEUpstreams profileIndex={0} endpoints={upstreams} onChange={setUpstreams} />}
        <div className="grid grid-cols-2 gap-3"><Field label="Protocol"><Select value={protocol} onChange={event => setProtocol(event.target.value as "tcp" | "udp")}><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field><Field label="Service port"><Input inputMode="numeric" value={port} onChange={event => setPort(event.target.value)} /></Field></div>
        <EntityPicker label="Users and groups" options={options} value="" onSelect={addSubject} placeholder="Search people or groups…" />
        <ul className="flex flex-wrap gap-2">{subjects.map(subject => <li key={`${subject.kind}:${subject.id}`} className="flex items-center gap-2 rounded-md border border-line px-2 py-1 text-sm"><span>{subject.label} <span className="text-xs text-ink-tertiary">· {subject.kind}</span></span><button type="button" aria-label={`Remove ${subject.label}`} onClick={() => setSubjects(current => current.filter(item => item !== subject))} className="px-1 text-ink-tertiary hover:text-ink-heading">×</button></li>)}</ul>
        <p className="text-xs text-ink-tertiary">Access applies to the selected users' connected devices.</p>
      </fieldset>
      <details className="rounded-inset border border-line p-3"><summary className="cursor-pointer text-sm font-medium">Organization prerequisites · {loading ? "checking" : fqdnEnabled && enforcing ? "enabled" : "review required"}</summary><div className="mt-3 space-y-4"><p className="text-xs text-ink-tertiary">These settings affect the entire organization. Review their existing impact checks here; saving a hostname does not turn them on.</p><FQDNEnforcementSetting orgId={orgId} role={role} central canEdit /><ModeSection orgId={orgId} canManage central onPolicyChange={() => void reload()} /><Button size="sm" variant="ghost" onClick={() => void reload()}>Recheck prerequisites</Button></div></details>
      <p className="rounded-inset border border-line p-3 text-xs text-ink-tertiary">Access is enforced by resolved IP address and port. Other hostnames sharing the same load balancer IP and service port share this network access; HTTP hostname or TLS SNI isolation is not provided.</p>
      {progress && <p role="status" className="text-sm text-ink-heading">{progress}</p>}
      <ErrorText>{error}</ErrorText>
      {resource && <div className="space-y-2 rounded-inset border border-line p-3 text-sm"><p>Resolver state: <strong>{resource.state}</strong> · {resource.answer_count} active {resource.answer_count === 1 ? "address" : "addresses"}</p><p className="text-xs text-ink-tertiary">{!fqdnEnabled || !enforcing ? "Access is pending: enable both FQDN and Zero Trust enforcement after reviewing their impact above." : "Saved rules still require fresh DNS answers, gateway policy application and the cloud return path. Test the hostname from an authorized device to verify access."}</p><div className="flex flex-wrap items-center gap-3"><Button size="sm" variant="ghost" disabled={busy} onClick={() => void refreshResource(resource.id)}>Refresh resolver status</Button><Link className="text-accent-400 hover:underline" to={`/access/resources/fqdn/${resource.id}`}>View resource and access rules</Link></div></div>}
      {uncertain && <Link className="text-sm text-accent-400 hover:underline" to="/access/resources?type=fqdn">Review saved resources before retrying</Link>}
    </div>
  </Modal>;
}
