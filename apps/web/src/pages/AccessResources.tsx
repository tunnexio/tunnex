import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AccessTabRail } from "../components/AccessTabRail";
import { LoadRetry } from "../components/LoadRetry";
import { Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import { api, apiErrorMessage, loadOne, type FQDNResource, type FQDNResourceImpact, type FQDNResourceSetting, type Member, type Node, type Resource, type Site } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { can } from "../lib/rbac";

/** Canonical Access Resources workspace. Group management intentionally lives elsewhere. */
export default function AccessResources() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [authorized, setAuthorized] = useState<boolean | null>(null);
  const [role, setRole] = useState<Member["role"] | undefined>(undefined);
  const [resources, setResources] = useState<Resource[] | null>(null);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [selected, setSelected] = useState<Resource | null>(null);
  const [query, setQuery] = useState("");
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const [protocol, setProtocol] = useState<"any" | "tcp" | "udp">("any");
  const [portScope, setPortScope] = useState<"all" | "single" | "range">("all");
  const [portLow, setPortLow] = useState("");
  const [portHigh, setPortHigh] = useState("");
  const [portsTouched, setPortsTouched] = useState(false);
  const [saveAttempted, setSaveAttempted] = useState(false);
  const [busy, setBusy] = useState(false);
  const reload = useCallback(async () => {
    if (!org || authorized !== true) return;
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/resources", { params: { path: { orgId: org.id } } }));
    if (!result.ok) { setError(result.error); return; }
    setResources(result.data);
  }, [authorized, org?.id]);
  useEffect(() => {
    let cancelled = false;
    if (!org || state.status !== "authed") { setRole(undefined); setAuthorized(false); return; }
    setAuthorized(null);
    setRole(undefined);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); setAuthorized(false); return; }
      const mine = (result.data as Member[]).find((member) => member.user_id === state.user.id);
      setRole(mine?.role);
      setAuthorized(mine?.role === "owner" || mine?.role === "admin");
    });
    return () => { cancelled = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : ""]);
  useEffect(() => { void reload(); }, [reload]);
  async function mutate(call: () => Promise<{ error?: unknown }>, fallback: string) {
    setBusy(true); setError("");
    try { const result = await call(); if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; } return true; }
    catch { setError("Could not reach the API."); return false; }
    finally { setBusy(false); }
  }
  const openCreate = () => { setSelected(null); setName(""); setCidr(""); setLabel(""); setProtocol("any"); setPortScope("all"); setPortLow(""); setPortHigh(""); setPortsTouched(false); setSaveAttempted(false); setDialog("create"); };
  const openEdit = (resource: Resource) => { setSelected(resource); setName(resource.name); setCidr(resource.cidr); setLabel(resource.label ?? ""); setProtocol(resource.protocol); setPortScope(resource.port_low == null ? "all" : resource.port_high == null || resource.port_high === resource.port_low ? "single" : "range"); setPortLow(resource.port_low == null ? "" : String(resource.port_low)); setPortHigh(resource.port_high == null ? "" : String(resource.port_high)); setPortsTouched(false); setSaveAttempted(false); setDialog("edit"); };
  const parsedLow = portLow === "" ? null : Number(portLow);
  const parsedHigh = portHigh === "" ? null : Number(portHigh);
  const portsValid = protocol === "any" || portScope === "all" || (Number.isInteger(parsedLow) && parsedLow! >= 1 && parsedLow! <= 65535 && (portScope === "single" || (Number.isInteger(parsedHigh) && parsedHigh! >= parsedLow! && parsedHigh! <= 65535)));
  const showPortError = (portsTouched || saveAttempted) && !portsValid;
  const scopeSummary = protocol === "any" ? "Any protocol, all ports" : portScope === "all" ? `${protocol.toUpperCase()}, all ports` : portScope === "single" ? `${protocol.toUpperCase()} port ${portLow || "—"}` : `${protocol.toUpperCase()} ports ${portLow || "—"}–${portHigh || "—"}`;
  const requestBody = () => ({ name: name.trim(), cidr: cidr.trim(), protocol, label: label.trim() || null, ...(protocol === "any" || portScope === "all" ? { port_low: null, port_high: null } : portScope === "single" ? { port_low: parsedLow!, port_high: null } : { port_low: parsedLow!, port_high: parsedHigh! }) });
  async function save() {
    setSaveAttempted(true);
    if (!org || !name.trim() || !cidr.trim() || !portsValid) return;
    const body = requestBody();
    const ok = selected
      ? await mutate(() => api.PATCH("/api/v1/organizations/{orgId}/resources/{resourceId}", { params: { path: { orgId: org.id, resourceId: selected.id } }, body }), "Could not update the resource.")
      : await mutate(() => api.POST("/api/v1/organizations/{orgId}/resources", { params: { path: { orgId: org.id } }, body }), "Could not create the resource.");
    if (ok) { setDialog(null); await reload(); }
  }
  async function remove() {
    if (!org || !selected) return;
    const ok = await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/resources/{resourceId}", { params: { path: { orgId: org.id, resourceId: selected.id } } }), "Could not delete the resource.");
    if (ok) { setDialog(null); setSelected(null); await reload(); }
  }
  const header = <><PageHeader title="Resources" subtitle="Named destination ranges used by access policy rules." actions={authorized === true ? <Button onClick={openCreate}>Create resource</Button> : undefined} /><AccessTabRail /></>;
  if (!org || authorized === null) return <div className="space-y-5">{header}<Card><Loading label="Checking resource permissions…" /></Card></div>;
  if (!authorized) return <div className="space-y-5">{header}<Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage CIDR resources.</p><ErrorText>{error}</ErrorText></Card><FQDNResources key={org.id} orgId={org.id} role={role} /></div>;
  if (!resources) return <div className="space-y-5">{header}<Card><Loading label="Loading resources…" /><ErrorText>{error}</ErrorText></Card></div>;
  const filteredResources = resources.filter((resource) => `${resource.name} ${resource.cidr} ${resource.protocol}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="space-y-5">{header}<ErrorText>{error}</ErrorText><div className="max-w-md"><Input aria-label="Search resources" value={query} placeholder="Search resource name, CIDR, or protocol" onChange={(event) => setQuery(event.target.value)} /></div><Card><DataTable caption="Resources inventory" rows={filteredResources} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={25} empty={<EmptyState>{resources.length === 0 ? "No resources yet. Define named destination ranges so policy rules stay readable and reusable." : "No resources match this search."}</EmptyState>} columns={[{ key: "name", header: "Resource", cell: (resource) => <button className="font-medium text-ink-heading hover:underline" onClick={() => openEdit(resource)}>{resource.name}</button> }, { key: "label", header: "Description", cell: (resource) => resource.label || "—" }, { key: "cidr", header: "CIDR", cell: (resource) => resource.cidr }, { key: "protocol", header: "Protocol", cell: (resource) => resource.protocol === "any" ? "Any" : resource.protocol.toUpperCase() }, { key: "ports", header: "Ports", cell: (resource) => resource.protocol === "any" || resource.port_low == null ? "All" : resource.port_high == null || resource.port_high === resource.port_low ? String(resource.port_low) : `${resource.port_low}–${resource.port_high}` }, { key: "actions", header: "", cell: (resource) => <div className="flex gap-2"><Button size="sm" variant="ghost" onClick={() => openEdit(resource)}>Edit</Button><Button size="sm" variant="danger" onClick={() => { setSelected(resource); setDialog("delete"); }}>Delete</Button></div> }]} /></Card>
    <FQDNResources key={org.id} orgId={org.id} role={role} />
    {(dialog === "create" || dialog === "edit") && <Modal title={dialog === "edit" ? "Edit resource" : "Create resource"} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim() || !cidr.trim()} onClick={() => void save()}>{dialog === "edit" ? "Save resource" : "Create resource"}</Button></>}><p className="mb-3 text-cell text-ink-tertiary">A change here changes the destination every referencing rule can reach. Rules inherit this CIDR, protocol, and port scope.</p><div className="space-y-3"><Field label="Name"><Input value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field><Field label="Description (optional)"><Input value={label} onChange={(event) => setLabel(event.target.value)} /></Field><Field label="CIDR"><Input value={cidr} placeholder="10.0.5.0/24" onChange={(event) => setCidr(event.target.value)} /></Field><Field label="Protocol"><Select value={protocol} onChange={(event) => { const next = event.target.value as "any" | "tcp" | "udp"; setProtocol(next); setPortsTouched(false); if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); } }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>{protocol !== "any" && <><Field label="Port scope"><Select value={portScope} onChange={(event) => { setPortScope(event.target.value as "all" | "single" | "range"); setPortsTouched(false); }}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>{portScope !== "all" && <div className="grid grid-cols-2 gap-3"><Field label="Port"><Input inputMode="numeric" value={portLow} onChange={(event) => { setPortsTouched(true); setPortLow(event.target.value); }} /></Field>{portScope === "range" && <Field label="Through"><Input inputMode="numeric" value={portHigh} onChange={(event) => { setPortsTouched(true); setPortHigh(event.target.value); }} /></Field>}</div>}</>}<p className="rounded-md border border-border bg-white/5 px-3 py-2 text-xs text-ink-tertiary">Scope: {scopeSummary}</p>{showPortError && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}</div></Modal>}
    {dialog === "delete" && selected && <Modal title="Delete resource?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>Delete resource</Button></>}><p className="text-cell text-ink-tertiary">Deleting {selected.name} can affect rules that reference this destination. This screen does not have a server-provided affected-rule count, so it cannot preview a number. The server may refuse the deletion; if it succeeds, recovery is to recreate the resource and review affected rules explicitly.</p></Modal>}
  </div>;
}

function FQDNResources({ orgId, role }: { orgId: string; role: Member["role"] | undefined }) {
  const canView = can(role, "fqdn_resource:view");
  const canManage = can(role, "fqdn_resource:manage");
  const [resources, setResources] = useState<FQDNResource[] | null>(null);
  const [setting, setSetting] = useState<FQDNResourceSetting | null>(null);
  const [settingError, setSettingError] = useState("");
  const [contexts, setContexts] = useState<{ sites: Site[]; nodes: Node[] } | null>(null);
  const [contextsError, setContextsError] = useState("");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<FQDNResource | null>(null);
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [impact, setImpact] = useState<FQDNResourceImpact | null>(null);
  const [impactError, setImpactError] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [fqdn, setFqdn] = useState("");
  const [label, setLabel] = useState("");
  const [protocol, setProtocol] = useState<"any" | "tcp" | "udp">("any");
  const [portScope, setPortScope] = useState<"all" | "single" | "range">("all");
  const [portLow, setPortLow] = useState("");
  const [portHigh, setPortHigh] = useState("");
  const [siteId, setSiteId] = useState("");
  const [gatewayId, setGatewayId] = useState("");

  const reload = useCallback(async () => {
    if (!canView) return;
    setError(""); setSettingError(""); setResources(null); setSetting(null);
    const [resourceResult, settingResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/setting", { params: { path: { orgId } } })),
    ]);
    if (!resourceResult.ok) { setError(resourceResult.error); return; }
    setResources(resourceResult.data as FQDNResource[]);
    if (settingResult.ok) setSetting(settingResult.data as FQDNResourceSetting);
    else setSettingError(settingResult.error);
  }, [canView, orgId]);
  useEffect(() => { void reload(); }, [reload]);

  const loadContexts = useCallback(async () => {
    if (contexts || !canManage) return;
    setContextsError("");
    const [sitesResult, nodesResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } })),
    ]);
    if (!sitesResult.ok) { setContextsError(sitesResult.error); return; }
    if (!nodesResult.ok) { setContextsError(nodesResult.error); return; }
    setContexts({ sites: sitesResult.data as Site[], nodes: nodesResult.data as Node[] });
  }, [canManage, contexts, orgId]);

  const openForm = (resource?: FQDNResource) => {
    setSelected(resource ?? null); setName(resource?.name ?? ""); setFqdn(resource?.fqdn ?? ""); setLabel(resource?.label ?? "");
    setProtocol(resource?.protocol ?? "any"); setPortScope(resource?.port_low == null ? "all" : resource.port_high == null || resource.port_high === resource.port_low ? "single" : "range"); setPortLow(resource?.port_low == null ? "" : String(resource.port_low)); setPortHigh(resource?.port_high == null ? "" : String(resource.port_high)); setSiteId(resource?.resolver_context?.site_id ?? ""); setGatewayId(resource?.resolver_context?.gateway_id ?? "");
    setDialog(resource ? "edit" : "create"); void loadContexts();
  };
  const gateways = (contexts?.nodes ?? []).filter((node) => node.status === "active" && node.enrolled_kind === "gateway" && node.site_id === siteId);
  const selectedGatewayValid = !siteId || gateways.some((node) => node.id === gatewayId);
  const parsedLow = portLow === "" ? null : Number(portLow);
  const parsedHigh = portHigh === "" ? null : Number(portHigh);
  const portsValid = protocol === "any" || portScope === "all" || (Number.isInteger(parsedLow) && parsedLow! >= 1 && parsedLow! <= 65535 && (portScope === "single" || (Number.isInteger(parsedHigh) && parsedHigh! >= parsedLow! && parsedHigh! <= 65535)));
  const scope = protocol === "any" ? "Any protocol, all ports" : portScope === "all" ? `${protocol.toUpperCase()}, all ports` : portScope === "single" ? `${protocol.toUpperCase()} port ${portLow || "—"}` : `${protocol.toUpperCase()} ports ${portLow || "—"}–${portHigh || "—"}`;
  async function mutate(call: () => Promise<{ error?: unknown }>, fallback: string) {
    setBusy(true); setError("");
    try {
      const result = await call();
      if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; }
      return true;
    } catch {
      setError("Could not reach the API. Your changes were not confirmed; try again.");
      return false;
    } finally { setBusy(false); }
  }
  async function save() {
    if (!name.trim() || !fqdn.trim() || !portsValid || (siteId && (!gatewayId || !selectedGatewayValid))) return;
    const body = { name: name.trim(), fqdn: fqdn.trim(), label: label.trim() || null, protocol, ...(protocol === "any" || portScope === "all" ? { port_low: null, port_high: null } : portScope === "single" ? { port_low: parsedLow!, port_high: parsedLow! } : { port_low: parsedLow!, port_high: parsedHigh! }), resolver_context: siteId ? { site_id: siteId, gateway_id: gatewayId } : null };
    const ok = selected
      ? await mutate(() => api.PATCH("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}", { params: { path: { orgId, resourceId: selected.id } }, body }), "Could not save the FQDN resource.")
      : await mutate(() => api.POST("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } }, body }), "Could not save the FQDN resource.");
    if (ok) { setDialog(null); await reload(); }
  }
  async function openDelete(resource: FQDNResource) {
    setSelected(resource); setImpact(null); setImpactError(""); setDialog("delete");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}/impact", { params: { path: { orgId, resourceId: resource.id } } }));
    if (result.ok) setImpact(result.data as FQDNResourceImpact); else setImpactError(result.error);
  }
  async function openDetail(resource: FQDNResource) {
    setSelected(resource); setImpact(null); setImpactError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}/impact", { params: { path: { orgId, resourceId: resource.id } } }));
    if (result.ok) setImpact(result.data as FQDNResourceImpact); else setImpactError(result.error);
  }
  async function remove() {
    if (!selected || !impact || impact.referencing_rule_count > 0 || impact.generation_withdrawal_required) return;
    const ok = await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}", { params: { path: { orgId, resourceId: selected.id } } }), "Could not delete the FQDN resource.");
    if (ok) { setDialog(null); setSelected(null); await reload(); }
  }
  async function setEnforcement(enabled: boolean) {
    const ok = await mutate(() => api.PUT("/api/v1/organizations/{orgId}/fqdn-resources/setting", { params: { path: { orgId } }, body: { enabled } }), enabled ? "Could not enable FQDN enforcement. It requires the fqdn_resources licence feature." : "Could not disable FQDN enforcement.");
    if (ok) await reload();
  }
  if (!canView) return <Card><div className="space-y-2" aria-labelledby="fqdn-resources-heading"><h2 id="fqdn-resources-heading" className="text-lg font-semibold text-ink-heading">FQDN resources</h2><p role="alert" className="text-cell text-ink-tertiary">FQDN resources are unavailable because your role lacks <code>fqdn_resource:view</code>. Owners and admins currently receive this permission.</p></div></Card>;
  const filtered = (resources ?? []).filter((resource) => `${resource.name} ${resource.fqdn} ${resource.state}`.toLowerCase().includes(query.toLowerCase()));
  return <Card><section aria-labelledby="fqdn-resources-heading" className="space-y-4"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><h2 id="fqdn-resources-heading" className="text-lg font-semibold text-ink-heading">FQDN resources</h2><p className="text-cell text-ink-tertiary">Resolver-backed exact hostnames. A hostname is not an IP ownership boundary: hostnames sharing an IP and protocol/port cannot be distinguished after resolution. The server projects exact referencing rule identities for recovery; DNS answers and diagnostic/audit projections remain unavailable.</p></div>{canManage ? <Button onClick={() => openForm()}>Create FQDN resource</Button> : <p className="text-cell text-ink-tertiary">Create, edit, delete, and enforcement controls require <code>fqdn_resource:manage</code> (currently owners and admins).</p>}</div>
    {settingError ? <LoadRetry error={`FQDN enforcement setting is unavailable: ${settingError}`} onRetry={() => void reload()} /> : setting === null ? <p role="status" className="text-cell text-ink-tertiary">Loading FQDN enforcement setting…</p> : <div role="status" className="flex flex-col gap-2 rounded-md border border-border px-3 py-2 text-cell text-ink-tertiary sm:flex-row sm:items-center sm:justify-between"><span>Enforcement opt-in: <strong className="text-ink-heading">{setting.enabled ? "enabled" : "not enabled"}</strong>. {setting.enabled ? "This permits compilation when a bound resource becomes ready." : "Resources can remain drafts; no FQDN resource compiles until this is enabled."}</span>{canManage ? <Button size="sm" disabled={busy} onClick={() => void setEnforcement(!setting.enabled)}>{setting.enabled ? "Disable enforcement" : "Enable enforcement"}</Button> : <span>Changing it requires <code>fqdn_resource:manage</code>.</span>}</div>}
    <ErrorText>{error}</ErrorText>
    {resources === null ? error ? <LoadRetry error={`Could not load FQDN resources: ${error}`} onRetry={() => void reload()} /> : <Loading label="Loading FQDN resources…" /> : <><div className="max-w-md"><Input aria-label="Search FQDN resources" value={query} placeholder="Search name, hostname, or state" onChange={(event) => setQuery(event.target.value)} /></div><DataTable caption="FQDN resources inventory" rows={filtered} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={25} empty={<EmptyState>{resources.length === 0 ? "No FQDN resources yet. Create an exact hostname or save an unbound draft." : "No FQDN resources match this search."}</EmptyState>} columns={[{ key: "name", header: "Resource", cell: (resource) => <button className="font-medium text-ink-heading hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400" onClick={() => void openDetail(resource)}>{resource.name}</button> }, { key: "fqdn", header: "Hostname", cell: (resource) => resource.fqdn }, { key: "ports", header: "Port scope", cell: (resource) => fqdnPortScope(resource) }, { key: "state", header: "State", cell: (resource) => <StateBadge state={resource.state} /> }, { key: "context", header: "Resolver context", cell: (resource) => resource.resolver_context ? `${resource.resolver_context.site_name} / ${resource.resolver_context.gateway_name}` : "Unbound draft" }, { key: "answers", header: "Answers", cell: (resource) => resource.state === "healthy" ? String(resource.answer_count) : "Not available" }, { key: "actions", header: "", cell: (resource) => canManage ? <div className="flex flex-wrap gap-2"><Button size="sm" variant="ghost" onClick={() => openForm(resource)}>Edit</Button><Button size="sm" variant="danger" onClick={() => void openDelete(resource)}>Delete</Button></div> : "Read-only — manage permission required" }]} /><p className="text-xs text-ink-tertiary">Select this destination from <Link className="text-accent-400 hover:underline" to="/access">Access Rules</Link>. The server does not publish DNS answer addresses or diagnostic/audit projections here.</p></>}
    {selected && !dialog && <FQDNDetail resource={selected} impact={impact} impactError={impactError} onDismiss={() => setSelected(null)} onEdit={canManage ? () => openForm(selected) : undefined} />}
    {(dialog === "create" || dialog === "edit") && <Modal title={dialog === "edit" ? "Edit FQDN resource" : "Create FQDN resource"} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim() || !fqdn.trim() || !portsValid || Boolean(siteId && (!gatewayId || !selectedGatewayValid))} onClick={() => void save()}>{dialog === "edit" ? "Save FQDN resource" : "Create FQDN resource"}</Button></>}><div className="space-y-3"><p className="text-cell text-ink-tertiary">Use one exact hostname, not a wildcard, URL, or IP. The server normalizes and validates it. A blank resolver context saves an unbound draft: it cannot compile or authorize traffic. Hostnames sharing an IP and protocol/port cannot be separated after resolution.</p><ErrorText>{error}</ErrorText><Field label="Name"><Input value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field><Field label="Exact hostname"><Input value={fqdn} placeholder="orders.internal.example.com" onChange={(event) => setFqdn(event.target.value)} /></Field><Field label="Description (optional)"><Input value={label} onChange={(event) => setLabel(event.target.value)} /></Field><Field label="Protocol"><Select value={protocol} onChange={(event) => { const next = event.target.value as "any" | "tcp" | "udp"; setProtocol(next); if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); } }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>{protocol !== "any" && <><Field label="Port scope"><Select value={portScope} onChange={(event) => setPortScope(event.target.value as "all" | "single" | "range")}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>{portScope !== "all" && <div className="grid grid-cols-1 gap-3 sm:grid-cols-2"><Field label="Port"><Input inputMode="numeric" value={portLow} onChange={(event) => setPortLow(event.target.value)} /></Field>{portScope === "range" && <Field label="Through"><Input inputMode="numeric" value={portHigh} onChange={(event) => setPortHigh(event.target.value)} /></Field>}</div>}</>}<p className="text-xs text-ink-tertiary">Scope: {scope}</p>{!portsValid && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}<Field label="Resolver site (optional)"><Select value={siteId} onChange={(event) => { setSiteId(event.target.value); setGatewayId(""); }}><option value="">Unbound draft</option>{(contexts?.sites ?? []).map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}</Select></Field>{contextsError && <LoadRetry error={`Could not load Site/Gateway authority: ${contextsError}`} onRetry={() => void loadContexts()} />}{siteId && <><Field label="Gateway"><Select value={gatewayId} onChange={(event) => setGatewayId(event.target.value)}><option value="">Select a gateway</option>{gateways.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}</Select></Field>{contexts === null && !contextsError ? <p role="status" className="mt-1 text-xs text-ink-tertiary">Loading selected Site/Gateway authority…</p> : gateways.length === 0 ? <p role="alert" className="mt-1 text-xs text-danger">No active gateway is bound to this site, so a bound resolver context cannot be saved.</p> : <p className="mt-1 text-xs text-ink-tertiary">The selected Site and Gateway are the resolver authority for this resource.</p>}</>}</div></Modal>}
    {dialog === "delete" && selected && <Modal title="Delete FQDN resource?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy || !impact || impact.referencing_rule_count > 0 || impact.generation_withdrawal_required} onClick={() => void remove()}>Delete FQDN resource</Button></>}><div className="space-y-3 text-cell text-ink-tertiary"><ErrorText>{error}</ErrorText>{impactError ? <LoadRetry error={`Server deletion impact could not be loaded: ${impactError}`} onRetry={() => void openDelete(selected)} /> : !impact ? <p role="status">Loading server-computed deletion impact…</p> : <><p>Server impact: {impact.referencing_rule_count} referencing {impact.referencing_rule_count === 1 ? "rule" : "rules"}; {impact.generation_withdrawal_required ? "a live generation must be withdrawn." : "no live generation needs withdrawal."} {impact.referencing_rule_count > 0 || impact.generation_withdrawal_required ? "Deletion is unavailable until the server-reported impact is cleared." : "If deletion succeeds, recovery requires recreating this resource; immutable generation history may still prevent deletion."}</p><p>Referencing rule identities: {impact.referencing_rule_ids.length ? impact.referencing_rule_ids.join(", ") : "none"}. <Link className="text-accent-400 hover:underline" to="/access">Review referenced rules in Access Rules</Link>.</p></>}</div></Modal>}
  </section></Card>;
}

function StateBadge({ state }: { state: FQDNResource["state"] }) {
  const copy: Record<FQDNResource["state"], string> = { draft: "Draft — unbound, no authorization", resolving: "Resolving — awaiting server result", healthy: "Healthy — active generation", stale: "Stale — last result is not current", failed: "Failed — no usable result", nxdomain: "NXDOMAIN — hostname absent" };
  return <span aria-label={copy[state]} className="text-xs text-ink-tertiary">{state === "nxdomain" ? "NXDOMAIN" : state}</span>;
}

function fqdnPortScope(resource: FQDNResource) {
  if (resource.protocol === "any" || resource.port_low == null) return resource.protocol === "any" ? "Any protocol, all ports" : `${resource.protocol.toUpperCase()}, all ports`;
  if (resource.port_high == null || resource.port_high === resource.port_low) return `${resource.protocol.toUpperCase()} port ${resource.port_low}`;
  return `${resource.protocol.toUpperCase()} ports ${resource.port_low}–${resource.port_high}`;
}

function FQDNDetail({ resource, impact, impactError, onDismiss, onEdit }: { resource: FQDNResource; impact: FQDNResourceImpact | null; impactError: string; onDismiss: () => void; onEdit?: () => void }) {
  return <Modal title={resource.name} onDismiss={onDismiss} actions={<><Button variant="ghost" onClick={onDismiss}>Close</Button>{onEdit && <Button onClick={onEdit}>Edit</Button>}</>}><div className="space-y-3 text-cell text-ink-tertiary"><p><strong className="text-ink-heading">{resource.fqdn}</strong> · {fqdnPortScope(resource)}</p><StateBadge state={resource.state} /><dl className="grid grid-cols-1 gap-2 sm:grid-cols-2"><div><dt>Resolver authority</dt><dd className="text-ink-heading">{resource.resolver_context ? `${resource.resolver_context.site_name} / ${resource.resolver_context.gateway_name}` : "Unbound draft — cannot compile or authorize traffic"}</dd></div><div><dt>Generation</dt><dd className="text-ink-heading">{resource.generation ?? "Not active"}</dd></div><div><dt>Answer count</dt><dd className="text-ink-heading">{resource.state === "healthy" ? resource.answer_count : "Not available"}</dd></div><div><dt>Effective TTL</dt><dd className="text-ink-heading">{resource.effective_ttl_seconds == null ? "Not available" : `${resource.effective_ttl_seconds} seconds`}</dd></div><div><dt>Last refresh</dt><dd className="text-ink-heading">{resource.refreshed_at ?? "Not available"}</dd></div><div><dt>Last good</dt><dd className="text-ink-heading">{resource.last_good_at ?? "Not available"}</dd></div></dl><p>Exact-host selection does not establish exclusive ownership of a shared IP: hostnames using the same IP and protocol/port cannot be differentiated after resolution. Current answer addresses and diagnostic/audit projections are not available from this server contract.</p>{impactError ? <p role="alert">Rule impact is unavailable: {impactError}. <Link className="text-accent-400 hover:underline" to="/access">Review Access Rules</Link> after retrying.</p> : !impact ? <p role="status">Loading server-reported referencing rules…</p> : <div><p>Referencing rule identities: {impact.referencing_rule_ids.length ? impact.referencing_rule_ids.join(", ") : "none"}.</p><Link className="text-accent-400 hover:underline" to="/access">Review and edit referenced rules in Access Rules</Link></div>}</div></Modal>;
}
