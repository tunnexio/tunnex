import "../network-workspaces.css";
import "../resources-workspace.css";
import "../access-policies-resources.css";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AccessTabRail } from "../components/AccessTabRail";
import { FQDNEnforcementSetting } from "../components/FQDNEnforcementSetting";
import { ResourceSummary } from "../components/ResourceSummary";
import { LoadRetry } from "../components/LoadRetry";
import { matchResolverProfile, PrivateDNSResolvers, providerName } from "../components/PrivateDNSResolvers";
import { Button, DataTable, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { api, apiErrorCode, apiErrorMessage, loadOne, type FQDNResolverContextConfig, type FQDNResource, type FQDNResourceImpact, type FQDNResourceMutationPreview, type Member, type Node, type Resource, type Site } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { can } from "../lib/rbac";

/** Canonical Access Resources workspace. Group management intentionally lives elsewhere. */
export default function AccessResources() {
  const { org } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}:${state.user.must_change_password}` : state.status;
  return <AccessResourcesWorkspace key={`${org?.id ?? ""}:${actor}`} />;
}

function AccessResourcesWorkspace() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [authorized, setAuthorized] = useState<boolean | null>(null);
  const canWrite = authorized === true && state.status === "authed" && state.user.email_verified && !state.user.must_change_password;
  const [role, setRole] = useState<Member["role"] | undefined>(undefined);
  const [membershipError, setMembershipError] = useState("");
  const [membershipAttempt, setMembershipAttempt] = useState(0);
  const [resources, setResources] = useState<Resource[] | null>(null);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<"choose" | "create" | "edit" | "delete" | null>(null);
  const [fqdnCreateToken, setFqdnCreateToken] = useState(0);
  const [selected, setSelected] = useState<Resource | null>(null);
  // The resource index owns the shareable filter contract.  Children receive
  // this same URL state rather than inventing private search state.
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get("q") ?? "";
  const type = ["cidr", "fqdn"].includes(searchParams.get("type") ?? "") ? searchParams.get("type")! : "cidr";
  const updateIndex = (next: Record<string, string>) => {
    const params = new URLSearchParams(searchParams);
    Object.entries(next).forEach(([key, value]) => value ? params.set(key, value) : params.delete(key));
    setSearchParams(params);
  };
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
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const alive = useRef(true), request = useRef(0), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; request.current++; }; }, []);
  const reload = useCallback(async () => {
    if (!org || authorized !== true) return;
    const sequence = ++request.current;
    setError(""); setResources(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/resources", { params: { path: { orgId: org.id } } }));
    if (!alive.current || sequence !== request.current) return;
    if (!result.ok) { setError(result.error); return; }
    setResources(result.data);
  }, [authorized, org?.id]);
  useEffect(() => {
    let cancelled = false;
    if (!org || state.status !== "authed") { setRole(undefined); setAuthorized(false); setMembershipError(""); return; }
    setAuthorized(null);
    setRole(undefined); setResources(null); setError(""); setMembershipError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setMembershipError(result.error); return; }
      const mine = (result.data as Member[]).find((member) => member.user_id === state.user.id);
      setRole(mine?.role);
      setAuthorized(mine?.role === "owner" || mine?.role === "admin");
    });
    return () => { cancelled = true; };
  }, [membershipAttempt, org?.id, state.status, state.status === "authed" ? state.user.id : ""]);
  useEffect(() => { void reload(); }, [reload]);
  async function mutate(call: () => Promise<{ error?: unknown }>, fallback: string) {
    if (locked.current || !alive.current || !canWrite) return false;
    locked.current = true;
    setBusy(true); setError("");
    try { const result = await call(); if (!alive.current) return false; if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; } return true; }
    catch { if (alive.current) setError("Could not reach the API."); return false; }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  const openCreate = () => { if (!canWrite || locked.current) return; setSelected(null); setName(""); setCidr(""); setLabel(""); setProtocol("any"); setPortScope("all"); setPortLow(""); setPortHigh(""); setPortsTouched(false); setSaveAttempted(false); setDialog("create"); };
  const openEdit = (resource: Resource) => { if (!canWrite || locked.current) return; setSelected(resource); setName(resource.name); setCidr(resource.cidr); setLabel(resource.label ?? ""); setProtocol(resource.protocol); setPortScope(resource.port_low == null ? "all" : resource.port_high == null || resource.port_high === resource.port_low ? "single" : "range"); setPortLow(resource.port_low == null ? "" : String(resource.port_low)); setPortHigh(resource.port_high == null ? "" : String(resource.port_high)); setPortsTouched(false); setSaveAttempted(false); setDialog("edit"); };
  const parsedLow = portLow === "" ? null : Number(portLow);
  const parsedHigh = portHigh === "" ? null : Number(portHigh);
  const portsValid = protocol === "any" || portScope === "all" || (Number.isInteger(parsedLow) && parsedLow! >= 1 && parsedLow! <= 65535 && (portScope === "single" || (Number.isInteger(parsedHigh) && parsedHigh! >= parsedLow! && parsedHigh! <= 65535)));
  const showPortError = (portsTouched || saveAttempted) && !portsValid;
  const scopeSummary = protocol === "any" ? "Any protocol, all ports" : portScope === "all" ? `${protocol.toUpperCase()}, all ports` : portScope === "single" ? `${protocol.toUpperCase()} port ${portLow || "Not available"}` : `${protocol.toUpperCase()} ports ${portLow || "Not available"}–${portHigh || "Not available"}`;
  const requestBody = () => ({ name: name.trim(), cidr: cidr.trim(), protocol, label: label.trim() || null, ...(protocol === "any" || portScope === "all" ? { port_low: null, port_high: null } : portScope === "single" ? { port_low: parsedLow!, port_high: parsedLow! } : { port_low: parsedLow!, port_high: parsedHigh! }) });
  async function save(_withheldBind = false) {
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
  const closeDialog = () => { if (!busy) setDialog(null); };
  const showScopes = can(role, "k8s_scope:view") && can(role, "policy:view");
  const header = <><PageHeader navigationTitle title="Resources" /><AccessTabRail includeKubernetesScopes={showScopes} actions={authorized === true ? <><a className="access-resource-link" aria-label="Private DNS resolvers" href="/access/resources?type=fqdn#private-dns-heading">Private DNS</a>{canWrite && <Button disabled={busy} onClick={() => setDialog("choose")}>Create resource</Button>}</> : undefined} /></>;
  const resourceTypeTabs = <nav aria-label="Resource types" className="access-scope-tabs">{(["cidr", "fqdn"] as const).map((resourceType) => <button key={resourceType} type="button" aria-current={type === resourceType ? "page" : undefined} aria-pressed={type === resourceType} disabled={busy} onClick={() => { setPage(1); updateIndex({ type: resourceType }); }}>{resourceType === "cidr" ? "CIDR" : "FQDN"}</button>)}</nav>;
  const shellClass = "network-management resources-workspace access-resources-workspace space-y-5";
  if (membershipError) return <div className={shellClass}>{header}{resourceTypeTabs}<LoadRetry error={`Could not check resource permissions: ${membershipError}`} onRetry={() => setMembershipAttempt((attempt) => attempt + 1)} /></div>;
  if (!org || authorized === null) return <div className={shellClass}>{header}{resourceTypeTabs}<Loading label="Checking resource permissions…" /></div>;
  const createChooser = canWrite && dialog === "choose" && <Modal title="Create resource" placement="right" size="enrollment" showClose onDismiss={closeDialog} actions={<Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button>}><div className="access-resource-editor"><div className="access-resource-choices"><button onClick={() => { updateIndex({ type: "cidr" }); openCreate(); }}><span>Create CIDR resource</span><small>A named network range with inherited protocol and ports.</small></button><button onClick={() => { setDialog(null); updateIndex({ type: "fqdn" }); setFqdnCreateToken((token) => token + 1); }}><span>Create FQDN resource</span><small>One exact hostname with a private resolver path; no authorization until a current generation is available.</small></button></div></div></Modal>;
  if (type === "fqdn") return <div className={shellClass}>{header}{resourceTypeTabs}<FQDNResources key={org.id} orgId={org.id} role={role} createToken={fqdnCreateToken} /><details className="resource-dns-settings" open={typeof window !== "undefined" && ["#private-dns-heading", "#fqdn-enforcement-heading"].includes(window.location.hash)}><summary>DNS configuration</summary><div className="resource-dns-settings-body"><FQDNEnforcementSetting key={"setting-" + org.id} orgId={org.id} role={role} /><PrivateDNSResolvers key={"resolver-" + org.id} orgId={org.id} role={role} /></div></details>{createChooser}</div>;
  if (!authorized) return <div className={shellClass}>{header}{resourceTypeTabs}<p role="alert" className="access-resource-copy">You do not have permission to manage CIDR resources.</p><ErrorText>{error}</ErrorText></div>;
  if (!resources) return <div className={shellClass}>{header}{resourceTypeTabs}{error ? <LoadRetry error={error} onRetry={() => void reload()} /> : <Loading label="Loading resources…" />}</div>;
  const cidrSort = ["name", "cidr", "protocol"].includes(searchParams.get("sort") ?? "") ? searchParams.get("sort")! : "name";
  const cidrDir = searchParams.get("dir") === "desc" ? "desc" : "asc";
  const filteredResources = resources.filter((resource) => `${resource.name} ${resource.cidr} ${resource.protocol}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => {
    const left = cidrSort === "cidr" ? a.cidr : cidrSort === "protocol" ? a.protocol : a.name;
    const right = cidrSort === "cidr" ? b.cidr : cidrSort === "protocol" ? b.protocol : b.name;
    return left.localeCompare(right) * (cidrDir === "desc" ? -1 : 1);
  });
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filteredResources.length / pageSize)));
  const visibleResources = filteredResources.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const updateCidrQuery = (next: Record<string, string>) => { setPage(1); updateIndex(next); };
  return <div className={shellClass}>{header}{resourceTypeTabs}<div className="access-resource-content">{!canWrite && <p role="status" className="access-resource-context">Verify your email to manage resources.</p>}<ErrorText>{error}</ErrorText>
    <div className="access-resource-toolbar"><Input aria-label="Search resources" value={query} placeholder="Search resources" onChange={(event) => updateCidrQuery({ q: event.target.value })} /><div className="access-resource-actions"><Select width="auto" aria-label="Sort CIDR resources" value={cidrSort} onChange={(event) => updateCidrQuery({ sort: event.target.value })}><option value="name">Name</option><option value="cidr">CIDR</option><option value="protocol">Protocol</option></Select><Select width="auto" aria-label="CIDR sort direction" value={cidrDir} onChange={(event) => updateCidrQuery({ dir: event.target.value })}><option value="asc">Ascending</option><option value="desc">Descending</option></Select><Button variant="ghost" disabled={busy} onClick={() => void reload()}>Refresh resources</Button></div></div>
    <DataTable variant="flat" caption="Resources inventory" rows={visibleResources} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={resources.length === 0 ? "No resources yet" : "No matching resources"} description={resources.length === 0 ? "Create a named destination range for reusable policy rules." : "Try another name, range, or protocol."} action={query ? <Button variant="ghost" onClick={() => updateCidrQuery({ q: "" })}>Clear search</Button> : undefined} />} columns={[
      { key: "name", header: "Resource", cell: (resource) => <div className="access-resource-cell">{canWrite ? <button className="access-resource-name" onClick={() => openEdit(resource)}>{resource.name}</button> : <span>{resource.name}</span>}{resource.label && <small>{resource.label}</small>}</div> },
      { key: "cidr", header: "CIDR", cell: (resource) => resource.cidr },
      { key: "ports", header: "Access scope", cell: (resource) => resourcePortScope(resource) },
      { key: "actions", header: "Actions", cell: (resource) => canWrite ? <AppAccessRowMenu label={`Actions for ${resource.name}`} actions={[{ key: "edit", label: `Edit ${resource.name}`, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => openEdit(resource) }, { key: "delete", label: `Delete ${resource.name}`, danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => { setSelected(resource); setDialog("delete"); } }]} /> : null },
    ]} />
    <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={visibleResources.length} hasNext={currentPage * pageSize < filteredResources.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
  </div>{createChooser}
    {canWrite && (dialog === "create" || dialog === "edit") && <Modal title={dialog === "edit" ? "Edit resource" : "Create resource"} placement="right" size="enrollment" showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button disabled={busy || !name.trim() || !cidr.trim()} onClick={() => void save()}>{dialog === "edit" ? "Save resource" : "Create resource"}</Button></>}><div className="access-resource-editor"><ErrorText>{error}</ErrorText><p>Referencing rules inherit this CIDR, protocol, and port scope.</p><Field label="Name"><Input disabled={busy} value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field><Field label="Description (optional)"><Input disabled={busy} value={label} onChange={(event) => setLabel(event.target.value)} /></Field><Field label="CIDR"><Input disabled={busy} value={cidr} placeholder="10.0.5.0/24" onChange={(event) => setCidr(event.target.value)} /></Field><Field label="Protocol"><Select disabled={busy} value={protocol} onChange={(event) => { const next = event.target.value as "any" | "tcp" | "udp"; setProtocol(next); setPortsTouched(false); if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); } }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>{protocol !== "any" && <><Field label="Port scope"><Select disabled={busy} value={portScope} onChange={(event) => { setPortScope(event.target.value as "all" | "single" | "range"); setPortsTouched(false); }}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>{portScope !== "all" && <div className="grid grid-cols-2 gap-3"><Field label="Port"><Input disabled={busy} inputMode="numeric" value={portLow} onChange={(event) => { setPortsTouched(true); setPortLow(event.target.value); }} /></Field>{portScope === "range" && <Field label="Through"><Input disabled={busy} inputMode="numeric" value={portHigh} onChange={(event) => { setPortsTouched(true); setPortHigh(event.target.value); }} /></Field>}</div>}</>}<p>Scope: {scopeSummary}</p>{showPortError && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}</div></Modal>}
    {canWrite && dialog === "delete" && selected && <Modal title="Delete resource?" danger showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>Delete resource</Button></>}><ErrorText>{error}</ErrorText><p className="access-resource-copy">Delete {selected.name}? Referencing rules may be affected. A server-provided affected-rule count is unavailable. The server can refuse deletion; recovery requires recreating the resource and reviewing its rules.</p></Modal>}
  </div>;
}

function FQDNResources({ orgId, role, createToken }: { orgId: string; role: Member["role"] | undefined; createToken: number }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const canView = can(role, "fqdn_resource:view");
  const { state } = useAuth();
  const canManage = can(role, "fqdn_resource:manage") && state.status === "authed" && state.user.email_verified && !state.user.must_change_password;
  const [resources, setResources] = useState<FQDNResource[] | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<FQDNResource | null>(null);
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [impact, setImpact] = useState<FQDNResourceImpact | null>(null);
  const [impactResourceId, setImpactResourceId] = useState<string | null>(null);
  const [impactError, setImpactError] = useState("");
  const selectedIdRef = useRef<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [fqdn, setFqdn] = useState("");
  const [label, setLabel] = useState("");
  const [protocol, setProtocol] = useState<"any" | "tcp" | "udp">("any");
  const [portScope, setPortScope] = useState<"all" | "single" | "range">("all");
  const [portLow, setPortLow] = useState("");
  const [portHigh, setPortHigh] = useState("");
  const [sites, setSites] = useState<Site[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [siteId, setSiteId] = useState("");
  const [gatewayId, setGatewayId] = useState("");
  const [resolverConfig, setResolverConfig] = useState<FQDNResolverContextConfig | null>(null);
  const [resolverLoading, setResolverLoading] = useState(false);
  const [resolverMissing, setResolverMissing] = useState(false);
  const [resolverError, setResolverError] = useState("");
  const resolverRequest = useRef(0);
  const alive = useRef(true), inventoryRequest = useRef(0), operation = useRef(false), consumedCreate = useRef(0);
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  useEffect(() => { alive.current = true; return () => { alive.current = false; inventoryRequest.current++; resolverRequest.current++; selectedIdRef.current = null; }; }, []);

  const reload = useCallback(async () => {
    if (!canView) return;
    const sequence = ++inventoryRequest.current;
    setError(""); setResources(null); setSites([]); setNodes([]);
    const [resourceResult, siteResult, nodeResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } })),
    ]);
    if (!alive.current || sequence !== inventoryRequest.current) return;
    if (!resourceResult.ok) { setError(resourceResult.error); return; }
    setResources(resourceResult.data as FQDNResource[]);
    if (siteResult.ok) setSites(siteResult.data as Site[]); else setError(siteResult.error);
    if (nodeResult.ok) setNodes(nodeResult.data as Node[]); else setError(nodeResult.error);
  }, [canView, orgId]);
  useEffect(() => { void reload(); }, [reload]);

  const openForm = (resource?: FQDNResource) => {
    if (!canManage || operation.current) return;
    const fallbackSite = sites.find((site) => nodes.some((node) => node.status === "active" && node.site_id === site.id));
    const nextSite = resource?.resolver_context?.site_id ?? fallbackSite?.id ?? "";
    const nextGateway = resource?.resolver_context?.gateway_id ?? nodes.find((node) => node.status === "active" && node.site_id === nextSite)?.id ?? "";
    setSelected(resource ?? null); setName(resource?.name ?? ""); setFqdn(resource?.fqdn ?? ""); setLabel(resource?.label ?? ""); setProtocol(resource?.protocol ?? "any");
    setPortScope(resource?.port_low == null ? "all" : resource.port_high == null || resource.port_high === resource.port_low ? "single" : "range");
    setPortLow(resource?.port_low == null ? "" : String(resource.port_low)); setPortHigh(resource?.port_high == null ? "" : String(resource.port_high));
    setSiteId(nextSite); setGatewayId(nextGateway); setResolverConfig(null); setResolverMissing(false); setResolverError(""); setDialog(resource ? "edit" : "create");
  };
  useEffect(() => { if (createToken > 0 && consumedCreate.current !== createToken && canManage && resources !== null) { consumedCreate.current = createToken; openForm(); } }, [createToken, canManage, resources, sites, nodes]);
  const formGateways = nodes.filter((node) => node.status === "active" && node.site_id === siteId);
  useEffect(() => {
    if (dialog !== "create" && dialog !== "edit") return;
    setGatewayId((current) => formGateways.some((gateway) => gateway.id === current) ? current : formGateways[0]?.id ?? "");
  }, [dialog, siteId, nodes]);
  useEffect(() => {
    const sequence = ++resolverRequest.current;
    setResolverConfig(null); setResolverMissing(false); setResolverError("");
    if ((dialog !== "create" && dialog !== "edit") || !siteId || !gatewayId) return;
    setResolverLoading(true);
    void (async () => {
      try {
        const result = await api.GET("/api/v1/organizations/{orgId}/fqdn-resolver-contexts/{siteId}/{gatewayId}", {
          params: { path: { orgId, siteId, gatewayId } },
        });
        if (sequence !== resolverRequest.current) return;
        if (result.error) {
          if (apiErrorCode(result.error) === "fqdn_resolver_config_not_found") setResolverMissing(true);
          else setResolverError(apiErrorMessage(result.error, "Could not load the inherited private DNS resolver."));
          return;
        }
        if (result.data) setResolverConfig(result.data as FQDNResolverContextConfig);
      } catch {
        if (sequence === resolverRequest.current) setResolverError("Could not reach the API.");
      } finally {
        if (sequence === resolverRequest.current) setResolverLoading(false);
      }
    })();
    return () => { resolverRequest.current += 1; };
  }, [dialog, gatewayId, orgId, siteId]);
  const resolverProfileMatch = resolverConfig ? matchResolverProfile(fqdn, resolverConfig) : null;
  const parsedLow = portLow === "" ? null : Number(portLow);
  const parsedHigh = portHigh === "" ? null : Number(portHigh);
  const portsValid = protocol === "any" || portScope === "all" || (Number.isInteger(parsedLow) && parsedLow! >= 1 && parsedLow! <= 65535 && (portScope === "single" || (Number.isInteger(parsedHigh) && parsedHigh! >= parsedLow! && parsedHigh! <= 65535)));
  const scope = protocol === "any" ? "Any protocol, all ports" : portScope === "all" ? `${protocol.toUpperCase()}, all ports` : portScope === "single" ? `${protocol.toUpperCase()} port ${portLow || "Not available"}` : `${protocol.toUpperCase()} ports ${portLow || "Not available"}–${portHigh || "Not available"}`;
  async function mutate(call: () => Promise<{ error?: unknown }>, fallback: string) {
    setBusy(true); setError("");
    try {
      const result = await call();
      if (!alive.current) return false;
      if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; }
      return true;
    } catch {
      if (alive.current) setError("Could not reach the API. Your changes were not confirmed; try again.");
      return false;
    } finally { if (alive.current) setBusy(false); }
  }
  async function save() {
    if (operation.current || !alive.current || !canManage || !name.trim() || !fqdn.trim() || !portsValid || !siteId || !gatewayId || !resolverConfig || !resolverProfileMatch) return;
    operation.current = true;
    try {
    const body = {
      name: name.trim(),
      fqdn: fqdn.trim(),
      label: label.trim() || null,
      protocol,
      ...(protocol === "any" || portScope === "all"
        ? { port_low: null, port_high: null }
        : portScope === "single"
          ? { port_low: parsedLow!, port_high: parsedLow! }
          : { port_low: parsedLow!, port_high: parsedHigh! }),
      resolver_context: { site_id: siteId, gateway_id: gatewayId },
      expected_impact_token: null,
    };
    let ok = false;
    if (selected) {
      setBusy(true); setError("");
      try {
        const previewResult = await api.POST("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}/impact", {
          params: { path: { orgId, resourceId: selected.id } },
          body,
        });
        if (previewResult.error || !previewResult.data) {
          setError(apiErrorMessage(previewResult.error, "Could not preview this FQDN change."));
          return;
        }
        const preview = previewResult.data as FQDNResourceMutationPreview;
        if (!alive.current) return;
        if (!preview.mutation_allowed) {
          setError(preview.refusal_reason ?? "The server refused this FQDN change.");
          return;
        }
        ok = await mutate(() => api.PATCH("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}", {
          params: { path: { orgId, resourceId: selected.id } },
          body: { ...body, expected_impact_token: preview.expected_impact_token },
        }), "Could not update the FQDN resource.");
      } finally {
        if (alive.current) setBusy(false);
      }
    } else {
      ok = await mutate(() => api.POST("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } }, body }), "Could not create the FQDN resource.");
    }
    if (ok) { setDialog(null); await reload(); }
    } finally { operation.current = false; if (alive.current) setBusy(false); }
  }
  async function openDelete(resource: FQDNResource) {
    // The impact endpoint is asynchronous. Keep its result bound to the row
    // that requested it so a late A response can never authorize deleting B.
    selectedIdRef.current = resource.id;
    setSelected(resource); setImpact(null); setImpactResourceId(null); setImpactError(""); setDialog("delete");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}/impact", { params: { path: { orgId, resourceId: resource.id } } }));
    if (!alive.current || selectedIdRef.current !== resource.id) return;
    if (result.ok) {
      const next = result.data as FQDNResourceImpact;
      if (!Number.isInteger(next.referencing_rule_count) || next.referencing_rule_count < 0 || typeof next.generation_withdrawal_required !== "boolean" || !Array.isArray(next.referencing_rule_ids)) { setImpactError("The server did not return a complete deletion impact. Retry before deleting."); return; }
      setImpact(next); setImpactResourceId(resource.id);
    } else setImpactError(result.error);
  }
  const detailTarget = (resource: FQDNResource) => ({ pathname: `/access/resources/fqdn/${resource.id}`, search: location.search, state: { from: `${location.pathname}${location.search}` } });
  function openDetail(resource: FQDNResource) {
    navigate(detailTarget(resource));
  }
  async function remove() {
    if (operation.current || !alive.current || !canManage || !selected || !impact || impactResourceId !== selected.id || impact.referencing_rule_count !== 0 || impact.generation_withdrawal_required !== false) return;
    operation.current = true;
    try {
    const ok = await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}", { params: { path: { orgId, resourceId: selected.id } } }), "Could not delete the FQDN resource.");
    if (ok) { selectedIdRef.current = null; setDialog(null); setSelected(null); setImpactResourceId(null); await reload(); }
    } finally { operation.current = false; }
  }
  if (!canView) return <div><h2 id="fqdn-resources-heading" className="sr-only">FQDN resources</h2><p role="alert" className="access-resource-copy">FQDN resources are unavailable because your role lacks <code>fqdn_resource:view</code>. Owners and admins currently receive this permission.</p></div>;
  const q = (searchParams.get("q") ?? "").trim();
  const status = ["all", "draft", "unconfigured", "resolving", "healthy", "stale", "failed", "nxdomain"].includes(searchParams.get("status") ?? "") ? searchParams.get("status")! : "all";
  const sort = ["name", "state", "fqdn"].includes(searchParams.get("sort") ?? "") ? searchParams.get("sort")! : "name";
  const dir = searchParams.get("dir") === "desc" ? "desc" : "asc";
  const updateQuery = (next: Record<string, string>) => {
    const params = new URLSearchParams(searchParams);
    Object.entries(next).forEach(([key, value]) => value && value !== "all" ? params.set(key, value) : params.delete(key));
    // This is a shared index: type is explicit and normalized even though this
    // section only displays FQDN rows. CIDR rows remain in the same workspace.
    params.set("type", "fqdn");
    setSearchParams(params);
  };
  const filtered = (resources ?? []).filter((resource) => `${resource.name} ${resource.fqdn} ${resource.state}`.toLowerCase().includes(q.toLowerCase()) && (status === "all" || resource.state === status)).sort((a, b) => {
    const left = sort === "state" ? a.state : sort === "fqdn" ? a.fqdn : a.name;
    const right = sort === "state" ? b.state : sort === "fqdn" ? b.fqdn : b.name;
    return left.localeCompare(right) * (dir === "desc" ? -1 : 1);
  });
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)));
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const closeForm = () => { if (!busy) setDialog(null); };
  return <section aria-labelledby="fqdn-resources-heading" className="access-resource-content"><h2 id="fqdn-resources-heading" className="sr-only">FQDN resources</h2>
    {!canManage && <p className="access-resource-context">Read only</p>}
    {resources !== null && <ErrorText>{error}</ErrorText>}
    {resources === null ? error ? <LoadRetry error={`Could not load FQDN resources: ${error}`} onRetry={() => void reload()} /> : <Loading label="Loading FQDN resources…" /> : <>
      {resources.length > 0 && <div className="access-resource-toolbar"><Input aria-label="Search FQDN resources" value={q} placeholder="Search name or hostname" onChange={(event) => { setPage(1); updateQuery({ q: event.target.value }); }} /><div className="access-resource-actions"><Select width="auto" aria-label="FQDN status" value={status} onChange={(event) => { setPage(1); updateQuery({ status: event.target.value }); }}><option value="all">All states</option>{["draft", "unconfigured", "resolving", "healthy", "stale", "failed", "nxdomain"].map((value) => <option key={value} value={value}>{value}</option>)}</Select><Select width="auto" aria-label="Sort FQDN resources" value={sort} onChange={(event) => { setPage(1); updateQuery({ sort: event.target.value }); }}><option value="name">Name</option><option value="fqdn">Hostname</option><option value="state">State</option></Select><Select width="auto" aria-label="Sort direction" value={dir} onChange={(event) => { setPage(1); updateQuery({ dir: event.target.value }); }}><option value="asc">Ascending</option><option value="desc">Descending</option></Select><Button variant="ghost" disabled={busy} onClick={() => void reload()}>Refresh</Button></div></div>}
      <DataTable variant="flat" caption="FQDN resources inventory" rows={visible} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={resources.length === 0 ? "No FQDN resources yet" : "No matching FQDN resources"} description={resources.length === 0 ? "Configure private DNS, then create hostnames that inherit the resolver path." : "Try another hostname or state."} action={resources.length === 0 && canManage ? <a className="access-resource-link" href="#private-dns-heading">Configure private DNS resolver</a> : q || status !== "all" ? <Button variant="ghost" onClick={() => { setPage(1); updateQuery({ q: "", status: "all" }); }}>Clear filters</Button> : undefined} />} columns={[
        { key: "name", header: "Resource", cell: (resource) => <div className="access-resource-cell"><button className="access-resource-name" onClick={() => openDetail(resource)}>{resource.name}</button><small>{resource.fqdn} · {fqdnPortScope(resource)}</small></div> },
        { key: "context", header: "Resolver path", cell: (resource) => <div className="access-resource-cell">{resource.resolver_context ? <><span>{resource.resolver_context.site_name}</span><small>{resource.resolver_context.gateway_name}</small></> : "Unbound draft"}</div> },
        { key: "state", header: "State", cell: (resource) => <div className="access-resource-cell"><StateBadge state={resource.state} />{resource.state === "healthy" && <small>{resource.answer_count} active answers</small>}</div> },
        { key: "actions", header: "Actions", cell: (resource) => <AppAccessRowMenu label={`Actions for ${resource.name}`} actions={[{ key: "view", label: `View ${resource.name}`, onSelect: () => openDetail(resource) }, ...(canManage ? [{ key: "edit", label: `Edit ${resource.name}`, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => openForm(resource) }, { key: "delete", label: `Delete ${resource.name}`, danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => { void openDelete(resource); } }] : [])]} /> },
      ]} />
      <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={visible.length} hasNext={currentPage * pageSize < filtered.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
      <details className="access-resource-help"><summary>How FQDN resources authorize traffic</summary><p>Only a current, healthy generation can authorize traffic. Hostnames inherit the most-specific active resolver profile; unmatched names fail closed. Select this destination from <Link className="access-resource-link" to="/access">Access Rules</Link>. DNS addresses, audit entries, and diagnostics depend on the server projection.</p></details>
    </>}
    {canManage && (dialog === "create" || dialog === "edit") && <Modal
      title={dialog === "edit" ? "Edit FQDN resource" : "Create FQDN resource"}
      placement="right" size="enrollment" showClose onDismiss={closeForm}
      actions={<>
        <Button variant="ghost" disabled={busy} onClick={closeForm}>Cancel</Button>
        <Button disabled={busy || resolverLoading || !resolverConfig || !resolverProfileMatch || !name.trim() || !fqdn.trim() || !portsValid} onClick={() => void save()}>
          {dialog === "edit" ? "Save resource" : "Create resource"}
        </Button>
      </>}
    ><div className="access-resource-editor">
      <p>One exact hostname, using the selected Site and Gateway’s active private resolver.</p>
      <ErrorText>{error}</ErrorText>
      <fieldset className="space-y-3">
        <legend className="text-sm font-semibold text-ink-heading">Identity</legend>
        <Field label="Name"><Input disabled={busy} value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field>
        <Field label="Exact hostname"><Input disabled={busy} value={fqdn} placeholder="orders.internal.example.com" onChange={(event) => setFqdn(event.target.value)} /></Field>
        <Field label="Description (optional)"><Input disabled={busy} value={label} onChange={(event) => setLabel(event.target.value)} /></Field>
      </fieldset>
      <fieldset className="space-y-3">
        <legend className="text-sm font-semibold text-ink-heading">Access scope</legend>
        <Field label="Protocol"><Select disabled={busy} value={protocol} onChange={(event) => {
          const next = event.target.value as "any" | "tcp" | "udp";
          setProtocol(next);
          if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); }
        }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>
        {protocol !== "any" && <>
          <Field label="Port scope"><Select disabled={busy} value={portScope} onChange={(event) => setPortScope(event.target.value as "all" | "single" | "range")}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>
          {portScope !== "all" && <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Port"><Input disabled={busy} inputMode="numeric" value={portLow} onChange={(event) => setPortLow(event.target.value)} /></Field>
            {portScope === "range" && <Field label="Through"><Input disabled={busy} inputMode="numeric" value={portHigh} onChange={(event) => setPortHigh(event.target.value)} /></Field>}
          </div>}
        </>}
        <p className="text-xs text-ink-tertiary">Scope: {scope}</p>
        {!portsValid && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}
      </fieldset>
      <fieldset className="space-y-3">
        <legend className="text-sm font-semibold text-ink-heading">Private DNS path</legend>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Site"><Select disabled={busy} value={siteId} onChange={(event) => setSiteId(event.target.value)}><option value="">Select a Site</option>{sites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}</Select></Field>
          <Field label="Gateway"><Select value={gatewayId} disabled={busy || !siteId} onChange={(event) => setGatewayId(event.target.value)}><option value="">Select a Gateway</option>{formGateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}</Select></Field>
        </div>
        {resolverLoading ? <Loading label="Finding the inherited resolver…" /> : resolverError ? <div><ErrorText>{resolverError}</ErrorText></div> : resolverConfig ? resolverProfileMatch ? <div className="access-resource-copy">
          <div className="flex items-center gap-3"><div><p className="font-medium text-ink-heading">{providerName(resolverProfileMatch.profile.provider_hint)} resolver selected automatically</p><p className="text-xs text-ink-tertiary">Profile {resolverProfileMatch.profile.name} · {resolverProfileMatch.matchedSuffix ? `matches ${resolverProfileMatch.matchedSuffix}` : "legacy catch-all"} · active version {resolverConfig.version} · {resolverProfileMatch.profile.endpoints.length} {resolverProfileMatch.profile.endpoints.length === 1 ? "endpoint" : "endpoints"}</p></div></div>
        </div> : fqdn.trim() ? <div role="alert" className="rounded-md border border-danger/50 bg-danger/5 p-3 text-sm"><p className="font-medium text-danger">No resolver profile matches this hostname.</p><p className="mt-1 text-ink-tertiary">Fail closed: no DNS request will be sent. Add a matching DNS zone suffix or choose another Site and Gateway.</p></div> : <p className="text-xs text-ink-tertiary">Enter an exact hostname to select its most-specific resolver profile.</p> : resolverMissing ? <div role="alert" className="rounded-md border border-dashed border-line p-3 text-sm text-ink-tertiary">
          <p>No active private DNS resolver is configured for this path.</p>
          <Button size="sm" variant="ghost" onClick={() => { setDialog(null); const heading = document.getElementById("private-dns-heading"); const settings = heading?.closest("details"); if (settings) settings.open = true; heading?.scrollIntoView({ behavior: "smooth" }); }}>Configure private DNS resolver</Button>
        </div> : <p className="text-xs text-ink-tertiary">Select a Site and Gateway. The matching active resolver will be reused automatically.</p>}
      </fieldset>
    </div></Modal>}
    {canManage && dialog === "delete" && selected && <Modal title="Delete FQDN resource?" danger showClose onDismiss={() => { if (!busy) { selectedIdRef.current = null; setDialog(null); } }} actions={<><Button variant="ghost" disabled={busy} onClick={() => { selectedIdRef.current = null; setDialog(null); }}>Cancel</Button><Button variant="danger" disabled={busy || !impact || impactResourceId !== selected.id || impact.referencing_rule_count !== 0 || impact.generation_withdrawal_required !== false} onClick={() => void remove()}>Delete FQDN resource</Button></>}><div className="space-y-3 text-cell text-ink-tertiary"><ErrorText>{error}</ErrorText>{impactError ? <LoadRetry error={`Server deletion impact could not be loaded: ${impactError}`} onRetry={() => void openDelete(selected)} /> : !impact || impactResourceId !== selected.id ? <p role="status">Loading server-computed deletion impact…</p> : <><p>Server impact: {impact.referencing_rule_count} referencing {impact.referencing_rule_count === 1 ? "rule" : "rules"}; {impact.generation_withdrawal_required ? "a live generation must be withdrawn." : "no live generation needs withdrawal."} {impact.referencing_rule_count > 0 || impact.generation_withdrawal_required ? "Deletion is unavailable until the server-reported impact is cleared." : "If deletion succeeds, recovery requires recreating this resource; immutable generation history may still prevent deletion."}</p><p>Referencing rule identities: {impact.referencing_rule_ids.length ? impact.referencing_rule_ids.join(", ") : "none"}. <Link className="text-accent-400 hover:underline" to="/access">Review referenced rules in Access Rules</Link>.</p></>}</div></Modal>}
  </section>;
}

function StateBadge({ state }: { state: FQDNResource["state"] }) {
  const copy: Record<FQDNResource["state"], string> = { draft: "Draft, unbound, no authorization", unconfigured: "Unconfigured, resolver context needs configuration", resolving: "Resolving, awaiting server result", healthy: "Healthy, active generation", stale: "Stale, last result is not current", failed: "Failed, no usable result", nxdomain: "NXDOMAIN, hostname absent" };
  return <span aria-label={copy[state]} className="text-xs text-ink-tertiary">{state === "nxdomain" ? "NXDOMAIN" : state}</span>;
}

function fqdnPortScope(resource: FQDNResource) {
  if (resource.protocol === "any" || resource.port_low == null) return resource.protocol === "any" ? "Any protocol, all ports" : `${resource.protocol.toUpperCase()}, all ports`;
  if (resource.port_high == null || resource.port_high === resource.port_low) return `${resource.protocol.toUpperCase()} port ${resource.port_low}`;
  return `${resource.protocol.toUpperCase()} ports ${resource.port_low}–${resource.port_high}`;
}

/** A stable, shareable workspace for an FQDN resource.  The list endpoint is
 * deliberately used because the current generated contract has no get-by-id
 * projection.  Do not infer answers, health, audit, or impact from that gap. */
export function FQDNResourceDetail() {
  const { org } = useOrg();
  const { state } = useAuth();
  return <FQDNResourceDetailWorkspace key={`${org?.id ?? ""}:${state.status === "authed" ? state.user.id : ""}`} />;
}

function FQDNResourceDetailWorkspace() {
  const { org } = useOrg();
  const { state } = useAuth();
  const { resourceId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [role, setRole] = useState<Member["role"] | undefined>();
  const [membershipOrgId, setMembershipOrgId] = useState<string | null>(null);
  const [membershipError, setMembershipError] = useState("");
  const [membershipAttempt, setMembershipAttempt] = useState(0);
  const [resources, setResources] = useState<FQDNResource[] | null>(null);
  const [impact, setImpact] = useState<FQDNResourceImpact | null>(null);
  const [error, setError] = useState("");
  // A list and its impact are one detail workspace request.  Keep both the
  // initiating org/resource key and a sequence so retries cannot let an older
  // response replace the newest route's server-owned projection.
  const detailKey = `${org?.id ?? ""}:${resourceId ?? ""}`;
  const detailKeyRef = useRef(detailKey);
  const detailSequenceRef = useRef(0);
  const membershipOrgRef = useRef(org?.id ?? "");
  const membershipSequenceRef = useRef(0);
  detailKeyRef.current = detailKey;
  membershipOrgRef.current = org?.id ?? "";
  const from = (location.state as { from?: string } | null)?.from;
  const back = from?.startsWith("/access/resources") ? from : `/access/resources${location.search}`;
  const reload = useCallback(async () => {
    if (!org || membershipOrgId !== org.id || !can(role, "fqdn_resource:view")) return;
    const requestKey = `${org.id}:${resourceId ?? ""}`;
    const sequence = ++detailSequenceRef.current;
    const isCurrent = () => detailKeyRef.current === requestKey && detailSequenceRef.current === sequence;
    setError(""); setResources(null); setImpact(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId: org.id } } }));
    if (!isCurrent()) return;
    if (!result.ok) { setError(result.error); return; }
    const found = (result.data as FQDNResource[]).find((candidate) => candidate.id === resourceId);
    setResources(result.data as FQDNResource[]);
    if (!found || !resourceId) return;
    const impactResult = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}/impact", { params: { path: { orgId: org.id, resourceId } } }));
    if (!isCurrent()) return;
    if (!impactResult.ok) { setError(impactResult.error); return; }
    setImpact(impactResult.data as FQDNResourceImpact);
  }, [membershipOrgId, org?.id, resourceId, role]);
  useEffect(() => {
    const requestOrgId = org?.id ?? "";
    const sequence = ++membershipSequenceRef.current;
    const isCurrent = () => membershipOrgRef.current === requestOrgId && membershipSequenceRef.current === sequence;
    setMembershipOrgId(null); setRole(undefined); setResources(null); setImpact(null); setError(""); setMembershipError("");
    if (!org || state.status !== "authed") { setMembershipOrgId(org?.id ?? null); return; }
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (!isCurrent()) return;
      if (!result.ok) { setMembershipError(result.error); setMembershipOrgId(org.id); return; }
      setRole((result.data as Member[]).find((member) => member.user_id === state.user.id)?.role);
      setMembershipOrgId(org.id);
    });
    return () => { membershipSequenceRef.current += 1; };
  }, [membershipAttempt, org?.id, state.status, state.status === "authed" ? state.user.id : ""]);
  useEffect(() => { void reload(); }, [reload]);
  const resource = resources?.find((candidate) => candidate.id === resourceId);
  const header = <><PageHeader navigationTitle title="FQDN resource" /><AccessTabRail includeKubernetesScopes={can(role, "k8s_scope:view") && can(role, "policy:view")} /></>;
  const shellClass = "network-management resources-workspace access-resources-workspace space-y-5";
  if (!org || membershipOrgId !== org.id) return <div className={shellClass}>{header}<Loading label="Checking FQDN resource permissions…" /></div>;
  if (membershipError) return <div className={shellClass}>{header}<LoadRetry error={`Could not check FQDN resource permissions: ${membershipError}`} onRetry={() => setMembershipAttempt((attempt) => attempt + 1)} /></div>;
  if (error) return <div className={shellClass}>{header}<LoadRetry error={`Could not load this FQDN resource: ${error}`} onRetry={() => void reload()} /></div>;
  if (!can(role, "fqdn_resource:view")) return <div className={shellClass}>{header}<p role="alert" className="access-resource-copy">You do not have permission to view FQDN resources.</p><Link className="access-resource-link" to={back}>Back to Resources</Link></div>;
  if (resources === null) return <div className={shellClass}>{header}<Loading label="Loading FQDN resource…" /></div>;
  if (!resource) return <div className={shellClass}>{header}<p role="alert" className="access-resource-copy">This FQDN resource is unavailable or no longer exists in the current organization.</p><Link className="access-resource-link" to={back}>Back to Resources</Link></div>;
  return <div className={shellClass}>
    <AccessTabRail includeKubernetesScopes={can(role, "k8s_scope:view") && can(role, "policy:view")} />
    <nav aria-label="Breadcrumb" className="access-resource-breadcrumb"><Link to={back}>Resources</Link><span aria-hidden="true">/</span><span aria-current="page">{resource.name}</span></nav>
    <PageHeader title={resource.name} subtitle={resource.fqdn} actions={<div className="access-resource-actions"><Button variant="ghost" onClick={() => void reload()}>Refresh resource</Button><Button variant="ghost" onClick={() => navigate(back)}>Back to Resources</Button></div>} />
    <section aria-label="FQDN resource details" className="access-resource-content">
      <div className="access-resource-actions"><StateBadge state={resource.state} /><span className="access-resource-context">{fqdnPortScope(resource)}</span></div>
      <p className="access-resource-copy">{nextAction(resource)}</p>
      {(resource.state === "draft" || resource.state === "unconfigured") && <Link className="access-resource-link" to="/access/resources?type=fqdn#private-dns-heading">Review Sites and resolver settings</Link>}
      <ResourceSummary title="Resolver settings"><dl className="access-resource-facts tnx-resource-facts tnx-resource-facts-three"><DetailFact label="Resolver authority" value={resource.resolver_context ? `${resource.resolver_context.site_name} / ${resource.resolver_context.gateway_name}` : "Unbound draft, cannot compile or authorize traffic"} /><DetailFact label="Generation" value={resource.generation == null ? "Unavailable, no active generation" : String(resource.generation)} /><DetailFact label="Answer summary" value={resource.state === "healthy" ? `${resource.answer_count} active answers` : "No active answers"} /></dl></ResourceSummary>
      <div className="access-resource-copy"><h2 className="sr-only">Rule impact and audit</h2>{impact ? <p>{impact.referencing_rule_count === 0 ? "No access rules currently reference this resource." : `${impact.referencing_rule_count} access ${impact.referencing_rule_count === 1 ? "rule references" : "rules reference"} this resource.`}</p> : <p role="status">Loading deletion impact…</p>}<div className="access-resource-actions"><Link className="access-resource-link" to="/access">Review Access Rules</Link><Link className="access-resource-link" to="/audit">Audit log</Link></div></div>
      <details className="access-resource-help"><summary>Resolver timing</summary><dl className="access-resource-facts tnx-resource-facts tnx-resource-facts-three"><DetailFact label="Effective TTL" value={resource.effective_ttl_seconds == null ? "Not available" : `${resource.effective_ttl_seconds} seconds`} /><DetailFact label="Last refresh" value={resource.refreshed_at ?? "Not available"} /><DetailFact label="Last good" value={resource.last_good_at ?? "Not available"} /></dl></details>
    </section>
  </div>;
}

function resourcePortScope(resource: Resource) {
  if (resource.protocol === "any" || resource.port_low == null) return resource.protocol === "any" ? "Any protocol, all ports" : `${resource.protocol.toUpperCase()}, all ports`;
  if (resource.port_high == null || resource.port_high === resource.port_low) return `${resource.protocol.toUpperCase()} port ${resource.port_low}`;
  return `${resource.protocol.toUpperCase()} ports ${resource.port_low}–${resource.port_high}`;
}

function DetailFact({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-ink-tertiary">{label}</dt><dd className="mt-1 text-cell text-ink-heading">{value}</dd></div>;
}

function nextAction(resource: FQDNResource) {
  if (resource.state === "draft") return "This unbound draft cannot authorize traffic. Configure its resolver path before relying on this destination.";
  if (resource.state === "unconfigured") return "The selected resolver needs configuration before this resource can authorize traffic.";
  if (resource.state === "resolving") return "Await the next server-reported resolution result.";
  if (resource.state === "healthy") return "Review referencing rules before changing this destination.";
  if (resource.state === "stale") return "Treat prior answers as not current and investigate resolver freshness.";
  if (resource.state === "nxdomain") return "Verify the exact hostname and authoritative resolver context.";
  return "Investigate the server-reported resolver failure before relying on this destination.";
}
