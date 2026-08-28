import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AccessTabRail } from "../components/AccessTabRail";
import { LoadRetry } from "../components/LoadRetry";
import { Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import { api, apiErrorMessage, loadOne, type FQDNResource, type FQDNResourceImpact, type Member, type Resource } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { can } from "../lib/rbac";

/** Canonical Access Resources workspace. Group management intentionally lives elsewhere. */
export default function AccessResources() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [authorized, setAuthorized] = useState<boolean | null>(null);
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
  const reload = useCallback(async () => {
    if (!org || authorized !== true) return;
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/resources", { params: { path: { orgId: org.id } } }));
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
  const header = <><PageHeader title="Resources" subtitle="Named CIDR ranges and resolver-backed exact hostnames used by access policy rules." actions={authorized === true ? <Button onClick={() => setDialog("choose")}>Create resource</Button> : undefined} /><AccessTabRail /></>;
  if (membershipError) return <div className="space-y-5">{header}<Card><LoadRetry error={`Could not check resource permissions: ${membershipError}`} onRetry={() => setMembershipAttempt((attempt) => attempt + 1)} /></Card></div>;
  if (!org || authorized === null) return <div className="space-y-5">{header}<Card><Loading label="Checking resource permissions…" /></Card></div>;
  const indexControls = <div className="grid max-w-2xl gap-2 sm:grid-cols-2">{type === "cidr" && <Input aria-label="Search resources" value={query} placeholder="Search resources" onChange={(event) => updateIndex({ q: event.target.value })} />}<Select aria-label="Resource type" value={type} onChange={(event) => updateIndex({ type: event.target.value })}><option value="cidr">CIDR</option><option value="fqdn">FQDN</option></Select></div>;
  const createChooser = dialog === "choose" && <Modal title="Create resource" onDismiss={() => setDialog(null)} actions={<Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button>}><p className="mb-4 text-cell text-ink-tertiary">Choose the destination shape. CIDR is a static network range; FQDN is one exact hostname saved as an unbound draft.</p><div className="grid gap-3 sm:grid-cols-2"><Button onClick={() => { setDialog(null); updateIndex({ type: "cidr" }); openCreate(); }}>Create CIDR resource</Button><Button onClick={() => { setDialog(null); updateIndex({ type: "fqdn" }); setFqdnCreateToken((token) => token + 1); }}>Create FQDN resource</Button></div></Modal>;
  if (type === "fqdn") return <div className="space-y-5">{header}{indexControls}<FQDNResources key={org.id} orgId={org.id} role={role} createToken={fqdnCreateToken} />{createChooser}</div>;
  if (!authorized) return <div className="space-y-5">{header}{indexControls}<Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage CIDR resources.</p><ErrorText>{error}</ErrorText></Card></div>;
  if (!resources) return <div className="space-y-5">{header}{indexControls}<Card><Loading label="Loading resources…" /><ErrorText>{error}</ErrorText></Card></div>;
  const cidrSort = ["name", "cidr", "protocol"].includes(searchParams.get("sort") ?? "") ? searchParams.get("sort")! : "name";
  const cidrDir = searchParams.get("dir") === "desc" ? "desc" : "asc";
  const filteredResources = resources.filter((resource) => `${resource.name} ${resource.cidr} ${resource.protocol}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => {
    const left = cidrSort === "cidr" ? a.cidr : cidrSort === "protocol" ? a.protocol : a.name;
    const right = cidrSort === "cidr" ? b.cidr : cidrSort === "protocol" ? b.protocol : b.name;
    return left.localeCompare(right) * (cidrDir === "desc" ? -1 : 1);
  });
  const updateCidrQuery = (next: Record<string, string>) => updateIndex(next);
  return <div className="space-y-5">{header}<ErrorText>{error}</ErrorText>{indexControls}<div className="grid max-w-2xl gap-2 sm:grid-cols-2"><Select aria-label="Sort CIDR resources" value={cidrSort} onChange={(event) => updateCidrQuery({ sort: event.target.value })}><option value="name">Name</option><option value="cidr">CIDR</option><option value="protocol">Protocol</option></Select><Select aria-label="CIDR sort direction" value={cidrDir} onChange={(event) => updateCidrQuery({ dir: event.target.value })}><option value="asc">Ascending</option><option value="desc">Descending</option></Select></div><Card><div className="hidden sm:block"><DataTable caption="Resources inventory" rows={filteredResources} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={25} empty={<EmptyState>{resources.length === 0 ? "No resources yet. Define named destination ranges so policy rules stay readable and reusable." : "No resources match this search."}</EmptyState>} columns={[{ key: "name", header: "Resource", cell: (resource) => <button className="font-medium text-ink-heading hover:underline" onClick={() => openEdit(resource)}>{resource.name}</button> }, { key: "label", header: "Description", cell: (resource) => resource.label || "—" }, { key: "cidr", header: "CIDR", cell: (resource) => resource.cidr }, { key: "protocol", header: "Protocol", cell: (resource) => resource.protocol === "any" ? "Any" : resource.protocol.toUpperCase() }, { key: "ports", header: "Ports", cell: (resource) => resourcePortScope(resource) }, { key: "actions", header: "Actions", cell: (resource) => <div className="flex flex-wrap gap-2"><Button size="sm" variant="ghost" aria-label={`Edit ${resource.name}`} onClick={() => openEdit(resource)}>Edit</Button><Button size="sm" variant="danger" aria-label={`Delete ${resource.name}`} onClick={() => { setSelected(resource); setDialog("delete"); }}>Delete</Button></div> }]} /></div><div className="space-y-3 sm:hidden" aria-label="CIDR resource summaries">{filteredResources.map((resource) => <section key={resource.id} className="rounded-md border border-line p-3"><h3 className="font-medium text-ink-heading">{resource.name}</h3><dl className="mt-2 grid grid-cols-2 gap-2 text-sm"><div><dt className="text-ink-tertiary">CIDR</dt><dd>{resource.cidr}</dd></div><div><dt className="text-ink-tertiary">Scope</dt><dd>{resourcePortScope(resource)}</dd></div></dl><div className="mt-3 flex gap-2"><Button size="sm" variant="ghost" aria-label={`Edit ${resource.name}`} onClick={() => openEdit(resource)}>Edit {resource.name}</Button><Button size="sm" variant="danger" aria-label={`Delete ${resource.name}`} onClick={() => { setSelected(resource); setDialog("delete"); }}>Delete {resource.name}</Button></div></section>)}{filteredResources.length === 0 && <EmptyState>{resources.length === 0 ? "No resources yet. Define named destination ranges so policy rules stay readable and reusable." : "No resources match this search."}</EmptyState>}</div></Card>
    {createChooser}
    {(dialog === "create" || dialog === "edit") && <Modal title={dialog === "edit" ? "Edit resource" : "Create resource"} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim() || !cidr.trim()} onClick={() => void save()}>{dialog === "edit" ? "Save resource" : "Create resource"}</Button></>}><p className="mb-3 text-cell text-ink-tertiary">A change here changes the destination every referencing rule can reach. Rules inherit this CIDR, protocol, and port scope.</p><div className="space-y-3"><Field label="Name"><Input value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field><Field label="Description (optional)"><Input value={label} onChange={(event) => setLabel(event.target.value)} /></Field><Field label="CIDR"><Input value={cidr} placeholder="10.0.5.0/24" onChange={(event) => setCidr(event.target.value)} /></Field><Field label="Protocol"><Select value={protocol} onChange={(event) => { const next = event.target.value as "any" | "tcp" | "udp"; setProtocol(next); setPortsTouched(false); if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); } }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>{protocol !== "any" && <><Field label="Port scope"><Select value={portScope} onChange={(event) => { setPortScope(event.target.value as "all" | "single" | "range"); setPortsTouched(false); }}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>{portScope !== "all" && <div className="grid grid-cols-2 gap-3"><Field label="Port"><Input inputMode="numeric" value={portLow} onChange={(event) => { setPortsTouched(true); setPortLow(event.target.value); }} /></Field>{portScope === "range" && <Field label="Through"><Input inputMode="numeric" value={portHigh} onChange={(event) => { setPortsTouched(true); setPortHigh(event.target.value); }} /></Field>}</div>}</>}<p className="rounded-md border border-border bg-white/5 px-3 py-2 text-xs text-ink-tertiary">Scope: {scopeSummary}</p>{showPortError && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}</div></Modal>}
    {dialog === "delete" && selected && <Modal title="Delete resource?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>Delete resource</Button></>}><p className="text-cell text-ink-tertiary">Deleting {selected.name} can affect rules that reference this destination. This screen does not have a server-provided affected-rule count, so it cannot preview a number. The server may refuse the deletion; if it succeeds, recovery is to recreate the resource and review affected rules explicitly.</p></Modal>}
  </div>;
}

function FQDNResources({ orgId, role, createToken }: { orgId: string; role: Member["role"] | undefined; createToken: number }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const canView = can(role, "fqdn_resource:view");
  const canManage = can(role, "fqdn_resource:manage");
  const [resources, setResources] = useState<FQDNResource[] | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<FQDNResource | null>(null);
  const [dialog, setDialog] = useState<"create" | "delete" | null>(null);
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

  const reload = useCallback(async () => {
    if (!canView) return;
    setError(""); setResources(null);
    const resourceResult = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } } }));
    if (!resourceResult.ok) { setError(resourceResult.error); return; }
    setResources(resourceResult.data as FQDNResource[]);
  }, [canView, orgId]);
  useEffect(() => { void reload(); }, [reload]);

  const openForm = () => {
    setSelected(null); setName(""); setFqdn(""); setLabel(""); setProtocol("any"); setPortScope("all"); setPortLow(""); setPortHigh("");
    setDialog("create");
  };
  useEffect(() => { if (createToken > 0 && canManage) openForm(); }, [createToken]);
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
    if (!name.trim() || !fqdn.trim() || !portsValid) return;
    // The current preview contract cannot safely express binding, opt-in, or
    // editing. Creates are explicit unbound drafts; existing contexts stay put.
    const body = { name: name.trim(), fqdn: fqdn.trim(), label: label.trim() || null, protocol, ...(protocol === "any" || portScope === "all" ? { port_low: null, port_high: null } : portScope === "single" ? { port_low: parsedLow!, port_high: parsedLow! } : { port_low: parsedLow!, port_high: parsedHigh! }), resolver_context: null };
    const ok = await mutate(() => api.POST("/api/v1/organizations/{orgId}/fqdn-resources", { params: { path: { orgId } }, body }), "Could not save the FQDN resource.");
    if (ok) { setDialog(null); await reload(); }
  }
  async function openDelete(resource: FQDNResource) {
    // The impact endpoint is asynchronous. Keep its result bound to the row
    // that requested it so a late A response can never authorize deleting B.
    selectedIdRef.current = resource.id;
    setSelected(resource); setImpact(null); setImpactResourceId(null); setImpactError(""); setDialog("delete");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}/impact", { params: { path: { orgId, resourceId: resource.id } } }));
    if (selectedIdRef.current !== resource.id) return;
    if (result.ok) { setImpact(result.data as FQDNResourceImpact); setImpactResourceId(resource.id); } else setImpactError(result.error);
  }
  const detailTarget = (resource: FQDNResource) => ({ pathname: `/access/resources/fqdn/${resource.id}`, search: location.search, state: { from: `${location.pathname}${location.search}` } });
  function openDetail(resource: FQDNResource) {
    navigate(detailTarget(resource));
  }
  async function remove() {
    if (!selected || !impact || impactResourceId !== selected.id || impact.referencing_rule_count > 0 || impact.generation_withdrawal_required) return;
    const ok = await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/fqdn-resources/{resourceId}", { params: { path: { orgId, resourceId: selected.id } } }), "Could not delete the FQDN resource.");
    if (ok) { selectedIdRef.current = null; setDialog(null); setSelected(null); setImpactResourceId(null); await reload(); }
  }
  if (!canView) return <Card><div className="space-y-2" aria-labelledby="fqdn-resources-heading"><h2 id="fqdn-resources-heading" className="text-lg font-semibold text-ink-heading">FQDN resources</h2><p role="alert" className="text-cell text-ink-tertiary">FQDN resources are unavailable because your role lacks <code>fqdn_resource:view</code>. Owners and admins currently receive this permission.</p></div></Card>;
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
  return <Card><section aria-labelledby="fqdn-resources-heading" className="space-y-4"><div><h2 id="fqdn-resources-heading" className="text-lg font-semibold text-ink-heading">FQDN resources</h2><p className="text-cell text-ink-tertiary">Resolver-backed exact hostnames. A hostname is not an IP ownership boundary: hostnames sharing an IP and protocol/port cannot be distinguished after resolution. The server projects exact referencing rule identities for recovery; DNS answers and diagnostic/audit projections remain unavailable.</p>{!canManage && <p className="mt-2 text-cell text-ink-tertiary">Create, edit, delete, and enforcement controls require <code>fqdn_resource:manage</code> (currently owners and admins).</p>}</div>
    <p className="rounded-md border border-border px-3 py-2 text-cell text-ink-tertiary">FQDN resources are currently created only as unbound drafts.</p>
    <ErrorText>{error}</ErrorText>
    {resources === null ? error ? <LoadRetry error={`Could not load FQDN resources: ${error}`} onRetry={() => void reload()} /> : <Loading label="Loading FQDN resources…" /> : <><div className="grid gap-2 sm:grid-cols-4"><Input aria-label="Search FQDN resources" value={q} placeholder="Search name or hostname" onChange={(event) => updateQuery({ q: event.target.value })} /><Select aria-label="FQDN status" value={status} onChange={(event) => updateQuery({ status: event.target.value })}><option value="all">All states</option>{["draft", "unconfigured", "resolving", "healthy", "stale", "failed", "nxdomain"].map((value) => <option key={value} value={value}>{value}</option>)}</Select><Select aria-label="Sort FQDN resources" value={sort} onChange={(event) => updateQuery({ sort: event.target.value })}><option value="name">Name</option><option value="fqdn">Hostname</option><option value="state">State</option></Select><Select aria-label="Sort direction" value={dir} onChange={(event) => updateQuery({ dir: event.target.value })}><option value="asc">Ascending</option><option value="desc">Descending</option></Select></div><div className="hidden sm:block"><DataTable caption="FQDN resources inventory" rows={filtered} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={25} empty={<EmptyState>{resources.length === 0 ? "No FQDN resources yet. Create an exact hostname or save an unbound draft." : "No FQDN resources match this search."}</EmptyState>} columns={[{ key: "name", header: "Resource", cell: (resource) => <button className="font-medium text-ink-heading hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400" onClick={() => openDetail(resource)}>{resource.name}</button> }, { key: "fqdn", header: "Hostname", cell: (resource) => resource.fqdn }, { key: "ports", header: "Port scope", cell: (resource) => fqdnPortScope(resource) }, { key: "state", header: "State", cell: (resource) => <StateBadge state={resource.state} /> }, { key: "context", header: "Resolver context", cell: (resource) => resource.resolver_context ? `${resource.resolver_context.site_name} / ${resource.resolver_context.gateway_name}` : "Unbound draft" }, { key: "answers", header: "Answers", cell: (resource) => resource.state === "healthy" ? String(resource.answer_count) : "Not available" }, { key: "actions", header: "Actions", cell: (resource) => canManage ? <Button size="sm" variant="danger" aria-label={`Delete ${resource.name}`} onClick={() => void openDelete(resource)}>Delete</Button> : "Read-only — manage permission required" }]} /></div><div className="space-y-3 sm:hidden" aria-label="FQDN resource summaries">{filtered.map((resource) => <section key={resource.id} className="rounded-md border border-line p-3"><h3 className="font-medium text-ink-heading">{resource.name}</h3><dl className="mt-2 grid grid-cols-2 gap-2 text-sm"><div><dt className="text-ink-tertiary">Hostname</dt><dd>{resource.fqdn}</dd></div><div><dt className="text-ink-tertiary">Scope</dt><dd>{fqdnPortScope(resource)}</dd></div><div><dt className="text-ink-tertiary">State</dt><dd><StateBadge state={resource.state} /></dd></div></dl><div className="mt-3 flex flex-wrap gap-2"><Link className="text-sm font-medium text-accent-400 hover:underline" to={detailTarget(resource)}>View {resource.name}</Link>{canManage ? <Button size="sm" variant="danger" aria-label={`Delete ${resource.name}`} onClick={() => void openDelete(resource)}>Delete {resource.name}</Button> : <span className="text-sm text-ink-tertiary">Read-only — manage permission required</span>}</div></section>)}{filtered.length === 0 && <EmptyState>{resources.length === 0 ? "No FQDN resources yet. Create an exact hostname or save an unbound draft." : "No FQDN resources match this search."}</EmptyState>}</div><p className="text-xs text-ink-tertiary">Select this destination from <Link className="text-accent-400 hover:underline" to="/access">Access Rules</Link>. DNS addresses, audit entries, and diagnostics are unavailable until the server projects them.</p></>}
    {dialog === "create" && <Modal title="Create FQDN resource" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim() || !fqdn.trim() || !portsValid} onClick={() => void save()}>Save as draft</Button></>}><div className="space-y-4"><p className="text-cell text-ink-tertiary">Use one exact hostname, not a wildcard, URL, or IP. The server normalizes and validates it.</p><ErrorText>{error}</ErrorText><fieldset className="space-y-3"><legend className="text-sm font-semibold text-ink-heading">Identity</legend><Field label="Name"><Input value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field><Field label="Exact hostname"><Input value={fqdn} placeholder="orders.internal.example.com" onChange={(event) => setFqdn(event.target.value)} /></Field><Field label="Description (optional)"><Input value={label} onChange={(event) => setLabel(event.target.value)} /></Field></fieldset><fieldset className="space-y-3"><legend className="text-sm font-semibold text-ink-heading">Access scope</legend><Field label="Protocol"><Select value={protocol} onChange={(event) => { const next = event.target.value as "any" | "tcp" | "udp"; setProtocol(next); if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); } }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>{protocol !== "any" && <><Field label="Port scope"><Select value={portScope} onChange={(event) => setPortScope(event.target.value as "all" | "single" | "range")}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>{portScope !== "all" && <div className="grid grid-cols-1 gap-3 sm:grid-cols-2"><Field label="Port"><Input inputMode="numeric" value={portLow} onChange={(event) => setPortLow(event.target.value)} /></Field>{portScope === "range" && <Field label="Through"><Input inputMode="numeric" value={portHigh} onChange={(event) => setPortHigh(event.target.value)} /></Field>}</div>}</>}<p className="text-xs text-ink-tertiary">Scope: {scope}</p>{!portsValid && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}</fieldset></div></Modal>}
    {dialog === "delete" && selected && <Modal title="Delete FQDN resource?" danger onDismiss={() => { selectedIdRef.current = null; setDialog(null); }} actions={<><Button variant="ghost" onClick={() => { selectedIdRef.current = null; setDialog(null); }}>Cancel</Button><Button variant="danger" disabled={busy || !impact || impactResourceId !== selected.id || impact.referencing_rule_count > 0 || impact.generation_withdrawal_required} onClick={() => void remove()}>Delete FQDN resource</Button></>}><div className="space-y-3 text-cell text-ink-tertiary"><ErrorText>{error}</ErrorText>{impactError ? <LoadRetry error={`Server deletion impact could not be loaded: ${impactError}`} onRetry={() => void openDelete(selected)} /> : !impact || impactResourceId !== selected.id ? <p role="status">Loading server-computed deletion impact…</p> : <><p>Server impact: {impact.referencing_rule_count} referencing {impact.referencing_rule_count === 1 ? "rule" : "rules"}; {impact.generation_withdrawal_required ? "a live generation must be withdrawn." : "no live generation needs withdrawal."} {impact.referencing_rule_count > 0 || impact.generation_withdrawal_required ? "Deletion is unavailable until the server-reported impact is cleared." : "If deletion succeeds, recovery requires recreating this resource; immutable generation history may still prevent deletion."}</p><p>Referencing rule identities: {impact.referencing_rule_ids.length ? impact.referencing_rule_ids.join(", ") : "none"}. <Link className="text-accent-400 hover:underline" to="/access">Review referenced rules in Access Rules</Link>.</p></>}</div></Modal>}
  </section></Card>;
}

function StateBadge({ state }: { state: FQDNResource["state"] }) {
  const copy: Record<FQDNResource["state"], string> = { draft: "Draft — unbound, no authorization", unconfigured: "Unconfigured — resolver context needs configuration", resolving: "Resolving — awaiting server result", healthy: "Healthy — active generation", stale: "Stale — last result is not current", failed: "Failed — no usable result", nxdomain: "NXDOMAIN — hostname absent" };
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
  if (!org || membershipOrgId !== org.id) return <div className="space-y-5"><PageHeader title="FQDN resource" subtitle="Authoritative resolver-backed destination." /><AccessTabRail /><Card><Loading label="Checking FQDN resource permissions…" /></Card></div>;
  if (membershipError) return <div className="space-y-5"><PageHeader title="FQDN resource" subtitle="Authoritative resolver-backed destination." /><AccessTabRail /><Card><LoadRetry error={`Could not check FQDN resource permissions: ${membershipError}`} onRetry={() => setMembershipAttempt((attempt) => attempt + 1)} /></Card></div>;
  if (error) return <div className="space-y-5"><PageHeader title="FQDN resource" subtitle="Authoritative resolver-backed destination." /><AccessTabRail /><Card><LoadRetry error={`Could not load this FQDN resource: ${error}`} onRetry={() => void reload()} /></Card></div>;
  if (!can(role, "fqdn_resource:view")) return <div className="space-y-5"><PageHeader title="FQDN resource" subtitle="Authoritative resolver-backed destination." /><AccessTabRail /><Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to view FQDN resources.</p><Link className="text-accent-400 hover:underline" to={back}>Back to Resources</Link></Card></div>;
  if (resources === null) return <div className="space-y-5"><PageHeader title="FQDN resource" subtitle="Authoritative resolver-backed destination." /><AccessTabRail /><Card><Loading label="Loading FQDN resource…" /></Card></div>;
  if (!resource) return <div className="space-y-5"><PageHeader title="FQDN resource" subtitle="Authoritative resolver-backed destination." /><AccessTabRail /><Card><p role="alert" className="text-cell text-ink-tertiary">This FQDN resource is unavailable or no longer exists in the current organization.</p><Link className="text-accent-400 hover:underline" to={back}>Back to Resources</Link></Card></div>;
  return <div className="space-y-5"><nav aria-label="Breadcrumb" className="text-sm text-ink-tertiary"><Link className="text-accent-400 hover:underline" to={back}>Resources</Link><span aria-hidden="true"> / </span><span aria-current="page">{resource.name}</span></nav><PageHeader title={resource.name} subtitle={resource.fqdn} actions={<Button variant="ghost" onClick={() => navigate(back)}>Back to Resources</Button>} /><AccessTabRail /><Card><section aria-labelledby="fqdn-detail-heading" className="space-y-5"><div><h2 id="fqdn-detail-heading" className="text-lg font-semibold text-ink-heading">Resolver-backed destination</h2><div className="mt-2 flex flex-wrap items-center gap-3"><StateBadge state={resource.state} /><span className="text-cell text-ink-tertiary">{fqdnPortScope(resource)}</span></div></div><dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3"><DetailFact label="Resolver authority" value={resource.resolver_context ? `${resource.resolver_context.site_name} / ${resource.resolver_context.gateway_name}` : "Unbound draft — cannot compile or authorize traffic"} /><DetailFact label="Generation" value={resource.generation == null ? "Unavailable — no active generation" : String(resource.generation)} /><DetailFact label="Answer summary" value={resource.state === "healthy" ? `${resource.answer_count} server-reported active answers` : "Unavailable for this state"} /><DetailFact label="Effective TTL" value={resource.effective_ttl_seconds == null ? "Unavailable" : `${resource.effective_ttl_seconds} seconds`} /><DetailFact label="Last refresh" value={resource.refreshed_at ?? "Unavailable"} /><DetailFact label="Last good" value={resource.last_good_at ?? "Unavailable"} /></dl><div className="border-t border-line pt-4 text-cell text-ink-tertiary"><h3 className="font-semibold text-ink-heading">Next action</h3><p className="mt-1">{nextAction(resource)}</p></div><div className="border-t border-line pt-4 text-cell text-ink-tertiary"><h3 className="font-semibold text-ink-heading">Rule impact and audit</h3>{impact ? <><p className="mt-1">Server deletion impact: exactly {impact.referencing_rule_count} referencing {impact.referencing_rule_count === 1 ? "rule" : "rules"}.</p><p className="mt-1">Referencing rule IDs: {impact.referencing_rule_ids.length ? impact.referencing_rule_ids.join(", ") : "none"}.</p></> : <p className="mt-1" role="status">Loading server-computed deletion impact…</p>}<div className="mt-2 flex flex-wrap gap-3"><Link className="text-accent-400 hover:underline" to="/access">Review Access Rules</Link><Link className="text-accent-400 hover:underline" to="/audit">Audit log</Link></div></div></section></Card></div>;
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
  if (resource.state === "draft") return "Bind this draft to an explicit Site and Gateway when server-owned resolver authority is available.";
  if (resource.state === "unconfigured") return "Configure the selected resolver authority; this resource cannot compile or authorize traffic yet.";
  if (resource.state === "resolving") return "Await the next server-reported resolution result.";
  if (resource.state === "healthy") return "Review referencing rules before changing this destination.";
  if (resource.state === "stale") return "Treat prior answers as not current and investigate resolver freshness.";
  if (resource.state === "nxdomain") return "Verify the exact hostname and authoritative resolver context.";
  return "Investigate the server-reported resolver failure before relying on this destination.";
}
