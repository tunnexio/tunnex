import { useCallback, useEffect, useState } from "react";
import { AccessTabRail } from "../components/AccessTabRail";
import { Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import { api, apiErrorMessage, loadOne, type Member, type Resource } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";

/** Canonical Access Resources workspace. Group management intentionally lives elsewhere. */
export default function AccessResources() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [authorized, setAuthorized] = useState<boolean | null>(null);
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
    if (!org || state.status !== "authed") { setAuthorized(false); return; }
    setAuthorized(null);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); setAuthorized(false); return; }
      const mine = (result.data as Member[]).find((member) => member.user_id === state.user.id);
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
  if (!authorized) return <div className="space-y-5">{header}<Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage resources.</p><ErrorText>{error}</ErrorText></Card></div>;
  if (!resources) return <div className="space-y-5">{header}<Card><Loading label="Loading resources…" /><ErrorText>{error}</ErrorText></Card></div>;
  const filteredResources = resources.filter((resource) => `${resource.name} ${resource.cidr} ${resource.protocol}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="space-y-5">{header}<ErrorText>{error}</ErrorText><div className="max-w-md"><Input aria-label="Search resources" value={query} placeholder="Search resource name, CIDR, or protocol" onChange={(event) => setQuery(event.target.value)} /></div><Card><DataTable caption="Resources inventory" rows={filteredResources} rowKey={(resource) => resource.id} failed={false} filterable={false} pageSize={25} empty={<EmptyState>{resources.length === 0 ? "No resources yet. Define named destination ranges so policy rules stay readable and reusable." : "No resources match this search."}</EmptyState>} columns={[{ key: "name", header: "Resource", cell: (resource) => <button className="font-medium text-ink-heading hover:underline" onClick={() => openEdit(resource)}>{resource.name}</button> }, { key: "label", header: "Description", cell: (resource) => resource.label || "—" }, { key: "cidr", header: "CIDR", cell: (resource) => resource.cidr }, { key: "protocol", header: "Protocol", cell: (resource) => resource.protocol === "any" ? "Any" : resource.protocol.toUpperCase() }, { key: "ports", header: "Ports", cell: (resource) => resource.protocol === "any" || resource.port_low == null ? "All" : resource.port_high == null || resource.port_high === resource.port_low ? String(resource.port_low) : `${resource.port_low}–${resource.port_high}` }, { key: "actions", header: "", cell: (resource) => <div className="flex gap-2"><Button size="sm" variant="ghost" onClick={() => openEdit(resource)}>Edit</Button><Button size="sm" variant="danger" onClick={() => { setSelected(resource); setDialog("delete"); }}>Delete</Button></div> }]} /></Card>
    {(dialog === "create" || dialog === "edit") && <Modal title={dialog === "edit" ? "Edit resource" : "Create resource"} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim() || !cidr.trim()} onClick={() => void save()}>{dialog === "edit" ? "Save resource" : "Create resource"}</Button></>}><p className="mb-3 text-cell text-ink-tertiary">A change here changes the destination every referencing rule can reach. Rules inherit this CIDR, protocol, and port scope.</p><div className="space-y-3"><Field label="Name"><Input value={name} autoFocus onChange={(event) => setName(event.target.value)} /></Field><Field label="Description (optional)"><Input value={label} onChange={(event) => setLabel(event.target.value)} /></Field><Field label="CIDR"><Input value={cidr} placeholder="10.0.5.0/24" onChange={(event) => setCidr(event.target.value)} /></Field><Field label="Protocol"><Select value={protocol} onChange={(event) => { const next = event.target.value as "any" | "tcp" | "udp"; setProtocol(next); setPortsTouched(false); if (next === "any") { setPortScope("all"); setPortLow(""); setPortHigh(""); } }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>{protocol !== "any" && <><Field label="Port scope"><Select value={portScope} onChange={(event) => { setPortScope(event.target.value as "all" | "single" | "range"); setPortsTouched(false); }}><option value="all">All ports</option><option value="single">Single port</option><option value="range">Port range</option></Select></Field>{portScope !== "all" && <div className="grid grid-cols-2 gap-3"><Field label="Port"><Input inputMode="numeric" value={portLow} onChange={(event) => { setPortsTouched(true); setPortLow(event.target.value); }} /></Field>{portScope === "range" && <Field label="Through"><Input inputMode="numeric" value={portHigh} onChange={(event) => { setPortsTouched(true); setPortHigh(event.target.value); }} /></Field>}</div>}</>}<p className="rounded-md border border-border bg-white/5 px-3 py-2 text-xs text-ink-tertiary">Scope: {scopeSummary}</p>{showPortError && <ErrorText>Use whole ports from 1 to 65535; a range must end at or above its starting port.</ErrorText>}</div></Modal>}
    {dialog === "delete" && selected && <Modal title="Delete resource?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>Delete resource</Button></>}><p className="text-cell text-ink-tertiary">Deleting {selected.name} can affect rules that reference this destination. This screen does not have a server-provided affected-rule count, so it cannot preview a number. The server may refuse the deletion; if it succeeds, recovery is to recreate the resource and review affected rules explicitly.</p></Modal>}
  </div>;
}
