import { Link, useSearchParams } from "react-router-dom";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, loadOne, type AuditLogEntry, type Member } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { relativeAge } from "../lib/format";
import { UNATTRIBUTED_NOTE, resolveActor, unattributedCount } from "../lib/auditview";
import { Button, DataTable, ErrorText, Input, Loading, Select } from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { ResourceSummary } from "../components/ResourceSummary";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { beamAuditDetails } from "../lib/beam";
import { TerminalReplay } from "../components/TerminalReplay";
import "../network-workspaces.css";
import "../app-access-workspace.css";
import "../audit-workspace.css";

type Filters = { actor: string; action: string; from: string; to: string; targetType: string; targetId: string };
const NO_FILTERS: Filters = { actor: "", action: "", from: "", to: "", targetType: "", targetId: "" };
type Cursor = Pick<AuditLogEntry, "id" | "created_at">;
type AuditPage = { rows: AuditLogEntry[]; hasNext: boolean };
type PageRequest = { filters: Filters; size: number; page: number; cursor?: Cursor };
const targetUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Calendar days use the viewer's local zone; the end includes the complete selected day.
const dayStart = (day: string) => new Date(`${day}T00:00:00`).toISOString();
const dayEnd = (day: string) => new Date(`${day}T23:59:59.999`).toISOString();
function validCalendarDay(day: string) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return false;
  const date = new Date(`${day}T00:00:00`);
  return Number.isFinite(date.getTime()) && date.getFullYear() === Number(day.slice(0, 4)) && date.getMonth() + 1 === Number(day.slice(5, 7)) && date.getDate() === Number(day.slice(8, 10));
}
function filterError(filters: Filters) {
  if ((filters.from && !validCalendarDay(filters.from)) || (filters.to && !validCalendarDay(filters.to))) return "Choose valid calendar dates.";
  if (filters.from && filters.to && filters.from > filters.to) return "Choose an end date on or after the start date.";
  if (filters.targetId && !targetUUID.test(filters.targetId)) return "Choose a valid target UUID.";
  return null;
}
function validAuditRows(value: unknown): value is AuditLogEntry[] {
  return Array.isArray(value) && value.every((row) => row && typeof row === "object" && typeof row.id === "string" && row.id.length > 0 && typeof row.action === "string" && typeof row.created_at === "string" && Number.isFinite(Date.parse(row.created_at)) && (row.actor_id == null || typeof row.actor_id === "string") && (row.actor_system == null || typeof row.actor_system === "string") && (row.target_type == null || typeof row.target_type === "string") && (row.target_id == null || typeof row.target_id === "string") && (row.details == null || (typeof row.details === "object" && !Array.isArray(row.details)))) && new Set(value.map((row) => row.id)).size === value.length;
}
function validRoster(value: unknown): value is Member[] {
  return Array.isArray(value) && value.every((member) => member && typeof member.user_id === "string" && typeof member.name === "string" && typeof member.email === "string" && typeof member.role === "string" && (member.roles === undefined || (Array.isArray(member.roles) && member.roles.every((role: unknown) => typeof role === "string")))) && new Set(value.map((member) => member.user_id)).size === value.length;
}
function actionLabel(action: string) {
  const leaf = action.split(".").at(-1) ?? action;
  const words = leaf.replace(/[_-]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
function targetLabel(entry: AuditLogEntry) {
  if (!entry.target_type) return "No target recorded";
  const label = entry.target_type === "beam_share" ? "Local share" : entry.target_type.replace(/[_-]+/g, " ");
  return entry.target_id ? `${label} · ${(/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(entry.target_id) ? `${entry.target_id.slice(0, 4)}…${entry.target_id.slice(-8)}` : entry.target_id)}` : label;
}
function detailValue(value: unknown): string {
  if (value == null) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value, null, 2);
}

export default function AuditLog() {
  const { org, loading, failed } = useOrg();
  const { state } = useAuth();
  const [search] = useSearchParams();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  const targetType = search.get("target_type") ?? "", targetId = search.get("target_id") ?? "";
  // Tenant, actor and linked-target changes withdraw all prior evidence synchronously.
  return <AuditWorkspace key={`${org?.id ?? ""}:${actor}:${targetType}:${targetId}`} targetType={targetType} targetId={targetId} orgLoading={loading} orgFailed={failed} />;
}

function AuditWorkspace({ targetType, targetId, orgLoading, orgFailed }: { targetType: string; targetId: string; orgLoading: boolean; orgFailed: boolean }) {
  const { org } = useOrg();
  const { state } = useAuth();
  const [, setSearch] = useSearchParams();
  const [filters, setFilters] = useState<Filters>({ ...NO_FILTERS, targetType, targetId });
  const [applied, setApplied] = useState<Filters>({ ...NO_FILTERS, targetType, targetId });
  const [pages, setPages] = useState<AuditPage[]>([]), [page, setPage] = useState(0), [pageSize, setPageSize] = useState(20);
  const [busy, setBusy] = useState(false), [readError, setReadError] = useState<string | null>(null), [validationError, setValidationError] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[]>([]), [rosterKnown, setRosterKnown] = useState(false), [rosterError, setRosterError] = useState<string | null>(null), [memberScoped, setMemberScoped] = useState<boolean | null>(null);
  const [selected, setSelected] = useState<AuditLogEntry | null>(null), [replay, setReplay] = useState<string>();
  const [moreFilters, setMoreFilters] = useState(Boolean(targetType || targetId));
  const request = useRef(0), rosterRequest = useRef(0), alive = useRef(true), retry = useRef<PageRequest | null>(null), detailHeading = useRef<HTMLHeadingElement>(null);
  const orgId = org?.id ?? "", actorId = state.status === "authed" ? state.user.id : "";
  useEffect(() => { alive.current = true; return () => { alive.current = false; request.current++; rosterRequest.current++; }; }, []);
  useEffect(() => { if (selected) detailHeading.current?.focus(); }, [selected?.id]);

  async function loadRoster() {
    if (!orgId || !actorId) return;
    const sequence = ++rosterRequest.current;
    setRosterKnown(false); setMemberScoped(null); setMembers([]); setRosterError(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } }));
    if (!alive.current || sequence !== rosterRequest.current) return;
    if (!result.ok || !validRoster(result.data)) { setRosterError(!result.ok ? result.error : "The actor roster was not returned correctly."); return; }
    setMembers(result.data); setRosterKnown(true);
    const mine = result.data.find((member) => member.user_id === actorId);
    setMemberScoped(!(mine?.roles ?? (mine ? [mine.role] : [])).some((role) => role === "owner" || role === "admin"));
  }
  async function fetchPage(next: PageRequest, reset = false) {
    if (!orgId || !actorId) return;
    const invalid = filterError(next.filters);
    if (invalid) { setValidationError(invalid); return; }
    const sequence = ++request.current;
    const snapshot = { ...next, filters: { ...next.filters } };
    retry.current = snapshot;
    setBusy(true); setReadError(null); setValidationError(null); setSelected(null); setReplay(undefined); setPage(next.page); setApplied(snapshot.filters);
    if (reset) setPages([]);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/audit-logs", { params: {
      path: { orgId }, query: { actor: snapshot.filters.actor || undefined, action: snapshot.filters.action || undefined, target_type: snapshot.filters.targetType || undefined, target_id: snapshot.filters.targetId || undefined, from: snapshot.filters.from ? dayStart(snapshot.filters.from) : undefined, to: snapshot.filters.to ? dayEnd(snapshot.filters.to) : undefined, cursor_ts: snapshot.cursor?.created_at, cursor_id: snapshot.cursor?.id, limit: snapshot.size + 1 },
    } }));
    if (!alive.current || sequence !== request.current) return;
    setBusy(false);
    if (!result.ok || !validAuditRows(result.data)) { setReadError(!result.ok ? `Could not load the audit log. ${result.error}` : "The audit page was not returned correctly. Retry or refresh to restart."); return; }
    const rows = result.data.slice(0, snapshot.size);
    const earlier = new Set(pages.slice(0, snapshot.page).flatMap((previous) => previous.rows.map((row) => row.id)));
    if (!reset && rows.some((row) => earlier.has(row.id))) { setReadError("The audit page overlapped earlier events. Refresh to restart from the newest event."); return; }
    setPages((previous) => [...(reset ? [] : previous.slice(0, snapshot.page)), { rows, hasNext: result.data.length > snapshot.size }]);
  }
  useEffect(() => {
    if (!orgId || !actorId) return;
    void loadRoster();
    const linked = { ...NO_FILTERS, targetType, targetId };
    const invalid = filterError(linked);
    if (invalid) setValidationError(invalid);
    else void fetchPage({ filters: linked, size: 20, page: 0 }, true);
  }, [orgId, actorId]);

  function start(next: Filters, size = pageSize) {
    const invalid = filterError(next);
    if (invalid) { setValidationError(invalid); return; }
    void fetchPage({ filters: { ...next }, size, page: 0 }, true);
  }
  function applyFilters(event: FormEvent) { event.preventDefault(); start(filters); }
  function clearFilters() {
    if (targetType || targetId) { setSearch({}); return; }
    setFilters({ ...NO_FILTERS }); setMoreFilters(false); start(NO_FILTERS);
  }
  const current = pages[page];
  const entries = current?.rows ?? [];
  const activeFilterCount = Object.values(applied).filter(Boolean).length;
  const gapCount = unattributedCount(entries);
  const firstItem = pages.slice(0, page).reduce((count, item) => count + item.rows.length, 0) + 1;
  function move(nextPage: number) {
    const index = nextPage - 1;
    if (busy || index < 0 || index === page) return;
    if (pages[index]) { request.current++; setPage(index); setReadError(null); setValidationError(null); setSelected(null); return; }
    const cursor = current?.rows.at(-1);
    if (index === page + 1 && current?.hasNext && cursor) void fetchPage({ filters: applied, size: pageSize, page: index, cursor });
  }
  const actor = selected ? resolveActor(selected, members, rosterKnown) : null;
  const details = selected ? selected.action.startsWith("beam.") ? beamAuditDetails(selected.details ?? {}) : Object.entries(selected.details ?? {}) : [];
  const scopeNotice = memberScoped === true ? "Showing your activity only. Organization-wide activity is visible to admins and owners." : null;

  return <div className="network-management audit-workspace">
    {selected && actor ? <section aria-label="Audit evidence" className="audit-detail">
      <nav aria-label="Audit breadcrumb" className="audit-breadcrumb"><button onClick={() => setSelected(null)}>Audit log</button><span aria-hidden="true">/</span><span aria-current="page" title={selected.id}>{actionLabel(selected.action)} · {selected.id.slice(-8)}</span></nav>
      <div className="audit-detail-heading"><div><h1 ref={detailHeading} tabIndex={-1}>{actionLabel(selected.action)}</h1><p>{selected.action}</p></div><Button variant="ghost" onClick={() => setSelected(null)}>Back to audit log</Button></div>
      <ResourceSummary title="Recorded event"><dl className="audit-facts tnx-resource-facts tnx-resource-facts-three"><AuditFact label="Actor"><ActorLabel entry={selected} members={members} rosterKnown={rosterKnown} /><small>{actor.kind.replace(/_/g, " ")}</small></AuditFact><AuditFact label="Target"><span title={selected.target_id}>{targetLabel(selected)}</span></AuditFact><AuditFact label="Recorded">{new Date(selected.created_at).toLocaleString()}</AuditFact></dl></ResourceSummary>
      {rosterError && <LoadRetry error={`Actor names are unavailable: ${rosterError}`} onRetry={() => void loadRoster()} />}
      {actor.gap && <p className="audit-attribution-note">{UNATTRIBUTED_NOTE}</p>}
      <div className="audit-detail-actions">{selected.target_type === "server_access" && selected.target_id && ["server_access.session_started", "server_access.session_ended"].includes(selected.action) && <Button variant="ghost" onClick={() => setReplay(selected.target_id!)}>Review session recording</Button>}{selected.target_type === "beam_share" && selected.target_id && /^beam\.(share|grants|connector|access)\./.test(selected.action) && <Link className="audit-link" to={`/beam/shares/${encodeURIComponent(selected.target_id)}`}>Share history and health</Link>}</div>
      {selected.action.startsWith("beam.") && <p className="audit-copy">Local Sharing evidence excludes app bodies, cookies, credential material and request URLs with query strings.</p>}
      <details className="audit-evidence"><summary id="audit-details-title">Recorded details &amp; IDs</summary><ResourceSummary title="Recorded identifiers" headingLevel={3}><dl className="audit-record-ids tnx-resource-facts tnx-resource-facts-three"><AuditFact label="Event ID">{selected.id}</AuditFact><AuditFact label="Actor ID">{selected.actor_id || "Not recorded"}</AuditFact><AuditFact label="System actor">{selected.actor_system || "Not recorded"}</AuditFact><AuditFact label="Target type">{selected.target_type || "Not recorded"}</AuditFact><AuditFact label="Target ID">{selected.target_id || "Not recorded"}</AuditFact><AuditFact label="Recorded timestamp">{selected.created_at}</AuditFact></dl></ResourceSummary>{details.length === 0 ? <p className="audit-copy">No additional details were recorded for this change.</p> : <dl className="audit-record-details tnx-resource-facts tnx-resource-facts-single">{details.map(([key, value]) => <AuditFact key={key} label={key}><span className="audit-detail-value">{detailValue(value)}</span></AuditFact>)}</dl>}</details>
    </section> : <>
      <form onSubmit={applyFilters} className="audit-filters">
        <div className="audit-filter-main"><label><span>Actor</span><Select aria-label="Actor" value={filters.actor} disabled={memberScoped !== false} onChange={(event) => setFilters((current) => ({ ...current, actor: event.target.value }))}><option value="">{memberScoped === true ? "Your activity" : memberScoped === false ? "Anyone" : "Recorded actors"}</option>{memberScoped === false && members.map((member) => <option key={member.user_id} value={member.user_id}>{member.name || member.email}</option>)}</Select></label><label><span>Action</span><Input aria-label="Action" list="audit-action-options" value={filters.action} placeholder="All actions or an action key" onChange={(event) => setFilters((current) => ({ ...current, action: event.target.value }))} /></label><div className="audit-filter-actions"><Button type="submit" disabled={busy || !org || !actorId}>Apply</Button>{(Object.values(filters).some(Boolean) || activeFilterCount > 0) && <Button type="button" variant="ghost" disabled={busy || !org} onClick={clearFilters}>Clear</Button>}<Button type="button" variant="ghost" disabled={busy || !org || !actorId} onClick={() => start(applied)}>Refresh</Button></div></div>
        <details className="audit-filter-extra" open={moreFilters} onToggle={(event) => setMoreFilters(event.currentTarget.open)}><summary>More filters{activeFilterCount > 0 && <span className="audit-filter-count">{activeFilterCount} applied</span>}</summary><div className="audit-filter-grid"><label><span>Target type</span><Input aria-label="Target type" list="audit-target-options" value={filters.targetType} onChange={(event) => setFilters((current) => ({ ...current, targetType: event.target.value }))} /></label><label><span>Target UUID</span><Input aria-label="Target UUID" value={filters.targetId} onChange={(event) => setFilters((current) => ({ ...current, targetId: event.target.value }))} placeholder="Exact target identity" /></label><label><span>From</span><Input aria-label="From" type="date" value={filters.from} onChange={(event) => setFilters((current) => ({ ...current, from: event.target.value }))} /></label><label><span>To</span><Input aria-label="To" type="date" value={filters.to} onChange={(event) => setFilters((current) => ({ ...current, to: event.target.value }))} /></label></div><div className="audit-filter-quick"><Button type="button" variant="ghost" disabled={busy || !org || !actorId} onClick={() => { const next = { ...NO_FILTERS, targetType: "beam_share" }; setFilters(next); start(next); }}>Local Sharing activity</Button></div></details>
        <datalist id="audit-target-options"><option value="beam_share">Local shares</option></datalist><datalist id="audit-action-options">{Array.from(new Set([...entries.map((entry) => entry.action), "beam.share.created", "beam.share.pause", "beam.share.resume", "beam.share.stop", "beam.share.extend", "beam.grants.updated", "beam.policy.updated", "beam.connector.issued", "beam.access.allowed", "beam.access.denied"])).sort().map((action) => <option key={action} value={action}>{actionLabel(action)}</option>)}</datalist>
      </form>
      {scopeNotice && <p className="audit-copy">{scopeNotice}</p>}
      {rosterError && <LoadRetry error={`Actor names are unavailable: ${rosterError}`} onRetry={() => void loadRoster()} />}
      <ErrorText>{validationError}</ErrorText>
      {orgLoading ? <Loading label="Loading your organization…" /> : !org ? <p role="alert" className="audit-copy">{orgFailed ? "Could not load your organizations." : "You are not a member of any organization yet."}</p> : !actorId ? <p role="alert" className="audit-copy">Sign in to view audit events.</p> : readError ? <LoadRetry error={readError} onRetry={() => retry.current && void fetchPage(retry.current, retry.current.page === 0)} /> : busy ? <Loading label="Loading audit events…" /> : current ? <>
        {gapCount > 0 && <p className="audit-attribution-note">{gapCount} of {entries.length} events on this page have no recorded actor. {UNATTRIBUTED_NOTE}</p>}
        <DataTable variant="flat" caption="Audit events" rows={entries} rowKey={(entry) => entry.id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={page > 0 ? "No events on this page" : activeFilterCount ? "No audit events match these filters." : "No audit events yet."} description={page > 0 ? "Older events may have expired. Use Previous to review earlier pages, or Refresh to restart from the newest event." : activeFilterCount ? "Clear or adjust the applied filters to review other events." : "Recorded activity will appear here."} action={activeFilterCount ? <Button variant="ghost" onClick={clearFilters}>Clear filters</Button> : undefined} />} columns={[
          { key: "action", header: "Change", cell: (entry) => <button className="audit-open" aria-label={`Inspect ${entry.action} audit event`} onClick={() => setSelected(entry)}><span>{actionLabel(entry.action)}</span><small>{entry.action}</small></button> },
          { key: "actor", header: "Actor", cell: (entry) => <ActorLabel entry={entry} members={members} rosterKnown={rosterKnown} /> },
          { key: "target", header: "Target", cell: (entry) => <span className="audit-copy" title={entry.target_id}>{targetLabel(entry)}</span> },
          { key: "when", header: "When", cell: (entry) => <span className="audit-copy" title={entry.created_at}>{relativeAge(entry.created_at)}</span> },
        ]} />
      </> : !validationError ? <Loading label="Loading audit events…" /> : null}
      {(current || readError) && <AppAccessPagination maxOffset={null} page={page + 1} pageSize={pageSize} count={busy || readError ? 0 : entries.length} hasNext={!readError && !!current?.hasNext} busy={busy} firstItem={firstItem} previousLabel="Previous audit events" nextLabel="Next audit events" onPageChange={move} onPageSizeChange={(size) => { setPageSize(size); start(applied, size); }} />}
    </>}
    {org && replay && <TerminalReplay orgId={org.id} sessionId={replay} onClose={() => setReplay(undefined)} />}
  </div>;
}

function ActorLabel({ entry, members, rosterKnown }: { entry: AuditLogEntry; members: Member[]; rosterKnown: boolean }) {
  const actor = resolveActor(entry, members, rosterKnown);
  return <span data-testid="audit-actor" data-actor-kind={actor.kind} className={`audit-actor${actor.gap ? " audit-actor-gap" : actor.kind === "system" || actor.kind === "cp_admin" ? " audit-actor-named" : ""}`}>{actor.label}</span>;
}
function AuditFact({ label, children }: { label: string; children: React.ReactNode }) { return <div><dt>{label}</dt><dd>{children}</dd></div>; }
