import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, loadOne } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { relativeAge } from "../lib/format";
import { Button, ErrorText, Loading, RefreshButton } from "../components/ui";
import AccessEventSources from "../components/AccessEventSources";
import AppAccessPagination from "../components/AppAccessPagination";
import { ResourceSummary } from "../components/ResourceSummary";
import "../app-access-workspace.css";
import "../access-events-workspace.css";

type Feed = components["schemas"]["AppAccessEvents"];
type Event = components["schemas"]["AppAccessEvent"];
type Cursor = components["schemas"]["AppAccessEventCursor"];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const eventKinds = new Set<string>(["launch_created","session_created","session_revoked","request_allowed","request_denied","stream_renewed","stream_denied","stream_terminated","publication_changed","recovery","gap"] satisfies Event["kind"][]);
const eventOutcomes = new Set<string>(["allowed","denied","completed","revoked","failed"] satisfies Event["outcome"][]);
const eventReasons = new Set<string>(["none","session_invalid","parent_unavailable","user_inactive","membership_unavailable","no_use_permission","no_active_grant","feature_disabled","feature_unavailable","publication_unavailable","installation_changed","session_revoked","lease_expired","connection_closed","self","admin","recovery","infrastructure_unavailable","dropped_events"] satisfies Event["reason"][]);
const isRecord = (value: unknown): value is Record<string,unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const isUuid = (value: unknown): value is string => typeof value === "string" && uuid.test(value);
const isDateTime = (value: unknown): value is string => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(value) && Number.isFinite(Date.parse(value));
const isCounter = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
function isEvent(value: unknown): value is Event {
  if (!isRecord(value)) return false;
  return isUuid(value.id) && isUuid(value.app_id) && isUuid(value.installation_generation) && isDateTime(value.created_at)
    && typeof value.kind === "string" && eventKinds.has(value.kind)
    && typeof value.outcome === "string" && eventOutcomes.has(value.outcome)
    && typeof value.reason === "string" && eventReasons.has(value.reason)
    && ["serving_generation","user_id","gateway_id","proxy_id","session_id","stream_id"].every(key => value[key] === undefined || isUuid(value[key]))
    && (value.revision === undefined || (isCounter(value.revision) && value.revision > 0));
}
function isCursor(value: unknown): value is Cursor {
  return isRecord(value) && isUuid(value.before_id) && isDateTime(value.before_time);
}
function isFeed(value: unknown, limit: number): value is Feed {
  if (!isRecord(value) || !Array.isArray(value.items) || value.items.length > limit || !value.items.every(isEvent)) return false;
  if (new Set(value.items.map(event => event.id.toLowerCase())).size !== value.items.length) return false;
  if (value.next_cursor !== undefined && !isCursor(value.next_cursor)) return false;
  return isRecord(value.telemetry) && typeof value.telemetry.available === "boolean"
    && [value.telemetry.emitted,value.telemetry.dropped,value.telemetry.storage_failures].every(isCounter);
}
const cursorKey = (cursor: Cursor) => `${cursor.before_id.toLowerCase()}:${Date.parse(cursor.before_time)}`;
const label = (value: string) => value.replace(/_/g," ");
const appLabel = (id: string) => `${id.slice(0,4)}…${id.slice(-8)}`;

export default function AppAccessEvents() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [params] = useSearchParams();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <ApplicationEventsWorkspace key={`${org?.id ?? "none"}:${actor}:${params.get("app_id") ?? ""}:${params.get("user_id") ?? ""}:${params.get("session_id") ?? ""}`} />;
}
function ApplicationEventsWorkspace() {
  const { org,loading,failed } = useOrg();
  const [params,setParams] = useSearchParams();
  const appId=params.get("app_id") ?? "", userId=params.get("user_id") ?? "", sessionId=params.get("session_id") ?? "";
  const valid=[appId,userId,sessionId].every(value => !value || uuid.test(value));
  const [filters,setFilters]=useState({ app:appId,user:userId,session:sessionId });
  const [feed,setFeed]=useState<Feed | null>(null);
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [page,setPage]=useState(1),[size,setSize]=useState(20),[refresh,setRefresh]=useState(0);
  const [selected,setSelected]=useState<Event | null>(null),[stage,setStage]=useState<"overview" | "evidence">("overview");
  const cache=useRef<Feed[]>([]), epoch=useRef(0);
  const pending=useRef<{ index:number;cursor?:Cursor }>({index:0});
  const heading=useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (selected) heading.current?.focus(); },[selected?.id,stage]);
  async function load(index=0,cursor?:Cursor) {
    if (!org || !valid) return;
    const generation=++epoch.current; pending.current={index,cursor}; setBusy(true); setError(""); setSelected(null);
    const result=await loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/events", { params: { path: { orgId:org.id }, query: { limit:size,...(appId ? {app_id:appId} : {}),...(userId ? {user_id:userId} : {}),...(sessionId ? {session_id:sessionId} : {}),...cursor } } }));
    if (generation !== epoch.current) return;
    setBusy(false);
    if (!result.ok) { setError(result.error === "Could not load." ? "Could not read application events. Your event permission is checked independently of application access." : result.error); return; }
    const data=result.data;
    if (!isFeed(data,size)) { setError("The server returned incomplete application-event evidence. Refresh to try again."); return; }
    const earlierPages=cache.current.slice(0,index);
    if (cursor && data.next_cursor && cursorKey(data.next_cursor) === cursorKey(cursor)) { setError("Event history did not advance. Refresh before continuing."); return; }
    if (data.next_cursor && earlierPages.some(item => item.next_cursor && cursorKey(item.next_cursor) === cursorKey(data.next_cursor!))) { setError("Event history repeated an earlier cursor. Refresh before continuing."); return; }
    const earlierIds=new Set(earlierPages.flatMap(item => item.items.map(event => event.id.toLowerCase())));
    if (data.items.some(event => earlierIds.has(event.id.toLowerCase()))) { setError("Event history overlapped earlier events. Refresh before continuing."); return; }
    cache.current=[...earlierPages,data]; setFeed(data); setPage(index+1);
  }
  useEffect(() => {
    epoch.current++; cache.current=[]; setFeed(null); setError(""); setPage(1); setSelected(null);
    if (org && valid) void load();
    return () => { epoch.current++; };
  },[org?.id,appId,userId,sessionId,valid,refresh,size]);
  function changePage(next:number) {
    if (busy || next<1 || (next>page && !feed?.next_cursor)) return;
    setSelected(null); setError("");
    const cached=cache.current[next-1];
    if (cached) { epoch.current++; setFeed(cached); setPage(next); return; }
    const cursor=cache.current[next-2]?.next_cursor;
    if (cursor) void load(next-1,cursor);
  }
  function apply(event:FormEvent) {
    event.preventDefault();
    const values={ app:filters.app.trim(),user:filters.user.trim(),session:filters.session.trim() };
    if (!Object.values(values).every(value => !value || uuid.test(value))) { setError("Use a valid UUID for each application, user or session filter."); return; }
    epoch.current++; cache.current=[]; setFeed(null); setPage(1); setSelected(null);
    setParams({ source:"applications",...(values.app ? {app_id:values.app} : {}),...(values.user ? {user_id:values.user} : {}),...(values.session ? {session_id:values.session} : {}) });
    setRefresh(value => value+1);
  }
  const active=!!appId || !!userId || !!sessionId;
  const rail=<AccessEventSources source="applications" actions={<RefreshButton label="Refresh" disabled={busy || !org || !valid} onClick={() => { epoch.current++; setFeed(null); setRefresh(value => value+1); }} />} />;
  if (loading) return <Loading label="Loading application events…" />;
  if (failed || !org) return <section className="application-events-workspace">{rail}<ErrorText>Could not load your organization.</ErrorText></section>;
  return <section className="application-events-workspace">{rail}
    <div hidden={!!selected}>
      <div className="event-application-toolbar"><span>{active ? "Filtered history" : "All application activity"}</span><span className="event-muted">{feed ? `${feed.items.length} records · newest first` : ""}</span></div>
      <details className="event-disclosure event-filter-disclosure" open={!valid || undefined}><summary>Filters{active && <span>{[appId,userId,sessionId].filter(Boolean).length} applied</span>}</summary><form className="event-filters-form" onSubmit={apply}>
        <label>Application ID<input aria-label="Application ID" value={filters.app} maxLength={36} onChange={event => setFilters(value => ({...value,app:event.target.value}))} placeholder="All applications" /></label>
        <label>User ID<input aria-label="User ID" value={filters.user} maxLength={36} onChange={event => setFilters(value => ({...value,user:event.target.value}))} placeholder="All users" /></label>
        <label>Session ID<input aria-label="Session ID" value={filters.session} maxLength={36} onChange={event => setFilters(value => ({...value,session:event.target.value}))} placeholder="All sessions" /></label>
        <div className="event-filter-actions"><Button type="submit" variant="ghost" disabled={busy}>Apply application filters</Button>{active && <Button variant="ghost" disabled={busy} onClick={() => { epoch.current++; setFeed(null); setParams({source:"applications"}); }}>Clear filters</Button>}</div>
      </form></details>
      {!valid && <ErrorText>This event link has an invalid filter. Correct the IDs before loading history.</ErrorText>}
      {error && <div><ErrorText>{error}</ErrorText><Button variant="ghost" disabled={!valid || busy} onClick={() => void load(pending.current.index,pending.current.cursor)}>Retry application events</Button></div>}
      {!feed && busy ? <Loading label="Loading application events…" /> : feed && <>
        <table className="event-table" aria-label="Application access event history" aria-busy={busy}><caption className="sr-only">Application access event history</caption><colgroup><col style={{width:"19%"}} /><col style={{width:"20%"}} /><col style={{width:"27%"}} /><col style={{width:"21%"}} /><col style={{width:"13%"}} /></colgroup><thead><tr><th>Outcome</th><th>Application</th><th>Event</th><th>Reason</th><th>Recorded</th></tr></thead><tbody>{feed.items.map(event => <tr key={event.id}>
          <td><button type="button" className={`event-outcome is-${["denied","failed"].includes(event.outcome) ? "bad" : event.outcome === "allowed" ? "ok" : "neutral"}`} aria-label={`View ${label(event.kind)} event`} onClick={() => { setSelected(event); setStage("overview"); }}>{label(event.outcome)}</button></td>
          <td><Link className="event-flow" title={event.app_id} to={`/app-access/applications/${event.app_id}`}>{appLabel(event.app_id)}</Link></td>
          <td>{label(event.kind)}</td><td className="event-muted">{label(event.reason)}</td><td><time dateTime={event.created_at} title={new Date(event.created_at).toLocaleString()}>{relativeAge(event.created_at)}</time></td>
        </tr>)}{!feed.items.length && <tr><td colSpan={5}><div className="event-empty"><h2>{page > 1 ? "No events on this page" : active ? "No matching events" : "No events recorded"}</h2><p>{page > 1 ? "Older records may have expired. Go back or refresh to read the latest activity." : "No application events match this view."}</p></div></td></tr>}</tbody></table>
        <AppAccessPagination page={page} pageSize={size} count={feed.items.length} hasNext={!!feed.next_cursor} busy={busy} maxOffset={null} firstItem={cache.current.slice(0,page-1).reduce((n,item) => n+item.items.length,1)} onPageChange={changePage} onPageSizeChange={value => { epoch.current++; setFeed(null); setSize(value); }} />
        <details className="event-disclosure"><summary><span>Telemetry health</span><span className={feed.telemetry.available && (feed.telemetry.dropped || feed.telemetry.storage_failures) ? "event-health-attention" : undefined}>{feed.telemetry.available ? feed.telemetry.dropped || feed.telemetry.storage_failures ? "Needs attention" : "Counters available" : "Counters unavailable"}</span></summary><p>{feed.telemetry.available ? `Telemetry for this organization since this service started: ${feed.telemetry.emitted} recorded · ${feed.telemetry.dropped} dropped · ${feed.telemetry.storage_failures} storage failures.` : "Current telemetry counters are unavailable. Stored event history remains available; zero loss has not been confirmed."}</p><p>Application decision records remain available under the event permission when Applications or VPN Zero Trust is off. Decision telemetry can lose records; mutation audits are recorded separately.</p></details>
      </>}
    </div>
    {selected && <section className="event-detail"><nav className="event-breadcrumb" aria-label="Application event breadcrumb"><button onClick={() => setSelected(null)}>Application events</button><span aria-hidden="true">/</span><span>Event {selected.id.slice(-8)}</span></nav><div className="event-detail-heading"><div><h1>{label(selected.kind)}</h1><p>{label(selected.outcome)} · {label(selected.reason)}</p></div><time>{new Date(selected.created_at).toLocaleString()}</time></div><div className="event-detail-layout"><nav className="event-detail-path" aria-label="Application event detail sections">{(["overview","evidence"] as const).map(value => <button key={value} aria-current={stage === value ? "step" : undefined} onClick={() => setStage(value)}>{value === "overview" ? "Overview" : "Evidence"}</button>)}</nav><div className="event-detail-stage"><ResourceSummary title={stage === "overview" ? "Overview" : "Technical evidence"} headingLevel={2} headingRef={heading} footer={<Button variant="ghost" onClick={() => setSelected(null)}>Back to events</Button>}><dl className="event-facts tnx-resource-facts">
      {stage === "overview" ? <><Fact wide label="Application" value={<Link to={`/app-access/applications/${selected.app_id}`}>{selected.app_id}</Link>} /><Fact label="Event" value={label(selected.kind)} /><Fact label="Outcome" value={label(selected.outcome)} /><Fact label="Reason" value={label(selected.reason)} /><Fact label="Recorded" value={new Date(selected.created_at).toLocaleString()} /></> : <><Fact label="Event ID" value={selected.id} /><Fact label="Recorded user" value={selected.user_id || "Not recorded"} /><Fact label="Session" value={selected.session_id || "Not recorded"} /><Fact label="Gateway" value={selected.gateway_id || "Not recorded"} /><Fact label="Proxy" value={selected.proxy_id || "Not recorded"} /><Fact label="Stream" value={selected.stream_id || "Not recorded"} /><Fact label="Revision" value={selected.revision ?? "Not recorded"} /><Fact label="Installation" value={selected.installation_generation} /><Fact label="Serving generation" value={selected.serving_generation || "Not recorded"} /></>}
      </dl></ResourceSummary></div></div></section>}
  </section>;
}
function Fact({label,value,wide}:{label:string;value:React.ReactNode;wide?:boolean}) { return <div className={wide ? "tnx-resource-fact-wide" : undefined}><dt>{label}</dt><dd>{value}</dd></div>; }
