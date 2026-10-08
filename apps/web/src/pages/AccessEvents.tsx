import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { BeamAccessEvidence } from "../components/BeamAccessEvidence";
import AccessEventSources from "../components/AccessEventSources";
import AppAccessPagination from "../components/AppAccessPagination";
import { Button, EmptyState, Loading } from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { api, loadOne, type Device, type Loaded, type Member, type Org } from "../lib/api";
import { relativeAge } from "../lib/format";
import { ATTRIBUTION_NOTE, accessIdentityOptions, accessIdentityQuery, parseAccessIdentityValue, accessIdentityValue, causeFor, collectorStateLabel, collectorStateTone, decisionLabel, decisionTone, destinationFor, emptyAccessEventsNote, eventTimeline, nextCursor, retentionNote, sourceFor, type AccessIdentityLabels, type AccessIdentityKind, type AccessEvent, type AccessLogHealth } from "../lib/flowlogview";
import type { AgentRow } from "../lib/agentview";
import "../app-access-workspace.css";
import "../access-events-workspace.css";

const IDENTITY_PAGE = 100;
const UUID_PATTERN = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
type EventPage = { rows: AccessEvent[]; next: ReturnType<typeof nextCursor> };
const outcomeTitle = (decision: AccessEvent["decision"]) => ({ allow:"Allowed", deny:"Denied", deny_aggregate:"Aggregated denies", terminated:"Terminated", gap:"Integrity gap" })[decision];
const eventReason = (event: AccessEvent) => { const reason = causeFor(event,() => null); return reason === "n/a" ? event.decision_reason?.replace(/_/g," ") || "Reason not recorded" : reason; };
type AgentPage = { items?: AgentRow[]; next_cursor?: string | null };

function currentMemberLabel(member: Member): string {
  const name = typeof member.name === "string" ? member.name.trim() : "";
  return name && name !== member.email ? `${name} · ${member.email}` : member.email;
}

async function loadAllAgents(
  orgId: string,
  stale: () => boolean,
): Promise<Loaded<AgentRow[]>> {
  const agents: AgentRow[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  do {
    const result = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/agents", {
        params: {
          path: { orgId },
          query: { limit: IDENTITY_PAGE, cursor },
        },
      }),
    );
    if (!result.ok) return { ok: false, error: result.error };
    if (stale()) return { ok: false, error: "Identity request superseded." };
    const page = result.data as AgentRow[] | AgentPage;
    if (Array.isArray(page)) {
      agents.push(...page);
      return { ok: true, data: agents };
    }
    if (!page || !Array.isArray(page.items)) return { ok: false, error: "Could not load current AI-agent labels." };
    agents.push(...page.items);
    const next = page.next_cursor ?? undefined;
    if (!next) return { ok: true, data: agents };
    if (cursors.has(next)) {
      return { ok: false, error: "Could not load current AI-agent labels." };
    }
    cursors.add(next);
    cursor = next;
  } while (!stale());
  return { ok: false, error: "Identity request superseded." };
}


export default function AccessEvents() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [params] = useSearchParams();
  const source = params.get("source") === "beam" ? "beam" : "network";
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <AccessEventsWorkspace key={`${org?.id ?? "none"}:${actor}:${source}`} source={source} />;
}

function AccessEventsWorkspace({ source }: { source: "network" | "beam" }) {
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const [rows, setRows] = useState<AccessEvent[]>([]);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [hasNext, setHasNext] = useState(false);
  const [reloadRevision, setReloadRevision] = useState(0);
  const [health, setHealth] = useState<AccessLogHealth | null>(null);
  const [healthBusy, setHealthBusy] = useState(false);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [identitiesBusy, setIdentitiesBusy] = useState(false);
  const [identitiesError, setIdentitiesError] = useState<string | null>(null);
  const [deniesOnly, setDeniesOnly] = useState(false);
  const [identityValue, setIdentityValue] = useState("");
  const [associatedDevice, setAssociatedDevice] = useState("");
  const [historicalIdentityKind, setHistoricalIdentityKind] = useState<AccessIdentityKind>("person");
  const [historicalIdentityID, setHistoricalIdentityID] = useState("");
  const [beamShareID, setBeamShareID] = useState("");
  const [beamShareDraft, setBeamShareDraft] = useState("");
  const [selected, setSelected] = useState<AccessEvent | null>(null);
  const [stage, setStage] = useState<"overview" | "evidence">("overview");
  const cache = useRef<EventPage[]>([]);
  const pending = useRef<{ index: number; cursor: ReturnType<typeof nextCursor> }>({ index: 0, cursor: null });
  const queryEpoch = useRef(0), healthEpoch = useRef(0), identityEpoch = useRef(0);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => () => { queryEpoch.current++; healthEpoch.current++; identityEpoch.current++; }, []);
  useEffect(() => { if (selected) heading.current?.focus(); }, [selected?.id, stage]);

  const resetPage = useCallback(() => {
    queryEpoch.current++; cache.current = []; setRows([]); setReady(false); setBusy(true);
    pending.current = { index: 0, cursor: null };
    setPage(1); setHasNext(false); setSelected(null); setError(null);
  }, []);
  const prepareFilterReload = useCallback(() => {
    resetPage(); setReloadRevision(revision => revision + 1);
  }, [resetPage]);
  const loadIdentities = useCallback(async (target: Org) => {
    const epoch = ++identityEpoch.current;
    setIdentitiesBusy(true); setIdentitiesError(null);
    const stale = () => epoch !== identityEpoch.current;
    const [people, fleet, ai] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: target.id } } })),
      source === "network" ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/devices", { params: { path: { orgId: target.id } } })) : Promise.resolve({ ok: true as const, data: [] as Device[] }),
      source === "network" ? loadAllAgents(target.id, stale) : Promise.resolve({ ok: true as const, data: [] as AgentRow[] }),
    ]);
    if (stale()) return;
    setIdentitiesBusy(false);
    setMembers(people.ok && Array.isArray(people.data) ? people.data : []);
    setDevices(fleet.ok && Array.isArray(fleet.data) ? fleet.data : []);
    setAgents(ai.ok && Array.isArray(ai.data) ? ai.data : []);
    const failed = [(!people.ok || !Array.isArray(people.data)) && "people", (!fleet.ok || !Array.isArray(fleet.data)) && "device", (!ai.ok || !Array.isArray(ai.data)) && "AI-agent"].filter(Boolean);
    if (failed.length) setIdentitiesError(`Could not load current ${failed.join(", ")} labels. Recorded event identities remain available.`);
  }, [source]);
  const loadHealth = useCallback(async (target: Org) => {
    const epoch = ++healthEpoch.current; setHealthBusy(true); setHealthError(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/access-log/health", { params: { path: { orgId: target.id } } }));
    if (epoch !== healthEpoch.current) return;
    setHealthBusy(false);
    if (!result.ok) { setHealth(null); setHealthError(result.error); return; }
    const data = result.data;
    const optionalTimestamp = (value: unknown) => value == null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
    const valid = data && typeof data === "object" && !Array.isArray(data)
      && typeof data.retention_failed === "boolean"
      && Number.isInteger(data.retention_dropped) && data.retention_dropped >= 0
      && optionalTimestamp(data.retention_last_sweep)
      && (data.gateway_collectors == null || (Array.isArray(data.gateway_collectors) && data.gateway_collectors.every(collector =>
        collector && typeof collector === "object" && !Array.isArray(collector)
        && typeof collector.node_id === "string" && !!collector.node_id
        && typeof collector.name === "string"
        && ["active", "disabled", "source_error", "delivery_error", "stale", "unknown"].includes(collector.state)
        && [collector.last_reported_at, collector.last_observed_at, collector.last_delivered_at, collector.last_event_at].every(optionalTimestamp)
      )));
    if (!valid) { setHealth(null); setHealthError("Could not load collector status."); return; }
    setHealth(data as AccessLogHealth);
  }, []);
  useEffect(() => {
    if (!org) return;
    void loadIdentities(org); if (source === "network") void loadHealth(org);
    return () => { identityEpoch.current++; healthEpoch.current++; };
  }, [org?.id, loadIdentities, loadHealth, source]);

  const loadPage = useCallback(async (index: number, cursor: ReturnType<typeof nextCursor>) => {
    if (!org) return;
    const epoch = ++queryEpoch.current;
    pending.current = { index, cursor }; setBusy(true); setError(null); setSelected(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/access-events", { params: { path: { orgId: org.id }, query: {
      limit: pageSize + 1, denies_only: deniesOnly || undefined,
      ...(source === "beam" ? { source, share_id: beamShareID || undefined } : {}),
      ...accessIdentityQuery(associatedDevice ? accessIdentityValue("device", associatedDevice) : identityValue), ...(cursor ?? {}),
    } } }));
    if (epoch !== queryEpoch.current) return;
    setBusy(false);
    if (!result.ok || !Array.isArray(result.data)) { setError(result.ok ? "The server did not return access events." : result.error === "Could not load." ? "Could not load access events." : result.error); return; }
    const fetched = result.data as AccessEvent[];
    if (fetched.some(event => !event || typeof event.id !== "string" || !event.id || !["allow","deny","deny_aggregate","terminated","gap"].includes(event.decision) || !Number.isFinite(Date.parse(event.created_at)) || !Number.isFinite(Date.parse(event.occurred_at))) || new Set(fetched.map(event => event.id)).size !== fetched.length) { setError("The server returned incomplete access-event evidence. Refresh to try again."); return; }
    if (cursor && fetched.some(event => cache.current.slice(0,index).some(item => item.rows.some(previous => previous.id === event.id)))) { setError("Event history did not advance. Refresh before continuing."); return; }
    const items = fetched.slice(0, pageSize);
    const next = fetched.length > pageSize ? nextCursor(items) : null;
    cache.current = [...cache.current.slice(0,index), { rows: items, next }];
    setRows(items); setPage(index + 1); setHasNext(!!next); setReady(true);
  }, [org?.id, pageSize, deniesOnly, source, beamShareID, associatedDevice, identityValue]);
  useEffect(() => { resetPage(); if (org) void loadPage(0,null); }, [loadPage, resetPage, reloadRevision]);
  function changePage(next: number) {
    if (busy || next < 1 || (next > page && !hasNext)) return;
    const cached = cache.current[next - 1]; setSelected(null); setError(null);
    if (cached) { queryEpoch.current++; setRows(cached.rows); setHasNext(!!cached.next); setPage(next); return; }
    const cursor = cache.current[next - 2]?.next;
    if (cursor) void loadPage(next - 1,cursor);
  }
  function refresh() { prepareFilterReload(); if (org) { void loadIdentities(org); if (source === "network") void loadHealth(org); } }
  const humanDevices = devices.filter(device => device.kind !== "agent");
  const memberLabels = new Map(members.map(member => [member.user_id,currentMemberLabel(member)]));
  const deviceLabels = new Map(humanDevices.map(device => [device.id,device.name]));
  const agentLabels = new Map(agents.map(agent => [agent.device_id,agent.name]));
  const labelsFor = (event: AccessEvent): AccessIdentityLabels => ({
    person: event.src_user_id ? memberLabels.get(event.src_user_id) : undefined,
    device: event.src_device_id ? deviceLabels.get(event.src_device_id) : undefined,
    agent: agentLabels.get(event.src_agent_id ?? (event.src_kind === "agent" ? event.src_device_id ?? "" : "")),
  });
  const identities = accessIdentityOptions(cache.current.flatMap(item => item.rows), {
    people: members.map(member => ({ id: member.user_id,label: currentMemberLabel(member) })),
    devices: humanDevices.map(device => ({ id: device.id,label: device.name })),
    agents: agents.map(agent => ({ id: agent.device_id,label: agent.name })),
  },identityValue);
  const chosenIdentity = parseAccessIdentityValue(identityValue);
  const associatedDevices = chosenIdentity?.kind === "person" ? humanDevices.filter(device => device.user_id === chosenIdentity.id) : [];
  const historicalUUID = historicalIdentityID.trim().toLowerCase();
  const historicalUUIDValid = UUID_PATTERN.test(historicalUUID);
  const historicalUUIDInvalid = historicalIdentityID.length > 0 && !historicalUUIDValid;
  const hasFilters = deniesOnly || !!identityValue || !!beamShareID;
  const rn = health ? retentionNote(health) : null;
  const outcomeClass = (event: AccessEvent) => { const tone = decisionTone(event.decision); return `event-outcome is-${tone}`; };
  const openEvent = (event: AccessEvent) => { setStage("overview"); setSelected(event); };
  const rail = <AccessEventSources source={source} actions={<Button variant="ghost" disabled={busy || !org} onClick={refresh}>Refresh</Button>} />;
  if (orgLoading) return <Loading size="page" label="Loading access events…" />;
  if (orgFailed || !org) return <section className="access-events-workspace">{rail}{orgFailed ? <LoadRetry error="Could not load your organizations." onRetry={() => window.location.reload()} /> : <EmptyState>You are not a member of any organization yet.</EmptyState>}</section>;

  return <section className="access-events-workspace">{rail}
    <div hidden={!!selected}>
      <div className="event-filter-row">
        <div className="event-scope" aria-label="Event scope">{[[false,"All activity"],[true,"Denies only"]].map(([value,label]) => <button key={String(value)} type="button" aria-pressed={deniesOnly === value} onClick={() => { if (deniesOnly === value) return; prepareFilterReload(); setDeniesOnly(value as boolean); }}>{label}</button>)}</div>
        <select aria-label="Source identity" value={identityValue} onChange={event => { prepareFilterReload(); setIdentityValue(event.target.value); setAssociatedDevice(""); }}><option value="">All sources</option>{([ ["People",identities.people], ["Devices", source === "network" ? identities.devices : []], ["AI agents",source === "network" ? identities.agents : []] ] as const).map(([label,items]) => !!items.length && <optgroup key={label} label={label}>{items.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</optgroup>)}</select>
        {identitiesBusy && <span role="status" className="event-muted">Loading current labels…</span>}
        <span className="event-page-meta">{ready ? `${rows.length} records · newest first` : ""}</span>
      </div>
      {source === "network" && chosenIdentity?.kind === "person" && <div className="event-associated"><label>Associated device<select aria-label="Associated device" value={associatedDevice} onChange={event => { prepareFilterReload(); setAssociatedDevice(event.target.value); }}><option value="">All activity recorded for this person</option>{associatedDevices.map(device => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label><span>{associatedDevice ? "Showing this device’s history across recorded owners." : associatedDevices.length ? `${associatedDevices.length} devices currently assigned to this person` : "No currently assigned devices found."}</span></div>}
      <details className="event-disclosure event-filter-disclosure"><summary>More filters{hasFilters && <span>Filters applied</span>}</summary><div className="event-filter-options">
        <form aria-label="Filter by historical identity UUID" onSubmit={event => { event.preventDefault(); if (!historicalUUIDValid) return; prepareFilterReload(); setIdentityValue(accessIdentityValue(historicalIdentityKind,historicalUUID)); setAssociatedDevice(""); }}>
          <label>Identity type<select aria-label="Historical identity type" value={historicalIdentityKind} onChange={event => setHistoricalIdentityKind(event.target.value as AccessIdentityKind)}><option value="person">Person</option>{source === "network" && <><option value="device">Device</option><option value="agent">AI agent</option></>}</select></label>
          <label>Historical UUID<input aria-label="Historical identity UUID" aria-invalid={historicalUUIDInvalid || undefined} aria-describedby={historicalUUIDInvalid ? "historical-identity-uuid-error" : undefined} value={historicalIdentityID} onChange={event => setHistoricalIdentityID(event.target.value)} placeholder="Exact identity UUID" spellCheck={false} autoComplete="off" /></label><Button variant="ghost" type="submit" disabled={!historicalUUIDValid}>Apply UUID</Button>
          {historicalUUIDInvalid && <p id="historical-identity-uuid-error" role="alert">Enter a complete UUID in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format.</p>}
        </form>
        {source === "beam" && <form onSubmit={event => { event.preventDefault(); const id=beamShareDraft.trim(); if (id && !UUID_PATTERN.test(id)) return; prepareFilterReload(); setBeamShareID(id); }}><label>Share ID<input aria-label="Share ID" value={beamShareDraft} onChange={event => setBeamShareDraft(event.target.value)} maxLength={36} placeholder="Exact share UUID" pattern="[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}" /></label><Button variant="ghost" type="submit">Filter share</Button>{beamShareID && <Button variant="ghost" onClick={() => { prepareFilterReload(); setBeamShareDraft(""); setBeamShareID(""); }}>Clear share</Button>}</form>}
        {hasFilters && <Button variant="ghost" onClick={() => { prepareFilterReload(); setDeniesOnly(false); setIdentityValue(""); setAssociatedDevice(""); setHistoricalIdentityID(""); setBeamShareDraft(""); setBeamShareID(""); }}>Clear filters</Button>}
      </div></details>
      {identitiesError && <LoadRetry error={identitiesError} onRetry={() => void loadIdentities(org)} />}
      {error && <LoadRetry error={error} onRetry={() => void loadPage(pending.current.index,pending.current.cursor)} />}
      {busy && !ready ? <Loading label={hasFilters ? "Loading access events matching the current filters…" : "Loading access events…"} /> : ready && <>
        <table className="event-table" aria-label="Access events" aria-busy={busy}><caption className="sr-only">Access events</caption><colgroup><col style={{width:"17%"}} /><col style={{width:"40%"}} /><col style={{width:"27%"}} /><col style={{width:"16%"}} /></colgroup><thead><tr><th>Outcome</th><th>Flow</th><th>Decision evidence</th><th>Observed</th></tr></thead><tbody>
          {rows.map(event => { const labels=labelsFor(event); const label=labels.agent || labels.device || labels.person; return <tr key={event.id}>
            <td><button type="button" className={outcomeClass(event)} data-decision={event.decision} aria-label={`View ${decisionLabel(event.decision)} event details`} onClick={() => openEvent(event)}>{outcomeTitle(event.decision)}</button></td>
            <td><button type="button" className="event-flow" onClick={() => openEvent(event)}><span aria-hidden={!!label}>{label || sourceFor(event,labels)}</span>{label && <span className="sr-only">{sourceFor(event,labels)}</span>}<small>→ {destinationFor(event)}</small></button><span className="event-protocol">{event.beam ? "Shared app" : event.protocol}{event.dst_port ? ` · ${event.dst_port}` : ""}</span></td>
            <td className="event-muted">{eventReason(event)}</td><td><time dateTime={event.occurred_at} title={new Date(event.occurred_at).toLocaleString()}>{relativeAge(event.occurred_at)}</time></td>
          </tr>; })}
          {!rows.length && <tr><td colSpan={4}><div className="event-empty"><h2>{page > 1 ? "No events on this page" : hasFilters ? "No matching events" : "No events recorded"}</h2><p>{page > 1 ? "Older records may have expired. Go back or refresh to read the latest activity." : source === "beam" ? "No retained Local Sharing access events match the current filters." : hasFilters ? "No retained access events match the current filters." : emptyAccessEventsNote(health,healthError !== null)}</p>{hasFilters && <Button variant="ghost" onClick={() => { prepareFilterReload(); setDeniesOnly(false); setIdentityValue(""); setAssociatedDevice(""); setBeamShareID(""); setBeamShareDraft(""); }}>Clear filters</Button>}</div></td></tr>}
        </tbody></table>
        <AppAccessPagination page={page} pageSize={pageSize} count={rows.length} hasNext={hasNext} busy={busy} maxOffset={null} firstItem={cache.current.slice(0,page-1).reduce((n,item) => n + item.rows.length,1)} onPageChange={changePage} onPageSizeChange={size => { prepareFilterReload(); setPageSize(size); }} />
      </>}
      {source === "network" ? <details className="event-disclosure" aria-label="Gateway collector status"><summary><span>Collection health</span><span className={healthError || health?.retention_failed || health?.gateway_collectors?.some(c => ["danger","warn"].includes(collectorStateTone(c.state))) ? "event-health-attention" : undefined}>{healthError ? "Status unavailable" : health?.retention_failed ? "Retention sweep failed" : !health ? "Checking collectors…" : health?.gateway_collectors?.length ? `${health.gateway_collectors.length} collectors · ${health.gateway_collectors.filter(c => ["danger","warn"].includes(collectorStateTone(c.state))).length} need attention` : "No collector reports"}</span></summary>
        {healthError ? <LoadRetry error={healthError} onRetry={() => void loadHealth(org)} /> : healthBusy && !health ? <Loading label="Loading collector status…" /> : health && <>{rn && <p className={`event-health-note is-${rn.tone}`}>{rn.text}{health.retention_last_sweep ? ` · ${relativeAge(health.retention_last_sweep)}` : ""}</p>}<CollectorInventory health={health} /></>}
      </details> : <details className="event-disclosure"><summary>About these records</summary><p>Local Sharing access comes from durable control-plane audit records. Retention follows Audit Log policy; network flow sequence and gateway collector health do not apply.</p><p>Reviewer IDs are recorded from authenticated browser authority; names are current labels only. These records contain no gateway flow evidence.</p></details>}
    </div>
    {selected && <section className="event-detail">
      <nav className="event-breadcrumb" aria-label="Access event breadcrumb"><button type="button" onClick={() => setSelected(null)}>{source === "beam" ? "Local Sharing access" : "Network events"}</button><span aria-hidden="true">/</span><span>Event {selected.id.slice(-8)}</span></nav>
      <div className="event-detail-heading"><div><h1>{outcomeTitle(selected.decision)}</h1><p>{eventReason(selected)}</p></div><time dateTime={selected.occurred_at}>{new Date(selected.occurred_at).toLocaleString()}</time></div>
      <div className="event-detail-layout"><nav className="event-detail-path" aria-label="Access event detail sections">{(["overview","evidence"] as const).map(value => <button key={value} type="button" aria-current={stage === value ? "step" : undefined} onClick={() => setStage(value)}>{value === "overview" ? "Overview" : "Evidence"}</button>)}</nav><div className="event-detail-stage"><h2 tabIndex={-1} ref={heading}>{stage === "overview" ? "Overview" : "Technical evidence"}</h2>
        {selected.beam ? (stage === "overview" ? <BeamAccessEvidence event={selected} reviewerLabel={labelsFor(selected).person} /> : <><dl className="event-facts"><Fact label="Audit event ID" value={selected.id} /><Fact label="Recorded reviewer ID" value={selected.src_user_id || "Not recorded"} /><Fact label="Share ID" value={selected.beam.share_id} /><Fact label="Recorded" value={selected.created_at} /></dl><p className="event-detail-note">Control-plane audit evidence. Gateway flow and policy evidence do not apply.</p></>) : stage === "overview" ? <>
          <dl className="event-facts"><Fact label="Source" value={labelsFor(selected).agent || labelsFor(selected).device || labelsFor(selected).person || sourceFor(selected,labelsFor(selected))} /><Fact label="Destination" value={destinationFor(selected)} /><Fact label="Protocol" value={`${selected.protocol}${selected.dst_port ? ` · ${selected.dst_port}` : ""}`} /><Fact label="Decision reason" value={eventReason(selected)} /><Fact label="Observed" value={new Date(selected.occurred_at).toLocaleString()} /></dl>
          <p className="event-detail-note">Names reflect current records. Recorded ownership does not identify who initiated the traffic.</p>
          <div className="event-detail-actions">{selected.src_user_id && <Button variant="ghost" onClick={() => { const id=selected.src_user_id!; prepareFilterReload(); setAssociatedDevice(""); setIdentityValue(accessIdentityValue("person",id)); }}>Filter by this person</Button>}{(selected.src_agent_id || selected.src_device_id) && <Button variant="ghost" onClick={() => { const event=selected; prepareFilterReload(); setAssociatedDevice(""); setIdentityValue(accessIdentityValue(event.src_agent_id || event.src_kind === "agent" ? "agent" : "device",event.src_agent_id || event.src_device_id!)); }}>Filter by this {selected.src_agent_id || selected.src_kind === "agent" ? "agent" : "device"}</Button>}</div>
        </> : <><dl className="event-facts"><Fact label="Event ID" value={selected.id} /><Fact label="Sequence" value={selected.seq} /><Fact label="Ingested" value={selected.created_at} /><Fact label="Policy" value={selected.policy_version ? `v${selected.policy_version}` : "not recorded"} /><Fact label="Policy hash" value={selected.policy_hash ?? "not recorded"} /><Fact label="Source config" value={selected.src_config_revision ?? "not recorded"} /><Fact label="Gateway" value={selected.node_id ?? "not recorded"} /><Fact label="Rule ID" value={selected.rule_id ?? "not recorded"} /></dl><h3>Evidence trace</h3><ol className="event-trace">{eventTimeline(selected).map(item => <li key={item}>{item}</li>)}</ol><p className="event-detail-note">{ATTRIBUTION_NOTE}</p></>}
        <footer className="event-detail-footer"><Button variant="ghost" onClick={() => setSelected(null)}>Back to events</Button></footer>
      </div></div>
    </section>}
  </section>;
}
function Fact({ label,value }: { label: string; value: string | number }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }
function CollectorInventory({ health }: { health: AccessLogHealth }) {
  const [page,setPage]=useState(1), [size,setSize]=useState(20);
  const collectors=health.gateway_collectors ?? [];
  useEffect(() => setPage(1),[health]);
  return collectors.length ? <><table className="event-table event-collector-table" aria-label="Gateway collectors"><thead><tr><th>Gateway</th><th>Status</th><th>Collection evidence</th></tr></thead><tbody>{collectors.slice((page-1)*size,page*size).map(collector => <tr key={collector.node_id}><td>{collector.name}</td><td className={`is-${collectorStateTone(collector.state)}`}>{collectorStateLabel(collector.state)}</td><td><dl>{[["Heartbeat",collector.last_reported_at],["Observed",collector.last_observed_at],["Delivered",collector.last_delivered_at],["Retained",collector.last_event_at]].map(([label,timestamp]) => <div key={label}><dt>{label}:</dt><dd>{timestamp ? relativeAge(timestamp) : "not reported"}</dd></div>)}</dl></td></tr>)}</tbody></table><AppAccessPagination page={page} pageSize={size} count={collectors.slice((page-1)*size,page*size).length} hasNext={page*size<collectors.length} maxOffset={null} onPageChange={setPage} onPageSizeChange={value => { setSize(value); setPage(1); }} /></> : <p className="event-health-note">No gateway has reported collector status yet.</p>;
}
