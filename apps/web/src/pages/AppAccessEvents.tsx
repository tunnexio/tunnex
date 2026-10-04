import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { Badge, Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, PageHeader } from "../components/ui";

type Feed = components["schemas"]["AppAccessEvents"];
type Cursor = components["schemas"]["AppAccessEventCursor"];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const label = (value: string) => value.replace(/_/g, " ");

export default function AppAccessEvents() {
  const { org, loading, failed } = useOrg();
  const [params, setParams] = useSearchParams();
  const appId = params.get("app_id") ?? "";
  const userId = params.get("user_id") ?? "";
  const sessionId = params.get("session_id") ?? "";
  const valid = [appId, userId, sessionId].every(value => !value || uuid.test(value));
  const [filters, setFilters] = useState({ app: appId, user: userId, session: sessionId });
  const [feed, setFeed] = useState<Feed | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const epoch = useRef(0);

  async function load(cursor?: Cursor) {
    if (!org || !valid) return;
    const generation = ++epoch.current;
    setBusy(true); setError("");
    try {
      const result = await api.GET("/api/v1/organizations/{orgId}/app-access/events", { params: { path: { orgId: org.id }, query: { limit: 50, ...(appId ? { app_id: appId } : {}), ...(userId ? { user_id: userId } : {}), ...(sessionId ? { session_id: sessionId } : {}), ...cursor } } });
      if (generation !== epoch.current) return;
      if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not read application events. Your event permission is checked independently of application access.")); return; }
      const data = result.data;
      setFeed(previous => cursor && previous ? { ...data, items: [...previous.items, ...data.items] } : data);
    } catch { if (generation === epoch.current) setError("Could not reach application event history."); }
    finally { if (generation === epoch.current) setBusy(false); }
  }
  useEffect(() => {
    epoch.current++; setFeed(null); setError(""); setFilters({ app: appId, user: userId, session: sessionId });
    if (org && valid) void load();
    return () => { epoch.current++; };
  }, [org?.id, appId, userId, sessionId, valid, refresh]);
  function apply(event: FormEvent) {
    event.preventDefault();
    if (![filters.app, filters.user, filters.session].every(value => !value || uuid.test(value))) { setError("Use a valid UUID for each application, user or session filter."); return; }
    epoch.current++; setFeed(null);
    setParams({ source: "applications", ...(filters.app ? { app_id: filters.app } : {}), ...(filters.user ? { user_id: filters.user } : {}), ...(filters.session ? { session_id: filters.session } : {}) });
    setRefresh(value => value + 1);
  }
  if (loading) return <Loading />;
  if (failed || !org) return <ErrorText>Could not load your organization.</ErrorText>;
  return <section className="app-access-workspace network-management min-w-0 space-y-5">
    <PageHeader title="Application access events" subtitle={org.name} actions={<Button variant="ghost" disabled={busy} onClick={() => { epoch.current++; setRefresh(value => value + 1); }}>Refresh application events</Button>} />
    <p className="text-sm text-ink-secondary">Application decision records remain available under the event permission when App Access or VPN Zero Trust is off. Decision telemetry can lose records; mutation audits are recorded separately.</p>
    <Card className="space-y-4"><div className="app-access-panel-header"><div><h2 className="font-semibold">Filter event history</h2><p className="mt-1 text-sm text-ink-secondary">Narrow the evidence to an application, user or session. Leave fields empty to include all.</p></div></div><form onSubmit={apply} className="grid gap-3 sm:grid-cols-3"><Field label="Application ID"><Input value={filters.app} maxLength={36} onChange={event => setFilters(value => ({ ...value, app: event.target.value }))} /></Field><Field label="User ID"><Input value={filters.user} maxLength={36} onChange={event => setFilters(value => ({ ...value, user: event.target.value }))} /></Field><Field label="Session ID"><Input value={filters.session} maxLength={36} onChange={event => setFilters(value => ({ ...value, session: event.target.value }))} /></Field><Button type="submit" disabled={busy}>Apply application filters</Button></form></Card>
    {!valid && <ErrorText>This event link has an invalid filter. Correct the IDs before loading history.</ErrorText>}
    {error && <div><ErrorText>{error}</ErrorText><Button variant="ghost" disabled={!valid || busy} onClick={() => setRefresh(value => value + 1)}>Retry application events</Button></div>}
    {!feed && busy ? <Loading /> : feed && <>
      <Card className="space-y-2"><h2 className="font-semibold">Telemetry health</h2><p className="text-sm text-ink-secondary">{feed.telemetry.available ? `Telemetry for this organization since this service started: ${feed.telemetry.emitted} recorded · ${feed.telemetry.dropped} dropped · ${feed.telemetry.storage_failures} storage failures.` : "Current telemetry counters are unavailable. Stored event history remains below; zero loss has not been confirmed."}</p></Card>
      <Card className="space-y-4"><div className="app-access-panel-header"><div><h2 className="font-semibold">Stored decision history</h2><p className="mt-1 text-sm text-ink-secondary">Newest events first. Application links open the related configuration.</p></div><Badge>{feed.items.length} loaded</Badge></div><DataTable caption="Application access event history" rows={feed.items} rowKey={event => event.id} failed={false} filterable={false} empty={<EmptyState>No application events match this view.</EmptyState>} columns={[
        { key: "time", header: "Time", cell: event => <time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString()}</time> },
        { key: "app", header: "Application", cell: event => <Link className="text-brand" to={`/app-access/applications/${event.app_id}`}>{event.app_id.slice(0, 8)}</Link> },
        { key: "kind", header: "Event", cell: event => label(event.kind) },
        { key: "outcome", header: "Outcome", cell: event => <Badge tone={event.outcome === "denied" || event.outcome === "failed" ? "danger" : "neutral"}>{label(event.outcome)}</Badge> },
        { key: "reason", header: "Reason", cell: event => label(event.reason) },
      ]} />
      {feed.next_cursor && <Button variant="ghost" disabled={busy} onClick={() => void load(feed.next_cursor)}>Load earlier application events</Button>}</Card>
    </>}
  </section>;
}
