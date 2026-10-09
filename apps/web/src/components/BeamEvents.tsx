import { useEffect, useState } from "react";
import { Button, ErrorText, Field, Input, Loading, RefreshButton } from "./ui";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessEmptyState from "./AppAccessEmptyState";
import { beamApi, type BeamEvent, type BeamEventFilters, type BeamPage } from "../lib/beam";

const actions = ["beam.share.created", "beam.share.pause", "beam.share.resume", "beam.share.stop", "beam.share.extend", "beam.grants.updated", "beam.policy.updated", "beam.access.allowed", "beam.access.denied", "beam.connector.issued"];
export function BeamEvents({ orgId, permitted, shareId, revision }: { orgId: string; permitted: boolean; shareId?: string; revision?: string }) {
  const [data, setData] = useState<BeamPage<BeamEvent> | null>(null), [error, setError] = useState("");
  const [pageSize, setPageSize] = useState(20);
  const [page, setPage] = useState(0), [reload, setReload] = useState(0), [draft, setDraft] = useState<BeamEventFilters>({}), [filters, setFilters] = useState<BeamEventFilters>({});
  useEffect(() => { if (!permitted) return; let current = true; setData(null); setError("");
    void (shareId ? beamApi.shareEvents(orgId, shareId, page * pageSize, filters, pageSize) : beamApi.events(orgId, page * pageSize, filters, pageSize)).then(result => { if (!current) return; if (result.ok) setData(result.data); else setError(result.error); });
    return () => { current = false; };
  }, [orgId, permitted, shareId, page, pageSize, reload, filters, revision]);
  if (!permitted) return <ErrorText>You do not have permission to view Local Sharing events.</ErrorText>;
  return <section className="beam-events beam-section space-y-4"><div className={`beam-section-heading ${shareId ? "" : "beam-events-toolbar"}`}><h2 className={shareId ? "font-semibold" : "sr-only"}>{shareId ? "Share history" : "Local Sharing events"}</h2><RefreshButton label="Refresh events" onClick={() => setReload(n => n + 1)} /></div>
    {shareId && <p className="text-sm text-ink-secondary">Sharing and access outcomes. App bodies, cookies and request query strings are never shown.</p>}
    <form className="beam-event-filters" onSubmit={event => { event.preventDefault(); setPage(0); setFilters({ ...draft, q: draft.q?.trim() || undefined }); }}>
      <Field label="Search events"><Input type="search" maxLength={200} value={draft.q ?? ""} onChange={event => setDraft(d => ({ ...d, q: event.target.value }))} placeholder="Action or reason" /></Field>
      {!shareId && <Field label="Share ID"><Input maxLength={36} value={draft.share_id ?? ""} onChange={event => setDraft(d => ({ ...d, share_id: event.target.value || undefined }))} placeholder="Exact share UUID" pattern="[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}" /></Field>}
      <Field label="Event action"><select className="w-full rounded border border-line bg-surface p-2" value={draft.action ?? ""} onChange={event => setDraft(d => ({ ...d, action: event.target.value || undefined }))}><option value="">All actions</option>{actions.map(action => <option key={action} value={action}>{action.replace("beam.", "")}</option>)}</select></Field>
      <Field label="Event outcome"><select className="w-full rounded border border-line bg-surface p-2" value={draft.outcome ?? ""} onChange={event => setDraft(d => ({ ...d, outcome: event.target.value || undefined }))}><option value="">All outcomes</option>{["success", "allowed", "denied"].map(outcome => <option key={outcome} value={outcome}>{outcome}</option>)}</select></Field>
      <div className="flex gap-3"><Button type="submit">Apply event filters</Button><Button type="button" variant="ghost" onClick={() => { setPage(0); setDraft({}); setFilters({}); }}>Clear event filters</Button></div>
    </form>
    {error ? <ErrorText>{error}</ErrorText> : !data ? <Loading label="Loading Local Sharing events…" /> : !data.items.length ? <AppAccessEmptyState title="No Local Sharing events match these filters in this page." description="Try another action or clear the event filters." /> : <div className="overflow-auto"><table className="beam-event-table"><caption className="sr-only">Local Sharing event history</caption><thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Share</th><th>Reason</th></tr></thead><tbody>{data.items.map(event => <tr key={event.id}><td>{new Date(event.created_at).toLocaleString()}</td><td>{event.action}</td><td>{event.outcome}</td><td>{event.share_id.slice(0,8)}</td><td>{event.reason || "None recorded"}</td></tr>)}</tbody></table></div>}
    <AppAccessPagination page={page + 1} pageSize={pageSize} count={data?.items.length ?? 0} hasNext={!!data && data.items.length >= pageSize} busy={!data} previousLabel="Previous events" nextLabel="Next events" onPageChange={next => setPage(next - 1)} onPageSizeChange={size => { setPageSize(size); setPage(0); }} />
  </section>;
}
