import { useEffect, useState } from "react";
import { Button, Card, EmptyState, ErrorText, Field, Input, Loading } from "./ui";
import { beamApi, type BeamEvent, type BeamEventFilters, type BeamPage } from "../lib/beam";

const actions = ["beam.share.created", "beam.share.pause", "beam.share.resume", "beam.share.stop", "beam.share.extend", "beam.grants.updated", "beam.policy.updated", "beam.access.allowed", "beam.access.denied", "beam.connector.issued"];
export function BeamEvents({ orgId, permitted, shareId, revision }: { orgId: string; permitted: boolean; shareId?: string; revision?: string }) {
  const [data, setData] = useState<BeamPage<BeamEvent> | null>(null), [error, setError] = useState("");
  const [page, setPage] = useState(0), [reload, setReload] = useState(0), [draft, setDraft] = useState<BeamEventFilters>({}), [filters, setFilters] = useState<BeamEventFilters>({});
  useEffect(() => { if (!permitted) return; let current = true; setData(null); setError("");
    void (shareId ? beamApi.shareEvents(orgId, shareId, page * 20, filters) : beamApi.events(orgId, page * 20, filters)).then(result => { if (!current) return; if (result.ok) setData(result.data); else setError(result.error); });
    return () => { current = false; };
  }, [orgId, permitted, shareId, page, reload, filters, revision]);
  if (!permitted) return <Card><ErrorText>You do not have permission to view Beam events.</ErrorText></Card>;
  return <Card className="space-y-4"><div className="flex flex-wrap justify-between gap-3"><h2 className="font-semibold">{shareId ? "Share history" : "Beam events"}</h2><Button variant="ghost" onClick={() => setReload(n => n + 1)}>Refresh events</Button></div>
    <p className="text-sm text-ink-secondary">Sharing and access outcomes. App bodies, cookies and request query strings are never shown.</p>
    <form className="grid gap-3 sm:grid-cols-2" onSubmit={event => { event.preventDefault(); setPage(0); setFilters({ ...draft, q: draft.q?.trim() || undefined }); }}>
      <Field label="Search events"><Input type="search" maxLength={200} value={draft.q ?? ""} onChange={event => setDraft(d => ({ ...d, q: event.target.value }))} placeholder="Action or reason" /></Field>
      {!shareId && <Field label="Share ID"><Input maxLength={36} value={draft.share_id ?? ""} onChange={event => setDraft(d => ({ ...d, share_id: event.target.value || undefined }))} placeholder="Exact share UUID" pattern="[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}" /></Field>}
      <Field label="Event action"><select className="w-full rounded border border-line bg-surface p-2" value={draft.action ?? ""} onChange={event => setDraft(d => ({ ...d, action: event.target.value || undefined }))}><option value="">All actions</option>{actions.map(action => <option key={action} value={action}>{action.replace("beam.", "")}</option>)}</select></Field>
      <Field label="Event outcome"><select className="w-full rounded border border-line bg-surface p-2" value={draft.outcome ?? ""} onChange={event => setDraft(d => ({ ...d, outcome: event.target.value || undefined }))}><option value="">All outcomes</option>{["success", "allowed", "denied"].map(outcome => <option key={outcome} value={outcome}>{outcome}</option>)}</select></Field>
      <div className="flex gap-3"><Button type="submit">Apply event filters</Button><Button type="button" variant="ghost" onClick={() => { setPage(0); setDraft({}); setFilters({}); }}>Clear event filters</Button></div>
    </form>
    {error ? <ErrorText>{error}</ErrorText> : !data ? <Loading label="Loading Beam events…" /> : !data.items.length ? <EmptyState>No Beam events match these filters in this page.</EmptyState> : <div className="overflow-auto"><table className="beam-event-table"><caption className="sr-only">Beam event history</caption><thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Share</th><th>Reason</th></tr></thead><tbody>{data.items.map(event => <tr key={event.id}><td>{new Date(event.created_at).toLocaleString()}</td><td>{event.action}</td><td>{event.outcome}</td><td>{event.share_id.slice(0,8)}</td><td>{event.reason || "None recorded"}</td></tr>)}</tbody></table></div>}
    <div className="flex items-center gap-3"><Button variant="ghost" disabled={!data || page === 0} onClick={() => setPage(n => n - 1)}>Previous events</Button><span>Page {page + 1}</span><Button variant="ghost" disabled={!data || data.items.length < data.limit || page >= 500} onClick={() => setPage(n => n + 1)}>Next events</Button></div>
  </Card>;
}
