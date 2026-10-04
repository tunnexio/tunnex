import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import AppAccessMemberTabs from "../components/AppAccessMemberTabs";
import { AppAccessRequestStatus } from "../components/AppAccessRequestStatus";
import { Button, Card, DataTable, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";

type Request = components["schemas"]["AppAccessAccessRequest"];
type Requests = components["schemas"]["AppAccessAccessRequests"];
export default function AppAccessRequests({ orgId, appId, managed = false, embedded = false, onChanged }: { orgId: string; appId?: string; managed?: boolean; embedded?: boolean; onChanged?: () => void }) {
  const [data, setData] = useState<Requests | null>(null); const [status, setStatus] = useState<"" | "pending" | "approved" | "rejected">(managed ? "pending" : "");
  const [page, setPage] = useState(0); const [reload, setReload] = useState(0); const [error, setError] = useState("");
  const [decision, setDecision] = useState<{ request: Request; approve: boolean } | null>(null);
  useEffect(() => {
    let cancelled = false; setData(null); setError("");
    void api.GET("/api/v1/organizations/{orgId}/app-access/access-requests", { params: { path: { orgId }, query: { scope: managed ? "managed" : "mine", status: status || undefined, app_id: appId, limit: 20, offset: page * 20 } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load access requests."));
      else setData(result.data);
    }).catch(() => { if (!cancelled) setError("Could not reach access requests."); });
    return () => { cancelled = true; };
  }, [orgId, appId, managed, page, status, reload]);
  const changed = () => { setDecision(null); setReload(value => value + 1); window.dispatchEvent(new Event("app-access-requests-changed")); onChanged?.(); };
  return <section className="app-access-workspace network-management min-w-0 space-y-5 [overflow-wrap:anywhere]" aria-label={managed ? "Managed access requests" : "My access requests"}>
    {!embedded && <><PageHeader title={managed ? "Access requests" : "My requests"} subtitle={managed ? "Review requests for applications you manage" : "Track your application access requests"} /><AppAccessMemberTabs orgId={orgId} /></>}
    <Card className="space-y-4"><div className="flex flex-wrap items-end justify-between gap-3"><div className="sm:w-60"><Field label="Request status"><Select value={status} onChange={event => { setStatus(event.target.value as typeof status); setPage(0); }}><option value="">All requests</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="rejected">Rejected</option></Select></Field></div><Button variant="ghost" onClick={() => setReload(value => value + 1)}>Refresh requests</Button></div>
    {managed && data && <p role="status" className="text-sm">{data.pending_count} pending request{data.pending_count === 1 ? "" : "s"}</p>}
    {!managed && <p className="text-sm text-ink-secondary">Request history stays available when an app is hidden from Company apps. An approval does not override expired or revoked access.</p>}
    {error ? <ErrorText>{error}</ErrorText> : !data ? <Loading /> : <DataTable failed={false} caption="Access requests" rows={data.items} rowKey={request => request.id} rowLabel={request => request.app_name} pageSize={0} filterable={false} empty="No access requests in this view." columns={[
      { key: "application", header: "Application", cell: request => <div><p className="font-medium">{request.app_name}</p><p className="text-xs text-ink-secondary">{new Date(request.created_at).toLocaleString()}</p></div> },
      ...(managed ? [{ key: "requester", header: "Requested by", cell: (request: Request) => <div>{request.requester.name || request.requester.email}<p className="text-xs text-ink-secondary">{request.requester.email}</p>{!request.requester.available && <p className="text-xs">Member unavailable</p>}</div> }] : []),
      { key: "reason", header: "Reason", cell: request => request.reason || "No reason provided" },
      { key: "status", header: "Status", cell: request => <AppAccessRequestStatus request={request} showOwner={!managed} /> },
      ...(managed ? [{ key: "actions", header: "Actions", cell: (request: Request) => request.status === "pending" ? <div className="flex flex-wrap gap-2"><Button size="sm" disabled={!request.requester.available} onClick={() => setDecision({ request, approve: true })}>Approve</Button><Button size="sm" variant="ghost" onClick={() => setDecision({ request, approve: false })}>Reject</Button></div> : <span className="text-sm text-ink-secondary">{request.decided_at ? new Date(request.decided_at).toLocaleString() : "Reviewed"}</span> }] : []),
    ]} />}
    <div className="app-access-pagination flex flex-wrap items-center gap-3"><Button variant="ghost" disabled={!data || page === 0} onClick={() => setPage(value => value - 1)}>Previous requests</Button><span>Page {page + 1}</span><Button variant="ghost" disabled={!data || data.items.length < 20 || page >= 500} onClick={() => setPage(value => value + 1)}>Next requests</Button></div></Card>
    {decision && <DecisionDialog key={`${orgId}:${decision.request.id}:${decision.request.version}`} orgId={orgId} request={decision.request} approve={decision.approve} onClose={() => setDecision(null)} onSaved={changed} />}
  </section>;
}
function DecisionDialog({ orgId, request, approve, onClose, onSaved }: { orgId: string; request: Request; approve: boolean; onClose: () => void; onSaved: () => void }) {
  const [reason, setReason] = useState(""); const [expires, setExpires] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const inFlight = useRef(false); const alive = useRef(true); useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); if (inFlight.current || (!approve && !reason.trim())) return;
    let expiresAt: string | null = null;
    if (approve && expires) { try { expiresAt = new Date(expires).toISOString(); if (Date.parse(expiresAt) <= Date.now()) throw new Error(); } catch { setError("Enter a future expiry date."); return; } }
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/access-requests/{requestId}/decision", { params: { path: { orgId, requestId: request.id } }, body: { expected_version: request.version, decision: approve ? "approved" : "rejected", reason: reason.trim(), expires_at: expiresAt } });
      if (!alive.current) return;
      if (result.error || !result.data) setError(["version_conflict", "stale_version"].includes(apiErrorCode(result.error) ?? "") ? "This request changed. Close and refresh requests before reviewing it again." : apiErrorMessage(result.error, "Could not confirm this decision. Refresh requests before retrying."));
      else onSaved();
    } catch { if (alive.current) setError("Could not confirm this decision. Close and refresh requests before retrying."); }
    finally { if (alive.current) setBusy(false); inFlight.current = false; }
  }
  return <Modal title={approve ? "Approve access request" : "Reject access request"} danger={!approve} onDismiss={() => { if (!busy) onClose(); }}><form onSubmit={submit} className="space-y-4"><p>{approve ? "Grant" : "Reject"} access to <strong>{request.app_name}</strong> for <strong>{request.requester.name || request.requester.email}</strong>?</p>{approve && <><p className="text-sm text-ink-secondary">Approval grants access when needed; existing valid access is retained. App publication and MFA requirements still apply.</p><Field label="Access expires at (optional)"><Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></Field><p className="text-xs text-ink-secondary">Your local timezone. Leave empty for no time limit.</p></>}<Field label={approve ? "Decision note (optional)" : "Rejection reason"}><textarea required={!approve} maxLength={1000} rows={3} className="w-full rounded-md border border-line bg-transparent p-2 text-sm" value={reason} onChange={event => setReason(event.target.value)} /></Field><ErrorText>{error}</ErrorText><div className="flex gap-3"><Button type="submit" variant={approve ? "primary" : "danger"} disabled={busy || (!approve && !reason.trim())}>{busy ? "Saving decision…" : approve ? "Confirm approval" : "Confirm rejection"}</Button><Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel decision</Button></div></form></Modal>;
}
