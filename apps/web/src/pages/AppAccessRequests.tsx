import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import AppAccessMemberTabs from "../components/AppAccessMemberTabs";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessDomainSetup from "../components/AppAccessDomainSetup";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import { Icon } from "../components/Icon";
import { Badge, Button, DataTable, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";

type Request = components["schemas"]["AppAccessAccessRequest"];
type Requests = components["schemas"]["AppAccessAccessRequests"];
export default function AppAccessRequests({ orgId, appId, managed = false, embedded = false, onChanged }: { orgId: string; appId?: string; managed?: boolean; embedded?: boolean; onChanged?: () => void }) {
  const [data, setData] = useState<Requests | null>(null); const [status, setStatus] = useState<"" | "pending" | "approved" | "rejected">(managed ? "pending" : "");
  const [page, setPage] = useState(0); const [pageSize, setPageSize] = useState(20); const [reload, setReload] = useState(0); const [error, setError] = useState("");
  const [decision, setDecision] = useState<{ request: Request; approve: boolean } | null>(null);
  useEffect(() => {
    let cancelled = false; setData(null); setError("");
    void api.GET("/api/v1/organizations/{orgId}/app-access/access-requests", { params: { path: { orgId }, query: { scope: managed ? "managed" : "mine", status: status || undefined, app_id: appId, limit: pageSize, offset: Math.min(10000, page * pageSize) } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load access requests."));
      else setData(result.data);
    }).catch(() => { if (!cancelled) setError("Could not reach access requests."); });
    return () => { cancelled = true; };
  }, [orgId, appId, managed, page, pageSize, status, reload]);
  const changed = () => { setDecision(null); setReload(value => value + 1); window.dispatchEvent(new Event("app-access-requests-changed")); onChanged?.(); };
  const clearStatus = () => { setStatus(""); setPage(0); };
  const emptyTitle = page > 0 ? "No more requests" : managed && status === "pending" ? "All caught up" : status ? `No ${status} requests` : "No requests yet";
  const emptyDescription = page > 0 ? "Return to the previous page to review earlier requests." : managed && status === "pending" ? appId ? "No pending requests for this application." : "No access requests are waiting for review." : status ? "Choose another status to see more request history." : managed ? "Requests from your team will appear here." : "Request access to an application from Company apps.";
  const emptyAction = page > 0 ? undefined : status ? <Button variant="ghost" onClick={clearStatus}>{managed && status === "pending" ? "View all requests" : "Clear filter"}</Button> : !managed ? <Link className="network-setup-link" to="/app-access/company-applications">Browse company apps</Link> : undefined;
  const hasNext = !!data && data.items.length === pageSize && page < Math.floor(10000 / pageSize);
  return <section className={`app-access-workspace network-management aa-requests-workspace${embedded ? " aa-requests-embedded" : " app-access-inventory-workspace"}`} aria-label={managed ? "Managed access requests" : "My access requests"}>
    {!embedded && <><PageHeader title="App Access" navigationTitle actions={<AppAccessDomainSetup />} /><AppAccessMemberTabs orgId={orgId} /></>}
    <div className="aa-requests-panel"><div className="aa-requests-toolbar"><div className="aa-requests-filters"><Select aria-label="Request status" width="auto" value={status} onChange={event => { setStatus(event.target.value as typeof status); setPage(0); }}><option value="">All requests</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="rejected">Rejected</option></Select>
      {managed && data && data.pending_count > 0 && <span role="status" className="aa-requests-count">{data.pending_count} pending</span>}</div><Button variant="ghost" aria-label="Refresh requests" title="Refresh requests" onClick={() => setReload(value => value + 1)}><Icon name="refresh-cw" size={16} /></Button></div>
    {error ? <div className="aa-requests-error"><ErrorText>{error}</ErrorText><Button variant="ghost" onClick={() => setReload(value => value + 1)}>Retry requests</Button></div> : !data ? <Loading label="Loading requests…" /> : !data.items.length ? <AppAccessEmptyState title={emptyTitle} description={emptyDescription} action={emptyAction} icon={managed && status === "pending" ? "check-circle" : "file-text"} /> : <div className="aa-requests-table"><DataTable failed={false} empty={null} caption="Access requests" rows={data.items} rowKey={request => request.id} rowLabel={request => request.app_name} pageSize={0} filterable={false} columns={[
      { key: "application", header: "Application", cell: request => <div className="aa-requests-application"><p>{request.app_name}</p><p title={new Date(request.created_at).toLocaleString()}>{new Date(request.created_at).toLocaleDateString()}</p></div> },
      ...(managed ? [{ key: "requester", header: "Requested by", cell: (request: Request) => <div className="aa-requests-requester">{request.requester.name || request.requester.email}{request.requester.name && <p>{request.requester.email}</p>}{!request.requester.available && <p>Member unavailable</p>}</div> }] : []),
      { key: "reason", header: "Reason", cell: request => <div className="aa-requests-reason">{request.reason || <span className="aa-requests-muted">No reason provided</span>}{request.decision_reason && <p>Decision: {request.decision_reason}</p>}</div> },
      { key: "status", header: "Status", cell: request => <div className="aa-requests-status"><Badge tone={request.status === "pending" ? "warn" : "neutral"}>{request.status === "pending" ? "Pending" : request.status === "approved" ? "Approved" : "Rejected"}</Badge>{!managed && <p>App admin: {request.app_admin ? request.app_admin.name || request.app_admin.email : "Unassigned"}{!request.app_admin?.available && " · Organization administrator review available"}</p>}</div> },
      ...(managed ? [{ key: "actions", header: "Actions", cell: (request: Request) => request.status === "pending" ? <AppAccessRowMenu label={`Actions for ${request.app_name} request by ${request.requester.name || request.requester.email}`} actions={[
        { key: "approve", label: "Approve", disabledReason: request.requester.available ? null : "This member is unavailable.", onSelect: () => setDecision({ request, approve: true }) },
        { key: "reject", label: "Reject", danger: true, onSelect: () => setDecision({ request, approve: false }) },
      ]} /> : <span className="aa-requests-reviewed">{request.decided_at ? new Date(request.decided_at).toLocaleDateString() : "Reviewed"}</span> }] : []),
    ]} /></div>}
    {data && <AppAccessPagination page={page + 1} pageSize={pageSize} count={data.items.length} hasNext={hasNext} previousLabel="Previous requests" nextLabel="Next requests" onPageChange={nextPage => setPage(Math.max(0, Math.min(Math.floor(10000 / pageSize), nextPage - 1)))} onPageSizeChange={size => { setPageSize(appAccessPageSize(String(size))); setPage(0); }} />}</div>
    {!managed && <details className="aa-editor-disclosure aa-requests-help"><summary>About requests</summary><div className="aa-editor-disclosure-content"><p>Requests stay in your history even when an app is hidden. Approval does not override expired or revoked access.</p></div></details>}
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
