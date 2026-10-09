import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { AppAccessIcon } from "../components/AppAccessIcon";
import AppAccessMemberTabs from "../components/AppAccessMemberTabs";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import { AppAccessRequestStatus } from "../components/AppAccessRequestStatus";
import { Badge, Button, Card, ErrorText, Field, Loading, Modal, PageHeader } from "../components/ui";
import { AppAccessOpenLink } from "./AppAccessMyApplications";

type Catalog = components["schemas"]["AppAccessCompanyApps"];
type App = Catalog["items"][number];
export default function AppAccessCompanyApplications({ orgId }: { orgId: string }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [reload, setReload] = useState(0);
  const [error, setError] = useState("");
  const [requesting, setRequesting] = useState<App | null>(null);
  useEffect(() => {
    let cancelled = false; setCatalog(null); setError("");
    void api.GET("/api/v1/organizations/{orgId}/app-access/company-apps", { params: { path: { orgId }, query: { limit: pageSize, offset: Math.min(10000, page * pageSize) } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load company applications."));
      else setCatalog(result.data);
    }).catch(() => { if (!cancelled) setError("Could not reach company applications."); });
    return () => { cancelled = true; };
  }, [orgId, page, pageSize, reload]);
  return <div className="app-access-workspace network-management min-w-0 space-y-6 [overflow-wrap:anywhere]">
    <PageHeader title="Company applications" navigationTitle />
    <AppAccessMemberTabs orgId={orgId} />
    <p className="text-sm text-ink-secondary">Your organization chooses which applications appear here. App admins review access requests; application access still requires a current grant.</p>
    {catalog && catalog.availability !== "available" && <p role="status" className="app-access-notice">{catalog.availability === "feature_disabled" ? "Applications is off for this organization." : catalog.availability === "feature_unavailable" ? "Applications requires an eligible license." : catalog.availability === "parent_unavailable" ? "Sign in again to open applications with this login." : "Application access setup is not complete. Contact your administrator."}</p>}
    {error ? <div><ErrorText>{error}</ErrorText><Button onClick={() => setReload(value => value + 1)}>Retry company apps</Button></div> : !catalog ? <Loading /> : !catalog.items.length ? <AppAccessEmptyState title={page ? "No more company apps" : "No company apps"} description={page ? "Return to the previous page to browse earlier applications." : "No company applications are available in this view."} /> : <ul className="grid min-w-0 gap-3 sm:grid-cols-2 xl:grid-cols-3">{catalog.items.map(app => <li key={app.id}><Card className="flex h-full min-w-0 flex-col gap-3 p-4">
      <div className="flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-surface"><AppAccessIcon icon={app.icon} image={app.icon_data_url} className="h-5 w-5 text-ink-secondary" /></span><h2 className="text-base font-semibold">{app.name}</h2></div>
      {app.description && <p className="text-sm text-ink-secondary">{app.description}</p>}
      <p className="text-sm">App admin: {app.app_admin ? app.app_admin.name || app.app_admin.email : "Unassigned"}{!app.app_admin?.available && <span className="block text-ink-secondary">App admin unavailable. An organization administrator can review requests.</span>}</p>
      <AppAccessRequestStatus request={app.latest_request} />
      {app.access_granted && app.require_mfa && <div className="space-y-1"><Badge>MFA required</Badge><p className="text-xs text-ink-secondary">{app.mfa_setup_required ? "Set up MFA when you open this app" : app.mfa_required ? "Verification needed" : "Recent verification can be reused"}</p></div>}
      <div className="mt-auto border-t border-line pt-3">{app.access_granted && app.launch_url ? <AppAccessOpenLink orgId={orgId} app={{ id: app.id, name: app.name, launch_url: app.launch_url }} /> : app.access_granted ? <p className="text-sm">Access is granted. Opening this application is currently unavailable.</p> : app.latest_request?.status === "pending" ? <p className="text-sm text-ink-secondary">Waiting for review</p> : <><Button onClick={() => setRequesting(app)}>{app.latest_request ? "Request access again" : "Request access"}</Button>{app.latest_request?.status === "approved" && <p className="mt-2 text-xs text-ink-secondary">The previous approval no longer provides current access.</p>}</>}</div>
    </Card></li>)}</ul>}
    {catalog && !error && <AppAccessPagination page={page + 1} pageSize={pageSize} count={catalog.items.length} hasNext={catalog.items.length === pageSize} onPageChange={next => setPage(Math.max(0, Math.min(Math.floor(10000 / pageSize), next - 1)))} onPageSizeChange={size => { setPageSize(appAccessPageSize(String(size))); setPage(0); }} />}
    {requesting && <RequestAccess key={`${orgId}:${requesting.id}`} orgId={orgId} app={requesting} onClose={() => setRequesting(null)} onSaved={() => { setRequesting(null); setReload(value => value + 1); window.dispatchEvent(new Event("app-access-requests-changed")); }} />}
  </div>;
}
function RequestAccess({ orgId, app, onClose, onSaved }: { orgId: string; app: App; onClose: () => void; onSaved: () => void }) {
  const [reason, setReason] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const inFlight = useRef(false); const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); if (inFlight.current) return; inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/access-requests", { params: { path: { orgId, appId: app.id } }, body: { reason: reason.trim() } });
      if (!alive.current) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not confirm the request. Close and refresh to check its status before retrying."));
      else onSaved();
    } catch { if (alive.current) setError("Could not confirm the request. Close and refresh to check its status before retrying."); }
    finally { if (alive.current) setBusy(false); inFlight.current = false; }
  }
  return <Modal title={`Request access to ${app.name}`} onDismiss={() => { if (!busy) onClose(); }}><form className="space-y-4" onSubmit={submit}><p>The App admin or an organization administrator will review your request.</p><Field label="Reason (optional)"><textarea maxLength={1000} className="w-full rounded-md border border-line bg-transparent p-2 text-sm" rows={3} value={reason} onChange={event => setReason(event.target.value)} /></Field><ErrorText>{error}</ErrorText><div className="flex gap-3"><Button type="submit" disabled={busy}>{busy ? "Sending request…" : "Send request"}</Button><Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel</Button></div></form></Modal>;
}
