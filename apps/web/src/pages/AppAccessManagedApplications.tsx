import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import AppAccessMemberTabs from "../components/AppAccessMemberTabs";
import AppAccessSubjectPicker from "../components/AppAccessSubjectPicker";
import AppAccessRequests from "./AppAccessRequests";
import { Badge, Button, Card, DataTable, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
type Managed = components["schemas"]["AppAccessManagedApps"];
type Grant = components["schemas"]["AppAccessGrant"];
type Subject = components["schemas"]["AppAccessGrantSubjects"]["items"][number];

export default function AppAccessManagedApplications({ orgId, appId }: { orgId: string; appId?: string }) {
  const [data, setData] = useState<Managed | null>(null); const [error, setError] = useState(""); const [reload, setReload] = useState(0); const [page, setPage] = useState(0);
  useEffect(() => {
    let cancelled = false; setError("");
    void api.GET("/api/v1/organizations/{orgId}/app-access/managed-apps", { params: { path: { orgId }, query: { app_id: appId, limit: 20, offset: appId ? 0 : page * 20 } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load applications you manage."));
      else setData(result.data);
    }).catch(() => { if (!cancelled) setError("Could not reach managed applications."); });
    return () => { cancelled = true; };
  }, [orgId, appId, page, reload]);
  const app = appId ? data?.items.find(item => item.id === appId) : null;
  return <div className="app-access-workspace network-management min-w-0 space-y-6 [overflow-wrap:anywhere]"><PageHeader title={app ? `Manage access · ${app.name}` : "Manage application access"} subtitle="Manage grants and review requests for your assigned applications" /><AppAccessMemberTabs orgId={orgId} />
    <p className="text-sm text-ink-secondary">App admin assignment lets you manage access to that app. It does not grant permission to open the app or change its configuration. Organization administrators can review requests when an App admin is unavailable.</p>
    {error ? <div><ErrorText>{error}</ErrorText><Button onClick={() => setReload(value => value + 1)}>Retry managed apps</Button></div> : !data ? <Loading /> : appId ? app ? <ScopedManagement key={`${orgId}:${appId}`} orgId={orgId} appId={appId} pending={app.pending_count} onChanged={() => { setReload(value => value + 1); window.dispatchEvent(new Event("app-access-requests-changed")); }} /> : <Card><ErrorText>This app is unavailable or you no longer manage its access.</ErrorText><Link to="/app-access/managed-applications">Back to managed applications</Link></Card> : <><DataTable failed={false} caption="Managed applications" rows={data.items} rowKey={item => item.id} rowLabel={item => item.name} filterable={false} pageSize={0} empty="No applications are assigned to you for access management." columns={[{ key: "app", header: "Application", cell: item => <div><Link className="text-brand" to={`/app-access/managed-applications/${item.id}`}>{item.name}</Link>{item.description && <p className="text-sm text-ink-secondary">{item.description}</p>}</div> }, { key: "requests", header: "Requests", cell: item => <Badge tone={item.pending_count ? "warn" : "neutral"}>{item.pending_count} pending</Badge> }, { key: "manage", header: "Actions", cell: item => <Link className="network-setup-link" to={`/app-access/managed-applications/${item.id}`}>Manage access</Link> }]} /><div className="app-access-pagination flex items-center gap-3"><Button variant="ghost" disabled={page === 0} onClick={() => setPage(value => value - 1)}>Previous applications</Button><span>Page {page + 1}</span><Button variant="ghost" disabled={data.items.length < 20 || page >= 500} onClick={() => setPage(value => value + 1)}>Next applications</Button></div></>}
  </div>;
}
function ScopedManagement({ orgId, appId, pending, onChanged }: { orgId: string; appId: string; pending: number; onChanged: () => void }) {
  const [requests, setRequests] = useState(false);
  return <section className="space-y-4"><div className="flex flex-wrap items-center gap-3"><Button aria-pressed={!requests} variant={requests ? "ghost" : "primary"} onClick={() => setRequests(false)}>Access grants</Button><Button aria-pressed={requests} variant={requests ? "primary" : "ghost"} onClick={() => setRequests(true)}>Requests{pending ? ` · ${pending} pending` : ""}</Button><Link className="text-brand text-sm" to="/app-access/managed-applications">All managed applications</Link></div>{requests ? <AppAccessRequests orgId={orgId} appId={appId} managed embedded onChanged={onChanged} /> : <ManagedGrants key={appId} orgId={orgId} appId={appId} onChanged={onChanged} />}</section>;
}
function ManagedGrants({ orgId, appId, onChanged }: { orgId: string; appId: string; onChanged: () => void }) {
  const [grants, setGrants] = useState<Grant[] | null>(null); const [error, setError] = useState(""); const [reload, setReload] = useState(0); const [page, setPage] = useState(0);
  const [dialog, setDialog] = useState<{ action: "edit" | "disable" | "revoke"; grant: Grant | null } | null>(null);
  const [view, setView] = useState<"current" | "history">("current");
  const [status, setStatus] = useState<Grant["status"] | "">("");
  const changeView = (next: "current" | "history") => { setView(next); setStatus(""); setPage(0); setDialog(null); };
  useEffect(() => {
    let cancelled = false; setGrants(null); setError("");
    void api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/managed-grants", { params: { path: { orgId, appId }, query: { view, status: status || undefined, limit: 20, offset: page * 20 } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load this application's grants."));
      else setGrants(result.data.items);
    }).catch(() => { if (!cancelled) setError("Could not reach application grants."); });
    return () => { cancelled = true; };
  }, [orgId, appId, view, status, page, reload]);
  return <Card className="space-y-4"><div className="flex flex-wrap justify-between gap-3"><h2 className="text-lg font-semibold">Access grants</h2><div className="flex gap-2"><Button variant="ghost" onClick={() => setReload(value => value + 1)}>Refresh grants</Button><Button disabled={!grants} onClick={() => setDialog({ action: "edit", grant: null })}>Add grant</Button></div></div><p className="text-sm text-ink-secondary">A user can still have access through another current user or group grant. Changes do not publish the app or bypass its MFA requirement.</p>
  <div role="group" aria-label="Grant view" className="flex flex-wrap gap-2"><Button type="button" variant={view === "current" ? "primary" : "ghost"} aria-pressed={view === "current"} onClick={() => changeView("current")}>Current</Button><Button type="button" variant={view === "history" ? "primary" : "ghost"} aria-pressed={view === "history"} onClick={() => changeView("history")}>History</Button></div>
  <div className="max-w-xs"><Field label="Grant status"><Select value={status} onChange={event => { setStatus(event.target.value as Grant["status"] | ""); setPage(0); }}><option value="">{view === "current" ? "Active and disabled" : "Revoked and expired"}</option>{view === "current" ? <><option value="active">Active</option><option value="disabled">Disabled</option><option value="scheduled">Scheduled</option><option value="subject_unavailable">Subject unavailable</option></> : <><option value="revoked">Revoked</option><option value="expired">Expired</option></>}</Select></Field></div>
  {error ? <ErrorText>{error}</ErrorText> : !grants ? <Loading /> : <DataTable failed={false} caption="Application grants" rows={grants} rowKey={grant => grant.id} rowLabel={grant => grant.subject_label} pageSize={0} filterable={false} empty="No grants match these filters." columns={[
    { key: "subject", header: "Subject", cell: grant => <div>{grant.subject_label}<p className="text-xs text-ink-secondary">{grant.subject_kind}</p></div> },
    { key: "status", header: "Status", cell: grant => <Badge>{grant.status.replace(/_/g, " ")}</Badge> },
    { key: "validity", header: "Validity", cell: grant => <div className="text-sm"><p>Starts {grant.starts_at ? new Date(grant.starts_at).toLocaleString() : "immediately"}</p><p>Expires {grant.expires_at ? new Date(grant.expires_at).toLocaleString() : "without a time limit"}</p></div> },
    { key: "actions", header: "Actions", cell: grant => !grant.revoked_at ? <div className="flex flex-wrap gap-2"><Button size="sm" variant="ghost" onClick={() => setDialog({ action: "edit", grant })}>Edit</Button>{grant.enabled && <Button size="sm" variant="ghost" onClick={() => setDialog({ action: "disable", grant })}>Disable</Button>}<Button size="sm" variant="ghost" onClick={() => setDialog({ action: "revoke", grant })}>Revoke</Button></div> : null },
  ]} />}
  <div className="app-access-pagination flex items-center gap-3"><Button variant="ghost" disabled={!grants || page === 0} onClick={() => setPage(value => value - 1)}>Previous grants</Button><span>Page {page + 1}</span><Button variant="ghost" disabled={!grants || grants.length < 20 || page >= 500} onClick={() => setPage(value => value + 1)}>Next grants</Button></div>
  {dialog && <ManagedGrantDialog key={`${appId}:${dialog.grant?.id ?? "new"}:${dialog.action}`} orgId={orgId} appId={appId} action={dialog.action} grant={dialog.grant} onClose={() => setDialog(null)} onSaved={() => { setDialog(null); setReload(value => value + 1); onChanged(); }} />}
  </Card>;
}
function localDate(value: string | null | undefined) {
  if (!value) return ""; const date = new Date(value); const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function ManagedGrantDialog({ orgId, appId, action, grant, onClose, onSaved }: { orgId: string; appId: string; action: "edit" | "disable" | "revoke"; grant: Grant | null; onClose: () => void; onSaved: () => void }) {
  const [subject, setSubject] = useState<Subject | null>(null); const [starts, setStarts] = useState(localDate(grant?.starts_at)); const [expires, setExpires] = useState(localDate(grant?.expires_at));
  const [enabled, setEnabled] = useState(grant?.enabled ?? true); const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const lock = useRef(false); const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); if (lock.current || (!grant && !subject)) return;
    let startsAt: string | null, expiresAt: string | null;
    try {
      startsAt = grant && starts === localDate(grant.starts_at) ? grant.starts_at : starts ? new Date(starts).toISOString() : null;
      expiresAt = grant && expires === localDate(grant.expires_at) ? grant.expires_at : expires ? new Date(expires).toISOString() : null;
      if (startsAt && expiresAt && startsAt >= expiresAt) throw new Error();
    } catch { setError("Enter valid dates with expiry after the start time."); return; }
    lock.current = true; setBusy(true); setError("");
    try {
      const result = action === "revoke" && grant
        ? await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/managed-grants/{grantId}/revoke", { params: { path: { orgId, appId, grantId: grant.id } }, body: { expected_version: grant.version } })
        : grant ? await api.PATCH("/api/v1/organizations/{orgId}/app-access/applications/{appId}/managed-grants/{grantId}", { params: { path: { orgId, appId, grantId: grant.id } }, body: { expected_version: grant.version, enabled: action === "disable" ? false : enabled, starts_at: startsAt, expires_at: expiresAt } })
        : await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/managed-grants", { params: { path: { orgId, appId } }, body: { app_id: appId, subject_id: subject!.id, subject_kind: subject!.kind, enabled, starts_at: startsAt, expires_at: expiresAt } });
      if (!alive.current) return;
      if (result.error || !result.data) setError(["version_conflict", "stale_version"].includes(apiErrorCode(result.error) ?? "") ? "This grant changed. Close and refresh grants before trying again." : apiErrorMessage(result.error, "Could not confirm this grant change. Close and refresh grants before retrying."));
      else onSaved();
    } catch { if (alive.current) setError("Could not confirm this grant change. Close and refresh grants before retrying."); }
    finally { lock.current = false; if (alive.current) setBusy(false); }
  }
  const removing = action !== "edit";
  return <Modal title={removing ? action === "disable" ? "Disable application grant" : "Revoke application grant" : grant ? "Edit application grant" : "Add application grant"} danger={removing} onDismiss={() => { if (!busy) onClose(); }}><form onSubmit={submit} className="space-y-4">{grant ? <p>{removing ? `${action === "disable" ? "Disable" : "Revoke"} access granted to` : "Subject:"} <strong>{grant.subject_label}</strong> ({grant.subject_kind}){removing ? "?" : ""}</p> : <AppAccessSubjectPicker orgId={orgId} appId={appId} label="Grant subject" value={subject} onChange={setSubject} />}{removing ? <p className="text-sm text-ink-secondary">Other valid user or group grants can still provide access. This changes grant configuration; it does not erase content already delivered.</p> : <><p className="text-sm text-ink-secondary">Times use your local timezone. Empty fields leave that side of the validity window unbounded.</p><Field label="Starts at"><Input type="datetime-local" value={starts} onChange={event => setStarts(event.target.value)} /></Field><Field label="Expires at"><Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></Field><label className="flex gap-2"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} />Grant enabled</label></>}<ErrorText>{error}</ErrorText><div className="flex gap-3"><Button type="submit" variant={removing ? "danger" : "primary"} disabled={busy || (!grant && !subject)}>{busy ? "Saving grant…" : removing ? action === "disable" ? "Confirm grant disable" : "Confirm grant revocation" : "Save grant"}</Button><Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel grant</Button></div></form></Modal>;
}
