import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { EntityPicker, type PickerOption } from "../components/EntityPicker";
import { Badge, Button, Card, DataTable, ErrorText, Field, Input, Loading, Modal, Select } from "../components/ui";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Member, type UserGroup } from "../lib/api";

type Grant = components["schemas"]["AppAccessGrant"];
type Settings = components["schemas"]["AppAccessSettings"];
type Application = components["schemas"]["AppAccessApplication"];
type Preview = components["schemas"]["AppAccessEffectiveAccess"];

/** Shared grant store projection. The outer permission boundary mounts no readers. */
export default function AppAccessAccess({ orgId, appId, permitted, canViewEvents = false, canViewAudit = false }: { orgId: string; appId?: string; permitted: boolean; canViewEvents?: boolean; canViewAudit?: boolean }) {
  if (!permitted) return <ErrorText>You do not have permission to manage application grants.</ErrorText>;
  return <AccessWorkspace key={`${orgId}:${appId ?? "global"}`} orgId={orgId} appId={appId} canViewEvents={canViewEvents} canViewAudit={canViewAudit} />;
}
function localDate(value?: string | null) {
  if (!value) return "";
  const date = new Date(value);
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function utcDate(value: string) { return value ? new Date(value).toISOString() : null; }
function failure(error: unknown, fallback: string) {
  return ["version_conflict", "stale_version"].includes(apiErrorCode(error) ?? "") ? "This grant changed. Your edits are preserved; close and refresh grants to review the latest version before retrying." : apiErrorMessage(error, fallback);
}
function AccessWorkspace({ orgId, appId, canViewEvents, canViewAudit }: { orgId: string; appId?: string; canViewEvents: boolean; canViewAudit: boolean }) {
  const [params, setParams] = useSearchParams();
  const filter = appId ?? params.get("app_id") ?? "";
  const search = params.get("grant_search") ?? "";
  const status = (params.get("grant_status") ?? "") as Grant["status"] | "";
  const view: "current" | "history" = params.get("grant_view") === "history" || (!params.has("grant_view") && (status === "revoked" || status === "expired")) ? "history" : "current";
  const [searchInput, setSearchInput] = useState(search);
  useEffect(() => { setSearchInput(search); }, [search]);
  const page = Math.min(501, Math.max(1, Math.floor(Number(params.get("grant_page"))) || 1));
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [applications, setApplications] = useState<Application[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [subjectError, setSubjectError] = useState("");
  const [subjectsLoading, setSubjectsLoading] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [dialog, setDialog] = useState<{ action: "edit" | "revoke" | "disable"; grant: Grant | null } | null>(null);
  const [previewUser, setPreviewUser] = useState<PickerOption | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState("");
  const [previewBusy, setPreviewBusy] = useState(false);
  const mounted = useRef(true);
  const currentScope = useRef("");
  currentScope.current = `${orgId}:${filter}:${previewUser?.value ?? ""}`;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setDialog(null); }, [filter, view]);
  useEffect(() => {
    let cancelled = false; setGrants(null); setSettings(null); setError(""); setPreview(null); setPreviewError(""); setPreviewUser(null);
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/settings", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/grants", { params: { path: { orgId }, query: { app_id: filter || undefined, view, search: search || undefined, status: status || undefined, limit: 20, offset: (page - 1) * 20 } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId }, query: { limit: 100, offset: 0 } } })),
    ]).then(([availability, list, apps]) => {
      if (cancelled) return;
      if (!availability.ok || !list.ok || !apps.ok) { setError(!availability.ok ? availability.error : !list.ok ? list.error : !apps.ok ? apps.error : "Could not load access."); return; }
      setSettings(availability.data); setGrants(list.data.items); setHasNext(list.data.items.length === list.data.limit); setApplications(apps.data.items);
    });
    return () => { cancelled = true; };
  }, [orgId, filter, view, search, status, page, attempt]);
  useEffect(() => {
    let cancelled = false; setSubjectError(""); setSubjectsLoading(true); setMembers([]); setGroups([]);
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } } })),
    ]).then(([users, peopleGroups]) => {
      if (cancelled) return;
      setSubjectsLoading(false);
      if (!users.ok || !peopleGroups.ok) { setSubjectError(!users.ok ? users.error : !peopleGroups.ok ? peopleGroups.error : "Could not load grant subjects."); return; }
      setMembers(users.data.filter(member => member.status === "active")); setGroups(peopleGroups.data);
    }); return () => { cancelled = true; };
  }, [orgId, attempt]);
  const options: PickerOption[] = [
    ...members.map(member => ({ value: `user:${member.user_id}`, kind: "user", tag: "USER", label: member.name || member.email, detail: member.email, section: "People" })),
    ...groups.map(group => ({ value: `group:${group.id}`, kind: "group", tag: "GROUP", label: group.name, detail: `${group.member_count} members`, section: "Groups" })),
  ];
  const canAdd = settings?.entitlement_available === true && settings.enabled && settings.domain_ready;
  const changeView = (next: "current" | "history") => {
    const query = new URLSearchParams(params);
    query.set("grant_view", next); query.delete("grant_status"); query.delete("grant_page"); setParams(query);
  };
  const changeFilter = (name: string, value: string) => {
    const query = new URLSearchParams(params); query.set("grant_view", view); query.delete("grant_page");
    value ? query.set(name, value) : query.delete(name); setParams(query);
  };
  const clearFilters = () => {
    const query = new URLSearchParams(params);
    query.set("grant_view", view); query.delete("grant_search"); query.delete("grant_status"); query.delete("grant_page");
    setSearchInput(""); setParams(query);
  };
  const changePage = (next: number) => { const query = new URLSearchParams(params); query.set("grant_page", String(next)); setParams(query); };
  const checkAccess = async () => {
    if (!filter || !previewUser || previewBusy) return; const scope = currentScope.current; setPreviewBusy(true); setPreviewError(""); setPreview(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/effective-access", { params: { path: { orgId, appId: filter } }, body: { user_id: previewUser.value.slice(5) } });
      if (!mounted.current || currentScope.current !== scope) return;
      if (result.error || !result.data) { setPreviewError(apiErrorMessage(result.error, "Could not preview current access.")); return; }
      setPreview(result.data);
    } catch { if (mounted.current && currentScope.current === scope) setPreviewError("Could not reach the API for current access."); } finally { if (mounted.current) setPreviewBusy(false); }
  };
  return <section aria-label="Application access" className="min-w-0 space-y-4 [overflow-wrap:anywhere]">
    <Card className="space-y-4">
      <div className="app-access-panel-header"><div><h2 className="text-xl font-semibold">Access grants</h2><p className="mt-1 text-sm text-ink-secondary">Manage user and group access.</p></div><Button disabled={!canAdd || !filter || subjectsLoading || !!subjectError || grants === null} onClick={() => setDialog({ action: "edit", grant: null })}>Add grant</Button></div>
      {(canViewEvents || canViewAudit) && <div className="flex flex-wrap gap-4 text-sm">{canViewEvents && <Link className="text-brand" to={"/access-events?source=applications" + (filter ? "&app_id=" + encodeURIComponent(filter) : "")}>Access events</Link>}{canViewAudit && <Link className="text-brand" to="/audit?target_type=app_access">Audit log</Link>}</div>}
      <div role="group" aria-label="Grant view" className="flex flex-wrap gap-2"><Button type="button" variant={view === "current" ? "primary" : "ghost"} aria-pressed={view === "current"} onClick={() => changeView("current")}>Current</Button><Button type="button" variant={view === "history" ? "primary" : "ghost"} aria-pressed={view === "history"} onClick={() => changeView("history")}>History</Button></div>
      <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); changeFilter("grant_search", searchInput.trim()); }}>
        {!appId && <div className="min-w-48 flex-1"><Field label="Filter by application"><Select value={filter} onChange={event => changeFilter("app_id", event.target.value)}><option value="">All applications</option>{filter && !applications.some(app => app.id === filter) && <option value={filter}>Selected application</option>}{applications.map(app => <option key={app.id} value={app.id}>{app.draft.name}</option>)}</Select></Field></div>}
        <div className="min-w-48 flex-1"><Field label="Search grants"><Input value={searchInput} maxLength={200} placeholder="Person, group or application" onChange={event => setSearchInput(event.target.value)} /></Field></div>
        <div className="min-w-40"><Field label="Grant status"><Select value={status} onChange={event => changeFilter("grant_status", event.target.value)}><option value="">{view === "current" ? "Active and disabled" : "Revoked and expired"}</option>{view === "current" ? <><option value="active">Active</option><option value="disabled">Disabled</option><option value="scheduled">Scheduled</option><option value="subject_unavailable">Subject unavailable</option></> : <><option value="revoked">Revoked</option><option value="expired">Expired</option></>}</Select></Field></div>
        <Button type="submit" variant="ghost">Search grants</Button>
        {(search || status) && <Button type="button" variant="ghost" onClick={clearFilters}>Clear search and status</Button>}
      </form>
      {!filter && <p className="text-sm text-ink-secondary">Select an application to add a grant.</p>}
      {!appId && applications.length === 100 && <p className="text-sm">The filter shows the first 100 applications. Use an application detail page to manage other applications.</p>}
      {settings && !canAdd && <p role="status" className="app-access-notice">New or edited grants require an eligible license, organization opt-in and a configured application domain. Existing grants remain inspectable and can be disabled or revoked.</p>}
      {subjectsLoading && <p role="status">Loading users and groups…</p>}{subjectError && <div><ErrorText>Could not load users and groups: {subjectError}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry subjects</Button></div>}
      {error ? <div><ErrorText>{error}</ErrorText><Button onClick={() => setAttempt(value => value + 1)}>Retry grants</Button></div> : grants === null ? <Loading /> : <DataTable<Grant> failed={false} caption="Access grants" rows={grants} rowKey={grant => grant.id} rowLabel={grant => grant.subject_label} pageSize={0} filterable={false} empty="No grants match these filters." columns={[
        { key: "subject", header: "Subject", cell: grant => <div className="min-w-0"><p className="font-medium">{grant.subject_label}</p><p className="text-xs text-ink-secondary">{grant.subject_kind === "user" ? "User" : "Group"}</p></div> },
        { key: "application", header: "Application", cell: grant => <Link className="text-brand" to={"/app-access/applications/" + grant.app_id}>{grant.app_label}</Link> },
        { key: "status", header: "Status", cell: grant => <Badge tone={grant.status === "scheduled" ? "warn" : "neutral"}>{grant.status.replace(/_/g, " ")}</Badge> },
        { key: "validity", header: "Validity", cell: grant => <div className="text-sm"><p>{grant.starts_at ? "From " + new Date(grant.starts_at).toLocaleString() : "Immediate"}</p><p>{grant.expires_at ? "Until " + new Date(grant.expires_at).toLocaleString() : "No expiry"}</p></div> },
        { key: "actions", header: "Actions", cell: grant => <div role="group" aria-label={"Grant actions for " + grant.subject_label} className="app-access-toolbar">{!grant.revoked_at && <><Button size="sm" variant="ghost" aria-label={"Edit " + grant.subject_label} disabled={!canAdd} onClick={() => setDialog({ action: "edit", grant })}>Edit</Button>{grant.enabled && <Button size="sm" variant="ghost" aria-label={"Disable " + grant.subject_label} onClick={() => setDialog({ action: "disable", grant })}>Disable</Button>}<Button size="sm" variant="ghost" aria-label={"Revoke " + grant.subject_label} onClick={() => setDialog({ action: "revoke", grant })}>Revoke</Button></>}{canViewAudit && <Link className="text-brand text-sm" aria-label={"Grant change audits for " + grant.subject_label} to={"/audit?target_type=app_access&target_id=" + encodeURIComponent(grant.id)}>Audit log</Link>}</div> },
      ]} />}
    <div className="app-access-pagination"><Button variant="ghost" disabled={page === 1 || grants === null} onClick={() => changePage(page - 1)}>Previous grants</Button><span>Page {page}</span><Button variant="ghost" disabled={!hasNext || grants === null || page >= 501} onClick={() => changePage(page + 1)}>Next grants</Button></div></Card>
    {filter && <Card className="space-y-4"><div className="app-access-panel-header"><div><h3 className="font-semibold">Preview effective access</h3><p className="mt-1 text-sm text-ink-secondary">Check one active user against the current grants and application requirements.</p></div></div><EntityPicker label="Preview user" placeholder="Select an active user" value={previewUser?.value ?? ""} options={options.filter(option => option.kind === "user")} onSelect={option => { setPreviewUser(option); setPreview(null); }} /><Button variant="ghost" disabled={!previewUser || previewBusy || subjectsLoading || !!subjectError} onClick={() => void checkAccess()}>{previewBusy ? "Checking access…" : "Check effective access"}</Button><ErrorText>{previewError}</ErrorText>{preview && <div role="status"><p>{preview.grant_match ? "A current explicit grant matches this user." : "No current explicit grant matches this user."}</p><p>{preview.access_allowed ? "Current configuration permits this user. Opening the application still requires a valid login and a fresh access decision." : `Current application access is denied. Reason: ${preview.deny_reason.replace(/_/g, " ")}.`}</p><p className="text-sm text-ink-secondary">This preview does not create a session or open application content.</p></div>}</Card>}
    {dialog?.action === "edit" && <GrantEditor orgId={orgId} appId={filter} grant={dialog.grant} options={options} canEdit={canAdd} onClose={() => setDialog(null)} onSaved={() => { setDialog(null); setAttempt(value => value + 1); }} />}
    {(dialog?.action === "revoke" || dialog?.action === "disable") && dialog.grant && <RevokeGrant disabling={dialog.action === "disable"} orgId={orgId} grant={dialog.grant} onClose={() => setDialog(null)} onSaved={() => { setDialog(null); setAttempt(value => value + 1); }} />}
  </section>;
}
function GrantEditor({ orgId, appId, grant, options, canEdit, onClose, onSaved }: { orgId: string; appId: string; grant: Grant | null; options: PickerOption[]; canEdit: boolean; onClose: () => void; onSaved: () => void }) {
  const [boundAppId] = useState(appId);
  const [subject, setSubject] = useState<PickerOption | null>(null);
  const [starts, setStarts] = useState(localDate(grant?.starts_at));
  const [expires, setExpires] = useState(localDate(grant?.expires_at));
  const [enabled, setEnabled] = useState(grant?.enabled ?? true);
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const save = async (event: React.FormEvent) => {
    event.preventDefault(); if (busy || !canEdit || (!grant && !subject)) return;
    let startsAt: string | null, expiresAt: string | null;
    try { startsAt = grant && starts === localDate(grant.starts_at) ? grant.starts_at : utcDate(starts); expiresAt = grant && expires === localDate(grant.expires_at) ? grant.expires_at : utcDate(expires); } catch { setError("Enter a valid start and expiry date."); return; }
    if (startsAt && expiresAt && startsAt >= expiresAt) { setError("Expiry must be after the start time."); return; }
    setBusy(true); setError("");
    try {
      const result = grant ? await api.PATCH("/api/v1/organizations/{orgId}/app-access/grants/{grantId}", { params: { path: { orgId, grantId: grant.id } }, body: { enabled, starts_at: startsAt, expires_at: expiresAt, expected_version: grant.version } }) : await api.POST("/api/v1/organizations/{orgId}/app-access/grants", { params: { path: { orgId } }, body: { app_id: boundAppId, subject_kind: subject!.kind as "user" | "group", subject_id: subject!.value.slice(subject!.value.indexOf(":") + 1), enabled, starts_at: startsAt, expires_at: expiresAt } });
      if (result.error || !result.data) { setError(failure(result.error, "Could not confirm grant save. Your input is preserved; refresh grants before retrying.")); return; } onSaved();
    } catch { setError("Could not reach the API. Your input is preserved; refresh grants to check the outcome before retrying."); } finally { setBusy(false); }
  };
  return <Modal title={grant ? "Edit grant" : "Add application grant"} onDismiss={() => { if (!busy) onClose(); }}><form onSubmit={save} className="space-y-4">{grant ? <p>Subject: {grant.subject_label} ({grant.subject_kind}). The application and subject cannot be changed.</p> : <EntityPicker label="Grant subject" placeholder="Select a user or group explicitly" value={subject?.value ?? ""} options={options} onSelect={setSubject} />}<p className="text-sm text-ink-secondary">Times use your local timezone and are saved as UTC. Empty fields leave that side of the validity window unbounded.</p><Field label="Starts at"><Input type="datetime-local" value={starts} onChange={event => setStarts(event.target.value)} /></Field><Field label="Expires at"><Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></Field><label className="flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} />Grant enabled</label><ErrorText>{error}</ErrorText><div className="flex flex-wrap gap-3"><Button type="submit" disabled={busy || !canEdit || (!grant && !subject)}>{busy ? "Saving grant…" : "Save grant"}</Button><Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel grant</Button></div></form></Modal>;
}

function RevokeGrant({ orgId, grant, disabling, onClose, onSaved }: { orgId: string; grant: Grant; disabling: boolean; onClose: () => void; onSaved: () => void }) {
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const [impact, setImpact] = useState<components["schemas"]["AppAccessGrantImpact"] | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false; setImpact(null); setError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/grants/{grantId}/revoke-impact", { params: { path: { orgId, grantId: grant.id } } })).then(result => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); return; }
      if (result.data.grant_version !== grant.version) { setError("This grant changed. Close and refresh grants before reviewing removal."); return; }
      setImpact(result.data);
    }); return () => { cancelled = true; };
  }, [orgId, grant.id, grant.version, attempt]);
  const revoke = async () => {
    if (busy || !impact) return; setBusy(true); setError("");
    try {
      const result = disabling
        ? await api.PATCH("/api/v1/organizations/{orgId}/app-access/grants/{grantId}", { params: { path: { orgId, grantId: grant.id } }, body: { expected_version: impact.grant_version, enabled: false, starts_at: grant.starts_at, expires_at: grant.expires_at } })
        : await api.POST("/api/v1/organizations/{orgId}/app-access/grants/{grantId}/revoke", { params: { path: { orgId, grantId: grant.id } }, body: { expected_version: impact.grant_version } });
      if (result.error || !result.data) { setError(failure(result.error, "Could not confirm removal. Refresh grants before retrying.")); return; } onSaved();
    } catch { setError("Could not reach the API. Refresh grants to check whether removal completed before retrying."); } finally { setBusy(false); }
  };
  return <Modal title={disabling ? "Disable application grant" : "Revoke application grant"} danger onDismiss={() => { if (!busy) onClose(); }}>
    <p>{disabling ? "Disable" : "Revoke"} the explicit {grant.subject_kind} grant for {grant.subject_label}?</p>
    <p className="mt-3">Other valid user or group grants can still match this user. This changes grant configuration; it does not confirm termination of browser sessions or erase content already delivered.</p>
    {impact ? <div role="status" className="mt-3"><p>Users currently matching this grant: {impact.matching_user_count}</p><p>Users losing their last current grant match: {impact.users_losing_grant_match_count}</p><p>Browser session impact is unavailable in this grant preview.</p><p className="text-sm">Evaluated {new Date(impact.evaluated_at).toLocaleString()}</p></div> : !error && <Loading />}
    <ErrorText>{error}</ErrorText>{error && !impact && <Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry grant impact</Button>}
    <div className="mt-4 flex flex-wrap gap-3"><Button variant="danger" disabled={busy || !impact} onClick={() => void revoke()}>{busy ? "Removing grant…" : disabling ? "Confirm grant disable" : "Confirm grant revocation"}</Button><Button variant="ghost" disabled={busy} onClick={onClose}>Cancel removal</Button></div>
  </Modal>;
}
