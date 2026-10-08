import { useEffect, useId, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { EntityPicker, type PickerOption } from "../components/EntityPicker";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "../components/AppAccessRowMenu";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import { Icon } from "../components/Icon";
import { Badge, Button, DataTable, ErrorText, Field, Input, Loading, Modal, Select } from "../components/ui";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Member, type UserGroup } from "../lib/api";

type Grant = components["schemas"]["AppAccessGrant"];
type Settings = components["schemas"]["AppAccessSettings"];
type Application = components["schemas"]["AppAccessApplication"];
type Preview = components["schemas"]["AppAccessEffectiveAccess"];

/** Shared grant store projection. The outer permission boundary mounts no readers. */
export default function AppAccessAccess({ orgId, appId, permitted, canViewAudit = false }: { orgId: string; appId?: string; permitted: boolean; canViewEvents?: boolean; canViewAudit?: boolean }) {
  if (!permitted) return <ErrorText>You do not have permission to manage application grants.</ErrorText>;
  return <AccessWorkspace key={`${orgId}:${appId ?? "global"}`} orgId={orgId} appId={appId} canViewAudit={canViewAudit} />;
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
function AccessWorkspace({ orgId, appId, canViewAudit }: { orgId: string; appId?: string; canViewAudit: boolean }) {
  const [params, setParams] = useSearchParams();
  const filter = appId ?? params.get("app_id") ?? "";
  const search = params.get("grant_search") ?? "";
  const status = (params.get("grant_status") ?? "") as Grant["status"] | "";
  const view: "current" | "history" = params.get("grant_view") === "history" || (!params.has("grant_view") && (status === "revoked" || status === "expired")) ? "history" : "current";
  const [searchInput, setSearchInput] = useState(search);
  useEffect(() => { setSearchInput(search); }, [search]);
  const pageSize = appAccessPageSize(params.get("grant_limit"));
  const maxPage = Math.floor(10000 / pageSize) + 1;
  const page = Math.min(maxPage, Math.max(1, Math.floor(Number(params.get("grant_page"))) || 1));
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
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/grants", { params: { path: { orgId }, query: { app_id: filter || undefined, view, search: search || undefined, status: status || undefined, limit: pageSize, offset: (page - 1) * pageSize } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId }, query: { limit: 100, offset: 0 } } })),
    ]).then(([availability, list, apps]) => {
      if (cancelled) return;
      if (!availability.ok || !list.ok || !apps.ok) { setError(!availability.ok ? availability.error : !list.ok ? list.error : !apps.ok ? apps.error : "Could not load access."); return; }
      setSettings(availability.data); setGrants(list.data.items); setHasNext(list.data.items.length === list.data.limit); setApplications(apps.data.items);
    });
    return () => { cancelled = true; };
  }, [orgId, filter, view, search, status, page, pageSize, attempt]);
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
  const changePage = (next: number) => { const query = new URLSearchParams(params); query.set("grant_page", String(Math.max(1, Math.min(maxPage, next)))); setParams(query); };
  const changePageSize = (next: number) => { const query = new URLSearchParams(params); query.set("grant_limit", String(appAccessPageSize(String(next)))); query.delete("grant_page"); setParams(query); };
  const checkAccess = async () => {
    if (!filter || !previewUser || previewBusy) return; const scope = currentScope.current; setPreviewBusy(true); setPreviewError(""); setPreview(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/effective-access", { params: { path: { orgId, appId: filter } }, body: { user_id: previewUser.value.slice(5) } });
      if (!mounted.current || currentScope.current !== scope) return;
      if (result.error || !result.data) { setPreviewError(apiErrorMessage(result.error, "Could not preview current access.")); return; }
      setPreview(result.data);
    } catch { if (mounted.current && currentScope.current === scope) setPreviewError("Could not reach the API for current access."); } finally { if (mounted.current) setPreviewBusy(false); }
  };
  const addUnavailable = !settings ? "Checking App Access setup…" : !settings.entitlement_available ? "An eligible license is required to add or edit grants." : !settings.enabled ? "Enable App Access to add or edit grants." : !settings.domain_ready ? "Complete domain setup to add or edit grants." : null;
  const addDisabled = !canAdd || subjectsLoading || !!subjectError || grants === null;
  const addGrant = <Button disabled={addDisabled} onClick={() => setDialog({ action: "edit", grant: null })}>Add grant</Button>;

  const rowActions = (grant: Grant): AppAccessRowMenuAction[] => [
    ...(!grant.revoked_at ? [
      { key: "edit", label: "Edit grant", disabledReason: addUnavailable, icon: <Icon name="settings" size={16} />, onSelect: () => setDialog({ action: "edit", grant }) },
      ...(grant.enabled ? [{ key: "disable", label: "Disable grant", icon: <Icon name="ban" size={16} />, onSelect: () => setDialog({ action: "disable", grant }) }] : []),
      { key: "revoke", label: "Revoke grant", danger: true, icon: <Icon name="shield-alert" size={16} />, onSelect: () => setDialog({ action: "revoke", grant }) },
    ] : []),
    ...(canViewAudit ? [{ key: "audit", label: "Grant change audits", icon: <Icon name="scroll-text" size={16} />, href: "/audit?target_type=app_access&target_id=" + encodeURIComponent(grant.id) }] : []),
  ];
  const emptyState = page > 1 ? <AppAccessEmptyState icon={appId ? null : "users"} title="No more grants" description="Return to the first page to see this access view." action={<Button variant="ghost" onClick={() => changePage(1)}>Back to first page</Button>} />
    : search || status ? <AppAccessEmptyState icon={appId ? null : "search"} title="No matching grants" description="Try another search or clear the filters." action={<Button variant="ghost" onClick={clearFilters}>Clear filters</Button>} />
    : view === "history" ? <AppAccessEmptyState icon={appId ? null : "clock-3"} title="No access history" description="Revoked and expired grants will appear here." action={<Button variant="ghost" onClick={() => changeView("current")}>View current access</Button>} />
    : <AppAccessEmptyState icon={appId ? null : "users"} title="No access granted" description={filter ? "Grant access to a person or group to get started." : "Choose an application, then grant access to a person or group."} action={!addDisabled ? <Button onClick={() => setDialog({ action: "edit", grant: null })}>Grant access</Button> : !filter ? <Link className="text-brand" to="/app-access/applications">View applications</Link> : undefined} />;
  return <section aria-label="Application access" className={`aa-access-focus${appId ? " aa-access-scoped" : " aa-access-global"}`}>
    <div className="aa-access-panel">
      <div className="aa-access-topbar"><div role="group" aria-label="Grant view" className="aa-access-view"><Button type="button" variant="ghost" aria-pressed={view === "current"} onClick={() => changeView("current")}>Current access</Button><Button type="button" variant="ghost" aria-pressed={view === "history"} onClick={() => changeView("history")}>History</Button></div>{addGrant}</div>
      {view === "history" && !!grants?.length && <p className="aa-access-view-help">Revoked and expired grants.</p>}
      <form className="aa-access-toolbar" onSubmit={event => { event.preventDefault(); changeFilter("grant_search", searchInput.trim()); }}>
        {!appId && <div className="aa-access-app-filter"><Field label="Filter by application"><Select aria-label="Filter by application" width="auto" value={filter} onChange={event => changeFilter("app_id", event.target.value)}><option value="">All applications</option>{filter && !applications.some(app => app.id === filter) && <option value={filter}>Selected application</option>}{applications.map(app => <option key={app.id} value={app.id}>{app.draft.name}</option>)}</Select></Field></div>}
        <div className="aa-access-search"><Input aria-label="Search grants" value={searchInput} maxLength={200} placeholder="Search people or groups…" onChange={event => setSearchInput(event.target.value)} /></div>
        <div className="aa-access-status-filter"><Field label="Grant status"><Select aria-label="Grant status" width="auto" value={status} onChange={event => changeFilter("grant_status", event.target.value)}><option value="">{view === "current" ? "All current" : "All history"}</option>{view === "current" ? <><option value="active">Active</option><option value="disabled">Disabled</option><option value="scheduled">Scheduled</option><option value="subject_unavailable">Subject unavailable</option></> : <><option value="revoked">Revoked</option><option value="expired">Expired</option></>}</Select></Field></div>
        <Button type="submit" variant="ghost" className="aa-access-search-submit">Search grants</Button>
        {(search || status) && <Button type="button" variant="ghost" onClick={clearFilters}>Clear search and status</Button>}
      </form>
      {!appId && applications.length === 100 && <p className="aa-access-view-help">The filter shows the first 100 applications. Open an application's Access step to manage others.</p>}
      {settings && !canAdd && <p role="status" className="aa-access-notice">{addUnavailable} Existing grants can still be disabled or revoked.</p>}
      {subjectsLoading && <p role="status">Loading users and groups…</p>}{subjectError && <div><ErrorText>Could not load users and groups: {subjectError}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry subjects</Button></div>}
      {error ? <div><ErrorText>{error}</ErrorText><Button onClick={() => setAttempt(value => value + 1)}>Retry grants</Button></div> : grants === null ? <Loading /> : grants.length === 0 ? emptyState : <div className="aa-access-table"><DataTable<Grant> variant="flat" failed={false} caption="Access grants" rows={grants} rowKey={grant => grant.id} rowLabel={grant => grant.subject_label} pageSize={0} filterable={false} empty={emptyState} columns={[
        { key: "subject", header: "Subject", cell: grant => <div className="aa-access-subject"><p>{grant.subject_label}</p><p>{grant.subject_kind === "user" ? "Person" : "Group"}</p></div> },
        ...(!appId ? [{ key: "application", header: "Application", cell: (grant: Grant) => <Link className="text-brand" to={"/app-access/applications/" + grant.app_id}>{grant.app_label}</Link> }] : []),
        { key: "status", header: "Status", cell: grant => <Badge tone={grant.status === "scheduled" ? "warn" : "neutral"}>{grant.status.replace(/_/g, " ")}</Badge> },
        { key: "validity", header: "Validity", cell: grant => <div className="aa-access-validity"><p>{grant.starts_at ? "From " + new Date(grant.starts_at).toLocaleString() : "Immediate"}</p><p>{grant.expires_at ? "Until " + new Date(grant.expires_at).toLocaleString() : "No expiry"}</p></div> },
        { key: "actions", header: "Actions", cell: grant => <AppAccessRowMenu label={"Grant actions for " + grant.subject_label} actions={rowActions(grant)} /> },
      ]} /></div>}
      {grants && !error && <AppAccessPagination page={page} pageSize={pageSize} count={grants.length} hasNext={hasNext} onPageChange={changePage} onPageSizeChange={changePageSize} previousLabel="Previous grants" nextLabel="Next grants" />}
    </div>
    {filter && <details className="aa-editor-disclosure aa-access-preview"><summary>Preview effective access</summary><div className="aa-editor-disclosure-content"><div className="aa-access-preview-content">
      <p className="aa-access-preview-help">Check one user against the current grants and application requirements.</p>
      <EntityPicker label="Preview user" placeholder="Select an active user" value={previewUser?.value ?? ""} options={options.filter(option => option.kind === "user")} onSelect={option => { setPreviewUser(option); setPreview(null); }} />
      <Button variant="ghost" disabled={!previewUser || previewBusy || subjectsLoading || !!subjectError} onClick={() => void checkAccess()}>{previewBusy ? "Checking access…" : "Check effective access"}</Button><ErrorText>{previewError}</ErrorText>
      {preview && <div role="status"><p>{preview.grant_match ? "A current explicit grant matches this user." : "No current explicit grant matches this user."}</p><p>{preview.access_allowed ? "Current configuration permits this user. Opening the application still requires a valid login and a fresh access decision." : `Current application access is denied. Reason: ${preview.deny_reason.replace(/_/g, " ")}.`}</p><p className="text-sm text-ink-secondary">This preview does not create a session or open application content.</p></div>}
    </div></div></details>}
    {dialog?.action === "edit" && <GrantEditor orgId={orgId} appId={filter} grant={dialog.grant} applications={applications} options={options} canEdit={canAdd} onClose={() => setDialog(null)} onSaved={() => { setDialog(null); setAttempt(value => value + 1); }} />}
    {(dialog?.action === "revoke" || dialog?.action === "disable") && dialog.grant && <RevokeGrant disabling={dialog.action === "disable"} orgId={orgId} grant={dialog.grant} onClose={() => setDialog(null)} onSaved={() => { setDialog(null); setAttempt(value => value + 1); }} />}
  </section>;
}

function GrantEditor({ orgId, appId, grant, applications, options, canEdit, onClose, onSaved }: { orgId: string; appId: string; grant: Grant | null; applications: Application[]; options: PickerOption[]; canEdit: boolean; onClose: () => void; onSaved: () => void }) {
  const [boundAppId, setBoundAppId] = useState(grant?.app_id ?? appId);
  const formId = useId();
  const [subject, setSubject] = useState<PickerOption | null>(null);
  const [starts, setStarts] = useState(localDate(grant?.starts_at));
  const [expires, setExpires] = useState(localDate(grant?.expires_at));
  const [enabled, setEnabled] = useState(grant?.enabled ?? true);
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const save = async (event: React.FormEvent) => {
    event.preventDefault(); if (busy || !canEdit || (!grant && (!boundAppId || !subject))) return;
    let startsAt: string | null, expiresAt: string | null;
    try { startsAt = grant && starts === localDate(grant.starts_at) ? grant.starts_at : utcDate(starts); expiresAt = grant && expires === localDate(grant.expires_at) ? grant.expires_at : utcDate(expires); } catch { setError("Enter a valid start and expiry date."); return; }
    if (startsAt && expiresAt && startsAt >= expiresAt) { setError("Expiry must be after the start time."); return; }
    setBusy(true); setError("");
    try {
      const result = grant ? await api.PATCH("/api/v1/organizations/{orgId}/app-access/grants/{grantId}", { params: { path: { orgId, grantId: grant.id } }, body: { enabled, starts_at: startsAt, expires_at: expiresAt, expected_version: grant.version } }) : await api.POST("/api/v1/organizations/{orgId}/app-access/grants", { params: { path: { orgId } }, body: { app_id: boundAppId, subject_kind: subject!.kind as "user" | "group", subject_id: subject!.value.slice(subject!.value.indexOf(":") + 1), enabled, starts_at: startsAt, expires_at: expiresAt } });
      if (result.error || !result.data) { setError(failure(result.error, "Could not confirm grant save. Your input is preserved; refresh grants before retrying.")); return; } onSaved();
    } catch { setError("Could not reach the API. Your input is preserved; refresh grants to check the outcome before retrying."); } finally { setBusy(false); }
  };
  const displayTime = (value: string, original?: string | null) => {
    const date = new Date(grant && value === localDate(original) ? original! : value);
    return Number.isNaN(date.getTime()) ? "Custom time" : date.toLocaleString();
  };
  const validity = `${starts ? "Starts " + displayTime(starts, grant?.starts_at) : "Starts immediately"} · ${expires ? "Expires " + displayTime(expires, grant?.expires_at) : "No expiry"}${enabled ? "" : " · Disabled"}`;
  const appLabel = grant?.app_label || applications.find(application => application.id === boundAppId)?.draft.name || "Selected application";
  return <Modal title={grant ? "Edit grant" : "Add application grant"} placement="right" showClose onDismiss={() => { if (!busy) onClose(); }} actions={<>
    <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel grant</Button>
    <Button type="submit" form={formId} disabled={busy || !canEdit || (!grant && (!boundAppId || !subject))}>{busy ? "Saving grant…" : "Save grant"}</Button>
  </>}><form id={formId} onSubmit={save} className="aa-grant-editor">
    {!grant && !appId ? <Field label="Application"><Select aria-label="Application" value={boundAppId} onChange={event => setBoundAppId(event.target.value)}><option value="">Choose an application</option>{applications.map(application => <option key={application.id} value={application.id}>{application.draft.name}</option>)}</Select></Field> : <dl className="aa-grant-context"><div><dt>Application</dt><dd>{appLabel}</dd></div>{grant && <div><dt>Subject</dt><dd>{grant.subject_label} ({grant.subject_kind})</dd></div>}</dl>}
    {grant ? <p className="aa-grant-help">The application and subject cannot be changed.</p> : <EntityPicker label="Grant subject" placeholder="Choose a person or group" value={subject?.value ?? ""} options={options} onSelect={setSubject} />}
    {!grant && !appId && !applications.length && <p className="aa-grant-help">No applications are available. <Link className="text-brand" to="/app-access/applications">View applications</Link></p>}
    <p className="aa-grant-defaults">{validity}</p>
    <details className="aa-editor-disclosure aa-grant-options"><summary>Schedule and options</summary><div className="aa-grant-options-content">
      <Field label="Starts at"><Input type="datetime-local" value={starts} onChange={event => setStarts(event.target.value)} /></Field>
      <Field label="Expires at"><Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></Field>
      <label className="flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} />Grant enabled</label>
      <p className="aa-grant-help">Your local timezone; saved as UTC. Leave dates empty for no time limit.</p>
    </div></details>
    <ErrorText>{error}</ErrorText>
  </form></Modal>;
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
