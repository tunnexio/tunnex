import { useEffect, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { useSearchParams } from "react-router-dom";
import { Button, Card, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, RefreshButton, Select } from "../components/ui";
import { Icon } from "../components/Icon";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import { api, loadOne } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { generateVaultPassword } from "../lib/vault";
import "../app-access-workspace.css";
import "../vault-workspace.css";

type Entry = components["schemas"]["VaultEntry"];
type Service = components["schemas"]["VaultService"];
type Workspace = components["schemas"]["VaultWorkspace"];
type History = components["schemas"]["VaultHistory"];
type Subjects = components["schemas"]["VaultSubjects"];
type Secret = components["schemas"]["VaultSecret"];
const entriesPath = "/api/v1/organizations/{orgId}/vault/entries";
const entryPath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}";
const servicesPath = "/api/v1/organizations/{orgId}/vault/services";
const subjectsPath = "/api/v1/organizations/{orgId}/vault/subjects";
const revealPath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}/reveal";
const historyPath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}/versions";

function dateLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export default function Vault() {
  const { org, failed } = useOrg();
  const { state } = useAuth();
  if (failed) return <Card><ErrorText>Could not load your organization.</ErrorText></Card>;
  if (!org || state.status !== "authed") return <Loading label="Loading Vault…" />;
  // Remount every user/tenant boundary: no selected entry, draft or revealed value survives it.
  return <VaultWorkspace key={`${org.id}:${state.user.id}`} orgId={org.id} />;
}

function VaultWorkspace({ orgId }: { orgId: string }) {
  const [data, setData] = useState<Workspace | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const [params, setParams] = useSearchParams();
  const search = (params.get("q") ?? "").slice(0, 100);
  const pageSize = appAccessPageSize(params.get("page_size"));
  const page = Math.min(Math.floor(10000 / pageSize) + 1, Math.max(1, Math.floor(Number(params.get("page"))) || 1));
  const [query, setQuery] = useState(search);
  const [editor, setEditor] = useState<"new" | Entry | null>(null);
  const [selected, setSelected] = useState<Entry | null>(null);
  const [deleting, setDeleting] = useState<Entry | null>(null);
  const [services, setServices] = useState<Service[] | null>(null);
  const [serviceError, setServiceError] = useState(false);
  const [serviceReload, setServiceReload] = useState(0);

  function changeQuery(next: { q?: string; page?: number; pageSize?: number }) {
    const updated = new URLSearchParams(params);
    if (next.q !== undefined) { if (next.q) updated.set("q", next.q); else updated.delete("q"); }
    if (next.page !== undefined) { if (next.page > 1) updated.set("page", String(next.page)); else updated.delete("page"); }
    if (next.pageSize !== undefined) updated.set("page_size", String(next.pageSize));
    setParams(updated);
  }
  function setPage(value: number) { changeQuery({ page: value }); }
  useEffect(() => { setQuery(search); }, [search]);

  useEffect(() => {
    let live = true;
    setData(null); setError("");
    void loadOne(() => api.GET(entriesPath, { params: { path: { orgId }, query: { limit: pageSize, offset: (page - 1) * pageSize, q: search || undefined } } })).then(result => {
      if (!live) return;
      if (result.ok) {
        if (page > 1 && !result.data.entries.length) { setPage(Math.max(1, Math.ceil(result.data.total / pageSize))); return; }
        setData(result.data);
      } else setError("Could not load your Vault. Check your access and try again.");
    });
    return () => { live = false; };
  }, [orgId, page, pageSize, search, reload]);
  useEffect(() => {
    let live = true;
    setServices(null); setServiceError(false);
    void loadOne(() => api.GET(servicesPath, { params: { path: { orgId } } })).then(result => {
      if (!live) return;
      if (result.ok) setServices(result.data); else setServiceError(true);
    });
    return () => { live = false; };
  }, [orgId, serviceReload]);

  function refreshed(message: string) { setNotice(message); setSelected(null); setReload(value => value + 1); }
  function openEditor(value: "new" | Entry) { setSelected(null); setEditor(value); }
  return <section className="vault-workspace network-management min-w-0">
    <PageHeader navigationTitle title="Tunnex Vault" />
    <div className="vault-workspace-bar"><div><h2>My Vault{data && <span className="vault-count">{data.total}</span>}</h2><p>{data?.can_assign ? "Your personal credentials and organization assignments." : "Personal credentials and credentials assigned to you."}</p></div><Button disabled={!data} onClick={() => openEditor("new")}>Add credential</Button></div>
    <form className="vault-toolbar" onSubmit={event => { event.preventDefault(); changeQuery({ q: query.trim(), page: 1 }); setNotice(""); }}>
      <div className="vault-search"><Icon name="search" size={16} /><Input type="search" aria-label="Search Vault" placeholder="Search title, service or username…" maxLength={100} value={query} onChange={event => setQuery(event.target.value)} /></div>
      <Button type="submit" variant="ghost">Search</Button>
      <RefreshButton label="Refresh Vault" onClick={() => { setSelected(null); setReload(value => value + 1); }} />
      {search && <Button type="button" variant="ghost" onClick={() => { setQuery(""); changeQuery({ q: "", page: 1 }); }}>Clear search</Button>}
    </form>
    {notice && <p role="status" className="vault-notice">{notice}</p>}
    {error ? <div className="vault-error"><ErrorText>{error}</ErrorText><Button variant="ghost" onClick={() => setReload(value => value + 1)}>Retry Vault</Button></div> : !data ? <Loading label="Loading credentials…" /> : !data.entries.length ? <EmptyState action={search ? <Button variant="ghost" onClick={() => { changeQuery({ q: "", page: 1 }); setQuery(""); }}>Clear search</Button> : <Button onClick={() => openEditor("new")}>Add your first credential</Button>}>{search ? "No credentials match your search." : "No credentials yet. Save a personal password or API key to get started."}</EmptyState> : <>
      <div className="vault-table-wrap"><table className="vault-table"><caption className="sr-only">Vault credentials</caption><thead><tr><th>Credential</th><th>Username</th><th>Access</th><th>Version</th><th>Updated</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{data.entries.map(entry => <tr key={entry.id}>
        <td><div className="vault-entry-identity"><span className="vault-entry-icon" aria-hidden="true"><Icon name="key" size={17} /></span><div><button type="button" className="vault-entry-title" onClick={() => setSelected(entry)}>{entry.title}</button><p>{entry.service_name} · {entry.kind === "api_key" ? "API key" : "Password"}</p></div></div></td>
        <td>{entry.username || <span className="vault-muted">Not set</span>}</td>
        <td><span className="vault-access">{entry.visibility === "personal" ? "Personal" : entry.subject_name || "Assigned"}</span><span className="vault-cell-note">{entry.visibility === "personal" ? "Only you" : entry.subject_kind === "group" ? "Shared with group" : "Assigned credential"}</span></td>
        <td><span className="vault-version">Version {entry.current_version}</span></td>
        <td><time dateTime={entry.updated_at}>{dateLabel(entry.updated_at)}</time></td>
        <td><AppAccessRowMenu label={`Actions for ${entry.title}`} actions={[{ key: "view", label: "View credential", onSelect: () => setSelected(entry) }, ...(entry.can_edit ? [{ key: "rotate", label: "Change secret", onSelect: () => openEditor(entry) }] : []), ...(entry.can_delete ? [{ key: "delete", label: "Delete credential", danger: true, onSelect: () => setDeleting(entry) }] : [])]} /></td>
      </tr>)}</tbody></table></div>
      <AppAccessPagination page={page} pageSize={pageSize} count={data.entries.length} hasNext={page * pageSize < data.total} onPageChange={setPage} onPageSizeChange={size => changeQuery({ pageSize: size, page: 1 })} />
    </>}
    <p className="vault-footer-note"><Icon name="shield-check" size={14} /> Personal entries are visible only to you. Assigned entries are shared with their recipients and Vault administrators.</p>
    {editor && <CredentialEditor key={editor === "new" ? "new" : editor.id} orgId={orgId} entry={editor === "new" ? undefined : editor} canAssign={data?.can_assign ?? false} services={services} serviceError={serviceError} onRetryServices={() => setServiceReload(value => value + 1)} onServiceAdded={service => setServices(current => [...(current ?? []).filter(value => value.id !== service.id), service].sort((a, b) => a.name.localeCompare(b.name)))} onDismiss={() => setEditor(null)} onSaved={() => { setEditor(null); refreshed(editor === "new" ? "Credential saved." : "New version saved. Earlier versions remain in history."); }} />}
    {selected && <CredentialDetails key={selected.id} orgId={orgId} entry={selected} onDismiss={() => setSelected(null)} onRotate={() => openEditor(selected)} onDelete={() => { setDeleting(selected); setSelected(null); }} />}
    {deleting && <DeleteCredential orgId={orgId} entry={deleting} onDismiss={() => setDeleting(null)} onDeleted={() => { setDeleting(null); refreshed("Credential and all of its versions deleted. The external service password or key was not changed."); }} />}
  </section>;
}

function CredentialEditor({ orgId, entry, canAssign, services, serviceError, onRetryServices, onServiceAdded, onDismiss, onSaved }: {
  orgId: string; entry?: Entry; canAssign: boolean; services: Service[] | null; serviceError: boolean;
  onRetryServices: () => void; onServiceAdded: (service: Service) => void; onDismiss: () => void; onSaved: () => void;
}) {
  const [title, setTitle] = useState(entry?.title ?? "");
  const [kind, setKind] = useState<"password" | "api_key">(entry?.kind ?? "password");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [secret, setSecret] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [visibility, setVisibility] = useState<"personal" | "assigned">(entry?.visibility ?? "personal");
  const [serviceId, setServiceId] = useState("");
  const [privateService, setPrivateService] = useState("");
  const [newService, setNewService] = useState("");
  const [addingService, setAddingService] = useState(false);
  const [showServiceForm, setShowServiceForm] = useState(false);
  const [subjectKind, setSubjectKind] = useState<"user" | "group">("user");
  const [subjectId, setSubjectId] = useState("");
  const [subjects, setSubjects] = useState<Subjects | null>(null);
  const [subjectError, setSubjectError] = useState(false);
  const [subjectReload, setSubjectReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [conflict, setConflict] = useState(false);
  const live = useRef(true);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => {
    if (!showSecret) return;
    const timer = window.setTimeout(() => setShowSecret(false), 30000);
    return () => window.clearTimeout(timer);
  }, [showSecret]);
  useEffect(() => {
    if (entry || visibility !== "assigned" || !canAssign) return;
    let current = true;
    setSubjects(null); setSubjectError(false);
    void loadOne(() => api.GET(subjectsPath, { params: { path: { orgId } } })).then(result => {
      if (!current) return;
      if (result.ok) setSubjects(result.data); else setSubjectError(true);
    });
    return () => { current = false; };
  }, [orgId, visibility, canAssign, entry, subjectReload]);

  function generate() {
    try { setSecret(generateVaultPassword()); setError(""); }
    catch { setError("Secure generation is unavailable. Enter a secret to continue."); }
  }
  async function addService() {
    if (!newService.trim() || addingService) return;
    setAddingService(true); setError("");
    try {
      const result = await api.POST(servicesPath, { params: { path: { orgId } }, body: { name: newService.trim() } });
      if (!live.current) return;
      if (!result.data || result.error) { setError(result.response.status === 409 ? "A service with that name already exists. Choose it from the catalog." : "Could not add the service. Try again."); return; }
      onServiceAdded(result.data); setServiceId(result.data.id); setNewService(""); setShowServiceForm(false);
    } catch { if (live.current) setError("Could not confirm service creation. Refresh the catalog before trying again."); }
    finally { if (live.current) setAddingService(false); }
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || addingService || conflict) return;
    if (!title.trim() || !secret || (!entry && !serviceId && !privateService.trim()) || (!entry && visibility === "assigned" && (!serviceId || !subjectId))) { setError("Complete the title, service, secret and any required assignment."); return; }
    setBusy(true); setError("");
    try {
      const result = entry
        ? await api.PUT(entryPath, { params: { path: { orgId, entryId: entry.id } }, body: { title: title.trim(), username, secret, expected_version: entry.current_version } })
        : await api.POST(entriesPath, { params: { path: { orgId } }, body: { title: title.trim(), kind, username, secret, visibility, ...(serviceId ? { service_id: serviceId } : { service_name: privateService.trim() }), ...(visibility === "assigned" ? { subject_kind: subjectKind, subject_id: subjectId } : {}) } });
      if (!live.current) return;
      if (result.error || !result.data) {
        if (entry && result.response.status === 409) { setConflict(true); setSecret(""); setShowSecret(false); setError("This credential changed while you were editing. Close this form and refresh Vault before making another change."); }
        else if (result.response.status >= 500) { setConflict(true); setSecret(""); setShowSecret(false); setError("Could not confirm the save. Close this form and refresh Vault before retrying."); }
        else setError("Could not save the credential. Check your access and try again.");
        return;
      }
      setSecret(""); setShowSecret(false); onSaved();
    } catch { if (live.current) { setSecret(""); setShowSecret(false); setError("Could not confirm the save. Close this form and refresh Vault before retrying."); setConflict(true); } }
    finally { if (live.current) setBusy(false); }
  }
  const choices = subjectKind === "user" ? subjects?.users : subjects?.groups;
  return <Modal title={entry ? "Change secret" : "Add credential"} size="wide" onDismiss={() => { if (!busy && !addingService) { setSecret(""); onDismiss(); } }} actions={<><Button variant="ghost" disabled={busy || addingService} onClick={() => { setSecret(""); onDismiss(); }}>Cancel</Button><Button type="submit" form="vault-credential-form" disabled={busy || addingService || conflict || (!entry && visibility === "assigned" && !subjects)}>{busy ? "Saving…" : entry ? "Save new version" : "Save credential"}</Button></>}>
    <form id="vault-credential-form" className="vault-form" onSubmit={submit} autoComplete="off">
      <ErrorText>{error}</ErrorText>
      {entry && <p className="vault-help">Saving creates version {entry.current_version + 1}. Earlier versions stay in history. Update the external service separately.</p>}
      <div className="vault-form-grid"><Field label="Title"><Input autoFocus maxLength={160} required value={title} onChange={event => setTitle(event.target.value)} placeholder="Production database" /></Field><Field label="Credential type"><Select value={kind} disabled={!!entry} onChange={event => setKind(event.target.value as typeof kind)}><option value="password">Password</option><option value="api_key">API key</option></Select></Field></div>
      {!entry && <>
        <Field label="Visibility"><Select value={visibility} onChange={event => { setVisibility(event.target.value as typeof visibility); setSubjectId(""); if (event.target.value === "assigned") setPrivateService(""); }}><option value="personal">Personal · only you</option>{canAssign && <option value="assigned">Assigned · administrators and recipients</option>}</Select></Field>
        {serviceError ? <div className="vault-inline-error"><ErrorText>Could not load the service catalog.</ErrorText><Button type="button" variant="ghost" size="sm" onClick={onRetryServices}>Retry services</Button></div> : services === null ? <Loading size="inline" label="Loading services…" /> : <Field label="Service"><Select value={serviceId} onChange={event => { setServiceId(event.target.value); if (event.target.value) setPrivateService(""); }}><option value="">{visibility === "personal" ? "Use a private service name" : "Choose a service"}</option>{services.map(service => <option key={service.id} value={service.id}>{service.name}</option>)}</Select></Field>}
        {visibility === "personal" && !serviceId && <Field label="Private service name"><Input maxLength={120} required value={privateService} onChange={event => setPrivateService(event.target.value)} placeholder="Service or application" /></Field>}
        {canAssign && <div className="vault-service-create">{!showServiceForm ? <button type="button" className="vault-text-action" onClick={() => setShowServiceForm(true)}>Add a service to the catalog</button> : <><Field label="New service name"><Input maxLength={120} value={newService} onChange={event => setNewService(event.target.value)} placeholder="Reusable organization service" /></Field><div className="vault-inline-actions"><Button type="button" variant="ghost" size="sm" disabled={addingService || !newService.trim()} onClick={() => void addService()}>{addingService ? "Adding…" : "Add service"}</Button><Button type="button" variant="ghost" size="sm" disabled={addingService} onClick={onRetryServices}>Refresh catalog</Button><Button type="button" variant="ghost" size="sm" disabled={addingService} onClick={() => { setShowServiceForm(false); setNewService(""); }}>Cancel service</Button></div><p className="vault-help">This service name will be available to everyone in this organization. Credentials keep their own permissions.</p></>}</div>}
        {visibility === "assigned" && <div className="vault-assignment">{subjectError ? <div className="vault-inline-error"><ErrorText>Could not load recipients.</ErrorText><Button type="button" variant="ghost" size="sm" onClick={() => setSubjectReload(value => value + 1)}>Retry recipients</Button></div> : !subjects ? <Loading size="inline" label="Loading recipients…" /> : <div className="vault-form-grid"><Field label="Assign to"><Select value={subjectKind} onChange={event => { setSubjectKind(event.target.value as typeof subjectKind); setSubjectId(""); }}><option value="user">User</option><option value="group">Group</option></Select></Field><Field label={subjectKind === "user" ? "User" : "Group"}><Select required value={subjectId} onChange={event => setSubjectId(event.target.value)}><option value="">Choose a {subjectKind}</option>{choices?.map(subject => <option key={subject.id} value={subject.id}>{subject.name}</option>)}</Select></Field></div>}<p className="vault-help">Administrators and current recipients can read and update every version. Administrators manage deletion.</p></div>}
        {visibility === "personal" && <p className="vault-help">Only you can open this credential and its history. A private service name stays within this entry.</p>}
      </>}
      {entry && <p className="vault-help">{entry.service_name} · {entry.visibility === "personal" ? "Personal · only you" : `Assigned to ${entry.subject_name || "the selected recipients"}`}</p>}
      <Field label="Username (optional)"><Input name="vault-credential-username" autoComplete="off" maxLength={320} value={username} onChange={event => setUsername(event.target.value)} placeholder="Login name or email" /></Field>
      <Field label={entry ? "New secret" : "Secret"}><Input name="vault-credential-value" autoComplete="new-password" type={showSecret ? "text" : "password"} spellCheck={false} required maxLength={16384} value={secret} onChange={event => setSecret(event.target.value)} /></Field>
      <div className="vault-inline-actions">{kind === "password" && <Button type="button" variant="ghost" size="sm" onClick={generate}>Generate password</Button>}<Button type="button" variant="ghost" size="sm" disabled={!secret} onClick={() => setShowSecret(value => !value)}>{showSecret ? "Hide secret" : "Show secret"}</Button><span className="vault-help">{kind === "password" ? "24 characters · letters, numbers and symbols" : "Paste the API key issued by the service."}</span></div>
    </form>
  </Modal>;
}

function CredentialDetails({ orgId, entry, onDismiss, onRotate, onDelete }: { orgId: string; entry: Entry; onDismiss: () => void; onRotate: () => void; onDelete: () => void }) {
  const [history, setHistory] = useState<History | null>(null);
  const [historyError, setHistoryError] = useState(false);
  const [page, setPage] = useState(1);
  const [reload, setReload] = useState(0);
  const [revealed, setRevealed] = useState<Secret | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const live = useRef(true);
  const request = useRef(0);
  useEffect(() => { live.current = true; return () => { live.current = false; request.current++; }; }, []);
  useEffect(() => {
    let current = true;
    setHistory(null); setHistoryError(false);
    void loadOne(() => api.GET(historyPath, { params: { path: { orgId, entryId: entry.id }, query: { limit: 10, offset: (page - 1) * 10 } } })).then(result => {
      if (!current) return;
      if (result.ok) setHistory(result.data); else { setHistoryError(true); conceal(); }
    });
    return () => { current = false; };
  }, [orgId, entry.id, page, reload]);
  useEffect(() => {
    if (!revealed) return;
    const timer = window.setTimeout(conceal, 30000);
    return () => window.clearTimeout(timer);
  }, [revealed]);
  useEffect(() => {
    function onVisibilityChange() { if (document.visibilityState === "hidden") conceal(); }
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);
  function conceal() { request.current++; setRevealed(null); setBusy(false); }
  function close() { conceal(); onDismiss(); }
  async function accessSecret(version?: number, copy = false) {
    const id = ++request.current;
    setBusy(true); setRevealed(null); setError(""); setNotice("");
    try {
      // Copy is a new authorized, audited request too; an old reveal is never reused.
      const result = await api.POST(revealPath, { params: { path: { orgId, entryId: entry.id } }, body: version ? { version } : {} });
      if (!live.current || id !== request.current) return;
      if (result.error || !result.data) { setError("Could not access this version. Refresh Vault to check your current access."); return; }
      if (copy) {
        await navigator.clipboard.writeText(result.data.value);
        if (live.current && id === request.current) setNotice(`Version ${result.data.version} copied.`);
      } else setRevealed(result.data);
    } catch { if (live.current && id === request.current) setError(copy ? "Could not copy the secret. Reveal it to select and copy it." : "Could not reveal this version. Try again."); }
    finally { if (live.current && id === request.current) setBusy(false); }
  }
  return <Modal title={entry.title} size="wide" showClose onDismiss={close} actions={<><Button variant="ghost" onClick={close}>Close</Button>{entry.can_delete && <Button variant="danger" onClick={() => { conceal(); onDelete(); }}>Delete credential</Button>}{entry.can_edit && <Button onClick={() => { conceal(); onRotate(); }}>Change secret</Button>}</>}>
    <div className="vault-detail"><dl className="vault-detail-facts"><div><dt>Service</dt><dd>{entry.service_name}</dd></div><div><dt>Type</dt><dd>{entry.kind === "api_key" ? "API key" : "Password"}</dd></div><div><dt>Username</dt><dd>{entry.username || "Not set"}</dd></div><div><dt>Access</dt><dd>{entry.visibility === "personal" ? "Personal · only you" : `Assigned · ${entry.subject_name || "recipients and administrators"}`}</dd></div></dl>
      <section className="vault-secret-panel" aria-label="Credential secret"><div className="vault-section-heading"><h3>{revealed ? `Version ${revealed.version}${revealed.version === (history?.current_version ?? entry.current_version) ? " · current" : " · historical"}` : "Secret hidden"}</h3>{revealed && <button type="button" className="vault-text-action" onClick={conceal}>Hide secret</button>}</div><code className="vault-secret-value" aria-label={revealed ? "Revealed secret" : "Hidden secret"}>{revealed?.value ?? "••••••••••••••••"}</code>{revealed && <p className="vault-help">Username in this version: {revealed.username || "Not set"}. Hidden automatically after 30 seconds.</p>}<div className="vault-inline-actions"><Button variant="ghost" size="sm" disabled={busy} onClick={() => void accessSecret()}>{busy ? "Checking access…" : "Reveal current secret"}</Button><Button variant="ghost" size="sm" disabled={busy} onClick={() => void accessSecret(revealed?.version, true)}>{revealed ? `Copy version ${revealed.version}` : "Copy current secret"}</Button></div><ErrorText>{error}</ErrorText>{notice && <p role="status" className="vault-help">{notice}</p>}</section>
      <section className="vault-history" aria-label="Version history"><div className="vault-section-heading"><h3>Version history{history && <span className="vault-count">{history.total}</span>}</h3><RefreshButton label="Refresh version history" onClick={() => { conceal(); setReload(value => value + 1); }} /></div><p className="vault-help">Each saved change keeps its own version. Revealing or copying a value is recorded in the audit log.</p>
        {historyError ? <div className="vault-inline-error"><ErrorText>Could not load version history.</ErrorText><Button variant="ghost" size="sm" onClick={() => setReload(value => value + 1)}>Retry history</Button></div> : !history ? <Loading label="Loading history…" /> : <><div className="vault-table-wrap"><table className="vault-table vault-history-table"><caption className="sr-only">Credential version history</caption><thead><tr><th>Version</th><th>Changed by</th><th>Saved</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{history.versions.map(version => <tr key={version.version}><td>{version.version}{version.version === history.current_version && <span className="vault-cell-note">Current</span>}</td><td>{version.changed_by_name}</td><td><time dateTime={version.created_at}>{dateLabel(version.created_at)}</time></td><td><Button variant="ghost" size="sm" disabled={busy} aria-label={`Reveal version ${version.version}`} onClick={() => void accessSecret(version.version)}>Reveal</Button></td></tr>)}</tbody></table></div><div className="vault-history-pagination"><span>{history.total} {history.total === 1 ? "version" : "versions"}</span><Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => { conceal(); setPage(value => value - 1); }}>Previous versions</Button><Button variant="ghost" size="sm" disabled={page * 10 >= history.total} onClick={() => { conceal(); setPage(value => value + 1); }}>Next versions</Button></div></>}
      </section>
    </div>
  </Modal>;
}

function DeleteCredential({ orgId, entry, onDismiss, onDeleted }: { orgId: string; entry: Entry; onDismiss: () => void; onDeleted: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const live = useRef(true);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  async function remove() {
    if (busy || uncertain) return;
    setBusy(true); setError("");
    try {
      const result = await api.DELETE(entryPath, { params: { path: { orgId, entryId: entry.id }, query: { expected_version: entry.current_version } } });
      if (!live.current) return;
      if (result.error) { setError(result.response.status === 409 ? "This credential has a newer version. Close this dialog and refresh Vault before deleting." : "Could not delete this credential. Check your access and try again."); if (result.response.status === 409) setUncertain(true); return; }
      onDeleted();
    } catch { if (live.current) { setError("Could not confirm deletion. Close this dialog and refresh Vault before retrying."); setUncertain(true); } }
    finally { if (live.current) setBusy(false); }
  }
  return <Modal title="Delete credential" danger onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant="danger" disabled={busy || uncertain} onClick={() => void remove()}>{busy ? "Deleting…" : "Confirm deletion"}</Button></>}><div className="vault-form"><ErrorText>{error}</ErrorText><p>Permanently delete <strong>{entry.title}</strong> and all {entry.current_version} saved versions from Vault{entry.visibility === "assigned" ? " for every recipient" : ""}?</p><p>This cannot be undone. The password or API key in the external service will remain unchanged. Audit records remain available.</p></div></Modal>;
}
