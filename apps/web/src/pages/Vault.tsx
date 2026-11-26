import { useEffect, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { useSearchParams } from "react-router-dom";
import { Button, Card, ErrorText, Field, Input, Loading, Modal, PageHeader, RefreshButton, Select } from "../components/ui";
import { Icon } from "../components/Icon";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import { AdminOnlyNotice } from "../components/AdminOnly";
import { InlineTerminalMfa } from "../components/InlineTerminalMfa";
import { api, apiErrorCode, loadOne } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { personLabel } from "../lib/personLabel";
import { copyRevealedSecret, copyVaultPasswordAfterSave, generateVaultPassword, vaultRequestId, scheduleClipboardClear, VaultCopyError, VaultRevealError } from "../lib/vault";
import "../app-access-workspace.css";
import "../beam-workspace.css";
import "../vault-workspace.css";

type Entry = components["schemas"]["VaultEntry"];
type Service = components["schemas"]["VaultService"];
type Workspace = components["schemas"]["VaultWorkspace"];
type History = components["schemas"]["VaultHistory"];
type Subjects = components["schemas"]["VaultSubjects"];
type Subject = components["schemas"]["VaultSubject"];
type Secret = components["schemas"]["VaultSecret"];
type Reauth = components["schemas"]["VaultReauthentication"];
type View = "all" | "personal" | "shared" | "assigned";
const entriesPath = "/api/v1/organizations/{orgId}/vault/entries";
const quickPath = "/api/v1/organizations/{orgId}/vault/entries/quick";
const entryPath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}";
const configurePath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}/configure";
const servicesPath = "/api/v1/organizations/{orgId}/vault/services";
const subjectsPath = "/api/v1/organizations/{orgId}/vault/subjects";
const revealPath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}/reveal";
const historyPath = "/api/v1/organizations/{orgId}/vault/entries/{entryId}/versions";
const CLIPBOARD_NOTE = "Clear it after use. Where this browser allows Vault to read the clipboard, Vault clears it after about 30 seconds if it still holds this secret.";

function dateLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
// VAULT-UX-1 V7: a saved quick password reads as what it is, with the next step, never "Unconfigured".
const QUICK_TITLE = "Generated password · add details";
function entryTitle(entry: Entry) { return entry.configured === false ? QUICK_TITLE : entry.title; }
function serviceLabel(entry: Entry) { return entry.configured === false ? "Details not added yet" : entry.service_name; }
function plural(n: number, one: string, many = `${one}s`) { return `${n} ${n === 1 ? one : many}`; }
function subjectLabel(subject: Subject) { return subject.email ? personLabel(subject) : subject.name; }

export default function Vault() {
  const { org, failed } = useOrg();
  const { state } = useAuth();
  if (failed) return <Card><ErrorText>Could not load your organization.</ErrorText></Card>;
  if (!org || state.status !== "authed") return <Loading label="Loading Vault…" />;
  // Remount every user/tenant boundary: no selected entry, draft or revealed value survives it.
  return <VaultWorkspace key={`${org.id}:${state.user.id}`} orgId={org.id} />;
}

const VIEWS: { key: View; label: string; admin?: boolean }[] = [
  { key: "all", label: "All" },
  { key: "personal", label: "Personal" },
  { key: "shared", label: "Shared with me" },
  { key: "assigned", label: "Organization", admin: true },
];
const EMPTY: Record<View, string> = {
  all: "Save a personal password or API key, or open a credential shared with you. Each change keeps its own version history.",
  personal: "Personal credentials are visible only to you.",
  shared: "Credentials an administrator shares with you, or with a group you are in, appear here.",
  assigned: "Credentials you share with people or groups in this organization appear here.",
};

type LoadFailure = "access" | "unverified" | "other";
type EditorState = { mode: "new" } | { mode: "configure" | "rotate" | "details"; entry: Entry };

function VaultWorkspace({ orgId }: { orgId: string }) {
  const [data, setData] = useState<Workspace | null>(null);
  const [failure, setFailure] = useState<LoadFailure | null>(null);
  const [canAssign, setCanAssign] = useState(false);
  const [reauth, setReauth] = useState<Reauth | undefined>(undefined);
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const [params, setParams] = useSearchParams();
  const search = (params.get("q") ?? "").slice(0, 100);
  const rawView = params.get("view");
  const view: View = rawView === "personal" || rawView === "shared" || rawView === "assigned" ? rawView : "all";
  const pageSize = appAccessPageSize(params.get("page_size"));
  const page = Math.min(Math.floor(10000 / pageSize) + 1, Math.max(1, Math.floor(Number(params.get("page"))) || 1));
  const [query, setQuery] = useState(search);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [quick, setQuick] = useState<{ password: string; requestId: string } | null>(null);
  const [selected, setSelected] = useState<Entry | null>(null);
  const [deleting, setDeleting] = useState<Entry | null>(null);
  const [services, setServices] = useState<Service[] | null>(null);
  const [serviceError, setServiceError] = useState(false);
  const [serviceReload, setServiceReload] = useState(0);
  const workspaceLive = useRef(true);
  useEffect(() => { workspaceLive.current = true; return () => { workspaceLive.current = false; }; }, []);

  function changeQuery(next: { q?: string; page?: number; pageSize?: number; view?: View }) {
    const updated = new URLSearchParams(params);
    if (next.q !== undefined) { if (next.q) updated.set("q", next.q); else updated.delete("q"); }
    if (next.page !== undefined) { if (next.page > 1) updated.set("page", String(next.page)); else updated.delete("page"); }
    if (next.pageSize !== undefined) updated.set("page_size", String(next.pageSize));
    if (next.view !== undefined) { if (next.view !== "all") updated.set("view", next.view); else updated.delete("view"); }
    setParams(updated);
  }
  function setPage(value: number) { changeQuery({ page: value }); }
  useEffect(() => { setQuery(search); }, [search]);

  useEffect(() => {
    let live = true;
    setData(null); setFailure(null);
    // Read the status, not just the data: a refusal is an access answer, not a broken page (V11).
    void (async () => {
      try {
        const result = await api.GET(entriesPath, { params: { path: { orgId }, query: { limit: pageSize, offset: (page - 1) * pageSize, q: search || undefined, view: view === "all" ? undefined : view } } });
        if (!live) return;
        if (result.data) {
          if (page > 1 && !result.data.entries.length) { setPage(Math.max(1, Math.ceil(result.data.total / pageSize))); return; }
          setData(result.data); setCanAssign(result.data.can_assign); setReauth(result.data.reauthentication);
          return;
        }
        const code = apiErrorCode(result.error);
        setFailure(code === "email_not_verified" ? "unverified" : result.response?.status === 403 ? "access" : "other");
      } catch { if (live) setFailure("other"); }
    })();
    return () => { live = false; };
  }, [orgId, page, pageSize, search, view, reload]);
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
  function open(state: EditorState) { setSelected(null); setEditor(state); }
  function quickGenerate() {
    try { const password = generateVaultPassword(); const requestId = vaultRequestId(); setSelected(null); setNotice(""); setQuick({ password, requestId }); }
    catch { setNotice("Secure generation is unavailable in this browser. Use Add credential to enter a password."); }
  }
  if (failure === "access") return <AdminOnlyNotice page="Vault" />;
  if (failure === "unverified") return <section aria-label="Vault"><Card className="max-w-2xl space-y-3"><h1 className="text-base font-semibold text-ink-heading">Vault</h1><p className="text-sm text-ink-secondary">Verify your email to use Vault. Check your inbox for the verification link, then reload this page.</p></Card></section>;
  const views = VIEWS.filter(item => !item.admin || canAssign);
  const savedMessage = (state: EditorState) => state.mode === "configure" ? "Details added. The generated password is unchanged." : state.mode === "details" ? "Details saved. No new version was created." : state.mode === "rotate" ? "New version saved. Earlier versions remain in history." : "Credential saved.";
  return <section className="beam-workspace vault-workspace network-management min-w-0 space-y-5">
    <PageHeader navigationTitle title="Vault" />
    <nav className="vault-views" aria-label="Vault views">{views.map(item => <button key={item.key} type="button" aria-pressed={view === item.key} onClick={() => { if (view !== item.key) { setSelected(null); changeQuery({ view: item.key, page: 1 }); } }}>{item.label}</button>)}</nav>
    <section className="beam-inventory" aria-label="Vault credentials">
    <div className="beam-workspace-bar"><p className="beam-list-summary vault-inventory-summary">{data ? plural(data.total, "credential") : "Credentials"}</p><div className="beam-workspace-tools"><button type="button" className="beam-inline-link" onClick={quickGenerate}>Quick generate</button><Button onClick={() => open({ mode: "new" })}>Add credential</Button></div></div>
    <form className="beam-toolbar" onSubmit={event => { event.preventDefault(); changeQuery({ q: query.trim(), page: 1 }); setNotice(""); }}>
      <div className="beam-search"><Icon name="search" size={17} /><Input type="search" aria-label="Search Vault" placeholder="Search title, service or username…" maxLength={100} value={query} onChange={event => setQuery(event.target.value)} /></div>
      <Button type="submit" variant="ghost" size="sm">Search</Button>
      <RefreshButton label="Refresh Vault" className="beam-refresh" onClick={() => { setSelected(null); setReload(value => value + 1); }} />
      {search && <Button type="button" variant="ghost" size="sm" onClick={() => { setQuery(""); changeQuery({ q: "", page: 1 }); }}>Clear search</Button>}
    </form>
    {notice && <p role="status" className="beam-notice">{notice}</p>}
    {failure === "other" ? <div className="beam-error"><ErrorText>Could not load your credentials. You can still add one; try loading the list again.</ErrorText><Button onClick={() => setReload(value => value + 1)}>Retry Vault</Button></div> : !data ? <Loading label="Loading credentials…" /> : !data.entries.length ? <AppAccessEmptyState
      icon={null}
      title={search ? "No credentials match your search." : view === "all" ? "No credentials yet" : `Nothing in ${views.find(item => item.key === view)?.label ?? "this view"} yet`}
      description={search ? "Try another title, service or username, or clear the search." : EMPTY[view]}
      action={search ? <Button variant="ghost" size="sm" onClick={() => { changeQuery({ q: "", page: 1 }); setQuery(""); }}>Clear filters</Button> : <button type="button" className="beam-inline-link" onClick={() => open({ mode: "new" })}>Add your first credential<Icon name="chevron-right" size={14} /></button>}
    /> : <>
      <div className="beam-table-wrap"><table className="beam-inventory-table vault-credentials-table"><caption className="sr-only">Vault credentials</caption><thead><tr><th>Credential</th><th>Username</th><th>Access</th><th>Version</th><th>Updated</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{data.entries.map(entry => <tr key={entry.id}>
        <td><div className="beam-app-identity"><div><h2><button type="button" className="vault-entry-title" onClick={() => setSelected(entry)}>{entryTitle(entry)}</button></h2><p className="beam-url vault-service-label">{serviceLabel(entry)} · {entry.kind === "api_key" ? "API key" : "Password"}</p></div></div></td>
        <td>{entry.username || <span className="vault-muted">Not set</span>}</td>
        <td><span className="vault-access">{entry.visibility === "personal" ? "Personal" : entry.subject_name || "Assigned"}</span><span className="vault-cell-note">{entry.visibility === "personal" ? "Only you" : entry.subject_kind === "group" ? "Shared with a group" : "Shared with a person"}</span></td>
        <td><span className="vault-version">Version {entry.current_version}</span></td>
        <td><time className="beam-expiry" dateTime={entry.updated_at}>{dateLabel(entry.updated_at)}</time></td>
        <td><div className="beam-row-actions">{entry.configured === false && entry.can_edit ? <button type="button" className="beam-open-link" aria-label="Add details for Generated password" onClick={() => open({ mode: "configure", entry })}>Add details<Icon name="chevron-right" size={15} /></button> : <button type="button" className="beam-open-link" aria-label={`View ${entryTitle(entry)}`} onClick={() => setSelected(entry)}>View<Icon name="chevron-right" size={15} /></button>}<AppAccessRowMenu label={`Actions for ${entryTitle(entry)}`} actions={[{ key: "view", label: "View credential", onSelect: () => setSelected(entry) },
          ...(entry.configured === false && entry.can_edit ? [{ key: "configure", label: "Add details", onSelect: () => open({ mode: "configure", entry }) }] : []),
          ...(entry.configured !== false && entry.can_edit ? [{ key: "rotate", label: "Change secret", onSelect: () => open({ mode: "rotate", entry }) }] : []),
          ...(entry.can_edit_details ? [{ key: "details", label: "Edit details", onSelect: () => open({ mode: "details", entry }) }] : []),
          ...(entry.can_delete ? [{ key: "delete", label: "Delete credential", danger: true, onSelect: () => setDeleting(entry) }] : [])]} /></div></td>
      </tr>)}</tbody></table></div>
      <AppAccessPagination page={page} pageSize={pageSize} count={data.entries.length} hasNext={page * pageSize < data.total} onPageChange={setPage} onPageSizeChange={size => changeQuery({ pageSize: size, page: 1 })} />
    </>}
    <details className="beam-disclosure beam-publishing-help"><summary>Who can see what</summary><div><p>Personal credentials and their history are visible only to you. Administrators cannot open them. If you leave this organization, your personal credentials here are deleted.</p><p>Shared credentials are visible to their current recipients and to Vault administrators. Opening one asks you to confirm it is you. Recipients can save a new secret; only administrators change the title, service or recipient, or delete it.</p><p>Saving a password or API key here does not change it in the external service.</p></div></details>
    </section>
    {quick && <QuickPassword orgId={orgId} password={quick.password} requestId={quick.requestId} onDismiss={() => setQuick(null)} onPersisted={() => { if (workspaceLive.current) setReload(value => value + 1); }} onCopied={() => { setQuick(null); setNotice(`Password saved and copied. Add its details from the list. ${CLIPBOARD_NOTE}`); }} />}
    {editor && <CredentialEditor key={editor.mode === "new" ? "new" : `${editor.entry.id}:${editor.mode}`} orgId={orgId} state={editor} canAssign={canAssign} services={services} serviceError={serviceError} onRetryServices={() => setServiceReload(value => value + 1)} onServiceAdded={service => setServices(current => [...(current ?? []).filter(value => value.id !== service.id), service].sort((a, b) => a.name.localeCompare(b.name)))} onDismiss={() => setEditor(null)} onStale={() => { setEditor(null); refreshed("That credential changed while you were editing. The list has been refreshed; open it again to continue."); }} onSaved={() => { setEditor(null); refreshed(savedMessage(editor)); }} />}
    {selected && <CredentialDetails key={selected.id} orgId={orgId} entry={selected} reauth={reauth} onDismiss={() => setSelected(null)} onRotate={() => open({ mode: "rotate", entry: selected })} onDetails={() => open({ mode: "details", entry: selected })} onConfigure={() => open({ mode: "configure", entry: selected })} onDelete={() => { setDeleting(selected); setSelected(null); }} />}
    {deleting && <DeleteCredential orgId={orgId} entry={deleting} onDismiss={() => setDeleting(null)} onDeleted={() => { setDeleting(null); refreshed("Credential and all of its versions deleted. The external service password or key was not changed."); }} />}
  </section>;
}

function QuickPassword({ orgId, password: initialPassword, requestId: initialRequestId, onDismiss, onPersisted, onCopied }: { orgId: string; password: string; requestId: string; onDismiss: () => void; onPersisted: () => void; onCopied: () => void }) {
  const [{ password, requestId }, setCandidate] = useState({ password: initialPassword, requestId: initialRequestId });
  const currentRequestId = useRef(initialRequestId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const saved = useRef<Entry | null>(null);
  const live = useRef(true);
  const attempt = useRef(0);
  const activeCopy = useRef(false);
  useEffect(() => { live.current = true; return () => { live.current = false; attempt.current++; }; }, []);
  useEffect(() => {
    function conceal() { if (document.visibilityState === "hidden") { attempt.current++; activeCopy.current = false; setBusy(false); } }
    document.addEventListener("visibilitychange", conceal);
    return () => document.removeEventListener("visibilitychange", conceal);
  }, []);
  function discard() { attempt.current++; onDismiss(); }
  // V8: closing an unsaved password asks first; a saved one is already in the list.
  function close() { if (saved.current) discard(); else setConfirmDiscard(true); }
  function regenerate() {
    if (activeCopy.current) return;
    try {
      const password = generateVaultPassword();
      const requestId = vaultRequestId();
      attempt.current++;
      currentRequestId.current = requestId;
      saved.current = null;
      setCandidate({ password, requestId });
      setError("");
    } catch { setError("Could not generate another password. Try again."); }
  }
  async function copy() {
    if (activeCopy.current) return;
    setConfirmDiscard(false);
    const current = ++attempt.current;
    const isCurrent = () => live.current && attempt.current === current && document.visibilityState !== "hidden";
    activeCopy.current = true; setBusy(true); setError("");
    const persist = saved.current ? undefined : async () => {
      const result = await api.POST(quickPath, { params: { path: { orgId } }, body: { request_id: requestId, secret: password } });
      if (result.error || !result.data) throw new Error("save_failed");
      if (currentRequestId.current === requestId) saved.current = result.data;
      // Metadata may refresh even if this drawer closed; the saved row stays recoverable.
      onPersisted();
    };
    try {
      await copyVaultPasswordAfterSave(password, persist, isCurrent);
      scheduleClipboardClear(password);
      if (isCurrent()) onCopied();
    } catch (cause) {
      if (!isCurrent()) return;
      if (cause instanceof VaultCopyError && cause.reason === "save_failed") setError("Could not confirm the save. Nothing was copied. Try Save & copy again to safely retry.");
      else if (saved.current) setError("Saved to Vault, but the password could not be copied. Try Save & copy again.");
      else setError("Could not save or copy this password. Try Save & copy again.");
    } finally { if (isCurrent()) { activeCopy.current = false; setBusy(false); } }
  }
  return <Modal placement="right" title="Quick generate" onDismiss={close} actions={<><button type="button" className="beam-inline-link mr-auto disabled:opacity-50" disabled={busy} onClick={regenerate}>Regenerate</button><button type="button" className="beam-inline-link" onClick={close}>Close</button><button type="button" className="beam-inline-link disabled:opacity-50" disabled={busy} onClick={() => void copy()}>{busy ? "Saving and copying…" : "Save & copy"}</button></>}>
    <div className="vault-quick-password vault-form"><Field label="Generated password"><Input type="text" readOnly autoFocus autoComplete="off" spellCheck={false} value={password} /></Field>
      <p className="vault-help">Saving keeps this password in your Vault so you can add details later. It is personal until you add details.</p>
      {confirmDiscard && <div className="vault-confirm" role="alertdialog" aria-label="Discard generated password"><p>This password isn't saved. Discard it?</p><div className="vault-inline-actions"><Button variant="ghost" size="sm" onClick={discard}>Discard</Button><Button variant="ghost" size="sm" onClick={() => setConfirmDiscard(false)}>Keep it</Button></div></div>}
      <ErrorText>{error}</ErrorText></div>
  </Modal>;
}

function CredentialEditor({ orgId, state, canAssign, services, serviceError, onRetryServices, onServiceAdded, onDismiss, onSaved, onStale }: {
  orgId: string; state: EditorState; canAssign: boolean; services: Service[] | null; serviceError: boolean;
  onRetryServices: () => void; onServiceAdded: (service: Service) => void; onDismiss: () => void; onSaved: () => void; onStale: () => void;
}) {
  const entry = state.mode === "new" ? undefined : state.entry;
  const mode = state.mode;
  const editingVisibility = mode === "new" || mode === "configure";
  const editingService = editingVisibility || mode === "details";
  const withSecret = mode === "new" || mode === "rotate";
  const [title, setTitle] = useState(entry?.title ?? "");
  const [kind, setKind] = useState<"password" | "api_key">(entry?.kind ?? "password");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [secret, setSecret] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [visibility, setVisibility] = useState<"personal" | "assigned">(entry?.visibility ?? "personal");
  const [serviceId, setServiceId] = useState(entry?.service_id ?? "");
  const [privateService, setPrivateService] = useState(entry && !entry.service_id ? entry.service_name : "");
  const [newService, setNewService] = useState("");
  const [addingService, setAddingService] = useState(false);
  const [showServiceForm, setShowServiceForm] = useState(false);
  const [subjectKind, setSubjectKind] = useState<"user" | "group">(entry?.subject_kind ?? "user");
  const [subjectId, setSubjectId] = useState(entry?.subject_id ?? "");
  const [subjects, setSubjects] = useState<Subjects | null>(null);
  const [subjectError, setSubjectError] = useState(false);
  const [subjectReload, setSubjectReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [stale, setStale] = useState(false);
  const live = useRef(true);
  const assigning = visibility === "assigned" && canAssign && (editingVisibility || mode === "details");
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => {
    if (!showSecret) return;
    const timer = window.setTimeout(() => setShowSecret(false), 30000);
    return () => window.clearTimeout(timer);
  }, [showSecret]);
  useEffect(() => {
    function conceal() { if (document.visibilityState === "hidden") setShowSecret(false); }
    document.addEventListener("visibilitychange", conceal);
    return () => document.removeEventListener("visibilitychange", conceal);
  }, []);
  useEffect(() => {
    if (!assigning) return;
    let current = true;
    setSubjects(null); setSubjectError(false);
    void loadOne(() => api.GET(subjectsPath, { params: { path: { orgId } } })).then(result => {
      if (!current) return;
      if (result.ok) setSubjects(result.data); else setSubjectError(true);
    });
    return () => { current = false; };
  }, [orgId, assigning, subjectReload]);

  function generate() {
    try { setSecret(generateVaultPassword()); setError(""); }
    catch { setError("Secure generation is unavailable. Enter a secret to continue."); }
  }
  function dismiss() { setSecret(""); onDismiss(); }
  async function addService() {
    if (!newService.trim() || addingService) return;
    setAddingService(true); setError("");
    try {
      const result = await api.POST(servicesPath, { params: { path: { orgId } }, body: { name: newService.trim() } });
      if (!live.current) return;
      if (!result.data || result.error) { setError(result.response.status === 409 ? "A service with that name already exists. Choose it from the list." : "Could not add the service. Try again."); return; }
      onServiceAdded(result.data); setServiceId(result.data.id); setPrivateService(""); setNewService(""); setShowServiceForm(false);
    } catch { if (live.current) setError("Could not confirm the new service. Refresh the list before trying again."); }
    finally { if (live.current) setAddingService(false); }
  }
  function incomplete(): string | null {
    if (mode !== "rotate" && !title.trim()) return "Add a title.";
    if (withSecret && !secret) return "Enter the secret, or generate a password.";
    if (editingService && !serviceId && !privateService.trim()) return visibility === "assigned" ? "Choose a service." : "Choose a service or type a private service name.";
    if ((editingVisibility || mode === "details") && visibility === "assigned" && (!serviceId || !subjectId)) return "Choose a service and who it is shared with.";
    return null;
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || addingService || stale) return;
    const missing = incomplete();
    if (missing) { setError(missing); return; }
    setBusy(true); setError("");
    try {
      const service = serviceId ? { service_id: serviceId } : { service_name: privateService.trim() };
      const metadata = { title: title.trim(), username, visibility, ...service, ...(visibility === "assigned" ? { subject_kind: subjectKind, subject_id: subjectId } : {}) };
      let result: { data?: unknown; error?: unknown; response: Response };
      if (mode === "configure" && entry) result = await api.POST(configurePath, { params: { path: { orgId, entryId: entry.id } }, body: { ...metadata, expected_version: entry.current_version } });
      else if (mode === "rotate" && entry) result = await api.PUT(entryPath, { params: { path: { orgId, entryId: entry.id } }, body: { username, secret, expected_version: entry.current_version } });
      else if (mode === "details" && entry) {
        // Send only what changed; visibility never changes here.
        const body: components["schemas"]["VaultDetailsInput"] = { expected_revision: entry.revision };
        if (title.trim() !== entry.title) body.title = title.trim();
        if (username !== entry.username) body.username = username;
        if (serviceId && serviceId !== entry.service_id) body.service_id = serviceId;
        if (!serviceId && (entry.service_id || privateService.trim() !== entry.service_name)) body.service_name = privateService.trim();
        if (entry.visibility === "assigned" && (subjectId !== entry.subject_id || subjectKind !== entry.subject_kind)) { body.subject_kind = subjectKind; body.subject_id = subjectId; }
        result = await api.PATCH(entryPath, { params: { path: { orgId, entryId: entry.id } }, body });
      } else result = await api.POST(entriesPath, { params: { path: { orgId } }, body: { ...metadata, kind, secret } });
      if (!live.current) return;
      if (result.error || !result.data) {
        const code = apiErrorCode(result.error);
        if (entry && result.response.status === 409) { setStale(true); setSecret(""); setShowSecret(false); setError("This credential changed while you were editing. Close and refresh to see the latest version."); }
        else if (code === "vault_recipient_without_access") setError("That person can't use Vault yet. They need the Vault role and a verified email. Choose someone else.");
        else if (code === "vault_details_forbidden") setError("Only Vault administrators can change the details of a shared credential.");
        else if (code === "vault_request_too_large") setError("That secret is too long. Secrets can be up to 16,384 characters.");
        else if (result.response.status >= 500) { setStale(true); setSecret(""); setShowSecret(false); setError("Could not confirm the save. Close and refresh before retrying."); }
        else setError("Could not save the credential. Check the fields and your access, then try again.");
        return;
      }
      setSecret(""); setShowSecret(false); onSaved();
    } catch { if (live.current) { setSecret(""); setShowSecret(false); setError("Could not confirm the save. Close and refresh before retrying."); setStale(true); } }
    finally { if (live.current) setBusy(false); }
  }
  const choices = subjectKind === "user" ? subjects?.users : subjects?.groups;
  const chosenGroup = subjectKind === "group" ? subjects?.groups.find(group => group.id === subjectId) : undefined;
  const withoutAccess = chosenGroup?.members_without_access ?? [];
  const reassigning = mode === "details" && entry?.visibility === "assigned" && !!subjectId && (subjectId !== entry.subject_id || subjectKind !== entry.subject_kind);
  const heading = mode === "configure" ? "Add details" : mode === "details" ? "Edit details" : mode === "rotate" ? "Change secret" : "Add credential";
  const submitLabel = mode === "configure" || mode === "details" ? "Save details" : mode === "rotate" ? "Save new version" : "Save credential";
  return <Modal placement="right" title={heading} size="wide" onDismiss={() => { if (!busy && !addingService) dismiss(); }} actions={<><Button variant="ghost" disabled={busy || addingService} onClick={dismiss}>Cancel</Button>{stale ? <Button onClick={() => { setSecret(""); onStale(); }}>Close and refresh</Button> : <Button type="submit" form="vault-credential-form" disabled={busy || addingService || (assigning && !subjects)}>{busy ? "Saving…" : submitLabel}</Button>}</>}>
    <form id="vault-credential-form" className="vault-form" onSubmit={submit} autoComplete="off">
      <ErrorText>{error}</ErrorText>
      {mode === "configure" && <p className="vault-help">Add a title and where this password is used. The saved password does not change and no new version is created.</p>}
      {mode === "details" && <p className="vault-help">Details changes do not create a new version. To change the secret itself, use Change secret.</p>}
      {mode === "rotate" && entry && <><p className="vault-readonly-title">{entry.title}</p><p className="vault-help">{entry.service_name} · {entry.visibility === "personal" ? "Personal · only you" : `Shared with ${entry.subject_name || "its recipients"}`}. Saving creates version {entry.current_version + 1}; earlier versions stay in history. Update the external service separately.</p></>}
      {mode !== "rotate" && <div className={mode === "new" ? "vault-form-grid" : undefined}><Field label="Title"><Input autoFocus maxLength={160} required value={title} onChange={event => setTitle(event.target.value)} placeholder="Production database" /></Field>{mode === "new" && <Field label="Credential type"><Select value={kind} onChange={event => setKind(event.target.value as typeof kind)}><option value="password">Password</option><option value="api_key">API key</option></Select></Field>}</div>}
      {editingVisibility && <Field label="Visibility"><Select value={visibility} onChange={event => { setVisibility(event.target.value as typeof visibility); setSubjectId(""); if (event.target.value === "assigned") setPrivateService(""); }}><option value="personal">Personal · only you</option>{canAssign && <option value="assigned">Assigned · administrators and recipients</option>}</Select></Field>}
      {mode === "details" && <p className="vault-help">{visibility === "personal" ? "Personal · only you. A personal credential can't be shared; to share it, add it again as Assigned." : "Assigned · administrators and recipients. It can be moved to another person or group, but not made personal."}</p>}
      {editingService && <>
        {serviceError ? <div className="vault-inline-error"><ErrorText>Could not load the service list.</ErrorText><Button type="button" variant="ghost" size="sm" onClick={onRetryServices}>Retry services</Button></div> : services === null ? <Loading size="inline" label="Loading services…" /> : <Field label="Service"><Select value={serviceId} onChange={event => { setServiceId(event.target.value); if (event.target.value) setPrivateService(""); }}><option value="">{visibility === "personal" ? "Use a private service name" : "Choose a service"}</option>{services.map(service => <option key={service.id} value={service.id}>{service.name}</option>)}</Select></Field>}
        {visibility === "personal" && !serviceId && <Field label="Private service name"><Input maxLength={120} required value={privateService} onChange={event => setPrivateService(event.target.value)} placeholder="Service or application" /></Field>}
        {canAssign && <div className="vault-service-create">{!showServiceForm ? <button type="button" className="vault-text-action" onClick={() => setShowServiceForm(true)}>Add a service to the catalog</button> : <><Field label="New service name"><Input maxLength={120} value={newService} onChange={event => setNewService(event.target.value)} placeholder="Reusable organization service" /></Field><div className="vault-inline-actions"><Button type="button" variant="ghost" size="sm" disabled={addingService || !newService.trim()} onClick={() => void addService()}>{addingService ? "Adding…" : "Add service"}</Button><Button type="button" variant="ghost" size="sm" disabled={addingService} onClick={onRetryServices}>Refresh list</Button><Button type="button" variant="ghost" size="sm" disabled={addingService} onClick={() => { setShowServiceForm(false); setNewService(""); }}>Cancel service</Button></div><p className="vault-help">Everyone in this organization can choose this service name. Each credential keeps its own access.</p></>}</div>}
        {assigning && <div className="vault-assignment">{subjectError ? <div className="vault-inline-error"><ErrorText>Could not load recipients.</ErrorText><Button type="button" variant="ghost" size="sm" onClick={() => setSubjectReload(value => value + 1)}>Retry recipients</Button></div> : !subjects ? <Loading size="inline" label="Loading recipients…" /> : <div className="vault-form-grid"><Field label="Assign to"><Select value={subjectKind} onChange={event => { setSubjectKind(event.target.value as typeof subjectKind); setSubjectId(""); }}><option value="user">User</option><option value="group">Group</option></Select></Field><Field label={subjectKind === "user" ? "User" : "Group"}><Select required value={subjectId} onChange={event => setSubjectId(event.target.value)}><option value="">Choose a {subjectKind}</option>{choices?.map(subject => <option key={subject.id} value={subject.id}>{subjectKind === "group" && typeof subject.member_count === "number" ? `${subject.name} (${plural(subject.member_count, "member")})` : subjectLabel(subject)}</option>)}</Select></Field></div>}
          {subjectKind === "user" && subjects && <p className="vault-help">Only people who can use Vault are listed: they need the Vault role and a verified email.</p>}
          {withoutAccess.length > 0 && <p className="vault-help" role="note">{plural(withoutAccess.length, "member")} of this group can't open it yet (no Vault role or unverified email): {withoutAccess.map(person => personLabel(person)).join(", ")}.</p>}
          {reassigning && <p className="vault-help" role="note">The new recipient can open every saved version. The current recipient loses access.</p>}
          <p className="vault-help">Recipients and Vault administrators can open every version and save a new secret. Only administrators change details or delete it.</p></div>}
        {visibility === "personal" && editingVisibility && <p className="vault-help">Only you can open this credential and its history. A private service name stays within this entry.</p>}
      </>}
      <Field label="Username (optional)"><Input name="vault-credential-username" autoComplete="off" maxLength={320} value={username} onChange={event => setUsername(event.target.value)} placeholder="Login name or email" /></Field>
      {withSecret && <>
        <Field label={entry ? "New secret" : "Secret"}><Input name="vault-credential-value" autoComplete="new-password" type={showSecret ? "text" : "password"} spellCheck={false} required maxLength={16384} value={secret} onChange={event => setSecret(event.target.value)} /></Field>
        <div className="vault-inline-actions">{kind === "password" && <Button type="button" variant="ghost" size="sm" onClick={generate}>Generate password</Button>}<Button type="button" variant="ghost" size="sm" disabled={!secret} onClick={() => setShowSecret(value => !value)}>{showSecret ? "Hide secret" : "Show secret"}</Button><span className="vault-help">{kind === "password" ? "24 characters · letters, numbers and symbols" : "Paste the API key issued by the service. Up to 16,384 characters."}</span></div>
      </>}
    </form>
  </Modal>;
}

type Pending = { version?: number; copy: boolean };
function revealMessage(code: string, status: number): string {
  switch (code) {
    case "current_password_required": return "Enter your current password to open a shared credential.";
    case "invalid_credentials": return "That password is incorrect. Try again.";
    case "reauthentication_rate_limited": return "Too many incorrect passwords. Try again in five minutes.";
    case "vault_reveal_rate_limited": return "You've opened a lot of secrets in a short time. Wait a minute and try again.";
    case "reauthentication_unavailable": return "To open shared credentials, set up an authenticator app first.";
    default: return status === 404 ? "This credential is no longer available to you. Close it and refresh Vault." : "Could not open this version. Try again.";
  }
}

function CredentialDetails({ orgId, entry, reauth, onDismiss, onRotate, onDetails, onConfigure, onDelete }: { orgId: string; entry: Entry; reauth?: Reauth; onDismiss: () => void; onRotate: () => void; onDetails: () => void; onConfigure: () => void; onDelete: () => void }) {
  const [history, setHistory] = useState<History | null>(null);
  const [historyError, setHistoryError] = useState(false);
  const [page, setPage] = useState(1);
  const [reload, setReload] = useState(0);
  const [revealed, setRevealed] = useState<Secret | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [password, setPassword] = useState("");
  const [stepUp, setStepUp] = useState<Pending | null>(null);
  const live = useRef(true);
  const request = useRef(0);
  const shared = entry.visibility === "assigned";
  const asksPassword = shared && !!reauth?.password;
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
  function close() { conceal(); setPassword(""); onDismiss(); }
  async function fetchSecret(version: number | undefined, copy: boolean, id: number): Promise<Secret> {
    const result = await api.POST(revealPath, { params: { path: { orgId, entryId: entry.id } }, body: { ...(version ? { version } : {}), purpose: copy ? "copy" : "reveal", ...(asksPassword && password ? { current_password: password } : {}) } });
    if (!live.current || id !== request.current) throw new VaultCopyError("cancelled");
    if (result.error || !result.data) throw new VaultRevealError(apiErrorCode(result.error) ?? "", result.response.status);
    return result.data;
  }
  async function accessSecret(version?: number, copy = false) {
    // V4: a shared credential asks for the password up front when the account has one.
    if (asksPassword && !password) { setError("Enter your current password to open a shared credential."); return; }
    const id = ++request.current;
    setBusy(true); setRevealed(null); setError(""); setNotice(""); setStepUp(null);
    try {
      // Copy is a new authorized, audited request too; an old reveal is never reused.
      if (copy) {
        let secret: Secret | undefined;
        const value = await copyRevealedSecret(async () => { secret = await fetchSecret(version, true, id); return secret.value; });
        scheduleClipboardClear(value);
        if (live.current && id === request.current) setNotice(`Version ${secret?.version ?? ""} copied. ${CLIPBOARD_NOTE}`);
      } else setRevealed(await fetchSecret(version, false, id));
    } catch (cause) {
      if (!live.current || id !== request.current) return;
      if (cause instanceof VaultRevealError) {
        if (cause.code === "mfa_step_up_required" || cause.code === "reauthentication_unavailable") setStepUp({ version, copy });
        if (cause.code !== "mfa_step_up_required") setError(revealMessage(cause.code, cause.status));
      } else if (!(cause instanceof VaultCopyError && cause.reason === "cancelled")) setError(copy ? "Could not copy the secret. Reveal it to select and copy it." : "Could not reveal this version. Try again.");
    } finally { if (live.current && id === request.current) setBusy(false); }
  }
  const currentVersion = history?.current_version ?? entry.current_version;
  return <Modal placement="right" title={entryTitle(entry)} size="wide" showClose onDismiss={close} actions={<><Button variant="ghost" onClick={close}>Close</Button>{entry.can_delete && <Button variant="danger" onClick={() => { conceal(); onDelete(); }}>Delete credential</Button>}{entry.configured === false ? entry.can_edit && <Button onClick={() => { conceal(); onConfigure(); }}>Add details</Button> : <>{entry.can_edit_details && <Button variant="ghost" onClick={() => { conceal(); onDetails(); }}>Edit details</Button>}{entry.can_edit && <Button onClick={() => { conceal(); onRotate(); }}>Change secret</Button>}</>}</>}>
    <div className="vault-detail"><dl className="vault-detail-facts"><div><dt>Service</dt><dd>{serviceLabel(entry)}</dd></div><div><dt>Type</dt><dd>{entry.kind === "api_key" ? "API key" : "Password"}</dd></div><div><dt>Username</dt><dd>{entry.username || "Not set"}</dd></div><div><dt>Access</dt><dd>{entry.visibility === "personal" ? "Personal · only you" : `Shared · ${entry.subject_name || "recipients"} and Vault administrators`}</dd></div></dl>
      <section className="vault-secret-panel" aria-label="Credential secret"><div className="vault-section-heading"><h3>{revealed ? `Version ${revealed.version}${revealed.version === currentVersion ? " · current" : " · earlier version"}` : "Secret hidden"}</h3>{revealed && <button type="button" className="vault-text-action" onClick={conceal}>Hide secret</button>}</div><code className="vault-secret-value" aria-label={revealed ? "Revealed secret" : "Hidden secret"}>{revealed?.value ?? "••••••••••••••••"}</code>{revealed && <p className="vault-help">{revealed.version === currentVersion ? "Username" : "Username saved with this version"}: {revealed.username || "Not set"}. Hidden automatically after 30 seconds.</p>}
        {shared && <div className="vault-stepup"><p className="vault-help">This is a shared credential, so opening or copying it asks you to confirm it is you{reauth?.mfa ? " (your password and a recent two-factor check)" : ""}.</p>{asksPassword && <Field label="Current password"><Input type="password" autoComplete="current-password" value={password} disabled={busy} onChange={event => setPassword(event.target.value)} /></Field>}</div>}
        <div className="vault-inline-actions"><Button variant="ghost" size="sm" disabled={busy} onClick={() => void accessSecret()}>{busy ? "Checking access…" : "Reveal current secret"}</Button><Button variant="ghost" size="sm" disabled={busy} onClick={() => void accessSecret(revealed?.version, true)}>{revealed ? `Copy version ${revealed.version}` : "Copy current secret"}</Button></div>
        {stepUp && <InlineTerminalMfa action="Open a shared Vault credential" freshnessSeconds={300} onVerified={() => { const pending = stepUp; setStepUp(null); setError(""); void accessSecret(pending.version, pending.copy); }} onCancel={() => { setStepUp(null); setError(""); }} />}
        <ErrorText>{error}</ErrorText>{notice && <p role="status" className="vault-help">{notice}</p>}</section>
      <section className="vault-history" aria-label="Version history"><div className="vault-section-heading"><h3>Version history{history && <span className="vault-count">{history.total}</span>}</h3><RefreshButton label="Refresh version history" onClick={() => { conceal(); setReload(value => value + 1); }} /></div><p className="vault-help">A new version is saved only when the secret changes. Revealing or copying a value is recorded in the audit log.</p>
        {historyError ? <div className="vault-inline-error"><ErrorText>Could not load version history.</ErrorText><Button variant="ghost" size="sm" onClick={() => setReload(value => value + 1)}>Retry history</Button></div> : !history ? <Loading label="Loading history…" /> : <><div className="beam-table-wrap"><table className="beam-inventory-table vault-history-table"><caption className="sr-only">Credential version history</caption><thead><tr><th>Version</th><th>Changed by</th><th>Saved</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{history.versions.map(version => <tr key={version.version}><td>{version.version}{version.version === history.current_version && <span className="vault-cell-note">Current</span>}</td><td>{personLabel({ name: version.changed_by_name, email: version.changed_by_email })}</td><td><time dateTime={version.created_at}>{dateLabel(version.created_at)}</time></td><td><div className="vault-inline-actions"><Button variant="ghost" size="sm" disabled={busy} aria-label={`Reveal version ${version.version}`} onClick={() => void accessSecret(version.version)}>Reveal</Button><Button variant="ghost" size="sm" disabled={busy} aria-label={`Copy version ${version.version} from history`} onClick={() => void accessSecret(version.version, true)}>Copy</Button></div></td></tr>)}</tbody></table></div><div className="vault-history-pagination"><span>{plural(history.total, "version")}</span><Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => { conceal(); setPage(value => value - 1); }}>Previous versions</Button><Button variant="ghost" size="sm" disabled={page * 10 >= history.total} onClick={() => { conceal(); setPage(value => value + 1); }}>Next versions</Button></div></>}
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
  const versions = entry.current_version === 1 ? "its saved version" : `all ${entry.current_version} saved versions`;
  return <Modal placement="right" title="Delete credential" danger onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button><Button variant="danger" disabled={busy || uncertain} onClick={() => void remove()}>{busy ? "Deleting…" : "Confirm deletion"}</Button></>}><div className="vault-form"><ErrorText>{error}</ErrorText><p>Permanently delete <strong>{entryTitle(entry)}</strong> and {versions} from Vault{entry.visibility === "assigned" ? " for every recipient" : ""}?</p><p>This cannot be undone. The password or API key in the external service will remain unchanged. Audit records remain available.</p></div></Modal>;
}
