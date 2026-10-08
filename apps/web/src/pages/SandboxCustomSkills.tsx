import "../resource-summary.css";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import * as Dialog from "@radix-ui/react-dialog";
import ReactMarkdown from "react-markdown";
import { api, apiErrorMessage } from "../lib/api";
import type { components } from "@tunnex/shared";
import { useOrg } from "../lib/useOrg";
import { Button, ErrorText, Field, Input, Loading, Select } from "../components/ui";
import { SandboxHeader } from "../components/SandboxChrome";
import { Logo } from "../brand";

type CustomSkill = components["schemas"]["SandboxCustomSkill"];
const example = "---\nname: my-skill\ndescription: What this skill helps me do\n---\n\nWrite your instructions here.\n";
function inspectDocument(document: string) {
 const bytes = new TextEncoder().encode(document).length;
 const lines = document.replace(/\r\n/g, "\n").split("\n");
 const end = lines.indexOf("---", 1);
 const metadata: Record<string, string> = {};
 let error = "";
 if (bytes > 32768) error = "Skill documents are limited to 32 KiB.";
 else if (!bytes || document.includes("\0") || lines[0] !== "---" || end < 0 || end >= 12) error = "Start with --- front matter containing name and description, then close it with ---.";
 else {
  for (const line of lines.slice(1, end)) {
   const colon = line.indexOf(":"); const key = line.slice(0, colon).trim(); let value = line.slice(colon + 1).trim();
   if (colon < 0 || !["name", "description"].includes(key) || key in metadata || !value) { error = "Front matter supports one name and one description. Both are required."; break; }
   if (value.startsWith('"')) { try { const parsed: unknown = JSON.parse(value); if (typeof parsed !== "string") throw new Error(); value = parsed; } catch { error = "Use plain scalar text or a valid double-quoted value in front matter."; break; } }
   else if (/["'\[\]{}&*!>|#]/.test(value)) { error = "Use plain scalar text or a valid double-quoted value in front matter."; break; }
   metadata[key] = value;
  }
  if (!error && (!metadata.name || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(metadata.name) || metadata.name.length > 64)) error = "Name must use lowercase words separated by hyphens, up to 64 characters.";
  if (!error && (!metadata.description || new TextEncoder().encode(metadata.description).length > 256 || /[\x00-\x1f\x7f]/.test(metadata.description))) error = "Add a description of up to 256 bytes without control characters.";
  if (!error && !lines.slice(end + 1).join("\n").trim()) error = "Add Markdown instructions after the front matter.";
 }
 return { bytes, error, name: metadata.name ?? "Untitled skill", description: metadata.description ?? "", body: end > 0 ? lines.slice(end + 1).join("\n") : document };
}
export default function SandboxCustomSkillsPage() {
 const { org, loading, failed } = useOrg(); const { skillId } = useParams();
 if (loading) return <Loading />;
 if (failed || !org) return <ErrorText>Organization could not be loaded.</ErrorText>;
 return <Editor key={`${org.id}/${skillId ?? "new"}`} orgId={org.id} skillId={skillId} />;
}
function Editor({ orgId, skillId }: { orgId: string; skillId?: string }) {
 const navigate = useNavigate(); const active = useRef(true); const importEpoch = useRef(0); const mutation = useRef(false);
 const [items, setItems] = useState<CustomSkill[]>([]); const [current, setCurrent] = useState<CustomSkill | null>(null);
 const [document, setDocument] = useState(example); const [loading, setLoading] = useState(true); const [pending, setPending] = useState(false);
 const [error, setError] = useState<string | null>(null); const [loadError, setLoadError] = useState<string | null>(null); const [revision, setRevision] = useState(0);
 const [open, setOpen] = useState(!!skillId); const [preview, setPreview] = useState(false); const [query, setQuery] = useState(""); const [sort, setSort] = useState("recent");
 const idempotency = useRef<{ document: string; key: string } | null>(null);
 const fileInput = useRef<HTMLInputElement>(null);
 const inspection = inspectDocument(document);
 useEffect(() => { active.current = true; return () => { active.current = false; importEpoch.current++; }; }, []);
 useEffect(() => { let live = true; setLoading(true); setLoadError(null); setError(null);
  void Promise.all([
   api.GET("/api/v1/organizations/{orgId}/sandbox-custom-skills", { params: { path: { orgId } } }),
   skillId ? api.GET("/api/v1/organizations/{orgId}/sandbox-custom-skills/{skillId}", { params: { path: { orgId, skillId } } }) : Promise.resolve(null),
  ]).then(([list, detail]) => {
   if (!live) return;
   const failure = list.error ?? detail?.error;
   if (failure) setLoadError(apiErrorMessage(failure, "Private skills could not be loaded."));
   else if (!list.data || (skillId && !detail?.data)) setLoadError("Private skills could not be loaded.");
   else { setItems(list.data.items); setCurrent(detail?.data ?? null); if (detail?.data) setDocument(detail.data.document); }
  }).catch(() => { if (live) setLoadError("Private skills could not be loaded."); }).finally(() => { if (live) setLoading(false); });
  return () => { live = false; };
 }, [orgId, skillId, revision]);
 function close() { if (pending) return; importEpoch.current++; setOpen(false); setError(null); if (skillId) navigate("/sandboxes/skills"); }
 async function importFile(file?: File) {
  const epoch = ++importEpoch.current; if (!file) return;
  if (file.size === 0 || file.size > 32768 || !file.name.toLowerCase().endsWith(".md")) { setError("Choose one UTF-8 .md file up to 32 KiB."); return; }
  try {
   const buffer = await new Promise<ArrayBuffer>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => reader.result instanceof ArrayBuffer ? resolve(reader.result) : reject(new Error("invalid file")); reader.onerror = () => reject(new Error("read failed")); reader.readAsArrayBuffer(file); });
   const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
   if (active.current && epoch === importEpoch.current) { setDocument(text); setPreview(false); setError(null); }
  } catch { if (active.current && epoch === importEpoch.current) setError("The skill file could not be read as UTF-8 text."); }
 }
 async function save(event: FormEvent) {
  event.preventDefault(); if (mutation.current || loading || loadError || (skillId && !current)) return;
  if (inspection.error) { setError(inspection.error); setPreview(false); return; }
  if (idempotency.current?.document !== document) idempotency.current = { document, key: crypto.randomUUID() };
  mutation.current = true; setPending(true); setError(null);
  try {
   const result = current
    ? await api.PUT("/api/v1/organizations/{orgId}/sandbox-custom-skills/{skillId}", { params: { path: { orgId, skillId: current.id } }, body: { document, generation: current.generation } })
    : await api.POST("/api/v1/organizations/{orgId}/sandbox-custom-skills", { params: { path: { orgId }, header: { "Idempotency-Key": idempotency.current.key } }, body: { document } });
   if (!active.current) return;
   if (result.error) setError(apiErrorMessage(result.error, "Skill save failed. Refresh if the version changed."));
   else if (result.data) { setCurrent(result.data); setDocument(result.data.document); if (!skillId) navigate(`/sandboxes/skills/${result.data.id}`); else setRevision(value => value + 1); }
   else setError("Save could not be confirmed. Refresh before retrying.");
  } catch { if (active.current) setError(current ? "Save could not be confirmed. Refresh before retrying." : "Add could not be confirmed. Retry the same document to preserve the request."); }
  finally { mutation.current = false; if (active.current) setPending(false); }
 }
 async function remove() {
  if (!current || mutation.current || !window.confirm("Delete this private skill? This disables all its revisions for existing sandboxes and withdraws their access. Their saved instruction content is not replaced.")) return;
  mutation.current = true; setPending(true); setError(null);
  try { const result = await api.DELETE("/api/v1/organizations/{orgId}/sandbox-custom-skills/{skillId}", { params: { path: { orgId, skillId: current.id }, query: { generation: current.generation } } });
   if (!active.current) return; if (result.error) setError(apiErrorMessage(result.error, "Delete failed. Refresh before retrying.")); else navigate("/sandboxes/skills");
  } catch { if (active.current) setError("Delete could not be confirmed. Refresh before retrying."); } finally { mutation.current = false; if (active.current) setPending(false); }
 }
 const visible = items.filter(item => `${item.name} ${item.description} ${item.generation}`.toLowerCase().includes(query.trim().toLowerCase())).sort((a, b) => sort === "name" ? a.name.localeCompare(b.name) : new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
 function add(importing = false) { setOpen(true); setPreview(false); setError(null); if (importing) window.setTimeout(() => fileInput.current?.click(), 0); }
 return <div className="sb-workspace">
  <SandboxHeader section="skills" title="Skills" subtitle="Private, versioned instructions." actions={<><Button variant="ghost" disabled={loading || pending} onClick={() => setRevision(value => value + 1)}>Refresh</Button><Button variant="ghost" disabled={loading || !!loadError} onClick={() => add(true)}>Import skill</Button><Button className="sb-primary" disabled={loading || !!loadError} onClick={() => add()}>Add custom skill <span aria-hidden>+</span></Button></>} />
  {loading ? <Loading /> : loadError ? <section className="sb-panel sb-error"><h2>Unable to load private skills</h2><ErrorText>{loadError}</ErrorText><p className="sb-help mt-3">Your library could not be verified. Retry to check your current access.</p><Button variant="ghost" className="mt-4" onClick={() => setRevision(value => value + 1)}>Retry</Button></section> : <>
   <div className="sb-skill-toolbar"><div className="sb-summary"><div><strong>{items.length}</strong><span>private skills</span></div><span className="sb-summary-gate">Only you can use these</span></div><div><Input aria-label="Search private skills" placeholder="Search name, description or revision…" value={query} onChange={e => setQuery(e.target.value)} /><Select aria-label="Sort private skills" width="auto" value={sort} onChange={e => setSort(e.target.value)}><option value="recent">Newest first</option><option value="name">Name A–Z</option></Select></div></div>
   <div className="sb-console-surface"><section aria-label="My private skills"><div className="sb-section-title"><h2>My private skills</h2><span>{visible.length} of {items.length}</span></div>
   {!items.length ? <div className="sb-empty-inline"><span className="sb-skill-document" aria-hidden>MD</span><div><h2>No custom skills yet.</h2><p>Add or import a SKILL.md document.</p></div></div> : visible.length ? <div className="sb-resource-list" role="table" aria-label="Private skills"><div className="sb-skill-row sb-list-head" role="row"><span role="columnheader">Skill</span><span role="columnheader">Revision</span><span role="columnheader">Added</span><span role="columnheader" className="sr-only">Actions</span></div>{visible.map(item => <div className="sb-skill-row" role="row" key={item.id}><div className="sb-row-identity" role="cell"><span className="sb-skill-document" aria-hidden>MD</span><div><h3>{item.name}</h3><p>{item.description}</p></div></div><div role="cell"><span className="sb-skill-revision">rev {item.generation}</span></div><time role="cell" dateTime={item.created_at}>{new Date(item.created_at).toLocaleDateString()}</time><div role="cell" className="sb-row-action"><Link to={`/sandboxes/skills/${item.id}`} className="sb-inline-link" aria-label={`Edit ${item.name}`}>Open & edit <span aria-hidden>→</span></Link></div></div>)}</div> : <div className="sb-empty-inline"><div><h2>No skills match your search</h2><p>Try a name, description or revision number.</p><Button variant="ghost" className="mt-2" onClick={() => setQuery("")}>Clear search</Button></div></div>}
   </section><details className="sb-catalog sb-skill-policy"><summary><span><strong>Private, versioned instructions</strong><span className="sb-muted">Your library · no additional access</span></span><span className="sb-disclosure-label">How skills work</span></summary><div className="sb-catalog-body"><p className="sb-help">Owned by you within this organization. Updates create immutable revisions; existing sandboxes keep their selection. Skills grant no additional network access, privileges, mounts or secrets.</p></div></details></div>
  </>}
  <Dialog.Root open={open} onOpenChange={value => { if (!value) close(); }}><Dialog.Portal><Dialog.Overlay className="sb-dialog-overlay"><Dialog.Content className="sb-dialog sb-skill-dialog" aria-describedby="sb-skill-description" onEscapeKeyDown={event => { if (pending) event.preventDefault(); }} onPointerDownOutside={event => event.preventDefault()}>
   <div className="sb-dialog-header"><div><div className="sb-eyebrow"><Logo size={17} /><span>/ PRIVATE SKILL</span></div><Dialog.Title>{skillId ? "Edit private skill" : "Add custom skill"}</Dialog.Title></div><Dialog.Close className="sb-dialog-close" disabled={pending} aria-label="Close skill editor">×</Dialog.Close></div>
   <form onSubmit={event => void save(event)}><div className="sb-wizard-body sb-skill-editor-body">
    <Dialog.Description id="sb-skill-description" className="sb-help">Write or import SKILL.md · 32 KiB max.</Dialog.Description>
    {loading ? <Loading /> : loadError ? <ErrorText>{loadError}</ErrorText> : <>
     <div className="sb-editor-toolbar"><div role="tablist" aria-label="Skill document view"><button id="sb-write-tab" tabIndex={preview ? -1 : 0} onKeyDown={event => { if (["ArrowRight", "ArrowLeft"].includes(event.key)) { event.preventDefault(); setPreview(true); window.requestAnimationFrame(() => globalThis.document.getElementById("sb-preview-tab")?.focus()); } }} type="button" role="tab" aria-selected={!preview} aria-controls="sb-skill-write" onClick={() => setPreview(false)}>Write</button><button id="sb-preview-tab" tabIndex={preview ? 0 : -1} onKeyDown={event => { if (["ArrowRight", "ArrowLeft"].includes(event.key)) { event.preventDefault(); setPreview(false); window.requestAnimationFrame(() => globalThis.document.getElementById("sb-write-tab")?.focus()); } }} type="button" role="tab" aria-selected={preview} aria-controls="sb-skill-preview" onClick={() => setPreview(true)}>Preview</button></div><div><label className="sb-file-label" htmlFor="sb-skill-import">Import SKILL.md</label><input id="sb-skill-import" ref={fileInput} type="file" accept=".md,text/markdown,text/plain" disabled={pending} onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ""; }} /><span>{(inspection.bytes / 1024).toFixed(1)} / 32 KiB</span></div></div>
     {!preview ? <div role="tabpanel" aria-labelledby="sb-write-tab" id="sb-skill-write"><Field label="SKILL.md document"><textarea required rows={14} disabled={pending} className="sb-editor" value={document} onChange={event => { importEpoch.current++; setDocument(event.target.value); setError(null); }} /></Field></div> : <div id="sb-skill-preview" aria-labelledby="sb-preview-tab" role="tabpanel" className="sb-preview"><div><span className="sb-overline">DOCUMENT PREVIEW</span><h3>{inspection.name}</h3><p className="sb-help">{inspection.description}</p></div><div className="sb-markdown"><ReactMarkdown skipHtml components={{ img: ({ alt }) => <span className="sb-help">Image reference: {alt || "external image"}</span> }}>{inspection.body}</ReactMarkdown></div></div>}
     <div className={`sb-validation ${inspection.error ? "sb-validation-error" : ""}`}>{inspection.error || "Valid format · verified again on save."}</div>
     {current && <section className="sb-revision-note"><h3>Current revision · {current.generation}</h3><p>Revision {current.generation}. Saving creates a new immutable revision; existing sandboxes keep their selected revision.</p><details><summary>Revision identity</summary><dl className="tnx-resource-facts tnx-resource-facts-single"><div><dt>Revision ID</dt><dd><code>{current.revision_id}</code></dd></div><div><dt>Content digest</dt><dd><code>{current.digest}</code></dd></div></dl><p>Earlier revision documents are not available in this view.</p></details></section>}
     <p className="sb-help mt-4">Instructions only; never executed here. Keep credentials out of skill text.</p>
    </>}{error && <div className="mt-4"><ErrorText>{error}</ErrorText></div>}
   </div><div className="sb-dialog-footer"><div><Button type="button" variant="ghost" disabled={pending} onClick={close}>Cancel</Button>{current && <Button variant="danger" type="button" disabled={pending} onClick={() => void remove()}>Delete private skill</Button>}</div><Button className="sb-primary" type="submit" disabled={pending || loading || !!loadError || (!!skillId && !current)}>{pending ? "Saving…" : current ? "Save new revision" : "Add private skill"}</Button></div></form>
  </Dialog.Content></Dialog.Overlay></Dialog.Portal></Dialog.Root>
 </div>;
}
