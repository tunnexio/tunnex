import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams, useLocation } from "react-router-dom";
import { api, apiErrorMessage, type Sandbox, type SandboxTemplate, type SandboxSkill, type SandboxScope, type SandboxCreationStatus, type SandboxImageProfile } from "../lib/api";
import { Button as LinkButton } from "../components/ui/button";
import { ResourceSummary } from "../components/ResourceSummary";
import { useOrg } from "../lib/useOrg";
import * as Dialog from "@radix-ui/react-dialog";
import { SandboxHeader, RuntimeMark, RuntimeSpecs, SandboxStatus, WorkflowNote, isConnectable, remainingLifetime } from "../components/SandboxChrome";
import { sandboxConnectCommand } from "../lib/sandboxConnection";
import { sandboxPublicKeys } from "../lib/sandboxPublicKeys";
import { SandboxBlockedReasons } from "../components/SandboxAvailability";
import { Logo } from "../brand";
import { Button, ErrorText, Field, Input, Loading, Select } from "../components/ui";

import { SavedSSHKeyPicker } from "../components/SavedSSHKeyPicker";
import { SandboxCandidateProfiles } from "../components/SandboxImageProfiles";
import { SandboxTerminalPicker, type SandboxTerminalSelection } from "../components/SandboxTerminalPicker";

type Inventory = { candidates?: SandboxImageProfile[]; status?: SandboxCreationStatus; items: Sandbox[]; templates: SandboxTemplate[]; skills: SandboxSkill[]; available: boolean; skillsAvailable: boolean; next?: string };
function useInventory(orgId: string) {
 const [data, setData] = useState<Inventory | null>(null);
 const [error, setError] = useState<string | null>(null);
 const [revision, setRevision] = useState(0);
 const epoch = useRef(0);
 const [loadingMore, setLoadingMore] = useState(false);
 useEffect(() => {
  let active = true; epoch.current++; setData(null); setError(null); setLoadingMore(false);
  void Promise.all([
   api.GET("/api/v1/organizations/{orgId}/sandboxes", { params: { path: { orgId } } }),
   api.GET("/api/v1/organizations/{orgId}/sandbox-templates", { params: { path: { orgId } } }),
   api.GET("/api/v1/organizations/{orgId}/sandbox-skills", { params: { path: { orgId } } }),
  ]).then(([list, templates, skills]) => {
   if (!active) return;
   const failure = list.error ?? templates.error ?? skills.error;
   if (failure) { setError(apiErrorMessage(failure, "Sandbox information could not be loaded.")); return; }
   if (!list.data || !templates.data || !skills.data) { setError("Sandbox information could not be loaded."); return; }
   setData({ candidates: templates.data.candidate_profiles, status: list.data.creation_status, items: list.data.items, templates: templates.data.items, skills: skills.data.items, available: list.data.create_available, skillsAvailable: skills.data.configuration_available, next: list.data.next_cursor });
  }).catch(() => { if (active) setError("Sandbox information could not be loaded."); });
  return () => { active = false; epoch.current++; };
 }, [orgId, revision]);
 async function loadMore() {
  if (!data?.next || loadingMore) return;
  const current = epoch.current; setLoadingMore(true);
  try {
   const result = await api.GET("/api/v1/organizations/{orgId}/sandboxes", { params: { path: { orgId }, query: { cursor: data.next } } });
   if (epoch.current !== current) return;
   if (result.error) setError(apiErrorMessage(result.error, "More sandboxes could not be loaded."));
   else if (result.data) { const page = result.data; setData(previous => previous ? { ...previous, items: [...previous.items, ...page.items.filter(item => !previous.items.some(existing => existing.id === item.id))], next: page.next_cursor } : null); }
  } catch { if (epoch.current === current) setError("More sandboxes could not be loaded."); }
  finally { if (epoch.current === current) setLoadingMore(false); }
 }
 return { data, error, reload: () => setRevision(r => r + 1), loadMore, loadingMore };
}

function ScopeList({ scopes }: { scopes: SandboxScope[] }) {
 return scopes.length ? <ul className="space-y-2">{scopes.map((s, i) => <li key={i}><code>{s.cidr}</code> · {s.protocol.toUpperCase()} · {s.port_low === 0 ? "all ports" : s.port_low === s.port_high ? `port ${s.port_low}` : `ports ${s.port_low}–${s.port_high}`}</li>)}</ul> : <p>No outbound network access requested.</p>;
}
function OrgPage({ mode }: { mode: "list" | "create" | "detail" }) {
 const { org, loading, failed } = useOrg();
 if (loading) return <Loading />;
 if (failed) return <ErrorText>Organizations could not be loaded.</ErrorText>;
 if (!org) return <p>Select an organization to view sandboxes.</p>;
 return <Workspace key={`${org.id}:${mode}`} orgId={org.id} mode={mode} />;
}
export function SandboxesPage() { return <OrgPage mode="list" />; }
export function SandboxCreatePage() { return <OrgPage mode="create" />; }
export function SandboxDetailPage() { return <OrgPage mode="detail" />; }

function Workspace({ orgId, mode }: { orgId: string; mode: "list" | "create" | "detail" }) {
 const { data, error, reload, loadMore, loadingMore } = useInventory(orgId);
 const { sandboxId } = useParams();
 const [now, setNow] = useState(Date.now());
 useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 60000); return () => window.clearInterval(timer); }, []);
 if (error && !data) return <div className="sb-workspace"><SandboxHeader title="Sandboxes" subtitle="Your private developer workspaces." /><section className="sb-panel sb-error"><h2>Unable to load sandbox information</h2><ErrorText>{error}</ErrorText><p className="sb-help mt-3">Retry, or ask an administrator to check your access.</p><Button variant="ghost" className="mt-4" onClick={reload}>Retry</Button></section></div>;
 if (!data) return <Loading />;
 if (mode === "detail" && sandboxId) return <Detail key={sandboxId} orgId={orgId} id={sandboxId} inventory={data} now={now} />;
 return <><InventoryView data={data} now={now} error={error} reload={reload} loadMore={loadMore} loadingMore={loadingMore} />{mode === "create" && <Create orgId={orgId} inventory={data} />}</>;
}

function CreateLink({ enabled, children = "Create sandbox", templateId }: { enabled: boolean; children?: string; templateId?: string }) {
 return enabled ? <LinkButton className="sb-primary" asChild><Link to={`/sandboxes/new${templateId ? `?template=${encodeURIComponent(templateId)}` : ""}`}>{children}<span aria-hidden>↗</span></Link></LinkButton> : <Button className="sb-primary" disabled>{children}<span aria-hidden>↗</span></Button>;
}
function InventoryView({ data, now, error, reload, loadMore, loadingMore }: { data: Inventory; now: number; error: string | null; reload: () => void; loadMore: () => Promise<void>; loadingMore: boolean }) {
 const location = useLocation(); const navigate = useNavigate();
 useEffect(() => { if (location.state?.sandboxDialogClosed) { (window.document.querySelector<HTMLElement>('.sb-header-actions a[href="/sandboxes/new"]') ?? window.document.querySelector<HTMLElement>(".sb-header-actions button"))?.focus(); navigate(location.pathname, { replace: true, state: null }); } }, [location, navigate]);
 const canCreate = data.available && data.templates.length > 0;
 return <div className="sb-workspace">
  <SandboxHeader title="Sandboxes" subtitle="Private workspaces over SSH." actions={<><Button variant="ghost" onClick={reload}>Refresh</Button>{data.status?.can_admin && canCreate && <LinkButton asChild variant="outline"><Link to="/sandboxes/setup">Sandbox setup</Link></LinkButton>}<CreateLink enabled={canCreate} /></>} />
  <div className="sb-summary" aria-label="Sandbox inventory summary"><div><strong>{data.items.length}{data.next ? "+" : ""}</strong><span>workspaces loaded</span></div><div><strong>{data.items.filter(item => isConnectable(item, now)).length}</strong><span>connection ready</span></div><div><strong>{data.templates.length}</strong><span>environments</span></div>{canCreate && <span className="sb-summary-gate">Creation enabled</span>}</div>
  {(!data.available || !data.templates.length) && <Availability available={data.available} templates={data.templates.length} status={data.status} />}
  {error && <ErrorText>{error}</ErrorText>}
  <div className="sb-console-surface">
  <section aria-label="Your sandboxes" className="sb-inventory"><div className="sb-section-title"><h2>Your sandboxes</h2><span>Status on refresh</span></div>
   {data.items.length === 0 ? <div className="sb-empty-inline"><RuntimeMark /><div><h2>No sandboxes yet.</h2><p>Inventory loaded. Create a workspace to get started.</p><Link to="/sandboxes/skills" className="sb-inline-link">Explore skills →</Link></div></div> : <div className="sb-resource-list" role="table" aria-label="Workspace inventory"><div className="sb-workspace-row sb-list-head" role="row"><span role="columnheader">Workspace</span><span role="columnheader">State</span><span role="columnheader">Memory</span><span role="columnheader">Lifetime</span><span role="columnheader">Private access</span><span role="columnheader" className="sr-only">Actions</span></div>{data.items.map(item => <WorkspaceRow key={item.id} item={item} template={data.templates.find(template => template.id === item.template_id)} now={now} />)}</div>}
   {data.next && <Button variant="ghost" className="mt-2" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? "Loading…" : "Load more"}</Button>}
  </section>
  <details className="sb-catalog" aria-label="Runtime environments"><summary><span><strong>Runtime environments</strong><span className="sb-muted">{data.templates.length} approved · {new Set(data.candidates?.map(profile => profile.name)).size} in preparation</span></span><span className="sb-disclosure-label">Browse catalog</span></summary><div className="sb-catalog-body">
   {data.templates.length ? <div className="sb-environment-list">{data.templates.map(template => <div key={template.id} className="sb-environment-row"><div className="sb-environment-identity"><RuntimeMark template={template} /><div><h3>{template.name}</h3><p>{template.memory_mib} MiB RAM · {Math.floor(template.max_ttl_seconds / 60)} min max · {template.maximum_scope.length} permitted network {template.maximum_scope.length === 1 ? "scope" : "scopes"}</p><span className="sb-muted">CPU / storage: not specified</span></div></div><CreateLink enabled={data.available} templateId={template.id} children="Configure" /><div className="sb-environment-details"><RuntimeSpecs template={template} /></div></div>)}</div> : <div className="sb-empty-inline"><div><h3>No approved environments</h3><p>No published runtime configurations are available. Check Sandbox setup for the next step.</p></div></div>}
   <SandboxCandidateProfiles profiles={data.candidates}/>
  </div></details>
  <WorkflowNote />
  </div>
 </div>;
}
function WorkspaceRow({ item, template, now }: { item: Sandbox; template?: SandboxTemplate; now: number }) {
 const connected = isConnectable(item, now);
 return <div className="sb-workspace-row" role="row"><div role="cell" className="sb-row-identity"><RuntimeMark template={template} /><div><h3><Link to={`/sandboxes/${item.id}`}>{item.name}</Link></h3><p>{template?.name ?? "Runtime configuration unavailable"}</p></div></div><div role="cell" className="sb-row-status"><SandboxStatus item={item} now={now} /></div><div role="cell" className="sb-row-resource"><span className="sb-mobile-label">Memory</span>{template ? `${template.memory_mib} MiB` : "Not specified"}</div><div role="cell" className="sb-row-lifetime"><span className="sb-mobile-label">Lifetime</span><span>{remainingLifetime(item.expires_at, now)}</span><time dateTime={item.expires_at}>Expires {new Date(item.expires_at).toLocaleString()}</time></div><div role="cell" className="sb-row-connection"><span>{connected ? "Private SSH available" : "Private SSH · not connected"}</span>{connected && <code>{item.connection!.address}</code>}</div><div role="cell" className="sb-row-action"><Link to={`/sandboxes/${item.id}`} className="sb-inline-link" aria-label={`Open ${item.name}`}>Open workspace <span aria-hidden>→</span></Link></div></div>;
}
function Availability({ available, templates, status }: { available: boolean; templates: number; status?: SandboxCreationStatus }) {
 return <section className="sb-notice"><details><summary><h2>{available ? "No approved environments" : "Creation unavailable"}</h2><span>View reasons</span></summary><SandboxBlockedReasons status={status} setupLink={false}/>{!templates && <p className="sb-help">No published runtime configurations are available.</p>}</details>{status?.can_admin && <Link to="/sandboxes/setup" className="sb-inline-link">Sandbox setup <span aria-hidden>→</span></Link>}</section>;
}

function Create({ orgId, inventory }: { orgId: string; inventory: Inventory }) {
 const navigate = useNavigate();
 const [query] = useSearchParams();
 const [step, setStep] = useState(0);
 const stepBody = useRef<HTMLDivElement>(null);
 useEffect(() => { if (step > 0) stepBody.current?.querySelector<HTMLElement>("h3")?.focus(); }, [step]);
 function dismiss() { if (!pending) navigate("/sandboxes", { state: { sandboxDialogClosed: true } }); }
 const [name, setName] = useState("");
 const [sshKeys, setSSHKeys] = useState("");
 const [terminal, setTerminal] = useState<SandboxTerminalSelection | null>(null);
 const requiresTerminal = inventory.status?.requires_terminal_device === true;
 const initialTemplate = inventory.templates.find(t => t.id === query.get("template")) ?? (!query.has("template") && inventory.templates.length === 1 ? inventory.templates[0] : undefined);
 const [templateId, setTemplateId] = useState(initialTemplate?.id ?? "");
 const [requested, setRequested] = useState<SandboxScope[]>([]);
 const [selectedSkills, setSelectedSkills] = useState<Record<string, Record<string, string>>>({});
 const creationInFlight = useRef(false);
 const [ttl, setTTL] = useState(Math.min(60, Math.floor((initialTemplate?.max_ttl_seconds ?? 3600) / 60)));
 const [pending, setPending] = useState(false);
 const [error, setError] = useState<string | null>(null);
 const active = useRef(true);
 useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
 const idempotency = useRef<{ intent: string; key: string } | null>(null);
 const template = inventory.templates.find(t => t.id === templateId);
 const steps = ["Environment", "Access", "Skills", "Review"];
 function chooseTemplate(id: string) {
  if (id === templateId) return;
  setTemplateId(id); setSelectedSkills({}); setRequested([]);
  const selected = inventory.templates.find(t => t.id === id);
  setTTL(Math.min(60, Math.floor((selected?.max_ttl_seconds ?? 3600) / 60)));
 }
 function validatedKeys() {
  const result = sandboxPublicKeys(sshKeys);
  if (result.error) { setError(result.error); return null; }
  return result.keys;
 }
 async function submit(event: FormEvent) {
  event.preventDefault(); if (creationInFlight.current || !inventory.available || !template || !name.trim()) return;
  if ((step === 1 || step === 3) && requiresTerminal && !terminal) { setError("Choose your terminal device before continuing."); return; }
  if (step < 3) { if (step === 1 && !validatedKeys()) return; setError(null); setStep(s => s + 1); return; }
  const publicKeys = validatedKeys(); if (!publicKeys) return;
  const body = { name: name.trim(), template_id: template.id, ...(requiresTerminal && terminal ? { terminal_device_id: terminal.id } : {}), requested_scope: requested, ttl_seconds: ttl * 60, ssh_public_keys: publicKeys, selected_skills: Object.keys(selectedSkills).sort().map(revision_id => ({ revision_id, configuration: selectedSkills[revision_id] })) };
  const intent = JSON.stringify(body);
  if (idempotency.current?.intent !== intent) idempotency.current = { intent, key: crypto.randomUUID() };
  creationInFlight.current = true; setPending(true); setError(null);
  try {
   const result = await api.POST("/api/v1/organizations/{orgId}/sandboxes", { params: { path: { orgId }, header: { "Idempotency-Key": idempotency.current.key } }, body });
   if (!active.current) return;
   if (result.error) setError(apiErrorMessage(result.error, "Sandbox request failed."));
   else if (result.data) navigate(`/sandboxes/${result.data.id}`);
   else setError("Sandbox creation could not be confirmed. Retry with the same configuration.");
  } catch { if (active.current) setError("Sandbox creation could not be confirmed. Retry with the same configuration."); }
  finally { creationInFlight.current = false; if (active.current) setPending(false); }
 }
 const eligibleSkills = inventory.skills.filter(skill => template && (skill.user_owned || template.allowed_skill_revision_ids?.includes(skill.id)));
 return <Dialog.Root open onOpenChange={open => { if (!open) dismiss(); }}><Dialog.Portal><Dialog.Overlay className="sb-dialog-overlay"><Dialog.Content className="sb-dialog" aria-describedby="sb-wizard-description" onOpenAutoFocus={event => { event.preventDefault(); stepBody.current?.querySelector<HTMLInputElement>("input")?.focus(); }} onCloseAutoFocus={event => event.preventDefault()} onEscapeKeyDown={event => { if (pending) event.preventDefault(); }} onPointerDownOutside={event => event.preventDefault()}>
  <div className="sb-dialog-header"><div><div className="sb-eyebrow"><Logo size={17} /><span>/ NEW WORKSPACE</span></div><Dialog.Title>Create sandbox</Dialog.Title></div><Dialog.Close className="sb-dialog-close" disabled={pending} aria-label="Close create sandbox">×</Dialog.Close></div>
  <div className="sb-wizard-steps" aria-label="Creation steps">{steps.map((label, index) => <button key={label} type="button" disabled={pending || index > step} aria-current={index === step ? "step" : undefined} onClick={() => { setError(null); setStep(index); }}><span>{index < step ? "✓" : `0${index + 1}`}</span>{label}</button>)}</div>
  <form onSubmit={event => void submit(event)}>
   <div className="sb-wizard-body" ref={stepBody} key={step}>
    <p id="sb-wizard-description" className="sr-only">Configure a private workspace in four steps. Nothing is created until you confirm on the review step.</p>
    {(!inventory.available || !inventory.templates.length) && <Availability available={inventory.available} templates={inventory.templates.length} status={inventory.status} />}
    {step === 0 && <><h3 tabIndex={-1}>Choose your environment</h3><p className="sb-help">Choose an approved runtime.</p><div className="sb-fields"><Field label="Sandbox name"><Input required maxLength={80} placeholder="e.g. api-development" value={name} onChange={event => setName(event.target.value)} /></Field><Field label="Runtime configuration"><Select required value={templateId} onChange={event => chooseTemplate(event.target.value)}><option value="">Select a configuration</option>{inventory.templates.map(t => <option key={t.id} value={t.id}>{t.name} · {t.memory_mib} MiB</option>)}</Select></Field>{template && <div className="sb-selected-runtime"><RuntimeMark template={template}/><div><RuntimeSpecs template={template}/></div></div>}</div></>}
    {step === 1 && <><h3 tabIndex={-1}>Resources & private access</h3><p className="sb-help">Public keys only. Keep your private key on your computer.</p><div className="sb-fields"><RuntimeSpecs template={template} /><Field label="Lifetime in minutes"><Input type="number" min={5} max={Math.floor((template?.max_ttl_seconds ?? 3600) / 60)} required value={ttl} onChange={e => setTTL(Number(e.target.value))} /></Field>{requiresTerminal && <SandboxTerminalPicker orgId={orgId} gatewayId={inventory.status?.terminal_gateway_id} value={terminal?.id ?? ""} onChange={setTerminal} />}<SavedSSHKeyPicker orgId={orgId} value={sshKeys} onChange={setSSHKeys} /><div><h3>Network access</h3><p className="sb-help mb-3">Choose permitted outbound access.</p>{template?.maximum_scope.map((scope, i) => <label key={i} className="sb-scope-choice mb-2"><input type="checkbox" checked={requested.includes(scope)} onChange={e => setRequested(old => e.target.checked ? [...old, scope] : old.filter(s => s !== scope))} /><span>{scope.cidr} · {scope.protocol.toUpperCase()} · {scope.port_low === 0 ? "all ports" : `${scope.port_low}–${scope.port_high}`}</span></label>)}<div className="sb-help mt-3"><ScopeList scopes={requested} /></div></div></div></>}
    {step === 2 && <><div className="sb-section-title"><h3 tabIndex={-1}>Skills</h3><Link to="/sandboxes/skills" target="_blank" rel="noopener" className="sb-inline-link">Manage private skills ↗</Link></div><p className="sb-help">Optional instructions. No additional access.</p>{!inventory.skillsAvailable && <p className="sb-help mt-4">Skill configuration is currently unavailable.</p>}{!eligibleSkills.length && <div className="sb-empty-catalog mt-5"><RuntimeMark /><div><h3>No skills for this environment</h3><p>Continue without skills.</p></div></div>}<div className="sb-fields">{eligibleSkills.map(skill => <div key={skill.id}><label className="sb-skill-choice"><input type="checkbox" disabled={!inventory.skillsAvailable} checked={Object.prototype.hasOwnProperty.call(selectedSkills, skill.id)} onChange={e => setSelectedSkills(old => { const next = { ...old }; if (e.target.checked) next[skill.id] = {}; else delete next[skill.id]; return next; })} /><span><strong>{skill.name} <span className="sb-help">· {skill.version}</span></strong><span className="sb-help">{skill.description}{skill.user_owned ? " · Private custom skill" : ""}</span></span></label>{Object.prototype.hasOwnProperty.call(selectedSkills, skill.id) && <div className="sb-skill-fields">{skill.fields.map(field => <Field key={field.key} label={`${skill.name}: ${field.label}`}><Select aria-label={`${skill.name}: ${field.label}`} required={field.required} disabled={!inventory.skillsAvailable} value={selectedSkills[skill.id][field.key] ?? ""} onChange={e => setSelectedSkills(old => { const config = { ...old[skill.id] }; if (e.target.value) config[field.key] = e.target.value; else delete config[field.key]; return { ...old, [skill.id]: config }; })}><option value="">Choose an option</option>{field.choices.map(choice => <option key={choice} value={choice}>{choice}</option>)}</Select></Field>)}</div>}</div>)}</div></>}
    {step === 3 && <><h3 tabIndex={-1}>Review & launch</h3><p className="sb-help">Confirm your configuration.</p><ResourceSummary title={name} description={template?.name}><RuntimeSpecs template={template} lifetime={`${ttl} minutes`} summary /><div className="mt-6"><dl className="tnx-resource-facts">{requiresTerminal && <div><dt>Terminal device</dt><dd>{terminal?.name ?? "Selection required"}</dd></div>}<div><dt>SSH access</dt><dd>{sshKeys.split(/\r?\n/).filter(line => line.trim()).length} public keys · private network</dd></div><div><dt>Skills</dt><dd>{Object.keys(selectedSkills).length ? inventory.skills.filter(skill => skill.id in selectedSkills).map(skill => skill.name).join(", ") : "None selected"}</dd></div><div className="tnx-resource-fact-wide"><dt>Requested network access</dt><dd><ScopeList scopes={requested} /></dd></div><div><dt>Connection</dt><dd>After policy & SSH readiness.</dd></div></dl></div><p className="sb-help mt-5">CPU / storage: not specified.</p></ResourceSummary></>}
    {error && <div className="mt-4"><ErrorText>{error}</ErrorText></div>}
   </div>
   <div className="sb-dialog-footer"><div><Button type="button" variant="ghost" disabled={pending} onClick={() => { if (step) { setError(null); setStep(s => s - 1); } else dismiss(); }}>{step ? "Back" : "Cancel"}</Button><p className="self-center">Step {step + 1} of 4 · {step === 3 ? "Ready to review" : "Nothing created yet"}</p></div><Button key={step} className="sb-primary" type="submit" onClick={event => { if (event.detail > 1) event.preventDefault(); }} disabled={pending || !inventory.available || !template || !name.trim()}>{pending ? "Creating…" : step === 3 ? "Create sandbox" : "Next"}<span aria-hidden>→</span></Button></div>
  </form>
 </Dialog.Content></Dialog.Overlay></Dialog.Portal></Dialog.Root>;
}

function Detail({ orgId, id, inventory, now }: { orgId: string; id: string; inventory: Inventory; now: number }) {
 const [item, setItem] = useState<Sandbox | null>(null);
 const [error, setError] = useState<string | null>(null);
 const [revision, setRevision] = useState(0);
 const [pending, setPending] = useState(false);
 useEffect(() => { let active = true; setItem(null); setError(null); void api.GET("/api/v1/organizations/{orgId}/sandboxes/{sandboxId}", { params: { path: { orgId, sandboxId: id } } }).then(result => { if (!active) return; if (result.error) setError(apiErrorMessage(result.error, "Sandbox request failed.")); else if (result.data) setItem(result.data); else setError("Sandbox could not be loaded."); }).catch(() => { if (active) setError("Sandbox could not be loaded."); }); return () => { active = false; }; }, [orgId, id, revision]);
 // Creation quota applies to new identities. Resume uses lifecycle state and
 // existing runtime/org signals; the action endpoint rechecks current authority.
 const resumeAllowed = item?.desired_state === "stopped" && item.observed_state === "stopped"
  && remainingLifetime(item.expires_at, now) !== "Expired"
  && (!inventory.status || (inventory.status.runtime_ready && !inventory.status.blocked_reasons.some(reason =>
   ["organization_disabled", "policy_not_enforcing", "runtime_binding_unavailable", "runtime_not_ready"].includes(reason))));
 async function action(desired: "started" | "stopped" | "deleted") {
  if (!item || pending || (desired === "started" && !resumeAllowed)) return;
  setPending(true); setError(null);
  try { const result = await api.POST("/api/v1/organizations/{orgId}/sandboxes/{sandboxId}/actions", { params: { path: { orgId, sandboxId: id } }, body: { generation: item.generation, desired_state: desired } }); if (result.error) setError(apiErrorMessage(result.error, "Sandbox request failed.")); else if (result.data) setItem(result.data); } catch { setError("The action could not be confirmed. Refresh before retrying."); } finally { setPending(false); }
 }
 const template = inventory.templates.find(t => t.id === item?.template_id);
 return <div className="sb-workspace"><SandboxHeader title={item?.name ?? "Sandbox"} subtitle="Private access & lifecycle." actions={<><LinkButton asChild variant="outline"><Link to="/sandboxes">← Workspaces</Link></LinkButton><Button variant="ghost" onClick={() => setRevision(r => r + 1)}>Refresh</Button></>} />
  {error && <ErrorText>{error}</ErrorText>}
  {!item ? (!error && <Loading />) : <>
   <div className="sb-console-surface sb-detail-console"><div className="sb-detail-grid"><section className="sb-panel sb-terminal-panel"><div className="sb-terminal-bar"><h2>PRIVATE TERMINAL / SSH</h2><SandboxStatus item={item} now={now} /></div>{isConnectable(item, now) ? <Connection connection={item.connection!} /> : <div className="sb-pending-connection"><RuntimeMark template={template} large /><h2 className="text-lg text-ink-heading">{remainingLifetime(item.expires_at, now) === "Expired" ? "Workspace lifetime ended" : "Waiting for private access"}</h2><p>Private connection instructions will appear once current policy and SSH readiness are confirmed.</p><p>Observed state: {item.observed_state}. Requested state: {item.desired_state}. Refresh to check the current response.</p></div>}</section>
   <aside><ResourceSummary title={template?.name ?? "Runtime configuration"} description={template ? "Approved environment" : "Details unavailable"}><RuntimeSpecs template={template} lifetime={remainingLifetime(item.expires_at, now)} summary /><div className="mt-6"><dl className="tnx-resource-facts"><div><dt>Expires</dt><dd>{new Date(item.expires_at).toLocaleString()}</dd></div><div><dt>Requested state</dt><dd>{item.desired_state} · generation {item.generation}</dd></div><div><dt>Selected skills</dt><dd>{item.selected_skills?.length ?? 0} immutable revisions</dd></div><div className="tnx-resource-fact-wide"><dt>Sandbox ID</dt><dd><code>{item.id}</code></dd></div></dl></div></ResourceSummary>
   <section className="sb-panel"><div className="sb-section-title"><h2>Lifecycle</h2></div>{!resumeAllowed && item.desired_state === "stopped" && <p className="sb-help mb-3">Resume is currently unavailable.</p>}<div className="flex flex-wrap gap-3"><Button className="sb-primary" disabled={pending || item.desired_state === "deleted" || (item.desired_state === "stopped" && !resumeAllowed)} onClick={() => void action(item.desired_state === "stopped" ? "started" : "stopped")}>{pending ? "Updating…" : item.desired_state === "stopped" ? "Resume" : "Stop"}</Button><Button variant="danger" disabled={pending || item.desired_state === "deleted"} onClick={() => { if (window.confirm("Delete this sandbox and its retained workspace? Deletion completes after cleanup is confirmed.")) void action("deleted"); }}>Delete</Button></div><p className="sb-help mt-3">Deletion completes after runtime cleanup is confirmed.</p></section></aside></div>
   <details className="sb-catalog"><summary><span><strong>Requested network access</strong><span className="sb-muted">{item.requested_scope.length} scopes</span></span><span className="sb-disclosure-label">View access</span></summary><div className="sb-catalog-body sb-help"><ScopeList scopes={item.requested_scope} /></div></details><WorkflowNote /></div>
  </>}
 </div>;
}
function Connection({ connection }: { connection: NonNullable<Sandbox["connection"]> }) {
 const [copied, setCopied] = useState<string | null>(null);
 const [copyError, setCopyError] = useState(false);
 const command = sandboxConnectCommand(connection);
 const knownHost = `${connection.address} ${connection.host_public_key}`;
 async function copy(label: string, text: string) { try { await navigator.clipboard.writeText(text); setCopied(label); setCopyError(false); } catch { setCopyError(true); } }
 if (!command) return <div className="sb-terminal-body"><h3>Connect</h3><ErrorText>Connection data is invalid. Refresh before connecting.</ErrorText></div>;
 return <div className="sb-terminal-body"><h3>Connect</h3><p>Join Tunnex, then copy and run this command in your local Terminal. It checks this sandbox's host key automatically.</p><div className="sb-command"><div><span>01 / RUN IN TERMINAL</span><Button size="sm" variant="ghost" onClick={() => void copy("SSH command", command)}>Copy SSH command</Button></div><pre>{command}</pre></div><p>Your normal known_hosts file stays unchanged.</p><div className="sb-command"><div><span>02 / HOST KEY DATA (NOT A COMMAND)</span><Button size="sm" variant="ghost" onClick={() => void copy("host key data", knownHost)}>Copy host key data</Button></div><pre>{knownHost}</pre></div><div className="sb-fingerprint">Host fingerprint<code>{connection.host_key_fingerprint}</code></div><p>Keep your private key local. Use -i with its path if needed.</p><p>Workspace: /workspace. Use your local terminal, Codex or Claude.</p>{copied && <p role="status">Copied {copied}.</p>}{copyError && <ErrorText>Copy failed. Select and copy the text above.</ErrorText>}</div>;
}
