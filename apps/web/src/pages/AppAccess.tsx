import "../network-workspaces.css";
import "../app-access-workspace.css";
import AppAccessWorkspaceTabs from "../components/AppAccessWorkspaceTabs";
import { isAppIconDataURL } from "../components/AppAccessIcon";
import AppAccessInventoryTable from "../components/AppAccessInventoryTable";
import AppAccessIconPicker from "../components/AppAccessIconPicker";
import AppAccessHostname, { validAppHostname } from "../components/AppAccessHostname";
import { useEffect, useRef, useState } from "react";
import { Link, Navigate, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import AppAccessAccess from "./AppAccessAccess";
import AppAccessMyApplications from "./AppAccessMyApplications";
import AppAccessConnection from "../components/AppAccessConnection";
import AppAccessPublication from "../components/AppAccessPublication";
import AppAccessSessions from "../components/AppAccessSessions";
import AppAccessMfaPolicy from "../components/AppAccessMfaPolicy";
import AppAccessCatalogSettings from "../components/AppAccessCatalogSettings";
import AppAccessCompanyApplications from "./AppAccessCompanyApplications";
import AppAccessManagedApplications from "./AppAccessManagedApplications";
import AppAccessRequests from "./AppAccessRequests";
import type { components } from "@tunnex/shared";
import { Button, Card, EmptyState, ErrorText, Field, Input, Loading, PageHeader, Select } from "../components/ui";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Member, type Node } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { can } from "../lib/rbac";

type Application = components["schemas"]["AppAccessApplication"];
type Draft = components["schemas"]["AppAccessDraftInput"];
type Settings = components["schemas"]["AppAccessSettings"];

export default function AppAccess() {
  const location = useLocation();
  const { appId } = useParams();
  const { org, failed } = useOrg();
  const { state } = useAuth();
  if (failed) return <Card><ErrorText>Could not load your organization.</ErrorText></Card>;
  if (!org || state.status !== "authed") return <Card><Loading label="Loading Applications…" /></Card>;
  // Safe member and assigned-owner routes do not load the global admin directory or application DTO.
  const key = `${org.id}:${state.user.id}:${appId ?? ""}`;
  if (location.pathname === "/app-access/company-applications") return <AppAccessCompanyApplications key={key} orgId={org.id} />;
  if (location.pathname === "/app-access/my-requests") return <AppAccessRequests key={key} orgId={org.id} />;
  if (location.pathname === "/app-access/requests") return <AppAccessRequests key={key} orgId={org.id} managed />;
  if (location.pathname === "/app-access/managed-applications" || location.pathname.startsWith("/app-access/managed-applications/")) return <AppAccessManagedApplications key={key} orgId={org.id} appId={appId} />;
  return <Workspace key={`${org.id}:${state.user.id}`} orgId={org.id} userId={state.user.id} serverAdmin={Boolean(state.user.cp_admin)} emailVerified={Boolean(state.user.email_verified)} />;
}
function Workspace({ orgId, userId, serverAdmin, emailVerified }: { orgId: string; userId: string; serverAdmin: boolean; emailVerified: boolean }) {
  const location = useLocation();
  const { appId } = useParams();
  const [roles, setRoles] = useState<Member["role"][] | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false; setRoles(null); setError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })).then(result => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); return; }
      const mine = result.data.find(member => member.user_id === userId && member.status === "active");
      setRoles(mine ? mine.roles ?? [mine.role] : []);
    });
    return () => { cancelled = true; };
  }, [orgId, userId, attempt]);
  if (error) return <div className="app-access-workspace network-management space-y-5"><PageHeader title="Applications" subtitle="Open private web apps in your browser" /><Card><ErrorText>{error}</ErrorText><Button onClick={() => setAttempt(n => n + 1)}>Retry permissions</Button></Card></div>;
  if (!roles) return <Card><Loading label="Checking application permissions…" /></Card>;
  const view = can(roles, "app_access:view");
  if (location.pathname === "/app-access") return <Navigate replace to={view ? "/app-access/applications" : "/app-access/my-applications"} />;
  if (location.pathname === "/app-access/my-applications") return <AppAccessMyApplications orgId={orgId} canUse={can(roles, "app_access:use")} />;
  if (!view) return <div className="space-y-3"><PageHeader title="Applications" /><ErrorText>You do not have permission to view application configuration.</ErrorText><Link to="/app-access/my-applications">My Applications</Link></div>;
  return <div className="app-access-workspace network-management space-y-6"><PageHeader title="Applications" subtitle="Open private web apps in your browser" actions={serverAdmin ? <Link className="network-setup-link" to="/settings?section=app-access-domains">Configure domains</Link> : undefined} /><AppAccessWorkspaceTabs viewApplications={view} manageGrants={can(roles, "app_access:grant")} />{location.pathname === "/app-access/access" ? <AppAccessAccess orgId={orgId} permitted={can(roles, "app_access:grant")} canViewEvents={can(roles, "app_access:event_view")} canViewAudit={can(roles, "org:view")} /> : appId || location.pathname.endsWith("/new") ? <><DraftEditor key={`${orgId}:${appId ?? "new"}`} orgId={orgId} userId={userId} appId={appId} manage={can(roles, "app_access:manage")} grant={can(roles, "app_access:grant")} sessionManage={can(roles, "app_access:session_manage")} canViewEvents={can(roles, "app_access:event_view")} canViewAudit={can(roles, "org:view")} /> </> : <Inventory orgId={orgId} manage={can(roles, "app_access:manage")} grant={can(roles, "app_access:grant")} featureSettingsLink={serverAdmin && emailVerified && can(roles, "org:update") && can(roles, "app_access:manage")} />}</div>;
}
function Availability({ settings }: { settings: Settings }) {
  return <p role="status" className="app-access-notice">{!settings.entitlement_available ? "Applications requires an eligible license. Saved configuration remains available for inspection." : !settings.enabled ? "Applications is off for this organization." : "Applications is enabled for this organization."} {!settings.domain_ready && "A server administrator must configure Applications domains before applications can be published."} Connection and routing changes require review and publication. Saved icons update immediately for members with access.</p>;
}
function Inventory({ orgId, manage, grant, featureSettingsLink }: { orgId: string; manage: boolean; grant: boolean; featureSettingsLink: boolean }) {
  const [params, setParams] = useSearchParams();
  const query = (params.get("q") ?? "").slice(0, 100);
  const page = Math.min(501, Math.max(1, Math.floor(Number(params.get("page"))) || 1));
  const publicationFilter = ["unpublished", "published", "disabled"].includes(params.get("publication") ?? "") ? params.get("publication") as "unpublished" | "published" | "disabled" : undefined;
  const [items, setItems] = useState<Application[] | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [hasNext, setHasNext] = useState(false);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false; setItems(null); setSettings(null); setError("");
    void Promise.all([loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/settings", { params: { path: { orgId } } })), loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId }, query: { search: query, limit: 20, offset: (page - 1) * 20, ...(publicationFilter ? { publication_state: publicationFilter } : {}) } } }))]).then(([availability, inventory]) => {
      if (cancelled) return;
      if (!availability.ok || !inventory.ok) { setError(!availability.ok ? availability.error : !inventory.ok ? inventory.error : "Could not load applications."); return; }
      setSettings(availability.data); setItems(inventory.data.items); setHasNext(inventory.data.items.length === inventory.data.limit);
    }); return () => { cancelled = true; };
  }, [orgId, query, page, attempt, publicationFilter]);
  const addApplication = manage && settings?.entitlement_available && settings.enabled && settings.domain_ready
    ? <Link className="app-access-primary-link" to="/app-access/applications/new">Add application</Link> : undefined;
  return <section aria-label="Applications" className="space-y-5">
    <div className="app-access-panel-header"><div><h2>Applications</h2><p>Manage browser access to your private HTTP and HTTPS apps.</p></div>{addApplication}</div>
    {settings && !settings.enabled && <div className="app-access-availability"><p role="status" className="app-access-notice">Applications is disabled.</p>{featureSettingsLink && <Link className="network-setup-link" to="/settings?section=features">Open feature settings</Link>}</div>}
    <Card>
      <div className="app-access-toolbar"><div className="app-access-search"><Field label="Search applications"><Input maxLength={100} placeholder="Search by application name" value={query} onChange={event => setParams({ ...(publicationFilter ? { publication: publicationFilter } : {}), ...(event.target.value ? { q: event.target.value } : {}) })} /></Field></div><div className="app-access-filter"><Field label="Publication"><Select value={publicationFilter ?? ""} onChange={event => setParams({ ...(query ? { q: query } : {}), ...(event.target.value ? { publication: event.target.value } : {}) })}><option value="">All applications</option><option value="unpublished">Unpublished</option><option value="published">Published</option><option value="disabled">Disabled</option></Select></Field></div></div>
      {error ? <div className="mt-5 space-y-3"><ErrorText>{error}</ErrorText><Button onClick={() => setAttempt(n => n + 1)}>Retry applications</Button></div> : items === null ? <Loading label="Loading applications…" /> : <div className="app-access-inventory-table"><AppAccessInventoryTable key={`${orgId}:${query}:${publicationFilter ?? ""}:${page}:${attempt}`} orgId={orgId} applications={items} manage={manage} grant={grant} canGrant={!!settings?.entitlement_available && settings.enabled && settings.domain_ready} onChanged={() => setAttempt(n => n + 1)} empty={<EmptyState>{query ? "No applications match your search." : publicationFilter ? "No applications match this publication filter." : "No application drafts yet."}</EmptyState>} /></div>}
      <div className="app-access-pagination"><Button variant="ghost" disabled={!items} onClick={() => setAttempt(n => n + 1)}>Refresh applications</Button><Button variant="ghost" disabled={page === 1 || !items} onClick={() => setParams({ q: query, ...(publicationFilter ? { publication: publicationFilter } : {}), page: String(page - 1) })}>Previous page</Button><span>Page {page}</span><Button variant="ghost" disabled={!items || !hasNext || page >= 501} onClick={() => setParams({ q: query, ...(publicationFilter ? { publication: publicationFilter } : {}), page: String(page + 1) })}>Next page</Button></div>
    </Card>
  </section>;
}
function draftInput(value: Draft): Draft { return { name: value.name, description: value.description, icon: value.icon, ...(value.icon_data_url !== undefined ? { icon_data_url: value.icon_data_url } : {}), origin_url: value.origin_url, gateway_id: value.gateway_id, public_hostname: value.public_hostname, idle_timeout_seconds: value.idle_timeout_seconds, absolute_timeout_seconds: value.absolute_timeout_seconds, ...(value.allowed_destination_cidrs !== undefined ? { allowed_destination_cidrs: value.allowed_destination_cidrs } : {}), ...(value.origin_ca_pem !== undefined ? { origin_ca_pem: value.origin_ca_pem } : {}) }; }
function validOriginRecovery(value: object): boolean {
  const policy = value as Partial<Draft>;
  return (policy.icon_data_url === undefined || policy.icon_data_url === "" || (typeof policy.icon_data_url === "string" && isAppIconDataURL(policy.icon_data_url))) && (policy.allowed_destination_cidrs === undefined || (Array.isArray(policy.allowed_destination_cidrs) && policy.allowed_destination_cidrs.length <= 32 && policy.allowed_destination_cidrs.every(item => typeof item === "string" && item.length <= 64))) && (policy.origin_ca_pem === undefined || (typeof policy.origin_ca_pem === "string" && policy.origin_ca_pem.length <= 32768 && !policy.origin_ca_pem.includes("PRIVATE KEY")));
}
const blank: Draft = { name: "", description: "", icon: "app", origin_url: "", gateway_id: "", public_hostname: "", idle_timeout_seconds: 1800, absolute_timeout_seconds: 28800 };
function DraftEditor({ orgId, userId, appId, manage, grant = false, sessionManage = false, canViewEvents = false, canViewAudit = false }: { orgId: string; userId: string; appId?: string; manage: boolean; grant?: boolean; sessionManage?: boolean; canViewEvents?: boolean; canViewAudit?: boolean }) {
  const navigate = useNavigate();
  const [setupParams, setSetupParams] = useSearchParams();
  const [newStep, setNewStep] = useState<"application" | "connection">("application");
  const requestedStep = setupParams.get("step");
  const step = appId ? requestedStep && ["application", "connection", "access", "review"].includes(requestedStep) ? requestedStep : "edit" : newStep;
  const move = (next: string) => {
    if (!appId) { if (next === "application" || next === "connection") setNewStep(next); return; }
    if (dirty && (next === "access" || next === "review")) { setError("Save your changes before continuing to access or review."); return; }
    setSetupParams({ step: next });
  };

  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [draft, setDraft] = useState<Draft>(blank);
  const [version, setVersion] = useState<number | null>(null);
  const [savedApplication, setSavedApplication] = useState<Application | null>(null);
  const [reviewCheck, setReviewCheck] = useState<components["schemas"]["AppAccessCheck"] | null>(null);
  const [savedGateway, setSavedGateway] = useState("");
  const [caDigest, setCaDigest] = useState("");
  const [caMode, setCaMode] = useState<"preserve" | "system" | "custom">(appId ? "preserve" : "system");
  const [nodes, setNodes] = useState<Node[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [iconReading, setIconReading] = useState(false);
  const [recovery, setRecovery] = useState<Draft | null>(null);
  const [attempt, setAttempt] = useState(0);
  const storageKey = `tunnex.appAccessDraft:${userId}:${orgId}:${appId ?? "new"}`;
  useEffect(() => {
    let cancelled = false; setReady(false); setError("");
    void Promise.all([loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/settings", { params: { path: { orgId } } })), loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } })), appId ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}", { params: { path: { orgId, appId } } })) : Promise.resolve(null)]).then(([availability, gateways, app]) => {
      if (cancelled) return;
      if (!availability.ok || !gateways.ok || (app && !app.ok)) { setError(!availability.ok ? availability.error : !gateways.ok ? gateways.error : app && !app.ok ? app.error : "Could not load draft."); return; }
      setSettings(availability.data); setNodes(gateways.data.filter(node => node.enrolled_kind === "gateway"));
      if (app?.ok) { setSavedApplication(app.data); setReviewCheck(null); setDraft(draftInput(app.data.draft)); setVersion(app.data.version); setSavedGateway(app.data.draft.gateway_id); setCaDigest(app.data.draft.origin_ca_digest ?? ""); setCaMode("preserve"); } else { setSavedApplication(null); setReviewCheck(null); setDraft(blank); setVersion(null); }
      try { const saved = window.sessionStorage.getItem(storageKey); if (saved) { const value: unknown = JSON.parse(saved); if (value && typeof value === "object" && validOriginRecovery(value) && Object.entries(blank).every(([key, initial]) => typeof (value as Record<string, unknown>)[key] === typeof initial) && ["app", "globe", "dashboard", "terminal"].includes((value as Draft).icon)) setRecovery(value as Draft); } } catch { /* unavailable storage is optional */ }
      setReady(true);
    }); return () => { cancelled = true; };
  }, [orgId, appId, attempt, storageKey]);
  useEffect(() => { if (!dirty) return; try { window.sessionStorage.setItem(storageKey, JSON.stringify({ ...draft, origin_ca_pem: draft.origin_ca_pem?.includes("PRIVATE KEY") ? undefined : draft.origin_ca_pem })); } catch { /* retain current form */ } const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); }; window.addEventListener("beforeunload", warn); return () => window.removeEventListener("beforeunload", warn); }, [draft, dirty, storageKey]);
  const change = <K extends keyof Draft>(key: K, value: Draft[K]) => { setDraft(current => ({ ...current, [key]: value })); setDirty(true); };
  const archived = savedApplication?.state === "archived";
  const editable = !archived && manage && settings?.entitlement_available === true && settings.enabled && settings.domain_ready;
  const selectedGateway = nodes.find(node => node.id === draft.gateway_id);
  const eligibleGateway = selectedGateway?.status === "active";
  const hostnameReady = validAppHostname(draft.public_hostname, settings?.base_domain ?? "") || (!!appId && draft.public_hostname === savedApplication?.draft.public_hostname);
  const save = async (event: React.FormEvent) => {
    event.preventDefault(); if (!editable || !eligibleGateway || busy || iconReading) return;
    if (!hostnameReady) { setError("Enter a valid application subdomain before saving."); return; }
    if (draft.origin_ca_pem?.includes("PRIVATE KEY")) { setError("Upload public CA certificates only. Private keys are not accepted."); return; }
    if (caMode === "custom" && !draft.origin_ca_pem?.trim()) { setError("Paste public CA certificates or choose system certificate roots."); return; }
    setBusy(true); setError("");
    try {
      const input = { ...draft, ...(draft.allowed_destination_cidrs !== undefined ? { allowed_destination_cidrs: draft.allowed_destination_cidrs.map(value => value.trim()).filter(Boolean) } : {}) };
      const result = appId && version !== null ? await api.PATCH("/api/v1/organizations/{orgId}/app-access/applications/{appId}", { params: { path: { orgId, appId } }, body: { ...input, expected_version: version } }) : await api.POST("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId } }, body: input });
      if (!mounted.current) return;
      if (result.error || !result.data) { setError((apiErrorCode(result.error) === "stale_version" || apiErrorCode(result.error) === "version_conflict") ? "This draft changed since you opened it. Your edits are preserved; return to the inventory and reopen the draft to review the latest version before restoring them." : apiErrorMessage(result.error, "Could not save draft. Your changes are kept here.")); return; }
      setSavedApplication(result.data); setReviewCheck(null); setDraft(draftInput(result.data.draft)); setVersion(result.data.version); setSavedGateway(result.data.draft.gateway_id); setCaDigest(result.data.draft.origin_ca_digest ?? ""); setCaMode("preserve"); setDirty(false); setRecovery(null); try { window.sessionStorage.removeItem(storageKey); } catch { /* optional */ }
      if (!appId) navigate(`/app-access/applications/${result.data.id}?step=access`, { replace: true });
    } catch { setError("Could not reach the API. Your changes are kept here; check the inventory before retrying a new draft."); } finally { if (mounted.current) setBusy(false); }
  };
  if (!ready) return <Card><ErrorText>{error}</ErrorText>{error ? <Button onClick={() => setAttempt(n => n + 1)}>Retry draft</Button> : <Loading label="Loading application settings…" />}</Card>;
  return <section className="app-access-editor space-y-5"><div className="app-access-editor-title"><div><h2>{archived ? "Archived application" : appId ? "Application draft" : "Add application"}</h2><p>{savedApplication ? savedApplication.draft.name : "Set up an application, connect its origin, then review who can open it."}</p></div><Link className="network-setup-link" to="/app-access/applications">All applications</Link></div>{settings && <Availability settings={settings} />}{archived && <p role="status">This application is archived. Its configuration and publication history are retained.</p>}{recovery && editable && <div className="space-y-2"><p role="status">Unsaved changes from this browser are available.</p><Button variant="ghost" onClick={() => { setDraft(recovery); setCaMode(recovery.origin_ca_pem === undefined ? "preserve" : recovery.origin_ca_pem ? "custom" : "system"); setDirty(true); setRecovery(null); }}>Restore unsaved changes</Button><Button variant="ghost" onClick={() => { setRecovery(null); try { window.sessionStorage.removeItem(storageKey); } catch { /* optional storage */ } }}>Discard saved changes</Button></div>}<ErrorText>{error}</ErrorText><nav aria-label="Application setup" className="app-access-steps">{[["application", "1. Application"], ["connection", "2. Connection"], ["access", "3. Access"], ["review", "4. Review & publish"]].map(([key, label]) => <Button key={key} type="button" variant="ghost" aria-current={step === key ? "step" : undefined} disabled={(!appId && (key === "access" || key === "review")) || (!appId && key === "connection" && (!draft.name.trim() || !hostnameReady || iconReading))} onClick={() => move(key)}>{label}</Button>)}</nav>{(step === "edit" || step === "application" || step === "connection") && <form onSubmit={event => { if (!appId && step === "application") { event.preventDefault(); if (draft.name.trim() && hostnameReady && !iconReading) move("connection"); } else void save(event); }} className="space-y-5"><fieldset disabled={!editable || busy || iconReading} className="space-y-5">{(step === "edit" || step === "application") && <Card className="app-access-form-section"><div className="app-access-section-description"><h3>Application identity</h3><p>The name and browser address people use to find this app.</p></div><div className="app-access-form-fields space-y-5"><Field label="Application name"><Input required maxLength={100} value={draft.name} onChange={event => change("name", event.target.value)} /></Field><Field label="Description"><Input maxLength={1000} value={draft.description} onChange={event => change("description", event.target.value)} /></Field><AppAccessIconPicker icon={draft.icon} image={draft.icon_data_url} onIconChange={value => change("icon", value)} onImageChange={value => change("icon_data_url", value)} onReadingChange={setIconReading} /><AppAccessHostname value={draft.public_hostname} domain={settings?.base_domain ?? ""} original={savedApplication?.draft.public_hostname} onChange={value => change("public_hostname", value)} /></div></Card>}{(step === "edit" || step === "connection") && <Card className="app-access-form-section"><div className="app-access-section-description"><h3>Origin connection</h3><p>Choose the private origin and the gateway that reaches it. HTTPS keeps the saved certificate trust.</p></div><div className="app-access-form-fields space-y-5"><div><Field label="Origin URL"><Input required type="url" value={draft.origin_url} onChange={event => change("origin_url", event.target.value)} /></Field><p className="mt-1 text-sm text-ink-secondary">Only a registered HTTP or HTTPS origin; root-path apps only.</p></div><Field label="Gateway connector"><Select required value={draft.gateway_id} onChange={event => change("gateway_id", event.target.value)}><option value="">Select a gateway</option>{draft.gateway_id && !selectedGateway && <option value={draft.gateway_id} disabled>Assigned gateway is unavailable</option>}{nodes.filter(node => node.status === "active" || node.id === draft.gateway_id).map(node => <option key={node.id} value={node.id} disabled={node.status !== "active"}>{node.name} · {node.status === "active" ? "Active gateway" : "Revoked: choose an active gateway"}</option>)}</Select></Field><p className="text-sm text-ink-secondary">Gateway enrollment does not establish Applications capability. Save the draft to inspect the connector and check its origin connection.</p><div className="space-y-4"><Field label="Allowed private destination ranges"><textarea className="w-full rounded-md border border-line bg-transparent p-2 font-mono text-sm" rows={3} maxLength={2080} value={(draft.allowed_destination_cidrs ?? []).join("\n")} onChange={event => change("allowed_destination_cidrs", event.target.value.split(/\n/).map(value => value.trim()))} /></Field><p className="text-sm text-ink-secondary">One private CIDR range per line, up to 32. Leave empty for safe public destinations only. Loopback, link-local, metadata and control plane addresses remain blocked.</p><Field label="Origin certificate trust"><Select value={caMode} onChange={event => { const mode = event.target.value as typeof caMode; setCaMode(mode); setDraft(current => { const next = { ...current }; if (mode === "preserve") delete next.origin_ca_pem; else next.origin_ca_pem = ""; return next; }); setDirty(true); }}>{appId && <option value="preserve">Keep saved trust ({caDigest ? "custom CA" : "system roots"})</option>}<option value="system">System certificate roots</option><option value="custom">Custom public CA certificates</option></Select></Field>{caMode === "custom" && <Field label="Public CA certificate PEM"><textarea className="w-full rounded-md border border-line bg-transparent p-2 font-mono text-sm" rows={6} maxLength={32768} value={draft.origin_ca_pem ?? ""} onChange={event => change("origin_ca_pem", event.target.value)} /></Field>}<p className="text-sm text-ink-secondary">HTTPS verifies the origin hostname and certificate chain. Custom trust accepts up to eight public CA certificates; paste no private keys.</p>{caDigest && <p className="break-all text-sm text-ink-secondary">Saved CA fingerprint: {caDigest}</p>}</div><div className="grid min-w-0 gap-4 sm:grid-cols-2"><Field label="Idle timeout (seconds)"><Input required type="number" min={60} max={1800} value={draft.idle_timeout_seconds} onChange={event => change("idle_timeout_seconds", Number(event.target.value))} /></Field><Field label="Maximum session (seconds)"><Input required type="number" min={300} max={28800} value={draft.absolute_timeout_seconds} onChange={event => change("absolute_timeout_seconds", Number(event.target.value))} /></Field></div></div></Card>}</fieldset><div className="app-access-form-actions">{editable && (!appId && step === "application" ? <Button type="submit" disabled={!draft.name.trim() || !hostnameReady || iconReading}>Continue to connection</Button> : <Button disabled={busy || iconReading || !hostnameReady || !eligibleGateway || (appId !== undefined && !dirty)} type="submit">{busy ? "Saving draft…" : "Save draft"}</Button>)}<Link to="/app-access/applications">Back to applications</Link></div>{dirty && <p role="status" className="text-sm">Unsaved changes are retained in this browser tab until saved or discarded.</p>}</form>}{appId && version !== null && savedGateway && (step === "edit" || step === "connection") && <AppAccessConnection key={`${orgId}:${appId}:${version}:${savedGateway}`} orgId={orgId} appId={appId} gatewayId={savedGateway} version={version} revision={savedApplication?.draft.revision} onCheck={setReviewCheck} canCheck={editable && eligibleGateway === true} dirty={dirty} />}{appId && step === "connection" && <Button disabled={dirty} onClick={() => move("access")}>Continue to access</Button>}{appId && (step === "edit" || step === "access") && <AppAccessCatalogSettings key={`${orgId}:${appId}:catalog`} orgId={orgId} appId={appId} permitted={manage && grant && !archived} dirty={dirty} onChanged={() => setAttempt(value => value + 1)} />}{appId && savedApplication && (step === "edit" || step === "access") && <AppAccessMfaPolicy key={`${orgId}:${appId}`} orgId={orgId} application={savedApplication} canManage={manage && !archived} dirty={dirty} onChanged={application => { setSavedApplication(application); setVersion(application.version); setReviewCheck(null); }} onReload={() => setAttempt(value => value + 1)} />}{appId && (step === "edit" || step === "access") && (grant && !archived ? <AppAccessAccess orgId={orgId} appId={appId} permitted canViewEvents={canViewEvents} canViewAudit={canViewAudit} /> : step === "access" ? <ErrorText>You do not have permission to manage application grants. Ask an administrator to configure access.</ErrorText> : null)}{appId && step === "access" && <Button onClick={() => move("review")}>Continue to review</Button>}{appId && step === "review" && savedApplication && <AppAccessPublication key={`${orgId}:${appId}:${version}`} orgId={orgId} userId={userId} application={savedApplication} check={reviewCheck} dirty={dirty} canManage={manage && !archived} canPublish={editable && eligibleGateway === true} onChanged={() => setAttempt(value => value + 1)} onArchived={() => navigate("/app-access/applications", { replace: true })} onRollback={() => { setSetupParams({ step: "connection" }); setAttempt(value => value + 1); }} />}{appId && step === "review" && sessionManage && <AppAccessSessions key={`${orgId}:${appId}`} orgId={orgId} appId={appId} />}</section>;
}
