import "../network-workspaces.css";
import "../app-access-workspace.css";
import AppAccessWorkspaceTabs from "../components/AppAccessWorkspaceTabs";
import AppAccessDomainSetup from "../components/AppAccessDomainSetup";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import { ResourceSummary } from "../components/ResourceSummary";
import { Icon } from "../components/Icon";
import { AppAccessIcon, isAppIconDataURL } from "../components/AppAccessIcon";
import AppAccessInventoryTable from "../components/AppAccessInventoryTable";
import AppAccessIconPicker from "../components/AppAccessIconPicker";
import AppAccessHostname, { validAppHostname } from "../components/AppAccessHostname";
import { useEffect, useId, useRef, useState } from "react";
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
import { Button, Card, ErrorText, Field, Input, Loading, PageHeader, RefreshButton, Select } from "../components/ui";
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
  if (error) return <div className="app-access-workspace network-management space-y-5"><PageHeader title="App Access" navigationTitle /><Card><ErrorText>{error}</ErrorText><Button onClick={() => setAttempt(n => n + 1)}>Retry permissions</Button></Card></div>;
  if (!roles) return <Card><Loading label="Checking application permissions…" /></Card>;
  const view = can(roles, "app_access:view");
  if (location.pathname === "/app-access") return <Navigate replace to={view ? "/app-access/applications" : "/app-access/my-applications"} />;
  if (location.pathname === "/app-access/my-applications") return <AppAccessMyApplications orgId={orgId} canUse={can(roles, "app_access:use")} />;
  if (!view) return <div className="space-y-3"><PageHeader title="App Access" navigationTitle /><ErrorText>You do not have permission to view application configuration.</ErrorText><Link to="/app-access/my-applications">My Applications</Link></div>;
  const detailPage = !!appId || location.pathname.endsWith("/new");
  return <div className={`app-access-workspace network-management space-y-6${detailPage ? " app-access-detail-workspace" : " app-access-inventory-workspace"}`}>
    {!detailPage && <><div className="app-access-heading"><PageHeader title="App Access" navigationTitle actions={serverAdmin ? <AppAccessDomainSetup /> : undefined} /></div><AppAccessWorkspaceTabs viewApplications={view} manageGrants={can(roles, "app_access:grant")} /></>}
    {location.pathname === "/app-access/access" ? <AppAccessAccess orgId={orgId} permitted={can(roles, "app_access:grant")} canViewEvents={can(roles, "app_access:event_view")} canViewAudit={can(roles, "org:view")} /> : detailPage ? <DraftEditor key={`${orgId}:${appId ?? "new"}`} orgId={orgId} userId={userId} appId={appId} manage={can(roles, "app_access:manage")} grant={can(roles, "app_access:grant")} configureDomains={serverAdmin} sessionManage={can(roles, "app_access:session_manage")} canViewEvents={can(roles, "app_access:event_view")} canViewAudit={can(roles, "org:view")} /> : <Inventory orgId={orgId} manage={can(roles, "app_access:manage")} grant={can(roles, "app_access:grant")} configureDomains={serverAdmin} featureSettingsLink={emailVerified && can(roles, "app_access:manage")} />}
  </div>;
}
function Availability({ settings, manage = true, archived = false }: { settings: Settings; manage?: boolean; archived?: boolean }) {
  const message = archived ? "This application is archived. Its configuration and publication history are retained." : !manage ? "You have view access. Ask an administrator to edit this configuration." : !settings.entitlement_available ? "Applications requires an eligible license. You can inspect saved configuration." : !settings.enabled ? "App Access is off for this organization. You can inspect saved configuration." : !settings.domain_ready ? "Complete domain setup before saving or publishing applications." : "";
  return message ? <p role="status" className="aa-editor-notice"><svg aria-hidden="true" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7h.01" /></svg><span>{message}</span></p> : null;
}
function Inventory({ orgId, manage, grant, configureDomains, featureSettingsLink }: { orgId: string; manage: boolean; grant: boolean; configureDomains: boolean; featureSettingsLink: boolean }) {
  const [params, setParams] = useSearchParams();
  const query = (params.get("q") ?? "").slice(0, 100);
  const pageSize = appAccessPageSize(params.get("page_size"));
  const page = Math.min(Math.floor(10000 / pageSize) + 1, Math.max(1, Math.floor(Number(params.get("page"))) || 1));
  const publicationFilter = ["unpublished", "published", "disabled"].includes(params.get("publication") ?? "") ? params.get("publication") as "unpublished" | "published" | "disabled" : undefined;
  const [items, setItems] = useState<Application[] | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [hasNext, setHasNext] = useState(false);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const refreshDomains = () => setAttempt(value => value + 1);
    window.addEventListener("app-access-domains-changed", refreshDomains);
    return () => window.removeEventListener("app-access-domains-changed", refreshDomains);
  }, []);
  useEffect(() => {
    let cancelled = false; setItems(null); setSettings(null); setError("");
    void Promise.all([loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/settings", { params: { path: { orgId } } })), loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications", { params: { path: { orgId }, query: { search: query, limit: pageSize, offset: (page - 1) * pageSize, ...(publicationFilter ? { publication_state: publicationFilter } : {}) } } }))]).then(([availability, inventory]) => {
      if (cancelled) return;
      if (!availability.ok || !inventory.ok) { setError(!availability.ok ? availability.error : !inventory.ok ? inventory.error : "Could not load applications."); return; }
      setSettings(availability.data); setItems(inventory.data.items); setHasNext(inventory.data.items.length === inventory.data.limit);
    }); return () => { cancelled = true; };
  }, [orgId, query, page, pageSize, attempt, publicationFilter]);
  const changePage = (next: number) => { const nextParams = new URLSearchParams(params); nextParams.set("page", String(next)); setParams(nextParams); };
  const changePageSize = (size: number) => { const nextParams = new URLSearchParams(params); nextParams.set("page_size", String(size)); nextParams.delete("page"); setParams(nextParams); };
  const addApplication = manage && settings?.entitlement_available && settings.enabled && settings.domain_ready
    ? <Link className="app-access-primary-link" to="/app-access/applications/new">Add application</Link> : undefined;
  const setupNotice = settings && (!settings.enabled
    ? { message: "App Access is off for this organization.", to: featureSettingsLink ? "/settings?section=features&feature=app-access" : undefined, action: "Manage in Features" }
    : !settings.entitlement_available
      ? { message: "App Access requires an eligible license.", to: undefined, action: undefined }
      : !settings.domain_ready
        ? { message: "Complete domain setup to publish applications", to: configureDomains ? "/settings?section=app-access-domains" : undefined, action: "Set up" }
        : null);
  return <section aria-label="Applications" className="app-access-inventory">
    {setupNotice && <div role="status" className="app-access-setup-notice"><span><span aria-hidden="true" className="app-access-setup-dot" />{setupNotice.message}</span>{setupNotice.to === "/settings?section=app-access-domains" ? <AppAccessDomainSetup label="Set up" /> : setupNotice.to && <Link to={setupNotice.to}>{setupNotice.action}<span aria-hidden="true">→</span></Link>}</div>}
    <div className="app-access-toolbar">
      <div className="app-access-search"><Icon name="search" size={17} /><Input type="search" aria-label="Search applications" maxLength={100} placeholder="Search applications…" value={query} onChange={event => setParams({ page_size: String(pageSize), ...(publicationFilter ? { publication: publicationFilter } : {}), ...(event.target.value ? { q: event.target.value } : {}) })} /></div>
      <Select aria-label="Publication" width="auto" className="app-access-filter" value={publicationFilter ?? ""} onChange={event => setParams({ page_size: String(pageSize), ...(query ? { q: query } : {}), ...(event.target.value ? { publication: event.target.value } : {}) })}><option value="">All states</option><option value="unpublished">Draft</option><option value="published">Published</option><option value="disabled">Disabled</option></Select>
      <RefreshButton label="Refresh applications" disabled={items === null} onClick={() => setAttempt(n => n + 1)} />
      {items && <span className="app-access-result-count">{items.length}{hasNext ? "+" : ""} application{items.length === 1 ? "" : "s"}</span>}
      {addApplication}
    </div>
    {error ? <div className="mt-5 space-y-3"><ErrorText>{error}</ErrorText><Button onClick={() => setAttempt(n => n + 1)}>Retry applications</Button></div> : items === null ? <Loading label="Loading applications…" /> : !items.length ? <AppAccessEmptyState title={query ? "No applications match your search." : publicationFilter ? "No applications match this publication filter." : "No application drafts yet."} description={query || publicationFilter ? "Try a different search or clear your filters." : "Applications you configure will appear here."} action={page > 1 ? <Button variant="ghost" onClick={() => changePage(page - 1)}>Back to previous page</Button> : query || publicationFilter ? <Button variant="ghost" onClick={() => setParams({ page_size: String(pageSize) })}>Clear filters</Button> : addApplication} /> : <div className="app-access-inventory-table"><AppAccessInventoryTable key={`${orgId}:${query}:${publicationFilter ?? ""}:${page}:${pageSize}:${attempt}`} orgId={orgId} applications={items} manage={manage} grant={grant} canGrant={!!settings?.entitlement_available && settings.enabled && settings.domain_ready} grantUnavailable={settings ? !settings.entitlement_available ? "An eligible license is required." : !settings.enabled ? "Enable App Access first." : !settings.domain_ready ? "Complete domain setup first." : undefined : undefined} onChanged={() => setAttempt(n => n + 1)} empty={null} /></div>}
    {items && !error && <AppAccessPagination page={page} pageSize={pageSize} count={items.length} hasNext={hasNext} onPageChange={changePage} onPageSizeChange={changePageSize} />}
  </section>;
}
function draftInput(value: Draft): Draft { return { name: value.name, description: value.description, icon: value.icon, ...(value.icon_data_url !== undefined ? { icon_data_url: value.icon_data_url } : {}), origin_url: value.origin_url, gateway_id: value.gateway_id, public_hostname: value.public_hostname, idle_timeout_seconds: value.idle_timeout_seconds, absolute_timeout_seconds: value.absolute_timeout_seconds, ...(value.allowed_destination_cidrs !== undefined ? { allowed_destination_cidrs: value.allowed_destination_cidrs } : {}), ...(value.origin_ca_pem !== undefined ? { origin_ca_pem: value.origin_ca_pem } : {}) }; }
function validOriginRecovery(value: object): boolean {
  const policy = value as Partial<Draft>;
  return (policy.icon_data_url === undefined || policy.icon_data_url === "" || (typeof policy.icon_data_url === "string" && isAppIconDataURL(policy.icon_data_url))) && (policy.allowed_destination_cidrs === undefined || (Array.isArray(policy.allowed_destination_cidrs) && policy.allowed_destination_cidrs.length <= 32 && policy.allowed_destination_cidrs.every(item => typeof item === "string" && item.length <= 64))) && (policy.origin_ca_pem === undefined || (typeof policy.origin_ca_pem === "string" && policy.origin_ca_pem.length <= 32768 && !policy.origin_ca_pem.includes("PRIVATE KEY")));
}
const blank: Draft = { name: "", description: "", icon: "app", origin_url: "", gateway_id: "", public_hostname: "", idle_timeout_seconds: 1800, absolute_timeout_seconds: 28800 };
const setupSteps = [
  { key: "application", label: "Application", title: "Application details", description: "Choose the name and browser address people will use." },
  { key: "connection", label: "Connection", title: "Origin connection", description: "Connect the private app through a gateway, then check the saved connection." },
  { key: "access", label: "Access", title: "Who can open this app?", description: "Only people with current grants can open a published app." },
  { key: "review", label: "Review & publish", title: "Review & publish", description: "Review the saved configuration before enabling browser access." },
] as const;
type SetupStep = typeof setupSteps[number]["key"];
function CopyApplicationAddress({ hostname }: { hostname: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  async function copy() {
    try { await navigator.clipboard.writeText(`https://${hostname}`); setCopied(true); setFailed(false); }
    catch { setFailed(true); }
  }
  return <span className="aa-editor-address"><span>{hostname}</span><button type="button" aria-label={copied ? "Application address copied" : "Copy application address"} title={copied ? "Copied" : "Copy address"} onClick={() => void copy()}>{copied ? <Icon name="check-circle" size={16} /> : <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><rect x="8" y="3" width="13" height="13" rx="2" /><path d="M16 16v5H3V8h5" /></svg>}</button>{failed && <span role="status" className="aa-editor-field-help">Select the address to copy it.</span>}</span>;
}
function DraftEditor({ orgId, userId, appId, manage, grant = false, configureDomains = false, sessionManage = false, canViewEvents = false, canViewAudit = false }: { orgId: string; userId: string; appId?: string; manage: boolean; grant?: boolean; configureDomains?: boolean; sessionManage?: boolean; canViewEvents?: boolean; canViewAudit?: boolean }) {
  const draftFormId = useId();
  const navigate = useNavigate();
  const [setupParams, setSetupParams] = useSearchParams();
  const [newStep, setNewStep] = useState<"application" | "connection">("application");
  const requestedStep = setupParams.get("step");
  const step: SetupStep = appId ? setupSteps.some(item => item.key === requestedStep) ? requestedStep as SetupStep : "application" : newStep;
  const currentStep = setupSteps.find(item => item.key === step)!;
  const setStep = (next: SetupStep) => { const params = new URLSearchParams(setupParams); params.set("step", next); setSetupParams(params); };
  const move = (next: SetupStep) => {
    if (!appId) { if (next === "application" || next === "connection") setNewStep(next); return; }
    if (dirty && (next === "access" || next === "review")) { setError("Save your changes before continuing to access or review."); return; }
    setError(""); setStep(next);
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
  const save = async (event: React.FormEvent, next?: SetupStep) => {
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
      if (!appId) navigate(`/app-access/applications/${result.data.id}?step=connection`, { replace: true });
      else if (next) setStep(next);
    } catch { setError("Could not reach the API. Your changes are kept here; check the inventory before retrying a new draft."); } finally { if (mounted.current) setBusy(false); }
  };
  if (!ready) return <Card><ErrorText>{error}</ErrorText>{error ? <Button onClick={() => setAttempt(n => n + 1)}>Retry draft</Button> : <Loading label="Loading application settings…" />}</Card>;
  const canSave = editable && !busy && !iconReading && !!draft.name.trim() && hostnameReady && eligibleGateway === true;
  const appName = savedApplication?.draft.name ?? "Add application";
  const readOnly = !!savedApplication && !editable;
  const savedDraft = savedApplication?.draft;
  const savedNode = nodes.find(node => node.id === savedGateway);
  const editActions = <div className="app-access-form-actions aa-editor-actions">
    {step === "application" ? <>
      <Button type="submit" form={draftFormId} disabled={busy || iconReading || (!appId && (!editable || !draft.name.trim() || !hostnameReady)) || (!!appId && dirty && !canSave)}>{busy ? "Saving draft…" : appId && dirty ? "Save and continue" : "Continue to connection"}</Button>
      {appId && editable && <Button type="button" variant="ghost" disabled={!canSave || !dirty} onClick={event => void save(event)}>Save draft</Button>}
      {appId && dirty && !canSave && <Button type="button" variant="ghost" onClick={() => move("connection")}>Edit connection</Button>}
    </> : <>
      <Button type="button" variant="ghost" disabled={busy} onClick={() => move("application")}>Back to application</Button>
      {editable && <Button type="submit" form={draftFormId} disabled={!canSave || (!!appId && !dirty)}>{busy ? "Saving draft…" : "Save draft"}</Button>}
    </>}
    <Link to="/app-access/applications">Back to applications</Link>
    {appId && step === "connection" && <><Button type="button" disabled={dirty || busy} onClick={() => move("access")}>Continue to access<Icon name="chevron-right" size={16} /></Button>{dirty && <span>Save the draft before continuing.</span>}</>}
  </div>;
  return <section className="app-access-editor aa-editor">
    <nav aria-label="Breadcrumb" className="aa-editor-breadcrumb"><ol>
      <li><Link to="/app-access">App Access</Link></li>
      <li><Link to="/app-access/applications">Applications</Link></li>
      {appId && <li><Link to={`/app-access/applications/${appId}?step=application`}>{appName}</Link></li>}
      {!appId && <li><span>Add application</span></li>}
      <li><span aria-current="page">{currentStep.label}</span></li>
    </ol></nav>
    <header className="aa-editor-heading"><div className="aa-editor-heading-identity"><span className="aa-editor-heading-icon" aria-hidden="true"><AppAccessIcon icon={savedDraft?.icon ?? draft.icon} image={savedDraft?.icon_data_url ?? draft.icon_data_url} size={30} /></span><div><h1>{appName}</h1>{savedDraft?.public_hostname && <p className="aa-editor-heading-hostname">{savedDraft.public_hostname}</p>}</div></div>
      {savedApplication && <span className={`aa-editor-publication aa-editor-publication-${savedApplication.publication_state}`}>{archived ? "Archived" : savedApplication.publication_state === "published" ? "Published" : savedApplication.publication_state === "disabled" ? "Disabled" : "Draft"}</span>}
    </header>
    {recovery && editable && <div className="aa-editor-recovery"><p role="status">Unsaved changes from this browser are available.</p><div>
      <Button variant="ghost" onClick={() => { setDraft(recovery); setCaMode(recovery.origin_ca_pem === undefined ? "preserve" : recovery.origin_ca_pem ? "custom" : "system"); setDirty(true); setRecovery(null); }}>Restore unsaved changes</Button>
      <Button variant="ghost" onClick={() => { setRecovery(null); try { window.sessionStorage.removeItem(storageKey); } catch { /* optional storage */ } }}>Discard saved changes</Button>
    </div></div>}
    <div className="aa-editor-layout">
    <aside className="aa-editor-rail"><p className="aa-editor-rail-label">Setup</p><nav aria-label="Application setup" className="app-access-steps aa-editor-steps">{setupSteps.map((item, index) => <Button key={item.key} type="button" variant="ghost" aria-label={`${index + 1}. ${item.label}`} aria-current={step === item.key ? "step" : undefined} disabled={busy || iconReading || (!appId && (item.key === "access" || item.key === "review")) || (!appId && item.key === "connection" && (!draft.name.trim() || !hostnameReady))} onClick={() => move(item.key)}><span className="aa-editor-step-number" aria-hidden="true">{index + 1}</span><span>{item.label}</span></Button>)}</nav><p className="aa-editor-rail-note">Routing changes go live after publishing.</p></aside>
    <div className="aa-editor-stage">
    <ErrorText>{error}</ErrorText>
    <div className="aa-editor-body" key={step}>
      {readOnly && savedDraft && step === "application" && <ResourceSummary title={currentStep.title} headingLevel={2} className="aa-editor-saved-summary" description="How this app appears to your team." actions={<span className="aa-editor-view-mode">Read only</span>} footer={<div className="aa-editor-actions aa-editor-readonly-actions"><Link to="/app-access/applications">Back to applications</Link><Button onClick={() => move("connection")}>Continue to connection<Icon name="chevron-right" size={16} /></Button></div>}>
        {settings && <Availability settings={settings} manage={manage} archived={archived} />}
        <dl aria-label="Saved application details" className="aa-editor-readonly-summary tnx-resource-facts">
          <div><dt>Name</dt><dd>{savedDraft.name}</dd></div>
          <div><dt>App icon</dt><dd><span className="aa-editor-summary-icon"><AppAccessIcon icon={savedDraft.icon} image={savedDraft.icon_data_url} size={26} /></span><span>{savedDraft.icon_data_url ? "Custom icon" : savedDraft.icon === "dashboard" ? "Dashboard" : savedDraft.icon === "globe" ? "Globe" : savedDraft.icon === "terminal" ? "Terminal" : "Application"}</span></dd></div>
          <div className="tnx-resource-fact-wide"><dt>Description</dt><dd>{savedDraft.description || <span className="aa-editor-value-empty">No description</span>}</dd></div>
          <div className="tnx-resource-fact-wide"><dt>Browser address</dt><dd className="aa-editor-value-hostname"><CopyApplicationAddress hostname={savedDraft.public_hostname} />{settings && !settings.domain_ready && <div className="aa-editor-domain-help">Domain setup required{configureDomains && <AppAccessDomainSetup label="View setup" />}</div>}</dd></div>
        </dl>
      </ResourceSummary>}
      {readOnly && savedDraft && step === "connection" && <ResourceSummary title={currentStep.title} headingLevel={2} className="aa-editor-saved-summary" description={currentStep.description} actions={<span className="aa-editor-view-mode">Read only</span>} footer={<div className="aa-editor-actions"><Link to="/app-access/applications">Back to applications</Link><Button variant="ghost" onClick={() => move("application")}>Back to application</Button><Button disabled={dirty || busy} onClick={() => move("access")}>Continue to access<Icon name="chevron-right" size={16} /></Button>{dirty && <span>Save the draft before continuing.</span>}</div>}>
        {settings && <Availability settings={settings} manage={manage} archived={archived} />}
        <dl aria-label="Saved connection details" className="aa-editor-readonly-summary tnx-resource-facts">
          <div className="tnx-resource-fact-wide"><dt>Origin URL</dt><dd>{savedDraft.origin_url}</dd></div>
          <div><dt>Gateway connector</dt><dd>{savedNode?.name ?? "Assigned gateway is unavailable"}</dd></div>
          <div><dt>Gateway status</dt><dd>{savedNode ? savedNode.status === "active" ? "Active gateway" : "Revoked gateway" : "Unavailable"}</dd></div>
        </dl>
        <details className="aa-editor-disclosure"><summary>Advanced connection settings</summary><div className="aa-editor-disclosure-content">
          <dl aria-label="Saved advanced connection settings" className="aa-editor-readonly-summary tnx-resource-facts">
            <div className="tnx-resource-fact-wide"><dt>Allowed private destination ranges</dt><dd>{savedDraft.allowed_destination_cidrs?.length ? savedDraft.allowed_destination_cidrs.join(", ") : "Safe public destinations only"}</dd></div>
            <div><dt>Origin certificate trust</dt><dd>{savedDraft.origin_ca_digest ? "Custom CA certificates" : "System certificate roots"}</dd></div>
            {savedDraft.origin_ca_digest && <div className="tnx-resource-fact-wide"><dt>Saved CA fingerprint</dt><dd className="aa-editor-value-fingerprint">{savedDraft.origin_ca_digest}</dd></div>}
            <div><dt>Idle timeout</dt><dd>{savedDraft.idle_timeout_seconds} seconds</dd></div>
            <div><dt>Maximum session</dt><dd>{savedDraft.absolute_timeout_seconds} seconds</dd></div>
          </dl>
          <p className="aa-editor-field-help">HTTPS verifies the origin hostname and certificate chain. Loopback, link-local, metadata and control plane destinations remain blocked.</p>
        </div></details>
        {appId && version !== null && savedGateway && <AppAccessConnection embedded key={`${orgId}:${appId}:${version}:${savedGateway}`} orgId={orgId} appId={appId} gatewayId={savedGateway} version={version} revision={savedApplication?.draft.revision} onCheck={setReviewCheck} canCheck={editable && eligibleGateway === true} dirty={dirty} />}
      </ResourceSummary>}
      {!readOnly && (step === "application" || step === "connection") && <ResourceSummary title={currentStep.title} headingLevel={2} className="aa-editor-editable-summary" description={currentStep.description} footer={editActions}>
        {settings && <Availability settings={settings} manage={manage} archived={archived} />}
        <form id={draftFormId} onSubmit={event => {
        if (step === "application") {
          if (!appId || !dirty) { event.preventDefault(); if (appId || (draft.name.trim() && hostnameReady && !iconReading)) move("connection"); }
          else void save(event, "connection");
        } else void save(event);
      }} className="aa-editor-form">
        <fieldset disabled={!editable || busy || iconReading} className="aa-editor-fields">
          {step === "application" && <div className="aa-editor-card"><div className="app-access-form-fields space-y-5">
            <Field label="Application name"><Input required maxLength={100} value={draft.name} onChange={event => change("name", event.target.value)} /></Field>
            <Field label="Description"><Input maxLength={1000} placeholder="Optional" value={draft.description} onChange={event => change("description", event.target.value)} /></Field>
            <AppAccessIconPicker icon={draft.icon} image={draft.icon_data_url} onIconChange={value => change("icon", value)} onImageChange={value => change("icon_data_url", value)} onReadingChange={setIconReading} />
            <AppAccessHostname value={draft.public_hostname} domain={settings?.base_domain ?? ""} original={savedApplication?.draft.public_hostname} onChange={value => change("public_hostname", value)} />
          </div></div>}
          {step === "connection" && <div className="aa-editor-card"><div className="app-access-form-fields space-y-5">
            <div><Field label="Origin URL"><Input required type="url" placeholder="https://your-private-app" value={draft.origin_url} onChange={event => change("origin_url", event.target.value)} /></Field><p className="aa-editor-field-help">HTTP or HTTPS, with the app served at its root path.</p></div>
            <Field label="Gateway connector"><Select required value={draft.gateway_id} onChange={event => change("gateway_id", event.target.value)}><option value="">Select a gateway</option>{draft.gateway_id && !selectedGateway && <option value={draft.gateway_id} disabled>Assigned gateway is unavailable</option>}{nodes.filter(node => node.status === "active" || node.id === draft.gateway_id).map(node => <option key={node.id} value={node.id} disabled={node.status !== "active"}>{node.name} · {node.status === "active" ? "Active gateway" : "Revoked: choose an active gateway"}</option>)}</Select></Field>
            <p className="aa-editor-field-help">Gateway enrollment does not confirm App Access capability. Save the draft to inspect the connector and check its origin connection.</p>
            <details className="aa-editor-disclosure"><summary>Advanced connection settings</summary><div className="aa-editor-disclosure-content space-y-5">
              <Field label="Allowed private destination ranges"><textarea className="w-full rounded-md border border-line bg-transparent p-2 font-mono text-sm" rows={3} maxLength={2080} value={(draft.allowed_destination_cidrs ?? []).join("\n")} onChange={event => change("allowed_destination_cidrs", event.target.value.split(/\n/).map(value => value.trim()))} /></Field>
              <p className="aa-editor-field-help">One private CIDR per line, up to 32. Empty allows safe public destinations only. Loopback, link-local, metadata and control plane addresses remain blocked.</p>
              <Field label="Origin certificate trust"><Select value={caMode} onChange={event => { const mode = event.target.value as typeof caMode; setCaMode(mode); setDraft(current => { const next = { ...current }; if (mode === "preserve") delete next.origin_ca_pem; else next.origin_ca_pem = ""; return next; }); setDirty(true); }}>{appId && <option value="preserve">Keep saved trust ({caDigest ? "custom CA" : "system roots"})</option>}<option value="system">System certificate roots</option><option value="custom">Custom public CA certificates</option></Select></Field>
              {caMode === "custom" && <Field label="Public CA certificate PEM"><textarea className="w-full rounded-md border border-line bg-transparent p-2 font-mono text-sm" rows={6} maxLength={32768} value={draft.origin_ca_pem ?? ""} onChange={event => change("origin_ca_pem", event.target.value)} /></Field>}
              <p className="aa-editor-field-help">HTTPS verifies the origin hostname and certificate chain. Custom trust accepts up to eight public CA certificates; paste no private keys.</p>
              {caDigest && <p className="break-all aa-editor-field-help">Saved CA fingerprint: {caDigest}</p>}
              <div className="grid min-w-0 gap-4 sm:grid-cols-2"><Field label="Idle timeout (seconds)"><Input required type="number" min={60} max={1800} value={draft.idle_timeout_seconds} onChange={event => change("idle_timeout_seconds", Number(event.target.value))} /></Field><Field label="Maximum session (seconds)"><Input required type="number" min={300} max={28800} value={draft.absolute_timeout_seconds} onChange={event => change("absolute_timeout_seconds", Number(event.target.value))} /></Field></div>
            </div></details>
          </div></div>}
        </fieldset>
        {dirty && <p role="status" className="aa-editor-field-help">Unsaved changes stay in this tab when you move between Application and Connection.</p>}
        </form>
        {appId && version !== null && savedGateway && step === "connection" && <AppAccessConnection embedded key={`${orgId}:${appId}:${version}:${savedGateway}`} orgId={orgId} appId={appId} gatewayId={savedGateway} version={version} revision={savedApplication?.draft.revision} onCheck={setReviewCheck} canCheck={editable && eligibleGateway === true} dirty={dirty} />}
      </ResourceSummary>}
      {appId && step === "access" && <ResourceSummary title={currentStep.title} headingLevel={2} className="aa-editor-access-summary" description={currentStep.description} footer={<div className="aa-editor-actions"><Button variant="ghost" onClick={() => move("connection")}>Back to connection</Button><Button onClick={() => move("review")}>Continue to review</Button></div>}>
        {settings && <Availability settings={settings} manage={manage} archived={archived} />}
        <div className="aa-editor-grants">{grant && !archived ? <AppAccessAccess orgId={orgId} appId={appId} permitted canViewEvents={canViewEvents} canViewAudit={canViewAudit} /> : <ErrorText>You do not have permission to manage application grants. Ask an administrator to configure access.</ErrorText>}</div>
        {savedApplication && <details className="aa-editor-disclosure"><summary>Multi-factor authentication</summary><div className="aa-editor-disclosure-content"><AppAccessMfaPolicy key={`${orgId}:${appId}`} orgId={orgId} application={savedApplication} canManage={manage && !archived} dirty={dirty} onChanged={application => { setSavedApplication(application); setVersion(application.version); setReviewCheck(null); }} onReload={() => setAttempt(value => value + 1)} /></div></details>}
        {manage && grant && !archived && <details className="aa-editor-disclosure"><summary>Catalog visibility &amp; app admin</summary><div className="aa-editor-disclosure-content"><AppAccessCatalogSettings key={`${orgId}:${appId}:catalog`} orgId={orgId} appId={appId} permitted dirty={dirty} onChanged={() => setAttempt(value => value + 1)} /></div></details>}
      </ResourceSummary>}
      {appId && step === "review" && savedApplication && <div className="aa-editor-review"><AppAccessPublication key={`${orgId}:${appId}:${version}`} orgId={orgId} userId={userId} application={savedApplication} check={reviewCheck} dirty={dirty} canManage={manage && !archived} canPublish={editable && eligibleGateway === true} publishUnavailableReason={!settings?.entitlement_available ? "Eligible license required" : !settings.enabled ? "App Access is disabled" : !settings.domain_ready ? "Domain setup required" : "Choose an active gateway"} onChanged={() => setAttempt(value => value + 1)} onArchived={() => navigate("/app-access/applications", { replace: true })} onRollback={() => { setStep("connection"); setAttempt(value => value + 1); }} notice={archived && settings ? <Availability settings={settings} manage={manage} archived={archived} /> : undefined} footer={<div className="aa-editor-actions"><Button variant="ghost" onClick={() => move("access")}>Back to access</Button></div>}>
        {sessionManage && <details className="aa-editor-disclosure"><summary>Application sessions</summary><div className="aa-editor-disclosure-content"><AppAccessSessions key={`${orgId}:${appId}`} orgId={orgId} appId={appId} /></div></details>}
      </AppAccessPublication></div>}
    </div>
    </div>
    </div>
  </section>;
}
