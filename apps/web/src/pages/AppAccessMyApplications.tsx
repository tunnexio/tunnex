import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { Badge, Button, ErrorText, Input, Loading, PageHeader } from "../components/ui";

import { Icon } from "../components/Icon";
import { AppAccessIcon } from "../components/AppAccessIcon";
import AppAccessMfaChallenge from "../components/AppAccessMfaChallenge";
import AppAccessMemberTabs from "../components/AppAccessMemberTabs";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessDomainSetup from "../components/AppAccessDomainSetup";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";

function browserDomain(launchURL: string) {
  try { return new URL(launchURL).hostname; } catch { return ""; }
}

type MyApps = components["schemas"]["AppAccessMyApps"];
type MySessions = components["schemas"]["AppAccessMySessions"];
const availabilityText: Record<MyApps["availability"], string> = {
  available: "Only published applications granted to you appear here.",
  feature_disabled: "Applications is off for this organization.",
  feature_unavailable: "Applications requires an eligible license.",
  domain_unavailable: "Application access setup is not complete. Contact your administrator.",
  parent_unavailable: "Sign in again to open applications with this login.",
};
const catalogIntentKey = "tunnex.appAccess.catalogLaunch";
const catalogIntentLifetime = 2 * 60 * 1000;
type CatalogLaunchIntent = { version: 1; orgId: string; appId: string; userId: string; origin: string; target: "/"; createdAt: number };

function isTopLevel() {
  try { return window.top === window.self; } catch { return false; }
}

function catalogStartURL(raw: string) {
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash || url.search || url.pathname !== "/__tunnex_app/start") throw new Error("Invalid application start URL");
  return url;
}

function takeCatalogIntent(): CatalogLaunchIntent | null {
  try {
    const raw = window.sessionStorage.getItem(catalogIntentKey);
    if (!raw) return null;
    // Remove before issuing any one-use request. A failed/uncertain attempt must
    // never become an automatic retry when this page is revisited.
    window.sessionStorage.removeItem(catalogIntentKey);
    const intent: unknown = JSON.parse(raw);
    if (!intent || typeof intent !== "object") return null;
    const value = intent as Partial<CatalogLaunchIntent>;
    if (value.version !== 1 || typeof value.orgId !== "string" || typeof value.appId !== "string" || typeof value.userId !== "string" || typeof value.origin !== "string" || value.target !== "/" || typeof value.createdAt !== "number" || !Number.isFinite(value.createdAt)) return null;
    const age = Date.now() - value.createdAt;
    if (age < 0 || age > catalogIntentLifetime || catalogStartURL(`${value.origin}/__tunnex_app/start`).origin !== value.origin) return null;
    return value as CatalogLaunchIntent;
  } catch { return null; }
}

export default function AppAccessMyApplications({ orgId, canUse = true }: { orgId: string; canUse?: boolean }) {
  const { state: auth } = useAuth();
  const [params, setParams] = useSearchParams();
  const showingSessions = params.get("view") === "sessions";
  const search = (params.get("q") ?? "").slice(0, 100);
  const pageSize = appAccessPageSize(params.get("page_size"));
  const page = Math.min(Math.floor(10000 / pageSize) + 1, Math.max(1, Math.floor(Number(params.get("page"))) || 1));
  const [apps, setApps] = useState<MyApps | null>(null);
  const [sessions, setSessions] = useState<MySessions | null>(null);
  const [error, setError] = useState("");
  const [sessionError, setSessionError] = useState("");
  const [reload, setReload] = useState(0);
  const [sessionReload, setSessionReload] = useState(0);
  const [sessionPage, setSessionPage] = useState(1);
  const [sessionPageSize, setSessionPageSize] = useState(20);
  const [revoking, setRevoking] = useState("");
  const [notice, setNotice] = useState("");
  const [launchError, setLaunchError] = useState("");
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    let cancelled = false;
    setApps(null); setError("");
    if (!canUse || showingSessions) return () => { cancelled = true; };
    void api.GET("/api/v1/organizations/{orgId}/app-access/my-apps", { params: { path: { orgId }, query: { limit: pageSize, offset: (page - 1) * pageSize, search } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load your applications."));
      else setApps(result.data);
    }).catch(() => { if (!cancelled) setError("Could not reach the API. Retry your applications."); });
    return () => { cancelled = true; };
  }, [orgId, page, pageSize, search, reload, canUse, showingSessions]);

  useEffect(() => {
    let cancelled = false;
    setSessions(null); setSessionError("");
    if (!showingSessions) return () => { cancelled = true; };
    void api.GET("/api/v1/organizations/{orgId}/app-access/my-sessions", { params: { path: { orgId }, query: { limit: sessionPageSize, offset: (sessionPage - 1) * sessionPageSize } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setSessionError(apiErrorMessage(result.error, "Could not load your application sessions."));
      else setSessions(result.data);
    }).catch(() => { if (!cancelled) setSessionError("Could not reach your application sessions."); });
    return () => { cancelled = true; };
  }, [orgId, sessionReload, sessionPage, sessionPageSize, showingSessions]);

  function changeSearch(value: string) {
    const next = new URLSearchParams(params);
    next.delete("page");
    if (value) next.set("q", value);
    else next.delete("q");
    setParams(next);
  }

  function changeCatalogPage(nextPage: number) {
    const next = new URLSearchParams(params);
    next.set("page", String(nextPage));
    setParams(next);
  }

  function changeCatalogPageSize(size: number) {
    const next = new URLSearchParams(params);
    next.set("page_size", String(size));
    next.delete("page");
    setParams(next);
  }

  function changeView(sessionsView: boolean) {
    const next = new URLSearchParams(params);
    if (sessionsView) next.set("view", "sessions");
    else next.delete("view");
    setParams(next);
  }

  function openApplication(app: MyApps["items"][number]) {
    if (!canUse || auth.status !== "authed") return;
    setLaunchError(launchCatalogApplication(app, orgId, auth.user.id));
  }

  async function revoke(id: string) {
    if (revoking) return;
    setRevoking(id); setSessionError(""); setNotice("");
    try {
      const result = await api.DELETE("/api/v1/organizations/{orgId}/app-access/my-sessions/{sessionId}", { params: { path: { orgId, sessionId: id } } });
      if (!mounted.current) return;
      if (result.error) setSessionError(apiErrorMessage(result.error, "Could not revoke this application session. Please retry."));
      else { setNotice("Application session access revoked."); setSessionReload(value => value + 1); }
    } catch { if (mounted.current) setSessionError("Could not confirm session revocation. Please retry."); }
    finally { if (mounted.current) setRevoking(""); }
  }

  return <div className="app-access-workspace network-management app-access-inventory-workspace app-access-my-apps min-w-0 space-y-6 [overflow-wrap:anywhere]">
    <div className="app-access-heading"><PageHeader title="App Access" navigationTitle actions={<AppAccessDomainSetup />} /></div>
    <AppAccessMemberTabs orgId={orgId} />
    {!canUse && <div className="space-y-3"><ErrorText>You do not have permission to launch applications. You can still revoke your own sessions.</ErrorText>{!showingSessions && <Button variant="ghost" onClick={() => changeView(true)}>My sessions</Button>}</div>}
    {canUse && !showingSessions && <section aria-label="My Applications" className="app-access-my-applications">
      <ErrorText>{launchError}</ErrorText>
      {apps && apps.items.length > 0 && apps.availability !== "available" && <p role="status" className="app-access-notice">{availabilityText[apps.availability]}</p>}
      {apps?.availability === "parent_unavailable" && apps.items.length > 0 && <FreshLogin />}
      <div className="app-access-toolbar">
        <div className="app-access-search"><Icon name="search" size={17} /><Input type="search" aria-label="Search applications" placeholder="Search your applications…" maxLength={100} value={search} onChange={event => changeSearch(event.target.value)} /></div>
        <button type="button" className="app-access-refresh" aria-label="Refresh my applications" title="Refresh my applications" disabled={apps === null && !error} onClick={() => setReload(value => value + 1)}><Icon name="refresh-cw" size={17} /></button>
        {apps && <span className="app-access-result-count">{apps.items.length}{apps.items.length === pageSize ? "+" : ""} application{apps.items.length === 1 ? "" : "s"}</span>}
        <Button className="app-access-view-toggle" variant="ghost" onClick={() => changeView(true)}>My sessions</Button>
      </div>
      {error ? <div className="mt-5 space-y-3"><ErrorText>{error}</ErrorText><Button onClick={() => setReload(value => value + 1)}>Retry applications</Button></div> : !apps ? <Loading label="Loading your applications…" /> : !apps.items.length ? <AppAccessEmptyState
        title={apps.availability !== "available" ? "Application access is unavailable" : search ? "No applications match your search." : page > 1 ? "No more applications" : "No applications yet"}
        description={apps.availability !== "available" ? availabilityText[apps.availability] : search ? "Try a different name or clear the search to see all your applications." : page > 1 ? "Return to the previous page to see your applications." : "No published applications are granted to you. Ask your administrator for access."}
        action={apps.availability === "parent_unavailable" ? <FreshLogin /> : apps.availability !== "available" ? undefined : search ? <Button variant="ghost" onClick={() => changeSearch("")}>Clear search</Button> : page > 1 ? undefined : <Link className="app-access-inline-link" to="/app-access/company-applications">Browse company apps</Link>}
      /> : <ul className="app-access-launch-list">{apps.items.map(app => <li key={app.id} className="app-access-launch-row">
        <div className="app-access-launch-identity"><span className="app-access-launch-icon"><AppAccessIcon icon={app.icon} image={app.icon_data_url} className="h-5 w-5" /></span><div className="app-access-launch-copy"><h2>{app.name}</h2><p>{browserDomain(app.launch_url)}</p>{app.description && <p className="app-access-launch-description">{app.description}</p>}</div></div>
        <div className="app-access-launch-assurance">{app.require_mfa && <><Badge>MFA required</Badge><span>{app.mfa_setup_required ? "Set up MFA when you open this app" : app.mfa_required ? "Verification needed" : "Recent verification can be reused"}</span></>}</div>
        <a className="app-access-launch-action" aria-label={`Open ${app.name}`} href={app.launch_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" onClick={event => { event.preventDefault(); if (event.detail <= 1) openApplication(app); }}>Open app<Icon name="chevron-right" className="h-4 w-4" /></a>
      </li>)}</ul>}
      {apps && <AppAccessPagination page={page} pageSize={pageSize} count={apps.items.length} hasNext={apps.items.length >= pageSize} onPageChange={changeCatalogPage} onPageSizeChange={changeCatalogPageSize} />}
    </section>}
    {showingSessions && <section className="app-access-session-workspace" aria-label="My application sessions">
      <div className="app-access-panel-header"><div><h2>My sessions</h2><p>Signing out here ends one application session. Your console login and other application sessions stay available.</p></div><Button variant="ghost" onClick={() => changeView(false)}>My Applications</Button></div>
      {notice && <p role="status" className="app-access-notice">{notice}</p>}
      {sessionError ? <div className="space-y-3"><ErrorText>{sessionError}</ErrorText><Button variant="ghost" onClick={() => setSessionReload(value => value + 1)}>Retry sessions</Button></div> : !sessions ? <Loading label="Loading your sessions…" /> : !sessions.items.length ? <AppAccessEmptyState icon="app-grid" title={sessionPage === 1 ? "No active sessions" : "No more sessions"} description={sessionPage === 1 ? "No active application sessions." : "No more application sessions."} /> : <ul className="app-access-data-list app-access-session-list">{sessions.items.map(item => <li key={item.id} className="app-access-data-row">
        <div><div className="mb-2 flex flex-wrap items-center gap-2"><p className="font-medium">{item.app_label}</p><Badge>{item.current_parent ? "This login" : "Another login"}</Badge></div><p className="text-sm text-ink-secondary">Expires <time dateTime={item.expires_at}>{new Date(item.expires_at).toLocaleString()}</time></p><p className="text-sm text-ink-secondary">Started <time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time> · <span className="font-mono">Session {item.id.slice(0, 8)}</span></p></div>
        <Button variant="ghost" size="sm" aria-label={`Sign out of ${item.app_label} · Session ${item.id.slice(0, 8)}`} disabled={!!revoking} onClick={() => void revoke(item.id)}>{revoking === item.id ? "Revoking…" : `Sign out of ${item.app_label}`}</Button>
      </li>)}</ul>}
      {sessions && <AppAccessPagination page={sessionPage} pageSize={sessionPageSize} count={sessions.items.length} hasNext={sessions.items.length >= sessionPageSize} busy={!!revoking} previousLabel="Previous sessions" nextLabel="More sessions" onPageChange={next => setSessionPage(Math.min(Math.floor(10000 / sessionPageSize) + 1, Math.max(1, next)))} onPageSizeChange={size => { setSessionPageSize(size); setSessionPage(1); }} />}
    </section>}
  </div>;
}

// Both catalogs use the same bound one-use launch intent and the existing MFA flow.
function launchCatalogApplication(app: { id: string; launch_url: string }, orgId: string, userId: string) {
  if (!isTopLevel()) return "Open My Applications in its own browser tab to launch an application.";
  let tab: PendingApplicationTab | null = null;
  try {
    const url = catalogStartURL(app.launch_url);
    tab = createPendingTab();
    const intent: CatalogLaunchIntent = { version: 1, orgId, appId: app.id, userId, origin: url.origin, target: "/", createdAt: Date.now() };
    const encoded = JSON.stringify(intent);
    tab.window.sessionStorage.setItem(catalogIntentKey, encoded);
    if (tab.window.sessionStorage.getItem(catalogIntentKey) !== encoded || !ownsPendingTab(tab)) throw new Error("Application tab unavailable");
    tab.window.location.replace(url.href);
    tab = null;
    return "";
  } catch (error) {
    return error instanceof PopupBlockedError ? "Your browser blocked the new tab. Allow pop-ups for this site, then open the application again." : "Could not open the application in a new tab. Please try again.";
  } finally { closePendingTab(tab); }
}
export function AppAccessOpenLink({ orgId, app }: { orgId: string; app: { id: string; name: string; launch_url: string } }) {
  const { state: auth } = useAuth();
  const [error, setError] = useState("");
  return <><a className="inline-flex items-center gap-2 text-sm font-medium text-brand underline underline-offset-4" href={app.launch_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" onClick={event => { event.preventDefault(); if (event.detail <= 1 && auth.status === "authed") setError(launchCatalogApplication(app, orgId, auth.user.id)); }}>Open {app.name}<Icon name="chevron-right" className="h-4 w-4" /></a><ErrorText>{error}</ErrorText></>;
}

function FreshLogin() {
  const { logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  return <Button disabled={busy} onClick={() => { setBusy(true); void logout().then(ok => { if (ok) navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`, { replace: true }); }).finally(() => setBusy(false)); }}>Sign in again</Button>;
}

type PendingApplicationTab = { window: Window; document: Document };
class PopupBlockedError extends Error {}

function ownsPendingTab(tab: PendingApplicationTab) {
  try {
    return !tab.window.closed && tab.window.location.href === "about:blank" && tab.window.document === tab.document;
  } catch { return false; }
}

function closePendingTab(tab: PendingApplicationTab | null) {
  try { if (tab && ownsPendingTab(tab)) tab.window.close(); } catch { /* The browser may already have disposed of the context. */ }
}

function createPendingTab(): PendingApplicationTab {
  // Keep a handle for failure cleanup; noopener window features can return null.
  const popup = window.open("about:blank", "_blank");
  if (!popup) throw new PopupBlockedError();
  const tab = { window: popup, document: popup.document };
  try {
    popup.opener = null;
    if (popup.opener !== null || !ownsPendingTab(tab)) throw new Error("Application tab unavailable");
    const referrer = popup.document.createElement("meta");
    referrer.name = "referrer"; referrer.content = "no-referrer";
    popup.document.head.append(referrer);
    popup.document.title = "Opening application";
    popup.document.body.textContent = "Opening your application…";
    return tab;
  } catch (error) { closePendingTab(tab); throw error; }
}

export function AppAccessLaunch() {
  const { state: auth } = useAuth();
  const authenticatedUserId = auth.status === "authed" ? auth.user.id : "";
  const { org, orgs, loading, setOrg } = useOrg();
  const [params] = useSearchParams();
  const location = useLocation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [freshLogin, setFreshLogin] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [opened, setOpened] = useState(false);
  const [checkingIntent, setCheckingIntent] = useState(true);
  const [automatic, setAutomatic] = useState(false);
  const [mfa, setMfa] = useState<"verify" | "setup" | null>(null);
  const automaticIntent = useRef<CatalogLaunchIntent | null>(null);
  const active = useRef(true);
  const generation = useRef(0);
  const issued = useRef(new Set<string>());
  const pendingTab = useRef<PendingApplicationTab | null>(null);
  const orgId = params.get("orgId") ?? "";
  const appId = params.get("appId") ?? "";
  const nonce = params.get("nonce_hash") ?? "";
  const target = params.get("target") ?? "/";
  const handoffKey = `${orgId}:${appId}:${nonce}`;
  useEffect(() => {
    active.current = true; generation.current++;
    const alreadyIssued = issued.current.has(handoffKey);
    setError(alreadyIssued ? "This application handoff has already been requested. Open a fresh link from My Applications." : "");
    setBusy(false); setFreshLogin(false); setAttempted(alreadyIssued); setOpened(false); setCheckingIntent(true); setAutomatic(false); setMfa(null); automaticIntent.current = null;
    return () => {
      active.current = false;
      closePendingTab(pendingTab.current);
      pendingTab.current = null;
    };
  }, [org?.id, location.search, handoffKey, authenticatedUserId]);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const valid = uuid.test(orgId) && uuid.test(appId) && /^[0-9a-f]{64}$/.test(nonce) && target.startsWith("/") && !target.startsWith("//") && target.length <= 8192 && !/[\\\u0000-\u0020\u007f]/.test(target) && !["orgId", "appId", "nonce_hash", "target"].some(key => params.getAll(key).length > 1);
  const membership = orgs.find(item => item.id === orgId);
  async function launch(automatic?: CatalogLaunchIntent) {
    if (!valid || busy || issued.current.has(handoffKey) || org?.id !== orgId || !isTopLevel()) return;
    const requestGeneration = generation.current;
    setError("");
    let tab: PendingApplicationTab | null = null;
    try {
      if (!automatic) {
        tab = createPendingTab();
        pendingTab.current = tab;
      }
      issued.current.add(handoffKey);
      setAttempted(true); setBusy(true);
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/my-apps/{appId}/launch", { params: { path: { orgId, appId } }, body: { nonce_hash: nonce, relative_target: target } });
      if (!active.current || requestGeneration !== generation.current) return;
      if (result.error || !result.data) {
        const code = apiErrorCode(result.error);
        if (code === "app_mfa_required" || code === "app_mfa_setup_required") {
          // These explicit server outcomes occur before consuming the nonce.
          // Uncertain network errors and other denials keep the one-use guard.
          issued.current.delete(handoffKey);
          setAttempted(false);
          setMfa(code === "app_mfa_setup_required" ? "setup" : "verify");
          return;
        }
        setError(apiErrorMessage(result.error, "This application could not be opened. Reopen it from My Applications."));
        setFreshLogin(code === "app_login_required");
        return;
      }
      const url = new URL(result.data.redirect_url);
      if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash || url.pathname !== "/__tunnex_app/redeem" || !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get("code") ?? "") || url.searchParams.size !== 1) throw new Error("Invalid application handoff");
      if (automatic) {
        if (url.origin !== automatic.origin) throw new Error("Application origin changed");
        // We are already in the child created by the catalog click.
        window.location.replace(url.href);
      } else {
        if (!tab || !ownsPendingTab(tab)) throw new Error("Application tab closed or changed");
        tab.window.location.replace(url.href);
      }
      // Navigation transfers ownership to the app; cleanup must never close it.
      pendingTab.current = null;
      tab = null;
      setOpened(true);
    } catch (error) { if (active.current && requestGeneration === generation.current) setError(error instanceof PopupBlockedError ? "Your browser blocked the new tab. Allow pop-ups for this site, then try again." : "Could not complete application handoff. Reopen it from My Applications."); }
    finally {
      closePendingTab(tab);
      if (pendingTab.current === tab) pendingTab.current = null;
      if (active.current && requestGeneration === generation.current) setBusy(false);
    }
  }
  useEffect(() => {
    if (loading || auth.status === "loading") return;
    let cancelled = false;
    // StrictMode replays effect setup/cleanup. Do not consume intent or issue a
    // code until that synchronous replay has settled for this page generation.
    queueMicrotask(() => {
      if (cancelled) return;
      setCheckingIntent(false);
      if (!authenticatedUserId || !isTopLevel()) return;
      const intent = takeCatalogIntent();
      if (!intent || !valid || !membership || org?.id !== orgId || intent.orgId !== orgId || intent.appId !== appId || intent.userId !== authenticatedUserId || intent.target !== target) return;
      setAutomatic(true);
      automaticIntent.current = intent;
      void launch(intent);
    });
    return () => { cancelled = true; };
  }, [loading, auth.status, authenticatedUserId, org?.id, location.search, handoffKey, valid, !!membership, target]);
  function verified() {
    if (!active.current) return;
    setMfa(null); setError("");
    const intent = automaticIntent.current;
    if (intent) void launch(intent);
  }
  if (loading || auth.status === "loading" || checkingIntent) return <Loading />;
  return <section className="max-w-xl space-y-4">
    <PageHeader title={automatic ? "Opening application" : "Open application"} subtitle={automatic ? "Connecting securely" : "Continue using your signed-in account"} />
    {!isTopLevel() ? <ErrorText>Open this application from a full browser tab.</ErrorText> : !valid || !membership ? <ErrorText>This application link is invalid or unavailable to your account. Open a fresh link from My Applications.</ErrorText> : org?.id !== orgId ? <><p>Continue in {membership.name} to open this application.</p><Button onClick={() => setOrg(orgId)}>Switch to {membership.name}</Button></> : mfa ? <AppAccessMfaChallenge key={handoffKey + ":" + authenticatedUserId} setupRequired={mfa === "setup"} onVerified={verified} /> : automatic ? <>
      {error ? <><ErrorText>{error}</ErrorText>{freshLogin && <FreshLogin />}</> : <p role="status">Opening application…</p>}
    </> : <>
      {opened ? <p role="status">Application opened in a new tab. You can return to My Applications.</p> : <p>Your administrator’s current access rules apply when you continue. The application opens in a new tab.</p>}
      <ErrorText>{error}</ErrorText>
      {freshLogin ? <FreshLogin /> : (!attempted || busy) && <Button disabled={busy} onClick={() => void launch()}>{busy ? "Opening application…" : "Continue to application"}</Button>}
    </>}
    <Link className="block text-brand" to="/app-access/my-applications">Back to My Applications</Link>
  </section>;
}
