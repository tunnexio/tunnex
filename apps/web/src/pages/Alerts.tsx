import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertManagement, isAlertEventKey } from "../components/AlertManagement";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination from "../components/AppAccessPagination";
import { Button, ErrorText, Input, Loading, Modal } from "../components/ui";
import { api, loadOne, type AlertOccurrence, type AlertOccurrenceState, type Role } from "../lib/api";
import { useAuth } from "../lib/auth";
import { relativeAge } from "../lib/format";
import { can, HUMAN_ROLES } from "../lib/rbac";
import { useOrg } from "../lib/useOrg";
import "../network-workspaces.css";
import "../alerts-workspace.css";

type View = "active" | "history" | "management";
const validDate = (value: unknown) => typeof value === "string" && value.trim() !== "" && Number.isFinite(Date.parse(value));
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const validRole = (value: unknown): value is Role => typeof value === "string" && HUMAN_ROLES.includes(value as Role);
function validOccurrence(value: unknown, expectedState: AlertOccurrenceState): value is AlertOccurrence {
  return isRecord(value) && typeof value.id === "string" && value.id.length > 0 && typeof value.subject === "string"
    && typeof value.resource_type === "string" && ["agent", "gateway", "site", "device", "kubernetes_cluster", "kubernetes_service", "ipsec_connection"].includes(value.resource_type)
    && typeof value.resource_id === "string" && value.resource_id.length > 0 && typeof value.resource_name === "string" && isAlertEventKey(value.event_key)
    && typeof value.severity === "string" && ["critical", "warning", "info"].includes(value.severity) && value.state === expectedState
    && typeof value.occurrence_count === "number" && Number.isSafeInteger(value.occurrence_count) && value.occurrence_count >= 0
    && validDate(value.first_observed_at) && validDate(value.last_observed_at)
    && (value.resolved_at === undefined || value.resolved_at === null || validDate(value.resolved_at));
}

function productLabel(row: AlertOccurrence): string {
  if (row.resource_type === "kubernetes_cluster" || row.resource_type === "kubernetes_service") return "Kubernetes";
  if (row.resource_type === "ipsec_connection") return "Site-to-site";
  return row.resource_type.charAt(0).toUpperCase() + row.resource_type.slice(1);
}

function resourceHref(row: AlertOccurrence): string | null {
  switch (row.resource_type) {
    case "ipsec_connection": return "/site-to-site";
    case "gateway": return `/gateways/${encodeURIComponent(row.resource_id)}`;
    case "site": return `/sites?site=${encodeURIComponent(row.resource_id)}`;
    case "device": return "/devices";
    case "agent": return `/agents/${encodeURIComponent(row.resource_id)}`;
    case "kubernetes_cluster":
    case "kubernetes_service": return "/kubernetes";
    default: return null;
  }
}

function dateLabel(value: string | undefined | null) {
  return value && Number.isFinite(new Date(value).getTime()) ? new Date(value).toLocaleString() : "Not reported";
}

export default function Alerts() {
  const { org } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <AlertsWorkspace key={`${org?.id ?? "no-organization"}:${actor}`} />;
}

function AlertsWorkspace() {
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const actorId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [view, setView] = useState<View>("active");
  const [severity, setSeverity] = useState("all"), [query, setQuery] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [rows, setRows] = useState<AlertOccurrence[] | null>(null), [loadedView, setLoadedView] = useState<View | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(), [roleLoading, setRoleLoading] = useState(true), [roleError, setRoleError] = useState("");
  const alive = useRef(true), occurrenceRequest = useRef(0), roleRequest = useRef(0), currentView = useRef(view);
  currentView.current = view;
  useEffect(() => { alive.current = true; return () => { alive.current = false; occurrenceRequest.current++; roleRequest.current++; }; }, []);

  const loadRole = useCallback(async () => {
    if (!org || !actorId) return;
    const request = ++roleRequest.current;
    setRoleLoading(true); setMyRole(undefined); setRoleError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }));
    if (!alive.current || request !== roleRequest.current) return;
    setRoleLoading(false);
    if (!result.ok || !Array.isArray(result.data) || result.data.some(member => !isRecord(member) || typeof member.user_id !== "string") || new Set(result.data.map(member => member.user_id)).size !== result.data.length) { setRoleError(result.ok ? "Could not check alert permissions." : result.error); return; }
    const own = result.data.find(member => member.user_id === actorId);
    if (own && (!validRole(own.role) || (own.roles !== undefined && (!Array.isArray(own.roles) || !own.roles.length || !own.roles.every(validRole) || !own.roles.includes(own.role) || new Set(own.roles).size !== own.roles.length)))) { setRoleError("Could not check alert permissions."); return; }
    const roles = own?.roles ?? (own ? [own.role] : []);
    setMyRole(roles.includes("owner") ? "owner" : roles.includes("admin") ? "admin" : own?.role);
  }, [org?.id, actorId]);
  const load = useCallback(async () => {
    if (!org || view === "management") return;
    const request = ++occurrenceRequest.current, requestedView = view;
    setRows(null); setLoadedView(null); setError(null);
    const requestedState: AlertOccurrenceState = view === "active" ? "firing" : "resolved";
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/alert-occurrences", { params: { path: { orgId: org.id }, query: { state: requestedState } } }));
    if (!alive.current || request !== occurrenceRequest.current || currentView.current !== requestedView) return;
    if (!result.ok || !Array.isArray(result.data) || !result.data.every(row => validOccurrence(row, requestedState)) || new Set(result.data.map(row => row.id)).size !== result.data.length) { setError(result.ok ? "The alert response could not be read." : result.error); return; }
    setRows(result.data); setLoadedView(requestedView);
  }, [org?.id, view]);
  useEffect(() => { if (!orgLoading) void loadRole(); }, [orgLoading, loadRole]);
  useEffect(() => { if (!orgLoading) void load(); }, [orgLoading, load]);
  const canManage = !roleLoading && can(myRole, "alerting:manage");
  useEffect(() => { if (!roleLoading && !canManage && view === "management") setView("active"); }, [roleLoading, canManage, view]);
  const currentRows = loadedView === view ? rows : null;
  const filtered = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return (currentRows ?? []).filter(row => (severity === "all" || row.severity === severity) && terms.every(term => `${row.subject} ${row.resource_name} ${row.resource_id} ${productLabel(row)} ${row.event_key} ${row.severity}`.toLowerCase().includes(term)));
  }, [currentRows, severity, query]);
  const lastPage = Math.max(1, Math.ceil(filtered.length / pageSize)), currentPage = Math.min(page, lastPage);
  const shown = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const inspected = currentRows?.find(row => row.id === inspectedId);
  useEffect(() => { setPage(previous => Math.min(previous, lastPage)); }, [lastPage]);
  function changeView(next: View) { setView(next); setSeverity("all"); setQuery(""); setPage(1); setInspectedId(null); }
  function navigation(actions: ReactNode) {
    const items: View[] = ["active", "history", ...(canManage ? ["management" as const] : [])];
    return <div className="alerts-nav"><div role="tablist" aria-label="Alert views" className="alerts-tabs" onKeyDown={event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      const tabs = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
      const index = tabs.indexOf(document.activeElement as HTMLButtonElement);
      if (index < 0) return;
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      changeView(items[next]); tabs[next].focus();
    }}>{items.map(item => <button key={item} type="button" role="tab" aria-selected={view === item} tabIndex={view === item ? 0 : -1} onClick={() => changeView(item)}>{item[0].toUpperCase() + item.slice(1)}</button>)}</div><div className="alerts-nav-actions">{actions}</div></div>;
  }

  if (orgLoading) return <Loading label="Loading alerts…" size="page" />;
  if (orgFailed || !org) return <ErrorText>Could not load the organization for alerts.</ErrorText>;
  return <div className="network-management alerts-workspace">
    {view === "management" && canManage ? <AlertManagement orgId={org.id} canEdit={emailVerified} canAllowPrivate={myRole === "owner"} renderNavigation={navigation} onRefreshAuthority={loadRole} /> : <>
      {navigation(<Button variant="ghost" disabled={currentRows === null && !error} onClick={() => { void load(); void loadRole(); }}>Refresh</Button>)}
      {view === "management" ? <Loading label="Checking alert permissions…" /> : error ? <section className="alerts-read-state" role="alert"><h2>Could not load alerts.</h2>{error !== "Could not load alerts." && <p>{error}</p>}<Button variant="ghost" onClick={() => void load()}>Retry</Button></section> : currentRows === null ? <Loading label={`Loading ${view} alerts…`} /> : <section className="alerts-inventory" aria-label={view === "active" ? "Active alert inventory" : "Resolved alert inventory"}>
        <div className="alerts-inventory-toolbar"><Input type="search" aria-label="Search alerts" placeholder="Search alerts…" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} /><div className="alerts-filters" aria-label="Filter severity">{["all", "critical", "warning", "info"].map(value => <button type="button" key={value} aria-pressed={severity === value} onClick={() => { setSeverity(value); setPage(1); }}>{value === "all" ? "All severities" : value}</button>)}</div><span className="alerts-result-count">{filtered.length} {view === "active" ? "active" : "resolved"}</span></div>
        {shown.length > 0 ? <div className="alerts-table-scroll"><table className="alerts-native-table alerts-occurrence-table"><caption className="sr-only">{view === "active" ? "Active alerts" : "Resolved alert history"}</caption><thead><tr><th>Severity</th><th>Condition</th><th>Resource</th><th>{view === "active" ? "Last observed" : "Resolved"}</th></tr></thead><tbody>{shown.map(row => {
          const href = resourceHref(row), label = row.resource_name || row.resource_id;
          return <tr key={row.id}><td><span className="alert-severity" data-severity={row.severity}>{row.severity}</span></td><td><button type="button" className="alert-open" onClick={() => setInspectedId(row.id)}>{row.subject}</button></td><td>{href ? <Link className="alert-resource-link" to={href}>{label}</Link> : <span>{label}</span>}<span className="alert-secondary">{productLabel(row)}</span></td><td><span className="alert-observed" title={dateLabel(view === "active" ? row.last_observed_at : row.resolved_at)}>{view === "active" ? relativeAge(row.last_observed_at) : row.resolved_at ? relativeAge(row.resolved_at) : "Not reported"}</span></td></tr>;
        })}</tbody></table></div> : <AppAccessEmptyState icon={null} title={query.trim() ? "No alerts match this search." : severity !== "all" ? "No alerts match this severity." : view === "active" ? "No active conditions have been recorded." : "No resolved alerts recorded yet."} description={query.trim() || severity !== "all" ? "Try another search or view all severities." : undefined} action={query.trim() || severity !== "all" ? <Button variant="ghost" onClick={() => { setQuery(""); setSeverity("all"); setPage(1); }}>Clear filters</Button> : undefined} />}
        <AppAccessPagination page={currentPage} pageSize={pageSize} count={shown.length} hasNext={currentPage < lastPage} maxOffset={null} previousLabel="Previous alerts page" nextLabel="Next alerts page" onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} />
        {currentRows.length >= 200 && <p className="alerts-bounded-note">Up to 200 recorded conditions are available in this view.</p>}
      </section>}
      {roleError && <p className="alerts-permission-note">Management permissions could not be checked. <button type="button" onClick={() => void loadRole()}>Retry permissions</button></p>}
    </>}
    {inspected && view !== "management" && <Modal title={inspected.subject} placement="right" size="enrollment" onDismiss={() => setInspectedId(null)} actions={<Button variant="ghost" onClick={() => setInspectedId(null)}>Close</Button>}><div className="alert-occurrence-detail"><div className="alert-detail-state"><span className="alert-severity" data-severity={inspected.severity}>{inspected.severity}</span><span>{inspected.state === "firing" ? "Active condition" : "Resolved"}</span></div><dl className="alert-detail-facts">{[
      ["Resource", inspected.resource_name || inspected.resource_id], ["Product", productLabel(inspected)], ["First observed", dateLabel(inspected.first_observed_at)], ["Last observed", dateLabel(inspected.last_observed_at)], ["Occurrences", inspected.occurrence_count], ["Signal", inspected.event_key], ...(inspected.state === "resolved" ? [["Resolved", dateLabel(inspected.resolved_at)]] : []),
    ].map(([label, value]) => <div key={String(label)}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>{resourceHref(inspected) && <Link className="alert-detail-link" to={resourceHref(inspected)!}>Open {productLabel(inspected).toLowerCase()}</Link>}</div></Modal>}
  </div>;
}
