import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, apiErrorMessage, loadOne, type AlertDelivery, type AlertDestination, type AlertDestinationKind, type AlertEventKey, type AlertingSetting } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading, Modal, Select, RefreshButton } from "./ui";
import { Link } from "react-router-dom";
import AppAccessEmptyState from "./AppAccessEmptyState";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessRowMenu from "./AppAccessRowMenu";
import { ResourceSummary } from "./ResourceSummary";

const labels: Record<AlertEventKey, string> = {
  "agent.offline": "Agent offline", "agent.denial_spike": "Agent denial spike", "agent.access_expiring": "Agent access expiring", "agent.rotation_failed": "Agent rotation failed", "agent.configuration_drift": "Agent configuration drift",
  "gateway.offline": "Gateway offline", "gateway.policy_degraded": "Gateway policy degraded", "site.link_down": "WireGuard site link down", "ipsec.tunnel_down": "IPsec tunnel down", "ipsec.connection_down": "IPsec connection down", "ipsec.status_unavailable": "IPsec status unavailable", "device.offline": "Device offline", "device.posture_blocked": "Device posture blocked",
  "kubernetes.connector_degraded": "Connector degraded", "kubernetes.inventory_stale": "Inventory stale", "kubernetes.service_unavailable": "Service unavailable",
};
const groups: Array<{ label: string; keys: AlertEventKey[] }> = [
  { label: "Gateways", keys: ["gateway.offline", "gateway.policy_degraded"] },
  { label: "Site-to-site", keys: ["site.link_down", "ipsec.tunnel_down", "ipsec.connection_down", "ipsec.status_unavailable"] },
  { label: "Devices", keys: ["device.offline", "device.posture_blocked"] },
  { label: "Kubernetes", keys: ["kubernetes.connector_degraded", "kubernetes.inventory_stale", "kubernetes.service_unavailable"] },
  { label: "AI agents", keys: ["agent.offline", "agent.denial_spike", "agent.access_expiring", "agent.rotation_failed", "agent.configuration_drift"] },
];
const kinds: Record<AlertDestinationKind, string> = { webhook: "Webhook", slack: "Slack", teams: "Microsoft Teams", pagerduty: "PagerDuty", opsgenie: "Opsgenie", discord: "Discord", google_chat: "Google Chat", email: "Email" };
const severities = ["info", "warning", "critical"];
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const validDate = (value: unknown) => typeof value === "string" && value.trim() !== "" && Number.isFinite(Date.parse(value));
const nonnegativeInteger = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
export function isAlertEventKey(value: unknown): value is AlertEventKey {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(labels, value);
}
function validRoute(value: unknown): value is AlertDestination {
  return isRecord(value) && typeof value.id === "string" && value.id.length > 0 && typeof value.name === "string" && value.name.trim().length > 0
    && typeof value.kind === "string" && Object.prototype.hasOwnProperty.call(kinds, value.kind)
    && typeof value.endpoint_host === "string" && value.endpoint_host.length > 0 && typeof value.endpoint_fingerprint === "string" && value.endpoint_fingerprint.length > 0
    && typeof value.archived === "boolean" && typeof value.allow_private === "boolean"
    && typeof value.severity_floor === "string" && severities.includes(value.severity_floor)
    && typeof value.cooldown_seconds === "number" && Number.isSafeInteger(value.cooldown_seconds) && value.cooldown_seconds >= 60 && value.cooldown_seconds <= 86400
    && validDate(value.created_at) && validDate(value.updated_at);
}
function validDelivery(value: unknown): value is AlertDelivery {
  return isRecord(value) && typeof value.id === "string" && value.id.length > 0 && typeof value.destination_id === "string" && value.destination_id.length > 0
    && isAlertEventKey(value.event_key) && typeof value.severity === "string" && severities.includes(value.severity)
    && typeof value.state === "string" && ["pending", "delivering", "sent", "failed"].includes(value.state)
    && nonnegativeInteger(value.attempts) && nonnegativeInteger(value.suppressed_count) && validDate(value.created_at)
    && (value.sent_at === undefined || validDate(value.sent_at)) && (value.failed_at === undefined || validDate(value.failed_at))
    && (value.last_error === undefined || typeof value.last_error === "string");
}
function validSubscriptions(value: unknown): value is AlertEventKey[] {
  return Array.isArray(value) && value.every(isAlertEventKey) && new Set(value).size === value.length;
}
const endpointMeta = (kind: AlertDestinationKind) => kind === "email" ? ["Recipient", "oncall@example.com", "email"] : kind === "pagerduty" ? ["Routing key", "Paste PagerDuty routing key", "password"] : kind === "opsgenie" ? ["API key", "Paste Opsgenie API key", "password"] : ["Endpoint", "https://alerts.example.com/tunnex", "url"];
const supportsPrivate = (kind: AlertDestinationKind) => !["email", "pagerduty", "opsgenie"].includes(kind);
const dateLabel = (value?: string) => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).toLocaleString() : "Not reported";
const routeSignature = (route: AlertDestination) => `${route.id}:${route.name}:${route.updated_at ?? ""}:${route.endpoint_fingerprint}:${route.archived}`;
type SubscriptionRead = { data: AlertEventKey[] | null; error: string };
type ManagementProps = { orgId: string; canEdit: boolean; canAllowPrivate: boolean; renderNavigation?: (actions: ReactNode) => ReactNode; onRefreshAuthority?: () => Promise<void> };

export function AlertManagement(props: ManagementProps) {
  return <AlertManagementWorkspace key={`${props.orgId}:${props.canEdit}:${props.canAllowPrivate}`} {...props} />;
}

function AlertManagementWorkspace({ orgId, canEdit, canAllowPrivate, renderNavigation, onRefreshAuthority }: ManagementProps) {
  const [setting, setSetting] = useState<AlertingSetting | null>(null), [routes, setRoutes] = useState<AlertDestination[] | null>(null), [deliveries, setDeliveries] = useState<AlertDelivery[] | null>(null);
  const [subs, setSubs] = useState<Record<string, SubscriptionRead>>({});
  const [readErrors, setReadErrors] = useState({ setting: "", routes: "", deliveries: "" });
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [signalError, setSignalError] = useState<{ routeId: string; message: string } | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [creating, setCreating] = useState(false);
  const [section, setSection] = useState<"routes" | "deliveries">("routes");
  const [query, setQuery] = useState(""), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [inspectedId, setInspectedId] = useState<string | null>(null), [routeStage, setRouteStage] = useState<"overview" | "signals">("overview");
  const [archiveTarget, setArchiveTarget] = useState<AlertDestination | null>(null);
  const alive = useRef(true), request = useRef(0), subscriptionRequests = useRef<Record<string, number>>({}), locked = useRef(false), ready = useRef(false);
  const currentRoutes = useRef<AlertDestination[] | null>(null), currentSubs = useRef<Record<string, SubscriptionRead>>({});
  useEffect(() => { alive.current = true; return () => { alive.current = false; ready.current = false; request.current++; }; }, []);
  const load = useCallback(async () => {
    const generation = ++request.current;
    ready.current = false; setLoading(true); setSetting(null); setRoutes(null); setDeliveries(null); setSubs({});
    setReadErrors({ setting: "", routes: "", deliveries: "" });
    const [s, r, d] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/alerting-settings", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/alert-destinations", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/alert-deliveries", { params: { path: { orgId } } })),
    ]);
    if (!alive.current || generation !== request.current) return;
    const nextRoutes = r.ok && Array.isArray(r.data) && r.data.every(validRoute) && new Set(r.data.map(route => route.id)).size === r.data.length ? r.data.filter(route => !route.archived) : null;
    const nextDeliveries = d.ok && Array.isArray(d.data) && d.data.every(validDelivery) && new Set(d.data.map(delivery => delivery.id)).size === d.data.length ? d.data : null;
    const nextSetting = s.ok && typeof s.data?.enabled === "boolean" ? s.data : null;
    const pairs = await Promise.all((nextRoutes ?? []).map(async route => {
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions", { params: { path: { orgId, destinationId: route.id } } }));
      const data = result.ok && validSubscriptions(result.data) ? result.data : null;
      return [route.id, { data, error: data ? "" : result.ok ? "The signal list could not be read." : result.error }] as const;
    }));
    if (!alive.current || generation !== request.current) return;
    const nextSubs = Object.fromEntries(pairs);
    currentRoutes.current = nextRoutes; currentSubs.current = nextSubs;
    setSetting(nextSetting); setRoutes(nextRoutes); setDeliveries(nextDeliveries); setSubs(nextSubs);
    setReadErrors({ setting: nextSetting ? "" : s.ok ? "The delivery setting could not be read." : s.error, routes: nextRoutes ? "" : r.ok ? "The routing policies could not be read." : r.error, deliveries: nextDeliveries ? "" : d.ok ? "The delivery activity could not be read." : d.error });
    ready.current = true; setLoading(false);
  }, [orgId]);
  useEffect(() => { void load(); }, [load]);
  const filteredRoutes = useMemo(() => (routes ?? []).filter(route => `${route.name} ${kinds[route.kind]} ${route.endpoint_host} ${route.severity_floor}`.toLowerCase().includes(query.trim().toLowerCase())), [routes, query]);
  const routeById = useMemo(() => new Map((routes ?? []).map(route => [route.id, route])), [routes]);
  const filteredDeliveries = useMemo(() => (deliveries ?? []).filter(delivery => `${labels[delivery.event_key] ?? delivery.event_key} ${routeById.get(delivery.destination_id)?.name ?? ""} ${delivery.state} ${delivery.severity} ${delivery.last_error ?? ""}`.toLowerCase().includes(query.trim().toLowerCase())), [deliveries, routeById, query]);
  const filtered = section === "routes" ? filteredRoutes : filteredDeliveries;
  const lastPage = Math.max(1, Math.ceil(filtered.length / pageSize)), currentPage = Math.min(page, lastPage);
  const shownRoutes = filteredRoutes.slice((currentPage - 1) * pageSize, currentPage * pageSize), shownDeliveries = filteredDeliveries.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const inspected = routes?.find(route => route.id === inspectedId);
  useEffect(() => { setPage(previous => Math.min(previous, lastPage)); }, [lastPage]);
  const blocked = busy || loading;
  function currentRoute(route: AlertDestination) { return currentRoutes.current?.find(current => current.id === route.id && !current.archived); }
  async function retrySignals(id: string) {
    if (locked.current || !ready.current || !currentRoutes.current?.some(route => route.id === id)) return;
    const generation = request.current, next = (subscriptionRequests.current[id] ?? 0) + 1;
    subscriptionRequests.current[id] = next;
    setSignalError(current => current?.routeId === id ? null : current);
    setSubs(all => ({ ...all, [id]: { data: null, error: "" } }));
    currentSubs.current = { ...currentSubs.current, [id]: { data: null, error: "" } };
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions", { params: { path: { orgId, destinationId: id } } }));
    if (!alive.current || generation !== request.current || next !== subscriptionRequests.current[id]) return;
    const data = result.ok && validSubscriptions(result.data) ? result.data : null;
    const nextRead = { data, error: data ? "" : result.ok ? "The signal list could not be read." : result.error };
    currentSubs.current = { ...currentSubs.current, [id]: nextRead }; setSubs(currentSubs.current);
  }
  async function toggleSignal(route: AlertDestination, key: AlertEventKey) {
    const current = currentRoute(route), read = currentSubs.current[route.id];
    if (!canEdit || !ready.current || locked.current || !current || !read?.data) return;
    const selected = read.data, on = selected.includes(key);
    locked.current = true; setBusy(true); setError(""); setNotice(""); setSignalError(null);
    try {
      const result = on ? await api.DELETE("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions/{eventKey}", { params: { path: { orgId, destinationId: current.id, eventKey: key } } }) : await api.POST("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions", { params: { path: { orgId, destinationId: current.id } }, body: { event_key: key } });
      if (!alive.current) return;
      if (result.error) { const message = apiErrorMessage(result.error, "Could not update subscribed signals."); setError(message); setSignalError({ routeId: route.id, message }); }
      else { currentSubs.current = { ...currentSubs.current, [current.id]: { data: on ? selected.filter(value => value !== key) : [...selected, key], error: "" } }; setSubs(currentSubs.current); }
    } catch {
      if (alive.current) { const message = "Could not confirm the signal update. Reload the signals before trying again."; setError(message); currentSubs.current = { ...currentSubs.current, [route.id]: { data: null, error: message } }; setSubs(currentSubs.current); }
    } finally { if (alive.current) { locked.current = false; setBusy(false); } }
  }
  async function test(route: AlertDestination) {
    const current = currentRoute(route);
    if (!canEdit || !ready.current || locked.current || !current) return;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/test", { params: { path: { orgId, destinationId: current.id } } });
      if (!alive.current) return;
      if (result.error) setError(apiErrorMessage(result.error, "Could not send the test."));
      else if (result.data?.delivered === true) setNotice(`Test delivered to ${current.name}.`);
      else if (result.data?.delivered === false) setError(`Test failed for ${current.name}: ${result.data.failure_code ?? "delivery failed"}.`);
      else setError("Could not confirm the test result. Refresh before trying again.");
    } catch { if (alive.current) setError("Could not confirm the test result. Refresh before trying again."); }
    finally { if (alive.current) { await load(); if (alive.current) { locked.current = false; setBusy(false); } } }
  }
  async function archive() {
    if (!archiveTarget || !canEdit || !ready.current || locked.current) return;
    const current = currentRoute(archiveTarget);
    if (!current || routeSignature(current) !== routeSignature(archiveTarget)) { setArchiveTarget(null); setError("The routing policy changed. Review it before archiving."); return; }
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const result = await api.DELETE("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}", { params: { path: { orgId, destinationId: current.id } } });
      if (!alive.current) return;
      if (result.error) setError(apiErrorMessage(result.error, "Could not archive the routing policy."));
      else { setNotice(`${current.name} archived.`); setInspectedId(null); }
      setArchiveTarget(null); await load();
    } catch { if (alive.current) { setArchiveTarget(null); setError("Could not confirm the archive result. Refresh before trying again."); await load(); } }
    finally { if (alive.current) { locked.current = false; setBusy(false); } }
  }
  const openRoute = (route: AlertDestination, stage: "overview" | "signals") => { if (!blocked) { setInspectedId(route.id); setRouteStage(stage); } };
  const actions = <><RefreshButton label="Refresh" disabled={blocked} onClick={() => { if (onRefreshAuthority) void onRefreshAuthority(); else void load(); }} /><Button disabled={!canEdit || blocked || routes === null} title={!canEdit ? "Verify your email to manage alert routing." : undefined} onClick={() => setCreating(true)}>New routing policy</Button></>;
  const routeActions = (route: AlertDestination) => [
    { key: "overview", label: "View policy", disabledReason: blocked ? "Wait for the current operation." : null, onSelect: () => openRoute(route, "overview") },
    { key: "signals", label: canEdit ? "Edit signals" : "View signals", disabledReason: blocked ? "Wait for the current operation." : null, onSelect: () => openRoute(route, "signals") },
    ...(canEdit ? [
      { key: "test", label: "Send test", disabledReason: blocked ? "Wait for the current operation." : null, onSelect: () => void test(route) },
      { key: "archive", label: "Archive", danger: true, disabledReason: blocked ? "Wait for the current operation." : null, onSelect: () => { if (!blocked && canEdit && currentRoute(route)) setArchiveTarget(route); } },
    ] : []),
  ];
  return <div className="alert-management-workspace" data-testid="alert-management">
    {renderNavigation ? renderNavigation(actions) : <div className="alerts-nav"><h2 className="sr-only">Alert management</h2><div className="alerts-nav-actions">{actions}</div></div>}
    {error && <ErrorText>{error}</ErrorText>}{notice && <p className="alerts-notice" role="status">{notice}</p>}
    {loading ? <Loading label="Loading alert management..." /> : <>
      {setting ? <div className="alert-delivery-setting"><div><span>Automatic delivery</span><strong>{setting.enabled ? "Enabled" : "Paused"}</strong>{!setting.enabled && <small>Conditions remain recorded.</small>}</div><Link className="text-brand text-sm" to="/settings?section=features&feature=alert-delivery">Manage feature</Link></div> : <AlertReadState title="Delivery setting unavailable" message={readErrors.setting} onRetry={() => void load()} />}
      {!canEdit && <p className="alerts-permission-note">Verify your email to change routing policies.</p>}
      <nav className="alert-management-sections" aria-label="Alert management sections"><button type="button" aria-current={section === "routes" ? "page" : undefined} onClick={() => { setSection("routes"); setQuery(""); setPage(1); }}>Routing policies{routes && <span>{routes.length}</span>}</button><button type="button" aria-current={section === "deliveries" ? "page" : undefined} onClick={() => { setSection("deliveries"); setQuery(""); setPage(1); }}>Delivery activity{deliveries && <span>{deliveries.length}</span>}</button></nav>
      {section === "routes" ? routes === null ? <AlertReadState title="Routing policies unavailable" message={readErrors.routes} onRetry={() => void load()} /> : <section className="alert-routing-inventory" aria-label="Routing policy inventory"><div className="alerts-inventory-toolbar"><Input type="search" aria-label="Search routing policies" placeholder="Search routing policies…" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} /><span className="alerts-result-count">{filteredRoutes.length} policies</span></div>{shownRoutes.length ? <div className="alerts-table-scroll"><table className="alerts-native-table alerts-routing-table"><caption className="sr-only">Routing policies</caption><thead><tr><th>Policy</th><th>Channel</th><th>Signals</th><th>Delivery rules</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{shownRoutes.map(route => {
        const selected = subs[route.id]?.data;
        return <tr key={route.id}><td><button type="button" className="alert-open" disabled={blocked} onClick={() => openRoute(route, "overview")}>{route.name}</button><span className="alert-secondary">{route.endpoint_host}</span></td><td>{kinds[route.kind]}</td><td><span className={selected == null ? "alert-unavailable" : ""}>{selected == null ? "Signals unavailable" : `${selected.length} signal${selected.length === 1 ? "" : "s"}`}</span></td><td><span className="alert-policy-severity">{route.severity_floor === "critical" ? "Critical only" : `${route.severity_floor}+`}</span><span className="alert-secondary">{route.cooldown_seconds % 60 === 0 ? `${route.cooldown_seconds / 60} min` : `${route.cooldown_seconds} sec`} cooldown</span></td><td className="alert-menu-column"><AppAccessRowMenu label={`Routing policy actions for ${route.name}`} actions={routeActions(route)} /></td></tr>;
      })}</tbody></table></div> : <AppAccessEmptyState icon={null} title={query.trim() ? "No routing policies match this search." : "No routing policies yet."} description={query.trim() ? "Try another policy name or channel." : "Create a policy to choose where alerts are delivered."} action={query.trim() ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />}
      <AppAccessPagination page={currentPage} pageSize={pageSize} count={shownRoutes.length} hasNext={currentPage < lastPage} maxOffset={null} busy={blocked} previousLabel="Previous routing policies page" nextLabel="Next routing policies page" onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} /></section> : deliveries === null ? <AlertReadState title="Delivery activity unavailable" message={readErrors.deliveries} onRetry={() => void load()} /> : <section className="alert-delivery-inventory" aria-label="Delivery activity"><div className="alerts-inventory-toolbar"><Input type="search" aria-label="Search delivery activity" placeholder="Search deliveries…" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} /><span className="alerts-result-count">{filteredDeliveries.length} recent attempts</span></div>{shownDeliveries.length ? <div className="alerts-table-scroll"><table className="alerts-native-table alerts-delivery-table"><caption className="sr-only">Delivery activity</caption><thead><tr><th>Signal</th><th>Policy</th><th>Outcome</th><th>Attempts</th><th>Recorded</th></tr></thead><tbody>{shownDeliveries.map(delivery => <tr key={delivery.id}><td><span>{labels[delivery.event_key] ?? delivery.event_key}</span><span className="alert-secondary">{delivery.severity}</span></td><td>{routeById.get(delivery.destination_id)?.name ?? "Policy not in current inventory"}</td><td><span className="alert-delivery-state" data-state={delivery.state}>{delivery.state}</span>{delivery.last_error && <span className="alert-secondary">{delivery.last_error}</span>}</td><td className="alert-number">{delivery.attempts}{delivery.suppressed_count > 0 && <span className="alert-secondary">{delivery.suppressed_count} suppressed</span>}</td><td><span className="alert-observed">{dateLabel(delivery.sent_at ?? delivery.failed_at ?? delivery.created_at)}</span></td></tr>)}</tbody></table></div> : <AppAccessEmptyState icon={null} title={query.trim() ? "No deliveries match this search." : "No delivery attempts yet."} description={query.trim() ? "Try another signal, policy or outcome." : undefined} action={query.trim() ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />}
      <AppAccessPagination page={currentPage} pageSize={pageSize} count={shownDeliveries.length} hasNext={currentPage < lastPage} maxOffset={null} busy={blocked} previousLabel="Previous deliveries page" nextLabel="Next deliveries page" onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} />{deliveries.length >= 100 && <p className="alerts-bounded-note">Showing the latest 100 delivery attempts.</p>}</section>}
    </>}
    {inspected && <Modal title={inspected.name} placement="right" size="enrollment" onDismiss={() => { if (!busy) setInspectedId(null); }} actions={<Button variant="ghost" disabled={busy} onClick={() => setInspectedId(null)}>Close</Button>}><div className="alert-route-detail">
      <nav aria-label="Routing policy sections" className="alert-editor-tabs"><button type="button" aria-current={routeStage === "overview" ? "step" : undefined} disabled={busy} onClick={() => setRouteStage("overview")}>Overview</button><button type="button" aria-current={routeStage === "signals" ? "step" : undefined} disabled={busy} onClick={() => setRouteStage("signals")}>Signals</button></nav>
      <ResourceSummary title={routeStage === "overview" ? "Routing settings" : "Signals"} description={`${kinds[inspected.kind]} · ${inspected.endpoint_host}`} className={`alert-route-summary${routeStage === "signals" ? " alert-signal-summary" : ""}`} footer={<Button variant="ghost" disabled={busy} onClick={() => setRouteStage(routeStage === "overview" ? "signals" : "overview")}>{routeStage === "overview" ? canEdit ? "Edit signals" : "View signals" : "Back to overview"}</Button>}>
        <div className="alert-detail-content">
          {routeStage === "overview" ? <>
            <dl className="alert-detail-facts tnx-resource-facts">{[["Channel", kinds[inspected.kind]], ["Destination host", inspected.endpoint_host], ["Minimum severity", inspected.severity_floor], ["Cooldown", `${inspected.cooldown_seconds} seconds`], ["Private network", inspected.allow_private ? "Allowed by an owner" : "Not allowed"]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
            <details className="alert-disclosure"><summary>Destination identity</summary><dl className="alert-detail-facts tnx-resource-facts"><div><dt>Fingerprint</dt><dd>{inspected.endpoint_fingerprint}</dd></div><div><dt>Created</dt><dd>{dateLabel(inspected.created_at)}</dd></div></dl><p>The endpoint credential is write-only and cannot be retrieved.</p></details>
          </> : subs[inspected.id]?.data == null ? subs[inspected.id]?.error ? <AlertReadState title="Signals unavailable" message={subs[inspected.id].error} onRetry={() => void retrySignals(inspected.id)} retryLabel="Retry signals" /> : <Loading label="Loading subscribed signals…" /> : <>
            <SignalPicker selected={subs[inspected.id].data!} disabled={!canEdit || busy} onToggle={key => void toggleSignal(inspected, key)} />
            {signalError?.routeId === inspected.id && <ErrorText>{signalError.message}</ErrorText>}
            {!canEdit && <p className="alerts-permission-note">Verify your email to change subscribed signals.</p>}
            <p className="alert-editor-note">Changes apply to future alerts. Queued deliveries keep their original routing.</p>
          </>}
        </div>
      </ResourceSummary>
    </div></Modal>}
    {creating && canEdit && !loading && routes && <CreateRoute orgId={orgId} canAllowPrivate={canAllowPrivate} onDismiss={() => setCreating(false)} onCreated={async message => { if (!alive.current) return; setCreating(false); await load(); if (alive.current) { if (message) setError(message); else setNotice("Routing policy created."); } }} />}
    {archiveTarget && <Modal title="Archive routing policy?" danger placement="right" size="enrollment" onDismiss={() => { if (!busy) setArchiveTarget(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setArchiveTarget(null)}>Cancel</Button><Button variant="danger" disabled={busy || loading || !canEdit} onClick={() => void archive()}>{busy ? "Archiving…" : "Archive"}</Button></>}><div className="alert-archive-confirm"><strong>{archiveTarget.name}</strong><p>This policy will stop receiving new alerts. Delivery history remains available.</p></div></Modal>}
  </div>;
}

function AlertReadState({ title, message, onRetry, retryLabel = "Retry" }: { title: string; message: string; onRetry: () => void; retryLabel?: string }) {
  return <section className="alerts-read-state" role="alert"><h3>{title}</h3>{message && message !== title && <p>{message}</p>}<Button variant="ghost" onClick={onRetry}>{retryLabel}</Button></section>;
}

function SignalPicker({ selected, disabled, onToggle }: { selected: AlertEventKey[]; disabled: boolean; onToggle: (key: AlertEventKey) => void }) {
  const [groupIndex, setGroupIndex] = useState(0), current = groups[groupIndex];
  return <div className="alert-signal-picker"><nav aria-label="Signal groups" className="alert-signal-groups">{groups.map((group, index) => <button type="button" key={group.label} aria-pressed={index === groupIndex} onClick={() => setGroupIndex(index)}>{group.label}<span aria-hidden="true">{group.keys.filter(key => selected.includes(key)).length}</span></button>)}</nav><fieldset className="alert-signal-options" disabled={disabled}><legend className="sr-only">{current.label} signals</legend>{current.keys.map(key => <label key={key}><input type="checkbox" checked={selected.includes(key)} onChange={() => onToggle(key)} /><span>{labels[key]}</span></label>)}</fieldset><p className="alert-signal-count">{selected.length} signal{selected.length === 1 ? "" : "s"} selected</p>{selected.length > 0 && <details className="alert-disclosure"><summary>Selected signals</summary><ul>{selected.map(key => <li key={key}>{labels[key] ?? key}</li>)}</ul></details>}</div>;
}

function CreateRoute({ orgId, canAllowPrivate, onDismiss, onCreated }: { orgId: string; canAllowPrivate: boolean; onDismiss: () => void; onCreated: (partialWarning?: string) => Promise<void> }) {
  const [stage, setStage] = useState<"destination" | "signals">("destination");
  const [kind, setKind] = useState<AlertDestinationKind>("webhook"), [name, setName] = useState(""), [endpoint, setEndpoint] = useState("");
  const [severity, setSeverity] = useState<"info" | "warning" | "critical">("warning"), [cooldown, setCooldown] = useState("900"), [allowPrivate, setAllowPrivate] = useState(false), [events, setEvents] = useState<AlertEventKey[]>([]);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [uncertain, setUncertain] = useState(false);
  const alive = useRef(true), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const meta = endpointMeta(kind), seconds = Number(cooldown);
  const validDestination = !!name.trim() && !!endpoint.trim() && Number.isInteger(seconds) && seconds >= 60 && seconds <= 86400;
  const goToSignals = () => { if (!validDestination) setError("Add a name, destination, and cooldown from 60 seconds to 24 hours."); else { setError(""); setStage("signals"); } };
  async function create() {
    if (locked.current || uncertain || stage !== "signals") return;
    if (!validDestination || !events.length) { setError("Choose a destination and at least one signal before creating the policy."); return; }
    locked.current = true; setBusy(true); setError("");
    let createdId: string | null = null;
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/alert-destinations", { params: { path: { orgId } }, body: { kind, name: name.trim(), endpoint: endpoint.trim(), allow_private: canAllowPrivate && supportsPrivate(kind) && allowPrivate, severity_floor: severity, cooldown_seconds: seconds } });
      if (!alive.current) return;
      if (result.error) { setError(apiErrorMessage(result.error, "Could not create the routing policy.")); return; }
      if (!result.data || typeof result.data.id !== "string" || !result.data.id) { setEndpoint(""); setUncertain(true); setError("Could not confirm policy creation. Refresh routing policies before trying again."); return; }
      createdId = result.data.id; setEndpoint("");
      let subscribed = 0;
      for (const key of events) {
        if (!alive.current) return;
        try {
          const sub = await api.POST("/api/v1/organizations/{orgId}/alert-destinations/{destinationId}/subscriptions", { params: { path: { orgId, destinationId: createdId } }, body: { event_key: key } });
          if (!alive.current) return;
          if (sub.error) { await onCreated(`The route was created, but not every signal could be subscribed (${subscribed} of ${events.length} confirmed). Open its signals to review the result.`); return; }
          subscribed++;
        } catch { if (alive.current) await onCreated(`The route was created, but not every signal could be confirmed (${subscribed} of ${events.length} confirmed). Open its signals to review the result.`); return; }
      }
      if (alive.current) await onCreated();
    } catch {
      if (alive.current) {
        setEndpoint("");
        if (createdId) await onCreated("The route was created, but its signals could not be confirmed. Open the routing policy to review the result.");
        else { setUncertain(true); setError("Could not confirm policy creation. Refresh routing policies before trying again."); }
      }
    } finally { if (alive.current) { locked.current = false; setBusy(false); } }
  }
  return <Modal title="New routing policy" placement="right" size="enrollment" onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button variant="ghost" disabled={busy} onClick={stage === "signals" && !uncertain ? () => setStage("destination") : onDismiss}>{stage === "signals" && !uncertain ? "Back" : "Cancel"}</Button>{uncertain ? <Button variant="ghost" onClick={() => void onCreated("Creation was not confirmed. Review the refreshed routing policies before trying again.")}>Review routing policies</Button> : stage === "destination" ? <Button disabled={busy} onClick={goToSignals}>Continue</Button> : <Button disabled={busy || !events.length} onClick={() => void create()}>{busy ? "Creating..." : "Create policy"}</Button>}</>}><div className="alert-route-builder"><nav aria-label="Routing policy setup" className="alert-editor-tabs"><button type="button" aria-current={stage === "destination" ? "step" : undefined} disabled={busy || uncertain} onClick={() => setStage("destination")}>Destination</button><button type="button" aria-current={stage === "signals" ? "step" : undefined} disabled={busy || uncertain} onClick={goToSignals}>Signals</button></nav>{!uncertain && (stage === "destination" ? <fieldset className="alert-destination-fields" disabled={busy}><Field label="Policy name"><Input value={name} onChange={event => setName(event.target.value)} maxLength={100} placeholder="Platform on-call" autoFocus /></Field><Field label="Channel"><Select value={kind} onChange={event => { setKind(event.target.value as AlertDestinationKind); setEndpoint(""); setAllowPrivate(false); }}>{(Object.keys(kinds) as AlertDestinationKind[]).map(value => <option key={value} value={value}>{kinds[value]}</option>)}</Select></Field><Field label={meta[0]}><Input type={meta[2]} autoComplete="off" value={endpoint} onChange={event => setEndpoint(event.target.value)} placeholder={meta[1]} /></Field><p className="alert-editor-note">The destination credential is stored securely and cannot be retrieved.</p><div className="alert-destination-pair"><Field label="Minimum severity"><Select value={severity} onChange={event => setSeverity(event.target.value as typeof severity)}><option value="info">Info+</option><option value="warning">Warning+</option><option value="critical">Critical only</option></Select></Field><Field label="Cooldown (seconds)"><Input type="number" min="60" max="86400" value={cooldown} onChange={event => setCooldown(event.target.value)} /></Field></div>{canAllowPrivate && supportsPrivate(kind) && <label className="alert-private-choice"><input type="checkbox" checked={allowPrivate} onChange={event => setAllowPrivate(event.target.checked)} /><span>Allow private-network destination<small>Owner exception: permits HTTP and private IP destinations.</small></span></label>}</fieldset> : <><p className="alert-route-context">{name.trim()} · {kinds[kind]} · {severity}+ · {seconds} sec cooldown</p><SignalPicker selected={events} disabled={busy} onToggle={key => setEvents(current => current.includes(key) ? current.filter(value => value !== key) : [...current, key])} /></>)}{error && <ErrorText>{error}</ErrorText>}</div></Modal>;
}
