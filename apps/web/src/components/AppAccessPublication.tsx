import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { Badge, Button, ErrorText, Loading, Modal, Field, Select } from "./ui";
import { Icon } from "./Icon";

type Application = components["schemas"]["AppAccessApplication"];
type Check = components["schemas"]["AppAccessCheck"];
type Publication = components["schemas"]["AppAccessPublicationState"];
type Operation = components["schemas"]["AppAccessPublicationOperation"];
type Input = components["schemas"]["AppAccessPublicationInput"];
type Impact = components["schemas"]["AppAccessPublicationImpact"];
type Confirmation = { kind: "publish"; input: Input } | { kind: "cancel"; id: string; version: number } | { kind: "disable"; applicationVersion: number; authorityVersion: number } | { kind: "archive"; applicationVersion: number } | { kind: "rollback"; applicationVersion: number; revision: number };
// These service refusals roll back the staging transaction. An uncertain earlier attempt
// must still be reconciled, even if a later retry receives a preflight refusal.
const preflightRefusals = new Set(["invalid_publication", "version_conflict", "stale_version", "application_archived", "app_domain_unavailable", "gateway_unavailable", "browser_capability_unavailable", "origin_check_required", "publication_pending", "browser_capacity_exceeded"]);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const matchesReview = (operation: Operation, input: Input, appId: string) => operation.app_id === appId && operation.reviewed_application_version === input.expected_version && operation.revision === input.revision && operation.digest === input.digest && operation.origin_check_id === input.check_id;
const pending = (operation: Operation | undefined) => operation?.status === "queued" || operation?.status === "checking";
const capabilityText: Record<Publication["browser_capability"], string> = {
  unknown: "The gateway has not reported browser connector capability.",
  unsupported: "Upgrade the gateway to a compatible browser connector.",
  unavailable: "The gateway browser capability report is no longer current.",
  supported: "The gateway supports browser application connections.",
};
const operationText: Record<Operation["status"], string> = {
  queued: "Publication requested. Waiting for readiness checks.", checking: "Checking the public browser URL and gateway connection.",
  activated: "Publication confirmed.", failed: "Publication failed.",
  cancelled: "Publication cancelled.", expired: "Publication expired.",
};
const diagnostics: Record<string, string> = {
  public_dns_failed: "The public application hostname could not be resolved safely.", public_tls_failed: "The public application certificate could not be verified.",
  public_challenge_failed: "The public URL did not reach the expected application proxy.", connector_failed: "The pending gateway connection could not complete its check.",
  dns_failed: "The gateway could not resolve the origin.", target_refused: "The origin destination is outside the saved policy.",
  connect_failed: "The gateway could not connect to the origin.", tls_failed: "The origin certificate could not be verified.", http_failed: "The origin did not complete the connection check.",
  deadline_exceeded: "Readiness checks did not finish in time.", assignment_changed: "The reviewed application changed. Reopen it and check the saved connection.",
  capability_unavailable: "The browser connector capability is no longer current.", origin_check_stale: "Run a fresh saved connection check.",
  publication_changed: "The active publication changed. Refresh before continuing.", proxy_unavailable: "The application proxy is unavailable.",
};
function recoverInput(key: string): Input | null {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(key) ?? "null") as Partial<Input> | null;
    if (value && typeof value.idempotency_key === "string" && uuidPattern.test(value.idempotency_key) && typeof value.check_id === "string" && uuidPattern.test(value.check_id) && typeof value.digest === "string" && /^[a-f0-9]{64}$/.test(value.digest) && Number.isSafeInteger(value.expected_version) && Number.isSafeInteger(value.revision) && value.expected_version! > 0 && value.revision! > 0) return value as Input;
  } catch { /* optional browser storage */ }
  return null;
}
export default function AppAccessPublication({ orgId, userId, application, check, dirty, canManage, canPublish, publishUnavailableReason, onChanged, onArchived, onRollback }: {
  orgId: string; userId: string; application: Application; check: Check | null; dirty: boolean; canManage: boolean; canPublish: boolean;
  onChanged: () => void; onArchived: () => void; onRollback: () => void;
  publishUnavailableReason?: string;
}) {
  const appId = application.id;
  const storageKey = `tunnex.appPublication:${userId}:${orgId}:${appId}`;
  const [view, setView] = useState<Publication | null>(null);
  const [operation, setOperation] = useState<Operation>();
  const [intent, setIntent] = useState<Input | null>(() => recoverInput(storageKey));
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [rollbackRevision, setRollbackRevision] = useState("");
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [impact, setImpact] = useState<Impact | null>(null);
  const [impactError, setImpactError] = useState("");
  const [impactBusy, setImpactBusy] = useState(false);
  const impactGeneration = useRef(0);
  const alive = useRef(true);
  const requestGeneration = useRef(0);
  const intentRef = useRef(intent); intentRef.current = intent;
  const ownOperation = useRef<string>();
  const [reading, setReading] = useState(true);
  const [checkTime, setCheckTime] = useState(Date.now);
  useEffect(() => {
    const now = Date.now(); setCheckTime(now);
    const expiry = check?.completed_at ? Date.parse(check.completed_at) + 5 * 60_000 : NaN;
    if (!Number.isFinite(expiry) || expiry <= now) return;
    const timer = window.setTimeout(() => setCheckTime(Date.now()), expiry - now + 1);
    return () => window.clearTimeout(timer);
  }, [check?.id, check?.completed_at]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const forgetIntent = (key?: string) => { if (key && intentRef.current?.idempotency_key !== key) return; intentRef.current = null; ownOperation.current = undefined; setIntent(null); try { window.sessionStorage.removeItem(storageKey); } catch { /* optional */ } };
  const rememberIntent = (input: Input) => { intentRef.current = input; setIntent(input); try { window.sessionStorage.setItem(storageKey, JSON.stringify(input)); } catch { /* retained in memory */ } };
  useEffect(() => {
    let cancelled = false; const generation = requestGeneration.current; setReading(true);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication", { params: { path: { orgId, appId } } })).then(result => {
      if (cancelled || generation !== requestGeneration.current) return;
      setReading(false);
      if (!result.ok || !result.data.browser_capability) { setError(result.ok ? "Could not read current publication. Refresh before continuing." : result.error); return; }
      setView(result.data); setError("");
      if (!intent) setOperation(result.data.pending_operation ?? result.data.last_operation);
    });
    return () => { cancelled = true; };
  }, [orgId, appId, refresh, intent]);
  useEffect(() => {
    if (!intent || busy) return;
    let cancelled = false; const generation = requestGeneration.current; const key = intent.idempotency_key;
    void api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication-operations/by-key/{idempotencyKey}", { params: { path: { orgId, appId, idempotencyKey: intent.idempotency_key } } }).then(result => {
      if (cancelled || generation !== requestGeneration.current || intentRef.current?.idempotency_key !== key) return;
      if (result.error || !result.data) { setActionError("This publication request is not confirmed. Read its status again or retry the same request."); return; }
      if (!matchesReview(result.data, intent, appId)) { setActionError("This request key belongs to a different review. Refresh publication status before continuing."); return; }
      ownOperation.current = result.data.id; setOperation(result.data); setActionError("");
      if (!pending(result.data)) forgetIntent(key);
    }).catch(() => { if (!cancelled && generation === requestGeneration.current && intentRef.current?.idempotency_key === key) setActionError("Could not confirm the publication request. Retry its status before starting another publication."); });
    return () => { cancelled = true; };
  }, [orgId, appId, intent, refresh, busy]);
  useEffect(() => {
    if (error || (!pending(operation) && !(view?.active?.state === "disabled" && !view.active.withdrawal_confirmed))) return;
    let cancelled = false; const generation = requestGeneration.current; const intentKey = intentRef.current?.idempotency_key;
    const timer = window.setTimeout(() => {
      if (!pending(operation)) { setRefresh(value => value + 1); return; }
      void loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication-operations/{operationId}", { params: { path: { orgId, appId, operationId: operation!.id } } })).then(result => {
        if (cancelled || !alive.current || generation !== requestGeneration.current) return;
        if (!result.ok) { setActionError(result.error); return; }
        const wasPending = pending(operation);
        setOperation(result.data); setActionError("");
        if (!pending(result.data)) { if (ownOperation.current === result.data.id && intentKey) forgetIntent(intentKey); setRefresh(value => value + 1); if (wasPending && result.data.status === "activated") onChanged(); }
      });
    }, 1000);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [orgId, appId, operation, view, error, onChanged]);
  const checkMatches = check?.status === "succeeded" && check.app_id === appId && check.revision === application.draft.revision && check.digest === application.draft.digest;
  const checkFresh = !!check?.completed_at && Number.isFinite(Date.parse(check.completed_at)) && Date.parse(check.completed_at) + 5 * 60_000 > checkTime;
  const canRequest = canManage && canPublish && !dirty && !error && !reading && view?.application_version === application.version && !!view && view.browser_capability === "supported" && checkMatches && checkFresh && !pending(view.pending_operation) && !intent;

  async function submit(input: Input) {
    const wasRetained = intentRef.current?.idempotency_key === input.idempotency_key;
    requestGeneration.current++; setBusy(true); setActionError(""); rememberIntent(input);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication-operations", { params: { path: { orgId, appId } }, body: input });
      if (!alive.current) return;
      if (result.error || !result.data) {
        if (!wasRetained && result.response?.status >= 400 && result.response?.status < 500 && preflightRefusals.has(apiErrorCode(result.error) ?? "")) {
          forgetIntent(input.idempotency_key); setRefresh(value => value + 1);
          setActionError(apiErrorMessage(result.error, "Publication was refused. Refresh and check the saved connection before trying again."));
        } else setActionError(apiErrorMessage(result.error, "Publication outcome is unknown. Read its status before starting another request."));
        return;
      }
      if (!matchesReview(result.data, input, appId)) { setActionError("The returned publication does not match this review. Read request status before continuing."); return; }
      ownOperation.current = result.data.id; setOperation(result.data); setActionError(""); setRefresh(value => value + 1);
      if (!pending(result.data)) forgetIntent(input.idempotency_key);
      onChanged();
    } catch { if (alive.current) setActionError("Could not confirm publication. Read its status or retry the same request."); }
    finally { if (alive.current) setBusy(false); }
  }
  async function apply(action: Confirmation) {
    setConfirmation(null);
    if (action.kind === "publish") { await submit(action.input); return; }
    requestGeneration.current++; setBusy(true); setActionError("");
    try {
      if (action.kind === "cancel") {
        const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication-operations/{operationId}/cancel", { params: { path: { orgId, appId, operationId: action.id } }, body: { expected_operation_version: action.version } });
        if (!alive.current) return;
        if (result.error || !result.data) { setError("Refresh publication status before continuing."); setActionError(apiErrorMessage(result.error, "Could not confirm cancellation. Refresh publication status.")); return; }
        setOperation(result.data); if (!pending(result.data) && ownOperation.current === result.data.id) forgetIntent(intentRef.current?.idempotency_key); onChanged();
      } else if (action.kind === "disable") {
        const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication/disable", { params: { path: { orgId, appId } }, body: { expected_application_version: action.applicationVersion, expected_authority_version: action.authorityVersion } });
        if (!alive.current) return;
        if (result.error || !result.data) { setError("Refresh publication status before continuing."); setActionError(apiErrorMessage(result.error, "Could not confirm disable. Refresh publication status.")); return; }
        setView(result.data); forgetIntent(); onChanged();
      } else if (action.kind === "rollback") {
        const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/rollback-draft", { params: { path: { orgId, appId } }, body: { expected_version: action.applicationVersion, revision: action.revision } });
        if (!alive.current) return;
        if (result.error || !result.data) { setError("Refresh publication status before continuing."); setActionError(apiErrorMessage(result.error, "Could not confirm the rollback draft. Refresh before retrying.")); return; }
        onRollback();
      } else {
        const result = await api.DELETE("/api/v1/organizations/{orgId}/app-access/applications/{appId}", { params: { path: { orgId, appId }, query: { expected_version: action.applicationVersion } } });
        if (!alive.current) return;
        if (result.error) { setError("Refresh publication status before continuing."); setActionError(apiErrorMessage(result.error, "Could not confirm archive. Refresh publication status.")); return; }
        forgetIntent(); onArchived();
      }
      setRefresh(value => value + 1);
    } catch { if (alive.current) { setError("Refresh publication status before continuing."); setActionError("The operation could not be confirmed. Refresh publication status before retrying."); } }
    finally { if (alive.current) setBusy(false); }
  }
  const active = view?.active;
  const pendingOperation = view?.pending_operation;
  const impactCurrent = !!impact && impact.application_version === view?.application_version && impact.authority_version === (active?.authority_version ?? 0);
  async function inspectImpact() {
    const generation = ++impactGeneration.current;
    setImpactBusy(true); setImpactError(""); setImpact(null);
    try {
      const result = await api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/publication/impact", { params: { path: { orgId, appId } } });
      if (!alive.current || generation !== impactGeneration.current) return;
      if (result.error || !result.data) { setImpactError(apiErrorMessage(result.error, "Could not evaluate current application impact.")); return; }
      setImpact(result.data);
    } catch { if (alive.current && generation === impactGeneration.current) setImpactError("Could not reach the application impact preview."); }
    finally { if (alive.current && generation === impactGeneration.current) setImpactBusy(false); }
  }
  const connectionLink = `/app-access/applications/${appId}?step=connection`;
  const accessLink = `/app-access/applications/${appId}?step=access`;
  const savedCurrent = !dirty && view?.application_version === application.version;
  const originReady = checkMatches && checkFresh;
  const connectorLabel = { supported: "Available", unknown: "No report", unsupported: "Upgrade required", unavailable: "Report expired" };
  const withdrawalPending = active?.state === "disabled" && !active.withdrawal_confirmed;
  return <section className="aa-publication" aria-label="Publication review">
    <div className="aa-publication-live">
      <div className="aa-publication-live-heading"><h3>{error ? "Last observed publication" : "Current publication"}</h3>
        {view && <Badge tone={error ? "unknown" : "neutral"}>{error ? "Last observed" : active?.state === "active" ? "Published" : active ? "Disabled" : "Unpublished"}</Badge>}
      </div>
      <Button variant="ghost" aria-label="Refresh publication status" title="Refresh publication status" className="aa-publication-refresh" disabled={busy} onClick={() => { setReading(true); setActionError(""); setRefresh(value => value + 1); }}><Icon name="refresh-cw" size={16} /></Button>
      {view && <div className="aa-publication-live-state">
        {active ? <><p role="status">{active.state === "active" ? `Active revision ${active.revision}` : active.withdrawal_confirmed ? "Disabled. Routing and stream withdrawal confirmed." : "Disabled. Waiting for stream withdrawal confirmation."}</p>
          <span className="aa-publication-live-address">{active.hostname}</span>
          {active.state === "active" && !error && <a href={`https://${active.hostname}/__tunnex_app/start`} referrerPolicy="no-referrer">Open published application <Icon name="chevron-right" size={14} /></a>}
        </> : <p role="status">No active publication. This app is not available in the browser yet.</p>}
      </div>}
    </div>
    <div className="aa-publication-draft">
      <div className="aa-publication-block-heading"><h3>Draft to publish</h3><span>Revision {application.draft.revision}</span></div>
      <dl className="aa-publication-summary">
        <div><dt>Browser address</dt><dd>{application.draft.public_hostname}</dd></div>
        <div><dt>Private origin</dt><dd>{application.draft.origin_url}</dd></div>
      </dl>
      <div className="aa-publication-draft-links"><Link to={connectionLink}>Edit connection</Link><Link to={accessLink}>Review access grants</Link></div>

    </div>
    {error && <ErrorText>{error}</ErrorText>}
    {!view && !error ? <Loading /> : view && <>
      <div className="aa-publication-readiness">
        <div className="aa-publication-block-heading"><h3>Before publishing</h3><span className={canRequest ? "aa-publication-ready" : ""}>{reading ? "Refreshing…" : intent ? "Request unresolved" : pending(pendingOperation) ? "Publishing…" : canRequest ? "Ready" : canManage ? "Needs attention" : "View only"}</span></div>
        <ul aria-label="Publish requirements">
          {!canPublish && canManage && <li><span>App Access setup</span><span className="aa-publication-blocker">{publishUnavailableReason || "Complete App Access setup"}</span></li>}
          <li><span>Saved changes</span><span className={savedCurrent ? "" : "aa-publication-blocker"}>{dirty ? "Save required" : savedCurrent ? "Up to date" : "Reload required"}</span>{dirty ? <Link to={connectionLink}>Save changes</Link> : !savedCurrent && <Button variant="ghost" disabled={busy} onClick={onChanged}>Reload saved application</Button>}</li>
          <li><span>Gateway connector</span><span className={view.browser_capability === "supported" ? "" : "aa-publication-blocker"} title={capabilityText[view.browser_capability]}>{connectorLabel[view.browser_capability]}</span>{view.browser_capability !== "supported" && <Link to={connectionLink}>Connection</Link>}</li>
          <li><span>Origin check</span><span className={originReady ? "" : "aa-publication-blocker"}>{originReady ? "Passed" : checkMatches ? "Expired" : "Required"}</span>{!originReady && <Link to={connectionLink}>Check the saved connection</Link>}</li>
        </ul>
      </div>
      {operation && <div className="aa-publication-request">
        <div className="aa-publication-block-heading"><h3>Latest publication request</h3><Badge tone={operation.status === "failed" || operation.status === "expired" ? "danger" : pending(operation) ? "warn" : "neutral"}>{operation.status}</Badge></div>
        <p role="status">{operationText[operation.status]}</p>
        {["failed", "cancelled", "expired"].includes(operation.status) && active?.state === "active" && <p>The previous active revision stays available.</p>}
        {operation.error_code && <p className="aa-publication-blocker">{diagnostics[operation.error_code] ?? "Readiness could not be confirmed. Check the saved connection."}</p>}
        <details className="aa-editor-disclosure"><summary>Connection diagnostics</summary><div className="aa-editor-disclosure-content"><p>Reviewed revision {operation.revision}</p><ul className="app-access-data-list" aria-label="Publication readiness results">{[["Public DNS", operation.public_dns_status], ["Public TLS", operation.public_tls_status], ["Gateway DNS", operation.connector_dns_status], ["Gateway connection", operation.connector_connect_status], ["Origin TLS", operation.connector_tls_status]].map(([label, status]) => <li key={label} className="app-access-data-row"><span>{label}</span><Badge tone={status === "failed" ? "danger" : "neutral"}>{status}</Badge></li>)}</ul></div></details>
      </div>}
      <ErrorText>{actionError}</ErrorText>
      {intent && <div className="aa-publication-recovery"><p role="status">A previous publication request is retained until its outcome is confirmed.</p><div><Button variant="ghost" disabled={busy} onClick={() => setRefresh(value => value + 1)}>Read request outcome</Button>{!pending(operation) && canManage && <Button disabled={busy} onClick={() => void submit(intent)}>Retry the same publication request</Button>}</div></div>}
      {canManage && <div className="aa-publication-actions">
        <p>{canRequest ? "Browser access starts after the final checks pass." : pending(pendingOperation) ? "Readiness checks are in progress." : intent ? "Confirm the previous request before publishing again." : "Resolve the requirements above to publish."}</p>
        <Button disabled={!canRequest || busy} onClick={() => { if (!checkMatches || !check) return; setConfirmation({ kind: "publish", input: { expected_version: application.version, revision: application.draft.revision, digest: application.draft.digest, check_id: check.id, idempotency_key: crypto.randomUUID() } }); }}>Publish application<Icon name="chevron-right" size={16} /></Button>
        {pending(pendingOperation) && pendingOperation && <Button variant="ghost" disabled={busy || reading || !!error} onClick={() => setConfirmation({ kind: "cancel", id: pendingOperation.id, version: pendingOperation.version })}>Cancel pending publication</Button>}
        {withdrawalPending && <Button variant="ghost" disabled={busy || reading || !!error} onClick={() => setConfirmation({ kind: "disable", applicationVersion: view.application_version, authorityVersion: active?.authority_version ?? 0 })}>Retry withdrawal confirmation</Button>}
      </div>}
      <details className="aa-editor-disclosure aa-publication-limits"><summary>Session limits</summary><div className="aa-editor-disclosure-content"><p>Idle timeout: {application.draft.idle_timeout_seconds / 60} minutes · Maximum session: {application.draft.absolute_timeout_seconds / 3600} hours</p><p>Only users with current access grants can open this app.</p>{checkMatches && check?.completed_at && <p>Origin checked: {new Date(check.completed_at).toLocaleString()}</p>}</div></details>
      {canManage && <details className="aa-editor-disclosure"><summary>Current access impact</summary><div className="aa-editor-disclosure-content aa-publication-optional"><p>Current grant matches and unexpired sessions. This does not predict future access or confirm termination.</p><Button variant="ghost" disabled={busy || impactBusy || !!error} onClick={() => void inspectImpact()}>{impactBusy ? "Evaluating impact…" : "Evaluate current impact"}</Button><ErrorText>{impactError}</ErrorText>{impact && (impactCurrent ? <><p>{impact.matching_user_count_is_lower_bound ? "At least " : ""}{impact.matching_user_count} users match current access grants.</p><p>{impact.session_impact_available ? `${impact.live_app_session_count_is_lower_bound ? "At least " : ""}${impact.live_app_session_count} unexpired app session records.` : "Unexpired app session records are unavailable."}</p><p>Evaluated {new Date(impact.evaluated_at).toLocaleString()}. Access may change after this preview.</p></> : <p role="status">The application changed after the impact preview. Evaluate it again.</p>)}</div></details>}
      {canManage && view.rollback_revisions.length > 0 && <details className="aa-editor-disclosure"><summary>Publication history</summary><div className="aa-editor-disclosure-content aa-publication-optional"><Field label="Previously published revision"><Select value={rollbackRevision} onChange={event => setRollbackRevision(event.target.value)}><option value="">Choose a revision</option>{view.rollback_revisions.map(item => <option key={item.revision} value={item.revision}>Revision {item.revision} · {item.name}</option>)}</Select></Field><p>Restore a revision as a new draft. The current publication stays live until the new draft passes checks and is published.</p><Button variant="ghost" disabled={!canPublish || dirty || busy || reading || !!error || !!intent || pending(pendingOperation) || view.application_version !== application.version || !view.rollback_revisions.some(item => item.revision === Number(rollbackRevision))} onClick={() => setConfirmation({ kind: "rollback", applicationVersion: view.application_version, revision: Number(rollbackRevision) })}>Create rollback draft</Button></div></details>}
      {canManage && <details className="aa-editor-disclosure"><summary>Manage publication</summary><div className="aa-editor-disclosure-content aa-publication-optional"><p>Disable browser access or archive an application after routing withdrawal is confirmed.</p><div className="aa-publication-maintenance-actions">
        {(!active || active.state === "active" || (pending(pendingOperation) && !withdrawalPending)) && <Button variant="ghost" disabled={busy || reading || !!error} onClick={() => setConfirmation({ kind: "disable", applicationVersion: view.application_version, authorityVersion: active?.authority_version ?? 0 })}>Disable application</Button>}
        {active?.state === "disabled" && active.withdrawal_confirmed && !pending(pendingOperation) && <Button variant="ghost" disabled={busy || reading || !!error} onClick={() => setConfirmation({ kind: "archive", applicationVersion: view.application_version })}>Archive application</Button>}
      </div></div></details>}
    </>}
    <div className="aa-publication-activity-links"><Link to={`/access-events?source=applications&app_id=${encodeURIComponent(appId)}`}>Application access events</Link><Link to={`/audit?target_type=app_access&target_id=${encodeURIComponent(appId)}`}>Application configuration audits</Link></div>
    {confirmation && <Modal title={confirmation.kind === "publish" ? "Publish reviewed application" : confirmation.kind === "disable" ? "Disable application" : confirmation.kind === "archive" ? "Archive application" : confirmation.kind === "rollback" ? "Create rollback draft" : "Cancel pending publication"} danger={confirmation.kind !== "publish"} onDismiss={() => setConfirmation(null)} actions={<><Button variant="ghost" onClick={() => setConfirmation(null)}>Keep reviewing</Button><Button onClick={() => void apply(confirmation)}>Confirm {confirmation.kind === "publish" ? "publication" : confirmation.kind === "cancel" ? "cancellation" : confirmation.kind === "rollback" ? "rollback draft" : confirmation.kind}</Button></>}><p>{confirmation.kind === "publish" ? "The reviewed revision becomes active only after the public URL and gateway readiness checks pass. Your previous active revision stays available if the checks fail." : confirmation.kind === "disable" ? "New access will be denied immediately. Live connections may take a few seconds to close. Already delivered content cannot be removed." : confirmation.kind === "archive" ? "The withdrawn application leaves the inventory. Its history and hostname ownership are retained." : confirmation.kind === "rollback" ? `Revision ${confirmation.revision} becomes a new draft. Check the connection and review access before publishing it.` : "This pending revision will not activate. The previous active revision stays available."}</p></Modal>}
  </section>;
}
