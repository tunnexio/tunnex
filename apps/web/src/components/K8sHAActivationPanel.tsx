import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import "../kubernetes-operations.css";
import { api, apiErrorMessage, type K8sConnectorPoolHAStatus, type K8sHASettings, type Role } from "../lib/api";
import { can } from "../lib/rbac";
import { Badge, Button, ErrorText, Modal, SettingRow, SettingValue } from "./ui";
import { NetworkDetailList } from "./NetworkDetailList";

type HAActivationProps = { orgId: string; role: Role | readonly Role[] | undefined; emailVerified: boolean; central?: boolean };

export function K8sHAActivationPanel(props: HAActivationProps) {
  return <HAActivationForScope key={props.orgId + ":" + (props.role ?? "unknown") + ":" + props.emailVerified + ":" + props.central} {...props} />;
}

function HAActivationForScope({ orgId, role, emailVerified, central = false }: HAActivationProps) {
  const canView = can(role, "k8s_ha:view");
  const canManage = emailVerified && can(role, "k8s_ha:manage");
  const [settings, setSettings] = useState<K8sHASettings | null>(null);
  const [pools, setPools] = useState<K8sConnectorPoolHAStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const alive = useRef(true);
  const requestSequence = useRef(0);
  const mutationBusy = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; requestSequence.current++; }; }, []);

  const load = useCallback(async () => {
    if (!canView || !alive.current) return;
    const request = ++requestSequence.current;
    setError(null);
    setSettings(null);
    setPools(null);
    try {
      const [settingsResult, poolsResult] = await Promise.all([
        api.GET("/api/v1/organizations/{orgId}/k8s/ha-settings", { params: { path: { orgId } } }),
        api.GET("/api/v1/organizations/{orgId}/k8s/connector-pools/ha-status", { params: { path: { orgId } } }),
      ]);
      if (!alive.current || request !== requestSequence.current) return;
      if (settingsResult.error || poolsResult.error || settingsResult.data === undefined || poolsResult.data === undefined) {
        setError(apiErrorMessage(settingsResult.error ?? poolsResult.error, "HA status is unavailable. No readiness is inferred."));
        return;
      }
      const value = settingsResult.data;
      if (!value || typeof value.enabled !== "boolean" || !Number.isInteger(value.revision) || value.revision < 0 || typeof value.actual_state !== "string" || typeof value.reason_code !== "string" || !Array.isArray(poolsResult.data) || poolsResult.data.some(pool => !pool || typeof pool.pool_id !== "string" || typeof pool.actual_mode !== "string" || typeof pool.requested_mode !== "string")) {
        setError("The server returned incomplete HA status. No readiness is inferred."); return;
      }
      setSettings(value);
      setPools(poolsResult.data);
    } catch {
      if (!alive.current || request !== requestSequence.current) return;
      setError("Could not reach the API. HA status is unavailable.");
    }
  }, [canView, orgId]);

  useEffect(() => { void load(); }, [load]);
  if (!canView) return null;

  async function setOrganizationEnabled(enabled: boolean) {
    if (!alive.current || !central || !canManage || !settings || mutationBusy.current) return;
    mutationBusy.current = true;
    setBusy("settings");
    setError(null);
    try {
      const { error: mutationError } = await api.PUT("/api/v1/organizations/{orgId}/k8s/ha-settings", {
        params: { path: { orgId } }, body: { enabled, expected_revision: settings.revision },
      });
      if (!alive.current) return;
      if (mutationError) {
        const message = apiErrorMessage(mutationError, "Could not change the HA opt-in.");
        setConfirmDisable(false);
        await load();
        if (alive.current) setError(`${message} Review the current reported state before retrying.`);
        return;
      }
      setConfirmDisable(false);
      await load();
    } catch {
      if (alive.current) { setSettings(null); setPools(null); setConfirmDisable(false); setError("Could not confirm the HA opt-in. Refresh status before retrying."); }
    } finally {
      mutationBusy.current = false;
      if (alive.current) setBusy(null);
    }
  }

  async function requestPoolMode(pool: K8sConnectorPoolHAStatus, requested_mode: "legacy" | "fenced_ha") {
    if (!alive.current || central || !canManage || !settings || mutationBusy.current || (requested_mode === "fenced_ha" && !settings.enabled)) return;
    mutationBusy.current = true;
    setBusy(pool.pool_id);
    setError(null);
    try {
      const { error: mutationError } = await api.PUT("/api/v1/organizations/{orgId}/k8s/connector-pools/{poolId}/ha-mode", {
        params: { path: { orgId, poolId: pool.pool_id } },
        body: { requested_mode, expected_transition_revision: pool.transition_revision },
      });
      if (!alive.current) return;
      if (mutationError) return setError(apiErrorMessage(mutationError, "Could not request the pool ownership mode."));
      await load();
    } catch {
      if (alive.current) setError("Could not request the pool ownership mode. Refresh status before retrying.");
    } finally {
      mutationBusy.current = false;
      if (alive.current) setBusy(null);
    }
  }

  const stateLabel = (value: string) => value.replace(/_/g, " ");
  const actualTone = (value: string): "danger" | "warn" | "neutral" => value === "blocked" ? "danger" : value === "drain_pending" || value === "bootstrap_pending" ? "warn" : "neutral";
  const ready = settings !== null && pools !== null;

  return <>
    {!ready && <SettingRow label="Connector HA activation" error={error}>
      <div className="k8s-operation-actions"><SettingValue tone={error ? "warn" : "muted"}>{error ? "Unavailable" : "Loading…"}</SettingValue>{error && <Button size="sm" variant="ghost" onClick={() => void load()}>Retry HA status</Button>}</div>
    </SettingRow>}
    {settings && pools !== null && <>
      <SettingRow label="Connector HA activation" description={settings.enabled ? "Available. Activate each pool separately." : "Off. Existing fenced pools use the safe drain path."} error={!reviewing && !confirmDisable ? error : null}>
        <div className="k8s-operation-actions features-control" aria-label="Connector HA controls"><SettingValue>{settings.enabled ? "Available" : "Off"}</SettingValue><span className="k8s-operation-muted">Actual</span><Badge tone={actualTone(settings.actual_state)}>{stateLabel(settings.actual_state)}</Badge>{central ? canManage && <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => settings.enabled ? setConfirmDisable(true) : void setOrganizationEnabled(true)}>{settings.enabled ? "Begin safe HA drain" : "Enable HA availability"}</Button> : <Link className="features-link" to="/settings?section=features&feature=kubernetes-ha">Manage in Features</Link>}</div>
      </SettingRow>
      {!central && <SettingRow label="Connector pools" description={pools.length === 0 ? "No configured pools. Direct connectors stay in legacy mode." : pools.length + " configured " + (pools.length === 1 ? "pool." : "pools.")}>
        <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => setReviewing(true)}>Review pools</Button>
      </SettingRow>}
      <details className="k8s-operation-disclosure k8s-ha-context"><summary>Activation status and safeguards</summary><div>
        <dl className="k8s-operation-facts"><div><dt>Requested availability</dt><dd>{settings.enabled ? "Enabled" : "Disabled"}</dd></div><div><dt>Settings revision</dt><dd>{settings.revision}</dd></div><div><dt>Deployment readiness</dt><dd>{settings.deployment_ready === undefined ? "Not reported" : settings.deployment_ready ? "Reported ready" : "Not ready"}</dd></div><div><dt>Scheduler</dt><dd>{settings.scheduler_state ? stateLabel(settings.scheduler_state) : "Not reported"}</dd></div><div><dt>Reason</dt><dd>{settings.reason_code}</dd></div>{settings.scheduler_reason_codes?.length > 0 && <div><dt>Scheduler reasons</dt><dd>{settings.scheduler_reason_codes.join(", ")}</dd></div>}</dl>
        <p>Availability and requested modes are configuration. Only the reported actual state shows whether fenced activation or a safe drain completed.</p>
      </div></details>
    </>}
    {!central && reviewing && <Modal title="Connector pools" placement="right" size="wide" showClose onDismiss={busy ? () => {} : () => setReviewing(false)} actions={<><Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void load()}>Refresh HA status</Button><Button variant="ghost" disabled={busy !== null} onClick={() => setReviewing(false)}>Done</Button></>}>
      <div className="k8s-ha-review">
        <p className="k8s-operation-note">Requested mode and reported ownership state are separate. A request alone does not verify failover or traffic.</p>
        <ErrorText>{error}</ErrorText>
        {!settings || pools === null ? <p role="status" className="k8s-operation-note">{error ? "Pool status unavailable. Refresh before requesting a mode." : "Reading pool status…"}</p> : pools.length === 0 ? <p role="status" className="k8s-operation-note">No connector pools are configured.</p> : <NetworkDetailList label="Connector pools" items={pools} searchText={pool => pool.pool_id + " " + pool.cluster_id + " " + pool.active_node_id + " " + pool.requested_mode + " " + pool.actual_mode + " " + pool.reason_code} renderItem={pool => <li key={pool.pool_id} className="k8s-ha-pool">
          <div className="k8s-ha-pool-heading"><strong>Pool {pool.pool_id.slice(0, 8)}</strong><Badge tone={actualTone(pool.actual_mode)}>{stateLabel(pool.actual_mode)}</Badge></div>
          <div className="k8s-ha-pool-summary"><span>Requested {stateLabel(pool.requested_mode)}</span><span>Generation {pool.promotion_generation}</span></div>
          <div className="k8s-ha-pool-actions">{canManage && <Button size="sm" variant="ghost" disabled={busy !== null || (!settings.enabled && pool.requested_mode === "legacy")} onClick={() => void requestPoolMode(pool, pool.requested_mode === "fenced_ha" ? "legacy" : "fenced_ha")}>{pool.requested_mode === "fenced_ha" ? "Request safe legacy drain" : "Request fenced HA"}</Button>}</div>
          <details className="k8s-operation-disclosure"><summary>Transition details</summary><div><dl className="k8s-operation-facts"><div><dt>Cluster</dt><dd>{pool.cluster_id}</dd></div><div><dt>Active connector</dt><dd>{pool.active_node_id}</dd></div><div><dt>Membership epoch</dt><dd>{pool.membership_epoch_known ? pool.membership_epoch ?? "Unavailable" : "Unavailable"}</dd></div><div><dt>Transition revision</dt><dd>{pool.transition_revision}</dd></div><div><dt>Reason</dt><dd>{pool.reason_code}</dd></div>{pool.requested_at && <div><dt>Requested at</dt><dd>{pool.requested_at}</dd></div>}{pool.achieved_at && <div><dt>Achieved at</dt><dd>{pool.achieved_at}</dd></div>}</dl></div></details>
        </li>} />}
      </div>
    </Modal>}
    {central && settings && confirmDisable && canManage && <Modal title="Begin organization-wide safe HA drain?" placement="right" danger showClose onDismiss={busy ? () => {} : () => setConfirmDisable(false)} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setConfirmDisable(false)}>Cancel</Button><Button variant="danger" disabled={busy !== null} onClick={() => void setOrganizationEnabled(false)}>{busy ? "Starting safe drain…" : "Begin safe drain"}</Button></>}>
      <div className="k8s-ha-drain"><p>Stop new fenced-HA activation and request a safe return to legacy mode for every fenced pool.</p><p>This does not immediately unfence nodes or claim that traffic has moved.</p><p>If ownership delivery, acknowledgement, or drain proof cannot complete, the pool remains fenced and reports a blocked or drain-pending actual state until an operator resolves it.</p><details className="k8s-operation-disclosure"><summary>Retained records</summary><div><p>Pool settings, transition history, and audit evidence survive the drain.</p></div></details><ErrorText>{error}</ErrorText></div>
    </Modal>}
  </>;
}
