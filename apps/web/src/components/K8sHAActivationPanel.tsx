import { useCallback, useEffect, useState } from "react";
import { api, apiErrorMessage, type K8sConnectorPoolHAStatus, type K8sHASettings, type Role } from "../lib/api";
import { can } from "../lib/rbac";
import { Badge, Button, Modal, Panel } from "./ui";

export function K8sHAActivationPanel({ orgId, role, emailVerified }: { orgId: string; role: Role | undefined; emailVerified: boolean }) {
  const canView = can(role, "k8s_ha:view");
  const canManage = emailVerified && can(role, "k8s_ha:manage");
  const [settings, setSettings] = useState<K8sHASettings | null>(null);
  const [pools, setPools] = useState<K8sConnectorPoolHAStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmDisable, setConfirmDisable] = useState(false);

  const load = useCallback(async () => {
    if (!canView) return;
    setError(null);
    const [settingsResult, poolsResult] = await Promise.all([
      api.GET("/api/v1/organizations/{orgId}/k8s/ha-settings", { params: { path: { orgId } } }),
      api.GET("/api/v1/organizations/{orgId}/k8s/connector-pools/ha-status", { params: { path: { orgId } } }),
    ]);
    if (settingsResult.error || poolsResult.error) {
      setSettings(null);
      setPools(null);
      setError(apiErrorMessage(settingsResult.error ?? poolsResult.error, "HA status is unavailable. No readiness is inferred."));
      return;
    }
    setSettings(settingsResult.data);
    setPools(poolsResult.data);
  }, [canView, orgId]);

  useEffect(() => { void load(); }, [load]);
  if (!canView) return null;

  async function setOrganizationEnabled(enabled: boolean) {
    if (!settings) return;
    setBusy("settings");
    try {
      const { error: mutationError } = await api.PUT("/api/v1/organizations/{orgId}/k8s/ha-settings", {
        params: { path: { orgId } }, body: { enabled, expected_revision: settings.revision },
      });
      if (mutationError) return setError(apiErrorMessage(mutationError, "Could not change the HA opt-in."));
      setConfirmDisable(false);
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function requestPoolMode(pool: K8sConnectorPoolHAStatus, requested_mode: "legacy" | "fenced_ha") {
    setBusy(pool.pool_id);
    try {
      const { error: mutationError } = await api.PUT("/api/v1/organizations/{orgId}/k8s/connector-pools/{poolId}/ha-mode", {
        params: { path: { orgId, poolId: pool.pool_id } },
        body: { requested_mode, expected_transition_revision: pool.transition_revision },
      });
      if (mutationError) return setError(apiErrorMessage(mutationError, "Could not request the pool ownership mode."));
      await load();
    } finally {
      setBusy(null);
    }
  }

  return <Panel title="Connector HA activation">
    {error && <div role="alert" className="mb-3 rounded-input border border-danger/40 bg-danger/10 p-2 text-micro text-danger">{error}</div>}
    {!error && (!settings || pools === null) && <p className="text-micro text-ink-faint">Loading HA configuration…</p>}
    {settings && pools !== null && <>
      <div className="flex flex-wrap items-start justify-between gap-3 rounded-input border border-line bg-surface-inset p-3">
        <div>
          <div className="flex items-center gap-2"><strong className="text-sm text-ink-heading">Organization opt-in</strong><Badge tone={settings.actual_state === "enabled" ? "ok" : settings.actual_state === "blocked" ? "danger" : "neutral"}>{settings.actual_state}</Badge></div>
          <p className="mt-1 text-micro text-ink-tertiary">{settings.enabled ? "HA is available, but each connector pool still requires an explicit fenced-HA request." : "HA is off. Existing fenced pools drain safely; omission or timeout never unfences a node."}</p>
          <p className="mt-1 font-mono text-micro text-ink-faint">reason {settings.reason_code} · revision {settings.revision}</p>
        </div>
        {canManage && <Button size="sm" variant={settings.enabled ? "danger" : "primary"} disabled={busy !== null} onClick={() => settings.enabled ? setConfirmDisable(true) : void setOrganizationEnabled(true)}>{settings.enabled ? "Begin safe HA drain" : "Enable HA availability"}</Button>}
      </div>
      <div className="mt-3 flex flex-col gap-2">
        {pools.length === 0 ? <p className="text-micro text-ink-faint">No connector pools are configured. A direct single connector remains legacy mode.</p> : pools.map((pool) => <div key={pool.pool_id} className="flex flex-wrap items-center justify-between gap-3 rounded-input border border-line p-3">
          <div>
            <div className="flex items-center gap-2"><span className="font-mono text-micro text-ink-body">pool {pool.pool_id.slice(0, 8)}</span><Badge tone={pool.actual_mode === "fenced_ha" ? "ok" : pool.actual_mode === "blocked" ? "danger" : "neutral"}>{pool.actual_mode}</Badge></div>
            <p className="mt-1 text-micro text-ink-faint">requested {pool.requested_mode} · generation {pool.promotion_generation} · {pool.membership_epoch_known ? `membership epoch ${pool.membership_epoch}` : "membership epoch unavailable"} · {pool.reason_code}</p>
          </div>
          {canManage && <Button size="sm" variant="ghost" disabled={busy !== null || (!settings.enabled && pool.requested_mode === "legacy")} onClick={() => void requestPoolMode(pool, pool.requested_mode === "fenced_ha" ? "legacy" : "fenced_ha")}>{pool.requested_mode === "fenced_ha" ? "Request safe legacy drain" : "Request fenced HA"}</Button>}
        </div>)}
      </div>
      {confirmDisable && <Modal title="Begin organization-wide safe HA drain?" danger onDismiss={busy ? () => {} : () => setConfirmDisable(false)} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setConfirmDisable(false)}>Cancel</Button><Button variant="danger" disabled={busy !== null} onClick={() => void setOrganizationEnabled(false)}>{busy ? "Starting safe drain…" : "Begin safe drain"}</Button></>}><div className="space-y-2 text-sm text-ink-tertiary"><p>This turns off new fenced-HA activation and asks every fenced pool to return through the safe drain path. It does not immediately unfence nodes or claim that traffic has moved.</p><p>Pool settings, transition history, and audit evidence survive. If ownership delivery, acknowledgement, or drain proof cannot complete, the pool remains fenced and reports a blocked or drain-pending actual state until an operator resolves it.</p></div></Modal>}
    </>}
  </Panel>;
}
