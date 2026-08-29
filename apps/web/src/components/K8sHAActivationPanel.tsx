import { useCallback, useEffect, useState } from "react";
import { api, apiErrorMessage, type K8sConnectorPoolHAStatus, type K8sHASettings, type Role } from "../lib/api";
import { can } from "../lib/rbac";
import { Badge, Button, Modal, SettingRow, SettingValue } from "./ui";

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

  return <>
    {error && <SettingRow label="Connector HA activation" description="Controls fenced connector ownership and safe failover." error={error}><SettingValue tone="danger">Unavailable</SettingValue></SettingRow>}
    {!error && (!settings || pools === null) && <SettingRow label="Connector HA activation" description="Controls fenced connector ownership and safe failover."><SettingValue>Loading…</SettingValue></SettingRow>}
    {settings && pools !== null && <>
      <SettingRow
        label="Connector HA activation"
        description={settings.enabled ? "Available for connector pools; each pool still requires an explicit fenced-HA request." : "Off. Existing fenced pools drain safely before returning to legacy mode."}
      >
        <div className="flex items-center gap-2" aria-label="Connector HA controls"><Badge tone={settings.actual_state === "enabled" ? "ok" : settings.actual_state === "blocked" ? "danger" : "neutral"}>{settings.actual_state}</Badge>{canManage && <Button size="sm" variant={settings.enabled ? "danger" : "primary"} disabled={busy !== null} onClick={() => settings.enabled ? setConfirmDisable(true) : void setOrganizationEnabled(true)}>{settings.enabled ? "Begin safe HA drain" : "Enable HA availability"}</Button>}</div>
      </SettingRow>
      <SettingRow
        label="Connector pools"
        description={pools.length === 0 ? "No pools configured. Direct connectors remain in legacy mode." : `${pools.length} connector ${pools.length === 1 ? "pool" : "pools"} configured.`}
      >
        {pools.length === 0 ? <SettingValue>Legacy</SettingValue> : <details className="relative text-cell"><summary className="cursor-pointer select-none text-ink-body">Review pools</summary><div className="absolute right-0 z-10 mt-2 w-[min(32rem,80vw)] rounded-card border border-line bg-surface p-3 shadow-xl">{pools.map((pool) => <div key={pool.pool_id} className="flex flex-wrap items-center justify-between gap-3 border-b border-line-row py-2 last:border-0"><div><div className="flex items-center gap-2"><span className="font-mono text-micro text-ink-body">pool {pool.pool_id.slice(0, 8)}</span><Badge tone={pool.actual_mode === "fenced_ha" ? "ok" : pool.actual_mode === "blocked" ? "danger" : "neutral"}>{pool.actual_mode}</Badge></div><p className="mt-1 text-micro text-ink-faint">requested {pool.requested_mode} · generation {pool.promotion_generation}</p></div>{canManage && <Button size="sm" variant="ghost" disabled={busy !== null || (!settings.enabled && pool.requested_mode === "legacy")} onClick={() => void requestPoolMode(pool, pool.requested_mode === "fenced_ha" ? "legacy" : "fenced_ha")}>{pool.requested_mode === "fenced_ha" ? "Request safe legacy drain" : "Request fenced HA"}</Button>}</div>)}</div></details>}
      </SettingRow>
      {confirmDisable && <Modal title="Begin organization-wide safe HA drain?" danger onDismiss={busy ? () => {} : () => setConfirmDisable(false)} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setConfirmDisable(false)}>Cancel</Button><Button variant="danger" disabled={busy !== null} onClick={() => void setOrganizationEnabled(false)}>{busy ? "Starting safe drain…" : "Begin safe drain"}</Button></>}><div className="space-y-2 text-sm text-ink-tertiary"><p>This turns off new fenced-HA activation and asks every fenced pool to return through the safe drain path. It does not immediately unfence nodes or claim that traffic has moved.</p><p>Pool settings, transition history, and audit evidence survive. If ownership delivery, acknowledgement, or drain proof cannot complete, the pool remains fenced and reports a blocked or drain-pending actual state until an operator resolves it.</p></div></Modal>}
    </>}
  </>;
}
