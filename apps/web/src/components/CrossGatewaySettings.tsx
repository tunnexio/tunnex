import { useEffect, useRef, useState } from "react";
import { api, apiErrorMessage, loadOne, type Org } from "../lib/api";
import { Button, SettingRow, SettingValue, Switch } from "./ui";

export function CrossGatewaySettings({ org, canEdit, onSaved }: {
  org: Org;
  canEdit: boolean;
  onSaved: (org: Org) => void | Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unknown, setUnknown] = useState(false);
  const alive = useRef(true), locked = useRef(false), allowed = useRef(canEdit);
  allowed.current = canEdit;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function reload() {
    if (!alive.current || locked.current) return;
    locked.current = true; setBusy(true);
    try {
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}", { params: { path: { orgId: org.id } } }));
    if (alive.current) {
      if (!result.ok || result.data.id !== org.id || typeof result.data.cross_gateway_clients_enabled !== "boolean") setError(result.ok ? "Organization settings are unavailable." : result.error);
      else { setUnknown(false); setError(null); await onSaved(result.data); }
    }
    } catch { if (alive.current) { setUnknown(true); setError("Organization status could not be confirmed. Reload before another change."); } }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  async function toggle(enabled: boolean) {
    if (!alive.current || locked.current || !allowed.current || unknown || error || typeof org.cross_gateway_clients_enabled !== "boolean") return;
    locked.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/cross-gateway-settings", {
        params: { path: { orgId: org.id } }, body: { enabled },
      });
      if (!alive.current || !allowed.current) return;
      if (result.error || typeof result.data?.enabled !== "boolean") {
        setUnknown(true);
        setError(apiErrorMessage(result.error, "Could not update cross-gateway connectivity."));
        return;
      }
      await onSaved({ ...org, cross_gateway_clients_enabled: result.data.enabled });
    } catch {
      if (alive.current) { setUnknown(true); setError("The change could not be confirmed. Reload before another change."); }
    } finally {
      locked.current = false;
      if (alive.current) setBusy(false);
    }
  }
  return <SettingRow label="Cross-gateway client connectivity"
    description="Connect clients across gateways. Zero Trust rules still apply; a reachable WireGuard endpoint is required."
    error={error}>
    {unknown || typeof org.cross_gateway_clients_enabled !== "boolean" ? <SettingValue>Unavailable</SettingValue> : <Switch label="Cross-gateway client connectivity" checked={org.cross_gateway_clients_enabled} disabled={busy || !canEdit || !!error} onChange={toggle} />}
    {(error || typeof org.cross_gateway_clients_enabled !== "boolean") && <Button variant="ghost" disabled={busy} onClick={() => void reload()}>Reload connectivity setting</Button>}
  </SettingRow>;
}
