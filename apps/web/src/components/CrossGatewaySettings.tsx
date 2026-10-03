import { useState } from "react";
import { api, apiErrorMessage, type Org } from "../lib/api";
import { SettingRow, Switch } from "./ui";

export function CrossGatewaySettings({ org, canEdit, onSaved }: {
  org: Org;
  canEdit: boolean;
  onSaved: (org: Org) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function toggle(enabled: boolean) {
    if (busy || !canEdit) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/cross-gateway-settings", {
        params: { path: { orgId: org.id } }, body: { enabled },
      });
      if (result.error || !result.data) {
        setError(apiErrorMessage(result.error, "Could not update cross-gateway connectivity."));
        return;
      }
      onSaved({ ...org, cross_gateway_clients_enabled: result.data.enabled });
    } catch {
      setError("Could not update cross-gateway connectivity. Try again.");
    } finally {
      setBusy(false);
    }
  }
  return <SettingRow label="Cross-gateway client connectivity"
    description="Allow human clients and enrolled agents on different gateways in this organization to reach each other. Off by default. Existing Zero Trust rules still apply. Requires at least one reachable WireGuard gateway endpoint."
    error={error}>
    <Switch checked={org.cross_gateway_clients_enabled === true} disabled={busy || !canEdit} onChange={toggle} />
  </SettingRow>;
}
