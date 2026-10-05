import { useEffect, useState } from "react";
import { api, apiErrorMessage, type Device } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ErrorText, Field, Select } from "./ui";

export type SandboxTerminalSelection = { id: string; name: string };

// The list is advisory. Create verifies ownership, membership, health and gateway
// again under the organization lock before storing immutable terminal identity.
export function SandboxTerminalPicker({ orgId, gatewayId, value, onChange }: {
  orgId: string; gatewayId?: string; value: string;
  onChange: (selection: SandboxTerminalSelection | null) => void;
}) {
  const { state } = useAuth();
  const userId = state.status === "authed" ? state.user.id : undefined;
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    setDevices(null); setError(null);
    if (!userId || !gatewayId) { onChange(null); return; }
    void api.GET("/api/v1/organizations/{orgId}/devices", { params: { path: { orgId } } }).then(result => {
      if (!active) return;
      if (result.error || !result.data) {
        onChange(null);
        setError(apiErrorMessage(result.error, "Terminal devices could not be loaded. Return to Access to retry."));
        return;
      }
      setDevices(result.data.filter(device => device.user_id === userId && device.kind === "human" && device.status === "active" && !device.health_blocked && device.node_id === gatewayId));
    }).catch(() => {
      if (active) { onChange(null); setError("Terminal devices could not be loaded. Return to Access to retry."); }
    });
    return () => { active = false; };
  }, [orgId, userId, gatewayId, onChange]);
  useEffect(() => {
    if (devices && value && !devices.some(device => device.id === value)) onChange(null);
  }, [devices, value, onChange]);
  return <div>
    <Field label="Your terminal device"><Select required value={value} disabled={!devices?.length} onChange={event => {
      const device = devices?.find(item => item.id === event.target.value);
      onChange(device ? { id: device.id, name: device.name } : null);
    }}><option value="">Choose your terminal device</option>{devices?.map(device => <option key={device.id} value={device.id}>{device.name}</option>)}</Select></Field>
    <p className="sb-help mt-2">Choose your active Tunnex device on the terminal gateway. Use your SSH key from that device to connect.</p>
    {error && <ErrorText>{error}</ErrorText>}
    {!userId && <p className="sb-help">Sign in to select your terminal device.</p>}
    {userId && !gatewayId && <ErrorText>Terminal gateway configuration is unavailable.</ErrorText>}
    {userId && gatewayId && !devices && !error && <p role="status">Loading your terminal devices…</p>}
    {devices?.length === 0 && <p className="sb-help">No eligible terminal device. Connect your own Tunnex device to this organization's terminal gateway, then return to Access.</p>}
  </div>;
}
