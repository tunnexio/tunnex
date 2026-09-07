import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Card } from "./ui";

type Settings = components["schemas"]["AIGatewaySettings"];

export function AIGatewaySettings(props: { orgId: string; canEdit: boolean }) {
  return <GatewaySettings key={props.orgId} {...props} />;
}

function GatewaySettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    void api.GET("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId } } })
      .then(({ data, error }) => {
        if (!mounted.current) return;
        if (error || !data) setError("Could not load AI gateway settings.");
        else setSettings(data);
      }).catch(() => { if (mounted.current) setError("Could not load AI gateway settings."); });
    return () => { mounted.current = false; };
  }, [orgId]);

  async function toggle() {
    if (!settings || busy) return;
    setBusy(true);
    setError(null);
    try {
      const { data, error } = await api.PUT("/api/v1/organizations/{orgId}/ai-gateway", {
        params: { path: { orgId } }, body: { enabled: !settings.enabled },
      });
      if (!mounted.current) return;
      if (error || !data) setError("Could not update AI gateway access.");
      else setSettings(data);
    } catch {
      if (mounted.current) setError("Could not update AI gateway access.");
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  return <Card>
    <h2 className="text-sm font-semibold text-ink-heading">AI gateway</h2>
    <p className="mt-1 text-xs text-ink-secondary">Available in Community. Off by default. Enrolled agents use scoped credentials; provider keys stay on your gateway.</p>
    {!settings && !error && <p role="status" className="mt-2 text-xs text-ink-secondary">Loading AI gateway settings…</p>}
    {settings && <>
      <p role="status" className="mt-2 text-xs text-ink-secondary">Organization access: {settings.enabled ? "enabled" : "disabled"}. Gateway: {settings.available ? "configured" : "not configured"}.</p>
      {!settings.available && <p className="mt-2 text-xs text-ink-secondary">Ask your installation administrator to configure the private AI gateway before enabling access.</p>}
      <p className="mt-2 text-xs text-ink-secondary">Disabling blocks new requests. Accepted requests may finish within 30 seconds. Usage thresholds are soft and concurrent requests can exceed them.</p>
      {canEdit && <Button className="mt-3" disabled={busy || (!settings.available && !settings.enabled)} onClick={() => void toggle()}>{busy ? "Saving…" : settings.enabled ? "Disable AI gateway" : "Enable AI gateway"}</Button>}
    </>}
    {error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}
  </Card>;
}
