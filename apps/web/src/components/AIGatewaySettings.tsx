import { HelpTooltip } from "./HelpTooltip";
import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import "./ai-gateway-settings.css";
import { Button, Card } from "./ui";

type Settings = components["schemas"]["AIGatewaySettings"];

export function AIGatewaySettings(props: { orgId: string; canEdit: boolean }) {
  return <GatewaySettings key={props.orgId} {...props} />;
}

function GatewaySettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    let live = true;
    setError(null);
    void api.GET("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId } } })
      .then(({ data, error }) => {
        if (!live) return;
        if (error || !data) setError("Could not load AI gateway settings.");
        else setSettings(data);
      }).catch(() => { if (live) setError("Could not load AI gateway settings."); });
    return () => { live = false; mounted.current = false; };
  }, [orgId, attempt]);

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

  return <Card className="ai-setting-card">
    <div className="ai-setting-row"><div className="ai-setting-copy"><h3>Gateway access <HelpTooltip label="About gateway access">Disabling blocks new requests. Accepted requests may finish within 30 seconds. Provider keys stay on your gateway. Usage thresholds are soft limits; concurrent requests can exceed them.</HelpTooltip></h3><p>Allow your organization to send requests to configured models.</p></div>
    {settings && <div className="ai-setting-actions"><span role="status" className={`ai-setting-state ${settings.enabled ? "is-on" : ""}`}>{settings.enabled ? "Enabled" : "Disabled"}</span>{canEdit && <Button disabled={busy || (!settings.available && !settings.enabled)} onClick={() => void toggle()}>{busy ? "Saving…" : settings.enabled ? "Disable AI gateway" : "Enable AI gateway"}</Button>}</div>}</div>
    {!settings && !error && <p role="status">Loading AI gateway settings…</p>}
    {settings && <div className="ai-setting-foot"><span>Gateway connection</span><span>{settings.available ? "Configured" : "Not configured"}</span>{!settings.available && <p>Ask your installation administrator to configure the gateway before enabling access.</p>}</div>}
    {error && <p role="alert" className="text-danger">{error}</p>}
    {error && !settings && <Button onClick={() => setAttempt(value => value + 1)}>Retry AI gateway settings</Button>}
  </Card>;
}
