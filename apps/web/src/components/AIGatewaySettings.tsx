import { HelpTooltip } from "./HelpTooltip";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { aiGatewayPrerequisite } from "../lib/aiGatewayPrerequisite";
import "./ai-gateway-settings.css";
import "./ai-gateway-access.css";
import { Button, Card } from "./ui";

type Settings = components["schemas"]["AIGatewaySettings"];

export function AIGatewaySettings(props: { orgId: string; canEdit: boolean }) {
  return <GatewaySettings key={props.orgId} {...props} />;
}

function GatewaySettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    setError(null); setSettings(null);
    void api.GET("/api/v1/organizations/{orgId}/ai-gateway", { params: { path: { orgId } } })
      .then(({ data, error }) => {
        if (!live) return;
        if (error || !data || typeof data.enabled !== "boolean" || typeof data.available !== "boolean" || !Number.isSafeInteger(data.revision) || data.revision < 0) setError("Could not load AI gateway settings.");
        else setSettings(data);
      }).catch(() => { if (live) setError("Could not load AI gateway settings."); });
    return () => { live = false; };
  }, [orgId, attempt]);

  const httpAllowed = settings?.http_allowed ?? settings?.private_http_allowed ?? false;
  return <Card className="ai-setting-card ai-secondary-settings">
    <div className="ai-setting-row"><div className="ai-setting-copy"><h3>Gateway access <HelpTooltip label="About gateway access">Disabling blocks new requests. Accepted requests may finish within 30 seconds. Provider keys stay on your gateway. Usage thresholds are soft limits; concurrent requests can exceed them.</HelpTooltip></h3><p>Allow your organization to send requests to configured models.</p></div>
    {settings && <div className="ai-setting-actions"><span role="status" className={`ai-setting-state ${settings.enabled ? "is-on" : ""}`}>{settings.enabled ? "Enabled" : "Disabled"}</span>{canEdit && <Link className="network-setup-link" to="/settings?section=features&feature=ai-gateway">Manage feature</Link>}</div>}</div>
    {!settings && !error && <p role="status">Loading AI gateway settings…</p>}
    {settings && <div className="ai-setting-foot"><span>Gateway connection</span><span>{settings.available ? httpAllowed ? "Configured · HTTP allowed" : "Configured" : settings.unavailable_reason === "https_required" ? settings.engine_installed ? "Installed · HTTPS required" : "HTTPS required" : "Not configured"}</span>{!settings.available && <p>{aiGatewayPrerequisite(settings)}</p>}{settings.available && httpAllowed && <p>Your server administrator permits HTTP access. HTTP does not encrypt credentials or requests; use HTTPS whenever possible.</p>}</div>}
    {error && <p role="alert" className="text-danger">{error}</p>}
    {error && !settings && <Button onClick={() => setAttempt(value => value + 1)}>Retry AI gateway settings</Button>}
  </Card>;
}
