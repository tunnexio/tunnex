import { useState } from "react";
import { HelpTooltip } from "./HelpTooltip";
import { AIGatewayOffBanner, useAIGatewayStatus } from "./AIGatewayOffBanner";
import { AIGatewaySwitch } from "./WorkspaceFeatureControl";
import "./ai-gateway-settings.css";
import "./ai-gateway-access.css";
import { Button, Card } from "./ui";

type Props = { orgId: string; canEdit: boolean; serverAdmin?: boolean };

export function AIGatewaySettings(props: Props) {
  return <GatewaySettings key={props.orgId} {...props} />;
}

function GatewaySettings({ orgId, canEdit, serverAdmin = false }: Props) {
  const gateway = useAIGatewayStatus(orgId);
  // The banner and the switch change the same saved setting; each re-reads after the other changes it.
  const [switchVersion, setSwitchVersion] = useState(0);
  const settings = gateway.settings;
  const httpAllowed = settings?.http_allowed ?? settings?.private_http_allowed ?? false;
  const reason = gateway.off ? gateway.status?.reason : null;
  const connection = !settings ? "" : reason === "transport_required" ? "Transport not chosen" : reason === "engine_not_installed" ? "AI engine not installed" : httpAllowed ? "Ready · HTTP allowed" : "Ready";
  return <>
    <AIGatewayOffBanner orgId={orgId} gateway={gateway} canManage={canEdit} serverAdmin={serverAdmin} onChanged={() => setSwitchVersion(value => value + 1)} />
    <Card className="ai-setting-card ai-secondary-settings">
      <div className="ai-setting-row"><div className="ai-setting-copy"><h3>Gateway access <HelpTooltip label="About gateway access">Disabling blocks new requests. Accepted requests may finish within 30 seconds. Provider keys stay on your gateway. Usage thresholds are soft limits; concurrent requests can exceed them.</HelpTooltip></h3><p>Allow your organization to send requests to configured models.</p></div>
      {settings && !canEdit && <div className="ai-setting-actions"><span role="status" className={`ai-setting-state ${settings.enabled ? "is-on" : ""}`}>{settings.enabled ? "Enabled" : "Disabled"}</span></div>}</div>
      {canEdit && <AIGatewaySwitch key={switchVersion} orgId={orgId} canEdit serverAdmin={serverAdmin} explained={gateway.off} onChanged={gateway.reload} />}
      {!canEdit && settings && <p className="mt-3 text-sm text-ink-secondary">Only an organization owner or administrator can turn AI Gateway on or off.</p>}
      {gateway.loading && <p role="status">Loading AI gateway settings…</p>}
      {settings && <div className="ai-setting-foot"><span>Gateway connection</span><span>{connection}</span>{settings.available && httpAllowed && <p>Your server administrator permits HTTP on the public internet. HTTP does not encrypt credentials or requests; use HTTPS whenever possible.</p>}</div>}
      {gateway.failed && !canEdit && <><p role="alert" className="text-danger">Could not load AI gateway settings.</p><Button onClick={gateway.reload}>Retry AI gateway settings</Button></>}
    </Card>
  </>;
}
