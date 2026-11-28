import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { toast } from "./Toasts";
import { HelpTooltip } from "./HelpTooltip";
import { AIGatewayOffBanner, useAIGatewayStatus } from "./AIGatewayOffBanner";
import { AIGatewaySwitch } from "./WorkspaceFeatureControl";
import "./ai-gateway-settings.css";
import "./ai-gateway-access.css";
import { Button, Card, Field, Input } from "./ui";

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
    <AICostSettingsCard orgId={orgId} canEdit={canEdit} />
  </>;
}

type CostSettings = components["schemas"]["AICostSettings"];

// AI-READY-1: what a daily limit does with a model that has no price, and how
// long the request log is kept.
function AICostSettingsCard({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [saved, setSaved] = useState<CostSettings | null>(null);
  const [policy, setPolicy] = useState<CostSettings["unknown_price_policy"]>("block");
  const [retention, setRetention] = useState("30");
  const [failed, setFailed] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/cost-settings", { params: { path: { orgId } } });
        if (!alive) return;
        if (r.error || !r.data) { setFailed(true); return; }
        setSaved(r.data); setPolicy(r.data.unknown_price_policy); setRetention(String(r.data.request_log_retention_days)); setFailed(false);
      } catch { if (alive) setFailed(true); }
    })();
    return () => { alive = false; };
  }, [orgId, attempt]);
  const days = Number(retention);
  const validDays = Number.isInteger(days) && days >= 1 && days <= 365;
  const changed = saved && (policy !== saved.unknown_price_policy || days !== saved.request_log_retention_days);
  async function save() {
    if (!saved) return;
    setBusy(true); setError("");
    try {
      const r = await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/cost-settings", { params: { path: { orgId } }, body: { unknown_price_policy: policy, request_log_retention_days: days, expected_revision: saved.revision } });
      if (r.error || !r.data) { setError(r.response?.status === 409 ? "Someone else changed these settings. Reload them before saving again." : apiErrorMessage(r.error, "Could not save the settings.")); return; }
      setSaved(r.data); toast.success("Cost settings saved");
    } catch { setError("Could not reach the API. Reload to check the saved settings."); }
    finally { setBusy(false); }
  }
  return <Card className="ai-setting-card ai-secondary-settings" aria-label="Cost settings">
    <div className="ai-setting-copy"><h3>Models without a price <HelpTooltip label="About models without a price">Applies to user groups, workloads and agent groups that have a daily cost limit. Set a price for a model in Models &amp; endpoints to cost it exactly.</HelpTooltip></h3>
      <p>What a daily cost limit does with a model whose price is unknown.</p></div>
    {failed && <><p role="alert" className="text-danger">Could not load cost settings.</p><Button variant="ghost" onClick={() => setAttempt((v) => v + 1)}>Retry cost settings</Button></>}
    {!saved && !failed && <p role="status">Loading cost settings…</p>}
    {saved && <div className="grid gap-3 mt-3">
      <fieldset className="grid gap-2" disabled={!canEdit || busy}>
        <legend className="sr-only">Models without a price</legend>
        <label className="flex gap-2 items-start"><input type="radio" name="unknown-price" disabled={!canEdit || busy} checked={policy === "block"} onChange={() => setPolicy("block")} /><span><strong>Block (default)</strong><br /><span className="text-sm text-ink-secondary">Refuse the request. Safest: the limit always covers every call.</span></span></label>
        <label className="flex gap-2 items-start"><input type="radio" name="unknown-price" disabled={!canEdit || busy} checked={policy === "allow_and_alert"} onChange={() => setPolicy("allow_and_alert")} /><span><strong>Allow and alert</strong><br /><span className="text-sm text-ink-secondary">Let the request through and send the “Model without a price” alert once a day per group and model. These calls do not count against the limit.</span></span></label>
      </fieldset>
      <Field label="Keep the request log for (days)"><Input type="number" inputMode="numeric" min="1" max="365" step="1" value={retention} disabled={!canEdit || busy} onChange={(e) => setRetention(e.target.value)} /></Field>
      {!validDays && <p className="text-sm text-danger">Enter a whole number of days from 1 to 365.</p>}
      <p className="text-sm text-ink-tertiary">The request log keeps time, who, model, status, tokens and cost for each AI call. Prompts and responses are never stored.</p>
      {error && <p role="alert" className="text-danger">{error}</p>}
      {canEdit ? <div><Button disabled={busy || !changed || !validDays} onClick={() => void save()}>{busy ? "Saving…" : "Save cost settings"}</Button></div> : <p className="text-sm text-ink-secondary">Only an organization owner or administrator can change these settings.</p>}
    </div>}
  </Card>;
}
