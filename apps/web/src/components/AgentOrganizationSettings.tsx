import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { api, apiErrorMessage, loadOne } from "../lib/api";
import { Button, Card, Field, Input, SettingRow, Switch } from "./ui";

export function AgentQuotaCard({ orgId, value, canEdit }: { orgId: string; value: number | null; canEdit: boolean }) {
  const [input, setInput] = useState(value == null ? "" : String(value)); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [saved, setSaved] = useState(false);
  useEffect(() => setInput(value == null ? "" : String(value)), [orgId, value]);
  async function save() { setBusy(true); setError(null); setSaved(false); const parsed = input.trim() === "" ? null : Number(input); if (parsed !== null && (!Number.isInteger(parsed) || parsed < 0)) { setBusy(false); setError("Enter a non-negative whole number, or leave blank for unlimited."); return; } const result = await api.PUT("/api/v1/organizations/{orgId}/agent-quota", { params: { path: { orgId } }, body: { max_agent_identities: parsed } }); setBusy(false); if (result.error || !result.data) { setError("Could not save the agent quota."); return; } const serverValue = result.data.max_agent_identities; setInput(serverValue == null ? "" : String(serverValue)); setSaved(true); }
  if (!canEdit) return null;
  return <Card data-testid="agent-quota-card"><h2 className="text-sm font-semibold text-ink-heading">Managed-agent quota</h2><p className="mt-1 text-xs text-ink-secondary">Maximum organization-wide agent identities. Pending, active, and suspended agents count; revoked and deleted agents do not. Leave blank for unlimited.</p><div className="mt-3 flex flex-wrap items-end gap-3"><Field label="Maximum identities"><Input inputMode="numeric" value={input} onChange={(event) => { setInput(event.target.value); setSaved(false); }} placeholder="Unlimited" disabled={busy} aria-label="Maximum agent identities" /></Field><Button onClick={() => void save()} disabled={busy}>{busy ? "Saving…" : "Save quota"}</Button></div>{saved && <p className="mt-2 text-xs text-accent-400">Quota saved from server response.</p>}{error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}</Card>;
}

type RuntimeSettingProps = { orgId: string; value: boolean; canEdit: boolean; central?: boolean; onSaved: (enabled: boolean) => void | Promise<void> };
export function AgentRuntimeSettingCard(props: RuntimeSettingProps) {
  const { state } = useAuth();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}:${state.user.must_change_password}` : state.status;
  return <RuntimeSetting key={`${props.orgId}:${actor}:${props.canEdit}:${props.central}`} {...props} canEdit={props.canEdit && state.status === "authed" && state.user.email_verified && !state.user.must_change_password} />;
}
function RuntimeSetting({ orgId,value,canEdit,central = false,onSaved }: RuntimeSettingProps) {
  const [enabled,setEnabled] = useState(value), [busy,setBusy] = useState(false), [error,setError] = useState<string | null>(null);
  const alive = useRef(true), locked = useRef(false);
  useEffect(() => { alive.current=true; return () => { alive.current=false; }; },[]);
  useEffect(() => { setEnabled(value); setError(null); },[value]);
  async function toggle(next:boolean) {
    if (!central || !canEdit || locked.current || error || typeof enabled !== "boolean" || next === enabled) return;
    locked.current=true; setBusy(true); setError(null);
    try {
      const result=await api.PUT("/api/v1/organizations/{orgId}/agent-runtime-settings",{params:{path:{orgId}},body:{enabled:next}});
      if (!alive.current) return;
      if (result.error || typeof result.data?.enabled !== "boolean") setError(apiErrorMessage(result.error,"Could not confirm runtime synchronization. Reload the saved setting before trying again."));
      else { setEnabled(result.data.enabled); await onSaved(result.data.enabled); }
    } catch { if (alive.current) setError("Could not confirm runtime synchronization. Reload the saved setting before trying again."); }
    finally { locked.current=false; if (alive.current) setBusy(false); }
  }
  async function reload() {
    if (!alive.current || locked.current) return;
    locked.current=true; setBusy(true);
    try {
      const result=await loadOne(() => api.GET("/api/v1/organizations/{orgId}",{params:{path:{orgId}}}));
      if (!alive.current) return;
      if (!result.ok || typeof result.data.managed_agent_runtime_enabled !== "boolean") setError(result.ok ? "Runtime synchronization status is unavailable." : result.error);
      else { setEnabled(result.data.managed_agent_runtime_enabled); await onSaved(result.data.managed_agent_runtime_enabled); if (alive.current) setError(null); }
    } catch { if (alive.current) setError("Could not confirm runtime synchronization. Reload the saved setting before trying again."); }
    finally { locked.current=false; if (alive.current) setBusy(false); }
  }
  if (central) return <div data-testid="agent-runtime-setting-card"><SettingRow label="Runtime synchronization" description="Allow server-owned managed runtime configuration updates. This does not grant model or MCP tool access." error={error}>{typeof enabled === "boolean" && !error ? <Switch label="Runtime synchronization" checked={enabled} disabled={!canEdit || busy} onChange={next => void toggle(next)} /> : <span className="text-sm text-ink-secondary">Unavailable</span>}</SettingRow>{error && <>{typeof enabled === "boolean" && <p className="feature-control-note">Last reported: {enabled ? "Enabled" : "Disabled"}.</p>}<Button variant="ghost" disabled={busy} onClick={() => void reload()}>Reload runtime synchronization setting</Button></>}</div>;
  return <Card data-testid="agent-runtime-setting-card"><h2 className="text-sm font-semibold text-ink-heading">Runtime synchronization</h2><p className="mt-1 text-xs text-ink-secondary">{typeof enabled !== "boolean" ? "Status unavailable." : enabled ? "Enabled for this organization." : "Disabled for this organization."}</p><Link className="text-brand text-sm" to="/settings?section=features&feature=agent-runtime">Manage feature</Link></Card>;
}
