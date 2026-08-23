import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Button, Card, Field, Input } from "./ui";

export function AgentQuotaCard({ orgId, value, canEdit }: { orgId: string; value: number | null; canEdit: boolean }) {
  const [input, setInput] = useState(value == null ? "" : String(value)); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [saved, setSaved] = useState(false);
  useEffect(() => setInput(value == null ? "" : String(value)), [orgId, value]);
  async function save() { setBusy(true); setError(null); setSaved(false); const parsed = input.trim() === "" ? null : Number(input); if (parsed !== null && (!Number.isInteger(parsed) || parsed < 0)) { setBusy(false); setError("Enter a non-negative whole number, or leave blank for unlimited."); return; } const result = await api.PUT("/api/v1/organizations/{orgId}/agent-quota", { params: { path: { orgId } }, body: { max_agent_identities: parsed } }); setBusy(false); if (result.error || !result.data) { setError("Could not save the agent quota."); return; } const serverValue = result.data.max_agent_identities; setInput(serverValue == null ? "" : String(serverValue)); setSaved(true); }
  if (!canEdit) return null;
  return <Card data-testid="agent-quota-card"><h2 className="text-sm font-semibold text-ink-heading">Managed-agent quota</h2><p className="mt-1 text-xs text-ink-secondary">Maximum organization-wide agent identities. Pending, active, and suspended agents count; revoked and deleted agents do not. Leave blank for unlimited.</p><div className="mt-3 flex flex-wrap items-end gap-3"><Field label="Maximum identities"><Input inputMode="numeric" value={input} onChange={(event) => { setInput(event.target.value); setSaved(false); }} placeholder="Unlimited" disabled={busy} aria-label="Maximum agent identities" /></Field><Button onClick={() => void save()} disabled={busy}>{busy ? "Saving…" : "Save quota"}</Button></div>{saved && <p className="mt-2 text-xs text-accent-400">Quota saved from server response.</p>}{error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}</Card>;
}

export function AgentRuntimeSettingCard({ orgId, value, canEdit, onSaved }: { orgId: string; value: boolean; canEdit: boolean; onSaved: (enabled: boolean) => void }) {
  const [enabled, setEnabled] = useState(value); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  useEffect(() => setEnabled(value), [orgId, value]);
  async function toggle() { const next = !enabled; setBusy(true); setError(null); const result = await api.PUT("/api/v1/organizations/{orgId}/agent-runtime-settings", { params: { path: { orgId } }, body: { enabled: next } }); setBusy(false); if (result.error || !result.data) { setError("Could not update managed runtime synchronization."); return; } setEnabled(result.data.enabled); onSaved(result.data.enabled); }
  if (!canEdit) return null;
  return <Card data-testid="agent-runtime-setting-card"><h2 className="text-sm font-semibold text-ink-heading">Runtime synchronization</h2><p className="mt-1 text-xs text-ink-secondary">Off by default. Enable the managed runtime channel only when this organization is ready for server-owned configuration updates.</p><div className="mt-3"><Button onClick={() => void toggle()} disabled={busy}>{busy ? "Saving…" : enabled ? "Disable runtime synchronization" : "Enable runtime synchronization"}</Button></div>{error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}</Card>;
}
