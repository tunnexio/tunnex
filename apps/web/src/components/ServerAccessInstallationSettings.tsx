import { useEffect, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading, SettingRow, Switch } from "./ui";
import { InlineTerminalMfa } from "./InlineTerminalMfa";

type Installation = components["schemas"]["ServerAccessInstallation"];
const endpoint = "/api/v1/admin/server-access/installation" as const;

/**
 * SA-UI-1: the installation-wide Server Access capability. Server administrators only; each change needs
 * recent re-authentication (current password and/or a fresh MFA verification) and is audited.
 */
export function ServerAccessInstallationSettings({ canEdit }: { canEdit: boolean }) {
  const [saved, setSaved] = useState<Installation | null>(null);
  const [pending, setPending] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [needMfa, setNeedMfa] = useState(false);
  const [busy, setBusy] = useState<"load" | "save" | null>("load");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  useEffect(() => {
    let current = true;
    setBusy("load"); setError(null);
    void api.GET(endpoint).then(({ data, error }) => {
      if (!current) return;
      if (error || !data) setError(apiErrorMessage(error, "Could not load the Server Access setting."));
      else { setSaved(data); setPending(null); setNeedMfa(false); setPassword(""); }
    }).catch(() => { if (current) setError("Could not reach the server. Try reloading again."); })
      .finally(() => { if (current) setBusy(null); });
    return () => { current = false; };
  }, [attempt]);

  async function save(event?: FormEvent) {
    event?.preventDefault();
    if (!saved || pending === null || !canEdit || busy) return;
    if (saved.reauthentication.password && !password) { setError("Enter your current password."); return; }
    setBusy("save"); setError(null); setResult(null);
    try {
      const response = await api.PATCH(endpoint, { body: { enabled: pending, expected_version: saved.version, ...(saved.reauthentication.password ? { current_password: password } : {}) } });
      if (!alive.current) return;
      if (response.error || !response.data) {
        const code = apiErrorCode(response.error);
        if (code === "mfa_step_up_required") { setNeedMfa(true); return; }
        if (code === "server_access_installation_changed") { setError("The setting changed on the server. Reload it before saving again."); return; }
        setError(apiErrorMessage(response.error, "Could not save the Server Access setting."));
        return;
      }
      const next = response.data;
      setSaved(next); setPending(null); setPassword(""); setNeedMfa(false);
      setResult(next.effective
        ? "Server Access is on for this installation. Each organization still turns it on in Settings → Features."
        : `Server Access is off for this installation. New sessions are refused${typeof next.ended_sessions !== "number" ? "" : next.ended_sessions === 0 ? "; no sessions were open" : `; ${next.ended_sessions} active ${next.ended_sessions === 1 ? "session was" : "sessions were"} ended`}.`);
    } catch {
      if (alive.current) setError("The response was interrupted. Reload the setting to check whether the change was saved.");
    } finally {
      if (alive.current) setBusy(null);
    }
  }

  if (!saved && busy === "load") return <Loading label="Loading Server Access setting…" />;
  if (!saved) return <div className="space-y-3"><ErrorText>{error}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry Server Access setting</Button></div>;

  const reauth = saved.reauthentication;
  // While the environment lock is set the switch shows what is enforced (Off) and cannot be changed; a saved
  // On is reported in words so the page never shows a green switch next to "Off".
  const switchDisabled = !canEdit || busy !== null || pending !== null || !reauth.available || saved.locked;
  const state = saved.effective ? "On" : saved.locked ? "Off, locked by the server environment" : "Off";
  return <div className="space-y-3" data-testid="server-access-installation">
    <SettingRow label="Server Access for this installation" description="Browser SSH and RDP for every organization on this server. Each organization must also turn it on in Settings → Features.">
      <Switch checked={saved.locked ? false : pending ?? saved.enabled} disabled={switchDisabled} onChange={next => { if (next !== saved.enabled) { setPending(next); setResult(null); setError(null); } }} />
    </SettingRow>
    <p className="text-sm text-ink-secondary">Status: <strong className="text-ink-heading">{state}</strong> · Source: {saved.source === "database" ? "Saved settings" : "Server environment"}</p>
    {saved.locked && <p className="text-sm text-ink-secondary" role="note">TUNNEX_SERVER_ACCESS_LOCKED is set on the server, so Server Access stays off and cannot be turned on here. Remove the lock in the server environment and restart the API to allow it.{saved.enabled ? " Saved setting: On. It applies again when the lock is removed." : ""}</p>}
    {!canEdit && <p className="text-sm text-ink-secondary">Verify your email and change your initial password to edit server settings.</p>}
    {canEdit && !reauth.available && <p className="text-sm text-ink-secondary" role="note">Changing this needs re-authentication, and your account has no password or authenticator on this server. Set up an authenticator app (two-factor authentication) in your account settings to change this setting.</p>}
    {pending !== null && <form className="space-y-3" onSubmit={event => void save(event)} aria-label="Confirm Server Access change">
      <p>{pending ? "Turn Server Access on for this installation. Organizations that have it turned on can register servers and open SSH or RDP sessions." : "Turn Server Access off for this installation. New sessions are refused and every active SSH or RDP session ends now."}</p>
      {reauth.password && <Field label="Current password"><Input type="password" autoComplete="current-password" required value={password} disabled={busy !== null} onChange={event => setPassword(event.target.value)} /></Field>}
      {!needMfa && <div className="flex gap-2"><Button type="submit" disabled={busy !== null}>{busy === "save" ? "Saving…" : pending ? "Turn on Server Access" : "Turn off Server Access"}</Button><Button type="button" variant="ghost" disabled={busy !== null} onClick={() => { setPending(null); setPassword(""); setError(null); }}>Cancel</Button></div>}
      {reauth.mfa && !needMfa && <p className="text-xs text-ink-secondary">You may be asked to verify MFA.</p>}
    </form>}
    {/* Outside the form above: the MFA step-up has its own form, and forms must not nest. */}
    {pending !== null && needMfa && <InlineTerminalMfa action="Change Server Access for this installation" freshnessSeconds={300} onVerified={() => { setNeedMfa(false); void save(); }} onCancel={() => setNeedMfa(false)} />}
    <ErrorText>{error}</ErrorText>
    {result && <p role="status" className="text-sm">{result}</p>}
    <Button variant="ghost" disabled={busy !== null} onClick={() => setAttempt(value => value + 1)}>{busy === "load" ? "Reloading…" : "Reload saved setting"}</Button>
  </div>;
}
