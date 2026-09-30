import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, apiErrorMessage, type ServerEmailSettings, type ServerEmailSettingsInput } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading, Select, Switch } from "./ui";

const endpoint = "/api/v1/admin/email-settings" as const;
const toDraft = (view: ServerEmailSettings): ServerEmailSettingsInput => ({
  enabled: view.enabled, host: view.host, port: view.port, from: view.from,
  username: view.username, revision: view.revision, password_action: "keep",
});

export function EmailDeliverySettings({ canEdit, email }: { canEdit: boolean; email: string }) {
  const [view, setView] = useState<ServerEmailSettings | null>(null);
  const [draft, setDraft] = useState<ServerEmailSettingsInput | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState<"load" | "save" | "test" | null>("load");
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(false);
  const locked = useRef(false);
  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);
  useEffect(() => {
    let current = true;
    setBusy("load"); setError(null); setResult(null); setDraft(null); setView(null);
    void api.GET(endpoint).then(({ data, error }) => {
      if (!current) return;
      if (!data || error) setError(apiErrorMessage(error, "Could not load email settings."));
      else { setView(data); setDraft(toDraft(data)); }
    }).catch(() => { if (current) setError("Could not reach the server. Try again."); })
      .finally(() => { if (current) setBusy(null); });
    return () => { current = false; };
  }, [attempt]);

  const change = (patch: Partial<ServerEmailSettingsInput>) => {
    setDraft(previous => previous ? { ...previous, ...patch } : previous);
    setResult(null); setError(null);
  };
  async function submit(action: "save" | "test", event?: FormEvent) {
    event?.preventDefault();
    if (!draft || !canEdit || locked.current || busy) return;
    locked.current = true; setBusy(action); setError(null); setResult(null);
    const body = { ...draft, password: draft.password_action === "replace" ? draft.password : undefined };
    try {
      if (action === "save") {
        const response = await api.PUT(endpoint, { body });
        if (!alive.current) return;
        if (response.error || !response.data) setError(apiErrorMessage(response.error, "Could not save email settings. Reload to check their current state."));
        else {
          setView(response.data); setDraft(toDraft(response.data));
          setResult(response.data.enabled ? "Email settings saved. New emails use this configuration; no restart is needed." : "Email delivery disabled. Invitations can still be shared manually.");
        }
      } else {
        const response = await api.POST("/api/v1/admin/email-settings/test", { body });
        if (!alive.current) return;
        if (response.error || !response.data?.accepted) setError(apiErrorMessage(response.error, "The test was not accepted. Saved settings were not changed."));
        else setResult("Your SMTP provider accepted the test email. Check your inbox or spam folder. These settings have not been saved.");
      }
    } catch {
      if (alive.current) setError(action === "save" ? "The response was interrupted. Reload to check whether your settings were saved before trying again." : "The test response was interrupted. Check your inbox before retrying. Saved settings were not changed.");
    } finally { locked.current = false; if (alive.current) setBusy(null); }
  }

  if (busy === "load") return <Loading label="Loading email settings…" />;
  if (!view || !draft) return <div><ErrorText>{error}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry email settings</Button></div>;
  const disabled = !canEdit || busy !== null;
  const changed = JSON.stringify(draft) !== JSON.stringify(toDraft(view));
  return <div className="space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line pb-5">
      <div className="space-y-1"><h3 className="text-sm font-semibold text-ink-heading">Email delivery for this server</h3>
        <p className="text-sm text-ink-secondary">Invitations, password resets and verification emails for every organization.</p>
        <p className="text-xs text-ink-tertiary">{view.source === "installer" ? "Using installation settings. Saving here creates a server-wide override." : "Using settings saved here. Installer values no longer override them."}</p>
      </div>
      <span className={`rounded-md border px-2.5 py-1 text-xs ${view.enabled ? "border-ok/30 text-ok" : "border-line text-ink-secondary"}`}>{view.enabled ? "Configured · delivery not verified" : "Email delivery off"}</span>
    </div>
    {!canEdit && <p className="text-sm text-warn">Verify your email and change your initial password to edit server settings.</p>}
    <form onSubmit={event => void submit("save", event)} className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><p className="text-sm font-medium text-ink-heading">Enable email delivery</p><p className="text-xs text-ink-secondary">Changes take effect when you save.</p></div>
        <Switch label="Enable email delivery" checked={draft.enabled} disabled={disabled} onChange={() => change({ enabled: !draft.enabled })} />
      </div>
      {!draft.enabled && <p className="rounded-md border border-warn/20 bg-warn/5 p-3 text-sm text-ink-body">Emails will not be sent. Share invitation links manually; email verification and password-reset delivery remain unavailable.</p>}
      <div className="grid min-w-0 gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Field label="SMTP server"><Input aria-label="SMTP server" autoComplete="off" value={draft.host} onChange={event => change({ host: event.target.value })} disabled={disabled || !draft.enabled} required={draft.enabled} placeholder="smtp.example.com" maxLength={253} /></Field>
        <Field label="Port"><Input aria-label="SMTP port" type="number" min={1} max={65535} value={draft.port} onChange={event => change({ port: Number(event.target.value) })} disabled={disabled || !draft.enabled} required={draft.enabled} /></Field>
      </div>
      <p className="text-xs text-ink-tertiary">Encrypted STARTTLS is required, usually on port 587. Implicit TLS on port 465 is not supported.</p>
      <div className="grid min-w-0 gap-4 md:grid-cols-2">
        <Field label="Sender email"><Input aria-label="Sender email" type="email" value={draft.from} onChange={event => change({ from: event.target.value })} disabled={disabled || !draft.enabled} required={draft.enabled} placeholder="no-reply@example.com" maxLength={320} /></Field>
        <Field label="Username (optional)"><Input aria-label="SMTP username" autoComplete="off" value={draft.username} onChange={event => change({ username: event.target.value })} disabled={disabled || !draft.enabled} maxLength={320} /></Field>
      </div>
      <div className="grid min-w-0 gap-4 md:grid-cols-2">
        <Field label="Password"><Select aria-label="Password action" value={draft.password_action} disabled={disabled || !draft.enabled} onChange={event => change({ password_action: event.target.value as ServerEmailSettingsInput["password_action"], password: undefined })}>
          <option value="keep">{view.password_configured ? "Keep saved password" : "No saved password"}</option><option value="replace">Set a new password</option><option value="clear">Clear saved password</option>
        </Select></Field>
        {draft.password_action === "replace" && <Field label="New password"><Input aria-label="New SMTP password" type="password" autoComplete="new-password" value={draft.password ?? ""} onChange={event => change({ password: event.target.value })} required={draft.enabled} disabled={disabled || !draft.enabled} maxLength={4096} /></Field>}
      </div>
      <p className="text-xs text-ink-tertiary">Saved passwords are never displayed. Replace or clear the password when changing the server or username.</p>
      <ErrorText>{error}</ErrorText>
      {result && <p role="status" className="rounded-md border border-line bg-surface-inset p-3 text-sm text-ink-body">{result}</p>}
      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-5">
        <Button type="submit" disabled={disabled || !changed}>{busy === "save" ? "Saving…" : "Save changes"}</Button>
        <Button type="button" variant="ghost" disabled={disabled || !draft.enabled} onClick={() => void submit("test")}>{busy === "test" ? "Sending test…" : "Send test email"}</Button>
        <Button type="button" variant="ghost" disabled={disabled} onClick={() => setAttempt(value => value + 1)}>Reload saved settings</Button>
      </div>
      <p className="break-words text-xs text-ink-tertiary">The test uses this form and sends only to {email}. It does not save changes. Provider acceptance does not guarantee inbox delivery.</p>
    </form>
  </div>;
}
