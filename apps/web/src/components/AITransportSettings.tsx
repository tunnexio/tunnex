import { useEffect, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Loading, Switch } from "./ui";
import "./ai-gateway-access.css";

type TransportSettings = components["schemas"]["AITransportSettings"];
const endpoint = "/api/v1/admin/ai-transport-settings" as const;

export function AITransportSettings({ canEdit }: { canEdit: boolean }) {
  const [saved, setSaved] = useState<TransportSettings | null>(null);
  const [allowHttp, setAllowHttp] = useState(false);
  const [busy, setBusy] = useState<"load" | "save" | null>("load");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [needsReload, setNeedsReload] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(false);
  const locked = useRef(false);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);
  useEffect(() => {
    let current = true;
    setBusy("load"); setError(null); setResult(null); setSaved(null); setNeedsReload(false);
    void api.GET(endpoint).then(({ data, error }) => {
      if (!current) return;
      if (error || !data) setError(apiErrorMessage(error, "Could not load AI Gateway transport settings."));
      else { setSaved(data); setAllowHttp(data.allow_http); }
    }).catch(() => {
      if (current) setError("Could not reach the server. Try again.");
    }).finally(() => { if (current) setBusy(null); });
    return () => { current = false; };
  }, [attempt]);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!saved || !canEdit || busy || locked.current || needsReload || allowHttp === saved.allow_http) return;
    locked.current = true; setBusy("save"); setError(null); setResult(null);
    try {
      const response = await api.PUT(endpoint, { body: { allow_http: allowHttp, revision: saved.revision } });
      if (!alive.current) return;
      if (response.error || !response.data) {
        if (response.response?.status === 409) {
          setNeedsReload(true);
          setError("These settings changed on the server. Reload saved settings before trying again.");
        } else setError(apiErrorMessage(response.error, "Could not save AI Gateway transport settings."));
      } else {
        setSaved(response.data); setAllowHttp(response.data.allow_http);
        setResult(response.data.allow_http
          ? "HTTP access is allowed. Open AI Gateway to continue setup. HTTPS remains available."
          : "HTTP access is blocked. Use HTTPS for AI Gateway.");
      }
    } catch {
      if (alive.current) {
        setNeedsReload(true);
        setError("The response was interrupted. Reload saved settings to check whether the change was saved.");
      }
    } finally {
      locked.current = false;
      if (alive.current) setBusy(null);
    }
  }

  if (busy === "load") return <Loading label="Loading AI Gateway transport settings…" />;
  if (!saved) return <div className="space-y-3"><ErrorText>{error}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry transport settings</Button></div>;
  const disabled = !canEdit || busy !== null || needsReload;
  return <div className="ai-transport-settings space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line pb-5">
      <div className="space-y-1"><h3 className="text-sm font-semibold text-ink-heading">AI Gateway transport for this server</h3>
        <p className="text-sm text-ink-secondary">Applies to every organization. HTTPS is required by default.</p></div>
      <span className="ai-transport-saved">Saved policy: {saved.allow_http ? "HTTP allowed" : "HTTPS required"}</span>
    </div>
    {!canEdit && <p className="text-sm text-warn">Verify your email and change your initial password to edit server settings.</p>}
    <form onSubmit={event => void save(event)} className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><p className="text-sm font-medium text-ink-heading">Allow AI Gateway over HTTP</p>
          <p className="text-xs text-ink-secondary">Permit AI setup and model requests on HTTP endpoints, including public endpoints. Changes take effect when you save.</p></div>
        <Switch label="Allow AI Gateway over HTTP" checked={allowHttp} disabled={disabled} onChange={value => { setAllowHttp(value); setError(null); setResult(null); }} />
      </div>
      <p className="ai-transport-risk">HTTP does not encrypt credentials or requests. Anyone on the network path may read or change them. Use HTTPS whenever possible.</p>
      <p className="text-sm text-ink-secondary">Provider credentials, organization access, and model grants remain separate. Changing this policy preserves saved credentials and keeps HTTPS available.</p>
      <ErrorText>{error}</ErrorText>
      {result && <p role="status" className="rounded-md border border-line bg-surface-inset p-3 text-sm text-ink-body">{result}</p>}
      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-5">
        <Button type="submit" disabled={disabled || allowHttp === saved.allow_http}>{busy === "save" ? "Saving…" : "Save changes"}</Button>
        <Button type="button" variant="ghost" disabled={busy !== null} onClick={() => setAttempt(value => value + 1)}>Reload saved settings</Button>
      </div>
    </form>
  </div>;
}
