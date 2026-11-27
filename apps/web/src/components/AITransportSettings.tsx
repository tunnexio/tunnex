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
  const [allowVpnHttp, setAllowVpnHttp] = useState(false);
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
      else { setSaved(data); setAllowHttp(data.allow_http); setAllowVpnHttp(data.allow_vpn_http); }
    }).catch(() => {
      if (current) setError("Could not reach the server. Try again.");
    }).finally(() => { if (current) setBusy(null); });
    return () => { current = false; };
  }, [attempt]);

  const changed = !!saved && (allowHttp !== saved.allow_http || allowVpnHttp !== saved.allow_vpn_http);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!saved || !canEdit || busy || locked.current || needsReload || !changed) return;
    locked.current = true; setBusy("save"); setError(null); setResult(null);
    try {
      const response = await api.PUT(endpoint, { body: { allow_http: allowHttp, allow_vpn_http: allowVpnHttp, revision: saved.revision } });
      if (!alive.current) return;
      if (response.error || !response.data) {
        if (response.response?.status === 409) {
          setNeedsReload(true);
          setError("These settings changed on the server. Reload saved settings before trying again.");
        } else setError(apiErrorMessage(response.error, "Could not save AI Gateway transport settings."));
      } else {
        setSaved(response.data); setAllowHttp(response.data.allow_http); setAllowVpnHttp(response.data.allow_vpn_http);
        setResult(`Saved. Inside the VPN: HTTP is ${response.data.allow_vpn_http ? "allowed" : "blocked"}. Public internet: HTTP is ${response.data.allow_http ? "allowed" : "blocked"}. HTTPS always works.`);
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
  const edit = (apply: () => void) => { apply(); setError(null); setResult(null); };
  return <div className="ai-transport-settings space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line pb-5">
      <div className="space-y-1"><h3 className="text-sm font-semibold text-ink-heading">AI Gateway transport for this server</h3>
        <p className="text-sm text-ink-secondary">Applies to every organization. HTTPS always works and is not affected by these switches. They only decide where plain HTTP is accepted.</p></div>
      <span className="ai-transport-saved">Saved policy: Inside the VPN {saved.allow_vpn_http ? "on" : "off"} · Public internet {saved.allow_http ? "on" : "off"}</span>
    </div>
    {!canEdit && <p className="text-sm text-warn">Verify your email and change your initial password to edit server settings.</p>}
    <form onSubmit={event => void save(event)} className="space-y-5">
      <div role="group" aria-labelledby="ai-transport-vpn" className="flex flex-wrap items-center justify-between gap-3">
        <div className="ai-transport-choice"><p className="text-sm font-medium text-ink-heading"><span id="ai-transport-vpn">Inside the VPN</span> <span className="ai-transport-tag">Recommended</span></p>
          <p className="text-xs text-ink-secondary">Lets people and agents connected to the VPN reach their models at the gateway's VPN address. Requests travel inside the encrypted VPN tunnel. This does not open anything on the public internet.</p>
          <p className="text-xs text-ink-secondary">If you turn this off, members cannot use models over the VPN unless a private HTTPS address is set up for the gateway.</p></div>
        <Switch label="Allow HTTP inside the VPN" checked={allowVpnHttp} disabled={disabled} onChange={value => edit(() => setAllowVpnHttp(value))} />
      </div>
      <div role="group" aria-labelledby="ai-transport-public" className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-5">
        <div className="ai-transport-choice"><p id="ai-transport-public" className="text-sm font-medium text-ink-heading">Public internet</p>
          <p className="text-xs text-ink-secondary">Lets AI setup and model requests use plain HTTP on this server's public address. Keep this off unless this server cannot use HTTPS.</p>
          <p className="ai-transport-risk text-warn">Warning: with this on, provider keys and access tokens travel unencrypted. Anyone on the network path can read or change them.</p></div>
        <Switch label="Allow HTTP on the public internet" checked={allowHttp} disabled={disabled} onChange={value => edit(() => setAllowHttp(value))} />
      </div>
      <p className="text-sm text-ink-secondary">The two switches are independent. Changes take effect when you save and keep saved provider credentials, organization access and model grants as they are.</p>
      <ErrorText>{error}</ErrorText>
      {result && <p role="status" className="rounded-md border border-line bg-surface-inset p-3 text-sm text-ink-body">{result}</p>}
      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-5">
        <Button type="submit" disabled={disabled || !changed}>{busy === "save" ? "Saving…" : "Save changes"}</Button>
        <Button type="button" variant="ghost" disabled={busy !== null} onClick={() => setAttempt(value => value + 1)}>Reload saved settings</Button>
      </div>
    </form>
  </div>;
}
