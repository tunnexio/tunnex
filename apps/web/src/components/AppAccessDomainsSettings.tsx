import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading } from "./ui";
import "../app-access-workspace.css";

type Domains = components["schemas"]["AppAccessDomains"];
const endpoint = "/api/v1/admin/app-access/domains" as const;

export function AppAccessDomainsSettings({ canEdit, onSaved, onSavingChange }: { canEdit: boolean; onSaved?: () => void; onSavingChange?: (saving: boolean) => void }) {
  const [saved, setSaved] = useState<Domains | null>(null);
  const [portal, setPortal] = useState("");
  const [base, setBase] = useState("");
  const [busy, setBusy] = useState<"load" | "save" | null>("load");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [needsReload, setNeedsReload] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(false);
  const locked = useRef(false);
  const portalHint = useId();
  const baseHint = useId();
  useEffect(() => { onSavingChange?.(busy === "save"); }, [busy, onSavingChange]);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);
  useEffect(() => {
    let current = true;
    setBusy("load"); setError(null); setResult(null);
    void api.GET(endpoint).then(({ data, error }) => {
      if (!current) return;
      if (error || !data) setError(apiErrorMessage(error, "Could not load Applications domains."));
      else {
        setSaved(data); setPortal(data.portal_url); setBase(data.app_base_domain);
        setNeedsReload(false);
      }
    }).catch(() => {
      if (current) setError("Could not reach the server. Your edits have been kept. Try reloading again.");
    }).finally(() => { if (current) setBusy(null); });
    return () => { current = false; };
  }, [attempt]);

  const changed = !!saved && (portal.trim() !== saved.portal_url || base.trim() !== saved.app_base_domain);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!saved || !canEdit || busy || locked.current || needsReload || !changed || !portal.trim() || !base.trim()) return;
    locked.current = true; setBusy("save"); setError(null); setResult(null);
    try {
      const response = await api.PATCH(endpoint, { body: { portal_url: portal.trim(), app_base_domain: base.trim(), expected_version: saved.version } });
      if (!alive.current) return;
      if (response.error || !response.data) {
        if (apiErrorCode(response.error) === "app_domains_changed") {
          setNeedsReload(true);
          setError("These settings changed on the server. Your edits are still shown. Reload saved settings before saving again; reloading will replace your edits.");
        } else setError(apiErrorMessage(response.error, "Could not save Applications domains."));
      } else {
        setSaved(response.data); setPortal(response.data.portal_url); setBase(response.data.app_base_domain);
        setResult("Applications domains saved. New application addresses use this domain. Existing application hostnames are preserved.");
        onSaved?.();
      }
    } catch {
      if (alive.current) {
        setNeedsReload(true);
        setError("The response was interrupted. Your edits are still shown. Reload saved settings to check whether the change was saved; reloading will replace your edits.");
      }
    } finally {
      locked.current = false;
      if (alive.current) setBusy(null);
    }
  }

  if (!saved && busy === "load") return <Loading label="Loading Applications domains…" />;
  if (!saved) return <div className="space-y-3"><ErrorText>{error}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry domain settings</Button></div>;
  const disabled = !canEdit || busy !== null;
  const previewBase = base.trim().toLowerCase();
  const validPreview = previewBase.length <= 248 && previewBase.split(".").length > 1 && previewBase.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) && /[a-z]/.test(previewBase.split(".").at(-1) ?? "");
  return <div className="aa-domain-settings">
    <div className="aa-domain-heading"><p>Shared by every organization on this server.</p><span>Source: {saved.source === "database" ? "Saved settings" : "Server environment"}</span></div>
    {!canEdit && <p className="aa-domain-notice">Verify your email and change your initial password to edit server settings.</p>}
    <form onSubmit={event => void save(event)} className="aa-domain-form">
      <div className="aa-domain-fields">
        <div><Field label="Portal URL"><Input type="url" required maxLength={2048} placeholder="https://console.example.com" value={portal} disabled={disabled} aria-describedby={portalHint} onChange={event => { setPortal(event.target.value); setResult(null); }} /></Field><p id={portalHint}>Tunnex sign-in address. HTTPS, without a path.</p></div>
        <div><Field label="Application base domain"><Input required maxLength={253} placeholder="apps.example.com" value={base} disabled={disabled} aria-describedby={baseHint} onChange={event => { setBase(event.target.value); setResult(null); }} /></Field><p id={baseHint}>A hostname, without https://, a port or a path.</p></div>
      </div>
      <div className="aa-domain-preview"><span>Example app address</span><p>{validPreview ? `https://test.${previewBase}` : "https://test.apps.example.com"}</p></div>
      <p className="aa-domain-notice">Saving here does not create DNS records or issue certificates.</p>
      {portal.trim() !== saved.portal_url && <p className="aa-domain-change-notice">Update your identity provider redirect URLs before using a new sign-in address.</p>}
      <ErrorText>{error}</ErrorText>
      {result && <p role="status" className="aa-domain-result">{result}</p>}
      <div className="aa-domain-actions"><Button type="button" variant="ghost" disabled={busy !== null} onClick={() => setAttempt(value => value + 1)}>{busy === "load" ? "Reloading…" : "Reload saved settings"}</Button><Button type="submit" disabled={disabled || needsReload || !changed || !portal.trim() || !base.trim()}>{busy === "save" ? "Saving…" : "Save changes"}</Button></div>
      <details className="aa-editor-disclosure"><summary>DNS &amp; HTTPS setup</summary><div className="aa-editor-disclosure-content aa-domain-guide">
        <p>Your organization manages DNS and TLS.</p>
        <ol><li><strong>Portal DNS</strong><span>Point the portal hostname to your control plane.</span></li><li><strong>App DNS</strong><span>Point *.{validPreview ? previewBase : "apps.example.com"} to your Applications proxy.</span></li><li><strong>HTTPS certificates</strong><span>Cover the portal and wildcard app hostnames on their HTTPS listeners.</span></li></ol>
        <p>When changing the portal URL, update the registered redirect URLs in your SSO identity providers to match the new portal before users sign in. Tunnex does not update those registrations automatically.</p>
        <p>Existing application hostnames stay unchanged. Keep their DNS and TLS coverage available.</p>
      </div></details>
      <details className="aa-editor-disclosure"><summary>Address requirements</summary><div className="aa-editor-disclosure-content aa-domain-guide"><p>An HTTPS IP address can be used for the sign-in portal. An IP address cannot be the application domain.</p><p>Use the portal hostname as the application base domain, or use independently registered domains for the portal and apps.</p><p>Saved configuration: {saved.configuration_ready ? "format accepted" : "configuration incomplete"}. DNS, certificates and reachability have not been checked here.</p></div></details>
    </form>
  </div>;
}
