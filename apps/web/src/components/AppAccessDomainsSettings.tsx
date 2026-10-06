import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading } from "./ui";

type Domains = components["schemas"]["AppAccessDomains"];
const endpoint = "/api/v1/admin/app-access/domains" as const;

export function AppAccessDomainsSettings({ canEdit }: { canEdit: boolean }) {
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
  return <div className="space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line pb-5">
      <div className="space-y-1"><h3 className="text-sm font-semibold text-ink-heading">Browser addresses for this server</h3>
        <p className="text-sm text-ink-secondary">Shared by every organization. Configure the sign-in portal and the domain used for new private web apps.</p></div>
      <span className="rounded-md border border-line px-2.5 py-1 text-xs text-ink-secondary">Source: {saved.source === "database" ? "Saved settings" : "Server environment"}</span>
    </div>
    {!canEdit && <p className="text-sm text-warn">Verify your email and change your initial password to edit server settings.</p>}
    <form onSubmit={event => void save(event)} className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-2">
        <div className="space-y-2"><Field label="Portal URL"><Input type="url" required maxLength={2048} placeholder="https://internal.tunnex.app" value={portal} disabled={disabled} aria-describedby={portalHint} onChange={event => { setPortal(event.target.value); setResult(null); }} /></Field>
          <p id={portalHint} className="text-xs text-ink-secondary">The HTTPS address users return to for Tunnex sign-in, without a path. An HTTPS IP address can be used for control-plane access.</p></div>
        <div className="space-y-2"><Field label="Application base domain"><Input required maxLength={253} placeholder="internal.tunnex.app" value={base} disabled={disabled} aria-describedby={baseHint} onChange={event => { setBase(event.target.value); setResult(null); }} /></Field>
          <p id={baseHint} className="text-xs text-ink-secondary">A public DNS hostname only, without https://, a port or a path. Private apps need hostname-based addresses; an IP address cannot be the application domain.</p></div>
      </div>
      <div className="rounded-md border border-line bg-surface-inset p-4 text-sm text-ink-secondary space-y-2">
        <p className="break-all">{validPreview ? <>With application prefix <strong className="text-ink-heading">test</strong>, the address will be <span className="font-mono text-ink-heading">https://test.{previewBase}</span>.</> : "Example: portal https://internal.tunnex.app and application domain internal.tunnex.app create https://test.internal.tunnex.app for prefix test."}</p>
        <p>Use the portal hostname as the application base domain, or use independently registered domains for the portal and apps.</p>
      </div>
      <div className="space-y-2 text-sm text-ink-secondary">
        <p className="font-medium text-ink-heading">One-time DNS and HTTPS setup</p>
        <p>Your organization manages DNS and TLS. Point the portal hostname to your control plane and wildcard application DNS to your Applications proxy. Configure TLS certificates covering the portal and wildcard application hostnames on their HTTPS listeners. Saving here does not create DNS records or issue certificates.</p>
        <p>When changing the portal URL, update the registered redirect URLs in your SSO identity providers to match the new portal before users sign in. Tunnex does not update those registrations automatically.</p>
        <p>Saved settings apply to new application addresses. Existing application hostnames stay unchanged; keep their DNS and TLS coverage available.</p>
        <p>Saved configuration: {saved.configuration_ready ? "format accepted" : "configuration incomplete"}. DNS, certificates and reachability have not been checked here.</p>
      </div>
      <ErrorText>{error}</ErrorText>
      {result && <p role="status" className="rounded-md border border-line bg-surface-inset p-3 text-sm text-ink-body">{result}</p>}
      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-5">
        <Button type="submit" disabled={disabled || needsReload || !changed || !portal.trim() || !base.trim()}>{busy === "save" ? "Saving…" : "Save changes"}</Button>
        <Button type="button" variant="ghost" disabled={busy !== null} onClick={() => setAttempt(value => value + 1)}>{busy === "load" ? "Reloading…" : "Reload saved settings"}</Button>
      </div>
    </form>
  </div>;
}
