import "../beam-workspace.css";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Button, ErrorText, Field, Input, Loading, Modal } from "./ui";
import { beamApi, type BeamReadiness, type BeamDomainSettings } from "../lib/beam";

const labels: Record<string, string> = { configuration: "Configuration and domain boundary", wildcard_dns: "Wildcard DNS", wildcard_tls: "Serving HTTPS certificate", unknown_host_denied: "Unallocated hostname denial", connector_tls: "Connector endpoint TLS" };
export function BeamDomainReadinessSettings({ canEdit }: { canEdit: boolean }) {
  const [view, setView] = useState<BeamReadiness | null>(null); const [saved, setSaved] = useState<BeamDomainSettings | null>(null);
  const [base, setBase] = useState(""); const [proxy, setProxy] = useState(""); const [enabled, setEnabled] = useState(false);
  const [error, setError] = useState(""); const [notice, setNotice] = useState(""); const [loading, setLoading] = useState(true); const [busy, setBusy] = useState<"save" | "check" | null>(null); const [uncertain, setUncertain] = useState(false); const [reload, setReload] = useState(0); const [now, setNow] = useState(Date.now()); const [confirm, setConfirm] = useState(false); const [endShares, setEndShares] = useState(false); const alive = useRef(true); const locked = useRef(false);
  useEffect(() => { alive.current = true; const clock = setInterval(() => setNow(Date.now()), 1000); return () => { alive.current = false; clearInterval(clock); }; }, []);
  useEffect(() => { let current = true; setLoading(true); setError(""); setView(null); setSaved(null); void Promise.all([beamApi.domainSettings(), beamApi.readiness()]).then(([settings, readiness]) => {
    if (!current) return;
    if (!settings.ok || !readiness.ok) { setError(!settings.ok ? settings.error : !readiness.ok ? readiness.error : "Could not load serving setup."); setLoading(false); return; }
    setSaved(settings.data); setBase(settings.data.base_domain); setProxy(settings.data.proxy_url); setEnabled(settings.data.operator_enabled); setView(readiness.data);
    const mismatch = settings.data.version !== readiness.data.settings_version; setUncertain(mismatch); if (mismatch) setError("Serving settings changed while loading. Reload before checking or saving."); setLoading(false);
  }); return () => { current = false; }; }, [reload]);
  const changed = !!saved && (base.trim() !== saved.base_domain || proxy.trim() !== saved.proxy_url || enabled !== saved.operator_enabled);
  async function check() { if (!view || !saved || !canEdit || locked.current || uncertain || changed) return; locked.current = true; setBusy("check"); setError(""); setNotice(""); try {
    const result = await beamApi.checkReadiness(view.configuration_version); if (!alive.current) return;
    if (result.ok && result.data.settings_version === saved.version) { setView(result.data); setNow(Date.now()); }
    else { setUncertain(true); setError(`${result.ok ? "Serving settings changed during the check." : result.error} Reload serving configuration before another check.`); }
  } finally { locked.current = false; if (alive.current) setBusy(null); } }
  function review(event: FormEvent) { event.preventDefault(); if (!saved || !canEdit || busy || uncertain || !changed) return; setEndShares(false); setConfirm(true); }
  async function save() { if (!saved || !canEdit || locked.current || uncertain || !changed || (saved.affected_active_shares > 0 && !endShares)) return;
    locked.current = true; setBusy("save"); setError(""); setNotice("");
    try { const result = await beamApi.saveDomainSettings({ expected_version: saved.version, operator_enabled: enabled, base_domain: base.trim(), proxy_url: proxy.trim(), confirm_end_active_shares: endShares }); if (!alive.current) return;
      if (!result.ok) { setUncertain(true); setConfirm(false); setError(`${result.error} Your edits are still shown. Reload saved configuration before another change; reloading replaces your edits.`); }
      else { setConfirm(false); setNotice("Serving configuration saved. Changed authority was withdrawn; ended share links cannot be resumed. Publication requires current independent checks and organization policy."); setReload(value => value + 1); }
    } finally { locked.current = false; if (alive.current) setBusy(null); }
  }
  if (loading) return <Loading label="Loading serving configuration…" />;
  if (!view || !saved) return <div className="space-y-3"><ErrorText>{error}</ErrorText><Button onClick={() => setReload(value => value + 1)}>Retry serving configuration</Button></div>;
  const fresh = !!view.expires_at && Date.parse(view.expires_at) > now;
  const status = !view.checked_at ? "Not checked" : !fresh ? "Check expired" : view.passed ? "Measured checks passed" : "Setup needs repair";
  const disabled = !canEdit || busy !== null || uncertain;
  return <div className="beam-policy-settings space-y-5">
    <div className="space-y-2"><h3 className="font-semibold">Configured endpoints and independent checks</h3><p className="text-sm text-ink-secondary">Installation settings apply to every organization. This check measures DNS, trusted HTTPS and exact-host denial from the control plane.</p><p role="status">{status}</p><p className="text-sm">Serving is {saved.operator_enabled ? "allowed by the operator" : "disabled by the operator"}. Authority at last read: {saved.authority_ready ? "available" : "unavailable"}.</p></div>
    <form onSubmit={review} className="space-y-4">
      <label className="flex items-center gap-3"><input type="checkbox" disabled={disabled} checked={enabled} onChange={event => setEnabled(event.target.checked)} /><span className="text-sm font-medium">Allow Local Sharing on this installation</span></label>
      <div className="grid gap-4 md:grid-cols-2"><Field label="Sharing domain"><Input required maxLength={218} disabled={disabled} value={base} placeholder="sharing.example.net" onChange={event => setBase(event.target.value)} /></Field><Field label="Connector endpoint"><Input required type="url" maxLength={2048} disabled={disabled} value={proxy} placeholder="https://connector.example.net:8443" onChange={event => setProxy(event.target.value)} /></Field></div>
      <p className="text-sm text-ink-secondary">Use a dedicated public DNS serving domain and an HTTPS connector URL without credentials, a path, query or fragment. Configure wildcard DNS and trusted serving certificates before checking. The connector uses the installation CA and its purpose-bound certificate.</p>
      <dl className="grid gap-4 md:grid-cols-2 text-sm"><div><dt className="font-medium">Control-plane portal (read-only)</dt><dd>{saved.portal_url || "Not configured"}</dd></div><div><dt className="font-medium">Saved configuration</dt><dd>Version {saved.version} · {saved.source === "database" ? "Shared installation registry" : "Environment seed; serving remains disabled until saved and checked"}</dd></div></dl>
      <p className="text-sm text-ink-secondary">The portal comes from <code>APP_BASE_URL</code>. <code>TUNNEX_BEAM_BASE_DOMAIN</code> and <code>TUNNEX_BEAM_PROXY_URL</code> seed initial values. An environment readiness assertion cannot bypass independent checks. Saving changed endpoints or disabling serving ends current shares across organizations; links are never retargeted.</p>
      <Button type="submit" disabled={disabled || !changed}>Review serving changes</Button>
    </form>
    <div className="border-t border-line pt-4 space-y-3"><p className="text-sm">Last measured: {view.checked_at ? new Date(view.checked_at).toLocaleString() : "No evidence recorded"}</p>
      {view.checks.length > 0 && <ul className="space-y-3" aria-label="Serving checks">{view.checks.map(item => <li key={item.name} className="rounded-md border border-line p-3 space-y-1"><p className="font-medium">{labels[item.name] ?? item.name}: {item.passed ? (fresh ? "Passed" : "Previously passed; expired") : "Needs repair"}</p><p className="text-sm text-ink-secondary">{item.detail}</p></li>)}</ul>}
      <p className="text-sm text-ink-secondary">Evidence lasts at most five minutes and never beyond the observed certificate expiry. The server refreshes checks in the background. Configuration withdrawal ends serving within the bounded authority lease; physical DNS or certificate changes are discovered on subsequent probes. Checks do not prove a reviewer browser session or cookie isolation.</p>
      {changed && <p className="text-sm">Save or reload your serving edits before checking endpoints.</p>}
      <div className="flex flex-wrap gap-3"><Button disabled={disabled || changed} onClick={() => void check()}>{busy === "check" ? "Checking endpoints…" : "Check DNS and TLS"}</Button><Button variant="ghost" disabled={busy !== null} onClick={() => { setNotice(""); setReload(value => value + 1); }}>Reload serving configuration</Button></div>
    </div>
    <ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}{!canEdit && <p className="text-sm text-warn">Verify your email and complete initial password setup before changing installation settings.</p>}
    {confirm && <Modal title="Review serving change" danger={saved.affected_active_shares > 0} onDismiss={() => { if (!busy) setConfirm(false); }} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setConfirm(false)}>Keep current setup</Button><Button variant={saved.affected_active_shares > 0 ? "danger" : "primary"} disabled={disabled || (saved.affected_active_shares > 0 && !endShares)} onClick={() => void save()}>{busy === "save" ? "Saving…" : "Save serving configuration"}</Button></>}>
      <div className="space-y-4 text-sm"><p>Apply this installation-wide configuration?</p><dl className="space-y-2"><div><dt className="font-medium">Serving domain</dt><dd className="break-all">{base.trim()}</dd></div><div><dt className="font-medium">Connector endpoint</dt><dd className="break-all">{proxy.trim()}</dd></div><div><dt className="font-medium">Operator permission</dt><dd>{enabled ? "Allow serving after successful checks" : "Disable serving"}</dd></div></dl><p>Last read: {saved.affected_active_shares} active shares across all organizations. Changed serving authority permanently ends active shares. New shares created since that read may also be affected. New publication waits for current independent checks; ended URLs are never reassigned.</p>{saved.affected_active_shares > 0 && <label className="flex items-start gap-3"><input type="checkbox" disabled={busy !== null} checked={endShares} onChange={event => setEndShares(event.target.checked)} /><span>End all active shares affected by this configuration change</span></label>}</div>
    </Modal>}
  </div>;
}
