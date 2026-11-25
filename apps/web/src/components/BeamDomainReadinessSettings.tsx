import "../beam-workspace.css";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Button, ErrorText, Field, Input, Loading, Modal } from "./ui";
import { ResourceSummary } from "./ResourceSummary";
import { beamApi, type BeamReadiness, type BeamDomainSettings } from "../lib/beam";

const labels: Record<string, string> = { configuration: "Configuration and domain boundary", wildcard_dns: "Wildcard DNS", wildcard_tls: "Serving HTTPS certificate", unknown_host_denied: "Unallocated hostname denial", connector_tls: "Connector endpoint TLS" };
// LS-UX-1: what to fix when a check fails, in the operator's terms.
const fixes: Record<string, string> = {
  configuration: "Use a sharing domain that is either exactly the console host or a different registrable domain (not a sibling such as share.<console domain>), separate from any App Access domain, and an https:// connector URL with no path.",
  wildcard_dns: "Create a wildcard DNS record (*.<sharing domain>) pointing to the public address of the Local Sharing proxy's browser listener (TUNNEX_BEAM_PUBLIC_BIND_IP). Private and loopback addresses do not pass.",
  wildcard_tls: "Install a trusted certificate whose names include exactly *.<sharing domain> on the Local Sharing proxy (public-cert.pem / public-key.pem), restart the proxy, and make sure port 443 reaches it.",
  unknown_host_denied: "Port 443 on the wildcard address must be served by the Local Sharing proxy, which refuses unknown hostnames. If Caddy or App Access answers there instead, give Local Sharing its own address.",
  connector_tls: "Start the Local Sharing proxy with the connector certificate from backupctl beam-proxy-certificate, and open the connector URL's port to publishers' computers.",
};
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
      else { setConfirm(false); setNotice("Serving configuration saved. Next, select Check DNS and TLS. Publishing starts once every check passes and an organization turns Local Sharing on."); setReload(value => value + 1); }
    } finally { locked.current = false; if (alive.current) setBusy(null); }
  }
  if (loading) return <Loading label="Loading serving configuration…" />;
  if (!view || !saved) return <div className="space-y-3"><ErrorText>{error}</ErrorText><Button onClick={() => setReload(value => value + 1)}>Retry serving configuration</Button></div>;
  const fresh = !!view.expires_at && Date.parse(view.expires_at) > now;
  const status = !view.checked_at ? "Not checked" : !fresh ? "Check expired. Run it again." : view.passed ? "All checks passed" : "Some checks failed";
  const disabled = !canEdit || busy !== null || uncertain;
  return <div className="beam-policy-settings space-y-5">
    <div className="space-y-2"><h3 className="font-semibold">Sharing domain and checks</h3><p className="text-sm text-ink-secondary">These settings apply to every organization on this server. The check is run from the control plane against your real DNS and certificates.</p><p role="status">{status}</p><p className="text-sm">Local Sharing is {saved.operator_enabled ? "allowed" : "not allowed"} on this server. Publishing: {saved.authority_ready ? "available" : "not available until every check passes"}.</p>
      <details className="rounded-md border border-line p-3 text-sm" open={!view.checked_at}><summary className="cursor-pointer font-medium">Setup checklist</summary><ol className="list-decimal pl-5 space-y-1 pt-2 text-ink-secondary"><li><strong>Domain:</strong> a registrable domain of its own (for example <code>share-example.dev</code>), not under the console's domain and not the App Access domain.</li><li><strong>Address:</strong> a public IPv4 address for port 443 that Caddy and App Access do not already use.</li><li><strong>DNS:</strong> <code>*.</code>your sharing domain → that address.</li><li><strong>Certificate:</strong> a trusted certificate for <code>*.</code>your sharing domain.</li><li><strong>Firewall:</strong> TCP 443 to that address from reviewers; the connector port (for example 8447) from publishers.</li><li><strong>Server:</strong> on the host, follow "Install (managed layout)" in <code>deploy/beam/README.md</code>. It installs the managed overlay, pins the signed proxy image, issues the proxy credential and connector certificate, and starts the proxy. The one-command upgrade keeps it up to date.</li><li><strong>Here:</strong> enter the domain and connector URL, allow Local Sharing, save, then select <strong>Check DNS and TLS</strong>. A failed check says what to fix.</li></ol></details></div>
    <form onSubmit={review} className="space-y-4">
      <label className="flex items-center gap-3"><input type="checkbox" disabled={disabled} checked={enabled} onChange={event => setEnabled(event.target.checked)} /><span className="text-sm font-medium">Allow Local Sharing on this installation</span></label>
      <div className="grid gap-4 md:grid-cols-2"><Field label="Sharing domain"><Input required maxLength={218} disabled={disabled} value={base} placeholder="sharing.example.net" onChange={event => setBase(event.target.value)} /></Field><Field label="Connector endpoint"><Input required type="url" maxLength={2048} disabled={disabled} value={proxy} placeholder="https://connector.example.net:8443" onChange={event => setProxy(event.target.value)} /></Field></div>
      <p className="text-sm text-ink-secondary">Sharing domain: a public DNS name of its own, for example <code>share-example.net</code>. Connector endpoint: the <code>https://</code> address and port publishers' computers use to reach the proxy, without a path.</p>
      <ResourceSummary title="Installation settings"><dl className="tnx-resource-facts"><div><dt>Control-plane portal (read-only)</dt><dd>{saved.portal_url || "Not configured"}</dd></div><div><dt>Saved configuration</dt><dd>Version {saved.version} · {saved.source === "database" ? "Saved on this server" : "Pre-filled from server settings; not saved yet"}</dd></div></dl></ResourceSummary>
      <p className="text-sm text-ink-secondary">The portal comes from <code>APP_BASE_URL</code>. <code>TUNNEX_BEAM_BASE_DOMAIN</code> and <code>TUNNEX_BEAM_PROXY_URL</code> only pre-fill this form; nothing is served until it is saved here and every check passes. Changing the domain or connector, or turning Local Sharing off, ends current shares in every organization.</p>
      <Button type="submit" disabled={disabled || !changed}>Review serving changes</Button>
    </form>
    <ResourceSummary title="Checks" className="beam-readiness-summary"><div className="space-y-4"><dl className="tnx-resource-facts"><div><dt>Last measured</dt><dd>{view.checked_at ? new Date(view.checked_at).toLocaleString() : "No evidence recorded"}</dd></div></dl>
      {view.checks.length > 0 && <ul className="beam-readiness-results" aria-label="Serving checks">{view.checks.map(item => <li key={item.name}><p className="font-medium">{labels[item.name] ?? "Other check"}: {item.passed ? (fresh ? "Passed" : "Previously passed; expired") : "Needs repair"}</p><p className="text-sm text-ink-secondary">{item.detail}</p>{!item.passed && fixes[item.name] && <p className="text-sm">How to fix: {fixes[item.name]}</p>}</li>)}</ul>}
      <p className="text-sm text-ink-secondary">A passed check counts for five minutes at most (never past the certificate's expiry). The server re-runs it every minute while Local Sharing is allowed, so publishing keeps working while DNS and certificates stay correct. If a check fails, publishing and reviewer access stop until it passes again.</p>
      {changed && <p className="text-sm">Save or reload your serving edits before checking endpoints.</p>}
      <div className="flex flex-wrap gap-3"><Button disabled={disabled || changed} onClick={() => void check()}>{busy === "check" ? "Checking endpoints…" : "Check DNS and TLS"}</Button><Button variant="ghost" disabled={busy !== null} onClick={() => { setNotice(""); setReload(value => value + 1); }}>Reload serving configuration</Button></div>
    </div></ResourceSummary>
    <ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}{!canEdit && <p className="text-sm text-warn">Verify your email and complete initial password setup before changing installation settings.</p>}
    {confirm && <Modal title="Review serving change" danger={saved.affected_active_shares > 0} onDismiss={() => { if (!busy) setConfirm(false); }} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setConfirm(false)}>Keep current setup</Button><Button variant={saved.affected_active_shares > 0 ? "danger" : "primary"} disabled={disabled || (saved.affected_active_shares > 0 && !endShares)} onClick={() => void save()}>{busy === "save" ? "Saving…" : "Save serving configuration"}</Button></>}>
      <div className="space-y-4 text-sm"><p>Apply this installation-wide configuration?</p><dl className="space-y-2"><div><dt className="font-medium">Serving domain</dt><dd className="break-all">{base.trim()}</dd></div><div><dt className="font-medium">Connector endpoint</dt><dd className="break-all">{proxy.trim()}</dd></div><div><dt className="font-medium">Operator permission</dt><dd>{enabled ? "Allow serving after successful checks" : "Disable serving"}</dd></div></dl><p>Last read: {saved.affected_active_shares} active shares across all organizations. Saving ends every active share; their links can't be reopened or reused. Publishing starts again once every check passes.</p>{saved.affected_active_shares > 0 && <label className="flex items-start gap-3"><input type="checkbox" disabled={busy !== null} checked={endShares} onChange={event => setEndShares(event.target.checked)} /><span>End all active shares affected by this configuration change</span></label>}</div>
    </Modal>}
  </div>;
}
