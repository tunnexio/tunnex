import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Field, Input } from "./ui";

type Profile = components["schemas"]["ConnectivityProfile"];

// Mount with key=orgId: neither secret input nor a delayed save can cross orgs.
export function RelayFallbackSettings({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    setError(null); setProfile(null); setSecret(""); setSaved(false);
    void api.GET("/api/v1/organizations/{orgId}/connectivity-profile", { params: { path: { orgId } } })
      .then(({ data, error }) => {
        if (!active) return;
        if (error || !data) { setError("Could not load relay configuration."); return; }
        setProfile(data); setUrl(data.relay_url); setEnabled(data.enabled);
      }).catch(() => { if (active) setError("Could not load relay configuration."); });
    return () => { active = false; };
  }, [orgId, retry]);

  async function save(clear = false) {
    if (!profile || !canEdit || busy) return;
    setBusy(true); setError(null); setSaved(false);
    try {
      const { data, error } = await api.PUT("/api/v1/organizations/{orgId}/connectivity-profile", {
        params: { path: { orgId } },
        body: { enabled: clear ? false : enabled, relay_url: clear ? "" : url.trim(),
          shared_secret: clear ? undefined : secret || undefined, clear_secret: clear, expected_revision: profile.revision },
      });
      if (error || !data) { setProfile(null); setError("Could not save. Reload the current configuration before retrying. Check the TLS relay URL and secret if the problem persists."); return; }
      setProfile(data); setUrl(data.relay_url); setEnabled(data.enabled); setSecret(""); setSaved(true);
    } catch { setProfile(null); setError("Could not reach the control plane. Reload to confirm the saved state before retrying."); }
    finally { setSecret(""); setBusy(false); }
  }

  return <section aria-labelledby="relay-fallback-heading" className="space-y-3 py-4">
    <h3 id="relay-fallback-heading" className="font-semibold text-ink-heading">Relay fallback</h3>
    <p className="text-sm text-ink-secondary">Use a customer-hosted relay when a direct connection is unavailable. Requires a relay-capable gateway and client. Existing application access rules still apply.</p>
    <details className="text-sm text-ink-secondary">
      <summary className="cursor-pointer">Setup and verification</summary>
      <ol className="list-decimal space-y-2 pl-5 pt-2">
        <li>Run coturn on a host reachable by both the gateway and employees. Configure a DNS name and a valid TLS certificate for that name.</li>
        <li>Allow the configured TCP TLS listener and coturn’s configured UDP relay-port range through the host and cloud firewalls. Restrict relay peers and set allocation and bandwidth limits; do not run an anonymous open relay.</li>
        <li>Configure coturn shared-secret authentication. Store the same randomly generated secret here; do not share it with employees. Enter the TLS relay URL, then enable and save fallback.</li>
        <li>Connect with a relay-capable desktop client in split-tunnel mode. With direct UDP blocked in a test environment, confirm the client reports Relay, an allowed application opens and a denied application remains blocked.</li>
      </ol>
      <p className="pt-2">Full-tunnel relay is not supported by this candidate. Saving does not test reachability or certify gateway readiness. A successful connection on one network does not prove relay access on every network.</p>
      <p className="pt-2">To rotate the secret, coordinate the coturn change with this saved configuration and reconnect affected clients. Session invalidation can interrupt active relay connections. Removing this configuration does not stop coturn or remove its secret from the relay host.</p>
    </details>
    {!profile ? <p role="status">{error ? "Configuration unavailable." : "Loading relay configuration…"}</p> : <>
      <p className="text-sm">Saved configuration: {profile.enabled ? "Enabled" : "Off"}. This is configuration status, not a connectivity test.</p>
      <Field label="TLS relay URL"><Input aria-label="TLS relay URL" value={url} onChange={e => { setUrl(e.target.value); setSaved(false); }} disabled={!canEdit || busy} placeholder="turns:relay.company.com:5349?transport=tcp" /></Field>
      <Field label="Relay shared secret"><Input aria-label="Relay shared secret" type="password" autoComplete="new-password" value={secret} onChange={e => { setSecret(e.target.value); setSaved(false); }} disabled={!canEdit || busy} placeholder={profile.secret_configured ? "Configured — leave blank to keep" : "At least 32 bytes; use a randomly generated secret"} /></Field>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} disabled={!canEdit || busy} onChange={e => { setEnabled(e.target.checked); setSaved(false); }} />Enable automatic relay fallback</label>
      <p className="text-xs text-ink-secondary">Saving changes invalidates current negotiation sessions. Removing configuration disables fallback and clears the stored secret.</p>
      <div className="flex gap-2"><Button disabled={!canEdit || busy} onClick={() => void save()}>{busy ? "Saving…" : "Save relay"}</Button><Button disabled={!canEdit || busy || (!profile.secret_configured && !profile.relay_url)} onClick={() => { if (window.confirm("Disable relay fallback and remove its stored secret?")) void save(true); }}>Remove configuration</Button></div>
    </>}
    {error && <div role="alert">{error} <Button disabled={busy} onClick={() => { setSecret(""); setRetry(n => n + 1); }}>Reload</Button></div>}
    {saved && <p role="status">Relay configuration saved.</p>}
  </section>;
}
