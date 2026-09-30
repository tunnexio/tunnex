import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Button } from "./ui";

export const CLIENT_DOWNLOAD_URL = "https://tunnex.io/download";

export function ClientConnection({ organization, compact = false }: { organization?: string; compact?: boolean }) {
  const { state } = useAuth();
  const [address, setAddress] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  useEffect(() => {
    let current = true;
    void api.GET("/api/v1/meta").then(({ data }) => {
      if (!current) return;
      try {
        const url = new URL(data?.public_base_url ?? "");
        if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password) setAddress(url.origin);
      } catch { /* Missing metadata must not become a guessed server address. */ }
    }).catch(() => {}).finally(() => { if (current) setLoaded(true); });
    return () => { current = false; };
  }, []);
  async function copyAddress() {
    if (!address) return;
    try { await navigator.clipboard.writeText(address); setCopyStatus("Server address copied"); }
    catch { setCopyStatus("Could not copy. Select and copy the server address above."); }
  }
  return <div className="space-y-4">
    <a className="setup-primary-link" href={CLIENT_DOWNLOAD_URL} target="_blank" rel="noreferrer">Download Client</a>
    <p className="text-sm text-ink-secondary">{compact ? "Install the client, enter this address and sign in." : "Choose the client for your computer. Open it, enter this server address, then sign in."}</p>
    <div className="rounded-card border border-border p-4 space-y-3">
      <div className="text-xs text-ink-tertiary">Tunnex Server address</div>
      {address ? <><code className="block break-all text-sm select-all">{address}</code><Button variant="ghost" onClick={copyAddress}>Copy server address</Button></> : <p className="text-sm text-ink-secondary">{loaded ? "Server address unavailable. Ask your administrator for the configured public address." : "Loading server address…"}</p>}
      {organization && <p className="text-sm">Organization: <strong>{organization}</strong></p>}
      {state.status === "authed" && <p className="text-sm break-all">Sign in as: <strong>{state.user.email}</strong></p>}
      <p role="status" className="text-xs text-ink-secondary">{copyStatus}</p>
    </div>
    <p className="text-sm text-ink-secondary">{compact ? "Connect, then test an allowed private app or server." : "Choose your organization and connect. If your device needs approval, ask your administrator. Then open a private resource you are allowed to access."}</p>
    {!compact && <p className="text-xs text-ink-tertiary">Signing in to the dashboard does not connect your computer to the VPN.</p>}
  </div>;
}
