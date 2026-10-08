import { useEffect, useState } from "react";
import { Button, ErrorText, Loading } from "./ui";
import { beamApi, beamDiagnosticExport, type BeamDiagnostics as Diagnostics } from "../lib/beam";

const reasons: Record<Diagnostics["reason"], string> = {
  ready: "Current serving and publisher authority checks passed.",
  domain_unavailable: "Installation serving checks are unavailable or expired. Ask the installation operator to check the serving setup.",
  publisher_authority_unavailable: "Publisher permission or its connector credential is no longer available. Check group membership and sign-in in the desktop client.",
  connector_offline: "The publisher connector is offline. Keep the desktop client and local app running, then check again.",
  share_paused: "This share is paused. Its owner can resume it before expiry if current policy allows.",
  share_ended: "This share has ended. Create a new share in the desktop client to publish again.",
};
export function beamHealthNextStep(data: Pick<Diagnostics, "reason" | "connectivity">): string {
  if (data.reason === "share_ended") return "Publish a new session from the CLI or desktop client. An ended link cannot be restarted.";
  if (data.reason === "share_paused") return "Resume this share from its management controls, then keep the publisher running.";
  if (data.reason === "domain_unavailable") return "Ask your installation operator to open Settings → Local Sharing setup and check DNS, HTTPS certificates and the connector endpoint.";
  if (data.reason === "publisher_authority_unavailable") return "Check that your publisher account still has permission. Sign in to the correct control plane before creating a new session.";
  if (data.connectivity === "origin_unavailable") return "Start your local app on the port you published. Open it on your own computer first, then keep both the app and publisher running.";
  if (data.reason === "connector_offline" || ["offline", "reconnecting"].includes(data.connectivity)) return "Check your internet connection and the publishing terminal or desktop client. Reconnect with the original login before the share expires.";
  return "The share is ready. Send its link to a selected reviewer; they sign in and open it in their browser.";
}
export function BeamDiagnostics({ orgId, shareId, revision }: { orgId: string; shareId: string; revision?: string }) {
  const [data, setData] = useState<Diagnostics | null>(null), [error, setError] = useState(""), [reload, setReload] = useState(0);
  useEffect(() => { let current = true; setData(null); setError(""); void beamApi.diagnostics(orgId, shareId).then(result => { if (!current) return; if (result.ok) setData(result.data); else setError(result.error); }); return () => { current = false; }; }, [orgId, shareId, reload, revision]);
  function download() {
    if (!data) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(beamDiagnosticExport(data), null, 2) + "\n"], { type: "application/json" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `local-sharing-diagnostics-${data.share_id}.json`; anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section className="beam-diagnostics beam-section space-y-3"><div className="beam-section-heading"><h2 className="font-semibold">Share diagnostics</h2><Button variant="ghost" onClick={() => setReload(n => n + 1)}>Check share health</Button></div><p className="text-sm text-ink-secondary">A redacted support snapshot contains share state and serving health. Local app addresses, credentials, certificate material, reviewer identities, request contents and cookies are excluded.</p>
    {error ? <ErrorText>{error}</ErrorText> : !data ? <Loading label="Checking share health…" /> : <><p role="status">{reasons[data.reason] ?? "Share health is unavailable. Check again."}</p><div className="rounded border border-line p-3"><h3 className="font-semibold text-sm">What to do next</h3><p className="text-sm text-ink-secondary">{beamHealthNextStep(data)}</p></div><dl className="beam-meta"><div><dt>State</dt><dd>{data.state}</dd></div><div><dt>Connectivity</dt><dd>{data.connectivity}</dd></div><div><dt>Serving checks</dt><dd>{data.domain_ready ? "Current" : "Unavailable"}</dd></div><div><dt>Saved version</dt><dd>{data.version}</dd></div></dl><p className="text-xs text-ink-secondary">Snapshot from the last check. Opening an app still requires current reviewer access.</p><Button variant="ghost" onClick={download}>Download redacted diagnostics</Button></>}
  </section>;
}
