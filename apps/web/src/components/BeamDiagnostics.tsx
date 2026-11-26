import { useEffect, useState } from "react";
import { Button, ErrorText, Loading } from "./ui";
import { ResourceSummary } from "./ResourceSummary";
import { beamApi, beamConnectivityLabel, beamDiagnosticExport, beamStateLabel, type BeamDiagnostics as Diagnostics } from "../lib/beam";

const reasons: Record<Diagnostics["reason"], string> = {
  ready: "The share is ready: the server checks pass and the publisher is connected.",
  domain_unavailable: "Local Sharing isn't available on this server right now: its setup is incomplete or a server check is failing.",
  publisher_authority_unavailable: "The publisher's sharing permission or sign-in is no longer valid. Check their publisher group and their sign-in in the CLI or desktop client.",
  connector_offline: "The publisher is offline. Keep the CLI or desktop client and the local app running, then check again.",
  share_paused: "This share is paused. It can be resumed before it expires if the sharing policy still allows it.",
  share_ended: "This share has ended. Create a new share to publish again.",
};
export function beamHealthNextStep(data: Pick<Diagnostics, "reason" | "connectivity">): string {
  if (data.reason === "share_ended") return "Publish a new session from the CLI or desktop client. An ended link cannot be restarted.";
  if (data.reason === "share_paused") return "Resume this share from its management controls, then keep the publisher running.";
  if (data.reason === "domain_unavailable") return "Ask a server administrator to open Settings → Local Sharing domain and fix the failing check.";
  if (data.reason === "publisher_authority_unavailable") return "Check that the publisher account is still allowed to publish, then sign in again in the CLI or desktop client and share the app again.";
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
  // LS-UX-4: plain words; the support file and its allowlist (beamDiagnosticExport) are unchanged.
  return <ResourceSummary title="Share health" headingLevel={2} className="beam-diagnostics" description="The support file has the share's status and server checks only: no local app address, credentials, certificates, reviewer names, app content or cookies." actions={<Button variant="ghost" onClick={() => setReload(n => n + 1)}>Check again</Button>} footer={data && !error ? <Button variant="ghost" onClick={download}>Download support file</Button> : undefined}>
    {error ? <ErrorText>{error}</ErrorText> : !data ? <Loading label="Checking share health…" /> : <div className="beam-diagnostics-content"><p role="status">{reasons[data.reason] ?? "Share health is unavailable. Check again."}</p><dl className="beam-meta tnx-resource-facts"><div><dt>Status</dt><dd>{beamStateLabel(data.state)}</dd></div><div><dt>Connection</dt><dd>{beamConnectivityLabel(data.connectivity)}</dd></div><div><dt>Server checks</dt><dd>{data.domain_ready ? "Passing" : "Failing"}</dd></div><div><dt>Revision</dt><dd>{data.version}</dd></div><div className="tnx-resource-fact-wide"><dt>What to do next</dt><dd>{beamHealthNextStep(data)}</dd></div></dl><p className="text-xs text-ink-secondary">As of the last check. Opening the app still checks each reviewer's access.</p></div>}
  </ResourceSummary>;
}
