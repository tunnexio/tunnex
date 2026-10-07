import { Link } from "react-router-dom";
import { decisionLabel, type AccessEvent } from "../lib/flowlogview";

export function BeamAccessEvidence({ event, reviewerLabel }: { event: AccessEvent; reviewerLabel?: string | null }) {
  if (!event.beam) return null;
  return <div className="space-y-4">
    <p className="text-sm text-ink-secondary">Beam browser access evidence records the authenticated reviewer and share at the control plane. Gateway addresses, flow sequence and applied network policy do not apply to this record.</p>
    <p role="status" className="font-semibold">{decisionLabel(event.decision)}</p>
    <dl className="grid gap-4 sm:grid-cols-2">
      <div><dt className="text-xs text-ink-faint">Reviewer</dt><dd>{reviewerLabel ? `${reviewerLabel} (current member label)` : event.src_user_id || "Not recorded"}</dd></div>
      <div><dt className="text-xs text-ink-faint">Recorded at the control plane</dt><dd>{new Date(event.created_at).toLocaleString()}</dd></div>
      <div><dt className="text-xs text-ink-faint">Share ID</dt><dd className="break-all">{event.beam.share_id}</dd></div>
      <div><dt className="text-xs text-ink-faint">Action</dt><dd>{event.beam.action}</dd></div>
      <div><dt className="text-xs text-ink-faint">Safe reason</dt><dd>{event.beam.reason.replace(/_/g, " ") || "None recorded"}</dd></div>
      <div><dt className="text-xs text-ink-faint">Audit event ID</dt><dd className="break-all">{event.id}</dd></div>
      <div><dt className="text-xs text-ink-faint">Recorded reviewer ID</dt><dd className="break-all">{event.src_user_id || "Not recorded"}</dd></div>
    </dl>
    <p className="text-xs text-ink-secondary">Retained under the organization's Audit Log policy. App bodies, URLs with query strings, cookies and credentials are excluded. Each new app request still checks current access.</p>
    <Link className="text-brand text-sm" to={`/beam/shares/${encodeURIComponent(event.beam.share_id)}`}>Share history and health</Link>
  </div>;
}
