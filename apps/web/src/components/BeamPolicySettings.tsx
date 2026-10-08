import "../beam-workspace.css";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Button, ErrorText, Field, Input, Loading, Modal } from "./ui";
import { AudiencePicker } from "./BeamAudiencePicker";
import { beamApi, type BeamAudience, type BeamGrant, type BeamPolicy, type BeamPolicyImpact } from "../lib/beam";

export function BeamPolicySettings({ orgId, canEdit, canOperate = false }: { orgId: string; canEdit: boolean; canOperate?: boolean }) {
  const [saved, setSaved] = useState<BeamPolicy | null>(null); const [draft, setDraft] = useState<BeamPolicy | null>(null); const [directory, setDirectory] = useState<BeamAudience | null>(null);
  const reviewOpener = useRef<HTMLElement | null>(null);
  const [review, setReview] = useState<{ policy: BeamPolicy; impact: BeamPolicyImpact } | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState(""); const [notice, setNotice] = useState(""); const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false); const [uncertain, setUncertain] = useState(false); const [reload, setReload] = useState(0); const alive = useRef(true); const locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { let current = true; setLoading(true); setError(""); setNotice(""); setSaved(null); setDraft(null); setDirectory(null); void beamApi.policy(orgId).then(async policy => {
    if (!current) return; if (!policy.ok) { setError(policy.error); setLoading(false); return; }
    setSaved(policy.data); setDraft(policy.data); setReview(null); setConfirmed(false); setUncertain(false);
    if (policy.data.can_manage_policy) {
      const subjects = await beamApi.audience(orgId);
      if (!current) return; if (!subjects.ok) { setError("Could not load the organization directory. Policy editing is unavailable until you reload successfully."); setLoading(false); return; }
      setDirectory(subjects.data);
    }
    setLoading(false);
  }); return () => { current = false; }; }, [orgId, reload]);
  async function preview(event: React.FormEvent) {
    event.preventDefault(); if (!draft || !saved || locked.current || uncertain || !directory || !canEdit || !saved.can_manage_policy) return;
    const submitter = (event.nativeEvent as SubmitEvent).submitter; reviewOpener.current = submitter instanceof HTMLElement ? submitter : document.activeElement instanceof HTMLElement ? document.activeElement : null;
    locked.current = true; setBusy(true); setError(""); setNotice(""); const captured = { ...draft, enabled: saved.enabled, version: saved.version };
    try { const result = await beamApi.policyImpact(orgId, captured); if (!alive.current) return;
      if (!result.ok) { if (result.code === "beam_version_conflict") setUncertain(true); setError(`${result.error} Sharing policy was not changed.${result.code === "beam_version_conflict" ? " Reload saved policy before another change; your edits are still shown." : ""}`); return; }
      if (result.data.policy_version !== saved.version) { setUncertain(true); setError("Sharing policy changed. Reload saved policy before another change; your edits are still shown."); return; }
      setConfirmed(false); setReview({ policy: captured, impact: result.data });
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  async function save() {
    if (!review || locked.current || uncertain || !canEdit || (review.impact.requires_confirmation && !confirmed)) return;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try { const result = await beamApi.savePolicy(orgId, review.policy, confirmed); if (!alive.current) return;
      if (!result.ok) { setReview(null); setUncertain(true); setError(`${result.error} Your edits are still shown. Reload saved policy before another change; reloading replaces your edits.`); }
      else { setReview(null); setSaved(result.data); setDraft(result.data); setNotice("Sharing policy saved. Current policy applies to new and existing shares."); }
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  if (loading) return <Loading label="Loading sharing policy…" />;
  if (!draft || !saved) return <div className="space-y-3"><ErrorText>{error}</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry sharing policy</Button></div>;
  const disabled = !canEdit || !saved.can_manage_policy || !directory || busy || uncertain;
  const reviewers: BeamGrant[] = [...draft.reviewer_user_ids.map(subject_id => ({ subject_kind: "user" as const, subject_id })), ...draft.reviewer_group_ids.map(subject_id => ({ subject_kind: "group" as const, subject_id }))];
  const change = (patch: Partial<BeamPolicy>) => { setDraft(current => current ? { ...current, ...patch } : current); setNotice(""); };
  return <form onSubmit={event => void preview(event)} className="beam-policy-settings space-y-5">
    <div className="space-y-2"><h3 className="font-semibold">Self-service local app sharing</h3><p className="text-sm text-ink-secondary">Let members create review links from the Tunnex CLI or desktop client. Normal shares inside this policy do not need administrator approval.</p><p role="status" className="text-sm">Serving domain: {saved.base_domain || "Not configured"} · {saved.domain_ready ? "Installation checks current" : "Setup incomplete"}</p><p className="text-xs text-ink-secondary">Serving setup is configured by the installation operator on the server. Wildcard DNS and HTTPS must be qualified there; organization policy cannot mark setup ready.</p></div>
    <details className="rounded-md border border-line p-4 text-sm space-y-3"><summary className="cursor-pointer font-medium">Operator setup guide</summary><div className="space-y-3 pt-3 text-ink-secondary"><p>Configure these settings on the control plane before enabling Local Sharing. Serving requires current independent installation checks; this organization screen does not run DNS or certificate probes.</p><ol className="list-decimal pl-5 space-y-2"><li>Set <code>TUNNEX_BEAM_BASE_DOMAIN</code> to the dedicated serving domain. Prefer a separate registrable domain from the HTTPS control-plane address configured in <code>APP_BASE_URL</code>.</li><li>Point wildcard DNS for the serving domain to the sharing proxy. Install trusted HTTPS certificates covering its wildcard hostnames.</li><li>Set <code>TUNNEX_BEAM_PROXY_URL</code> to the qualified HTTPS connector endpoint. The desktop client must reach it with trusted TLS and its issued connector certificate.</li><li>Save versioned installation settings, then run the server DNS and TLS checks. Environment readiness assertions cannot bypass these checks.</li><li>Enable this organization's policy and choose publisher groups and a reviewer audience. Each share still requires current publisher and reviewer authority.</li></ol><p>Changing or withdrawing serving configuration can end existing shares. Qualify the new setup before re-enabling publishing.</p></div></details>
    {canOperate && <Link className="text-brand text-sm" to="/settings?section=beam-serving">Manage installation serving setup</Link>}
    <ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}
    <div className="flex flex-wrap items-center gap-3 text-sm"><span role="status">Local Sharing: {saved.enabled ? "Enabled" : "Disabled"}</span><Link className="text-brand" to="/settings?section=features&feature=local-sharing">Manage feature</Link></div>
    <label className="flex items-start gap-3"><input type="checkbox" checked={draft.open_for_all_users ?? false} disabled={disabled} onChange={event => change({ open_for_all_users: event.target.checked })} /><span><span className="block text-sm font-medium">Open for all users</span><span className="block text-sm text-ink-secondary">Every active, eligible member of this organization can publish using the CLI or desktop client and select any organization user or group as a reviewer. Each reviewer still needs an explicit share grant and signs in through their browser.</span></span></label>
    {draft.open_for_all_users && <p role="status" className="text-sm">Publisher group and reviewer allowlists are not applied in this mode. Lifetime, share limits and MFA settings still apply. Saved allowlists are retained for restricted mode.</p>}
    <div className="grid gap-4 md:grid-cols-2"><Field label="Maximum lifetime (minutes)"><Input type="number" min={1} max={1440} required disabled={disabled} value={draft.max_duration_seconds / 60} onChange={event => change({ max_duration_seconds: Number(event.target.value) * 60 })} /></Field><Field label="Shares per publisher"><Input type="number" min={1} max={25} required disabled={disabled} value={draft.max_shares} onChange={event => change({ max_shares: Number(event.target.value) })} /></Field></div>
    <label className="flex items-center gap-3"><input type="checkbox" checked={draft.require_mfa} disabled={disabled} onChange={event => change({ require_mfa: event.target.checked })} /><span className="text-sm">Require recent reviewer MFA</span></label>
    {!draft.open_for_all_users && <><div className="space-y-3"><h4 className="font-medium">Publisher groups</h4><p className="text-sm text-ink-secondary">Selected groups can publish inside the allowed audience and limits. No selection means publishing is denied.</p>{directory && <div className="beam-picker" role="group" aria-label="Publisher groups">{!directory.groups.length && <p className="text-sm">Create a user group before delegating publishing.</p>}{directory.groups.map(group => <label key={group.id}><input type="checkbox" disabled={disabled} checked={draft.publisher_group_ids.includes(group.id)} onChange={event => change({ publisher_group_ids: event.target.checked ? [...draft.publisher_group_ids, group.id] : draft.publisher_group_ids.filter(id => id !== group.id) })} /><span>{group.name}</span></label>)}</div>}<Link className="text-brand text-sm" to="/users/groups">Manage user groups</Link></div>
    <div className="space-y-3"><h4 className="font-medium">Allowed reviewer audience</h4><p className="text-sm text-ink-secondary">Publishers may grant their own shares to these users and groups. Administrators still need an explicit share grant to open app content.</p>{directory && <AudiencePicker audience={directory} disabled={disabled} grants={reviewers} onChange={grants => change({ reviewer_user_ids: grants.filter(grant => grant.subject_kind === "user").map(grant => grant.subject_id), reviewer_group_ids: grants.filter(grant => grant.subject_kind === "group").map(grant => grant.subject_id) })} />}</div>
    </>}
    <div className="flex flex-wrap gap-3 border-t border-line pt-4"><Button type="submit" disabled={disabled || (draft.enabled && !saved.domain_ready) || !Number.isInteger(draft.max_duration_seconds) || draft.max_duration_seconds < 60 || draft.max_duration_seconds > 86400 || !Number.isInteger(draft.max_shares) || draft.max_shares < 1 || draft.max_shares > 25}>Review policy changes</Button><Button type="button" variant="ghost" disabled={busy} onClick={() => setReload(n => n + 1)}>Reload saved policy</Button></div>
    {review && <Modal returnFocusTo={reviewOpener.current} title="Review sharing policy change" onDismiss={() => { if (!busy) setReview(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setReview(null)}>Keep editing policy</Button><Button disabled={busy || uncertain || (review.impact.requires_confirmation && !confirmed)} onClick={() => void save()}>Confirm sharing policy</Button></>}>
      <p>Publishing access: <strong>{review.policy.open_for_all_users ? "Open for all users in this organization" : "Restricted publisher groups and reviewer audience"}</strong></p>
      <p>{review.impact.active_share_count} active shares; {review.impact.affected_share_count} shares and {review.impact.affected_reviewer_session_count} current reviewer sessions affected by this change.</p><p className="text-sm text-ink-secondary">The server checks this saved policy version and current impact again before applying the change.</p>{review.impact.requires_confirmation && <label className="flex items-center gap-3"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} /><span>End active shares affected by this policy change</span></label>}
    </Modal>}
  </form>;
}
