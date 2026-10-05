import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage, loadOne, type SandboxRunnerEnrollment as Enrollment, type SandboxRunnerEnrollmentList, type SandboxRunnerEnrollmentProfile } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading, Modal, Select } from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";
import { SandboxRunnerCommand } from "./SandboxRunnerCommand";
import { SandboxRunnerQualificationTrial } from "./SandboxRunnerQualificationTrial";

const terminalStates = new Set(["expired", "revoked"]);
const blockerMessages: Record<string, string> = {
  runner_profile_unavailable: "No approved deployment profile is available. Ask an operator to register a verified package, image and controller trust configuration.",
  native_qualification_required: "The machine is connected, but its host and immutable image still require native qualification. An operator must review the host proof before it can create sandboxes.",
  runner_offline: "The runner is offline. Check the existing machine's service and control-plane connection, then refresh. Retained sandboxes still keep their original expiry deadline.",
  bootstrap_expired: "The enrollment token has expired. Start a new enrollment; the old token cannot be reused.",
  credential_expired: "The runner credential has expired. Ask an operator to review and renew the machine identity before it can reconnect.",
  enrollment_revoked: "Runner access was revoked. Cleanup remains pending until the machine and network removals are confirmed.",
  policy_not_enforcing: "Enable enforcing network policy before enrolling a sandbox runner.",
  module_disabled: "The sandbox module is disabled on this server. Ask an operator to enable it before enrolling a runner.",
  module_draining: "The sandbox module is draining existing work. New runner enrollment is unavailable until an operator finishes draining it.",
  cleanup_pending: "Runner-owned sandboxes or network resources still need confirmed cleanup. The retained slot cannot be reused yet.",
  qualification_checks_incomplete: "Qualification has failed or unrun checks. Complete the machine's supported qualification workflow and submit a fresh report before approval.",
  native_proof_required: "The control plane still needs verified native trial evidence from this exact machine and image. A host report alone cannot approve the runner.",
};
function Reasons({ reasons }: { reasons: string[] }) {
  return reasons.length ? <ul className="sb-runner-reasons">{reasons.map(reason => <li key={reason}>{blockerMessages[reason] ?? reason.replace(/_/g, " ")}</li>)}</ul> : null;
}
function enrollmentLabel(enrollment: Enrollment, confirmed: boolean) {
  if (!confirmed) return "Status unconfirmed";
  if (enrollment.state === "awaiting_connection" && enrollment.last_seen_at && enrollment.blocked_reasons.includes("native_qualification_required")) return "Connected · qualification required";
  return ({ awaiting_install: "Waiting for installation", awaiting_connection: "Waiting for runner connection", ready: "Ready", offline: "Offline", expired: "Expired", revoked: "Revoked", pending_cleanup: "Access withdrawn · cleanup pending" } as Record<string, string>)[enrollment.state] ?? "Status unavailable";
}


/** Public enrollment metadata may be reloaded. A bootstrap token lives only in
 * this mounted component and is never added to a URL, command or browser store. */
export function SandboxRunnerEnrollment({ orgId, canManage, onRunnerChange, onReadinessConfirmed }: { orgId: string; canManage: boolean; onRunnerChange?: () => void; onReadinessConfirmed?: (confirmed: boolean) => void }) {
  const [data, setData] = useState<SandboxRunnerEnrollmentList | null>(null);
  const [readError, setReadError] = useState<string | null>(null), [mutationError, setMutationError] = useState<string | null>(null);
  const [reading, setReading] = useState(false), [pending, setPending] = useState(false);
  const [draftOpen, setDraftOpen] = useState(false), [review, setReview] = useState(false), [name, setName] = useState(""), [profileId, setProfileId] = useState(""), [acknowledged, setAcknowledged] = useState(false);
  const [viewId, setViewId] = useState<string | null>(null), [secret, setSecret] = useState<string | null>(null), [lostSecret, setLostSecret] = useState(false), [revokeId, setRevokeId] = useState<string | null>(null);
  const active = useRef(true), inFlight = useRef(false), requestEpoch = useRef(0);
  const idempotency = useRef<{ intent: string; key: string } | null>(null);
  const lastStates = useRef<Map<string, string> | null>(null);
  const onChange = useRef(onRunnerChange);
  const onConfirmation = useRef(onReadinessConfirmed);
  useEffect(() => { onChange.current = onRunnerChange; }, [onRunnerChange]);
  useEffect(() => { onConfirmation.current = onReadinessConfirmed; }, [onReadinessConfirmed]);
  useEffect(() => { active.current = true; return () => { active.current = false; requestEpoch.current++; }; }, []);

  function replaceEnrollment(enrollment: Enrollment) {
    lastStates.current?.set(enrollment.id, enrollment.state);
    setData(previous => previous ? { ...previous, enrollments: [enrollment, ...previous.enrollments.filter(item => item.id !== enrollment.id)] } : previous);
  }
  const refresh = useCallback(async () => {
    if (!canManage || inFlight.current) return;
    const epoch = ++requestEpoch.current; setReading(true);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/sandbox-runner-enrollments", { params: { path: { orgId } } }));
    if (!active.current || requestEpoch.current !== epoch) return;
    setReading(false);
    if (!result.ok || !Array.isArray(result.data.profiles) || !Array.isArray(result.data.enrollments) || !Array.isArray(result.data.blocked_reasons)) {
      setReadError(result.ok ? "Runner enrollment information is unavailable on this server. Refresh after it is updated." : result.error);
      onConfirmation.current?.(false);
      return;
    }
    const states = new Map(result.data.enrollments.map(enrollment => [enrollment.id, enrollment.state]));
    if (lastStates.current && result.data.enrollments.some(enrollment => (lastStates.current?.get(enrollment.id) === "ready") !== (enrollment.state === "ready"))) onChange.current?.();
    lastStates.current = states;
    setReadError(null); setData(result.data);
    onConfirmation.current?.(result.data.enrollments.some(enrollment=>enrollment.state==="ready"));
  }, [orgId, canManage]);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!data?.enrollments.some(enrollment => !terminalStates.has(enrollment.state))) return;
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => window.clearInterval(timer);
  }, [data, refresh]);

  const profile = data?.profiles.find(item => item.id === profileId);
  const eligibleProfiles = data?.profiles.filter(item => item.blocked_reasons.length === 0) ?? [];
  const canIssue = canManage && !!data && !readError && !data.blocked_reasons.length && eligibleProfiles.length > 0;
  const view = data?.enrollments.find(item => item.id === viewId);
  const viewProfile = data?.profiles.find(item => item.id === view?.profile_id);
  const confirmed = !readError;
  function begin() {
    if (!canIssue) return;
    setProfileId(previous => data?.profiles.some(item => item.id === previous && !item.blocked_reasons.length) ? previous : eligibleProfiles.length === 1 ? eligibleProfiles[0].id : "");
    setReview(false); setAcknowledged(false); setMutationError(null); setDraftOpen(true);
  }
  function closeDraft() { if (!inFlight.current) { setDraftOpen(false); setMutationError(null); } }
  async function issue() {
    if (inFlight.current || !canIssue || !profile || profile.blocked_reasons.length || !name.trim() || !acknowledged) return;
    const body = { name: name.trim(), profile_id: profile.id };
    const intent = JSON.stringify(body);
    if (idempotency.current?.intent !== intent) idempotency.current = { intent, key: crypto.randomUUID() };
    inFlight.current = true; requestEpoch.current++; setPending(true); setMutationError(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/sandbox-runner-enrollments", { params: { path: { orgId } }, body: { ...body, idempotency_key: idempotency.current.key } });
      if (!active.current) return;
      if (result.error || !result.data) {
        setMutationError(apiErrorMessage(result.error, "Enrollment could not be confirmed. Retry with the same name and profile; the request will use the same idempotency key.")); return;
      }
      replaceEnrollment(result.data.enrollment); setViewId(result.data.enrollment.id); setDraftOpen(false);
      idempotency.current = null;
      setLostSecret(!result.data.bootstrap_token); setSecret(result.data.bootstrap_token ?? null);
    } catch { if (active.current) setMutationError("Enrollment could not be confirmed. Retry with the same name and profile; the request will use the same idempotency key."); }
    finally { inFlight.current = false; if (active.current) { setPending(false); setReading(false); } }
  }
  async function revoke() {
    if (!revokeId || inFlight.current) return;
    inFlight.current = true; requestEpoch.current++; setPending(true); setMutationError(null);
    try {
      const result = await api.DELETE("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}", { params: { path: { orgId, enrollmentId: revokeId } } });
      if (!active.current) return;
      if (result.error) { setMutationError(apiErrorMessage(result.error, "Revocation could not be confirmed. Refresh before retrying.")); return; }
      if (result.data) replaceEnrollment(result.data);
      setSecret(null); setRevokeId(null); setLostSecret(false); onChange.current?.();
    } catch { if (active.current) setMutationError("Revocation could not be confirmed. Refresh before retrying."); }
    finally { inFlight.current = false; if (active.current) { setPending(false); void refresh(); } }
  }

  return <section className="sb-runner-enrollment" aria-labelledby="sb-runner-heading">
    <div className="sb-runner-toolbar"><div><h2 id="sb-runner-heading">Sandbox runners</h2><p className="sb-help">Enroll a machine on an approved Linux gateway host. A machine administrator runs the installer.</p></div><div><Button type="button" variant="ghost" disabled={reading || pending} onClick={() => void refresh()}>Refresh runners</Button><Button type="button" disabled={!canIssue || pending} onClick={begin}>Add sandbox runner</Button></div></div>
    {!canManage ? <p className="sb-help">An organization owner or administrator can enroll a sandbox runner.</p> : <>
      {readError && <ErrorText>{readError} Runner connection and readiness are unconfirmed until a successful refresh.</ErrorText>}
      {!data && !readError && <Loading label="Loading runner enrollment…" />}
      {data && <><Reasons reasons={data.blocked_reasons} />{!data.profiles.length && <p className="sb-help">No approved deployment profiles. Ask an operator to provide a verified public bundle, qualified image and controller trust configuration.</p>}{data.profiles.length > 0 && !eligibleProfiles.length && <div className="sb-runner-profile-blockers"><p className="sb-help">Deployment profiles need attention before a token can be issued.</p>{data.profiles.map(item => <div key={item.id}><h3>{item.name}</h3><Reasons reasons={item.blocked_reasons} /></div>)}</div>}
        {!data.enrollments.length ? <p className="sb-help mt-3">No runner enrollments yet.</p> : <ul className="sb-runner-list" aria-label="Runner enrollments">{data.enrollments.map(enrollment => <li key={enrollment.id}><div><h3>{enrollment.name}</h3><p className="sb-help"><span>{enrollmentLabel(enrollment, confirmed)}</span>{enrollment.last_seen_at && <> · Last seen <time dateTime={enrollment.last_seen_at}>{new Date(enrollment.last_seen_at).toLocaleString()}</time></>}</p></div><Button type="button" size="sm" variant="ghost" onClick={() => { setViewId(enrollment.id); setLostSecret(false); setMutationError(null); void refresh(); }}>View {enrollment.name}</Button></li>)}</ul>}
      </>}
    </>}
    {draftOpen && <Modal title={review ? "Review runner enrollment" : "Add sandbox runner"} size="enrollment" onDismiss={closeDraft} actions={<><Button type="button" variant="ghost" disabled={pending} onClick={() => review ? setReview(false) : closeDraft()}>{review ? "Back" : "Cancel"}</Button><Button type="button" disabled={pending || !canIssue || !profile || !!profile.blocked_reasons.length || !name.trim() || (review && !acknowledged)} onClick={() => review ? void issue() : setReview(true)}>{pending ? "Issuing enrollment…" : review ? "Issue enrollment token" : "Review enrollment"}</Button></>}>
      {!review ? <div className="sb-runner-fields"><p>Choose an approved deployment profile. This does not install or start anything on the machine.</p><Field label="Runner name"><Input autoFocus maxLength={80} required value={name} onChange={event => setName(event.target.value)} placeholder="e.g. team-gateway-runner" /></Field><Field label="Deployment profile"><Select required value={profileId} onChange={event => { setProfileId(event.target.value); setAcknowledged(false); }}><option value="">Choose a deployment profile</option>{data?.profiles.map(item => <option key={item.id} value={item.id} disabled={!!item.blocked_reasons.length}>{item.name} · {item.architecture}{item.blocked_reasons.length ? " · unavailable" : ""}</option>)}</Select></Field>{profile && <ProfileRequirements profile={profile} />}</div> : <div className="sb-runner-fields"><p>Issue a short-lived token for <strong>{name.trim()}</strong> using <strong>{profile?.name}</strong>. It authorizes this bounded runner enrollment only.</p>{profile && <ProfileRequirements profile={profile} />}<label className="sb-scope-choice"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} /><span>I can ask the machine administrator to run this on the approved gateway host and review the installation and activation prompts.</span></label><p className="sb-help">Enrollment does not publish templates or enable sandbox creation. Connected machines still need server-confirmed qualification.</p></div>}
      {mutationError && <ErrorText>{mutationError}</ErrorText>}
      {readError && <ErrorText>{readError} Refresh runner information before issuing a token.</ErrorText>}
      {data && <Reasons reasons={data.blocked_reasons} />}
    </Modal>}
    {secret && view && <OneTimeSecretModal title="Save the runner enrollment token" secret={secret} copyLabel="Copy enrollment token" requireAck="I have saved this token for the machine's hidden terminal prompt." caption={<>Shown once. Expires <time dateTime={view.expires_at}>{new Date(view.expires_at).toLocaleString()}</time>. Paste it only when the installer asks. Keep it out of command arguments, URLs and logs.</>} onDismiss={() => setSecret(null)}><SandboxRunnerCommand command={view.install_command} /><Button type="button" variant="danger" className="mt-3" onClick={() => { setSecret(null); setLostSecret(true); setRevokeId(view.id); }}>Cancel enrollment</Button></OneTimeSecretModal>}
    {view && !secret && !revokeId && <Modal title={`Runner: ${view.name}`} size="enrollment" onDismiss={() => { if (!pending) setViewId(null); }} actions={<><Button type="button" variant="ghost" disabled={reading || pending} onClick={() => void refresh()}>Refresh status</Button>{!terminalStates.has(view.state) && view.state !== "pending_cleanup" && <Button type="button" variant="danger" disabled={pending} onClick={() => { setRevokeId(view.id); setMutationError(null); }}>{view.state === "awaiting_install" ? "Cancel enrollment" : "Revoke runner"}</Button>}<Button type="button" variant="ghost" disabled={pending} onClick={() => setViewId(null)}>Close</Button></>}>
      <div className="sb-runner-fields"><p role="status" className="sb-runner-state">{enrollmentLabel(view, confirmed)}</p>{readError && <ErrorText>{readError} Refresh before relying on runner readiness.</ErrorText>}{lostSecret && <p className="sb-runner-token-note">This enrollment already exists. Its one-time token cannot be shown again. If you did not save it, cancel this enrollment and start a new one.</p>}<Reasons reasons={view.blocked_reasons} />
        {view.state === "awaiting_install" && <><p>The machine administrator runs this command on the approved gateway host, then pastes the separately saved token into the hidden terminal prompt.</p><SandboxRunnerCommand command={view.install_command} disabled={!confirmed} /><p className="sb-help">Token deadline: <time dateTime={view.expires_at}>{new Date(view.expires_at).toLocaleString()}</time>. Closing this screen does not cancel enrollment and never reveals the token again.</p></>}
        {(view.state === "awaiting_connection" || view.state === "offline") && <><p>{view.last_seen_at ? "The server has observed this runner. It will become Ready only after fresh authenticated health and reviewed host qualification are confirmed." : "The token was redeemed. Waiting for the installed runner's authenticated connection and qualification."}</p><p className="sb-help">For recovery, rerun the public command on the same machine. It reuses that enrollment's local identity. Do not move its private keys to another machine.</p><SandboxRunnerCommand command={view.install_command} disabled={!confirmed} /></>}
        {view.state === "ready" && confirmed && <><p>The server confirms that this runner is qualified and connected. Review organization activation and published templates before creating a sandbox.</p><Link to="/sandboxes/setup" className="sb-inline-link" onClick={() => { setViewId(null); onChange.current?.(); }}>Review Sandbox setup →</Link><p className="sb-help">Then create a sandbox, choose your terminal device, saved SSH public key and optional skills, and use its confirmed private SSH instructions.</p></>}
        {(view.state==="awaiting_connection"||view.state==="offline"||view.qualification_trial)&&<SandboxRunnerQualificationTrial key={view.id} orgId={orgId} enrollmentId={view.id} enrollmentState={view.state} lastSeenAt={view.last_seen_at} terminalGatewayId={viewProfile?.terminal_gateway_id} confirmed={confirmed} initialTrial={view.qualification_trial} onTrialChange={()=>void refresh()} />}
        <RunnerQualification enrollment={view} orgId={orgId} confirmed={confirmed} onReviewed={updated=>{const wasReady=view.state==="ready";replaceEnrollment(updated);if(wasReady!==(updated.state==="ready"))onChange.current?.();void refresh();}} />
        {view.state === "expired" && <><p>The old enrollment token is no longer usable. Start a new enrollment after reviewing the same deployment prerequisites.</p><Button type="button" disabled={!canIssue || pending} onClick={() => { setViewId(null); begin(); }}>Start new enrollment</Button></>}
        {(view.state === "revoked" || view.state === "pending_cleanup") && <p>New runner access is withdrawn. Retained sandbox deletion and network removal complete only after confirmed cleanup. An offline machine receives revocation when it reconnects; existing local absolute expiry remains enforced.</p>}
        {view.state === "revoked" && <Button type="button" disabled={!canIssue || pending} onClick={() => { setViewId(null); begin(); }}>Start new enrollment</Button>}
      </div>{mutationError && <ErrorText>{mutationError}</ErrorText>}
    </Modal>}
    {revokeId && <Modal title="Withdraw runner access?" danger onDismiss={() => { if (!pending) setRevokeId(null); }} actions={<><Button type="button" variant="ghost" disabled={pending} onClick={() => setRevokeId(null)}>Keep enrollment</Button><Button type="button" variant="danger" disabled={pending} onClick={() => void revoke()}>{pending ? "Withdrawing…" : "Withdraw runner access"}</Button></>}><p>The bootstrap token and runner credential will be revoked. Any runner-owned sandboxes are requested for deletion; removal completes after runtime and network cleanup are confirmed.</p><p className="sb-help mt-3">An offline machine may receive the change later. Existing local expiry deadlines remain the hard limit.</p>{mutationError && <ErrorText>{mutationError}</ErrorText>}</Modal>}
  </section>;
}

function ProfileRequirements({ profile }: { profile: SandboxRunnerEnrollmentProfile }) {
  return <div className="sb-runner-prerequisites"><h3>Machine prerequisites</h3><p className="sb-help">{profile.host_os.charAt(0).toUpperCase()+profile.host_os.slice(1)} {profile.host_version} · {profile.architecture.toUpperCase()} on the existing approved gateway host. Installation requires machine administrator permission.</p><ul>{profile.prerequisites.map(requirement => <li key={requirement}>{requirement}</li>)}</ul><Reasons reasons={profile.blocked_reasons} /><p className="sb-help">The installer verifies the pinned public package and preloaded image. It does not install packages on every sandbox launch. Capacity remains one shared retained sandbox.</p><details className="sb-runner-pins"><summary>Approved machine and package identity</summary><dl><div><dt>Gateway</dt><dd><code>{profile.install.gateway.node_id}</code></dd></div><div><dt>Existing gateway container</dt><dd><code>{profile.install.gateway.container_id}</code></dd></div><div><dt>Controller</dt><dd>{profile.install.controller.url}</dd></div><div><dt>Source</dt><dd><code>{profile.install.source_sha}</code></dd></div><div><dt>Binary bundle checksum</dt><dd><code>{profile.install.bundle.sha256}</code></dd></div>{profile.install.images.map(image => <div key={image.template_id}><dt>Immutable sandbox image</dt><dd><code>{image.config_digest}</code></dd></div>)}</dl></details></div>;
}

function RunnerQualification({ enrollment, orgId, confirmed, onReviewed }: { enrollment: Enrollment; orgId: string; confirmed: boolean; onReviewed: (updated: Enrollment) => void }) {
  const qualification = enrollment.qualification;
  const [decision, setDecision] = useState<"approve" | "reject" | null>(null), [note, setNote] = useState(""), [acknowledged, setAcknowledged] = useState(false);
  const [pending, setPending] = useState(false), [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false), active = useRef(true);
  const currentReport = useRef("");
  currentReport.current = `${enrollment.id}:${qualification?.report_sha256 ?? ""}`;
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  useEffect(() => { setDecision(null); setNote(""); setAcknowledged(false); setError(null); }, [qualification?.report_sha256]);
  if (!qualification) return enrollment.state === "awaiting_connection" && enrollment.blocked_reasons.includes("native_qualification_required") ? <section className="sb-runner-qualification"><h3>Native qualification</h3><p>No qualification report has been submitted yet. Complete the installed machine's supported native qualification workflow, then refresh. Installation and connection alone do not qualify a host.</p></section> : null;
  const current = confirmed && !terminalStates.has(enrollment.state) && enrollment.state !== "pending_cleanup";
  const canApprove = current && qualification.decision === "pending" && qualification.approvable && !qualification.blocked_reasons.length && qualification.report.checks.length > 0 && qualification.report.checks.every(check=>check.result==="passed");
  const canReject = current && qualification.decision === "pending";
  async function submit() {
    if (!qualification || !decision || inFlight.current || !acknowledged || note.trim().length < 10 || (decision === "approve" ? !canApprove : !canReject)) return;
    const expectedIdentity = `${enrollment.id}:${qualification.report_sha256}`;
    inFlight.current = true; setPending(true); setError(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}/qualification-review", { params: { path: { orgId, enrollmentId: enrollment.id } }, body: { expected_report_sha256: qualification.report_sha256, decision, review_note: note.trim() } });
      if (!active.current) return;
      if (currentReport.current !== expectedIdentity) { setError("The report changed while review was pending. Review the current report before continuing."); return; }
      if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Qualification review could not be confirmed. Refresh the current report before retrying.")); return; }
      onReviewed(result.data); setDecision(null); setAcknowledged(false); setNote("");
    } catch { if (active.current) setError("Qualification review could not be confirmed. Refresh the current report before retrying."); }
    finally { inFlight.current = false; if (active.current) setPending(false); }
  }
  return <section className="sb-runner-qualification" aria-label="Native qualification review"><div className="sb-runner-qualification-heading"><h3>Native qualification</h3><span>{qualification.decision === "pending" ? "Awaiting administrator review" : qualification.decision === "approved" ? "Report approved" : "Report rejected"}</span></div>
    <p className="sb-help">Review the exact machine and immutable deployment below. Approval authorizes this report and identity; Ready still requires a fresh authenticated runner check.</p><Reasons reasons={qualification.blocked_reasons} />
    <dl className="sb-runner-report-pins"><div><dt>Report SHA256</dt><dd><code>{qualification.report_sha256}</code></dd></div><div><dt>Machine public key SHA256</dt><dd><code>{qualification.runner_spki_sha256}</code></dd></div><div><dt>Deployment profile</dt><dd><code>{qualification.report.profile_id}</code></dd></div><div><dt>Runtime binding SHA256</dt><dd><code>{qualification.report.binding_sha256}</code></dd></div><div><dt>Source</dt><dd><code>{qualification.report.source_sha}</code></dd></div><div><dt>Platform</dt><dd>{qualification.report.platform.os} {qualification.report.platform.version} · {qualification.report.platform.architecture}</dd></div><div><dt>Report submitted</dt><dd><time dateTime={qualification.submitted_at}>{new Date(qualification.submitted_at).toLocaleString()}</time></dd></div>{qualification.report.image_config_digests.map(digest=><div key={digest}><dt>Tested immutable image</dt><dd><code>{digest}</code></dd></div>)}</dl>
    <table className="sb-runner-checks" aria-label="Runner qualification checks"><thead><tr><th>Check</th><th>Result</th><th>Evidence</th></tr></thead><tbody>{qualification.report.checks.map(check=><tr key={check.code}><th scope="row">{check.code.replace(/_/g," ")}</th><td data-result={check.result}>{check.result}</td><td>{check.evidence}</td></tr>)}</tbody></table>
    {qualification.reviewed_at && <p className="sb-help">Reviewed <time dateTime={qualification.reviewed_at}>{new Date(qualification.reviewed_at).toLocaleString()}</time>{qualification.reviewed_by&&<> · Administrator ID {qualification.reviewed_by}</>}. {qualification.review_note}</p>}
    {qualification.decision === "approved" && enrollment.state !== "ready" && <p className="sb-help">The report is approved. Waiting for fresh runner health before sandbox creation can become available.</p>}
    {qualification.decision === "pending" && !decision && <div className="sb-runner-review-actions"><Button type="button" disabled={!canApprove||pending} onClick={()=>{setDecision("approve");setAcknowledged(false);setError(null);}}>Review approval</Button><Button type="button" variant="danger" disabled={!canReject||pending} onClick={()=>{setDecision("reject");setAcknowledged(false);setError(null);}}>Reject report</Button></div>}
    {decision && <div className="sb-runner-fields sb-runner-review-form"><h4>{decision==="approve"?"Approve this machine and report":"Reject this report"}</h4><Field label="Qualification review note"><textarea rows={3} minLength={10} maxLength={512} required disabled={pending} value={note} onChange={event=>setNote(event.target.value)} /></Field><p className="sb-help">Describe the evidence you reviewed. Keep tokens, private keys and other credentials out of review notes.</p><label className="sb-scope-choice"><input type="checkbox" disabled={pending} checked={acknowledged} onChange={event=>setAcknowledged(event.target.checked)} /><span>{decision==="approve"?"I reviewed this exact machine public key, deployment and native evidence. Approval must not replace missing or failed checks.":"I am rejecting this exact report; it will not qualify this runner for sandbox creation."}</span></label><div className="sb-runner-review-actions"><Button type="button" variant="ghost" disabled={pending} onClick={()=>{setDecision(null);setError(null);}}>Cancel review</Button><Button type="button" variant={decision==="reject"?"danger":"primary"} disabled={pending||!acknowledged||note.trim().length<10||(decision==="approve"?!canApprove:!canReject)} onClick={()=>void submit()}>{pending?"Submitting review…":decision==="approve"?"Approve qualified runner":"Reject qualification report"}</Button></div></div>}
    {error && <ErrorText>{error}</ErrorText>}
  </section>;
}
