import { useCallback, useEffect, useRef, useState } from "react";
import { api, apiErrorMessage, loadOne, type SandboxRunnerEnrollment, type SandboxRunnerQualificationTrial as Trial } from "../lib/api";
import { sandboxConnectCommand } from "../lib/sandboxConnection";
import { sandboxPublicKeys } from "../lib/sandboxPublicKeys";
import { Button, ErrorText } from "./ui";
import { SavedSSHKeyPicker } from "./SavedSSHKeyPicker";
import { SandboxTerminalPicker, type SandboxTerminalSelection } from "./SandboxTerminalPicker";
import { SandboxRunnerCommand } from "./SandboxRunnerCommand";

const phaseLabels: Record<Trial["phases"][number]["code"], string> = {
  initial_ready: "Initial private SSH readiness",
  stopped: "Stop and retained identity",
  resume_ready: "Resume and private SSH readiness",
  offline_expiry: "Original expiry with the control connection offline",
  retired: "Confirmed runtime and network retirement",
};
const blockedMessages: Record<string, string> = {
  trial_authority_withdrawn: "Runner authority was withdrawn. New verification work is blocked while actual cleanup is confirmed.",
  trial_cancelled: "The verification was cancelled. The retained slot remains occupied until runtime and network removal are confirmed.",
  qualification_incomplete: "Native qualification proof is incomplete. Keep the supported verification command running through every phase, then refresh the server's report.",
};
function recentlySeen(lastSeenAt?: string) { return !!lastSeenAt && Date.now() - Date.parse(lastSeenAt) < 45_000; }
function completed(trial: Trial) { return trial.state === "complete" && !!trial.retired_at; }
function updateTrial(previous: Trial | null, next: Trial) {
  if (previous && previous.id !== next.id && Date.parse(previous.created_at) > Date.parse(next.created_at)) return previous;
  if (previous?.id === next.id && (previous.generation > next.generation || (previous.retired_at && !next.retired_at))) return previous;
  return next;
}
function stateLabel(trial: Trial, confirmed: boolean) {
  if (!confirmed) return "Trial status unconfirmed";
  if (trial.state === "complete") return trial.retired_at ? "Trial complete · retirement confirmed" : "Retirement unconfirmed";
  if (trial.state === "failed") return trial.retired_at ? "Trial failed · resources retired" : "Trial failed · cleanup pending";
  if (trial.state === "pending" && (trial.observed_state === "ready" || trial.phase !== "initial_ready")) return "Native verification in progress";
  return ({ pending: "Trial queued", running: "Native verification in progress", awaiting_expiry: "Waiting for the original expiry", cleanup_pending: "Waiting for confirmed cleanup" } as Record<string, string>)[trial.state] ?? "Trial status unavailable";
}

export function SandboxRunnerQualificationTrial({ orgId, enrollmentId, terminalGatewayId, enrollmentState, lastSeenAt, confirmed, initialTrial, onTrialChange }: {
  orgId: string; enrollmentId: string; terminalGatewayId?: string; enrollmentState: SandboxRunnerEnrollment["state"]; lastSeenAt?: string;
  confirmed: boolean; initialTrial?: Trial; onTrialChange?: () => void;
}) {
  const [trial, setTrial] = useState<Trial | null>(initialTrial ?? null), [formOpen, setFormOpen] = useState(false);
  const [terminal, setTerminal] = useState<SandboxTerminalSelection | null>(null), [keys, setKeys] = useState(""), [consent, setConsent] = useState(false);
  const [pending, setPending] = useState(false), [reading, setReading] = useState(false), [error, setError] = useState<string | null>(null), [readError, setReadError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false), [copyFailed, setCopyFailed] = useState(false);
  const [, updateDeadline] = useState(0);
  const active = useRef(true), inFlight = useRef(false), epoch = useRef(0), idempotency = useRef<{ intent: string; key: string } | null>(null);
  const form = useRef<HTMLDivElement>(null);
  const onChange = useRef(onTrialChange), previousState = useRef(initialTrial?.state);
  useEffect(() => { onChange.current = onTrialChange; }, [onTrialChange]);
  useEffect(() => { active.current = true; return () => { active.current = false; epoch.current++; }; }, []);
  useEffect(() => { if (initialTrial) setTrial(previous => updateTrial(previous, initialTrial)); }, [initialTrial]);
  useEffect(() => { if(formOpen)form.current?.querySelector<HTMLElement>("h4")?.focus(); }, [formOpen]);
  const trialId = trial?.id;
  const refresh = useCallback(async () => {
    if (!trialId || inFlight.current) return;
    const request = ++epoch.current; setReading(true);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}/qualification-trials/{trialId}", { params: { path: { orgId, enrollmentId, trialId } } }));
    if (!active.current || epoch.current !== request) return;
    setReading(false);
    if (!result.ok) { setReadError(result.error); return; }
    if (result.data.id !== trialId || result.data.enrollment_id !== enrollmentId) { setReadError("Trial identity did not match this enrollment. Refresh before continuing."); return; }
    setReadError(null); setTrial(previous => updateTrial(previous, result.data));
    if (previousState.current !== result.data.state) onChange.current?.();
    previousState.current = result.data.state;
  }, [orgId, enrollmentId, trialId]);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!trial || completed(trial) || (trial.state === "failed" && trial.retired_at)) return;
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => window.clearInterval(timer);
  }, [trial, refresh]);
  useEffect(() => {
    if (!trial) return;
    const remaining = Date.parse(trial.expires_at) - Date.now();
    if (remaining <= 0 || !Number.isFinite(remaining)) return;
    const timer = window.setTimeout(() => updateDeadline(value => value + 1), Math.min(remaining, 2_147_483_647));
    return () => window.clearTimeout(timer);
  }, [trial?.expires_at]);
  const fresh = confirmed && !readError;
  const reusable = !trial || (!!trial.retired_at && (trial.state === "complete" || trial.state === "failed"));
  const connected = recentlySeen(lastSeenAt);
  const canStart = fresh && connected && !!terminalGatewayId && enrollmentState === "awaiting_connection" && reusable;
  const connectionCommand = fresh && (enrollmentState==="awaiting_connection"||enrollmentState==="ready") && trial?.connection && trial.desired_state === "started" && trial.observed_state === "ready" && (trial.state === "pending" || trial.state === "running" || trial.state === "awaiting_expiry") && Date.now() < Date.parse(trial.expires_at) ? sandboxConnectCommand(trial.connection) : null;
  useEffect(() => { setCopied(false); setCopyFailed(false); }, [connectionCommand]);
  async function begin() {
    if (!canStart || !recentlySeen(lastSeenAt) || !terminal || !consent || inFlight.current) return;
    const parsed = sandboxPublicKeys(keys);
    if (!parsed.keys) { setError(parsed.error); return; }
    if (parsed.keys.length !== 1) { setError("Use exactly one SSH public key for this verification trial."); return; }
    const body = { terminal_device_id: terminal.id, ssh_public_keys: parsed.keys };
    const intent = JSON.stringify({ enrollmentId, ...body });
    if (idempotency.current?.intent !== intent) idempotency.current = { intent, key: crypto.randomUUID() };
    inFlight.current = true; epoch.current++; setPending(true); setError(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/sandbox-runner-enrollments/{enrollmentId}/qualification-trials", { params: { path: { orgId, enrollmentId } }, body: { ...body, idempotency_key: idempotency.current.key } });
      if (!active.current) return;
      if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Trial creation could not be confirmed. Retry with the same terminal and public keys; the request will reuse its idempotency key.")); return; }
      if (result.data.enrollment_id !== enrollmentId || result.data.terminal_device_id !== terminal.id) { setError("Trial identity did not match the request. Refresh this enrollment before continuing."); return; }
      setTrial(result.data); previousState.current = result.data.state; setFormOpen(false); setReadError(null); idempotency.current = null; onChange.current?.();
    } catch { if (active.current) setError("Trial creation could not be confirmed. Retry with the same terminal and public keys; the request will reuse its idempotency key."); }
    finally { inFlight.current = false; if (active.current) { setPending(false); setReading(false); } }
  }
  async function copyConnection() {
    if (!connectionCommand || !trial || Date.now() >= Date.parse(trial.expires_at)) return;
    try { await navigator.clipboard.writeText(connectionCommand); setCopied(true); setCopyFailed(false); }
    catch { setCopyFailed(true); }
  }
  return <section className="sb-runner-trial" aria-label="Native qualification trial"><div className="sb-runner-qualification-heading"><h3>Verify this machine</h3>{trial && <Button type="button" size="sm" variant="ghost" disabled={reading || pending} onClick={() => void refresh()}>Refresh trial</Button>}</div>
    <p className="sb-help">Run a controlled native trial before reviewing the runner. It uses the one retained sandbox slot and its original expiry deadline, at most 15 minutes. Installation and an online heartbeat do not replace this proof.</p>
    {!trial && <p className="sb-help mt-2">The trial verifies private SSH readiness, stop/resume, expiry while the control connection is offline, and actual runtime and network cleanup.</p>}
    {!terminalGatewayId && <ErrorText>The approved profile has no terminal gateway. An operator must configure its terminal binding before this machine can be verified.</ErrorText>}
    {readError && <ErrorText>{readError} Trial progress and connection instructions are unconfirmed until a successful refresh.</ErrorText>}
    {!fresh && !readError && <p className="sb-help mt-2">Refresh runner status before starting a trial or relying on its connection instructions.</p>}
    {fresh && !connected && enrollmentState === "awaiting_connection" && <p className="sb-help mt-2">Wait for a fresh authenticated runner connection before starting verification. Refresh after the installed runner connects.</p>}
    {enrollmentState === "offline" && <p className="sb-help mt-2">Reconnect the existing runner before starting a new trial.</p>}
    {(!trial || reusable) && !formOpen && <Button type="button" className="mt-3" disabled={!canStart || pending} onClick={() => { setFormOpen(true); setConsent(false); setError(null); }}>{trial ? "Start new qualification trial" : "Start qualification trial"}</Button>}
    {formOpen && <div ref={form} className="sb-runner-fields sb-runner-trial-form"><h4 tabIndex={-1}>Choose your terminal and public key</h4><SandboxTerminalPicker orgId={orgId} gatewayId={terminalGatewayId} value={terminal?.id ?? ""} onChange={setTerminal} /><SavedSSHKeyPicker orgId={orgId} value={keys} onChange={setKeys} /><label className="sb-scope-choice"><input type="checkbox" disabled={pending} checked={consent} onChange={event => setConsent(event.target.checked)} /><span>I authorize this bounded verification and can ask the machine administrator to run its command on the enrolled host. It will stop/resume the trial sandbox and test its original expiry and cleanup.</span></label><p className="sb-help">Use one normal SSH public key. Your private key stays local. The trial has no optional skills or additional outbound access.</p><div className="sb-runner-review-actions"><Button type="button" variant="ghost" disabled={pending} onClick={() => { setFormOpen(false); setError(null); }}>Cancel trial setup</Button><Button type="button" disabled={!canStart || pending || !terminal || !consent} onClick={() => void begin()}>{pending ? "Requesting trial…" : "Create verification trial"}</Button></div></div>}
    {error && <ErrorText>{error}</ErrorText>}
    {trial && <div className="sb-runner-trial-progress"><p role="status" className="sb-runner-state">{stateLabel(trial, fresh)}</p><p className="sb-help">Original deadline: <time dateTime={trial.expires_at}>{new Date(trial.expires_at).toLocaleString()}</time>. Stop, resume, disconnecting and closing this screen do not extend it.</p>
      <ol className="sb-runner-trial-phases" aria-label="Qualification phases">{trial.phases.map(phase => <li key={phase.code} data-state={phase.state}><span>{phaseLabels[phase.code]}</span><span>{phase.state}{phase.observed_at && <> · <time dateTime={phase.observed_at}>{new Date(phase.observed_at).toLocaleTimeString()}</time></>}</span></li>)}</ol>
      {trial.blocked_reasons.length > 0 && <ul className="sb-runner-reasons">{trial.blocked_reasons.map(reason => <li key={reason}>{blockedMessages[reason] ?? reason.replace(/_/g, " ")}</li>)}</ul>}
      {!completed(trial) && trial.state !== "failed" && <><p>Run this public command on the same installed gateway host. Review its machine administrator prompts and keep it running through the controlled verification.</p><SandboxRunnerCommand command={trial.qualification_command} kind="qualification" disabled={!fresh} /></>}
      {connectionCommand && <div className="sb-runner-trial-connection"><p className="sb-help">Private SSH is currently confirmed for the trial. Connect from your selected terminal device with your normal SSH key.</p><div className="sb-command"><div><span>OPTIONAL / VERIFY FROM YOUR TERMINAL</span><Button type="button" size="sm" variant="ghost" onClick={() => void copyConnection()}>Copy trial SSH command</Button></div><pre>{connectionCommand}</pre></div>{copied && <p role="status" className="sb-help">Trial SSH command copied.</p>}{copyFailed && <ErrorText>Copy failed. Select and copy the command above.</ErrorText>}</div>}
      {completed(trial) && <p>The server confirms that the trial resources retired. Review the resulting native qualification report. Approval and fresh runner health are still required before enabling creation.</p>}
      {trial.state === "failed" && <p>The verification failed. Review the machine's public failure output and the server's blocked reasons. {trial.retired_at ? "After correcting the cause, start a new trial with a fresh request." : "The retained slot remains occupied until runtime and network cleanup are confirmed."}</p>}
      {!trial.retired_at && <p className="sb-help">To cancel an active trial, withdraw runner access using Revoke runner. This requests deletion; the slot becomes reusable only after actual cleanup is confirmed.</p>}
    </div>}
  </section>;
}
