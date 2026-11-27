import "../agents-workspace.css";
import "../resource-summary.css";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage } from "../lib/api";
import { useAgentFeatures } from "../lib/agentFeatures";
import { FeatureEnableInline } from "./FeatureEnableInline";
import { AGENT_PREREQ, agentBootstrapCommand } from "../lib/agentview";
import { Button, ErrorText, Field, Input, Loading, Modal, Select } from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";

type Gateway = { id: string; name: string; status?: string };
export type AddAgentVisualStage = "details" | "review" | "token" | "waiting";
type Stage = Exclude<AddAgentVisualStage, "waiting">;

function SetupSteps({ current }: { current: number }) {
  return <ol className="agents-enroll-steps" aria-label="Agent setup progress">{["Identity", "Review", "Install"].map((label, index) => <li key={label} aria-current={current === index + 1 ? "step" : undefined}><span>{index + 1}</span>{label}</li>)}</ol>;
}

function HostRequirements({ legacy = false }: { legacy?: boolean }) {
  return <details className="agents-enroll-help"><summary>Host requirements</summary><div><p>{AGENT_PREREQ}</p><p>The host must resolve and reach this control plane over HTTPS.</p>{legacy && <p>This older release requires a preinstalled release verifier. Upgrade the control plane for automatic verifier setup.</p>}</div></details>;
}

/**
 * Browser-side setup stops at token issuance. Enrollment completion remains a
 * server protocol fact; this flow never infers it from a gateway or command.
 */
export function AddAgentFlow({ orgId, enabled = false, runtimeEnabled = true, onDismiss, visualStage }: { orgId: string; enabled?: boolean; runtimeEnabled?: boolean; onDismiss: () => void; visualStage?: AddAgentVisualStage }) {
  const [name, setName] = useState("");
  const [gatewayId, setGatewayId] = useState("");
  const [gateways, setGateways] = useState<Gateway[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<Stage>("details");
  const [command, setCommand] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [needsLegacyVerifier, setNeedsLegacyVerifier] = useState(false);
  // Runtime synchronization is read fresh from the server, never from a remembered organization row.
  const [readAttempt, setReadAttempt] = useState(0);
  const features = useAgentFeatures(enabled && !visualStage ? orgId : undefined);
  const runtimeFeature = features.get("runtime_sync");
  // On, and included in this plan: a saved switch the plan cannot use must not start an install that fails.
  const runtimeReady = visualStage ? runtimeEnabled : runtimeFeature ? runtimeFeature.enabled && runtimeFeature.available : null;
  const runtimeError = !visualStage && (features.state.kind === "error" || (features.state.kind === "ready" && runtimeReady === null));

  useEffect(() => {
    if (!enabled) return;
    setError(""); setGateways(null);
    let cancelled = false;
    void api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } }).then(({ data, error: requestError }) => {
      if (cancelled) return;
      if (requestError || !data) { setError(apiErrorMessage(requestError, "Could not load gateways. Refresh to retry.")); setGateways([]); return; }
      setGateways(data as Gateway[]);
    }).catch(() => { if (!cancelled) { setError("Could not reach the API to load gateways."); setGateways([]); } });
    return () => { cancelled = true; };
  }, [enabled, orgId, readAttempt]);

  function dismiss() {
    // The only copy of the shown-once token is component memory.
    setCommand(null);
    setToken(null);
    setNeedsLegacyVerifier(false);
    onDismiss();
  }
  function continueToReview() {
    setError("");
    if (!name.trim() || !gatewayId) { setError("Enter an agent name and choose a gateway before continuing."); return; }
    setStage("review");
  }
  async function issue() {
    if (!enabled || runtimeReady !== true || !name.trim() || !gatewayId) return;
    setBusy(true); setError("");
    try {
      const { data, error: requestError } = await api.POST("/api/v1/organizations/{orgId}/agents/bootstrap-token", {
        params: { path: { orgId } }, body: { name: name.trim(), gateway_id: gatewayId },
      });
      if (requestError || !data) { setError(`${apiErrorMessage(requestError, "The install token could not be created.")} The agent has not enrolled.`); return; }
      // The token is kept apart from the command on purpose: the command is
      // pasted into a shell and asks for the token on a hidden prompt.
      setCommand(agentBootstrapCommand(data.release));
      setToken(data.bootstrap_token);
      setNeedsLegacyVerifier(!data.release.verifier);
      setStage("token");
    } catch { setError("Could not reach the API. The agent has not enrolled."); } finally { setBusy(false); }
  }

  if (!enabled) return null;
  if (runtimeReady === null) return <Modal placement="right" title="Checking agent prerequisites" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={dismiss}>Close</Button>{runtimeError && <Button onClick={() => { features.reload(); setReadAttempt(attempt => attempt + 1); }}>Retry</Button>}</>}><div className="agents-enroll"><SetupSteps current={1} />{runtimeError ? <p role="alert">Could not verify runtime synchronization. Retry before installing an agent.</p> : <Loading label="Checking runtime synchronization…" />}</div></Modal>;
  // The switch the flow needs is here, in the flow: no detour through Settings.
  if (!runtimeReady) return <Modal placement="right" title="Step 1 of 3, agent identity" onDismiss={dismiss} actions={<Button variant="ghost" onClick={dismiss}>Cancel</Button>}><div className="agents-enroll"><SetupSteps current={1} /><p>{runtimeFeature && !runtimeFeature.available ? "Adding an agent needs runtime synchronization, which your plan does not include." : "Adding an agent needs runtime synchronization, which is off for this organization. Turn it on here to continue."}</p><FeatureEnableInline orgId={orgId} feature="runtime_sync" features={features} /></div></Modal>;
  const shownStage = visualStage ?? stage;
  const gateway = gateways?.find(item => item.id === gatewayId);
  const visualCommand = command ?? "sh <<'TUNNEX_BOOTSTRAP'\n# install steps for this release\nTUNNEX_BOOTSTRAP";
  const visualToken = token ?? "tnx_agent_example-shown-once";
  if (shownStage === "token") return <OneTimeSecretModal title="Step 3 of 3, install agent" caption="Run the command on the agent host and paste the install token when it asks. The token works once, expires in 1 hour, and is shown only now. Enrollment remains pending; no agent is claimed as enrolled until the server reports it." secret={visualCommand} secretLabel="Install command" copyLabel="Copy command" downloadFilename="tunnex-agent.sh" extraSecret={{ label: "Install token", value: visualToken, copyLabel: "Copy token", note: "The command asks for this token when it runs, so the token stays out of your shell history." }} onDismiss={dismiss}><div className="agents-enroll agents-enroll-secret"><SetupSteps current={3} /><HostRequirements legacy={needsLegacyVerifier} /></div></OneTimeSecretModal>;
  if (shownStage === "waiting") return <Modal placement="right" title="Waiting for enrollment" onDismiss={dismiss} actions={<Button onClick={dismiss}>Done</Button>}><div className="agents-enroll"><SetupSteps current={3} /><p>The command was issued. Enrollment remains pending until a future server-owned status contract reports it.</p><p>The install token is shown once and cannot be recovered after closing. Until it is used or expires, it is listed under Pending install tokens, where it can be revoked.</p></div></Modal>;
  if (shownStage === "review") return <Modal placement="right" title="Step 2 of 3, review agent" onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={() => setStage("details")}>Back</Button><Button disabled={busy} onClick={() => void issue()}>{busy ? "Issuing…" : "Issue one-time command"}</Button></>}><div className="agents-enroll"><SetupSteps current={2} /><dl className="agents-enroll-facts tnx-resource-facts"><div><dt>Agent name</dt><dd>{name.trim()}</dd></div><div><dt>Gateway</dt><dd>{gateway?.name ?? "Selected gateway"}</dd></div><div><dt>Runtime sync</dt><dd>Enabled</dd></div></dl><p>Next, run the one-time command on the host to enroll this agent.</p><HostRequirements /><ErrorText>{error}</ErrorText></div></Modal>;
  return <Modal placement="right" title="Step 1 of 3, agent identity" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={dismiss}>Cancel</Button><Button disabled={busy || gateways === null} onClick={continueToReview}>Continue</Button></>}><div className="agents-enroll"><SetupSteps current={1} />{gateways === null ? <Loading label="Loading gateways…" /> : <><Field label="Agent name"><Input placeholder="e.g. production-runner" value={name} onChange={event => setName(event.target.value)} autoFocus /></Field><Field label="Gateway"><Select value={gatewayId} onChange={event => setGatewayId(event.target.value)}><option value="">Select a gateway</option>{gateways.map(item => <option key={item.id} value={item.id}>{item.name}{item.status ? `, ${item.status}` : ""}</option>)}</Select></Field>{gateways.length === 0 && !error && <p>No gateways available. <Link to="/gateways" onClick={dismiss}>Set up a gateway</Link> first.</p>}</>}<HostRequirements /><ErrorText>{error}</ErrorText></div></Modal>;
}
