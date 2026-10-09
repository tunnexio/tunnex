import "../agents-workspace.css";
import "../resource-summary.css";
import { useEffect, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
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
  const [needsLegacyVerifier, setNeedsLegacyVerifier] = useState(false);
  const [runtimeState, setRuntimeState] = useState<{ orgId: string; enabled: boolean } | null>(null);
  const [runtimeError, setRuntimeError] = useState(false);
  const [readAttempt, setReadAttempt] = useState(0);
  const runtimeReady = visualStage ? runtimeEnabled : runtimeState?.orgId === orgId ? runtimeState.enabled : null;

  useEffect(() => {
    if (!enabled || visualStage) return;
    let cancelled = false;
    setRuntimeState(null); setRuntimeError(false);
    void api.GET("/api/v1/organizations/{orgId}", { params: { path: { orgId } } }).then(({ data, error: requestError }) => {
      if (cancelled) return;
      if (requestError || typeof data?.managed_agent_runtime_enabled !== "boolean") { setRuntimeError(true); return; }
      setRuntimeState({ orgId, enabled: data.managed_agent_runtime_enabled });
    }).catch(() => { if (!cancelled) setRuntimeError(true); });
    return () => { cancelled = true; };
  }, [enabled, orgId, visualStage, readAttempt]);

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
    // The only copy of a shown-once token-derived command is component memory.
    setCommand(null);
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
      if (requestError || !data) { setError(`${apiErrorMessage(requestError, "The bootstrap token could not be issued.")} The agent has not enrolled.`); return; }
      setCommand(agentBootstrapCommand(data.bootstrap_token, data.release));
      setNeedsLegacyVerifier(!data.release.verifier);
      setStage("token");
    } catch { setError("Could not reach the API. The agent has not enrolled."); } finally { setBusy(false); }
  }

  if (!enabled) return null;
  if (runtimeReady === null) return <Modal placement="right" title="Checking agent prerequisites" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={dismiss}>Close</Button>{runtimeError && <Button onClick={() => setReadAttempt(attempt => attempt + 1)}>Retry</Button>}</>}><div className="agents-enroll"><SetupSteps current={1} />{runtimeError ? <p role="alert">Could not verify runtime synchronization. Retry before installing an agent.</p> : <Loading label="Checking runtime synchronization…" />}</div></Modal>;
  if (!runtimeReady) return <Modal placement="right" title="Enable the agent runtime first" onDismiss={dismiss} actions={<Button variant="ghost" onClick={dismiss}>Close</Button>}><div className="agents-enroll"><SetupSteps current={1} /><p>Runtime synchronization is currently off for this organization.</p><a href="/settings?section=features&feature=agent-runtime">Configure AI Agent settings</a><details className="agents-enroll-help"><summary>About runtime synchronization</summary><div>Requires a paid plan. Enabling it does not grant model or MCP tool access.</div></details></div></Modal>;
  const shownStage = visualStage ?? stage;
  const gateway = gateways?.find(item => item.id === gatewayId);
  const visualCommand = command ?? "tunnex agent bootstrap --token tnx_fixture_one_time_token";
  if (shownStage === "token") return <OneTimeSecretModal title="Step 3 of 3, install agent" caption="Run this single-use command on the agent host. It is shown once. Enrollment remains pending; no agent is claimed as enrolled until the server reports it." secret={visualCommand} copyLabel="Copy command" downloadFilename="tunnex-agent.sh" onDismiss={dismiss}><div className="agents-enroll agents-enroll-secret"><SetupSteps current={3} /><HostRequirements legacy={needsLegacyVerifier} /></div></OneTimeSecretModal>;
  if (shownStage === "waiting") return <Modal placement="right" title="Waiting for enrollment" onDismiss={dismiss} actions={<Button onClick={dismiss}>Done</Button>}><div className="agents-enroll"><SetupSteps current={3} /><p>The command was issued. Enrollment remains pending until a future server-owned status contract reports it.</p><p>The token is shown once and cannot be recovered after closing.</p></div></Modal>;
  if (shownStage === "review") return <Modal placement="right" title="Step 2 of 3, review agent" onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={() => setStage("details")}>Back</Button><Button disabled={busy} onClick={() => void issue()}>{busy ? "Issuing…" : "Issue one-time command"}</Button></>}><div className="agents-enroll"><SetupSteps current={2} /><dl className="agents-enroll-facts tnx-resource-facts"><div><dt>Agent name</dt><dd>{name.trim()}</dd></div><div><dt>Gateway</dt><dd>{gateway?.name ?? "Selected gateway"}</dd></div><div><dt>Runtime sync</dt><dd>Enabled</dd></div></dl><p>Next, run the one-time command on the host to enroll this agent.</p><HostRequirements /><ErrorText>{error}</ErrorText></div></Modal>;
  return <Modal placement="right" title="Step 1 of 3, agent identity" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={dismiss}>Cancel</Button><Button disabled={busy || gateways === null} onClick={continueToReview}>Continue</Button></>}><div className="agents-enroll"><SetupSteps current={1} />{gateways === null ? <Loading label="Loading gateways…" /> : <><Field label="Agent name"><Input placeholder="e.g. production-runner" value={name} onChange={event => setName(event.target.value)} autoFocus /></Field><Field label="Gateway"><Select value={gatewayId} onChange={event => setGatewayId(event.target.value)}><option value="">Select a gateway</option>{gateways.map(item => <option key={item.id} value={item.id}>{item.name}{item.status ? `, ${item.status}` : ""}</option>)}</Select></Field>{gateways.length === 0 && !error && <p>No gateways available. <a href="/gateways">Set up a gateway</a> first.</p>}</>}<HostRequirements /><ErrorText>{error}</ErrorText></div></Modal>;
}
