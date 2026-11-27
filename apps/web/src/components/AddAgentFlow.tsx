import "../agents-workspace.css";
import "../resource-summary.css";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage } from "../lib/api";
import { useAgentFeatures } from "../lib/agentFeatures";
import { FeatureEnableInline } from "./FeatureEnableInline";
import { AGENT_PREREQ, agentBootstrapCommand } from "../lib/agentview";
import { Button, ErrorText, Field, Input, Loading, Modal, Select } from "./ui";
import { AgentInstallStep } from "./AgentInstallStep";

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
 * The browser issues the token and then shows what the server reports for it.
 * Enrollment and the tunnel are server facts; this flow never infers either
 * from a gateway or from the command having been copied.
 */
export function AddAgentFlow({ orgId, enabled = false, runtimeEnabled = true, onDismiss, visualStage }: { orgId: string; enabled?: boolean; runtimeEnabled?: boolean; onDismiss: () => void; visualStage?: AddAgentVisualStage }) {
  const [name, setName] = useState("");
  const [gatewayId, setGatewayId] = useState("");
  const [gateways, setGateways] = useState<Gateway[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<Stage>("details");
  const [issued, setIssued] = useState<{ command: string; tokenFileCommand: string; token: string; tokenId?: string; at: number } | null>(null);
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
    setIssued(null);
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
      // Neither variant of the command is given the token.
      setIssued({ command: agentBootstrapCommand(data.release), tokenFileCommand: agentBootstrapCommand(data.release, undefined, { tokenFile: true }), token: data.bootstrap_token, tokenId: data.token_id, at: Date.now() });
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
  // The gallery specimens show the same panel with example values and a fixed status.
  const specimen = "sh <<'TUNNEX_BOOTSTRAP'\n# install steps for this release\nTUNNEX_BOOTSTRAP";
  if (shownStage === "token" || shownStage === "waiting") return <AgentInstallStep orgId={orgId} command={issued?.command ?? specimen} tokenFileCommand={issued?.tokenFileCommand ?? specimen} token={issued?.token ?? "tnx_agent_example-shown-once"} tokenId={issued?.tokenId} origin={globalThis.location?.origin ?? ""} issuedAt={issued?.at ?? Date.now()} status={visualStage ? { id: "00000000-0000-4000-8000-000000000000", agent_name: "example-agent", state: "pending", expires_at: new Date(Date.now() + 3600_000).toISOString() } : undefined} onDismiss={dismiss}><SetupSteps current={3} /><HostRequirements legacy={needsLegacyVerifier} /></AgentInstallStep>;
  if (shownStage === "review") return <Modal placement="right" title="Step 2 of 3, review agent" onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={() => setStage("details")}>Back</Button><Button disabled={busy} onClick={() => void issue()}>{busy ? "Issuing…" : "Issue one-time command"}</Button></>}><div className="agents-enroll"><SetupSteps current={2} /><dl className="agents-enroll-facts tnx-resource-facts"><div><dt>Agent name</dt><dd>{name.trim()}</dd></div><div><dt>Gateway</dt><dd>{gateway?.name ?? "Selected gateway"}</dd></div><div><dt>Runtime sync</dt><dd>Enabled</dd></div></dl><p>Next, run the one-time command on the host to enroll this agent.</p><HostRequirements /><ErrorText>{error}</ErrorText></div></Modal>;
  return <Modal placement="right" title="Step 1 of 3, agent identity" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={dismiss}>Cancel</Button><Button disabled={busy || gateways === null} onClick={continueToReview}>Continue</Button></>}><div className="agents-enroll"><SetupSteps current={1} />{gateways === null ? <Loading label="Loading gateways…" /> : <><Field label="Agent name"><Input placeholder="e.g. production-runner" value={name} onChange={event => setName(event.target.value)} autoFocus /></Field><Field label="Gateway"><Select value={gatewayId} onChange={event => setGatewayId(event.target.value)}><option value="">Select a gateway</option>{gateways.map(item => <option key={item.id} value={item.id}>{item.name}{item.status ? `, ${item.status}` : ""}</option>)}</Select></Field>{gateways.length === 0 && !error && <p>No gateways available. <Link to="/gateways" onClick={dismiss}>Set up a gateway</Link> first.</p>}</>}<HostRequirements /><ErrorText>{error}</ErrorText></div></Modal>;
}
