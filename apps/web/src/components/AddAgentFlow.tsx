import { useEffect, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { AGENT_PREREQ, agentBootstrapCommand } from "../lib/agentview";
import { Button, ErrorText, Field, Input, Loading, Modal, Select } from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";

type Gateway = { id: string; name: string; status?: string };
export type AddAgentVisualStage = "details" | "review" | "token" | "waiting";
type Stage = Exclude<AddAgentVisualStage, "waiting">;

/**
 * Browser-side setup stops at token issuance. Enrollment completion remains a
 * server protocol fact; this flow never infers it from a gateway or command.
 */
export function AddAgentFlow({ orgId, enabled = false, onDismiss, visualStage }: { orgId: string; enabled?: boolean; onDismiss: () => void; visualStage?: AddAgentVisualStage }) {
  const [name, setName] = useState("");
  const [gatewayId, setGatewayId] = useState("");
  const [gateways, setGateways] = useState<Gateway[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<Stage>("details");
  const [command, setCommand] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    void api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } }).then(({ data, error: requestError }) => {
      if (cancelled) return;
      if (requestError || !data) { setError(apiErrorMessage(requestError, "Could not load gateways. Refresh to retry.")); setGateways([]); return; }
      setGateways(data as Gateway[]);
    }).catch(() => { if (!cancelled) { setError("Could not reach the API to load gateways."); setGateways([]); } });
    return () => { cancelled = true; };
  }, [enabled, orgId]);

  function dismiss() {
    // The only copy of a shown-once token-derived command is component memory.
    setCommand(null);
    onDismiss();
  }
  function continueToReview() {
    setError("");
    if (!name.trim() || !gatewayId) { setError("Enter an agent name and choose a gateway before continuing."); return; }
    setStage("review");
  }
  async function issue() {
    if (!enabled || !name.trim() || !gatewayId) return;
    setBusy(true); setError("");
    try {
      const { data, error: requestError } = await api.POST("/api/v1/organizations/{orgId}/agents/bootstrap-token", {
        params: { path: { orgId } }, body: { name: name.trim(), gateway_id: gatewayId },
      });
      if (requestError || !data) { setError(`${apiErrorMessage(requestError, "The bootstrap token could not be issued.")} The agent has not enrolled.`); return; }
      setCommand(agentBootstrapCommand(data.bootstrap_token, data.release));
      setStage("token");
    } catch { setError("Could not reach the API. The agent has not enrolled."); } finally { setBusy(false); }
  }

  if (!enabled) return null;
  const shownStage = visualStage ?? stage;
  const gateway = gateways?.find((item) => item.id === gatewayId);
  const visualCommand = command ?? "tunnex agent bootstrap --token tnx_fixture_one_time_token";
  if (shownStage === "token") return <OneTimeSecretModal title="Step 3 of 3 — run the one-time command" caption={<>Run this on the agent host. It contains a single-use token and is shown once. {AGENT_PREREQ} Token issuance is pending enrollment; no agent is claimed as enrolled from this command alone.</>} secret={visualCommand} copyLabel="Copy command" downloadFilename="tunnex-agent.sh" onDismiss={dismiss} />;
  if (shownStage === "waiting") return <Modal title="Waiting for enrollment" onDismiss={dismiss} actions={<Button onClick={dismiss}>Done</Button>}><p className="text-sm text-ink-secondary">The one-time command was issued. Enrollment remains pending until a future server-owned status contract reports it. Refreshing or closing this screen never reveals the token again.</p></Modal>;
  if (shownStage === "review") return <Modal title="Step 2 of 3 — review bootstrap" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={() => setStage("details")}>Back</Button><Button disabled={busy} onClick={() => void issue()}>{busy ? "Issuing…" : "Issue one-time command"}</Button></>}><div className="space-y-3"><p className="text-sm text-ink-secondary">Confirm the identity and gateway before creating a single-use token. This does not enroll an agent.</p><dl className="divide-y divide-white/10 rounded-md border border-white/10 text-sm"><div className="flex justify-between gap-4 px-3 py-2"><dt className="text-ink-tertiary">Agent name</dt><dd className="font-medium text-ink-heading">{name.trim()}</dd></div><div className="flex justify-between gap-4 px-3 py-2"><dt className="text-ink-tertiary">Gateway</dt><dd className="font-medium text-ink-heading">{gateway?.name ?? "Selected gateway"}</dd></div></dl><ErrorText>{error}</ErrorText></div></Modal>;
  return <Modal title="Step 1 of 3 — identity and gateway" onDismiss={dismiss} actions={<><Button variant="ghost" onClick={dismiss}>Cancel</Button><Button disabled={busy || gateways === null} onClick={continueToReview}>Continue</Button></>}><div className="space-y-4"><p className="text-sm text-ink-secondary">Choose where this managed agent will enroll. You will review these details before a one-time command is issued.</p>{gateways === null ? <Loading label="Loading gateways…" /> : <><Field label="Agent name"><Input value={name} onChange={(event) => setName(event.target.value)} autoFocus /></Field><Field label="Gateway"><Select value={gatewayId} onChange={(event) => setGatewayId(event.target.value)}><option value="">Select a gateway</option>{gateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}{gateway.status ? ` — ${gateway.status}` : ""}</option>)}</Select></Field></>}<ErrorText>{error}</ErrorText></div></Modal>;
}
