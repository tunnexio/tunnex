import { useState } from "react";
import { Button } from "./ui";
import { agentHostRemoveCommand } from "../lib/agentview";

/**
 * "Remove the agent from this host": the command that clears a revoked agent's host so it can be enrolled
 * again. The command is the same for every agent and holds no secret, so it is shown without asking the
 * server for anything. It is offered for a revoked agent only; a working agent is revoked first.
 */
export function AgentHostRemoval({ when }: { /** One sentence on when to use it, for the place it is shown. */ when: string }) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const command = agentHostRemoveCommand();
  async function copyCommand() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(command);
      setCopy("copied");
    } catch { setCopy("failed"); }
  }
  return <>
    <p className="agent-detail-context">{when}</p>
    <pre data-testid="agent-host-remove-command" tabIndex={0} aria-label="Remove command" className="mt-3 max-h-64 overflow-auto rounded-md bg-ink-950 p-3 font-mono text-xs text-slate-300">{command}</pre>
    <p className="agent-detail-context">Run it on the agent&apos;s host as root or with sudo. It stops the runtime service, brings the tunnel down and removes the runtime, its credential, its state and its tunnel configuration. Nothing else on the host is changed, and no token is needed.</p>
    {copy === "failed" && <p role="status" className="agent-detail-context">Could not copy. Select the command and copy it by hand.</p>}
    <div className="agent-detail-panel-actions"><Button variant="ghost" size="sm" onClick={() => void copyCommand()}>{copy === "copied" ? "Copied" : "Copy command"}</Button></div>
  </>;
}
