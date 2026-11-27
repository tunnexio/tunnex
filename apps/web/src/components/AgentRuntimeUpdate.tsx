import { useEffect, useRef, useState } from "react";
import { Button } from "./ui";
import { api, apiErrorCode, type BootstrapRelease } from "../lib/api";
import { agentRuntimeUpdateCommand } from "../lib/agentview";

type UpdateState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; release: BootstrapRelease; command: string }
  | { kind: "error"; message: string };

/**
 * "Update runtime" for an agent that is already enrolled.
 *
 * The command is built from the release this control plane serves, read without issuing an install
 * token. It replaces the runtime on the host and nothing else, so the agent keeps its identity, group
 * membership, rules and MCP settings. Nothing is fetched until the administrator asks for the command.
 */
export function AgentRuntimeUpdate({ orgId }: { orgId: string }) {
  const [state, setState] = useState<UpdateState>({ kind: "idle" });
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const request = useRef(0);
  useEffect(() => { request.current += 1; setState({ kind: "idle" }); setCopy("idle"); return () => { request.current += 1; }; }, [orgId]);

  async function load() {
    const mine = ++request.current;
    setState({ kind: "loading" }); setCopy("idle");
    try {
      const { data, error } = await api.GET("/api/v1/organizations/{orgId}/agents/runtime-release", { params: { path: { orgId } } });
      if (mine !== request.current) return;
      if (error || !data) {
        setState({ kind: "error", message: apiErrorCode(error) === "bootstrap_unavailable"
          ? "The runtime release is not available from this Tunnex server right now, so there is no update command to run. Nothing was changed on the agent. Try again later."
          : "Could not load the update command. Nothing was changed on the agent." });
        return;
      }
      setState({ kind: "ready", release: data, command: agentRuntimeUpdateCommand(data) });
    } catch {
      if (mine === request.current) setState({ kind: "error", message: "Could not load the update command. Nothing was changed on the agent." });
    }
  }

  async function copyCommand(command: string) {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(command);
      setCopy("copied");
    } catch { setCopy("failed"); }
  }

  return <>
    <p className="agent-detail-context">Replaces the Tunnex runtime on this agent&apos;s host with the current release. The agent keeps its identity, access and MCP settings, and no install token is needed.</p>
    {state.kind === "error" && <p role="alert" className="agent-detail-context">{state.message}</p>}
    {state.kind === "ready" && <>
      <pre data-testid="runtime-update-command" tabIndex={0} aria-label="Update command" className="mt-3 max-h-64 overflow-auto rounded-md bg-ink-950 p-3 font-mono text-xs text-slate-300">{state.command}</pre>
      <p className="agent-detail-context">Run it on the agent&apos;s host as root or with sudo. It installs runtime {state.release.runtime.version} and restarts the agent service; if the service does not start, the previous runtime is put back.</p>
      {!state.release.verifier && <p className="agent-detail-context">This older release needs the signed release verifier to be installed on the host already; the command stops without changing anything if it is missing.</p>}
      {copy === "failed" && <p role="status" className="agent-detail-context">Could not copy. Select the command and copy it by hand.</p>}
    </>}
    <div className="agent-detail-panel-actions">
      {state.kind === "ready"
        ? <Button variant="ghost" size="sm" onClick={() => void copyCommand(state.command)}>{copy === "copied" ? "Copied" : "Copy command"}</Button>
        : <Button variant="ghost" size="sm" disabled={state.kind === "loading"} onClick={() => void load()}>{state.kind === "loading" ? "Loading…" : state.kind === "error" ? "Try again" : "Show update command"}</Button>}
    </div>
  </>;
}
