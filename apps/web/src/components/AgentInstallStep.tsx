import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { INSTALL_TOKEN_FILE } from "../lib/agentview";
import { CopyButton } from "./CopyButton";
import { Button } from "./ui";

export type AgentInstallStatus = components["schemas"]["AgentBootstrapTokenStatus"];

/** How often the install status is read while the step is open. */
export const INSTALL_STATUS_POLL_MS = 3000;
/** After this long with no connected agent, the step shows what to check on the host. */
export const INSTALL_SLOW_AFTER_MS = 10 * 60 * 1000;

const clock = (at: string | null | undefined) => {
  const time = at ? new Date(at) : null;
  return time && !Number.isNaN(time.getTime()) ? time.toLocaleTimeString() : "";
};

function Line({ state, children }: { state: "done" | "waiting" | "problem"; children: ReactNode }) {
  const mark = state === "done" ? "✓" : state === "problem" ? "!" : "…";
  return <li data-state={state} className="flex min-w-0 items-start gap-2"><span aria-hidden="true" className={`mt-px w-4 shrink-0 text-center font-mono ${state === "done" ? "text-ok" : state === "problem" ? "text-danger" : "text-ink-tertiary"}`}>{mark}</span><span className={`min-w-0 break-words ${state === "waiting" ? "text-ink-secondary" : "text-ink-heading"}`}>{children}</span></li>;
}

/** The three facts the administrator is waiting for, in the order they happen. */
function InstallProgress({ status, readFailed, tracked }: { status: AgentInstallStatus | null; readFailed: boolean; tracked: boolean }) {
  if (!tracked) return <p className="text-ink-secondary">This server does not report install progress here. After you run the command, the agent appears in the agents list.</p>;
  if (!status) return <ul className="grid gap-1.5"><Line state={readFailed ? "problem" : "waiting"}>{readFailed ? "Could not read the install status. Trying again." : "Checking the install status…"}</Line></ul>;
  if (status.state === "revoked") return <ul className="grid gap-1.5"><Line state="problem">This install token was revoked, so the command can no longer be used. Close this panel and add the agent again.</Line></ul>;
  if (status.state === "expired") return <ul className="grid gap-1.5"><Line state="problem">This install token expired before an agent used it. Close this panel and add the agent again.</Line></ul>;
  const enrolled = status.state === "enrolled";
  const tunnel = status.tunnel ?? null;
  return <ul className="grid gap-1.5">
    <Line state={enrolled ? "done" : "waiting"}>{enrolled ? `Enrolled${clock(status.enrolled_at) ? ` at ${clock(status.enrolled_at)}` : ""}` : "Waiting for the agent to enroll. Run the command on the host."}</Line>
    {!enrolled ? <Line state="waiting">The tunnel connects after the agent enrolls.</Line>
      : !tunnel || !tunnel.gateway_reporting ? <Line state="waiting">Tunnel status unknown: this agent&apos;s gateway is not reporting connections right now.</Line>
        : tunnel.connected ? <Line state="done">Tunnel connected{clock(tunnel.last_handshake_at) ? ` at ${clock(tunnel.last_handshake_at)}` : ""}</Line>
          : <Line state="waiting">Waiting for the tunnel to connect.</Line>}
    {readFailed && <Line state="problem">Could not refresh the install status. Trying again.</Line>}
  </ul>;
}

function Check({ title, command, expect }: { title: string; command: string; expect: string }) {
  return <li className="min-w-0"><p className="text-ink-heading">{title}</p><div className="mt-1 flex min-w-0 flex-wrap items-center gap-2"><code className="min-w-0 break-all rounded bg-surface-inset px-2 py-1 font-mono text-ink-body">{command}</code><CopyButton text={command} label="Copy" aria-label={`Copy: ${command}`} /></div><p className="mt-1 text-ink-secondary">{expect}</p></li>;
}

/** Shown once ten minutes pass without a connected agent: the likely causes, each with a check to run on the host. */
function SlowInstallHelp({ origin }: { origin: string }) {
  return <section aria-label="What to check on the host" className="rounded-lg border border-line p-3">
    <h3 className="text-sm font-semibold text-ink-heading">Nothing has connected after ten minutes</h3>
    <p className="mt-1 text-ink-secondary">These are the three most likely causes. Run each check on the agent host.</p>
    <ol className="mt-2 grid list-decimal gap-3 pl-5">
      <Check title="The command was not run, or the wrong token was entered." command="sudo systemctl status tunnex-agent-runtime" expect="If the service is not found, the install did not finish: run the command again with the token shown above." />
      <Check title="The host cannot reach Tunnex over HTTPS." command={`curl -sI ${origin}`} expect="A line starting with HTTP means it can. No answer means a firewall, a proxy or DNS is in the way." />
      <Check title="WireGuard traffic (UDP) to the gateway is blocked." command="sudo wg show" expect={'A "latest handshake" line means the tunnel is up. None means UDP from this host to the gateway is blocked.'} />
    </ol>
  </section>;
}

/**
 * Step 3 of adding an agent. The command and the install token stay on screen while the status under
 * them follows the agent: waiting, enrolled, tunnel connected. Nothing here is inferred by the browser;
 * every line is what the server reports for this token.
 *
 * The token and the command are shown once and live only in the caller's memory, so the panel closes
 * only through its own button, never by Escape or a click outside.
 */
export function AgentInstallStep({ orgId, command, tokenFileCommand, token, tokenId, origin, issuedAt, status: fixedStatus, onDismiss, children }: {
  orgId: string;
  /** Asks for the token on the terminal. */
  command: string;
  /** Reads the token from the root-only file, for a host with no terminal. */
  tokenFileCommand: string;
  token: string;
  /** Identifies the token for its status. Without it (an older server) no progress is shown. */
  tokenId?: string;
  /** This control plane's address, for the reachability check. */
  origin: string;
  issuedAt: number;
  /** Design-gallery input only: a fixed status instead of live reads. */
  status?: AgentInstallStatus | null;
  onDismiss: () => void;
  children?: ReactNode;
}) {
  const [live, setLive] = useState<AgentInstallStatus | null>(null);
  const [readFailed, setReadFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [noTerminal, setNoTerminal] = useState(false);
  const status = fixedStatus !== undefined ? fixedStatus : live;
  const tracked = fixedStatus !== undefined || Boolean(tokenId);
  const connected = status?.state === "enrolled" && Boolean(status.tunnel?.gateway_reporting && status.tunnel.connected);
  const finished = connected || status?.state === "revoked" || status?.state === "expired";
  const inFlight = useRef(false);

  useEffect(() => {
    if (fixedStatus !== undefined || finished) return;
    let cancelled = false;
    const read = async () => {
      setNow(Date.now());
      if (!tokenId || inFlight.current) return;
      inFlight.current = true;
      try {
        const result = await api.GET("/api/v1/organizations/{orgId}/agents/bootstrap-tokens/{tokenId}", { params: { path: { orgId, tokenId } } });
        if (cancelled) return;
        if (result.error || !result.data || typeof result.data.state !== "string") setReadFailed(true);
        else { setLive(result.data); setReadFailed(false); }
      } catch { if (!cancelled) setReadFailed(true); }
      finally { inFlight.current = false; }
    };
    void read();
    const timer = window.setInterval(() => void read(), INSTALL_STATUS_POLL_MS);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [orgId, tokenId, fixedStatus, finished]);

  const slow = !finished && now - issuedAt >= INSTALL_SLOW_AFTER_MS;
  const shown = noTerminal ? tokenFileCommand : command;
  function download() {
    const url = URL.createObjectURL(new Blob([shown], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url; link.download = "tunnex-agent.sh";
    document.body.appendChild(link); link.click(); document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return <Dialog.Root open>
    <Dialog.Portal>
      <Dialog.Overlay className="fixed inset-0 z-[60] flex justify-end bg-black/65">
        <Dialog.Content
          onEscapeKeyDown={event => event.preventDefault()}
          onKeyDown={event => { if (event.key === "Escape") event.stopPropagation(); }}
          onPointerDownOutside={event => event.preventDefault()}
          onInteractOutside={event => event.preventDefault()}
          className="flex h-full max-h-[100dvh] w-full max-w-[560px] flex-col border-l border-line bg-surface focus:outline-none"
        >
          <div className="agents-enroll min-h-0 flex-1 overflow-y-auto p-4 sm:p-6">
            <div>
              <Dialog.Title className="text-lg font-semibold tracking-tight text-ink-heading">Step 3 of 3, install agent</Dialog.Title>
              <Dialog.Description className="mt-2 text-ink-secondary">Run the command on the agent host. The install token works once and expires in 1 hour. The command and the token are shown only now; this panel stays open while the agent connects.</Dialog.Description>
            </div>
            {children}
            <section aria-label="Install command" className="min-w-0">
              <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-sm font-semibold text-ink-heading">Install command</h3><div className="flex flex-wrap gap-2"><Button type="button" variant="ghost" size="sm" onClick={download}>Download</Button><CopyButton text={shown} label="Copy command" /></div></div>
              <pre data-testid="ots-secret" className="mt-2 max-h-48 overflow-auto rounded-md border border-line bg-surface-inset p-3 font-mono text-xs text-ink-body">{shown}</pre>
            </section>
            <section aria-label="Install token" className="min-w-0">
              <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-sm font-semibold text-ink-heading">Install token</h3><CopyButton text={token} label="Copy token" /></div>
              <code data-testid="ots-extra-secret" className="mt-2 block min-w-0 overflow-x-auto whitespace-nowrap rounded-md border border-line bg-surface-inset p-3 font-mono text-xs text-ink-body">{token}</code>
              <p className="mt-2">{noTerminal ? "The token goes in a file on the host, never in the command, so it stays out of the shell history." : "The command asks for this token when it runs, so the token stays out of your shell history."}</p>
              <label className="mt-2 flex items-start gap-2 text-ink-heading"><input type="checkbox" className="mt-0.5" checked={noTerminal} onChange={event => setNoTerminal(event.target.checked)} /><span>This host has no terminal</span></label>
              {noTerminal && <div role="group" aria-label="Supply the token from a file" className="mt-2 grid gap-2 rounded-lg border border-line p-3">
                <p>For a host you reach through automation, the command above reads the token from a file instead of asking for it.</p>
                <ol className="grid list-decimal gap-2 pl-5">
                  <li>Create <code className="break-all font-mono text-ink-body">{INSTALL_TOKEN_FILE}</code> on the host, containing only the install token, owned by root with mode 600. Use your configuration management tool, or an editor:<div className="mt-1 grid gap-1"><code className="break-all rounded bg-surface-inset px-2 py-1 font-mono text-ink-body">sudo install -m 600 /dev/null {INSTALL_TOKEN_FILE}</code><code className="break-all rounded bg-surface-inset px-2 py-1 font-mono text-ink-body">sudoedit {INSTALL_TOKEN_FILE}</code></div></li>
                  <li>Run the install command. It reads the file once and deletes it before it contacts anything.</li>
                </ol>
                <p>Do not write the token with <code className="font-mono">echo</code> or any other command line: that would save it in the shell history.</p>
              </div>}
            </section>
            <section aria-label="Install status" aria-live="polite" className="min-w-0">
              <h3 className="text-sm font-semibold text-ink-heading">Status</h3>
              <div className="mt-2"><InstallProgress status={status} readFailed={readFailed} tracked={tracked} /></div>
              {connected && status?.device_id && <p className="mt-2"><Link to={`/agents/${encodeURIComponent(status.device_id)}`} onClick={onDismiss}>Open {status.agent_name || "the agent"}</Link> to give it access.</p>}
            </section>
            {slow && <SlowInstallHelp origin={origin} />}
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-line p-4">
            <p className="min-w-0 text-xs text-ink-secondary">{connected ? "The agent is connected." : "Closing hides the token for good. The agent can still enroll with it until it expires."}</p>
            <Button type="button" variant={connected ? "primary" : "ghost"} onClick={onDismiss}>{connected ? "Done" : "I’ve saved it"}</Button>
          </div>
        </Dialog.Content>
      </Dialog.Overlay>
    </Dialog.Portal>
  </Dialog.Root>;
}
