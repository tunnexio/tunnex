import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, listItems, loadOne } from "../lib/api";
import { Button, ErrorText, Field, Input, Modal, Select } from "./ui";
import { CopyButton } from "./CopyButton";
import { MCPToolRows, modeSummary, type MCPToolMode, type MCPToolRow } from "./MCPToolSettings";

type Preview = components["schemas"]["MCPConnectionPreview"];
type Connection = components["schemas"]["MCPConnection"];

/** Where the server is being connected: one agent, or an agent group. */
export type MCPConnectTarget = { kind: "agent"; id: string; name: string } | { kind: "group"; id: string; name: string };

/** How often the preview is read while the gateway fetches the tool list. */
export const PREVIEW_POLL_MS = 2000;
/** The gateway looks for new servers about every 30 seconds, so a tool list usually arrives within this time. */
export const PREVIEW_EXPECTED_MS = 35_000;
/** After this long with no answer the dialog stops waiting and offers to try again. */
export const PREVIEW_GIVE_UP_MS = 90_000;

/** The local address an MCP client on the agent host uses for a server. */
export const mcpLocalAddress = (serverName: string) => `http://127.0.0.1:17100/${serverName}`;
const SERVER_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;

const FAILURE: Record<string, string> = {
  unreachable: "The gateway could not reach this address. Check the address, and that the server is running and can be reached from the gateway.",
  unauthorized: "The server asks for a sign-in before it lists its tools. Connect it with every tool off, finish the sign-in on the agent's MCP tab, then choose the tools.",
  invalid: "Something answered at this address, but not as an MCP server. Check the path: many servers use /mcp.",
  no_gateway: "No gateway that can read this server is connected. Check that the agent's gateway is online and up to date, and that the agent is connected.",
  timed_out: "The gateway did not answer in time. Try again.",
};

type Stage =
  | { kind: "address" }
  | { kind: "reading"; previewId: string | null; startedAt: number }
  | { kind: "failed"; reason: string; message: string }
  | { kind: "tools"; preview: Preview | null }
  | { kind: "done"; connection: Connection };

/**
 * One guided action that connects an MCP server to an agent or an agent group: enter the address, the
 * gateway reads the tool list, choose Allow, Ask first or Off for each tool, save. The profile, the group
 * membership and the assignment are created by the server in one step; no network rule is needed.
 */
export function ConnectMCPServer({ orgId, target: fixedTarget, onDismiss, onConnected }: {
  orgId: string;
  /** Omitted on the MCP page, where the administrator first picks the agent or the group. */
  target?: MCPConnectTarget;
  onDismiss: () => void;
  onConnected?: (connection: Connection) => void;
}) {
  const [stage, setStage] = useState<Stage>({ kind: "address" });
  const [endpoint, setEndpoint] = useState("");
  const [name, setName] = useState("");
  const [serverName, setServerName] = useState("");
  const [rows, setRows] = useState<MCPToolRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const [choices, setChoices] = useState<{ groups: MCPConnectTarget[]; agents: MCPConnectTarget[] } | null>(null);
  const [choicesError, setChoicesError] = useState("");
  const [picked, setPicked] = useState<{ kind: "agent" | "group"; id: string }>({ kind: "group", id: "" });
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  useEffect(() => {
    if (fixedTarget) return;
    let cancelled = false;
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId }, query: { limit: 100 } } })),
    ]).then(([groups, agents]) => {
      if (cancelled) return;
      if (!groups.ok && !agents.ok) { setChoicesError("Could not load your agents and agent groups. Close this and try again."); return; }
      // Only what a server can be connected to now: a revoked, suspended or not yet enrolled agent cannot use one, and an archived group has no agents.
      const groupChoices = groups.ok && Array.isArray(groups.data) ? groups.data.filter((group) => !(group as { archived_at?: string | null }).archived_at).map((group) => ({ kind: "group" as const, id: group.id, name: group.name })) : [];
      const agentChoices = agents.ok ? listItems(agents.data).filter((agent) => agent.status === "active").map((agent) => ({ kind: "agent" as const, id: agent.device_id, name: agent.name })) : [];
      setChoices({ groups: groupChoices, agents: agentChoices });
      setPicked(groupChoices.length ? { kind: "group", id: "" } : { kind: "agent", id: "" });
    });
    return () => { cancelled = true; };
  }, [orgId, fixedTarget]);

  const target: MCPConnectTarget | undefined = fixedTarget ?? (picked.kind === "group" ? choices?.groups : choices?.agents)?.find((item) => item.id === picked.id);
  const previewId = stage.kind === "reading" ? stage.previewId : null;
  const readingSince = stage.kind === "reading" ? stage.startedAt : 0;

  function show(preview: Preview) {
    if (preview.state === "ready") {
      setRows(preview.tools.map((tool) => ({ name: tool.name, description: tool.description, mode: "off" as MCPToolMode, effect: null })));
      setName((current) => current.trim() || preview.server_name || "");
      setServerName((current) => current || preview.suggested_server_name || "");
      setStage({ kind: "tools", preview });
    } else if (preview.state === "failed") {
      const reason = preview.failure_reason ?? "";
      setStage({ kind: "failed", reason, message: FAILURE[reason] ?? "The gateway could not read the tool list from this address. Check the address and try again." });
    }
  }

  // While the gateway reads the tool list: re-read the preview, and keep the visible wait moving.
  useEffect(() => {
    if (stage.kind !== "reading") return;
    let cancelled = false, inFlight = false;
    const timer = window.setInterval(() => {
      const at = Date.now();
      setNow(at);
      if (at - readingSince >= PREVIEW_GIVE_UP_MS) { setStage({ kind: "failed", reason: "timed_out", message: FAILURE.timed_out }); return; }
      if (!previewId || inFlight) return;
      inFlight = true;
      void api.GET("/api/v1/organizations/{orgId}/mcp-connections/preview/{previewId}", { params: { path: { orgId, previewId } } }).then((result) => {
        if (cancelled) return;
        if (apiErrorCode(result.error) === "mcp_connection_preview_not_found") { setStage({ kind: "failed", reason: "timed_out", message: FAILURE.timed_out }); return; }
        if (result.data) show(result.data);
      }).catch(() => undefined).finally(() => { inFlight = false; });
    }, PREVIEW_POLL_MS);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [stage.kind, previewId, readingSince, orgId]);

  async function read() {
    if (!target || busy) return;
    let address: URL;
    try { address = new URL(endpoint.trim()); } catch { setError("Enter the full address of the MCP server, for example http://10.0.0.5:8080/mcp."); return; }
    if (address.protocol !== "http:" && address.protocol !== "https:") { setError("The address must start with http:// or https://."); return; }
    if (address.username || address.password) { setError("Leave any user name or password out of the address. A server that needs a sign-in is signed in to from the agent's MCP tab."); return; }
    setError(""); setBusy(true);
    const startedAt = Date.now();
    setNow(startedAt); setStage({ kind: "reading", previewId: null, startedAt });
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/mcp-connections/preview", { params: { path: { orgId } }, body: { endpoint: endpoint.trim(), ...(target.kind === "agent" ? { via_device_id: target.id } : { via_group_id: target.id }) } });
      if (!alive.current) return;
      if (result.error || !result.data) { setStage({ kind: "address" }); setError(apiErrorMessage(result.error, "Could not start reading the tool list. Try again.")); return; }
      if (result.data.state === "waiting") setStage({ kind: "reading", previewId: result.data.preview_id, startedAt });
      else show(result.data);
    } catch { if (alive.current) { setStage({ kind: "address" }); setError("Could not reach the API. Nothing was connected."); } }
    finally { if (alive.current) setBusy(false); }
  }

  async function save() {
    if (!target || stage.kind !== "tools" || busy) return;
    if (!name.trim()) { setError("Give the server a name."); return; }
    if (serverName && (!SERVER_NAME.test(serverName) || serverName === "mcp")) { setError(serverName === "mcp" ? "The address name \"mcp\" is kept for clients set up earlier. Choose another." : "The address name can use lower-case letters, digits and hyphens, and must start with a letter or digit."); return; }
    setError(""); setBusy(true);
    const hashes = new Map((stage.preview?.tools ?? []).map((tool) => [tool.name, tool.tool_definition_hash]));
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/mcp-connections", { params: { path: { orgId } }, body: {
        target: target.kind === "agent" ? { device_id: target.id } : { group_id: target.id },
        name: name.trim(), endpoint: endpoint.trim(),
        ...(serverName ? { server_name: serverName } : {}),
        ...(stage.preview ? { preview_id: stage.preview.preview_id } : {}),
        // Every tool is sent, Off ones too, so a marker set on a blocked tool is kept.
        tools: rows.map((row) => ({ tool_name: row.name, mode: row.mode, effect: row.effect, tool_definition_hash: hashes.get(row.name) })),
      } });
      if (!alive.current) return;
      if (result.error || !result.data) {
        const code = apiErrorCode(result.error);
        setError(code === "mcp_tool_definition_stale" ? "The server changed a tool while you were choosing. Read the tool list again and check it before saving."
          : code === "mcp_server_name_taken" ? "Another MCP server already uses this address name. Choose a different one."
            : apiErrorMessage(result.error, "Could not connect the server. Nothing was changed."));
        return;
      }
      setStage({ kind: "done", connection: result.data }); onConnected?.(result.data);
    } catch { if (alive.current) setError("Could not reach the API. Check the MCP servers list before trying again."); }
    finally { if (alive.current) setBusy(false); }
  }

  const title = fixedTarget ? `Connect MCP server to ${fixedTarget.name}` : "Connect MCP server";
  const close = () => { if (!busy) onDismiss(); };

  if (stage.kind === "done") {
    const { connection } = stage;
    const address = mcpLocalAddress(connection.tool_policy.server_name || connection.profile.server_name || "");
    return <Modal title="MCP server connected" size="wide" showClose onDismiss={onDismiss} actions={<Button onClick={onDismiss}>Done</Button>}>
      <div className="grid gap-3" role="status">
        <p><strong>{connection.profile.name}</strong> is connected to {target?.kind === "agent" ? target.name : `the agent group ${connection.group.name}`}. {modeSummary(rows)}.</p>
        {connection.group_created && <p className="text-ink-tertiary">The agent group <strong>{connection.group.name}</strong> was created to hold this server&apos;s tool choices. Add other agents to it to give them the same server.</p>}
        <div><p className="text-ink-tertiary">MCP clients on the agent host use this address:</p><p className="mt-1 flex min-w-0 flex-wrap items-center gap-2"><code className="min-w-0 break-all font-mono text-ink-heading">{address}</code><CopyButton text={address} label="Copy address" /></p></div>
        <p className="text-ink-tertiary">The agent needs no network rule for this server: its calls go through the gateway, which applies your choices.</p>
      </div>
    </Modal>;
  }

  if (stage.kind === "reading") {
    const elapsed = Math.max(0, now - stage.startedAt);
    const seconds = Math.floor(elapsed / 1000);
    return <Modal title={title} size="wide" showClose onDismiss={close} actions={<Button variant="ghost" onClick={() => { setStage({ kind: "address" }); setError(""); }}>Cancel</Button>}>
      <div className="grid gap-3" role="status" aria-live="polite">
        <p className="text-ink-heading">Reading the tool list from the gateway…</p>
        <div role="progressbar" aria-label="Reading the tool list" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.min(100, Math.round(elapsed / PREVIEW_EXPECTED_MS * 100))} className="h-1.5 w-full overflow-hidden rounded-full bg-surface-inset"><div className="h-full bg-ink-heading transition-[width] duration-500" style={{ width: `${Math.min(100, elapsed / PREVIEW_EXPECTED_MS * 100)}%` }} /></div>
        <p className="text-ink-tertiary">The gateway asks <span className="break-all font-mono">{endpoint.trim()}</span> for its tools. This usually takes about 35 seconds. {seconds} s so far.</p>
        {elapsed > PREVIEW_EXPECTED_MS && <p className="text-ink-secondary">This is taking longer than usual. The gateway may be busy; you can keep waiting or cancel and try again.</p>}
        <p className="text-ink-tertiary">Nothing is connected yet, and no tool is allowed until you save.</p>
      </div>
    </Modal>;
  }

  if (stage.kind === "failed") return <Modal title={title} size="wide" showClose onDismiss={close} actions={<><Button variant="ghost" onClick={close}>Close</Button>{stage.reason === "unauthorized" && <Button variant="ghost" onClick={() => { setRows([]); setError(""); setStage({ kind: "tools", preview: null }); }}>Connect with every tool off</Button>}<Button onClick={() => { setError(""); setStage({ kind: "address" }); }}>Change the address</Button><Button disabled={busy} onClick={() => void read()}>Try again</Button></>}>
    <div className="grid gap-2"><p role="alert" className="text-danger">The tool list could not be read.</p><p>{stage.message}</p><p className="break-all font-mono text-ink-tertiary">{endpoint.trim()}</p><p className="text-ink-tertiary">Nothing was connected.</p></div>
  </Modal>;

  if (stage.kind === "tools") return <Modal title={title} size="workspace" showClose onDismiss={close} actions={<><Button variant="ghost" disabled={busy} onClick={() => { setError(""); setStage({ kind: "address" }); }}>Back</Button><Button disabled={busy || !target} onClick={() => void save()}>{busy ? "Connecting…" : "Connect server"}</Button></>}>
    <div className="grid gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Server name"><Input value={name} disabled={busy} onChange={(event) => setName(event.target.value)} /></Field>
        <Field label="Address name"><Input value={serverName} disabled={busy} placeholder="chosen for you" onChange={(event) => setServerName(event.target.value.trim().toLowerCase())} /></Field>
      </div>
      <p className="text-ink-tertiary">Server: <span className="break-all font-mono">{endpoint.trim()}</span>.{serverName && <> MCP clients on the agent host will use <span className="break-all font-mono text-ink-body">{mcpLocalAddress(serverName)}</span>.</>}</p>
      {stage.preview === null ? <p role="note" className="text-ink-secondary">The server will be connected with every tool off. After the sign-in, the gateway reads the tool list and you choose the tools on the agent&apos;s MCP tab.</p>
        : rows.length === 0 ? <p role="note" className="text-ink-secondary">This server offers no tools right now. You can connect it and choose tools when it has some.</p> : <>
          <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-ink-tertiary">Choose what {target?.kind === "group" ? `the agents in ${target.name}` : target?.name ?? "the agent"} may do with each tool. Every tool starts Off. The marker is your own note about what a tool does; it changes nothing by itself.</p></div>
          <div className="flex flex-wrap items-center gap-2"><span className="text-ink-secondary">Set every tool to</span>{(["allow", "ask", "off"] as const).map((mode) => <Button key={mode} size="sm" variant="ghost" disabled={busy} onClick={() => setRows((current) => current.map((row) => ({ ...row, mode })))}>{mode === "allow" ? "Allow" : mode === "ask" ? "Ask first" : "Off"}</Button>)}<span className="ml-auto text-ink-secondary">{modeSummary(rows)}</span></div>
          <MCPToolRows rows={rows} disabled={busy} onChange={(tool, patch) => setRows((current) => current.map((row) => row.name === tool ? { ...row, ...patch } : row))} />
        </>}
      <ErrorText>{error}</ErrorText>
    </div>
  </Modal>;

  return <Modal title={title} size="wide" showClose onDismiss={close} actions={<><Button variant="ghost" onClick={close}>Cancel</Button><Button disabled={busy || !target || !endpoint.trim()} onClick={() => void read()}>Read tool list</Button></>}>
    <div className="grid gap-3">
      <p className="text-ink-tertiary">Enter the server&apos;s address. The gateway reads its tool list, then you choose what may be done with each tool. Nothing is connected until you save.</p>
      {!fixedTarget && (choicesError ? <p role="alert" className="text-danger">{choicesError}</p> : !choices ? <p role="status" className="text-ink-secondary">Loading your agents and agent groups…</p> : <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Connect to"><Select value={picked.kind} onChange={(event) => setPicked({ kind: event.target.value as "agent" | "group", id: "" })}><option value="group">An agent group</option><option value="agent">One agent</option></Select></Field>
        <Field label={picked.kind === "group" ? "Agent group" : "Agent"}><Select value={picked.id} onChange={(event) => setPicked({ kind: picked.kind, id: event.target.value })}><option value="">{picked.kind === "group" ? "Select a group" : "Select an agent"}</option>{(picked.kind === "group" ? choices.groups : choices.agents).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field>
        {picked.kind === "group" && choices.groups.length === 0 && <p className="text-ink-secondary sm:col-span-2">You have no agent groups yet. Choose one agent instead: a group is created for it.</p>}
        {picked.kind === "agent" && choices.agents.length === 0 && <p className="text-ink-secondary sm:col-span-2">You have no active agent. Add an agent first, then connect a server to it.</p>}
      </div>)}
      {target?.kind === "agent" && <p className="text-ink-tertiary">An agent group named for this agent is created to hold the server&apos;s tool choices, unless it already has one.</p>}
      <Field label="Server address"><Input autoFocus value={endpoint} placeholder="http://10.0.0.5:8080/mcp" inputMode="url" onChange={(event) => setEndpoint(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void read(); }} /></Field>
      <p className="text-ink-tertiary">Use the address the gateway can reach, without a user name or password.</p>
      <ErrorText>{error}</ErrorText>
    </div>
  </Modal>;
}
