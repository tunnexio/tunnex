import { useEffect, useId, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Loaded } from "../lib/api";
import { compactDateTime } from "../lib/format";
import { Badge, Button, DataTable, Field, Input, Modal } from "./ui";
import { MCPToolRows, modeSummary, parseRate, type MCPToolMode, type MCPToolRow } from "./MCPToolSettings";

type Inventory = components["schemas"]["AgentMCPInventory"];
type Policy = components["schemas"]["AgentMCPToolPolicy"];
type Approval = components["schemas"]["AgentMCPToolApprovalRequest"];
type OAuthConnection = components["schemas"]["AgentMCPOAuthConnection"];
type EffectiveMCP = components["schemas"]["AgentEffectiveMCPProfile"];
type Activity = components["schemas"]["AgentMCPToolActivity"];
type Tool = { endpoint: string; server_name: string; tool_name: string; input_schema_hash: string; description?: string; tool_definition_hash?: string; definition_state?: string };
const toolsFrom = (inventory: Inventory): Tool[] => (Array.isArray(inventory.snapshot.servers) ? inventory.snapshot.servers as Array<Record<string, unknown>> : []).flatMap((server) => {
  const endpoint = typeof server.endpoint === "string" ? server.endpoint : "";
  const serverName = typeof server.server_name === "string" ? server.server_name : "";
  return (Array.isArray(server.tools) ? server.tools as Array<Record<string, unknown>> : []).flatMap((tool) => {
    const name = typeof tool.name === "string" ? tool.name : "";
    const hash = typeof tool.input_schema_hash === "string" ? tool.input_schema_hash : "";
    const text = (value: unknown) => typeof value === "string" && value ? value : undefined;
    return endpoint && serverName && name && hash ? [{ endpoint, server_name: serverName, tool_name: name, input_schema_hash: hash, description: text(tool.description), tool_definition_hash: text(tool.tool_definition_hash), definition_state: text(tool.definition_state) }] : [];
  });
});

export const approvalOutcome: Record<Approval["state"], string> = { pending: "Waiting", approved: "Approved, not used yet", denied: "Denied", expired: "Expired", consumed: "Used" };
const EARLIER_REQUEST_LIMIT = 20;

export function approvalTimeLeft(expiresAt: string, now: number): string | null {
  const end = new Date(expiresAt).getTime();
  if (Number.isNaN(end)) return null;
  const seconds = Math.floor((end - now) / 1000);
  if (seconds <= 0) return "Out of time";
  const minutes = Math.floor(seconds / 60);
  return minutes > 0 ? `${minutes} min ${seconds % 60} s left` : `${seconds} s left`;
}

function argumentText(value: unknown): string {
  if (typeof value === "string") return value === "" ? "(empty)" : value;
  return JSON.stringify(value) ?? "";
}

/** What the approver is being asked to allow. The arguments are data from the agent: shown as text, never run. */
export function ApprovalArguments({ item }: { item: Approval }) {
  const entries = item.arguments ? Object.entries(item.arguments) : null;
  return <div role="group" aria-label="Arguments" className="mt-1 min-w-0">
    <div className="text-slate-500">Arguments</div>
    {entries && entries.length > 0 && <dl className="mt-1 grid gap-1">{entries.map(([name, value]) => <div key={name} className="grid min-w-0 gap-x-3 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]"><dt className="break-all font-mono text-slate-400">{name}</dt><dd className="whitespace-pre-wrap break-all font-mono">{argumentText(value)}</dd></div>)}</dl>}
    {item.arguments_truncated ? <p className="mt-1 text-slate-400">Shortened: the arguments were too long to show in full. Deny the call if you are not sure what it will do.</p> : entries === null ? <p className="mt-1 text-slate-500">The arguments were not kept for this request.</p> : entries.length === 0 ? <p className="mt-1 text-slate-500">This call has no arguments.</p> : null}
  </div>;
}

export function AgentMCPToolApprovalPanel({ orgId, deviceId, canApprove }: { orgId: string; deviceId: string; canApprove: boolean }) {
  const [requests, setRequests] = useState<Loaded<Approval[]> | null>(null); const [busy, setBusy] = useState<string | null>(null); const [confirmation, setConfirmation] = useState<Approval | null>(null); const [mutationError, setMutationError] = useState<string | null>(null);
  const [denying, setDenying] = useState<string | null>(null); const [denyError, setDenyError] = useState<string | null>(null); const [notice, setNotice] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const load = () => {
    if (!canApprove) { setRequests(null); return; }
    setRequests(null);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests", { params: { path: { orgId, deviceId } } })).then((result) => setRequests(result as Loaded<Approval[]>));
  };
  useEffect(load, [orgId, deviceId, canApprove]);
  const items = requests?.ok ? requests.data : [];
  const pending = items.filter((item) => item.state === "pending");
  const earlier = items.filter((item) => item.state !== "pending").sort((a, b) => String(b.requested_at ?? "").localeCompare(String(a.requested_at ?? "")));
  const counting = pending.some((item) => approvalTimeLeft(item.expires_at, now) !== null);
  useEffect(() => {
    if (!counting) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [counting]);
  const path = (item: Approval) => ({ params: { path: { orgId, deviceId, requestId: item.id } } });
  // Someone else decided, or the request ran out of time, between the list loading and the click.
  const alreadyHandled = () => { setConfirmation(null); setDenying(null); setMutationError(null); setDenyError(null); setNotice("This request was already handled. The list is now up to date."); load(); };
  const approve = async (item: Approval) => { setBusy(item.id); setMutationError(null); setNotice(null); const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/approve", path(item)); setBusy(null); if (apiErrorCode(result.error) === "mcp_tool_approval_not_pending") { alreadyHandled(); return; } if (result.error || !result.data) { setMutationError(apiErrorMessage(result.error, "Could not approve this step-up request. It may already have expired or been consumed. Refresh and try again.")); return; } setConfirmation(null); load(); };
  const deny = async (item: Approval) => {
    setBusy(item.id); setDenyError(null); setNotice(null);
    const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/deny", path(item));
    setBusy(null);
    if (apiErrorCode(result.error) === "mcp_tool_approval_not_pending") { alreadyHandled(); return; }
    if (result.error || !result.data) { setDenyError("Could not deny this request. Refresh and try again."); return; }
    setDenying(null); load();
  };
  const title = (item: Approval) => <div className="min-w-0 break-words"><span className="font-mono text-ink-heading">{item.tool_name}</span> <span className="text-slate-400">on {item.server_name}</span></div>;
  return <div data-testid="agent-mcp-tool-approvals" className="text-xs text-slate-300">
    <p className="text-slate-500">When a tool is set to Ask first, the agent&apos;s call waits here. Approving lets that one call run once, with exactly the arguments shown. <Link className="underline" to="/approvals">See every agent&apos;s requests in Approvals</Link>.</p>
    {notice && <p role="status" className="mt-2 text-slate-300">{notice}</p>}
    {!canApprove ? <p role="status" className="mt-2 text-slate-500">You do not have permission to review or approve step-up requests.</p> : requests === null ? <p role="status" className="mt-2 text-slate-500">Loading step-up requests…</p> : !requests.ok ? <><p role="alert" className="mt-2 text-danger">Step-up requests could not be loaded: {requests.error}</p><Button size="sm" variant="ghost" className="mt-2" onClick={load}>Retry</Button></> : items.length === 0 ? <p className="mt-2 text-slate-500">No step-up requests.</p> : <>
      {pending.length === 0 ? <p className="mt-2 text-slate-500">Nothing is waiting for a decision.</p> : <ul aria-label="Waiting for a decision" className="mt-2 grid gap-3">{pending.map((item) => {
        const left = approvalTimeLeft(item.expires_at, now);
        return <li key={item.id} aria-label={`${item.tool_name} on ${item.server_name}`} className="min-w-0 border-t border-white/10 pt-3">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">{title(item)}{left && <span className="text-slate-400">{left}</span>}</div>
          <ApprovalArguments item={item} />
          {denying === item.id ? <div className="mt-2 flex flex-wrap items-center gap-2"><span>Deny this call? The agent is told no and has to ask again.</span><Button size="sm" variant="danger" disabled={busy !== null} onClick={() => void deny(item)}>{busy === item.id ? "Denying…" : "Deny call"}</Button><Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => { setDenying(null); setDenyError(null); }}>Keep waiting</Button></div>
            : <div className="mt-2 flex flex-wrap items-center gap-2"><Button disabled={busy !== null} onClick={() => { setMutationError(null); setNotice(null); setDenying(null); setConfirmation(item); }}>Approve once</Button><Button variant="ghost" disabled={busy !== null} onClick={() => { setDenyError(null); setNotice(null); setDenying(item.id); }}>Deny</Button></div>}
          {denying === item.id && denyError && <p role="alert" className="mt-2 text-danger">{denyError}</p>}
        </li>;
      })}</ul>}
      {earlier.length > 0 && <><h4 className="mt-4 text-slate-400">Earlier requests</h4><ul aria-label="Earlier requests" className="mt-1 grid gap-1">{earlier.slice(0, EARLIER_REQUEST_LIMIT).map((item) => <li key={item.id} aria-label={`${item.tool_name} on ${item.server_name}`} className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-t border-white/10 pt-2">{title(item)}<span className="text-slate-400"><span>{approvalOutcome[item.state] ?? item.state}</span>{compactDateTime(item.requested_at) && <span title={new Date(item.requested_at).toLocaleString()}> · asked {compactDateTime(item.requested_at)}</span>}</span></li>)}</ul>{earlier.length > EARLIER_REQUEST_LIMIT && <p className="mt-2 text-slate-500">Showing the {EARLIER_REQUEST_LIMIT} most recent of {earlier.length} earlier requests.</p>}</>}
    </>}
    {confirmation && <Modal title={`Approve ${confirmation.tool_name} once?`} onDismiss={() => !busy && setConfirmation(null)} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setConfirmation(null)}>Cancel</Button><Button disabled={busy !== null} onClick={() => void approve(confirmation)}>{busy ? "Approving…" : mutationError ? "Retry approval" : "Approve once"}</Button></>}><p className="text-cell text-ink-tertiary">This authorizes one retried invocation of <strong>{confirmation.server_name} / {confirmation.tool_name}</strong>: the agent can run this call once, with exactly these arguments.</p><div className="mt-3 text-xs"><ApprovalArguments item={confirmation} /></div>{mutationError && <p role="alert" className="mt-3 text-danger">{mutationError}</p>}</Modal>}
  </div>;
}

type Rule = Policy["rules"][number];
type Choice = { mode: MCPToolMode; rate: string };
/** A tool keeps its identity (server address and name) when its description or inputs change. */
const toolIdentity = (tool: Pick<Tool, "endpoint" | "tool_name">) => `${tool.endpoint}\u0000${tool.tool_name}`;
/** The rule's own state wins: it is read with the policy, so it is newer than the inventory on the page. */
const definitionChanged = (rule: Rule, tool: Tool | undefined) => rule.definition_state === "changed" || (rule.definition_state == null && tool?.definition_state === "changed") || (tool !== undefined && rule.input_schema_hash !== tool.input_schema_hash);
/** Only what a save may send: the server's own notes on a rule are left out. */
const writable = (rule: Rule) => ({ endpoint: rule.endpoint, server_name: rule.server_name, tool_name: rule.tool_name, input_schema_hash: rule.input_schema_hash, step_up_required: rule.step_up_required ?? false, ...(rule.rate_limit_per_minute ? { rate_limit_per_minute: rule.rate_limit_per_minute } : {}), ...(rule.argument_constraints ? { argument_constraints: rule.argument_constraints } : {}) });

/**
 * This agent's own tool policy: Allow, Ask first or Off for each tool the gateway sees. With `endpoint` it
 * shows one MCP server and leaves the agent's choices for its other servers exactly as they are.
 */
export function AgentMCPToolPolicyPanel({ orgId, deviceId, inventory, canManage, enforcement, endpoint, onSaved }: { orgId: string; deviceId: string; inventory: Inventory; canManage: boolean; enforcement?: EffectiveMCP["enforcement"]; endpoint?: string; onSaved?: () => void }) {
  const tools = toolsFrom(inventory).filter((tool) => !endpoint || tool.endpoint === endpoint);
  const [policy, setPolicy] = useState<Loaded<Policy | null> | null>(null); const [choices, setChoices] = useState<Record<string, Choice>>({}); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState<Set<string>>(new Set()); const [notice, setNotice] = useState<string | null>(null);
  const hydrate = (current: Policy | null) => {
    const next: Record<string, Choice> = {};
    for (const rule of current?.rules ?? []) next[toolIdentity(rule)] = { mode: rule.step_up_required ? "ask" : "allow", rate: rule.rate_limit_per_minute?.toString() ?? "" };
    setChoices(next); setAccepted(new Set());
  };
  const loadPolicy = () => { if (!canManage) { setPolicy(null); return; } setPolicy(null); void loadOne(async () => { const result = await api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy", { params: { path: { orgId, deviceId } } }); return apiErrorCode(result.error) === "mcp_tool_policy_not_found" ? { data: null } : result; }).then((result) => { if (!result.ok) { setPolicy(result as Loaded<Policy | null>); return; } const current = (result.data as Policy | null) ?? null; setPolicy({ ok: true, data: current }); hydrate(current); }); };
  useEffect(loadPolicy, [orgId, deviceId, canManage]);
  const rules = policy?.ok && policy.data && Array.isArray(policy.data.rules) ? policy.data.rules : [];
  const ruleFor = (tool: Tool) => rules.find((item) => toolIdentity(item) === toolIdentity(tool));
  const changed = (tool: Tool) => { if (accepted.has(toolIdentity(tool))) return false; const rule = ruleFor(tool); return rule ? definitionChanged(rule, tool) : false; };
  const choiceFor = (tool: Tool): Choice => choices[toolIdentity(tool)] ?? { mode: "off", rate: "" };
  const save = async () => {
    setError(null); setNotice(null);
    const unreviewed = tools.find((tool) => choiceFor(tool).mode !== "off" && changed(tool));
    if (unreviewed) { setError(`Review ${unreviewed.tool_name} first: accept its new version, or turn it Off.`); return; }
    // The agent's choices for its other servers are sent back unchanged. One that changed would be accepted by this save, so it has to be reviewed first.
    const kept = endpoint ? rules.filter((rule) => rule.endpoint !== endpoint) : [];
    const keptChanged = kept.find((rule) => rule.definition_state === "changed");
    if (keptChanged) { setError(`Review ${keptChanged.tool_name} on ${keptChanged.server_name} first: that server changed it, and saving here would accept the change.`); return; }
    const invalid = tools.find((tool) => choiceFor(tool).mode !== "off" && !parseRate(choiceFor(tool).rate).ok);
    if (invalid) { setError(`Calls per minute for ${invalid.tool_name} must be a whole number above zero, or empty for no limit.`); return; }
    const body = [...kept.map(writable), ...tools.filter((tool) => choiceFor(tool).mode !== "off").map((tool) => { const choice = choiceFor(tool); const rate = parseRate(choice.rate); const constraints = ruleFor(tool)?.argument_constraints; return { endpoint: tool.endpoint, server_name: tool.server_name, tool_name: tool.tool_name, input_schema_hash: tool.input_schema_hash, step_up_required: choice.mode === "ask", ...(rate.ok && rate.rate ? { rate_limit_per_minute: rate.rate } : {}), ...(constraints ? { argument_constraints: constraints } : {}) }; })];
    setBusy(true);
    const result = await api.PUT("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy", { params: { path: { orgId, deviceId } }, body: { rules: body } });
    setBusy(false);
    if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not save the tool policy. If the server changed a tool, refresh the page and review it, then save again.")); return; }
    setPolicy({ ok: true, data: result.data as Policy }); hydrate(result.data as Policy); setNotice("Tool policy saved."); onSaved?.();
  };
  const accept = async (tool: Tool) => {
    if (!tool.tool_definition_hash) { setError("Refresh the page to load the new version before accepting it."); return; }
    setBusy(true); setError(null); setNotice(null);
    const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy/accept-definition", { params: { path: { orgId, deviceId } }, body: { endpoint: tool.endpoint, tool_name: tool.tool_name, tool_definition_hash: tool.tool_definition_hash } });
    setBusy(false);
    if (result.error || !result.data) {
      const code = apiErrorCode(result.error);
      setError(code === "mcp_tool_definition_stale" ? "This tool changed again while you were reading. Refresh the page and review it once more." : code === "mcp_tool_rule_not_found" ? "This tool is no longer in the saved policy. Refresh the page, then allow it again." : "Could not accept the new version. Refresh the page and try again.");
      return;
    }
    // Only this tool's rule moved; choices being edited for other tools stay as they are.
    setPolicy({ ok: true, data: result.data as Policy });
    setAccepted((previous) => new Set(previous).add(toolIdentity(tool)));
    setNotice(`New version accepted. ${tool.tool_name} can run again.`);
  };
  const atGateway = enforcement === "gateway";
  const servers = [...new Map(tools.map((tool) => [tool.endpoint, tool.server_name])).entries()];
  const rowsFor = (server: string): MCPToolRow[] => tools.filter((tool) => tool.endpoint === server).map((tool) => { const choice = choiceFor(tool); return { name: tool.tool_name, description: tool.description, mode: choice.mode, effect: null, rate: choice.rate, changed: choice.mode !== "off" && changed(tool), argumentLimits: Boolean(ruleFor(tool)?.argument_constraints) }; });
  const allRows = servers.flatMap(([server]) => rowsFor(server));
  return <div data-testid="agent-mcp-tool-policy" className="min-w-0 text-sm">
    <p className="text-ink-tertiary">{atGateway ? "Choose what this agent may do with each tool. A tool nobody has decided about is Off. The gateway checks every call this agent makes." : "Choose what this agent may do with each tool. A tool nobody has decided about is Off. The choices apply to calls made through the agent's local MCP address; a call sent straight to the server is not checked."}</p>
    {!canManage ? <p role="status" className="mt-2 text-ink-secondary">You do not have permission to view or change the MCP tool policy.</p> : policy === null ? <p role="status" className="mt-2 text-ink-secondary">Loading MCP tool policy…</p> : !policy.ok ? <><p role="alert" className="mt-2 text-danger">MCP tool policy could not be loaded: {policy.error}</p><Button size="sm" variant="ghost" className="mt-2" onClick={loadPolicy}>Retry</Button></> : <>
      {!policy.data && <p className="mt-1 text-ink-secondary">No choices are saved yet, so every tool is Off.</p>}
      {tools.length === 0 ? <p className="mt-2 text-ink-secondary">The gateway has not read any tools for this agent yet.</p> : servers.map(([server, serverName]) => <div key={server} className="mt-2 min-w-0">
        {servers.length > 1 && <h4 className="text-sm font-semibold text-ink-heading">{serverName}</h4>}
        <MCPToolRows label={`Tools on ${serverName}`} rows={rowsFor(server)} disabled={busy} markers="hide" limits
          onChange={(name, patch) => { const tool = tools.find((item) => item.endpoint === server && item.tool_name === name); if (!tool) return; setNotice(null); setChoices((old) => ({ ...old, [toolIdentity(tool)]: { ...(old[toolIdentity(tool)] ?? { mode: "off", rate: "" }), ...(patch.mode ? { mode: patch.mode } : {}), ...(patch.rate !== undefined ? { rate: patch.rate } : {}) } })); }}
          onAccept={(name) => { const tool = tools.find((item) => item.endpoint === server && item.tool_name === name); if (tool) void accept(tool); }} />
      </div>)}
      <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line pt-3"><Button disabled={busy || tools.length === 0} onClick={() => void save()}>{busy ? "Saving…" : "Save tool policy"}</Button>{tools.length > 0 && <span className="text-ink-secondary">{modeSummary(allRows)}</span>}</div>
    </>}
    {notice && <p role="status" className="mt-2 text-ink-body">{notice}</p>}{error && <p role="alert" className="mt-2 text-danger">{error}</p>}
  </div>;
}

const oauthOutcome: Record<string, { tone: "success" | "danger"; text: string }> = {
  connected: { tone: "success", text: "Sign-in completed. The agent can now use this MCP server." },
  expired: { tone: "danger", text: "Sign-in was not completed in the browser that started it, or it took longer than 10 minutes. Start again from this page and finish in the same browser." },
  failed: { tone: "danger", text: "The MCP server's sign-in was refused or could not be completed. Check the client ID, secret and scopes, then try again." },
};
const oauthFailure: Record<string, string> = {
  refresh_rejected: "The MCP server's sign-in is no longer accepted. The agent is not sending a credential until you connect again.",
  token_expired: "The MCP server's sign-in has expired and cannot be renewed. The agent is not sending a credential until you connect again.",
  consent_refused: "Sign-in was refused at the MCP server.",
  consent_browser_mismatch: "Sign-in was finished in a different browser from the one that started it, so it was not accepted.",
  exchange_failed: "The MCP server did not accept the sign-in. Check the client ID, secret and scopes.",
};
const oauthStateLabel: Record<string, string> = { connected: "Connected", pending_consent: "Waiting for sign-in", expired: "Needs connecting again", failed: "Not connected", disconnected: "Disconnected", discovered: "Not connected" };

export function AgentMCPOAuthPanel({ orgId, deviceId, inventory, canManage, outcome }: { orgId: string; deviceId: string; inventory: Inventory; canManage: boolean; outcome?: string }) {
  const discovered = (inventory.snapshot.oauth_discovery as { servers?: Array<{ endpoint?: string; status?: string; protected_resource?: string; authorization_servers?: string[]; scopes_supported?: string[] }> } | undefined)?.servers ?? [];
  const protectedServer = discovered.find((server) => server.status === "protected");
  const [clientId, setClientId] = useState(""); const [clientSecret, setClientSecret] = useState("");
  const [scopes, setScopes] = useState((protectedServer?.scopes_supported ?? []).join(" "));
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [confirming, setConfirming] = useState(false);
  const [connections, setConnections] = useState<Loaded<OAuthConnection[]> | null>(null);
  const loadConnections = () => { if (!canManage) { setConnections(null); return; } setConnections(null); void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-oauth-connections", { params: { path: { orgId, deviceId } } })).then((result) => setConnections(result as Loaded<OAuthConnection[]>)); };
  useEffect(loadConnections, [orgId, deviceId, canManage]);
  if (!protectedServer) return null;
  const current = connections?.ok ? connections.data.find((connection) => connection.endpoint === protectedServer.endpoint) : undefined;
  const connected = current?.state === "connected";
  const redirectURI = `${window.location.origin}/api/v1/mcp/oauth/callback`;
  const result = outcome ? oauthOutcome[outcome] : undefined;
  const start = async () => { if (!canManage || !protectedServer.endpoint || !protectedServer.protected_resource || !protectedServer.authorization_servers?.[0]) return; setBusy(true); setError(null); const submittedSecret = clientSecret; setClientSecret(""); const started = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-oauth-connections", { params: { path: { orgId, deviceId } }, body: { endpoint: protectedServer.endpoint, protected_resource: protectedServer.protected_resource, issuer: protectedServer.authorization_servers[0], scopes: scopes.split(/\s+/).filter(Boolean), client_id: clientId, ...(submittedSecret ? { client_secret: submittedSecret } : {}) } }); setBusy(false); if (started.error || !started.data) { setError("Could not start sign-in. Check the client ID and that the MCP server's sign-in service is reachable."); return; } window.location.assign((started.data as { authorization_url: string }).authorization_url); };
  const disconnect = async () => { if (!current) return; setBusy(true); setError(null); const removed = await api.DELETE("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-oauth-connections/{connectionId}", { params: { path: { orgId, deviceId, connectionId: current.id } } }); setBusy(false); setConfirming(false); if (!removed.response?.ok) { setError("Could not disconnect. Try again."); return; } loadConnections(); };
  return <div data-testid="agent-mcp-oauth" className="text-xs text-slate-300">
    {result && <p role={result.tone === "danger" ? "alert" : "status"} className={`mb-2 ${result.tone === "danger" ? "text-danger" : "text-success"}`}>{result.text}</p>}
    <p className="text-slate-500">This MCP server asks the agent to sign in. Tunnex keeps the sign-in here on the server and hands the agent a short-lived token in memory; nothing is shown on this page or stored on the agent.</p>
    {!canManage ? <p role="status" className="mt-2 text-slate-500">You do not have permission to manage MCP sign-in for this agent.</p> : connections === null ? <p role="status" className="mt-2 text-slate-500">Loading sign-in status…</p> : !connections.ok ? <><p role="alert" className="mt-2 text-danger">Sign-in status could not be loaded: {connections.error}</p><Button size="sm" variant="ghost" className="mt-2" onClick={loadConnections}>Retry</Button></> : <>
      {current && <div className="mt-2 text-slate-400">{current.endpoint} · <span className={connected ? "text-success" : current.state === "expired" || current.state === "failed" ? "text-danger" : ""}>{oauthStateLabel[current.state] ?? current.state}</span>{connected && current.token_expires_at ? ` · token renews automatically (current one until ${new Date(current.token_expires_at).toLocaleString()})` : ""}</div>}
      {current && !connected && current.failure_code && <p role="alert" className="mt-1 text-danger">{oauthFailure[current.failure_code] ?? "The MCP server's sign-in did not complete."}</p>}
      {connected ? (confirming
        ? <div className="mt-2 flex flex-wrap items-center gap-2"><span>The agent stops sending a credential to this MCP server straight away. You can connect again later.</span><Button size="sm" variant="danger" disabled={busy} onClick={() => void disconnect()}>Disconnect now</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => setConfirming(false)}>Keep connected</Button></div>
        : <Button size="sm" variant="ghost" className="mt-2" onClick={() => setConfirming(true)}>Disconnect</Button>)
        : <>
          <p className="mt-3 text-slate-400">Register this redirect address with the MCP server's sign-in service, then enter the client it gives you:</p>
          <p className="mt-1 flex flex-wrap items-center gap-2"><code className="break-all text-slate-200">{redirectURI}</code><Button size="sm" variant="ghost" onClick={() => void navigator.clipboard?.writeText(redirectURI)}>Copy</Button></p>
          <div className="mt-3 grid gap-2 sm:grid-cols-2"><Field label="Client ID"><Input value={clientId} onChange={(event) => setClientId(event.target.value)} /></Field><Field label="Client secret (optional)"><Input type="password" autoComplete="new-password" value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} /></Field><Field label="Requested scopes"><Input aria-label="Requested scopes" value={scopes} onChange={(event) => setScopes(event.target.value)} /></Field><div className="flex items-end"><Button disabled={busy || !clientId || !scopes.trim()} onClick={() => void start()}>{busy ? "Opening sign-in…" : current && current.state !== "discovered" && current.state !== "pending_consent" ? "Connect again" : "Continue to sign-in"}</Button></div></div>
          <p className="mt-2 text-slate-500">Finish the sign-in in this same browser within 10 minutes. A sign-in link opened anywhere else is refused.</p>
        </>}
    </>}
    {error && <p role="alert" className="mt-2 text-danger">{error}</p>}
  </div>;
}

const ACTIVITY_PAGE = 50;
const blockedReason: Record<string, string> = {
  policy: "not allowed by the tool rules", method: "this kind of request is not allowed", arguments: "the arguments are not allowed", schema: "the arguments do not fit the tool's inputs",
  rate_limit: "too many calls in a minute", step_up_required: "waiting for approval", step_up_denied: "approval was denied", definition_changed: "the tool changed and needs review",
  no_profile: "no MCP profile is assigned", no_inventory: "the tool list is not available yet", unavailable: "the rules could not be checked",
};
function activityResult(item: Activity): { text: string; tone: "ok" | "warn" | "danger" | "neutral" } {
  if (item.decision === "deny" || item.result_status === "not_forwarded") { const reason = blockedReason[item.reason]; return { text: reason ? `Blocked: ${reason}` : "Blocked", tone: "warn" }; }
  if (item.result_status === "ok") return { text: "Ran", tone: "neutral" };
  if (item.result_status === "error") return { text: "Failed", tone: "danger" };
  if (item.result_status === "upstream_unavailable") return { text: "Failed: the MCP server did not answer", tone: "danger" };
  return { text: "Still running", tone: "neutral" };
}
type ActivityState = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: Activity[]; next: string | null };
type ActivityShow = "all" | "denied" | "approved";
type ActivityFilters = { show: ActivityShow; from: string; to: string; server: string };
const NO_FILTERS: ActivityFilters = { show: "all", from: "", to: "", server: "" };
/** A day picked in the browser, as the instant it starts or ends in the person's own time zone. */
const dayEdge = (day: string, end: boolean): string | undefined => {
  if (!day) return undefined;
  const at = new Date(`${day}T${end ? "23:59:59.999" : "00:00:00"}`);
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
};
/** The filters as the server takes them, shared by the list and the CSV export so both show the same calls. */
function activityQuery(filters: ActivityFilters): Record<string, string | boolean> {
  const from = dayEdge(filters.from, false), to = dayEdge(filters.to, true);
  return { ...(filters.show === "denied" ? { decision: "deny" } : {}), ...(filters.show === "approved" ? { approved: true } : {}), ...(from ? { from } : {}), ...(to ? { to } : {}), ...(filters.server ? { server: filters.server } : {}) };
}
export function mcpActivityExportHref(orgId: string, deviceId: string, filters: ActivityFilters): string {
  const query = new URLSearchParams(Object.entries(activityQuery(filters)).map(([key, value]) => [key, String(value)])).toString();
  return `/api/v1/organizations/${encodeURIComponent(orgId)}/agents/${encodeURIComponent(deviceId)}/mcp-tool-activity/export${query ? `?${query}` : ""}`;
}
function activityApproval(item: Activity): ReactNode {
  if (!item.approval_request_id) return <span>Not needed</span>;
  const when = item.approved_at ? compactDateTime(item.approved_at) : "";
  if (item.approved_by_email) return <span title={item.approved_at ? new Date(item.approved_at).toLocaleString() : undefined}>Approved by {item.approved_by_email}{when ? `, ${when}` : ""}</span>;
  return <span title={item.approval_request_id}>Approved request {item.approval_request_id.slice(0, 8)}</span>;
}

/**
 * What the agent did through MCP, newest first, with filters the server applies: denied or approved
 * calls, a date range and one server. Arguments and results are never stored, so none are shown.
 */
export function AgentMCPToolActivityPanel({ orgId, deviceId, servers = [] }: { orgId: string; deviceId: string; /** The agent's MCP servers, for the server filter. */ servers?: Array<{ server_name: string; profile_name: string }> }) {
  const [state, setState] = useState<ActivityState>({ kind: "loading" }); const [filters, setFilters] = useState<ActivityFilters>(NO_FILTERS);
  const [olderBusy, setOlderBusy] = useState(false); const [olderError, setOlderError] = useState<string | null>(null); const [version, setVersion] = useState(0);
  const dayId = useId();
  const backwards = Boolean(filters.from && filters.to && filters.from > filters.to);
  const filtered = filters.show !== "all" || Boolean(filters.from || filters.to || filters.server);
  const fetchPage = (cursor?: string) => loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-activity", { params: { path: { orgId, deviceId }, query: { limit: ACTIVITY_PAGE, ...activityQuery(filters), ...(cursor ? { cursor } : {}) } as never } }));
  // Older fixtures answer with a bare list; the contract is { items, next_cursor }.
  const pageOf = (data: unknown): { items: Activity[]; next: string | null } => Array.isArray(data) ? { items: data as Activity[], next: null } : { items: (data as { items?: Activity[] } | undefined)?.items ?? [], next: (data as { next_cursor?: string | null } | undefined)?.next_cursor ?? null };
  useEffect(() => {
    if (backwards) return;
    let cancelled = false;
    setState({ kind: "loading" }); setOlderError(null);
    void fetchPage().then((result) => { if (!cancelled) setState(result.ok ? { kind: "ready", ...pageOf(result.data) } : { kind: "error", message: result.error }); });
    return () => { cancelled = true; };
  }, [orgId, deviceId, version, filters.show, filters.from, filters.to, filters.server, backwards]);
  const older = async () => {
    if (state.kind !== "ready" || !state.next) return;
    setOlderBusy(true); setOlderError(null);
    const result = await fetchPage(state.next);
    setOlderBusy(false);
    if (!result.ok) { setOlderError(`Older calls could not be loaded: ${result.error}`); return; }
    const page = pageOf(result.data);
    setState((current) => current.kind === "ready" ? { kind: "ready", items: [...current.items, ...page.items], next: page.next } : current);
  };
  const set = (patch: Partial<ActivityFilters>) => setFilters((current) => ({ ...current, ...patch }));
  const controls = <div role="group" aria-label="Filter MCP calls" className="grid min-w-0 gap-3">
    <div role="group" aria-label="Show" className="flex flex-wrap items-center gap-2">{([["all", "All calls"], ["denied", "Denied calls"], ["approved", "Approved calls"]] as const).map(([value, label]) => <Button key={value} size="sm" variant={filters.show === value ? "primary" : "ghost"} aria-pressed={filters.show === value} onClick={() => set({ show: value })}>{label}</Button>)}</div>
    <div className="flex min-w-0 flex-wrap items-end gap-3">
      <label htmlFor={`${dayId}-from`} className="grid gap-1 text-xs text-ink-secondary">From<input id={`${dayId}-from`} type="date" value={filters.from} max={filters.to || undefined} onChange={(event) => set({ from: event.target.value })} className="min-h-9 rounded-md border border-line bg-surface px-2 text-sm text-ink-body" /></label>
      <label htmlFor={`${dayId}-to`} className="grid gap-1 text-xs text-ink-secondary">To<input id={`${dayId}-to`} type="date" value={filters.to} min={filters.from || undefined} onChange={(event) => set({ to: event.target.value })} className="min-h-9 rounded-md border border-line bg-surface px-2 text-sm text-ink-body" /></label>
      {servers.length > 0 && <label htmlFor={`${dayId}-server`} className="grid gap-1 text-xs text-ink-secondary">Server<select id={`${dayId}-server`} value={filters.server} onChange={(event) => set({ server: event.target.value })} className="min-h-9 rounded-md border border-line bg-surface px-2 text-sm text-ink-body"><option value="">All servers</option>{servers.map((server) => <option key={server.server_name} value={server.server_name}>{server.profile_name}</option>)}</select></label>}
      {filtered && <Button size="sm" variant="ghost" onClick={() => setFilters(NO_FILTERS)}>Clear filters</Button>}
      {/* A plain link, not a script-started download: the browser handles it even where scripted downloads are blocked. */}
      {!backwards && <a className="inline-flex min-h-9 items-center text-sm underline sm:ml-auto" href={mcpActivityExportHref(orgId, deviceId, filters)} download>Download CSV</a>}
    </div>
    <p className="text-xs text-ink-secondary">The CSV holds the calls that match these filters, up to 10,000 rows.</p>
  </div>;
  return <div data-testid="agent-mcp-tool-activity" className="min-w-0">
    {controls}
    <div className="mt-3 min-w-0">{backwards ? <p role="alert">The From date is after the To date. Change one of them to see calls.</p>
      : state.kind === "loading" ? <p role="status">Loading MCP calls…</p>
        : state.kind === "error" ? <><p role="alert">MCP calls could not be loaded: {state.message}</p><Button size="sm" variant="ghost" className="mt-2" aria-label="Retry MCP calls" onClick={() => setVersion((value) => value + 1)}>Retry</Button></>
          : state.items.length === 0 ? (filtered ? <p>No calls match these filters.</p> : <><p className="text-ink-heading">No MCP calls yet.</p><p>Calls this agent makes to its MCP servers through the gateway are listed here.</p></>)
            : <>
              <DataTable caption="MCP calls" rows={state.items} rowKey={(item) => item.id} failed={false} filterable={false} pageSize={0} empty={<>No MCP calls yet.</>} columns={[
                { key: "time", header: "Time", cell: (item) => <span className="whitespace-nowrap" title={new Date(item.occurred_at).toLocaleString()}>{compactDateTime(item.occurred_at)}</span> },
                { key: "tool", header: "Tool", cell: (item) => <span className="break-all font-mono">{item.tool_name || item.method}</span> },
                { key: "server", header: "Server", cell: (item) => <span className="break-all">{item.server_name || item.endpoint}</span> },
                { key: "result", header: "Result", cell: (item) => { const result = activityResult(item); return <Badge tone={result.tone}>{result.text}</Badge>; } },
                { key: "approval", header: "Approval", cell: activityApproval },
              ]} />
              {state.next && <Button size="sm" variant="ghost" className="mt-3" disabled={olderBusy} onClick={() => void older()}>{olderBusy ? "Loading…" : "Show older calls"}</Button>}
              {olderError && <p role="alert" className="mt-2">{olderError}</p>}
            </>}</div>
  </div>;
}

const noticeDate = (at: Date) => new Intl.DateTimeFormat(undefined, { day: "numeric", month: "long", year: "numeric" }).format(at);
function hostOf(endpoint: string | null | undefined): string {
  try { return endpoint ? new URL(endpoint).hostname : ""; } catch { return ""; }
}
function EnforcementNotice({ tone, title, children }: { tone: "warn" | "danger"; title: string; children: ReactNode }) {
  const id = useId();
  return <div role="note" aria-labelledby={id} className="mt-3 min-w-0 text-xs"><Badge tone={tone}><span id={id} className="whitespace-normal text-ink-heading">{title}</span></Badge><p className="mt-1 text-ink-tertiary">{children}</p></div>;
}

/**
 * Where this agent's tool rules are applied, and what the administrator has to do about it. Driven only by
 * what the server reports for the agent's effective profile; nothing is shown when it did not say.
 */
export function MCPEnforcementNotices({ profile, now = new Date(), updateHref }: { profile: EffectiveMCP; now?: Date; /** The agent's Runtime tab, where "Update runtime" is. */ updateHref?: string }) {
  if (!profile.assigned) return null;
  const graceUntil = profile.direct_path_grace_until ? new Date(profile.direct_path_grace_until) : null;
  const inGrace = graceUntil !== null && !Number.isNaN(graceUntil.getTime()) && graceUntil.getTime() > now.getTime();
  const host = hostOf(profile.endpoint);
  // The runtime is updated in place: the agent is not removed or enrolled again, so nothing it has is lost.
  const howToUpdate = <> The agent keeps its identity, access and MCP settings. {updateHref ? <Link className="underline" to={updateHref}>Update runtime</Link> : "Use Update runtime on the agent's page."}</>;
  return <>
    {profile.enforcement === "gateway" && <p role="note" className="mt-3 text-xs text-ink-tertiary">Tool rules are applied at the gateway. This agent needs no network rule for the MCP server.</p>}
    {profile.enforcement === "agent_host" && (inGrace && graceUntil
      ? <EnforcementNotice tone="warn" title={`Update this agent's runtime before ${noticeDate(graceUntil)} to keep MCP working`}>The new version sends MCP calls through the gateway, which applies the tool rules; the older way is switched off after this date.{howToUpdate}</EnforcementNotice>
      : <EnforcementNotice tone="warn" title="Update this agent's runtime to keep MCP working">The new version sends MCP calls through the gateway, which applies the tool rules; the older way can be switched off at any time.{howToUpdate}</EnforcementNotice>)}
    {profile.enforcement === "unavailable" && <EnforcementNotice tone="danger" title="Upgrade this agent's gateway to use MCP">MCP is off for this agent because its gateway cannot apply tool rules yet. If the gateway is already up to date, update this agent&apos;s runtime.</EnforcementNotice>}
    {profile.direct_path_closable === false && <EnforcementNotice tone="warn" title="Tunnex cannot fully block direct access to this server">The agent&apos;s machine may still reach {host || "this server"} without going through the gateway. Use a private IP address for the server, or add an FQDN resource with the same name. For a public server with no sign-in, tool rules cannot be guaranteed.</EnforcementNotice>}
  </>;
}
