import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Loaded } from "../lib/api";
import { compactDateTime } from "../lib/format";
import { Button, Field, Input, Modal } from "./ui";

type Inventory = components["schemas"]["AgentMCPInventory"];
type Policy = components["schemas"]["AgentMCPToolPolicy"];
type Approval = components["schemas"]["AgentMCPToolApprovalRequest"];
type OAuthConnection = components["schemas"]["AgentMCPOAuthConnection"];
type Tool = { endpoint: string; server_name: string; tool_name: string; input_schema_hash: string };
const toolsFrom = (inventory: Inventory): Tool[] => (Array.isArray(inventory.snapshot.servers) ? inventory.snapshot.servers as Array<Record<string, unknown>> : []).flatMap((server) => {
  const endpoint = typeof server.endpoint === "string" ? server.endpoint : "";
  const serverName = typeof server.server_name === "string" ? server.server_name : "";
  return (Array.isArray(server.tools) ? server.tools as Array<Record<string, unknown>> : []).flatMap((tool) => {
    const name = typeof tool.name === "string" ? tool.name : "";
    const hash = typeof tool.input_schema_hash === "string" ? tool.input_schema_hash : "";
    return endpoint && serverName && name && hash ? [{ endpoint, server_name: serverName, tool_name: name, input_schema_hash: hash }] : [];
  });
});

const approvalOutcome: Record<Approval["state"], string> = { pending: "Waiting", approved: "Approved, not used yet", denied: "Denied", expired: "Expired", consumed: "Used" };
const EARLIER_REQUEST_LIMIT = 20;

function timeLeft(expiresAt: string, now: number): string | null {
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
function ApprovalArguments({ item }: { item: Approval }) {
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
  const counting = pending.some((item) => timeLeft(item.expires_at, now) !== null);
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
    <p className="text-slate-500">When a tool needs approval, the agent&apos;s call waits here. Approving lets that one call run once, with exactly the arguments shown.</p>
    {notice && <p role="status" className="mt-2 text-slate-300">{notice}</p>}
    {!canApprove ? <p role="status" className="mt-2 text-slate-500">You do not have permission to review or approve step-up requests.</p> : requests === null ? <p role="status" className="mt-2 text-slate-500">Loading step-up requests…</p> : !requests.ok ? <><p role="alert" className="mt-2 text-danger">Step-up requests could not be loaded: {requests.error}</p><Button size="sm" variant="ghost" className="mt-2" onClick={load}>Retry</Button></> : items.length === 0 ? <p className="mt-2 text-slate-500">No step-up requests.</p> : <>
      {pending.length === 0 ? <p className="mt-2 text-slate-500">Nothing is waiting for a decision.</p> : <ul aria-label="Waiting for a decision" className="mt-2 grid gap-3">{pending.map((item) => {
        const left = timeLeft(item.expires_at, now);
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

export function AgentMCPToolPolicyPanel({ orgId, deviceId, inventory, canManage }: { orgId: string; deviceId: string; inventory: Inventory; canManage: boolean }) {
  const tools = toolsFrom(inventory); const [policy, setPolicy] = useState<Loaded<Policy | null> | null>(null); const [selected, setSelected] = useState<Set<string>>(new Set()); const [controls, setControls] = useState<Record<string, { rate: string; stepUp: boolean; constraints: string }>>({}); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const key = (tool: Tool) => `${tool.endpoint}\u0000${tool.server_name}\u0000${tool.tool_name}\u0000${tool.input_schema_hash}`;
  const loadPolicy = () => { if (!canManage) { setPolicy(null); setSelected(new Set()); return; } setPolicy(null); void loadOne(async () => { const result = await api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy", { params: { path: { orgId, deviceId } } }); return apiErrorCode(result.error) === "mcp_tool_policy_not_found" ? { data: null } : result; }).then((result) => { if (!result.ok) { setPolicy(result as Loaded<Policy | null>); setSelected(new Set()); return; } if (result.data) { const current = result.data as Policy; setPolicy({ ok: true, data: current }); setSelected(new Set(current.rules.map((rule) => key(rule)))); setControls(Object.fromEntries(current.rules.map((rule) => [key(rule), { rate: rule.rate_limit_per_minute?.toString() ?? "", stepUp: rule.step_up_required ?? false, constraints: rule.argument_constraints ? JSON.stringify(rule.argument_constraints) : "" }]))); } else { setPolicy({ ok: true, data: null }); setSelected(new Set()); } }); };
  useEffect(loadPolicy, [orgId, deviceId, canManage]);
  const save = async () => { setBusy(true); setError(null); let rules; try { rules = tools.filter((tool) => selected.has(key(tool))).map((tool) => { const control = controls[key(tool)] ?? { rate: "", stepUp: false, constraints: "" }; const rate = Number(control.rate); const constraints = control.constraints ? JSON.parse(control.constraints) : undefined; if (control.constraints && (!constraints || !Array.isArray(constraints.required) || !constraints.properties || typeof constraints.properties !== "object" || Array.isArray(constraints.properties))) { throw new Error('Argument constraints need a required array and a properties object, for example {"required":[],"properties":{}}.'); } return { ...tool, step_up_required: control.stepUp, ...(Number.isInteger(rate) && rate > 0 ? { rate_limit_per_minute: rate } : {}), ...(constraints ? { argument_constraints: constraints } : {}) }; }); } catch (cause) { setBusy(false); setError(cause instanceof SyntaxError ? "Argument constraints must be valid JSON." : cause instanceof Error ? cause.message : "Argument constraints must be valid JSON."); return; } const result = await api.PUT("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy", { params: { path: { orgId, deviceId } }, body: { rules } }); setBusy(false); if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not save the MCP tool policy. Check argument constraints and rate limits, then refresh inventory if the tool changed.")); return; } setPolicy({ ok: true, data: result.data as Policy }); };
  return <div data-testid="agent-mcp-tool-policy" className="text-xs text-slate-300"><p className="text-slate-500">Default deny. Only checked tools may pass through the agent’s explicit local MCP proxy; direct upstream use is not protected.</p>{!canManage ? <p role="status" className="mt-2 text-slate-500">You do not have permission to view or change the MCP tool policy.</p> : policy === null ? <p role="status" className="mt-2 text-slate-500">Loading MCP tool policy…</p> : !policy.ok ? <><p role="alert" className="mt-2 text-danger">MCP tool policy could not be loaded: {policy.error}</p><Button size="sm" variant="ghost" className="mt-2" onClick={loadPolicy}>Retry</Button></> : <>{policy.data ? <p className="mt-1 text-slate-500">Current version {policy.data.version} · based on inventory observed {policy.data.inventory_observed_at}.</p> : <p className="mt-1 text-slate-500">No policy yet: the local proxy denies every tool.</p>}{tools.length === 0 ? <p className="mt-2 text-slate-500">No observed tools are available to allow.</p> : <div className="mt-2 grid gap-2">{tools.map((tool) => { const id = key(tool); const control = controls[id] ?? { rate: "", stepUp: false, constraints: "" }; return <div key={id}><label className="flex items-center gap-2"><input type="checkbox" checked={selected.has(id)} disabled={busy} onChange={(event) => setSelected((previous) => { const next = new Set(previous); if (event.target.checked) next.add(id); else next.delete(id); return next; })} /><span>{tool.server_name} · <span className="font-mono">{tool.tool_name}</span></span></label>{selected.has(id) && <div className="ml-6 mt-1 grid gap-1 sm:grid-cols-3"><Input aria-label={`Rate limit for ${tool.tool_name}`} placeholder="calls/min" value={control.rate} disabled={busy} onChange={(event) => setControls((old) => ({ ...old, [id]: { ...control, rate: event.target.value } }))} /><label className="flex items-center gap-1"><input type="checkbox" checked={control.stepUp} disabled={busy} onChange={(event) => setControls((old) => ({ ...old, [id]: { ...control, stepUp: event.target.checked } }))} />Step-up approval</label><textarea aria-label={`Argument constraints for ${tool.tool_name}`} className="min-h-10 rounded border border-slate-700 bg-surface px-2 py-1 font-mono" placeholder='{"required":[],"properties":{}}' value={control.constraints} disabled={busy} onChange={(event) => setControls((old) => ({ ...old, [id]: { ...control, constraints: event.target.value } }))} /></div>}</div>; })}</div>}<Button className="mt-3" disabled={busy || tools.length === 0} onClick={() => void save()}>{busy ? "Saving…" : "Save tool policy"}</Button></>}{error && <p role="alert" className="mt-2 text-danger">{error}</p>}</div>;
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
