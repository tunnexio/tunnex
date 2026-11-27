import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { AgentMCPToolPolicyPanel } from "./AgentMCPControls";
import { ConnectMCPServer, mcpLocalAddress } from "./ConnectMCPServer";
import { CopyButton } from "./CopyButton";
import { AgentGroupMCPToolPolicyPanel } from "./MCPToolSettings";
import { Badge, Button } from "./ui";

type EffectiveMCP = components["schemas"]["AgentEffectiveMCPProfile"];
type Server = components["schemas"]["AgentEffectiveMCPServer"];
type Inventory = components["schemas"]["AgentMCPInventory"];
type Profile = components["schemas"]["AgentMCPProfile"];
type Assignment = components["schemas"]["AgentMCPProfileAssignment"];

/** The address clients set up before several servers existed still use; the first server answers there too. */
export const MCP_FIRST_SERVER_ADDRESS = "http://127.0.0.1:17100/mcp";

/** Ready-to-paste client settings for one server. The address is local to the agent host and carries no secret. */
export function mcpClientSnippets(serverName: string, address: string): Array<{ client: string; text: string }> {
  return [
    { client: "Claude Code", text: `claude mcp add --transport http ${serverName} ${address}` },
    { client: "Cursor and other clients that read mcpServers", text: JSON.stringify({ mcpServers: { [serverName]: { url: address } } }, null, 2) },
    { client: "VS Code", text: JSON.stringify({ servers: { [serverName]: { type: "http", url: address } } }, null, 2) },
  ];
}

function Address({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><dt className="text-xs text-ink-secondary">{label}</dt><dd className="mt-0.5 flex min-w-0 flex-wrap items-center gap-2"><code className="min-w-0 break-all font-mono text-sm text-ink-heading">{value}</code><CopyButton text={value} label="Copy" aria-label={`Copy ${label.toLowerCase()}`} /></dd></div>;
}

function ClientSnippets({ serverName, address }: { serverName: string; address: string }) {
  return <details className="rounded-md border border-line"><summary className="cursor-pointer px-3 py-2 text-sm text-ink-body">Set up an MCP client</summary><div className="grid gap-3 px-3 pb-3"><p className="text-sm text-ink-tertiary">Run or paste one of these on the agent host. The address works only on that host.</p>{mcpClientSnippets(serverName, address).map((snippet) => <div key={snippet.client} role="group" aria-label={snippet.client} className="min-w-0"><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-sm text-ink-heading">{snippet.client}</span><CopyButton text={snippet.text} label="Copy" aria-label={`Copy the ${snippet.client} setup`} /></div><pre className="mt-1 overflow-x-auto rounded bg-surface-inset p-2 font-mono text-xs text-ink-body">{snippet.text}</pre></div>)}</div></details>;
}

const groupHref = (groupId: string) => `/agents/groups?group=${encodeURIComponent(`agents:${groupId}`)}`;

function AgentServer({ orgId, deviceId, server, several, inventory, canManagePolicy, enforcement, onChanged }: { orgId: string; deviceId: string; server: Server; several: boolean; inventory: Inventory | null; canManagePolicy: boolean; enforcement?: EffectiveMCP["enforcement"]; onChanged: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [ownPolicy, setOwnPolicy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const address = server.local_url || mcpLocalAddress(server.server_name);
  const overrides = server.policy_source === "agent";
  async function useGroupPolicy() {
    setBusy(true); setError("");
    try {
      const result = await api.DELETE("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-policy/override", { params: { path: { orgId, deviceId }, query: { endpoint: server.endpoint } } });
      // Already removed elsewhere: the agent follows the group, which is what was asked for.
      if (result.error && apiErrorCode(result.error) !== "mcp_tool_policy_override_not_found") { setError(apiErrorMessage(result.error, "Could not switch to the group's policy. Try again.")); return; }
      setConfirming(false); onChanged();
    } catch { setError("Could not reach the API. The agent's own policy is unchanged."); }
    finally { setBusy(false); }
  }
  return <section aria-label={server.profile_name} className="min-w-0 border-t border-line pt-4 first:border-t-0 first:pt-0">
    <div className="flex min-w-0 flex-wrap items-center gap-2"><h4 className="min-w-0 break-words text-sm font-semibold text-ink-heading">{server.profile_name}</h4>{several && server.default && <Badge tone="neutral">First server</Badge>}</div>
    <dl className="mt-2 grid min-w-0 gap-3">
      <Address label="Address for MCP clients on the agent host" value={address} />
      <div className="min-w-0"><dt className="text-xs text-ink-secondary">Server</dt><dd className="mt-0.5 break-all font-mono text-sm text-ink-body">{server.endpoint}</dd></div>
      <div className="min-w-0"><dt className="text-xs text-ink-secondary">Connected through</dt><dd className="mt-0.5 text-sm"><Link className="underline" to={groupHref(server.group_id)}>{server.group_name}</Link></dd></div>
    </dl>
    {server.default && <p className="mt-2 text-sm text-ink-tertiary">{several ? "As the first server it also answers at" : "It also answers at"} <span className="break-all font-mono">{MCP_FIRST_SERVER_ADDRESS}</span>, so clients set up earlier keep working.</p>}
    <div className="mt-3"><ClientSnippets serverName={server.server_name} address={address} /></div>
    <div className="mt-4 min-w-0" role="group" aria-label={`Tool policy for ${server.profile_name}`}>
      <div className="flex min-w-0 flex-wrap items-center gap-2"><h5 className="text-sm font-medium text-ink-heading">Tool policy</h5>{overrides ? <Badge tone="warn">This agent&apos;s own policy</Badge> : <Badge tone="neutral">Group policy</Badge>}</div>
      {overrides ? <>
        <p className="mt-1 text-sm text-ink-tertiary">This agent has its own tool policy for this server. It overrides the policy of {server.group_name}: changes to the group&apos;s policy do not reach this agent.</p>
        {canManagePolicy && (confirming
          ? <div className="mt-2 flex flex-wrap items-center gap-2 text-sm"><span>Use the group&apos;s policy? This agent&apos;s own choices for this server are removed, and it follows {server.group_name} from now on.</span><Button size="sm" variant="danger" disabled={busy} onClick={() => void useGroupPolicy()}>{busy ? "Switching…" : "Use the group's policy"}</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => { setConfirming(false); setError(""); }}>Keep this agent&apos;s policy</Button></div>
          : <Button size="sm" variant="ghost" className="mt-2" onClick={() => setConfirming(true)}>Use the group&apos;s policy</Button>)}
        {error && <p role="alert" className="mt-2 text-sm text-danger">{error}</p>}
        <div className="mt-3">{inventory ? <AgentMCPToolPolicyPanel orgId={orgId} deviceId={deviceId} inventory={inventory} canManage={canManagePolicy} enforcement={enforcement} endpoint={server.endpoint} servers={[server]} onSaved={onChanged} /> : <p className="text-sm text-ink-secondary">The gateway has not read this server&apos;s tool list for this agent yet.</p>}</div>
      </> : ownPolicy && inventory ? <>
        <p className="mt-1 text-sm text-ink-tertiary">Saving here gives this agent its own policy for this server. From then on it no longer follows {server.group_name}.</p>
        <Button size="sm" variant="ghost" className="mt-2" onClick={() => setOwnPolicy(false)}>Back to the group&apos;s policy</Button>
        <div className="mt-3"><AgentMCPToolPolicyPanel orgId={orgId} deviceId={deviceId} inventory={inventory} canManage={canManagePolicy} enforcement={enforcement} endpoint={server.endpoint} servers={[server]} onSaved={onChanged} /></div>
      </> : <>
        <p className="mt-1 text-sm text-ink-tertiary">This agent follows the policy of <Link className="underline" to={groupHref(server.group_id)}>{server.group_name}</Link>. A change here applies to every agent in that group.</p>
        <div className="mt-3"><AgentGroupMCPToolPolicyPanel orgId={orgId} groupId={server.group_id} profileId={server.profile_id} groupName={server.group_name} canManage={canManagePolicy} /></div>
        {canManagePolicy && inventory && <Button size="sm" variant="ghost" className="mt-3" onClick={() => setOwnPolicy(true)}>Give this agent its own policy</Button>}
      </>}
    </div>
  </section>;
}

/**
 * The MCP servers one agent can use, by name: each with the local address its clients use, client setup,
 * and the tool policy that decides for it (the group's, or the agent's own where it has one).
 */
export function AgentMCPServers({ orgId, deviceId, agentName, effective, inventory, canManagePolicy, canConnect, onChanged }: {
  orgId: string; deviceId: string; agentName: string; effective: EffectiveMCP; inventory: Inventory | null; canManagePolicy: boolean; canConnect: boolean; onChanged: () => void;
}) {
  const [connecting, setConnecting] = useState(false);
  const servers = effective.servers ?? [];
  return <div data-testid="agent-mcp-servers" className="grid min-w-0 gap-4">
    <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
      <p className="min-w-0 flex-1 text-sm text-ink-tertiary">{servers.length === 0 ? "No MCP server is connected to this agent yet." : servers.length === 1 ? "This agent can use 1 MCP server. Its calls go through the gateway, which applies the tool policy below." : `This agent can use ${servers.length} MCP servers, each at its own address. Its calls go through the gateway, which applies each server's tool policy.`}</p>
      {canConnect && <Button onClick={() => setConnecting(true)}>Connect MCP server</Button>}
    </div>
    {servers.length === 0 && <p className="text-sm text-ink-secondary">{canConnect ? "Connect one to choose which of its tools this agent may use. No network rule is needed." : "Ask an owner or administrator to connect one."}</p>}
    {servers.map((server) => <AgentServer key={server.profile_id} orgId={orgId} deviceId={deviceId} server={server} several={servers.length > 1} inventory={inventory} canManagePolicy={canManagePolicy} enforcement={effective.enforcement} onChanged={onChanged} />)}
    {connecting && <ConnectMCPServer orgId={orgId} target={{ kind: "agent", id: deviceId, name: agentName }} onDismiss={() => setConnecting(false)} onConnected={onChanged} />}
  </div>;
}

type GroupServers = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; servers: Array<{ assignment: Assignment; profile: Profile | undefined }> };

/** The MCP servers of one agent group, each with the tool policy every agent in the group follows. */
export function AgentGroupMCPServers({ orgId, groupId, groupName, canManage }: { orgId: string; groupId: string; groupName: string; canManage: boolean }) {
  const [state, setState] = useState<GroupServers>({ kind: "loading" });
  const [connecting, setConnecting] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-mcp-assignments", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-mcp-profiles", { params: { path: { orgId } } })),
    ]).then(([assignments, profiles]) => {
      if (cancelled) return;
      if (!assignments.ok || !Array.isArray(assignments.data)) { setState({ kind: "error", message: assignments.ok ? "The list was not returned." : assignments.error }); return; }
      const byId = new Map((profiles.ok && Array.isArray(profiles.data) ? profiles.data : []).map((profile) => [profile.id, profile]));
      setState({ kind: "ready", servers: assignments.data.filter((item) => item.group_id === groupId && item.state === "active").map((assignment) => ({ assignment, profile: byId.get(assignment.profile_id) })) });
    });
    return () => { cancelled = true; };
  }, [orgId, groupId, attempt]);
  return <section data-testid="agent-group-mcp-servers" aria-label="MCP servers" className="grid min-w-0 gap-3">
    <div className="flex min-w-0 flex-wrap items-start justify-between gap-3"><div className="min-w-0 flex-1"><h3 className="text-sm font-semibold text-ink-heading">MCP servers</h3><p className="mt-1 text-sm text-ink-tertiary">Every agent in {groupName} can use these servers, with the tool policy set here.</p></div>{canManage && <Button onClick={() => setConnecting(true)}>Connect MCP server</Button>}</div>
    {state.kind === "loading" ? <p role="status" className="text-sm text-ink-secondary">Loading MCP servers…</p>
      : state.kind === "error" ? <div><p role="alert" className="text-sm text-danger">MCP servers could not be loaded: {state.message}</p><Button size="sm" variant="ghost" className="mt-2" onClick={() => setAttempt((value) => value + 1)}>Retry</Button></div>
        : state.servers.length === 0 ? <p className="text-sm text-ink-secondary">No MCP server is connected to this group yet.</p>
          : state.servers.map(({ assignment, profile }) => <section key={assignment.id} aria-label={assignment.profile_name} className="min-w-0 border-t border-line pt-3">
            <h4 className="break-words text-sm font-semibold text-ink-heading">{assignment.profile_name}</h4>
            <dl className="mt-2 grid min-w-0 gap-3">{profile?.server_name && <Address label="Address for MCP clients on the agent host" value={mcpLocalAddress(profile.server_name)} />}{profile && <div className="min-w-0"><dt className="text-xs text-ink-secondary">Server</dt><dd className="mt-0.5 break-all font-mono text-sm text-ink-body">{profile.endpoint}</dd></div>}</dl>
            <div className="mt-3"><AgentGroupMCPToolPolicyPanel orgId={orgId} groupId={groupId} profileId={assignment.profile_id} groupName={groupName} canManage={canManage} /></div>
          </section>)}
    {connecting && <ConnectMCPServer orgId={orgId} target={{ kind: "group", id: groupId, name: groupName }} onDismiss={() => setConnecting(false)} onConnected={() => setAttempt((value) => value + 1)} />}
  </section>;
}
