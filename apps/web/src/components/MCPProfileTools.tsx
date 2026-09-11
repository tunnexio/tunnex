import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, loadOne } from "../lib/api";
import { Button, Card, Select } from "./ui";

type Member = components["schemas"]["AgentGroupMember"];
type Inventory = components["schemas"]["AgentMCPInventory"];
function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
export function MCPProfileTools({ orgId, endpoint, members }: { orgId: string; endpoint: string; members: Member[] }) {
  const [chosen, setChosen] = useState("");
  const deviceId = members.some(m => m.device_id === chosen) ? chosen : members[0]?.device_id ?? "";
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setInventory(null); setError("");
    if (deviceId) void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-inventory", { params: { path: { orgId, deviceId } } })).then(result => {
      if (cancelled) return;
      if (result.ok) setInventory(result.data); else setError(result.error);
    });
    return () => { cancelled = true; };
  }, [orgId, deviceId, reload]);
  const servers = Array.isArray(inventory?.snapshot?.servers) ? inventory.snapshot.servers.map(object).filter(server => server.endpoint === endpoint) : [];
  return <Card>
    <h2 className="text-sm font-semibold text-ink-heading">Discovered tools</h2>
    <p className="mt-2 text-sm text-ink-tertiary">Tools are discovered by an assigned agent. Discovery does not grant access; each agent has its own tool policy.</p>
    {!deviceId ? <p className="mt-3">Add an agent to this group and enable its runtime to discover this server’s tools.</p> : <>
      <Select aria-label="Reporting agent" value={deviceId} onChange={event => setChosen(event.target.value)} className="mt-3">{members.map(member => <option key={member.device_id} value={member.device_id}>{member.name || member.device_id}</option>)}</Select>
      <Button variant="ghost" className="mt-2" onClick={() => setReload(value => value + 1)}>Refresh tools</Button>
      {error ? <p role="alert">Could not load tool inventory: {error}</p> : !inventory ? <p role="status">Loading observed tools…</p> : <>
        <p className="mt-2 text-xs text-ink-tertiary">Last observed: {inventory.observed_at}. This is the last agent report, not a live connection check.</p>
        {!servers.length && <p>No tools reported for this endpoint yet. Check the agent runtime and its inherited MCP profile.</p>}
        {servers.map((server, index) => <section key={index} className="mt-3">
          <h3 className="font-medium">{String(server.server_name || "MCP server")} · {String(server.status || "unknown")}</h3>
          {Array.isArray(server.tools) && server.tools.length ? <ul className="mt-2 space-y-3">{server.tools.map(object).map((tool, i) => <li key={i}><code>{String(tool.name || "Unnamed tool")}</code><p className="text-sm text-ink-tertiary">{String(tool.description || "No description provided")}</p><details><summary>Input schema</summary><pre className="overflow-auto text-xs">{JSON.stringify(tool.input_schema ?? {}, null, 2)}</pre></details></li>)}</ul> : <p>No tools reported by this server.</p>}
        </section>)}
      </>}
      <Link className="mt-4 inline-block text-accent-400" to={`/agents/${deviceId}?tab=mcp`}>Manage this agent’s tool permissions</Link>
    </>}
  </Card>;
}
