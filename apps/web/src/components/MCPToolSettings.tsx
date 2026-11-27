import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { Badge, Button, Input, Select } from "./ui";

export type MCPToolMode = components["schemas"]["MCPToolMode"];
export type MCPToolEffect = components["schemas"]["MCPToolEffect"];
type GroupPolicy = components["schemas"]["AgentGroupMCPToolPolicy"];
type ToolSetting = components["schemas"]["MCPToolSetting"];
type ToolSettingInput = components["schemas"]["MCPToolSettingInput"];

/** One tool as the administrator sees it: the server's own words, the choice, and the marker they set. */
export type MCPToolRow = {
  name: string;
  /** The description the MCP server gives. Shown as written; nothing is inferred from it. */
  description?: string | null;
  mode: MCPToolMode;
  effect: MCPToolEffect | null;
  /** Calls per minute, as typed. Empty means no limit. */
  rate?: string;
  /** The server changed the tool since it was allowed; it is blocked until this version is accepted. */
  changed?: boolean;
  /** False when the server no longer offers the tool. */
  observed?: boolean;
  /** Limits on the tool's arguments exist. They are kept on save and are not edited here. */
  argumentLimits?: boolean;
};

export const MODE_LABEL: Record<MCPToolMode, string> = { allow: "Allow", ask: "Ask first", off: "Off" };
export const MODE_HELP: Record<MCPToolMode, string> = {
  allow: "The agent can call the tool.",
  ask: "Each call waits for a person to approve it.",
  off: "The tool is blocked.",
};
export const EFFECT_LABEL: Record<MCPToolEffect, string> = { reads: "Reads", changes: "Changes data", destructive: "Destructive" };
const MODES: MCPToolMode[] = ["allow", "ask", "off"];
const EFFECTS: MCPToolEffect[] = ["reads", "changes", "destructive"];

export function parseRate(value: string | undefined): { ok: true; rate: number | null } | { ok: false } {
  const text = (value ?? "").trim();
  if (!text) return { ok: true, rate: null };
  const rate = Number(text);
  return Number.isInteger(rate) && rate > 0 ? { ok: true, rate } : { ok: false };
}

/**
 * One row per tool. The choice is Allow, Ask first or Off, and a tool nobody has decided about is Off.
 * The marker (reads, changes data, destructive) is the administrator's own note about the tool; it never
 * changes what the tool may do.
 */
export function MCPToolRows({ rows, disabled = false, onChange, onAccept, markers = "edit", limits = false, label = "Tools" }: {
  rows: MCPToolRow[];
  disabled?: boolean;
  onChange: (name: string, patch: Partial<MCPToolRow>) => void;
  /** Accept the version of a changed tool that is on screen. */
  onAccept?: (name: string) => void;
  /** `edit`: the marker can be set. `hide`: this list does not own the markers. */
  markers?: "edit" | "hide";
  /** Offer a calls-per-minute limit for a tool that is not Off. */
  limits?: boolean;
  label?: string;
}) {
  return <ul aria-label={label} className="grid min-w-0 gap-0">{rows.map((row) => <li key={row.name} aria-label={row.name} className="grid min-w-0 gap-2 border-t border-line py-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-start md:gap-4">
    <div className="min-w-0">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1"><span className="break-all font-mono text-sm text-ink-heading">{row.name}</span>
        {markers === "hide" && row.effect && <Badge tone={row.effect === "destructive" ? "danger" : row.effect === "changes" ? "warn" : "neutral"}>{EFFECT_LABEL[row.effect]}</Badge>}
        {row.changed && <><Badge tone="warn">Changed, review</Badge><Badge tone="danger">Blocked</Badge></>}
        {row.observed === false && <Badge tone="neutral">No longer on the server</Badge>}
      </div>
      <p className="mt-1 whitespace-pre-wrap break-words text-sm text-ink-tertiary">{row.description || "The server gives no description for this tool."}</p>
      {row.changed && <p className="mt-1 text-sm text-ink-secondary">The server changed this tool&apos;s name, description or inputs. It is blocked until you accept the new version.</p>}
      {row.changed && onAccept && <div className="mt-2"><Button size="sm" disabled={disabled} onClick={() => onAccept(row.name)}>Accept new version</Button></div>}
      {row.argumentLimits && <p className="mt-1 text-xs text-ink-secondary">Limits on this tool&apos;s arguments are set and are kept when you save.</p>}
    </div>
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <div role="radiogroup" aria-label={`Choice for ${row.name}`} className="inline-flex overflow-hidden rounded-md border border-line">{MODES.map((mode) => <button key={mode} type="button" role="radio" aria-checked={row.mode === mode} title={MODE_HELP[mode]} disabled={disabled} onClick={() => row.mode !== mode && onChange(row.name, { mode })}
        className={`min-h-9 whitespace-nowrap px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus disabled:opacity-50 ${row.mode === mode ? "bg-ink-heading font-medium text-surface" : "bg-surface text-ink-body hover:bg-surface-inset"}`}>{MODE_LABEL[mode]}</button>)}</div>
      {markers === "edit" && <Select width="auto" aria-label={`What ${row.name} does`} value={row.effect ?? ""} disabled={disabled} onChange={(event) => onChange(row.name, { effect: (event.target.value || null) as MCPToolEffect | null })}><option value="">Not marked</option>{EFFECTS.map((effect) => <option key={effect} value={effect}>{EFFECT_LABEL[effect]}</option>)}</Select>}
      {limits && row.mode !== "off" && <Input aria-label={`Calls per minute for ${row.name}`} className="w-28" inputMode="numeric" placeholder="No limit" title="The most calls this tool may get in one minute" value={row.rate ?? ""} disabled={disabled} onChange={(event) => onChange(row.name, { rate: event.target.value })} />}
    </div>
  </li>)}</ul>;
}

/** A plain count of the choices, so the administrator sees what a save will do before pressing it. */
export function modeSummary(rows: MCPToolRow[]): string {
  const count = (mode: MCPToolMode) => rows.filter((row) => row.mode === mode).length;
  return `${count("allow")} allowed, ${count("ask")} ask first, ${count("off")} off`;
}

const rowOf = (tool: ToolSetting): MCPToolRow => ({
  name: tool.tool_name, description: tool.description, mode: tool.mode, effect: tool.effect ?? null,
  rate: tool.rate_limit_per_minute ? String(tool.rate_limit_per_minute) : "",
  changed: tool.definition_state === "changed" && tool.mode !== "off", observed: tool.observed, argumentLimits: Boolean(tool.argument_constraints),
});

type PolicyState = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; policy: GroupPolicy };

/**
 * The tool policy of one MCP server on one agent group. It applies to every agent in the group, except an
 * agent that has its own policy for this server.
 */
export function AgentGroupMCPToolPolicyPanel({ orgId, groupId, profileId, groupName, canManage, onSaved }: {
  orgId: string; groupId: string; profileId: string; groupName?: string; canManage: boolean; onSaved?: (policy: GroupPolicy) => void;
}) {
  const [state, setState] = useState<PolicyState>({ kind: "loading" });
  const [rows, setRows] = useState<MCPToolRow[]>([]);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const path = { orgId, groupId, profileId };
  const accept = (policy: GroupPolicy) => { setState({ kind: "ready", policy }); setRows(policy.tools.map(rowOf)); setDirty(false); };
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    setState({ kind: "loading" }); setError(null); setNotice(null);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/mcp-servers/{profileId}/tool-policy", { params: { path } })).then((result) => {
      if (cancelled) return;
      if (!result.ok || !Array.isArray(result.data.tools)) { setState({ kind: "error", message: result.ok ? "The tool list was not returned." : result.error }); return; }
      accept(result.data);
    });
    return () => { cancelled = true; };
  }, [orgId, groupId, profileId, canManage, attempt]);

  async function save() {
    if (state.kind !== "ready" || busy) return;
    setError(null); setNotice(null);
    // A changed tool is never accepted as a side effect of saving something else.
    const unreviewed = rows.find((row) => row.changed && row.mode !== "off");
    if (unreviewed) { setError(`Review ${unreviewed.name} first: accept its new version, or turn it Off.`); return; }
    const invalid = rows.find((row) => row.mode !== "off" && !parseRate(row.rate).ok);
    if (invalid) { setError(`Calls per minute for ${invalid.name} must be a whole number above zero, or empty for no limit.`); return; }
    const saved = new Map(state.policy.tools.map((tool) => [tool.tool_name, tool]));
    const tools: ToolSettingInput[] = rows.map((row) => {
      const tool = saved.get(row.name);
      const rate = parseRate(row.rate);
      return {
        tool_name: row.name, mode: row.mode, effect: row.effect,
        // The version on screen is the one being allowed: the server refuses the save if the tool changed again.
        ...(row.mode !== "off" && tool?.tool_definition_hash ? { tool_definition_hash: tool.tool_definition_hash } : {}),
        ...(row.mode !== "off" && tool?.argument_constraints ? { argument_constraints: tool.argument_constraints } : {}),
        ...(row.mode !== "off" && rate.ok && rate.rate ? { rate_limit_per_minute: rate.rate } : {}),
      };
    });
    setBusy(true);
    try {
      const result = await api.PUT("/api/v1/organizations/{orgId}/agent-groups/{groupId}/mcp-servers/{profileId}/tool-policy", { params: { path }, body: { tools } });
      if (!alive.current) return;
      if (result.error || !result.data) {
        const code = apiErrorCode(result.error);
        setError(code === "mcp_tool_definition_stale" ? "The server changed a tool while you were choosing. The list was read again: check it, then save." : apiErrorMessage(result.error, "Could not save the tool policy. Try again."));
        if (code === "mcp_tool_definition_stale") setAttempt((value) => value + 1);
        return;
      }
      accept(result.data); setNotice("Tool policy saved."); onSaved?.(result.data);
    } catch { if (alive.current) setError("Could not reach the API. The tool policy was not saved."); }
    finally { if (alive.current) setBusy(false); }
  }

  const scope = groupName ? `every agent in ${groupName}` : "every agent in this group";
  if (!canManage) return <p role="status" className="text-sm text-ink-secondary">You do not have permission to view or change the tool policy.</p>;
  if (state.kind === "loading") return <p role="status" className="text-sm text-ink-secondary">Loading the tool policy…</p>;
  if (state.kind === "error") return <div><p role="alert" className="text-sm text-danger">The tool policy could not be loaded: {state.message}</p><Button size="sm" variant="ghost" className="mt-2" onClick={() => setAttempt((value) => value + 1)}>Retry</Button></div>;
  const { policy } = state;
  const overriding = policy.overriding_agent_count ?? 0;
  return <div data-testid="agent-group-mcp-tool-policy" className="min-w-0 text-sm">
    <p className="text-ink-tertiary">Choose what {scope} may do with this server. A tool nobody has decided about is Off.</p>
    {policy.version === 0 && rows.length > 0 && <p className="mt-1 text-ink-secondary">No choices are saved yet, so every tool is Off.</p>}
    {overriding > 0 && <p role="note" className="mt-1 text-ink-secondary">{overriding === 1 ? "1 agent in this group has its own policy for this server and does not follow this one." : `${overriding} agents in this group have their own policy for this server and do not follow this one.`}</p>}
    {rows.length === 0 ? <p className="mt-2 text-ink-secondary">The gateway has not read this server&apos;s tool list yet. It reads it about every 30 seconds once an agent of the group is connected.</p> : <>
      <div className="mt-2"><MCPToolRows rows={rows} disabled={busy} limits onAccept={(name) => { setRows((current) => current.map((row) => row.name === name ? { ...row, changed: false } : row)); setDirty(true); setNotice(`New version of ${name} accepted. Save to let it run again.`); }} onChange={(name, patch) => { setRows((current) => current.map((row) => row.name === name ? { ...row, ...patch } : row)); setDirty(true); setNotice(null); }} /></div>
      <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line pt-3"><Button disabled={busy || !dirty} onClick={() => void save()}>{busy ? "Saving…" : "Save tool policy"}</Button><span className="text-ink-secondary">{modeSummary(rows)}</span></div>
    </>}
    {notice && <p role="status" className="mt-2 text-ink-body">{notice}</p>}
    {error && <p role="alert" className="mt-2 text-danger">{error}</p>}
  </div>;
}
