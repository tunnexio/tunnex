import "../network-workspaces.css";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { compactDateTime } from "../lib/format";
import { announceMCPApprovalCountChanged } from "../lib/useMCPApprovalCount";
import { useOrg } from "../lib/useOrg";
import type { NamedMCPServer } from "../lib/mcpServerName";
import { ApprovalArguments, approvalOutcome, approvalTimeLeft } from "../components/AgentMCPControls";
import { Button, Loading, Modal, PageHeader, RefreshButton } from "../components/ui";

type Item = components["schemas"]["MCPToolApprovalInboxItem"];
type View = "pending" | "all";
type State = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: Item[]; next: string | null };

/** How often the inbox is read again while it is open, so a new request appears without a refresh. */
export const APPROVALS_REFRESH_MS = 5000;
const PAGE = 50;

/**
 * The organization's approvals inbox: every MCP call an agent made to an "Ask first" tool and that is
 * waiting for a person. Approving lets that one call run once, with exactly the arguments shown.
 */
export default function Approvals() {
  const { org } = useOrg();
  return org ? <ApprovalsInbox key={org.id} orgId={org.id} /> : <Loading label="Loading organization…" />;
}

function ApprovalsInbox({ orgId }: { orgId: string }) {
  const [view, setView] = useState<View>("pending");
  const [state, setState] = useState<State>({ kind: "loading" });
  const [version, setVersion] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [busy, setBusy] = useState<string | null>(null);
  const [approving, setApproving] = useState<Item | null>(null);
  const [approveError, setApproveError] = useState<string | null>(null);
  const [denying, setDenying] = useState<string | null>(null);
  const [denyError, setDenyError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [olderBusy, setOlderBusy] = useState(false);
  const [olderError, setOlderError] = useState<string | null>(null);
  // The organization's MCP servers, so a request names its server as the administrator named it.
  const [named, setNamed] = useState<NamedMCPServer[]>([]);
  useEffect(() => {
    let cancelled = false;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-mcp-profiles", { params: { path: { orgId } } })).then((result) => {
      if (cancelled || !result.ok || !Array.isArray(result.data)) return;
      setNamed(result.data.filter((profile) => !profile.archived_at).map((profile) => ({ endpoint: profile.endpoint, profile_name: profile.name, server_name: profile.server_name ?? "" })));
    });
    return () => { cancelled = true; };
  }, [orgId, version]);
  const deciding = useRef(false);
  deciding.current = busy !== null || approving !== null || denying !== null;

  const fetchPage = (cursor?: string) => loadOne(() => api.GET("/api/v1/organizations/{orgId}/mcp-tool-approval-requests", { params: { path: { orgId }, query: { state: view, limit: PAGE, ...(cursor ? { cursor } : {}) } } }));
  useEffect(() => {
    let cancelled = false;
    const read = (quiet: boolean) => void fetchPage().then((result) => {
      if (cancelled) return;
      // A background read never replaces a list someone is deciding on, and never hides it behind an error.
      if (quiet && deciding.current) return;
      if (!result.ok || !Array.isArray(result.data.items)) { if (!quiet) setState({ kind: "error", message: result.ok ? "The list was not returned." : result.error }); return; }
      setState((current) => quiet && current.kind === "ready" && current.items.length > PAGE ? current : { kind: "ready", items: result.data.items, next: result.data.next_cursor ?? null });
    });
    setState({ kind: "loading" }); setOlderError(null);
    read(false);
    const refresh = window.setInterval(() => read(true), APPROVALS_REFRESH_MS);
    return () => { cancelled = true; window.clearInterval(refresh); };
  }, [orgId, view, version]);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const reload = () => { setVersion((value) => value + 1); announceMCPApprovalCountChanged(); };
  const path = (item: Item) => ({ params: { path: { orgId, deviceId: item.request.device_id, requestId: item.request.id } } });
  // Someone else decided, or the request ran out of time, between the list loading and the click.
  const alreadyHandled = () => { setApproving(null); setDenying(null); setApproveError(null); setDenyError(null); setNotice("This request was already handled. The list is now up to date."); reload(); };
  async function approve(item: Item) {
    setBusy(item.request.id); setApproveError(null); setNotice(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/approve", path(item));
      if (apiErrorCode(result.error) === "mcp_tool_approval_not_pending") { alreadyHandled(); return; }
      if (result.error || !result.data) { setApproveError(apiErrorMessage(result.error, "Could not approve this call. Try again.")); return; }
      setApproving(null); setNotice(`Approved. ${item.agent_name} can run ${item.request.tool_name} once.`); reload();
    } catch { setApproveError("Could not reach the API. The call was not approved."); }
    finally { setBusy(null); }
  }
  async function deny(item: Item) {
    setBusy(item.request.id); setDenyError(null); setNotice(null);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-tool-approval-requests/{requestId}/deny", path(item));
      if (apiErrorCode(result.error) === "mcp_tool_approval_not_pending") { alreadyHandled(); return; }
      if (result.error || !result.data) { setDenyError(apiErrorMessage(result.error, "Could not deny this call. Try again.")); return; }
      setDenying(null); setNotice(`Denied. ${item.agent_name} was told no.`); reload();
    } catch { setDenyError("Could not reach the API. The call was not denied."); }
    finally { setBusy(null); }
  }
  async function older() {
    if (state.kind !== "ready" || !state.next) return;
    setOlderBusy(true); setOlderError(null);
    const result = await fetchPage(state.next);
    setOlderBusy(false);
    if (!result.ok || !Array.isArray(result.data.items)) { setOlderError("Older requests could not be loaded. Try again."); return; }
    setState((current) => current.kind === "ready" ? { kind: "ready", items: [...current.items, ...result.data.items], next: result.data.next_cursor ?? null } : current);
  }

  const items = state.kind === "ready" ? state.items : [];
  const pending = items.filter((item) => item.request.state === "pending");
  const earlier = items.filter((item) => item.request.state !== "pending");
  // The administrator's name for the server; then its address name; the server's own name only as a last resort.
  const serverOf = (item: Item) => {
    const address = item.request.endpoint.trim();
    const profile = named.find((server) => item.mcp_server_name && server.server_name === item.mcp_server_name) ?? named.find((server) => server.endpoint.trim() === address);
    return profile?.profile_name || item.mcp_server_name || item.request.server_name;
  };
  const who = (item: Item) => <dl className="mt-2 grid min-w-0 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
    <div className="min-w-0"><dt className="text-xs text-ink-secondary">Agent</dt><dd className="break-words"><Link className="underline" to={`/agents/${encodeURIComponent(item.request.device_id)}?tab=mcp`}>{item.agent_name}</Link></dd></div>
    <div className="min-w-0"><dt className="text-xs text-ink-secondary">Agent owner</dt><dd className="break-all">{item.owner_email || "No owner"}</dd></div>
  </dl>;
  const title = (item: Item) => <h3 className="min-w-0 break-words text-sm font-semibold text-ink-heading"><span className="font-mono">{item.request.tool_name}</span> <span className="font-normal text-ink-tertiary">on {serverOf(item)}</span></h3>;

  return <div className="network-management space-y-5">
    <PageHeader navigationTitle title="Approvals" subtitle="MCP calls waiting for a person" actions={<RefreshButton label="Refresh approvals" onClick={reload} />} />
    <p className="max-w-3xl text-sm text-ink-tertiary">When an agent calls a tool set to Ask first, the call waits here for up to five minutes. Approving lets that one call run once, with exactly the arguments shown.</p>
    <div role="group" aria-label="Show" className="flex flex-wrap items-center gap-2">{([["pending", "Waiting"], ["all", "Waiting and recent"]] as const).map(([value, label]) => <Button key={value} size="sm" variant={view === value ? "primary" : "ghost"} aria-pressed={view === value} onClick={() => { setNotice(null); setView(value); }}>{label}</Button>)}</div>
    {notice && <p role="status" className="text-sm text-ink-body">{notice}</p>}
    {state.kind === "loading" ? <Loading label="Loading approvals…" />
      : state.kind === "error" ? <div><p role="alert" className="text-sm text-danger">Approvals could not be loaded: {state.message}</p><Button size="sm" variant="ghost" className="mt-2" onClick={reload}>Retry</Button></div>
        : <>
          {pending.length === 0 ? <div role="status" className="rounded-lg border border-line p-5"><h2 className="text-sm font-semibold text-ink-heading">Nothing is waiting for a decision</h2><p className="mt-1 text-sm text-ink-tertiary">A call appears here when an agent uses a tool set to Ask first. This page checks for new ones every few seconds.</p></div>
            : <ul aria-label="Waiting for a decision" className="grid gap-3">{pending.map((item) => {
              const left = approvalTimeLeft(item.request.expires_at, now);
              return <li key={item.request.id} aria-label={`${item.request.tool_name} on ${serverOf(item)}, from ${item.agent_name}`} className="min-w-0 rounded-lg border border-line p-4">
                <div className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-4 gap-y-1">{title(item)}{left && <span className="whitespace-nowrap text-sm text-ink-secondary">{left}</span>}</div>
                {who(item)}
                <div className="mt-2 text-xs"><ApprovalArguments item={item.request} /></div>
                {denying === item.request.id
                  ? <div className="mt-3 flex flex-wrap items-center gap-2 text-sm"><span>Deny this call? The agent is told no and has to ask again.</span><Button size="sm" variant="danger" disabled={busy !== null} onClick={() => void deny(item)}>{busy === item.request.id ? "Denying…" : "Deny call"}</Button><Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => { setDenying(null); setDenyError(null); }}>Keep waiting</Button></div>
                  : <div className="mt-3 flex flex-wrap items-center gap-2"><Button disabled={busy !== null} onClick={() => { setApproveError(null); setNotice(null); setDenying(null); setApproving(item); }}>Approve once</Button><Button variant="ghost" disabled={busy !== null} onClick={() => { setDenyError(null); setNotice(null); setDenying(item.request.id); }}>Deny</Button></div>}
                {denying === item.request.id && denyError && <p role="alert" className="mt-2 text-sm text-danger">{denyError}</p>}
              </li>;
            })}</ul>}
          {view === "all" && <section aria-label="Recent requests"><h2 className="text-sm font-semibold text-ink-heading">Recent requests</h2>{earlier.length === 0 ? <p className="mt-1 text-sm text-ink-tertiary">No earlier requests.</p> : <ul aria-label="Recent requests" className="mt-2 grid gap-0">{earlier.map((item) => <li key={item.request.id} className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-t border-line py-2 text-sm"><span className="min-w-0 break-words"><span className="font-mono text-ink-heading">{item.request.tool_name}</span> <span className="text-ink-tertiary">on {serverOf(item)}, from </span><Link className="underline" to={`/agents/${encodeURIComponent(item.request.device_id)}?tab=mcp`}>{item.agent_name}</Link></span><span className="text-ink-secondary">{approvalOutcome[item.request.state] ?? item.request.state}{compactDateTime(item.request.requested_at) && <span title={new Date(item.request.requested_at).toLocaleString()}> · asked {compactDateTime(item.request.requested_at)}</span>}</span></li>)}</ul>}</section>}
          {state.next && <Button size="sm" variant="ghost" disabled={olderBusy} onClick={() => void older()}>{olderBusy ? "Loading…" : "Show older requests"}</Button>}
          {olderError && <p role="alert" className="text-sm text-danger">{olderError}</p>}
        </>}
    {approving && <Modal title={`Approve ${approving.request.tool_name} once?`} onDismiss={() => busy === null && setApproving(null)} actions={<><Button variant="ghost" disabled={busy !== null} onClick={() => setApproving(null)}>Cancel</Button><Button disabled={busy !== null} onClick={() => void approve(approving)}>{busy ? "Approving…" : approveError ? "Retry approval" : "Approve once"}</Button></>}>
      <p className="text-cell text-ink-tertiary"><strong>{approving.agent_name}</strong> can run <strong>{serverOf(approving)} / {approving.request.tool_name}</strong> once, with exactly these arguments.</p>
      <div className="mt-3 text-xs"><ApprovalArguments item={approving.request} /></div>
      {approveError && <p role="alert" className="mt-3 text-danger">{approveError}</p>}
    </Modal>}
  </div>;
}
