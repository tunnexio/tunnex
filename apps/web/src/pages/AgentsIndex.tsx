import "../network-workspaces.css";
import "../app-access-workspace.css";
import "../agents-workspace.css";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorCode, apiErrorMessage, type Member, type Role } from "../lib/api";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import { useOrg } from "../lib/useOrg";
import {
  agentLiveness,
  attributionNote,
  livenessLabel,
  type AgentRow,
} from "../lib/agentview";
import { Button, DataTable, Input, Loading, Select, StatusDot } from "../components/ui";
import { AddAgentFlow } from "../components/AddAgentFlow";
import { AgentsTabRail } from "../components/AgentsTabRail";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import { relativeAge } from "../lib/format";

type AgentsPage = {
  items: AgentRow[];
  next_cursor?: string | null;
  partial?: boolean;
};

type ViewState =
  | { kind: "loading" }
  | { kind: "ready"; page: AgentsPage; canEnroll: boolean; canManageMCP: boolean }
  | { kind: "denied" }
  | { kind: "failed"; message: string };

/** Development-gallery input only. Production routes never supply it. */
export type AgentsIndexFixture = { state: ViewState };

const filters = [
  ["lifecycle", "All lifecycle states", ["active", "pending", "suspended", "revoked"]],
  ["runtime", "All runtime states", ["not_configured", "pending", "healthy", "degraded"]],
  ["mcp", "All MCP states", ["assigned", "unassigned"]],
  ["access", "All access states", ["active", "pending", "none"]],
] as const;

function asPage(value: unknown): AgentsPage {
  if (Array.isArray(value)) return { items: value as AgentRow[] };
  const candidate = value as Partial<AgentsPage> | undefined;
  return {
    items: Array.isArray(candidate?.items) ? candidate.items : [],
    next_cursor: candidate?.next_cursor ?? null,
    partial: candidate?.partial === true,
  };
}

function labelForStatus(agent: AgentRow) {
  return livenessLabel(agent);
}

/**
 * The operational AI Agents index uses the generated cursor-query contract.
 */
export default function AgentsIndex({ fixture }: { fixture?: AgentsIndexFixture }) {
  const { org } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <AgentsIndexWorkspace key={`${org?.id ?? "no-organization"}:${actor}`} fixture={fixture} />;
}

function AgentsIndexWorkspace({ fixture }: { fixture?: AgentsIndexFixture }) {
  const { org } = useOrg();
  const { state: authState } = useAuth();
  const [params, setParams] = useSearchParams();
  const [state, setState] = useState<ViewState>(fixture?.state ?? { kind: "loading" });
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [readAttempt, setReadAttempt] = useState(0);
  const pageSize = appAccessPageSize(params.get("page_size"));
  const cursorHistory = params.getAll("previous_cursor");
  const pageNumber = cursorHistory.length + (params.get("cursor") && !cursorHistory.length ? 2 : 1);

  const query = useMemo(() => ({
    q: params.get("q") ?? "",
    lifecycle: params.get("lifecycle") ?? "",
    runtime: params.get("runtime") ?? "",
    mcp: params.get("mcp") ?? "",
    access: params.get("access") ?? "",
    gateway_id: params.get("gateway_id") ?? "",
    sort: params.get("sort") ?? "name",
    dir: params.get("dir") === "desc" ? "desc" : "asc",
    cursor: params.get("cursor") ?? "",
  }), [params]);

  useEffect(() => {
    if (fixture) {
      setState(fixture.state);
      return;
    }
    if (!org || authState.status !== "authed") return;
    let cancelled = false;
    setState({ kind: "loading" });

    void (async () => {
      // Match the server's authorization order. An actor who cannot read the
      // organization must never receive deployment entitlement information.
      const membership = await api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: org.id } },
      });
      if (cancelled) return;
      if (membership.error || !membership.data) {
        const code = apiErrorCode(membership.error);
        setState(code === "permission_denied" || code === "forbidden"
          ? { kind: "denied" }
          : { kind: "failed", message: apiErrorMessage(membership.error, "Could not resolve your AI Agents access.") });
        return;
      }
      const role = (membership.data as Member[]).find((member) => member.user_id === authState.user.id)?.role as Role | undefined;
      if (!can(role, "org:view")) {
        setState({ kind: "denied" });
        return;
      }

      // Licence state is deployment-scoped and follows the permission check.
      // Base AI Agents is available on Community, so neither a missing key nor
      // a failed entitlement read is a reason to hide inventory or enrollment.
      await api.GET("/api/v1/license");
      if (cancelled) return;
      const canEnroll = can(role, "agent:enroll");

      const result = await api.GET("/api/v1/organizations/{orgId}/agents", {
        params: {
          path: { orgId: org.id },
          query: {
            q: query.q || undefined,
            lifecycle: query.lifecycle ? [query.lifecycle as "active" | "pending" | "suspended" | "revoked"] : undefined,
            runtime: query.runtime ? [query.runtime as "not_configured" | "pending" | "healthy" | "degraded"] : undefined,
            mcp: query.mcp ? [query.mcp as "assigned" | "unassigned"] : undefined,
            access: query.access ? [query.access as "active" | "pending" | "none"] : undefined,
            gateway_id: query.gateway_id ? [query.gateway_id] : undefined,
            sort: "name",
            dir: query.dir === "desc" ? "desc" : "asc",
            limit: pageSize,
            cursor: query.cursor || undefined,
          },
        },
      });
      if (cancelled) return;
      if (result.data) {
        setState({ kind: "ready", page: asPage(result.data), canEnroll, canManageMCP: can(role, "agent_template:manage") });
        return;
      }
      const code = apiErrorCode(result.error);
      if (code === "permission_denied" || code === "forbidden") setState({ kind: "denied" });
      else setState({ kind: "failed", message: apiErrorMessage(result.error, "Could not load AI agents.") });
    })().catch(() => {
      if (!cancelled) setState({ kind: "failed", message: "Could not reach the API." });
    });
    return () => { cancelled = true; };
  }, [authState, fixture, org?.id, pageSize, query.q, query.lifecycle, query.runtime, query.mcp, query.access, query.gateway_id, query.dir, query.cursor, readAttempt]);

  useEffect(() => {
    if (state.kind !== "ready" || state.canEnroll || params.get("add") !== "1") return;
    const next = new URLSearchParams(params);
    next.delete("add");
    setParams(next, { replace:true });
  }, [state, params, setParams]);

  function update(values: Record<string, string | null>, replace = false) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(values)) {
      if (value) next.set(key, value); else next.delete(key);
    }
    if (Object.keys(values).some(key => ["q", "lifecycle", "runtime", "mcp", "access", "gateway_id", "sort", "dir", "page_size"].includes(key))) { next.delete("cursor"); next.delete("previous_cursor"); }
    setParams(next, { replace });
  }

  function changePage(nextPage: number) {
    const next = new URLSearchParams(params);
    const history = [...cursorHistory];
    if (nextPage > pageNumber && state.kind === "ready" && state.page.next_cursor) {
      history.push(query.cursor);
      next.set("cursor", state.page.next_cursor);
    } else if (nextPage < pageNumber) {
      const previous = history.pop();
      if (previous) next.set("cursor", previous); else next.delete("cursor");
    } else return;
    next.delete("previous_cursor");
    history.forEach(cursor => next.append("previous_cursor", cursor));
    setParams(next);
  }

  const rows = state.kind === "ready" ? state.page.items : [];
  const activeFilterCount = filters.reduce((count, [key]) => count + (query[key] ? 1 : 0), 0);
  const filtered = activeFilterCount > 0 || Boolean(query.q || query.gateway_id);
  return (
    <div className="network-management agents-workspace agents-index">
      <AgentsTabRail actions={<>
        <Button variant="ghost" disabled={state.kind === "loading"} onClick={() => setReadAttempt(attempt => attempt + 1)}>Refresh</Button>
        {state.kind === "ready" && state.canEnroll && <Button onClick={() => update({ add: "1" })}>Add agent</Button>}
      </>} />
      {state.kind === "ready" && state.canEnroll && params.get("add") === "1" && org && <AddAgentFlow key={org.id} orgId={org.id} runtimeEnabled={Boolean(org.managed_agent_runtime_enabled)} enabled onDismiss={() => update({ add: null })} />}
      {state.kind === "loading" && <div className="agents-inventory-state"><Loading label="Loading AI agents…" /></div>}
      {state.kind === "denied" && <AppAccessEmptyState icon={null} title="Agent access required" description="Ask an organization administrator for access to this workspace." />}
      {state.kind === "failed" && <div className="agents-load-error"><p role="alert">{state.message}</p><Button variant="ghost" onClick={() => setReadAttempt(attempt => attempt + 1)}>Retry</Button></div>}
      {state.kind === "ready" && <section className="agents-inventory" aria-label="Agent inventory">
        <div className="agents-inventory-toolbar">
          <Input aria-label="Search AI agents" placeholder="Search name, owner, address" value={query.q} onChange={event => update({ q: event.target.value }, true)} />
          <Button size="sm" variant="ghost" aria-expanded={filtersOpen} onClick={() => setFiltersOpen(open => !open)}>Filters{activeFilterCount ? ` (${activeFilterCount})` : ""}</Button>
          <Select aria-label="Sort AI agents" width="auto" value={`${query.sort}:${query.dir}`} onChange={event => {
            const [sort, dir] = event.target.value.split(":"); update({ sort, dir });
          }}><option value="name:asc">Name, A–Z</option><option value="name:desc">Name, Z–A</option></Select>
          <section className="agents-result-context" aria-label="Agent result summary">{rows.length} {rows.length === 1 ? "agent" : "agents"}{state.page.next_cursor && <span> · more available</span>}</section>
        </div>
        {(filtersOpen || activeFilterCount > 0) && <div className="agents-inventory-filters">
          {filters.map(([key, label, options]) => <Select key={key} aria-label={label} value={query[key]} onChange={event => update({ [key]: event.target.value })}>
            <option value="">{label}</option>{options.map(option => <option key={option} value={option}>{option.replace(/_/g, " ")}</option>)}
          </Select>)}
        </div>}
        {filtered && <Button size="sm" variant="ghost" className="agents-clear-filters" onClick={() => update({ q:null,lifecycle:null,runtime:null,mcp:null,access:null,gateway_id:null })}>Clear filters</Button>}
        {state.page.partial && <p role="status" className="agents-partial-note">Some posture data is unavailable. Showing the latest inventory.</p>}
        <div className="agents-inventory-table"><DataTable<AgentRow>
          caption="AI Agents" rows={rows} rowKey={agent => agent.device_id} failed={false} filterable={false} pageSize={0}
          empty={<AppAccessEmptyState icon={null} title={filtered ? "No matching agents" : pageNumber > 1 ? "No agents on this page" : "No agents yet"} description={filtered ? "Try another search or clear the filters." : pageNumber > 1 ? "Return to the previous page or refresh the inventory." : "Connect an agent to start managing its runtime and access."} action={filtered ? <Button variant="ghost" onClick={() => update({ q:null,lifecycle:null,runtime:null,mcp:null,access:null,gateway_id:null })}>Clear filters</Button> : pageNumber === 1 && state.canEnroll ? <Button onClick={() => update({ add:"1" })}>Add agent</Button> : undefined} />}
          rowAttrs={agent => ({ "data-liveness": agentLiveness(agent) })}
          columns={[
            { key:"name", header:"Agent", cell:agent => <div><Link className="agents-name-link" to={`/agents/${agent.device_id}`}>{agent.name}</Link><span className="agents-secondary agents-address">{agent.address ?? "Address not reported"}</span></div> },
            { key:"status", header:"Connectivity", cell:agent => { const status=labelForStatus(agent); return <div><span className="agents-liveness" data-tone={status.tone} title={status.detail}><StatusDot tone={status.tone === "ok" ? "on" : status.tone === "warn" ? "warn" : "off"} />{status.label}</span><span className="agents-secondary">{agent.last_handshake_at ? relativeAge(agent.last_handshake_at) : "Never reported"}</span></div>; } },
            { key:"owner", header:"Owner", cell:agent => { const note=attributionNote(agent); return <span className={note ? "agents-attribution-note" : undefined} title={note?.detail}>{note?.label ?? agent.owner_email ?? "Unassigned"}</span>; } },
            { key:"gateway", header:"Gateway", cell:agent => agent.gateway_name || "Not reported" },
            { key:"actions", header:"Actions", cell:agent => <AppAccessRowMenu label={`Agent actions for ${agent.name}`} actions={[
              { key:"runtime", label:"View runtime", href:`/agents/${agent.device_id}?tab=runtime` },
              { key:"access", label:"Manage access", href:`/agents/${agent.device_id}?tab=access` },
              { key:"activity", label:"View activity", href:`/agents/${agent.device_id}?tab=activity` },
            ]} /> },
          ]}
        /></div>
        <AppAccessPagination page={pageNumber} pageSize={pageSize} count={rows.length} hasNext={Boolean(state.page.next_cursor)} maxOffset={null} onPageChange={changePage} onPageSizeChange={size => update({ page_size:String(size) })} />
      </section>}
    </div>
  );
}
