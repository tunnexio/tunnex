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
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  Input,
  Loading,
  PageHeader,
  Select,
  StatusDot,
} from "../components/ui";
import { AddAgentFlow } from "../components/AddAgentFlow";
import { AgentsTabRail } from "../components/AgentsTabRail";

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

const LIMIT = 50;
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
  const { state: authState } = useAuth();
  const [params, setParams] = useSearchParams();
  const [state, setState] = useState<ViewState>(fixture?.state ?? { kind: "loading" });

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
      if (!canEnroll && params.get("add") === "1") {
        const next = new URLSearchParams(params);
        next.delete("add");
        setParams(next, { replace: true });
      }

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
            limit: LIMIT,
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
  }, [authState, fixture, org?.id, params, query, setParams]);

  function update(values: Record<string, string | null>, replace = false) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(values)) {
      if (value) next.set(key, value); else next.delete(key);
    }
    if (!("cursor" in values)) next.delete("cursor");
    setParams(next, { replace });
  }

  const rows = state.kind === "ready" ? state.page.items : [];
  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader
        title="AI Agents"
        subtitle={state.kind === "ready" ? `${rows.length} in this result` : "Operational inventory, runtime posture, and inherited access context."}
        actions={state.kind === "ready" && state.canEnroll ? <Link to="?add=1"><Button>Add agent</Button></Link> : undefined}
      />
      <AgentsTabRail />
      {state.kind === "ready" && state.canEnroll && params.get("add") === "1" && org && <AddAgentFlow orgId={org.id} enabled onDismiss={() => update({ add: null })} />}

      {state.kind === "ready" && <Card>
        <div className="grid gap-2 lg:grid-cols-[minmax(16rem,1fr)_repeat(5,minmax(0,11rem))_auto]">
          <Input aria-label="Search AI agents" placeholder="Search name, owner, address" value={query.q} onChange={(event) => update({ q: event.target.value }, true)} />
          {filters.map(([key, label, options]) => (
            <Select key={key} aria-label={label} value={query[key]} onChange={(event) => update({ [key]: event.target.value })}>
              <option value="">{label}</option>
              {options.map((option) => <option key={option} value={option}>{option.replace(/_/g, " ")}</option>)}
            </Select>
          ))}
          <Select aria-label="Sort AI agents" width="auto" value={`${query.sort}:${query.dir}`} onChange={(event) => {
            const [sort, dir] = event.target.value.split(":");
            update({ sort, dir });
          }}><option value="name:asc">Name, A–Z</option><option value="name:desc">Name, Z–A</option></Select>
        </div>
      </Card>}

      {state.kind === "loading" && <Card><Loading label="Loading AI agents…" /></Card>}
      {state.kind === "denied" && <Card><EmptyState>You do not have permission to view AI Agents in this organization.</EmptyState></Card>}
      {state.kind === "failed" && <Card><div role="alert" className="py-6 text-sm text-danger">{state.message} <Button variant="ghost" onClick={() => update({}, true)}>Retry</Button></div></Card>}
      {state.kind === "ready" && (
        <Card>
          {state.page.partial && <p role="status" className="mb-3 rounded-md border border-warn/40 px-3 py-2 text-xs text-warn">Some agent posture data is unavailable. Rows below include the latest complete inventory data.</p>}
          <DataTable<AgentRow>
            caption="AI Agents"
            rows={rows}
            rowKey={(agent) => agent.device_id}
            failed={false}
            filterable={false}
            pageSize={0}
            empty={<EmptyState>No AI agents match this query. {state.canEnroll ? "Clear a filter or add an agent." : "Clear a filter or ask an organization administrator to enroll one."}</EmptyState>}
            rowAttrs={(agent) => ({ "data-liveness": agentLiveness(agent) })}
            columns={[
              {
                key: "name", header: "Agent", sortValue: (agent) => agent.name,
                cell: (agent) => {
                  const status = labelForStatus(agent);
                  return <Link className="inline-flex items-center gap-2 text-white hover:underline" to={`/agents/${agent.device_id}`}><StatusDot tone={status.tone === "ok" ? "on" : status.tone === "warn" ? "warn" : "off"} /><span>{agent.name}</span></Link>;
                },
              },
              { key: "status", header: "Status", sortValue: (agent) => labelForStatus(agent).label, cell: (agent) => { const status = labelForStatus(agent); return <Badge tone={status.tone}>{status.label}</Badge>; } },
              { key: "owner", header: "Owner", sortValue: (agent) => agent.owner_email ?? "", cell: (agent) => { const note = attributionNote(agent); return note ? <Badge tone={note.tone}>{note.label}</Badge> : <span>{agent.owner_email ?? "Not available"}</span>; } },
              { key: "gateway", header: "Gateway", sortValue: (agent) => agent.gateway_name, cell: (agent) => <span>{agent.gateway_name || "—"}</span> },
              { key: "address", header: "Address", sortValue: (agent) => agent.address ?? "", cell: (agent) => <span className="font-mono text-xs">{agent.address ?? "Not available"}</span> },
              { key: "last_seen", header: "Last seen", sortValue: (agent) => agent.last_handshake_at ?? "", cell: (agent) => <span>{agent.last_handshake_at ? new Date(agent.last_handshake_at).toLocaleString() : "Never reported"}</span> },
            ]}
          />
          <div className="mt-3 flex items-center justify-between gap-3">
            <span className="text-xs text-ink-secondary">{state.page.next_cursor ? `Up to ${LIMIT} results shown` : "End of results"}</span>
            <Button variant="ghost" disabled={!state.page.next_cursor} onClick={() => update({ cursor: state.page.next_cursor ?? null })}>Next</Button>
          </div>
        </Card>
      )}
    </div>
  );
}
