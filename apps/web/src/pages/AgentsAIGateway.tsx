import "../network-workspaces.css";
import "../agents-workspace.css";
import "../agents-management-workspace.css";
import "../components/ai-gateway-configuration.css";
import "../ai-gateway-workspace.css";
import { useEffect, useRef, useState } from "react";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { modelDisplayName } from "../components/HelpTooltip";
import { WorkspaceTabs } from "../components/WorkspaceTabs";
import { AgentsTabRail } from "../components/AgentsTabRail";
import { AIGatewaySettings } from "../components/AIGatewaySettings";
import { AIProviderWorkspace } from "../components/AIProviderWorkspace";
import { AIWorkloads } from "../components/AIWorkloads";
import { AIUsageWorkspace } from "../components/AIUsageWorkspace";
import { Button, Card, Field, Input, Loading, Modal, PageHeader, Select, RefreshButton } from "../components/ui";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { NetworkDetailList } from "../components/NetworkDetailList";
import { api } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { AIAccessGate, AIGroupAccess, AIUseModel } from "../components/AIUserAccess";
type S = components["schemas"];
type Inventory = {
  groups: S["AgentGroup"][];
  devices: { id: string; name: string; status: string }[];
  nextAgentCursor: string | null;
  teams: S["AITeamPolicy"][];
  assignments: S["AIAssignment"][];
  providers: S["AIProviderList"];
};
const lines = (v: string) => [
  ...new Set(
    v
      .split("\n")
      .map((v) => v.trim())
      .filter(Boolean),
  ),
];
const area =
  "w-full rounded-lg border border-white/10 bg-ink-900 px-3 py-2 text-sm text-ink-heading";
const thresholdDecimal = new Intl.NumberFormat("en-US", {
  useGrouping: false,
  maximumSignificantDigits: 21,
});
const gatewayTabs = [
  { href: "/ai-gateway/models", label: "Models & endpoints" },
  { href: "/ai-gateway/credentials", label: "LLM credentials" },
  { href: "/ai-gateway/access", label: "Access" },
  { href: "/ai-gateway/usage", label: "Usage & cost" },
  { href: "/ai-gateway/my-models", label: "Playground" },
  { href: "/ai-gateway/settings", label: "Settings" },
];
export default function AgentsAIGateway() {
  const [grant, setGrant] = useState<{ connection: string; model: string } | null>(null);
  const { org } = useOrg();
  const { state } = useAuth();
  const canManageTransport = state.status === "authed" && Boolean(state.user.cp_admin);
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [search] = useSearchParams();
  useEffect(() => setGrant(null), [org?.id, pathname]);
  const page = pathname.split("/")[2] || "models";
  return <div className="network-management ai-workspace ai-gateway-workspace space-y-5">
    <AIAccessGate key={org?.id}>{(orgId, access) => {
      if (pathname === "/ai-gateway" || pathname === "/ai-gateway/") return <Navigate to={access.view ? "/ai-gateway/models" : "/ai-gateway/my-models"} replace />;
      if (!access.view && page !== "my-models") return <Navigate to="/ai-gateway/my-models" replace />;
      if (!gatewayTabs.some((tab) => tab.href === `/ai-gateway/${page}`)) return <Navigate to="/ai-gateway/models" replace />;
      const tabs = access.view ? gatewayTabs : gatewayTabs.filter((tab) => tab.href.endsWith("/my-models"));
      return <>
        <WorkspaceTabs label="AI gateway views" items={tabs} />
        {grant && <AIGroupAccess orgId={orgId} canManage={access.manage} initialConnection={grant.connection} initialModel={grant.model} dialogOnly onDone={() => setGrant(null)} />}
        {page === "my-models" ? <AIUseModel key={orgId} orgId={orgId} />
           : page === "access" ? <>
            <nav aria-label="Access subjects" className="workspace-tabs">
              <Link to="/ai-gateway/access" aria-current={search.get("subject") !== "workloads" || !access.workloadsView ? "page" : undefined}>User groups</Link>
              {access.workloadsView && <Link to="/ai-gateway/access?subject=workloads" aria-current={search.get("subject") === "workloads" ? "page" : undefined}>Workloads</Link>}
            </nav>
            {search.get("subject")==="workloads" && access.workloadsView ? <AIWorkloads key={orgId} orgId={orgId} canManage={access.workloadsManage} /> : <AIGroupAccess key={`${orgId}:${search.get("connection")}:${search.get("model")}`} orgId={orgId} canManage={access.manage} initialConnection={search.get("connection") ?? ""} initialModel={search.get("model") ?? ""} />}
          </>
          : page === "usage" ? <AIUsageWorkspace key={orgId} orgId={orgId} inventory={{ groups: [], devices: [], teams: [], assignments: [] }} />
          : page === "models" || page === "credentials" ? <AIProviderWorkspace key={`${orgId}:${page}`} orgId={orgId} canManage={access.manage} canManageTransport={canManageTransport}
            view={page === "credentials" ? "connections" : pathname.endsWith("/new") && access.manage ? "add" : "models"}
            onViewChange={(view) => navigate(view === "connections" ? "/ai-gateway/credentials" : view === "add" ? "/ai-gateway/models/new" : "/ai-gateway/models")}
            onGrantAccess={(connection, model) => setGrant({ connection, model })} />
          : <div className="ai-gateway-configuration"><h2 className="sr-only">Gateway settings</h2>
            <AIGatewaySettings orgId={orgId} canEdit={access.manage} />
            {access.agents && <Card className="ai-setting-card"><div className="ai-setting-row"><div className="ai-setting-copy"><h3>Agent model access</h3><p>Choose which models your managed agents can use.</p></div><Link className="network-setup-link" to="/agents/model-access">Manage access</Link></div></Card>}
          </div>}
      </>;
    }}</AIAccessGate>
  </div>;
}
export function AgentModelAccess() {
  const { org } = useOrg();
  return <div className="network-management agents-workspace agents-management ai-workspace space-y-5">
    <PageHeader navigationTitle title="Agent model access" subtitle={org?.name} />
    <AgentsTabRail />
    <AIAccessGate key={org?.id}>{(orgId, access) => !access.agents ? <Card><p role="alert">You do not have permission to manage agent model access.</p></Card>
      : !org?.agent_policy_templates_enabled ? <AppAccessEmptyState icon={null} title="Agent groups are turned off" description="Enable this organization’s opt-in before assigning group model policies." action={<Link className="agents-management-link" to="/settings?section=features&feature=agent-templates">Configure Agent Group settings</Link>} />
      : <div className="ai-gateway-configuration"><AIGatewayWorkspace key={orgId} orgId={orgId} /></div>}
    </AIAccessGate>
  </div>;
}
export function AIGatewayWorkspace({ orgId }: { orgId: string }) {
  const [editor, setEditor] = useState<"team" | "agent" | null>(null);
  const [view, setView] = useState<"teams" | "agents">("teams");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [data, setData] = useState<Inventory | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(true),
    [loadingAgents, setLoadingAgents] = useState(false);
  const [teamID, setTeamID] = useState(""),
    [deviceID, setDeviceID] = useState("");
  const alive = useRef(true),
    generation = useRef(0);
  async function reload() {
    const n = ++generation.current;
    setLoading(true);
    setLoadingAgents(false);
    setError("");
    try {
      const params = { params: { path: { orgId } } };
      const [g, d, t, a, p] = await Promise.all([
        api.GET("/api/v1/organizations/{orgId}/agent-groups", params),
        api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId }, query: { limit: 100 } } }),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/teams", params),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/agents", params),
        api.GET("/api/v1/organizations/{orgId}/ai-gateway/providers", params),
      ]);
      if (!alive.current || n !== generation.current) return;
      if (
        g.error ||
        d.error ||
        t.error ||
        a.error || p.error || !p.data ||
        !g.data ||
        !d.data ||
        !t.data ||
        !a.data
      )
        throw Error();
      setDeviceID((selected) => d.data.items.some((agent) => agent.device_id === selected) ? selected : "");
      setTeamID((selected) => g.data.some((group) => group.id === selected) ? selected : "");
      setData({
        groups: g.data,
        devices: d.data.items.map((d) => ({ id: d.device_id, name: d.name, status: d.status })),
        nextAgentCursor: d.data.next_cursor ?? null,
        teams: t.data,
        assignments: a.data,
        providers: p.data!,
      });
    } catch {
      if (alive.current && n === generation.current)
        setError(
          "Could not load AI policies. Retry to refresh authoritative state.",
        );
    } finally {
      if (alive.current && n === generation.current) setLoading(false);
    }
  }
  async function loadMoreAgents() {
    if (!data?.nextAgentCursor || loadingAgents || busy) return;
    const n = generation.current;
    const cursor = data.nextAgentCursor;
    setLoadingAgents(true);
    setError("");
    try {
      const result = await api.GET("/api/v1/organizations/{orgId}/agents", {
        params: { path: { orgId }, query: { limit: 100, cursor } },
      });
      if (!alive.current || n !== generation.current) return;
      if (result.error || !result.data || result.data.next_cursor === cursor) throw Error();
      const page = result.data;
      setData((current) => current ? {
        ...current,
        devices: [...new Map([...current.devices, ...page.items.map((d) => ({ id: d.device_id, name: d.name, status: d.status }))].map((d) => [d.id, d])).values()],
        nextAgentCursor: page.next_cursor ?? null,
      } : current);
    } catch {
      if (alive.current && n === generation.current)
        setError("Could not load more agents. Your selection is preserved; retry loading more agents.");
    } finally {
      if (alive.current && n === generation.current) setLoadingAgents(false);
    }
  }
  useEffect(() => {
    alive.current = true;
    void reload();
    return () => {
      alive.current = false;
      generation.current++;
    };
  }, [orgId]);
  async function mutate(
    call: () => Promise<{
      data?: unknown;
      error?: unknown;
    }>,
  ) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const r = await call();
      if (!alive.current) return;
      if (r.error || !r.data) {
        setError(
          "Update failed. Refresh before retrying if another administrator changed this policy.",
        );
        return;
      }
      await reload();
    } catch {
      if (alive.current)
        setError(
          "Could not reach the API. Saved state has not been changed locally.",
        );
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  if (loading) return <Loading label="Loading AI policies…" />;
  if (!data)
    return (
      <Card>
        <p role="alert">{error}</p>
        <Button onClick={() => void reload()}>Retry AI policies</Button>
      </Card>
    );
  const team = data.teams.find((t) => t.team_id === teamID),
    assignment = data.assignments.find((a) => a.device_id === deviceID);
  const teamName = (id: string) =>
    data.groups.find((g) => g.id === id)?.name ??
    `Archived/unavailable group (${id})`;
  const agentName = (id: string) => data.devices.find((d) => d.id === id)?.name ?? id;
  const matchingTeams = data.teams.filter((t) => `${teamName(t.team_id)} ${t.models.join(" ")}`.toLowerCase().includes(query.trim().toLowerCase()));
  const matchingAssignments = data.assignments.filter((a) => `${agentName(a.device_id)} ${teamName(a.team_id)} ${a.status}`.toLowerCase().includes(query.trim().toLowerCase()));
  const count = view === "teams" ? matchingTeams.length : matchingAssignments.length;
  const currentPage = Math.min(page, Math.max(1, Math.ceil(count / pageSize)));
  const first = (currentPage - 1) * pageSize;
  const visibleTeams = matchingTeams.slice(first, first + pageSize), visibleAssignments = matchingAssignments.slice(first, first + pageSize);
  const openTeam = (id = "") => { setTeamID(id); setView("teams"); setEditor("team"); };
  const openAgent = (id = "") => { setDeviceID(id); setView("agents"); setEditor("agent"); };
  return <div className="agents-management agents-management-content ai-agent-access">
    <div className="agents-management-view-tabs" role="tablist" aria-label="Agent model policy views">
      <button type="button" role="tab" aria-selected={view === "teams"} onClick={() => { setView("teams"); setQuery(""); setPage(1); }}>Group policies</button>
      <button type="button" role="tab" aria-selected={view === "agents"} onClick={() => { setView("agents"); setQuery(""); setPage(1); }}>Agent assignments</button>
    </div>
    <div className="agents-management-toolbar"><Input aria-label="Search model policies" value={query} placeholder={view === "teams" ? "Search groups or models" : "Search agents or groups"} onChange={(event) => { setQuery(event.target.value); setPage(1); }} /><div className="agents-management-actions"><RefreshButton label="Refresh" disabled={busy} onClick={() => void reload()} /><Button variant={view === "teams" ? "primary" : "ghost"} disabled={busy} onClick={() => openTeam()}>Add policy</Button><Button variant={view === "agents" ? "primary" : "ghost"} disabled={busy} onClick={() => openAgent()}>Assign agent</Button></div></div>
    {error && !editor && <p role="alert">{error}</p>}
    <div className="agents-management-table-scroll">
      {view === "teams" ? matchingTeams.length ? <table className="ai-compact-table"><caption className="sr-only">Group model policies</caption><thead><tr><th scope="col">Agent group</th><th scope="col">Models</th><th scope="col">Revision</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>{visibleTeams.map((t) => <tr key={t.team_id}><td><button className="agents-management-name" aria-label={`Edit policy for ${teamName(t.team_id)}`} onClick={() => openTeam(t.team_id)}>{teamName(t.team_id)}</button></td><td title={t.models.map(modelDisplayName).join(", ")}>{t.models.length}</td><td>{t.revision}</td><td><AppAccessRowMenu label={`Actions for policy ${teamName(t.team_id)}`} actions={[{ key: "edit", label: "Edit policy", disabledReason: busy ? "Wait for the current update." : undefined, onSelect: () => openTeam(t.team_id) }]} /></td></tr>)}</tbody></table> : <AppAccessEmptyState icon={null} title={query ? "No matching group policies" : "No team policies yet."} description={query ? "Try another group or model." : "Choose an agent group, its exact models, and owned provider credentials."} action={query ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />
      : matchingAssignments.length ? <table className="ai-compact-table"><caption className="sr-only">Agent model assignments</caption><thead><tr><th scope="col">Agent</th><th scope="col">Policy group</th><th scope="col">Synchronization</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>{visibleAssignments.map((a) => <tr key={a.device_id}><td><button className="agents-management-name" aria-label={`Manage access for ${agentName(a.device_id)}`} onClick={() => openAgent(a.device_id)}>{agentName(a.device_id)}</button></td><td>{teamName(a.team_id)}</td><td>{a.enabled ? a.status : "Disabled"}</td><td><AppAccessRowMenu label={`Actions for model access ${agentName(a.device_id)}`} actions={[{ key: "manage", label: "Manage access", disabledReason: busy ? "Wait for the current update." : undefined, onSelect: () => openAgent(a.device_id) }]} /></td></tr>)}</tbody></table> : <AppAccessEmptyState icon={null} title={query ? "No matching agent assignments" : "No agent assignments yet."} description={query ? "Try another agent or policy group." : "Assign an active group member to one model policy."} action={query ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />}
    </div>
    <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={view === "teams" ? visibleTeams.length : visibleAssignments.length} hasNext={currentPage * pageSize < count} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
    <details className="agents-management-help"><summary>How agent model policies work</summary><p>Each agent uses one group policy and must remain an active member. Model overrides can only narrow that policy. Network templates and MCP tool permissions are configured separately. Provider credentials stay in the private backend.</p><Link className="agents-management-link" to="/ai-gateway/usage">View observed model usage</Link></details>
    {editor === "team" && <Modal title="Team model policy" placement="right" size="enrollment" showClose onDismiss={() => !busy && setEditor(null)}><div className="agents-model-editor">
      {error && <p role="alert">{error}</p>}
      {data.groups.length === 0 ? <p>No Agent Groups yet. <Link to="/agents/groups">Create a group</Link> first.</p> : <>
        <Field label="Policy team"><Select value={teamID} disabled={busy} onChange={(event) => setTeamID(event.target.value)}><option value="">Choose a group</option>{data.groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</Select></Field>
        {!teamID && <p>Select a group to configure exact models and provider credentials.</p>}
        {teamID && <TeamEditor key={`${teamID}:${team?.revision ?? 0}`} team={team} providers={data.providers} busy={busy} save={(body) => mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/teams/{teamId}", { params: { path: { orgId, teamId: teamID } }, body }))} />}
      </>}
      {data.teams.some((t) => !data.groups.some((g) => g.id === t.team_id)) && <details><summary>Retained policies</summary>{data.teams.filter((t) => !data.groups.some((g) => g.id === t.team_id)).map((t) => <p key={t.team_id}>{teamName(t.team_id)}, retained policy revision {t.revision}.</p>)}</details>}
    </div></Modal>}
    {editor === "agent" && <Modal title="Agent access" placement="right" size="enrollment" showClose onDismiss={() => !busy && setEditor(null)}><div className="agents-model-editor">
      {error && <p role="alert">{error}</p>}
      {data.devices.length === 0 ? <p>No enrolled agents are available.</p> : data.devices.length > 10 ? <fieldset><legend className="mb-2 text-sm text-ink-heading">Agent</legend><NetworkDetailList label="Available model agents" items={data.devices} searchText={(d) => `${d.name} ${d.status}`} renderItem={(d) => <li key={d.id}><label><input type="radio" name="agent-model-candidate" aria-label={`Select ${d.name}`} checked={deviceID === d.id} disabled={busy || loadingAgents} onChange={() => setDeviceID(d.id)} /><span>{d.name}<small>{d.status}</small></span></label></li>} /></fieldset> : <Field label="Agent"><Select value={deviceID} disabled={busy} onChange={(event) => setDeviceID(event.target.value)}><option value="">Choose an agent</option>{data.devices.map((d) => <option key={d.id} value={d.id}>{d.name} ({d.status})</option>)}</Select></Field>}{data.devices.length > 10 && deviceID && <p>Selected: {agentName(deviceID)}</p>}
      {data.nextAgentCursor && <Button variant="ghost" disabled={busy || loadingAgents} onClick={() => void loadMoreAgents()}>{loadingAgents ? "Loading more agents…" : "Load more agents"}</Button>}
      {!deviceID && data.devices.length > 0 && <p>Select an agent, choose its group policy, then review model scope and synchronization.</p>}
      {deviceID && <AssignmentEditor key={`${deviceID}:${assignment?.revision ?? 0}`} orgId={orgId} deviceID={deviceID} assignment={assignment} inventory={data} busy={busy} save={(body) => mutate(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}", { params: { path: { orgId, deviceId: deviceID } }, body }))} reconcile={() => mutate(() => api.POST("/api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}/reconcile", { params: { path: { orgId, deviceId: deviceID } } }))} />}
      <p>Disabling blocks new requests. Accepted streams may finish within 30 seconds.</p>
      {data.assignments.some((a) => !data.devices.some((d) => d.id === a.device_id)) && <details><summary>Agents outside loaded inventory</summary>{data.assignments.filter((a) => !data.devices.some((d) => d.id === a.device_id)).map((a) => <p key={a.device_id}>Agent not in loaded inventory ({a.device_id}): {a.status}; retained usage history.</p>)}</details>}
    </div></Modal>}
  </div>;
}

function TeamEditor({
  team,
  providers,
  busy,
  save,
}: {
  team?: S["AITeamPolicy"];
  providers: S["AIProviderList"];
  busy: boolean;
  save: (body: S["AITeamPolicyWrite"]) => Promise<void>;
}) {
  const [models, setModels] = useState(team?.models.join("\n") ?? ""),
    [keys, setKeys] = useState(team?.key_ids.join("\n") ?? ""),
    [limit, setLimit] = useState(team?.daily_cost_limit == null ? "" : thresholdDecimal.format(team.daily_cost_limit));
  const valid =
    lines(models).length > 0 &&
    lines(keys).length > 0 &&
    (limit === "" ||
      (Number.isFinite(Number(limit)) &&
        Number(limit) > 0 &&
        Number(limit) <= 100000));
  return (
    <div className="ai-config-editor">
      <div className="ai-config-policy-summary"><span className="ai-config-pill">{team ? `Revision ${team.revision}` : "New policy"}</span>{team && <span>{team.models.length} model{team.models.length === 1 ? "" : "s"} · {team.key_ids.length} provider key ID{team.key_ids.length === 1 ? "" : "s"}</span>}</div>
      <Field label="Add a configured model">
        <Select value="" disabled={busy} onChange={event => { if (event.target.value) setModels([...new Set([...lines(models), event.target.value])].join("\n")); }}>
          <option value="">Choose a model</option>
          {[...new Set(providers.items.filter(c => c.enabled && c.status === "applied" && c.applied_revision === c.revision).flatMap(c => c.models))].map(model => <option key={model} value={model}>{modelDisplayName(model)}</option>)}
        </Select>
      </Field>
      <Field label="Exact models (one per line)">
        <textarea
          className={area}
          rows={3}
          value={models}
          onChange={(e) => setModels(e.target.value)}
          placeholder="openrouter/openai/gpt-4o-mini"
        />
      </Field>
      <fieldset><legend className="mb-2 text-xs text-ink-secondary">Provider connections</legend><div className="ai-config-provider-options">
        {providers.items.map((c) => <label key={c.id}><input type="checkbox" checked={lines(keys).includes(c.key_id)} disabled={busy || (!lines(keys).includes(c.key_id) && (!c.enabled || c.status !== "applied" || c.applied_revision !== c.revision || lines(keys).length >= 8))} onChange={(e) => setKeys((e.target.checked ? [...lines(keys), c.key_id] : lines(keys).filter((key) => key !== c.key_id)).join("\n"))} /><span>{c.name}<small>{providers.definitions?.find((d) => d.id === c.provider)?.name ?? c.provider} · {c.status} · {c.models.length} models</small></span></label>)}
        {providers.legacy_key_ids.map((id) => <label key={id}><input type="checkbox" checked={lines(keys).includes(id)} disabled={busy || (!lines(keys).includes(id) && lines(keys).length >= 8)} onChange={(e) => setKeys((e.target.checked ? [...lines(keys), id] : lines(keys).filter((key) => key !== id)).join("\n"))} /><span>{id}<small>Legacy operator-managed reference</small></span></label>)}
        {lines(keys).filter((id) => !providers.items.some((c) => c.key_id === id) && !providers.legacy_key_ids.includes(id)).map((id) => <label key={id}><input type="checkbox" checked disabled={busy} onChange={() => setKeys(lines(keys).filter((key) => key !== id).join("\n"))} /><span>Unavailable policy reference ({id})<small>Remove this reference or refresh provider inventory.</small></span></label>)}
        {!providers.items.length && !providers.legacy_key_ids.length && <p>No owned provider connections are available. Add one in Models &amp; endpoints.</p>}
      </div><p className="mt-2 text-xs text-ink-secondary">Choose up to eight applied connections. Selected models must be covered by the chosen connections.</p></fieldset>
      <Field label="Daily USD soft threshold (optional)">
        <Input
          type="number"
          min="0"
          max="100000"
          step="any"
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
        />
      </Field>
      <p className="text-xs text-ink-secondary">
        Observed usage since midnight UTC. Concurrent requests may exceed this
        threshold. Unknown prices fail closed with monetary thresholds; this is
        not a strict spending cap.
      </p>
      <Button
        disabled={busy || !valid}
        onClick={() =>
          void save({
            models: lines(models),
            key_ids: lines(keys),
            daily_cost_limit: limit === "" ? null : Number(limit),
            expected_revision: team?.revision ?? 0,
          })
        }
      >
        Save team policy
      </Button>
    </div>
  );
}
function AssignmentEditor({
  orgId,
  deviceID,
  assignment,
  inventory,
  busy,
  save,
  reconcile,
}: {
  orgId: string;
  deviceID: string;
  assignment?: S["AIAssignment"];
  inventory: Inventory;
  busy: boolean;
  save: (body: S["AIAssignmentWrite"]) => Promise<void>;
  reconcile: () => Promise<void>;
}) {
  const [teamID, setTeamID] = useState(assignment?.team_id ?? ""),
    [models, setModels] = useState(
      assignment?.models_override.join("\n") ?? "",
    ),
    [membership, setMembership] = useState("absent"),
    [attempt, setAttempt] = useState(0);
  const team = inventory.teams.find((t) => t.team_id === teamID);
  useEffect(() => {
    let live = true;
    setMembership(teamID ? "loading" : "absent");
    if (teamID)
      void api
        .GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", {
          params: { path: { orgId, groupId: teamID } },
        })
        .then(({ data, error }) => {
          if (live)
            setMembership(
              error || !data
                ? "error"
                : data.some(
                      (m) => m.device_id === deviceID && m.status === "active",
                    )
                  ? "member"
                  : "absent",
            );
        })
        .catch(() => {
          if (live) setMembership("error");
        });
    return () => {
      live = false;
    };
  }, [orgId, deviceID, teamID, attempt]);
  const valid =
    team &&
    membership === "member" &&
    lines(models).every((m) => team.models.includes(m));
  return (
    <div className="ai-config-editor">
      {assignment && (
        <div role="status" className={`ai-config-sync ai-config-sync-${assignment.status}`}><div className="ai-config-sync-heading"><span className="ai-config-pill">Synchronization: {assignment.status}</span><span>{assignment.enabled ? "Access requested." : "Access disabled."}</span></div><p>Desired revision {assignment.revision}; applied revision {assignment.applied_revision}; applied team revision {assignment.applied_team_revision}.</p></div>
      )}
      <Field label="Agent AI team">
        <Select
          disabled={busy}
          value={teamID}
          onChange={(e) => {
            setTeamID(e.target.value);
            setModels("");
          }}
        >
          <option value="">Choose one policy team</option>
          {inventory.teams.map((t) => (
            <option key={t.team_id} value={t.team_id}>
              {inventory.groups.find((g) => g.id === t.team_id)?.name ??
                `Archived/unavailable group (${t.team_id})`}
            </option>
          ))}
        </Select>
      </Field>
      <p className={`ai-config-membership ai-config-membership-${membership}`}>
        {membership === "member"
          ? "Current group membership verified; the server rechecks it on every request."
          : membership === "loading"
            ? "Checking current group membership…"
            : membership === "error"
              ? "Could not verify current group membership."
              : "The agent must be an active member of the selected group before access can be enabled."}
      </p>
      {membership === "error" && (
        <Button onClick={() => setAttempt((v) => v + 1)}>
          Retry membership
        </Button>
      )}
      <Field label="Agent models (must narrow the team policy)">
        <textarea
          className={area}
          rows={3}
          value={models}
          onChange={(e) => setModels(e.target.value)}
        />
      </Field>
      <p className="text-xs text-ink-secondary">Leave agent models blank to inherit all models from the selected team.</p>
      {team && (
        <p className="ai-config-model-summary">
          Team models: {team.models.join(", ")}
        </p>
      )}
      <div className="ai-config-actions">
        <Button
          disabled={busy || !valid}
          onClick={() =>
            void save({
              team_id: teamID,
              enabled: true,
              models_override: lines(models),
              expected_revision: assignment?.revision ?? 0,
            })
          }
        >
          Save agent access
        </Button>
        {assignment && (
          <>
            <Button
              disabled={busy || !assignment.enabled}
              onClick={() =>
                void save({
                  team_id: assignment.team_id,
                  enabled: false,
                  models_override: assignment.models_override,
                  expected_revision: assignment.revision,
                })
              }
            >
              Disable agent access
            </Button>
            <Button disabled={busy} onClick={() => void reconcile()}>
              Retry synchronization
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
