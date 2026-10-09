import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { UsersTabRail } from "../components/WorkspaceTabs";
import { AgentsTabRail } from "../components/AgentsTabRail";
import { can } from "../lib/rbac";
import "../network-workspaces.css";
import "../agents-workspace.css";
import "../agents-management-workspace.css";
import { Badge, Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select, RefreshButton } from "../components/ui";
import { api, apiErrorMessage, listItems, loadOne, type AgentGroup, type AgentGroupMember, type GroupMember, type Member, type UserGroup } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { DIRECTORY_MANAGED_NOTE, isDirectoryManaged } from "../lib/idpsyncview";
import { relativeAge } from "../lib/format";
import "../users-groups-workspace.css";
import { LoadRetry } from "../components/LoadRetry";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { ResourceSummary } from "../components/ResourceSummary";
import { NetworkDetailList } from "../components/NetworkDetailList";

type Kind = "people" | "agents" | "directory";

function hasExactMemberCount(group: UserGroup | AgentGroup): boolean {
  return Number.isInteger(group.member_count) && group.member_count >= 0;
}

function memberLabel(count: number): string {
  return count === 1 ? "1 member" : `${count} members`;
}

type GroupScope = "people" | "agents";
export default function AccessGroups({ scope = "people" }: { scope?: GroupScope }) {
  const { org } = useOrg();
  const { state } = useAuth();
  if (scope === "people") {
    const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
    return <PeopleGroupsWorkspace key={`${org?.id ?? ""}:${actor}`} />;
  }
  const agentActor = state.status === "authed" ? `:${state.user.id}:${state.user.email_verified}:${state.user.must_change_password}` : `:${state.status}`;
  return <AccessGroupsLoader key={`${org?.id}:${scope}${agentActor}`} scope={scope} />;
}


function AccessGroupsLoader({ scope }: { scope: GroupScope }) {
  const { org } = useOrg();
  const { state } = useAuth();
  const writable = state.status === "authed" && state.user.email_verified && !state.user.must_change_password;
  const agentGroupsEnabled = scope === "agents" && Boolean(org?.agent_policy_templates_enabled);
  const [authorized, setAuthorized] = useState<boolean | null>(null);
  const [people, setPeople] = useState<UserGroup[] | null>(null);
  const [agentGroups, setAgentGroups] = useState<AgentGroup[] | null>(null);
  const [members, setMembers] = useState<Member[] | null>(null);
  const [error, setError] = useState("");
  const [permissionAttempt, setPermissionAttempt] = useState(0);
  const inventoryAlive = useRef(true), inventoryRequest = useRef(0);
  useEffect(() => { inventoryAlive.current = true; return () => { inventoryAlive.current = false; inventoryRequest.current++; }; }, []);
  const reload = useCallback(async () => {
    if (!org || authorized !== true) return;
    const request = ++inventoryRequest.current;
    setError("");
    setPeople(null);
    setAgentGroups(null);
    const [peopleResult, agentResult] = await Promise.all([
      scope === "people" ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: org.id } } })) : Promise.resolve({ ok: true as const, data: [] as UserGroup[] }),
      agentGroupsEnabled
        ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId: org.id } } }))
        : Promise.resolve({ ok: true as const, data: [] as AgentGroup[] }),
    ]);
    if (scope === "agents" && (!inventoryAlive.current || request !== inventoryRequest.current)) return;
    if (!peopleResult.ok || !agentResult.ok) { setError("Could not load the group inventory."); return; }
    setPeople(peopleResult.data);
    setAgentGroups(agentResult.data);
  }, [agentGroupsEnabled, authorized, org?.id, scope]);
  useEffect(() => {
    let cancelled = false;
    if (!org || state.status !== "authed") { setAuthorized(false); return; }
    setAuthorized(null);
    setError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); return; }
      if (!Array.isArray(result.data) || !result.data.every(member => member && typeof member.user_id === "string" && typeof member.role === "string")) { setError("Could not read current group permissions. Retry before managing groups."); return; }
      setMembers(result.data);
      const mine = result.data.find((member) => member.user_id === state.user.id);
      const roles = mine ? [mine.role, ...(mine.roles ?? [])] : [];
      setAuthorized(scope === "agents" ? writable && can(roles, "agent_template:manage") : roles.includes("owner") || roles.includes("admin"));
    });
    return () => { cancelled = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : "", writable, permissionAttempt, scope]);
  useEffect(() => { void reload(); }, [reload]);
  const header = <><PageHeader navigationTitle title={scope === "agents" ? "Agent groups" : "Users & Groups"} subtitle={scope === "agents" ? "Organize managed agents and their inherited policies." : "Manage people and directory-synced group membership."} />{scope === "agents" ? <AgentsTabRail /> : <UsersTabRail />}</>;
  if (!org || authorized === null) return <div className="network-management agents-workspace space-y-5">{header}<Card>{error ? <LoadRetry error={`Could not check group permissions: ${error}`} onRetry={() => setPermissionAttempt((attempt) => attempt + 1)} /> : <Loading label="Checking group permissions…" />}</Card></div>;
  if (!writable && scope === "agents") return <div className="network-management agents-workspace space-y-5">{header}<p role="status" className="text-cell text-ink-tertiary">Verify your email before managing AI Agent groups.</p></div>;
  if (!authorized) return <div className="network-management agents-workspace space-y-5">{header}<Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage groups.</p><ErrorText>{error}</ErrorText></Card></div>;
  if (!people || !agentGroups || !members) return <div className="network-management agents-workspace space-y-5">{header}<Card>{error ? <LoadRetry error={error} onRetry={() => void reload()} /> : <Loading label="Loading groups…" />}</Card></div>;
  return <CanonicalGroupsWorkspace orgId={org.id} people={people} agentGroups={agentGroups} agentGroupsEnabled={agentGroupsEnabled} peopleOptions={members} scope={scope} onReload={reload} />;
}

type CanonicalRow = {
  id: string;
  kind: Kind;
  name: string;
  memberCount: number;
  source: string;
  status: string;
  raw: UserGroup | AgentGroup;
};

function CanonicalGroupsWorkspace({
  orgId,
  people,
  agentGroups,
  agentGroupsEnabled,
  peopleOptions,
  onReload,
  scope,
}: {
  orgId: string;
  scope: GroupScope;
  people: UserGroup[];
  agentGroups: AgentGroup[];
  agentGroupsEnabled: boolean;
  peopleOptions: Member[];
  onReload: () => Promise<void>;
}) {
  const [search, setSearch] = useSearchParams();
  const [selectedMembers, setSelectedMembers] = useState<Array<GroupMember | AgentGroupMember> | null>(null);
  const [agentOptions, setAgentOptions] = useState<Array<{ device_id: string; name: string }>>([]);
  const [dialog, setDialog] = useState<"create" | "rename" | "add" | "remove" | "archive" | null>(null);
  const [createKind, setCreateKind] = useState<"people" | "agents">("people");
  const [name, setName] = useState("");
  const [memberId, setMemberId] = useState("");
  const [removing, setRemoving] = useState<GroupMember | AgentGroupMember | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [memberPage, setMemberPage] = useState(1), [memberPageSize, setMemberPageSize] = useState(20), [memberQuery, setMemberQuery] = useState("");
  const [memberError, setMemberError] = useState("");
  const [membersFor, setMembersFor] = useState("");
  const [agentCursor, setAgentCursor] = useState<string | null>(null), [candidateError, setCandidateError] = useState("");
  const [candidateLoading, setCandidateLoading] = useState(false), [candidateAttempt, setCandidateAttempt] = useState(0), [candidatePageFailure, setCandidatePageFailure] = useState(false);
  const agentAlive = useRef(true), memberRequest = useRef(0), agentRequest = useRef(0), agentLocked = useRef(false);
  useEffect(() => { agentAlive.current = true; return () => { agentAlive.current = false; memberRequest.current++; agentRequest.current++; }; }, []);
  const requestedType = (search.get("type") as "all" | Kind | null) ?? "all";
  const type = scope === "agents" ? "agents" : requestedType === "people" || requestedType === "directory" ? requestedType : "all";
  const selectedId = search.get("group") ?? "";
  const query = search.get("q") ?? "";
  const currentMembers = scope === "agents" && membersFor !== selectedId ? null : selectedMembers;
  const currentMemberError = scope === "agents" && membersFor !== selectedId ? "" : memberError;
  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(search);
    Object.entries(changes).forEach(([key, value]) => value ? next.set(key, value) : next.delete(key));
    setSearch(next);
  };
  const rows = useMemo<CanonicalRow[]>(() => [
    ...people.map((group) => ({ id: `people:${group.id}`, kind: isDirectoryManaged(group) ? "directory" as const : "people" as const, name: group.name, memberCount: group.member_count, source: isDirectoryManaged(group) ? "Directory sync" : "Manual", status: isDirectoryManaged(group) ? "Synced" : "Active", raw: group })),
    ...agentGroups.map((group) => ({ id: `agents:${group.id}`, kind: "agents" as const, name: group.name, memberCount: group.member_count, source: "Manual", status: "Active", raw: group })),
  ], [people, agentGroups]);
  // `member_count` is a required bounded-list contract. A stale control plane
  // must be visible as such; it must never render an invented zero or an
  // interpolation such as "undefined members".
  const countsValid = people.every(hasExactMemberCount) && agentGroups.every(hasExactMemberCount);
  const selected = rows.find((row) => row.id === selectedId);
  const visible = rows.filter((row) => (type === "all" || row.kind === type) && row.name.toLowerCase().includes(query.toLowerCase()));
  const typeCounts = {
    all: rows.length,
    people: rows.filter((row) => row.kind === "people").length,
    agents: rows.filter((row) => row.kind === "agents").length,
    directory: rows.filter((row) => row.kind === "directory").length,
  };
  const createLabel = scope === "agents" ? "Create agent group" : "Create people group";
  const canCreate = type !== "directory" && (scope === "people" || agentGroupsEnabled);
  const visibleTypes: Array<"all" | Kind> = scope === "agents" ? [] : ["all", "people", "directory"];
  const inventoryDescription = agentGroupsEnabled
    ? `${rows.length} agent groups. Manage membership and inherited policies.`
    : `${rows.length} groups across people and directory sources.`;
  const loadSelected = useCallback(async () => {
    const request = ++memberRequest.current;
    if (scope === "agents") setMemberError("");
    if (!selected) { setSelectedMembers(null); return; }
    setSelectedMembers(null);
    const groupId = selected.raw.id;
    const result = selected.kind === "agents"
      ? await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", { params: { path: { orgId, groupId } } }))
      : await loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId, groupId } } }));
    if (scope === "agents" && (!agentAlive.current || request !== memberRequest.current)) return;
    if (scope === "agents") setMembersFor(selectedId);
    if (!result.ok) { if (scope === "agents") setMemberError(result.error); else setError(result.error); return; }
    setSelectedMembers(result.data);
  }, [orgId, selectedId]);
  useEffect(() => { void loadSelected(); }, [loadSelected]);
  useEffect(() => {
    if (scope === "agents") { setMemberPage(1); setMemberQuery(""); setDialog(null); setRemoving(null); setMemberId(""); }
  }, [selectedId, scope]);
  useEffect(() => {
    if (selected?.kind !== "agents") return;
    let active = true; const request = ++agentRequest.current;
    if (scope === "agents") { setCandidateError(""); setCandidateLoading(true); setCandidatePageFailure(false); }
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId }, ...(scope === "agents" ? { query: { limit: 100 } } : {}) } })).then((result) => {
      if (scope === "agents" && (!active || !agentAlive.current || request !== agentRequest.current)) return;
      if (result.ok) { setAgentOptions(listItems(result.data).map((agent) => ({ device_id: agent.device_id, name: agent.name }))); if (scope === "agents") setAgentCursor(result.data.next_cursor ?? null); }
      else if (scope === "agents") setCandidateError("Could not load available agents. Retry before adding a member.");
      if (scope === "agents") setCandidateLoading(false);
    });
    return () => { active = false; };
  }, [orgId, selected?.kind, scope, candidateAttempt]);
  async function moreCandidates() {
    if (!agentCursor || candidateLoading || busy) return;
    const cursor = agentCursor, request = agentRequest.current;
    setCandidateLoading(true); setCandidateError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId }, query: { limit: 100, cursor } } }));
    if (!agentAlive.current || request !== agentRequest.current) return;
    if (!result.ok || result.data.next_cursor === cursor) { setCandidatePageFailure(true); setCandidateError("Could not load more agents. Your selection is preserved; retry loading more agents."); }
    else { setCandidatePageFailure(false); setAgentOptions((current) => [...new Map([...current, ...result.data.items.map((agent) => ({ device_id: agent.device_id, name: agent.name }))].map((agent) => [agent.device_id, agent])).values()]); setAgentCursor(result.data.next_cursor ?? null); }
    setCandidateLoading(false);
  }
  async function action(call: () => Promise<{ error?: unknown }>, fallback: string, success: string) {
    if (scope === "agents" && (!agentGroupsEnabled || agentLocked.current || !agentAlive.current)) return false;
    if (scope === "agents") agentLocked.current = true;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await call();
      if (scope === "agents" && !agentAlive.current) return false;
      if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; }
      setNotice(success);
      return true;
    } catch { if (scope !== "agents" || agentAlive.current) setError("Could not reach the API."); return false; }
    finally { if (scope === "agents") agentLocked.current = false; if (scope !== "agents" || agentAlive.current) setBusy(false); }
  }
  async function create() {
    if (!name.trim()) return;
    const ok = await action(() => createKind === "agents"
      ? api.POST("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId } }, body: { name: name.trim() } })
      : api.POST("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } }, body: { name: name.trim() } }), "Could not create the group.", "Group created. Add members to make its scope effective.");
    if (ok) { setDialog(null); setName(""); await onReload(); }
  }
  async function rename() {
    if (!selected || selected.kind === "directory" || !name.trim()) return;
    const groupId = selected.raw.id;
    const ok = await action(() => selected.kind === "agents"
      ? api.PATCH("/api/v1/organizations/{orgId}/agent-groups/{groupId}", { params: { path: { orgId, groupId } }, body: { name: name.trim() } })
      : api.PATCH("/api/v1/organizations/{orgId}/groups/{groupId}", { params: { path: { orgId, groupId } }, body: { name: name.trim() } }), "Could not rename the group.", "Group renamed. Existing references follow its identity.");
    if (ok) { setDialog(null); await onReload(); }
  }
  async function addMember() {
    if (!selected || selected.kind === "directory" || !memberId || (scope === "agents" && (!currentMembers || currentMemberError || candidateError || candidateLoading || !agentOptions.some((agent) => agent.device_id === memberId)))) return;
    const groupId = selected.raw.id;
    const ok = await action(() => selected.kind === "agents"
      ? api.POST("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", { params: { path: { orgId, groupId } }, body: { device_id: memberId } })
      : api.POST("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId, groupId } }, body: { user_id: memberId } }), "Could not add the member.", selected.kind === "agents" ? "Agent added. Desired inherited configuration was queued, not confirmed applied." : "Person added. This group’s network rules and granted AI models now include them.");
    if (ok) { setDialog(null); setMemberId(""); await Promise.all([loadSelected(), onReload()]); }
  }
  async function removeMember() {
    if (!selected || selected.kind === "directory" || !removing) return;
    const groupId = selected.raw.id;
    const memberKey = selected.kind === "agents" ? (removing as AgentGroupMember).device_id : (removing as GroupMember).user_id;
    const ok = await action(() => selected.kind === "agents"
      ? api.DELETE("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members/{deviceId}", { params: { path: { orgId, groupId, deviceId: memberKey } } })
      : api.DELETE("/api/v1/organizations/{orgId}/groups/{groupId}/members/{userId}", { params: { path: { orgId, groupId, userId: memberKey } } }), "Could not remove the member.", selected.kind === "agents" ? "Agent removed. Its group-derived desired configuration was withdrawn; other members are unchanged." : "Person removed. Network rules and AI models granted only through this group no longer apply to them.");
    if (ok) { setDialog(null); setRemoving(null); await Promise.all([loadSelected(), onReload()]); }
  }
  async function archive() {
    if (!selected || selected.kind === "directory") return;
    const groupId = selected.raw.id;
    const ok = await action(() => selected.kind === "agents"
      ? api.DELETE("/api/v1/organizations/{orgId}/agent-groups/{groupId}", { params: { path: { orgId, groupId } } })
      : api.DELETE("/api/v1/organizations/{orgId}/groups/{groupId}", { params: { path: { orgId, groupId } } }), "Could not archive the group.", "Group archived. Nothing was silently cascaded.");
    if (ok) { setDialog(null); update({ group: null }); await onReload(); }
  }
  const candidates = selected?.kind === "agents" ? agentOptions : peopleOptions;
  const memberIds = new Set((currentMembers ?? []).map((member) => selected?.kind === "agents" ? (member as AgentGroupMember).device_id : (member as GroupMember).user_id));
  if (scope === "agents") {
    const currentPage = Math.min(page, Math.max(1, Math.ceil(visible.length / pageSize)));
    const groupRows = visible.slice((currentPage - 1) * pageSize, currentPage * pageSize);
    const matchedMembers = (currentMembers ?? []).filter((member) => (member as AgentGroupMember).name.toLowerCase().includes(memberQuery.trim().toLowerCase()));
    const currentMemberPage = Math.min(memberPage, Math.max(1, Math.ceil(matchedMembers.length / memberPageSize)));
    const memberRows = matchedMembers.slice((currentMemberPage - 1) * memberPageSize, currentMemberPage * memberPageSize);
    const closeDialog = () => { if (!busy) setDialog(null); };
    const openCreate = () => { setCreateKind("agents"); setName(""); setDialog("create"); };
    return <div className="network-management agents-workspace agents-management space-y-5">
      <PageHeader navigationTitle title="Agent groups" />
      <AgentsTabRail actions={<><RefreshButton label="Refresh groups" disabled={busy} onClick={() => void onReload()} />{agentGroupsEnabled && countsValid && !selected && <Button disabled={busy} onClick={openCreate}>Create agent group</Button>}</>} />
      <div className="agents-management-content">
      <ErrorText>{error}</ErrorText>{notice && <p role="status" className="agents-management-notice">{notice}</p>}
      {!agentGroupsEnabled ? <AppAccessEmptyState icon={null} title="Agent groups are turned off" description="Enable this organization’s opt-in for agent groups and network policy templates." action={<Link className="agents-management-link" to="/settings?section=features&feature=agent-templates">Configure AI Agent settings</Link>} /> : !countsValid ? <p role="alert">Member counts require the matching control-plane API version. Refresh when the server can return a valid count for every group.</p> : selected ? <>
        <nav aria-label="Breadcrumb" className="agents-management-breadcrumb"><button disabled={busy} onClick={() => update({ group: null })}>Agent groups</button><span aria-hidden="true">/</span><span aria-current="page">{selected.name}</span></nav>
        <div className="agents-management-heading"><div><h2>{selected.name}</h2></div><div className="agents-management-actions"><Button disabled={busy || !currentMembers || !!currentMemberError} onClick={() => { setMemberId(""); setDialog("add"); }}>Add member</Button><AppAccessRowMenu label={`Actions for ${selected.name}`} actions={[
          { key: "rename", label: "Rename", disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => { setName(selected.name); setDialog("rename"); } },
          { key: "archive", label: "Archive", danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => setDialog("archive") },
          { key: "network", label: "Network templates", href: `/agents/policies?group=${encodeURIComponent(selected.raw.id)}` },
          { key: "models", label: "Model policies", href: "/agents/model-access" },
        ]} /></div></div>
        <ResourceSummary title="Group settings" className="group-saved-summary" footer={<Button variant="ghost" disabled={busy} onClick={() => update({ group: null })}>Back to groups</Button>}><div className="group-detail-content"><dl className="tnx-resource-facts"><div><dt>Reported membership</dt><dd>{memberLabel(selected.memberCount)}</dd></div><div><dt>Group identity</dt><dd>{selected.raw.id}</dd></div></dl>
        {currentMemberError ? <LoadRetry error={currentMemberError} onRetry={() => void loadSelected()} /> : currentMembers === null ? <Loading label="Loading members…" /> : <>
          <div className="agents-management-toolbar"><Input aria-label="Search agent group members" value={memberQuery} placeholder="Search members" onChange={(event) => { setMemberQuery(event.target.value); setMemberPage(1); }} /><Link className="agents-management-link" to="/audit">View audit context</Link></div>
          <DataTable variant="flat" caption="Agent group members" rows={memberRows} rowKey={(member) => (member as AgentGroupMember).device_id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={memberQuery ? "No matching members" : "No members."} description={memberQuery ? "Try another agent name." : "Add agents to share this group’s desired configuration."} action={memberQuery ? <Button variant="ghost" onClick={() => { setMemberQuery(""); setMemberPage(1); }}>Clear search</Button> : undefined} />} columns={[
            { key: "name", header: "Agent", cell: (member) => <Link className="agents-management-name" to={`/agents/${encodeURIComponent((member as AgentGroupMember).device_id)}`}>{(member as AgentGroupMember).name}</Link> },
            { key: "status", header: "Status", cell: (member) => (member as AgentGroupMember).status },
            { key: "actions", header: "Actions", cell: (member) => <AppAccessRowMenu label={`Actions for ${(member as AgentGroupMember).name}`} actions={[{ key: "remove", label: "Remove member", danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => { setRemoving(member); setDialog("remove"); } }]} /> },
          ]} />
          <AppAccessPagination maxOffset={null} page={currentMemberPage} pageSize={memberPageSize} count={memberRows.length} hasNext={currentMemberPage * memberPageSize < matchedMembers.length} busy={busy} onPageChange={setMemberPage} onPageSizeChange={(size) => { setMemberPageSize(size); setMemberPage(1); }} />
        </>}
        <details className="agents-management-help"><summary>Inherited group configuration</summary><p>Adding members queues desired inherited configuration; queued does not mean applied. Removing a member withdraws its group-derived desired configuration after reconciliation. Model policies, network templates, and MCP tool permissions remain separate.</p></details></div></ResourceSummary>
      </> : <>
        <div className="agents-management-toolbar"><Input aria-label="Search groups" value={query} placeholder="Search agent groups" onChange={(event) => { setPage(1); update({ q: event.target.value || null }); }} /></div>
        <DataTable variant="flat" caption="Groups inventory" rows={groupRows} rowKey={(row) => row.id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={query ? "No matching agent groups" : "No agent groups yet"} description={query ? "Try another group name." : "Create a group, then add agents and choose inherited policies."} action={query ? <Button variant="ghost" onClick={() => { update({ q: null }); setPage(1); }}>Clear search</Button> : undefined} />} columns={[
          { key: "name", header: "Agent group", cell: (row) => <button className="agents-management-name" onClick={() => update({ group: row.id })}>{row.name}</button> },
          { key: "members", header: "Members", cell: (row) => memberLabel(row.memberCount) },
          { key: "actions", header: "Actions", cell: (row) => <AppAccessRowMenu label={`Actions for ${row.name}`} actions={[{ key: "open", label: "Members & policies", onSelect: () => update({ group: row.id }) }]} /> },
        ]} />
        <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={groupRows.length} hasNext={currentPage * pageSize < visible.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
      </>}
      </div>
      {dialog === "create" && agentGroupsEnabled && <Modal title="Create group" placement="right" size="enrollment" showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void create()}>Create group</Button></>}><div className="agents-group-editor"><ErrorText>{error}</ErrorText><Field label="Name"><Input autoFocus maxLength={100} disabled={busy} value={name} onChange={(event) => setName(event.target.value)} /></Field><p>Members share this group’s desired inherited configuration.</p></div></Modal>}
      {agentGroupsEnabled && dialog === "rename" && selected && <Modal title="Rename group" placement="right" size="enrollment" showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void rename()}>Save name</Button></>}><div className="agents-group-editor"><ErrorText>{error}</ErrorText><Field label="Name"><Input autoFocus maxLength={100} disabled={busy} value={name} onChange={(event) => setName(event.target.value)} /></Field><p>Existing rules and assignments keep their group identity.</p></div></Modal>}
      {agentGroupsEnabled && dialog === "add" && selected && <Modal title="Add agent member" placement="right" size="enrollment" showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button disabled={busy || !memberId || !currentMembers || !!currentMemberError || candidateLoading || !!candidateError} onClick={() => void addMember()}>Add member</Button></>}><div className="agents-group-editor"><ErrorText>{error}</ErrorText>{candidateError && <LoadRetry error={candidateError} onRetry={() => candidatePageFailure ? void moreCandidates() : setCandidateAttempt((value) => value + 1)} />}{agentOptions.filter((agent) => !memberIds.has(agent.device_id)).length > 10 ? <fieldset><legend className="mb-2 text-sm text-ink-heading">Agent</legend><NetworkDetailList label="Available agent members" items={agentOptions.filter((agent) => !memberIds.has(agent.device_id))} searchText={(agent) => agent.name} renderItem={(agent) => <li key={agent.device_id}><label><input type="radio" name="agent-group-candidate" aria-label={`Select ${agent.name}`} checked={memberId === agent.device_id} disabled={busy || candidateLoading} onChange={() => setMemberId(agent.device_id)} /><span>{agent.name}</span></label></li>} /></fieldset> : <Field label="Agent"><Select value={memberId} disabled={busy || candidateLoading} onChange={(event) => setMemberId(event.target.value)}><option value="">Select agent</option>{agentOptions.filter((agent) => !memberIds.has(agent.device_id)).map((agent) => <option key={agent.device_id} value={agent.device_id}>{agent.name}</option>)}</Select></Field>}{memberId && <p>Selected: {agentOptions.find((agent) => agent.device_id === memberId)?.name}</p>}{candidateLoading && <Loading label="Loading available agents…" />}{agentCursor && <Button variant="ghost" disabled={busy || candidateLoading} onClick={() => void moreCandidates()}>Load more agents</Button>}<p>Adding an agent queues inherited configuration. Queued does not mean applied.</p></div></Modal>}
      {agentGroupsEnabled && dialog === "remove" && selected && <Modal title="Remove member?" danger showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void removeMember()}>Remove member</Button></>}><ErrorText>{error}</ErrorText><p>Remove {(removing as AgentGroupMember | null)?.name} from {selected.name}? Its group-derived desired configuration will be withdrawn after reconciliation. Other members are unchanged. Recovery requires explicitly adding it again.</p></Modal>}
      {agentGroupsEnabled && dialog === "archive" && selected && <Modal title="Archive group" danger showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void archive()}>Archive group</Button></>}><ErrorText>{error}</ErrorText><p>Remove members and attached policy/template assignments first. The server refuses unsafe archive; nothing is silently cascaded. Recovery requires a new group and explicit membership and assignments.</p></Modal>}
    </div>;
  }
  if (!countsValid) return <div className="network-management agents-workspace space-y-5">
    <PageHeader navigationTitle title="Users & Groups" subtitle="People, managed-agent, and directory-synced groups in one operational inventory." actions={canCreate ? <Button onClick={() => { setCreateKind(type === "agents" ? "agents" : "people"); setName(""); setDialog("create"); }}>{createLabel}</Button> : undefined} />
    <UsersTabRail />
    <Card><p role="alert" className="text-cell text-ink-tertiary">Member counts require the matching control-plane API version.</p><p className="mt-2 text-cell text-ink-tertiary">The inventory is withheld until the server returns a non-negative member count for every group.</p></Card>
  </div>;
  return <div className="network-management agents-workspace space-y-5">
    <PageHeader navigationTitle title="Users & Groups" subtitle={inventoryDescription} actions={canCreate ? <Button onClick={() => { setCreateKind(type === "agents" ? "agents" : "people"); setName(""); setDialog("create"); }}>{createLabel}</Button> : undefined} />
    <UsersTabRail />
    <div className="flex flex-wrap items-center gap-2"><Input aria-label="Search groups" className="min-w-[14rem] flex-1 sm:max-w-sm" value={query} placeholder="Search groups" onChange={(event) => update({ q: event.target.value || null })} />{visibleTypes.map((value) => <Button key={value} size="sm" variant={type === value ? "primary" : "ghost"} onClick={() => update({ type: value === "all" ? null : value, group: null })}>{value === "all" ? "All" : value[0].toUpperCase() + value.slice(1)} <span className="ml-1 text-ink-tertiary">{typeCounts[value]}</span></Button>)}</div>
    <ErrorText>{error}</ErrorText>{notice && <p role="status" className="text-sm text-ok">{notice}</p>}
    <Card><DataTable caption="Groups inventory" rows={visible} rowKey={(row) => row.id} failed={false} filterable={false} pageSize={0} empty={<EmptyState>No groups match this view.</EmptyState>} columns={[{ key: "name", header: "Group name", cell: (row) => <button type="button" className="font-medium text-ink-heading hover:underline" onClick={() => update({ group: row.id })}>{row.name}</button> }, { key: "type", header: "Type", cell: (row) => <Badge tone="neutral">{row.kind === "agents" ? "Agent" : row.kind === "directory" ? "Directory" : "People"}</Badge> }, { key: "members", header: "Members", cell: (row) => memberLabel(row.memberCount) }, { key: "source", header: "Source", cell: (row) => row.source }, { key: "status", header: "Status", cell: (row) => <Badge tone={row.kind === "directory" ? "neutral" : "ok"}>{row.status}</Badge> }]} /></Card>
    {selected && dialog === null && <Modal title={selected.name} onDismiss={() => update({ group: null })} actions={<Button variant="ghost" onClick={() => update({ group: null })}>Close</Button>}><div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm text-ink-tertiary"><Badge tone={selected.kind === "directory" ? "neutral" : "ok"}>{selected.status}</Badge><span>{selected.kind === "agents" ? "Agent" : selected.kind === "directory" ? "Directory" : "People"}</span><span>{memberLabel(selected.memberCount)}</span><span>{selected.source}</span></div>
      {selected.kind !== "directory" && <div className="flex flex-wrap gap-2"><Button size="sm" onClick={() => setDialog("add")}>Add member</Button><Button size="sm" variant="ghost" onClick={() => { setName(selected.name); setDialog("rename"); }}>Rename</Button><Button size="sm" variant="danger" onClick={() => setDialog("archive")}>Archive</Button></div>}
      <section className="border-t border-white/10 pt-3"><h3 className="text-sm font-medium text-ink-heading">Members</h3>{selectedMembers === null ? <Loading label="Loading members…" /> : selectedMembers.length === 0 ? <p className="mt-2 text-sm text-ink-tertiary">No members.</p> : <div className="mt-2 max-h-72 divide-y divide-white/10 overflow-y-auto">{selectedMembers.map((member) => { const id = selected.kind === "agents" ? (member as AgentGroupMember).device_id : (member as GroupMember).user_id; const label = selected.kind === "agents" ? (member as AgentGroupMember).name : (member as GroupMember).name || (member as GroupMember).email; return <div key={id} className="flex items-center justify-between gap-3 py-2 text-sm"><span>{label}</span>{selected.kind !== "directory" && <Button size="sm" variant="ghost" disabled={busy} aria-label={`Remove ${label}`} onClick={() => { setRemoving(member); setDialog("remove"); }}>Remove</Button>}</div>; })}</div>}</section>
      <Link className="inline-block text-sm text-accent-400 hover:underline" to="/audit">View audit context</Link>
    </div></Modal>}
    {dialog === "create" && <Modal title="Create group" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void create()}>Create group</Button></>}><div className="space-y-3"><p className="text-xs text-ink-tertiary">{createKind === "agents" ? "Shares inherited configuration with managed agents." : "Defines people used as policy subjects."}</p><Field label="Name"><Input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field></div></Modal>}
    {dialog === "rename" && <Modal title="Rename group" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void rename()}>Save name</Button></>}><Field label="Name"><Input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field><p className="mt-2 text-xs text-ink-tertiary">Rules and assignments follow the group identity, so renaming does not rebuild their scope.</p></Modal>}
    {dialog === "add" && <Modal title={`Add ${selected?.kind === "agents" ? "agent" : "person"} member`} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !memberId} onClick={() => void addMember()}>Add member</Button></>}><p className="mb-3 text-cell text-ink-tertiary">{selected?.kind === "agents" ? "Adding an agent can give it this group’s desired inherited configuration. Queued does not mean applied." : "Adding a person expands rules that use this group as a subject."}</p><Field label={selected?.kind === "agents" ? "Agent" : "Person"}><Select value={memberId} onChange={(event) => setMemberId(event.target.value)}><option value="">Select {selected?.kind === "agents" ? "agent" : "person"}</option>{candidates.filter((candidate) => !memberIds.has(selected?.kind === "agents" ? (candidate as { device_id: string }).device_id : (candidate as Member).user_id)).map((candidate) => { const id = selected?.kind === "agents" ? (candidate as { device_id: string }).device_id : (candidate as Member).user_id; const label = selected?.kind === "agents" ? (candidate as { name: string }).name : (candidate as Member).name || (candidate as Member).email; return <option key={id} value={id}>{label}</option>; })}</Select></Field></Modal>}
    {dialog === "remove" && <Modal title="Remove member?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void removeMember()}>Remove member</Button></>}><p className="text-cell text-ink-tertiary">{selected?.kind === "agents" ? "This removes the agent’s inherited group context. Desired configuration is withdrawn after server reconciliation; other members are unchanged." : "This removes the person from this policy subject group. Rules scoped only through this group no longer apply to them."} Recovery is to explicitly add the member back.</p></Modal>}
    {dialog === "archive" && <Modal title="Archive group" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void archive()}>Archive group</Button></>}><p className="text-cell text-ink-tertiary">The server refuses unsafe archive. Remove members and attached policy/template assignments first; nothing is silently cascaded. Recovery requires recreating the group and restoring membership and assignments explicitly.</p></Modal>}
  </div>;
}

// People groups have their own read and mutation lifecycle; the AI Agent workspace above stays independent.
type PeopleGroupDialog = "rename" | "add" | "remove" | "archive" | null;
function validPeopleGroups(value: unknown): value is UserGroup[] {
  return Array.isArray(value) && value.every((group) => group && typeof group === "object" && typeof group.id === "string" && group.id.length > 0 && typeof group.name === "string" && (group.origin === undefined || group.origin === "manual" || group.origin === "idp_sync")) && new Set(value.map((group) => group.id)).size === value.length;
}
function validPeopleMembers(value: unknown): value is GroupMember[] {
  return Array.isArray(value) && value.every((member) => member && typeof member === "object" && typeof member.user_id === "string" && member.user_id.length > 0 && typeof member.email === "string" && typeof member.name === "string" && typeof member.added_at === "string") && new Set(value.map((member) => member.user_id)).size === value.length;
}
function validPeopleCandidates(value: unknown): value is Member[] {
  return Array.isArray(value) && value.every((member) => member && typeof member === "object" && typeof member.user_id === "string" && member.user_id.length > 0 && typeof member.email === "string" && typeof member.name === "string") && new Set(value.map((member) => member.user_id)).size === value.length;
}

function PeopleGroupsWorkspace() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [search, setSearch] = useSearchParams();
  const [permission, setPermission] = useState<boolean | null>(null), [permissionError, setPermissionError] = useState("");
  const [permissionAttempt, setPermissionAttempt] = useState(0);
  const [groups, setGroups] = useState<UserGroup[] | null>(null), [inventoryError, setInventoryError] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [createOpen, setCreateOpen] = useState(false), [name, setName] = useState(""), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [opening, setOpening] = useState<PeopleGroupDialog>(null);
  const alive = useRef(true), inventoryRequest = useRef(0), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; inventoryRequest.current++; }; }, []);
  const orgId = org?.id ?? "";
  const canWrite = permission === true && state.status === "authed" && state.user.email_verified;
  const selectedKey = search.get("group") ?? "";
  const selected = groups?.find((group) => `people:${group.id}` === selectedKey);
  const query = search.get("q") ?? "";
  const source = search.get("type") === "directory" ? "directory" : search.get("type") === "people" ? "people" : "all";
  function update(changes: Record<string, string | null>) {
    const next = new URLSearchParams(search);
    Object.entries(changes).forEach(([key, value]) => value ? next.set(key, value) : next.delete(key));
    setSearch(next);
  }
  useEffect(() => {
    let current = true;
    setPermission(null); setPermissionError(""); setGroups(null); setInventoryError("");
    if (!orgId || state.status !== "authed") { setPermission(false); return; }
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })).then((result) => {
      if (!current || !alive.current) return;
      if (!result.ok) { setPermissionError(result.error); return; }
      if (!Array.isArray(result.data) || !result.data.every((member) => member && typeof member.user_id === "string" && typeof member.role === "string" && (member.roles === undefined || Array.isArray(member.roles)))) { setPermissionError("The permission response was not valid. Retry to reload it."); return; }
      const mine = result.data.find((member) => member.user_id === state.user.id);
      const roles = mine?.roles ?? (mine ? [mine.role] : []);
      setPermission(roles.includes("owner") || roles.includes("admin"));
    });
    return () => { current = false; };
  }, [orgId, state.status, state.status === "authed" ? state.user.id : "", state.status === "authed" ? state.user.email_verified : false, permissionAttempt]);
  const reload = useCallback(async () => {
    if (!orgId || permission !== true) return false;
    const request = ++inventoryRequest.current;
    setGroups(null); setInventoryError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } } }));
    if (!alive.current || request !== inventoryRequest.current) return false;
    if (!result.ok || !validPeopleGroups(result.data)) { setInventoryError("Could not load the group inventory."); return false; }
    if (!result.data.every(hasExactMemberCount)) { setInventoryError("Member counts require the matching control-plane API version. The inventory is withheld until every group has a non-negative member count."); return false; }
    setGroups(result.data); return true;
  }, [orgId, permission]);
  useEffect(() => { void reload(); }, [reload]);
  async function createPeopleGroup() {
    if (!canWrite || source === "directory" || locked.current || !alive.current || !groups || !name.trim()) return;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const { error: failure } = await api.POST("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId } }, body: { name: name.trim() } });
      if (!alive.current) return;
      if (failure) { setError(apiErrorMessage(failure, "Could not create the group.")); return; }
      setCreateOpen(false); setName(""); setNotice("Group created. Add members to make its scope effective."); await reload();
    } catch {
      if (!alive.current) return;
      setCreateOpen(false); setError("Creation was not confirmed. Review the refreshed inventory before trying again."); await reload();
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  function openGroup(group: UserGroup, action: PeopleGroupDialog = null) { if (busy) return; setOpening(action); update({ group: `people:${group.id}` }); }
  const matching = (groups ?? []).filter((group) => (source === "all" || (source === "directory") === isDirectoryManaged(group)) && group.name.toLowerCase().includes(query.trim().toLowerCase()));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(matching.length / pageSize)));
  const visible = matching.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const actions = <><RefreshButton label="Refresh" disabled={busy} onClick={() => { setCreateOpen(false); setOpening(null); setPage(1); void reload(); }} />{canWrite && groups && source !== "directory" && !selectedKey && <Button disabled={busy} onClick={() => { setName(""); setError(""); setCreateOpen(true); }}>Create group</Button>}</>;
  return <div className="network-management users-workspace users-groups-workspace space-y-5">
    <UsersTabRail actions={permission === true ? actions : undefined} />
    <div className="users-groups-content">
      {!createOpen && <ErrorText>{error}</ErrorText>}{notice && <p role="status" className="users-groups-notice">{notice}</p>}
      {!org || permission === null ? permissionError ? <LoadRetry error={`Could not check group permissions: ${permissionError}`} onRetry={() => { setPermission(null); setPermissionAttempt((attempt) => attempt + 1); }} /> : <Loading label="Checking group permissions…" /> : !permission ? <p role="alert" className="users-groups-copy">You do not have permission to manage groups.</p> : inventoryError ? <LoadRetry error={inventoryError} onRetry={() => void reload()} /> : !groups ? <Loading label="Loading groups…" /> : selected ? <PeopleGroupMembers key={selected.id} orgId={orgId} group={selected} canWrite={canWrite} initialDialog={opening} onBack={() => { setOpening(null); update({ group: null }); }} onReload={reload} onNotice={setNotice} /> : selectedKey ? <div><p role="alert" className="users-groups-copy">This group is not available in the current organization.</p><Button variant="ghost" onClick={() => { setOpening(null); update({ group: null }); }}>Back to groups</Button></div> : <>
        {!canWrite && <p className="users-groups-copy">Verify your email to manage groups.</p>}
        <div className="users-groups-toolbar"><Input aria-label="Search groups" value={query} placeholder="Search groups" onChange={(event) => { setPage(1); update({ q: event.target.value || null }); }} /><Select width="auto" aria-label="Group source" value={source} onChange={(event) => { setPage(1); update({ type: event.target.value === "all" ? null : event.target.value }); }}><option value="all">All sources</option><option value="people">Manual</option><option value="directory">Directory sync</option></Select></div>
        <DataTable variant="flat" caption="Groups inventory" rows={visible} rowKey={(group) => group.id} rowLabel={(group) => group.name} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={query || source !== "all" ? "No matching groups" : "No groups yet"} description={query || source !== "all" ? "Try another name or source." : canWrite ? "Create a people group, then add organization members." : "Groups will appear here when an administrator creates or syncs them."} action={query || source !== "all" ? <Button variant="ghost" onClick={() => { setPage(1); update({ q: null, type: null }); }}>Clear filters</Button> : undefined} />} columns={[
          { key: "name", header: "Group", cell: (group) => <button className="users-groups-name" onClick={() => openGroup(group)}>{group.name}</button> },
          { key: "members", header: "Members", cell: (group) => memberLabel(group.member_count) },
          { key: "source", header: "Source", cell: (group) => <span className="users-groups-copy">{isDirectoryManaged(group) ? "Directory sync · Read only" : "Manual"}</span> },
          { key: "actions", header: "Actions", cell: (group) => <AppAccessRowMenu label={`Actions for ${group.name}`} actions={[{ key: "members", label: "View members", onSelect: () => openGroup(group) }, ...(canWrite && !isDirectoryManaged(group) ? [{ key: "rename", label: "Rename", onSelect: () => openGroup(group, "rename") }, { key: "archive", label: "Archive", danger: true, onSelect: () => openGroup(group, "archive") }] : [])]} /> },
        ]} />
        <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={visible.length} hasNext={currentPage * pageSize < matching.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPage(1); setPageSize(size); }} />
      </>}
    </div>
    {createOpen && canWrite && source !== "directory" && groups && <Modal title="Create group" placement="right" size="enrollment" showClose onDismiss={() => !busy && setCreateOpen(false)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setCreateOpen(false)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void createPeopleGroup()}>{busy ? "Creating…" : "Create group"}</Button></>}><div className="users-groups-editor"><ErrorText>{error}</ErrorText><Field label="Name"><Input autoFocus disabled={busy} value={name} onChange={(event) => setName(event.target.value)} /></Field><p>Use this group as a subject for shared access policies.</p></div></Modal>}
  </div>;
}

function PeopleGroupMembers({ orgId, group, canWrite, initialDialog, onBack, onReload, onNotice }: { orgId: string; group: UserGroup; canWrite: boolean; initialDialog: PeopleGroupDialog; onBack: () => void; onReload: () => Promise<boolean>; onNotice: (notice: string) => void }) {
  const directory = isDirectoryManaged(group), editable = canWrite && !directory;
  const [members, setMembers] = useState<GroupMember[] | null>(null), [memberError, setMemberError] = useState("");
  const [candidates, setCandidates] = useState<Member[] | null>(null), [candidateError, setCandidateError] = useState("");
  const [candidateAttempt, setCandidateAttempt] = useState(0), [dialog, setDialog] = useState<PeopleGroupDialog>(editable ? initialDialog : null);
  const [memberId, setMemberId] = useState(""), [name, setName] = useState(group.name), [removing, setRemoving] = useState<GroupMember | null>(null);
  const [query, setQuery] = useState(""), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false), [uncertain, setUncertain] = useState(false);
  const alive = useRef(true), memberRequest = useRef(0), candidateRequest = useRef(0), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; memberRequest.current++; candidateRequest.current++; }; }, []);
  const reloadMembers = useCallback(async () => {
    const request = ++memberRequest.current;
    setMembers(null); setMemberError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId, groupId: group.id } } }));
    if (!alive.current || request !== memberRequest.current) return;
    if (!result.ok || !validPeopleMembers(result.data)) { setMemberError(!result.ok ? result.error : "The membership response was not valid. Retry to reload it."); return; }
    setMembers(result.data);
  }, [orgId, group.id]);
  useEffect(() => { void reloadMembers(); }, [reloadMembers]);
  useEffect(() => {
    if (dialog !== "add" || !editable) return;
    let current = true; const request = ++candidateRequest.current;
    setCandidates(null); setCandidateError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } })).then((result) => {
      if (!current || !alive.current || request !== candidateRequest.current) return;
      if (!result.ok || !validPeopleCandidates(result.data)) { setCandidateError(!result.ok ? result.error : "Available people were not returned correctly. Retry before adding a member."); return; }
      setCandidates(result.data);
    });
    return () => { current = false; candidateRequest.current++; };
  }, [orgId, dialog, editable, candidateAttempt]);
  const memberIds = new Set((members ?? []).map((member) => member.user_id));
  const available = (candidates ?? []).filter((member) => !memberIds.has(member.user_id));
  const matched = (members ?? []).filter((member) => `${member.name} ${member.email}`.toLowerCase().includes(query.trim().toLowerCase()));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(matched.length / pageSize)));
  const visible = matched.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const mutationBlocked = busy || uncertain;
  function openDialog(next: PeopleGroupDialog) { if (!editable || mutationBlocked || locked.current) return; setError(""); setMemberId(""); setName(group.name); setDialog(next); }
  const closeDialog = () => { if (!busy) { setDialog(null); setRemoving(null); } };
  async function mutate() {
    if (!editable || mutationBlocked || locked.current || !alive.current || !dialog) return;
    if (dialog === "rename" && !name.trim()) return;
    if (dialog === "add" && (!members || memberError || !candidates || candidateError || !available.some((candidate) => candidate.user_id === memberId))) return;
    if (dialog === "remove" && (!members || memberError || !removing || !members.some((member) => member.user_id === removing.user_id))) return;
    locked.current = true; setBusy(true); setError("");
    const action = dialog;
    try {
      const result = action === "rename"
        ? await api.PATCH("/api/v1/organizations/{orgId}/groups/{groupId}", { params: { path: { orgId, groupId: group.id } }, body: { name: name.trim() } })
        : action === "add"
          ? await api.POST("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId, groupId: group.id } }, body: { user_id: memberId } })
          : action === "remove"
            ? await api.DELETE("/api/v1/organizations/{orgId}/groups/{groupId}/members/{userId}", { params: { path: { orgId, groupId: group.id, userId: removing!.user_id } } })
            : await api.DELETE("/api/v1/organizations/{orgId}/groups/{groupId}", { params: { path: { orgId, groupId: group.id } } });
      if (!alive.current) return;
      if (result.error) { setError(apiErrorMessage(result.error, `Could not ${action === "rename" ? "rename the group" : action === "archive" ? "archive the group" : action === "add" ? "add the member" : "remove the member"}.`)); return; }
      setDialog(null); setRemoving(null);
      onNotice(action === "rename" ? "Group renamed. Existing references follow its identity." : action === "archive" ? "Group archived. Its membership and scoped access references were removed." : action === "add" ? "Person added. This group’s network rules and granted AI models now include them." : "Person removed. Access granted only through this group no longer applies to them.");
      if (action === "archive") onBack();
      await onReload();
    } catch {
      if (!alive.current) return;
      setUncertain(true); setDialog(null); setError("The change was not confirmed. Refresh groups to review the current state before another action.");
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  return <>
    <nav aria-label="Group breadcrumb" className="users-groups-breadcrumb"><button disabled={busy} onClick={onBack}>Groups</button><span aria-hidden="true">/</span><span aria-current="page">{group.name}</span></nav>
    <div className="users-groups-heading"><div><h1>{group.name}</h1></div>{editable && <div className="users-groups-actions"><Button disabled={mutationBlocked || !members || !!memberError} onClick={() => openDialog("add")}>Add member</Button><AppAccessRowMenu label={`Actions for ${group.name}`} actions={[{ key: "rename", label: "Rename", disabledReason: mutationBlocked ? "Refresh or wait for the current action." : undefined, onSelect: () => openDialog("rename") }, { key: "archive", label: "Archive", danger: true, disabledReason: mutationBlocked ? "Refresh or wait for the current action." : undefined, onSelect: () => openDialog("archive") }]} /></div>}</div>
    <ResourceSummary title="Group settings" className="group-saved-summary" footer={<Button variant="ghost" disabled={busy} onClick={onBack}>Back to groups</Button>}><div className="group-detail-content"><dl className="tnx-resource-facts tnx-resource-facts-three"><div><dt>Source</dt><dd>{directory ? "Directory sync" : "Manual"}</dd></div><div><dt>Reported membership</dt><dd>{memberLabel(group.member_count)} reported</dd></div><div><dt>Group identity</dt><dd>{group.id}</dd></div></dl>
    {directory && <p className="users-groups-copy">{DIRECTORY_MANAGED_NOTE}</p>}{!canWrite && <p className="users-groups-copy">Verify your email to manage groups.</p>}
    {!dialog && <ErrorText>{error}</ErrorText>}
    {memberError ? <LoadRetry error={memberError} onRetry={() => void reloadMembers()} /> : !members ? <Loading label="Loading members…" /> : <>
      <div className="users-groups-toolbar"><Input aria-label="Search group members" value={query} placeholder="Search name or email" onChange={(event) => { setPage(1); setQuery(event.target.value); }} /><Link className="users-groups-link" to="/audit">View audit context</Link></div>
      <div className={`users-groups-members${editable ? "" : " users-groups-readonly"}`}><DataTable variant="flat" caption="Group members" rows={visible} rowKey={(member) => member.user_id} rowLabel={(member) => member.name || member.email} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={query ? "No matching members" : "No members."} description={query ? "Try another name or email." : directory ? "Membership is managed in the directory." : editable ? "Add organization members to this group." : "An administrator can add organization members to this group."} action={query ? <Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button> : undefined} />} columns={[
        { key: "person", header: "Person", cell: (member) => <div className="users-groups-cell"><span>{member.name || member.email}</span>{member.name && member.name !== member.email && <small>{member.email}</small>}</div> },
        { key: "added", header: "Added", cell: (member) => <span title={member.added_at} className="users-groups-copy">{relativeAge(member.added_at)}</span> },
        ...(editable ? [{ key: "actions", header: "Actions", cell: (member: GroupMember) => <AppAccessRowMenu label={`Actions for ${member.name || member.email}`} actions={[{ key: "remove", label: "Remove member", danger: true, disabledReason: mutationBlocked ? "Refresh or wait for the current action." : undefined, onSelect: () => { if (!mutationBlocked && members.some((row) => row.user_id === member.user_id)) { setError(""); setRemoving(member); setDialog("remove"); } } }]} /> }] : []),
      ]} /></div>
      <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={visible.length} hasNext={currentPage * pageSize < matched.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPage(1); setPageSize(size); }} />
    </>}
    <details className="users-groups-help"><summary>Group access</summary><p>Network rules, application and server grants, and AI model grants can use this group as a subject. Membership changes affect the access granted through this group. Other group memberships and direct grants remain separate.</p></details></div></ResourceSummary>
    {(dialog === "rename" || dialog === "add") && editable && <Modal title={dialog === "rename" ? "Rename group" : "Add person member"} placement="right" size="enrollment" showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button disabled={mutationBlocked || (dialog === "rename" ? !name.trim() : !memberId || !members || !!memberError || !candidates || !!candidateError)} onClick={() => void mutate()}>{busy ? "Saving…" : dialog === "rename" ? "Save name" : "Add member"}</Button></>}><div className="users-groups-editor"><ErrorText>{error}</ErrorText>{dialog === "rename" ? <><Field label="Name"><Input autoFocus disabled={busy} value={name} onChange={(event) => setName(event.target.value)} /></Field><p>Existing rules and assignments keep the group identity.</p></> : <>
      {candidateError ? <LoadRetry error={candidateError} onRetry={() => setCandidateAttempt((attempt) => attempt + 1)} /> : !candidates ? <Loading label="Loading available people…" /> : available.length === 0 ? <p>No available people. Every organization member is already in this group.</p> : available.length > 10 ? <fieldset><legend>Person</legend><NetworkDetailList label="Available people" items={available} searchText={(member) => `${member.name} ${member.email}`} renderItem={(member) => <li key={member.user_id}><label className="users-groups-candidate"><input type="radio" name="group-person" aria-label={`Select ${member.name || member.email}`} checked={memberId === member.user_id} disabled={busy} onChange={() => setMemberId(member.user_id)} /><span>{member.name || member.email}<small>{member.email}</small></span></label></li>} /></fieldset> : <Field label="Person"><Select value={memberId} disabled={busy} onChange={(event) => setMemberId(event.target.value)}><option value="">Select person</option>{available.map((member) => <option key={member.user_id} value={member.user_id}>{member.name ? `${member.name} · ${member.email}` : member.email}</option>)}</Select></Field>}
      {memberId && <p>Selected: {available.find((member) => member.user_id === memberId)?.name || available.find((member) => member.user_id === memberId)?.email}</p>}<p>Adding a person expands access granted through this group.</p>
    </>}</div></Modal>}
    {(dialog === "remove" || dialog === "archive") && editable && <Modal title={dialog === "remove" ? "Remove member?" : "Archive group"} danger showClose onDismiss={closeDialog} actions={<><Button variant="ghost" disabled={busy} onClick={closeDialog}>Cancel</Button><Button variant="danger" disabled={mutationBlocked} onClick={() => void mutate()}>{busy ? "Applying…" : dialog === "remove" ? "Remove member" : "Archive group"}</Button></>}><div className="users-groups-confirm"><ErrorText>{error}</ErrorText>{dialog === "remove" ? <p>Remove {removing?.name || removing?.email} from {group.name}? Access and agent-management authority granted only through this group will be withdrawn. Other memberships and direct grants remain. Recovery requires explicitly adding the person back.</p> : <><p>Archiving deletes {group.name}, its membership, and scoped network rules. Group-based access grants are withdrawn, and agent-management assignments can be cleared. The server refuses protected active references.</p>{Number.isInteger(group.managed_agent_count) && (group.managed_agent_count ?? -1) >= 0 && <p>{group.managed_agent_count} managed agent profile assignment{group.managed_agent_count === 1 ? "" : "s"} will be cleared.</p>}<p>Recovery requires a new group and explicitly restoring its membership, grants, and assignments.</p></>}</div></Modal>}
  </>;
}
