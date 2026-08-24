import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AccessTabRail } from "../components/AccessTabRail";
import { Badge, Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import { api, apiErrorMessage, listItems, loadOne, type AgentGroup, type AgentGroupMember, type GroupMember, type Member, type UserGroup } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { isDirectoryManaged } from "../lib/idpsyncview";

type Kind = "people" | "agents" | "directory";

function hasExactMemberCount(group: UserGroup | AgentGroup): boolean {
  return Number.isInteger(group.member_count) && group.member_count >= 0;
}

function memberLabel(count: number): string {
  return count === 1 ? "1 member" : `${count} members`;
}

export default function AccessGroups() {
  return <AccessGroupsLoader />;
}


function AccessGroupsLoader() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [authorized, setAuthorized] = useState<boolean | null>(null);
  const [people, setPeople] = useState<UserGroup[] | null>(null);
  const [agentGroups, setAgentGroups] = useState<AgentGroup[] | null>(null);
  const [members, setMembers] = useState<Member[] | null>(null);
  const [error, setError] = useState("");
  const reload = useCallback(async () => {
    if (!org || authorized !== true) return;
    const [peopleResult, agentResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId: org.id } } })),
    ]);
    if (!peopleResult.ok || !agentResult.ok) { setError("Could not load the group inventory. Refresh to retry."); return; }
    setPeople(peopleResult.data);
    setAgentGroups(agentResult.data);
  }, [authorized, org?.id]);
  useEffect(() => {
    let cancelled = false;
    if (!org || state.status !== "authed") { setAuthorized(false); return; }
    setAuthorized(null);
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); setAuthorized(false); return; }
      setMembers(result.data);
      const mine = result.data.find((member) => member.user_id === state.user.id);
      setAuthorized(mine?.role === "owner" || mine?.role === "admin");
    });
    return () => { cancelled = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : ""]);
  useEffect(() => { void reload(); }, [reload]);
  const header = <><PageHeader title="Groups" subtitle="People, managed-agent, and directory-synced groups in one operational inventory." /><AccessTabRail /></>;
  if (!org || authorized === null) return <div className="space-y-5">{header}<Card><Loading label="Checking group permissions…" /></Card></div>;
  if (!authorized) return <div className="space-y-5">{header}<Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage groups.</p><ErrorText>{error}</ErrorText></Card></div>;
  if (!people || !agentGroups || !members) return <div className="space-y-5">{header}<Card><Loading label="Loading groups…" /><ErrorText>{error}</ErrorText></Card></div>;
  return <CanonicalGroupsWorkspace orgId={org.id} people={people} agentGroups={agentGroups} peopleOptions={members} onReload={reload} />;
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
  peopleOptions,
  onReload,
}: {
  orgId: string;
  people: UserGroup[];
  agentGroups: AgentGroup[];
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
  const type = (search.get("type") as "all" | Kind | null) ?? "all";
  const selectedId = search.get("group") ?? "";
  const query = search.get("q") ?? "";
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
  const visibleIds = visible.map((row) => row.id).join(",");
  const typeCounts = {
    all: rows.length,
    people: rows.filter((row) => row.kind === "people").length,
    agents: rows.filter((row) => row.kind === "agents").length,
    directory: rows.filter((row) => row.kind === "directory").length,
  };
  const createLabel = type === "agents" ? "Create agent group" : type === "people" ? "Create people group" : "Create group";
  const canCreate = type !== "directory";
  useEffect(() => {
    const firstVisibleId = visibleIds.split(",")[0];
    if (firstVisibleId && visibleIds.split(",").includes(selectedId)) return;
    const next = new URLSearchParams(search);
    if (firstVisibleId) next.set("group", firstVisibleId);
    else next.delete("group");
    setSearch(next, { replace: true });
  }, [selectedId, setSearch, visibleIds]);
  const loadSelected = useCallback(async () => {
    if (!selected) { setSelectedMembers(null); return; }
    setSelectedMembers(null);
    const groupId = selected.raw.id;
    const result = selected.kind === "agents"
      ? await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", { params: { path: { orgId, groupId } } }))
      : await loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId, groupId } } }));
    if (!result.ok) { setError(result.error); return; }
    setSelectedMembers(result.data);
  }, [orgId, selectedId]);
  useEffect(() => { void loadSelected(); }, [loadSelected]);
  useEffect(() => {
    if (selected?.kind !== "agents") return;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents", { params: { path: { orgId } } })).then((result) => {
      if (result.ok) setAgentOptions(listItems(result.data).map((agent) => ({ device_id: agent.device_id, name: agent.name })));
    });
  }, [orgId, selected?.kind]);
  async function action(call: () => Promise<{ error?: unknown }>, fallback: string, success: string) {
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await call();
      if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; }
      setNotice(success);
      return true;
    } catch { setError("Could not reach the API."); return false; }
    finally { setBusy(false); }
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
    if (!selected || selected.kind === "directory" || !memberId) return;
    const groupId = selected.raw.id;
    const ok = await action(() => selected.kind === "agents"
      ? api.POST("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", { params: { path: { orgId, groupId } }, body: { device_id: memberId } })
      : api.POST("/api/v1/organizations/{orgId}/groups/{groupId}/members", { params: { path: { orgId, groupId } }, body: { user_id: memberId } }), "Could not add the member.", selected.kind === "agents" ? "Agent added. Desired inherited configuration was queued, not confirmed applied." : "Person added. Rules scoped to this group now include them.");
    if (ok) { setDialog(null); setMemberId(""); await Promise.all([loadSelected(), onReload()]); }
  }
  async function removeMember() {
    if (!selected || selected.kind === "directory" || !removing) return;
    const groupId = selected.raw.id;
    const memberKey = selected.kind === "agents" ? (removing as AgentGroupMember).device_id : (removing as GroupMember).user_id;
    const ok = await action(() => selected.kind === "agents"
      ? api.DELETE("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members/{deviceId}", { params: { path: { orgId, groupId, deviceId: memberKey } } })
      : api.DELETE("/api/v1/organizations/{orgId}/groups/{groupId}/members/{userId}", { params: { path: { orgId, groupId, userId: memberKey } } }), "Could not remove the member.", selected.kind === "agents" ? "Agent removed. Its group-derived desired configuration was withdrawn; other members are unchanged." : "Person removed. Rules scoped only to this group no longer apply to them.");
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
  const memberIds = new Set((selectedMembers ?? []).map((member) => selected?.kind === "agents" ? (member as AgentGroupMember).device_id : (member as GroupMember).user_id));
  if (!countsValid) return <div className="space-y-5">
    <PageHeader title="Groups" subtitle="People, managed-agent, and directory-synced groups in one operational inventory." actions={canCreate ? <Button onClick={() => { setCreateKind(type === "agents" ? "agents" : "people"); setName(""); setDialog("create"); }}>{createLabel}</Button> : undefined} />
    <AccessTabRail />
    <Card><p role="alert" className="text-cell text-ink-tertiary">Member counts require the matching control-plane API version.</p><p className="mt-2 text-cell text-ink-tertiary">The inventory is withheld until the server returns a non-negative member count for every group.</p></Card>
  </div>;
  return <div className="space-y-5">
    <PageHeader title="Groups" subtitle={`${rows.length} groups across people, agents, and directory sources.`} actions={canCreate ? <Button onClick={() => { setCreateKind(type === "agents" ? "agents" : "people"); setName(""); setDialog("create"); }}>{createLabel}</Button> : undefined} />
    <AccessTabRail />
    <div className="flex flex-wrap items-center gap-2"><Input aria-label="Search groups" className="min-w-[14rem] flex-1 sm:max-w-sm" value={query} placeholder="Search groups" onChange={(event) => update({ q: event.target.value || null })} />{(["all", "people", "agents", "directory"] as const).map((value) => <Button key={value} size="sm" variant={type === value ? "primary" : "ghost"} onClick={() => update({ type: value === "all" ? null : value, group: null })}>{value === "all" ? "All" : value[0].toUpperCase() + value.slice(1)} <span className="ml-1 text-ink-tertiary">{typeCounts[value]}</span></Button>)}</div>
    <ErrorText>{error}</ErrorText>{notice && <p role="status" className="text-sm text-ok">{notice}</p>}
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,.75fr)]"><Card><DataTable caption="Groups inventory" rows={visible} rowKey={(row) => row.id} failed={false} filterable={false} pageSize={0} empty={<EmptyState>No groups match this view. Groups keep people and managed agents scoped to the policy and configuration that applies to them.</EmptyState>} columns={[{ key: "name", header: "Group name", cell: (row) => <button type="button" className="font-medium text-ink-heading hover:underline" onClick={() => update({ group: row.id })}>{row.name}</button> }, { key: "type", header: "Type", cell: (row) => <Badge tone="neutral">{row.kind === "agents" ? "Agent" : row.kind === "directory" ? "Directory" : "People"}</Badge> }, { key: "members", header: "Members", cell: (row) => memberLabel(row.memberCount) }, { key: "source", header: "Source", cell: (row) => row.source }, { key: "status", header: "Status", cell: (row) => <Badge tone={row.kind === "directory" ? "neutral" : "ok"}>{row.status}</Badge> }]} /></Card>
      <Card>{!selected ? <EmptyState>Select a group to inspect membership, policy context, and safe management actions.</EmptyState> : <div className="space-y-4"><div><h2 className="text-base font-semibold text-ink-heading">{selected.name}</h2><p className="mt-1 text-cell text-ink-tertiary">{memberLabel(selected.memberCount)} · {selected.kind === "agents" ? "Managed-agent membership changes inherited MCP and template context." : selected.kind === "directory" ? "Directory-synced membership is managed in the connected directory." : "People membership controls policy subjects."}</p><dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-cell text-ink-tertiary"><div><dt>Type</dt><dd className="text-ink-heading">{selected.kind === "agents" ? "Agent" : selected.kind === "directory" ? "Directory" : "People"}</dd></div><div><dt>Source</dt><dd className="text-ink-heading">{selected.source}</dd></div><div><dt>Status</dt><dd className="text-ink-heading">{selected.status}</dd></div></dl></div>{selected.kind !== "directory" && <div className="flex flex-wrap gap-2"><Button size="sm" variant="ghost" onClick={() => { setName(selected.name); setDialog("rename"); }}>Rename</Button><Button size="sm" onClick={() => setDialog("add")}>Add member</Button><Button size="sm" variant="danger" onClick={() => setDialog("archive")}>Archive</Button></div>}<section className="border-t border-white/10 pt-3"><h3 className="text-sm font-medium text-ink-heading">Members</h3>{selectedMembers === null ? <Loading label="Loading members…" /> : selectedMembers.length === 0 ? <p className="mt-2 text-cell text-ink-tertiary">No members are currently returned. Add one to make this group’s scope meaningful.</p> : <div className="mt-2 divide-y divide-white/10">{selectedMembers.map((member) => { const id = selected.kind === "agents" ? (member as AgentGroupMember).device_id : (member as GroupMember).user_id; const label = selected.kind === "agents" ? (member as AgentGroupMember).name : (member as GroupMember).name || (member as GroupMember).email; return <div key={id} className="flex items-center justify-between gap-3 py-2 text-cell"><span>{label}</span>{selected.kind !== "directory" && <Button size="sm" variant="danger" disabled={busy} onClick={() => { setRemoving(member); setDialog("remove"); }}>Remove</Button>}</div>; })}</div>}</section><section className="border-t border-white/10 pt-3 text-cell text-ink-tertiary"><p>Policy usage: Not available from the current API.</p>{selected.kind === "agents" && <p className="mt-1">MCP profile/effective configuration: Not available until the assignment inventory API is live.</p>}<Link className="mt-2 inline-block text-accent-400 hover:underline" to="/audit">View audit context</Link></section></div>}</Card></div>
    {dialog === "create" && <Modal title="Create group" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void create()}>Create group</Button></>}><p className="mb-3 text-cell text-ink-tertiary">Choose the member model. Directory groups are externally synchronized and cannot be manually created.</p><Field label="Group type"><Select value={createKind} onChange={(event) => setCreateKind(event.target.value as "people" | "agents")}><option value="people">People — policy subjects made of users</option><option value="agents">Agents — managed devices with inherited configuration</option></Select></Field><p className="mt-2 text-xs text-ink-tertiary">{createKind === "agents" ? "Agent groups control shared template and MCP inheritance; they cannot contain people." : "People groups control policy subjects; they cannot contain managed agents."}</p><div className="mt-3"><Field label="Name"><Input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field></div></Modal>}
    {dialog === "rename" && <Modal title="Rename group" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void rename()}>Save name</Button></>}><Field label="Name"><Input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field><p className="mt-2 text-xs text-ink-tertiary">Rules and assignments follow the group identity, so renaming does not rebuild their scope.</p></Modal>}
    {dialog === "add" && <Modal title={`Add ${selected?.kind === "agents" ? "agent" : "person"} member`} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !memberId} onClick={() => void addMember()}>Add member</Button></>}><p className="mb-3 text-cell text-ink-tertiary">{selected?.kind === "agents" ? "Adding an agent can give it this group’s desired inherited configuration. Queued does not mean applied." : "Adding a person expands rules that use this group as a subject."}</p><Field label={selected?.kind === "agents" ? "Agent" : "Person"}><Select value={memberId} onChange={(event) => setMemberId(event.target.value)}><option value="">Select {selected?.kind === "agents" ? "agent" : "person"}</option>{candidates.filter((candidate) => !memberIds.has(selected?.kind === "agents" ? (candidate as { device_id: string }).device_id : (candidate as Member).user_id)).map((candidate) => { const id = selected?.kind === "agents" ? (candidate as { device_id: string }).device_id : (candidate as Member).user_id; const label = selected?.kind === "agents" ? (candidate as { name: string }).name : (candidate as Member).name || (candidate as Member).email; return <option key={id} value={id}>{label}</option>; })}</Select></Field></Modal>}
    {dialog === "remove" && <Modal title="Remove member?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void removeMember()}>Remove member</Button></>}><p className="text-cell text-ink-tertiary">{selected?.kind === "agents" ? "This removes the agent’s inherited group context. Desired configuration is withdrawn after server reconciliation; other members are unchanged." : "This removes the person from this policy subject group. Rules scoped only through this group no longer apply to them."} Recovery is to explicitly add the member back.</p></Modal>}
    {dialog === "archive" && <Modal title="Archive group" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void archive()}>Archive group</Button></>}><p className="text-cell text-ink-tertiary">The server refuses unsafe archive. Remove members and attached policy/template assignments first; nothing is silently cascaded. Recovery requires recreating the group and restoring membership and assignments explicitly.</p></Modal>}
  </div>;
}
