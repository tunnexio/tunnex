import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { AgentsTabRail } from "../components/AgentsTabRail";

type Profile = components["schemas"]["AgentMCPProfile"];
type Group = components["schemas"]["AgentGroup"];
type Member = components["schemas"]["AgentGroupMember"];
type Assignment = components["schemas"]["AgentMCPProfileAssignment"];
type Impact = components["schemas"]["AgentMCPProfileImpact"];
type ArchiveConflict = components["schemas"]["AgentMCPProfileArchiveConflict"];
type Load<T> = { kind: "loading" } | { kind: "ready"; data: T } | { kind: "error"; message: string; code?: string };
const loading = <T,>(): Load<T> => ({ kind: "loading" });

/** Keep the stable API error code at this boundary: a forbidden inventory is not a failed inventory. */
async function loadProfiles(orgId: string): Promise<Load<Profile[]>> {
  try {
    const result = await api.GET("/api/v1/organizations/{orgId}/agent-mcp-profiles", { params: { path: { orgId } } });
    if (result.error || !result.data) return { kind: "error", message: apiErrorMessage(result.error, "Could not load MCP profiles."), code: apiErrorCode(result.error) };
    return { kind: "ready", data: result.data };
  } catch {
    return { kind: "error", message: "Could not reach the API." };
  }
}

/** Profiles are Agents-owned; group membership has its only management home in Access. */
export default function AgentsMCP() {
  const { org } = useOrg();
  const [search, setSearch] = useSearchParams();
  const [profiles, setProfiles] = useState<Load<Profile[]>>(loading);
  const [groups, setGroups] = useState<Load<Group[]>>(loading);
  const [members, setMembers] = useState<Load<Member[]>>(loading);
  const [assignments, setAssignments] = useState<Load<Assignment[]>>(loading);
  const [profileName, setProfileName] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [impact, setImpact] = useState<Impact | null>(null);
  const [dialog, setDialog] = useState<"replace" | "unassign" | "archive" | null>(null);
  const groupId = search.get("group") ?? "";
  const profileId = search.get("profile") ?? "";
  const [managementEnabled, setManagementEnabled] = useState(Boolean(org?.agent_policy_templates_enabled));
  const enabled = managementEnabled;

  useEffect(() => setManagementEnabled(Boolean(org?.agent_policy_templates_enabled)), [org?.id, org?.agent_policy_templates_enabled]);
  const selectedGroup = useMemo(() => groups.kind === "ready" ? groups.data.find((group) => group.id === groupId) : undefined, [groups, groupId]);
  const selectedProfile = useMemo(() => profiles.kind === "ready" ? profiles.data.find((profile) => profile.id === profileId) : undefined, [profiles, profileId]);
  const activeAssignment = useMemo(() => assignments.kind === "ready" ? assignments.data.find((assignment) => assignment.group_id === groupId && assignment.state === "active") : undefined, [assignments, groupId]);
  function select(values: Record<string, string | null>) {
    const next = new URLSearchParams(search);
    for (const [key, value] of Object.entries(values)) value ? next.set(key, value) : next.delete(key);
    setSearch(next);
  }
  async function reload() {
    if (!org || !enabled) return;
    setProfiles(loading()); setGroups(loading()); setAssignments(loading()); setError("");
    const [profileResult, groupResult, assignmentResult] = await Promise.all([
      loadProfiles(org.id),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-mcp-assignments", { params: { path: { orgId: org.id } } })),
    ]);
    setProfiles(profileResult);
    setGroups(groupResult.ok ? { kind: "ready", data: groupResult.data } : { kind: "error", message: groupResult.error });
    setAssignments(assignmentResult.ok ? { kind: "ready", data: assignmentResult.data } : { kind: "error", message: assignmentResult.error });
  }
  useEffect(() => { void reload(); }, [org?.id, enabled]);
  useEffect(() => {
    if (profiles.kind !== "ready" || groups.kind !== "ready") return;
    const next = new URLSearchParams(search);
    let changed = false;
    if (!profileId && profiles.data[0]) { next.set("profile", profiles.data[0].id); changed = true; }
    if (!groupId && groups.data[0]) { next.set("group", groups.data[0].id); changed = true; }
    if (changed) setSearch(next);
  }, [groups, groupId, profileId, profiles, search, setSearch]);
  useEffect(() => {
    if (!org || !enabled || !groupId) { setMembers({ kind: "ready", data: [] }); return; }
    let cancelled = false;
    setMembers(loading());
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups/{groupId}/members", { params: { path: { orgId: org.id, groupId } } })).then((result) => {
      if (!cancelled) setMembers(result.ok ? { kind: "ready", data: result.data } : { kind: "error", message: result.error });
    });
    return () => { cancelled = true; };
  }, [org?.id, enabled, groupId]);
  async function enable() {
    if (!org) return;
    setBusy(true); setError("");
    const result = await api.PUT("/api/v1/organizations/{orgId}/agent-policy-template-settings", { params: { path: { orgId: org.id } }, body: { enabled: true } });
    setBusy(false);
    if (result.error) { setError(apiErrorMessage(result.error, "Could not enable MCP profile management.")); return; }
    setManagementEnabled(true); setNotice("MCP profile management is enabled for this organization.");
  }
  async function createProfile() {
    if (!org || !profileName.trim() || !endpoint.trim()) return false;
    setBusy(true); setError(""); setNotice("");
    const result = await api.POST("/api/v1/organizations/{orgId}/agent-mcp-profiles", { params: { path: { orgId: org.id } }, body: { name: profileName.trim(), endpoint: endpoint.trim() } });
    setBusy(false);
    if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not create the MCP profile.")); return false; }
    setProfileName(""); setEndpoint("");
    setNotice("Profile created. Select an Agent Group to understand shared assignment context.");
    select({ profile: result.data.id }); await reload(); return true;
  }
  async function preview(group: Group, profile: Profile | null, nextDialog: "replace" | "unassign") {
    if (!org) return;
    setBusy(true); setError(""); setNotice("");
    const result = await api.POST("/api/v1/organizations/{orgId}/agent-groups/{groupId}/mcp-profile-impact", {
      params: { path: { orgId: org.id, groupId: group.id } },
      body: profile ? { profile_id: profile.id, unassign: false } : { unassign: true },
    });
    setBusy(false);
    if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not calculate shared profile impact.")); return; }
    setImpact(result.data); setDialog(nextDialog);
  }
  async function replace() {
    if (!org || !selectedGroup || !selectedProfile || !impact) return;
    setBusy(true); setError("");
    const result = await api.PUT("/api/v1/organizations/{orgId}/agent-groups/{groupId}/mcp-profile", { params: { path: { orgId: org.id, groupId: selectedGroup.id } }, body: { profile_id: selectedProfile.id } });
    setBusy(false);
    if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not set the group profile.")); return; }
    setDialog(null); setImpact(null);
    setNotice(`Profile assignment saved. Desired runtime updates were ${result.data.desired_runtime_updates_queued ? "queued" : "not needed"}; runtime application remains separately observed.`);
    await reload();
  }
  async function unassign() {
    if (!org || !selectedGroup || !impact) return;
    setBusy(true); setError("");
    const result = await api.DELETE("/api/v1/organizations/{orgId}/agent-groups/{groupId}/mcp-profile", { params: { path: { orgId: org.id, groupId: selectedGroup.id } } });
    setBusy(false);
    if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not unassign the group profile.")); return; }
    setDialog(null); setImpact(null);
    setNotice("Profile unassigned. The prior assignment remains in history; assign another profile to restore inherited configuration.");
    await reload();
  }
  async function archive() {
    if (!org || !selectedProfile) return;
    setBusy(true); setError("");
    const result = await api.POST("/api/v1/organizations/{orgId}/agent-mcp-profiles/{profileId}/archive", { params: { path: { orgId: org.id, profileId: selectedProfile.id } } });
    setBusy(false);
    if (result.error || !result.data) {
      const conflict = ((result.error as { error?: Partial<ArchiveConflict> } | undefined)?.error ?? result.error) as Partial<ArchiveConflict> | undefined;
      if (conflict?.code === "mcp_profile_in_use" && Number.isInteger(conflict.active_group_count) && Number.isInteger(conflict.affected_agent_count)) {
        setError(`Archive is blocked by ${conflict.active_group_count} active group${conflict.active_group_count === 1 ? "" : "s"} affecting ${conflict.affected_agent_count} distinct agent${conflict.affected_agent_count === 1 ? "" : "s"}. Unassign the profile from those groups, then retry.`);
      } else {
        setError(apiErrorMessage(result.error, "Could not archive the profile. Unassign it from every active group first."));
      }
      return;
    }
    setDialog(null); select({ profile: null });
    setNotice("Profile archived. Historical assignments remain available for audit; create a new profile to restore future use.");
    await reload();
  }
  if (!org) return <Loading label="Loading organization…" />;
  const groupLink = <Link className="inline-flex min-h-10 items-center text-sm font-medium text-accent-400 hover:underline" to="/access/groups?type=agents">Manage agent groups</Link>;
  const createButton = <Button onClick={() => setCreateOpen(true)}>Create profile</Button>;
  const denied = (profiles.kind === "error" && (profiles.code === "permission_denied" || profiles.code === "forbidden")) || (groups.kind === "error" && /permission|forbidden/i.test(groups.message));
  const transportError = profiles.kind === "error" ? profiles.message : groups.kind === "error" ? groups.message : "";
  const selectedProfileAlreadyActive = activeAssignment?.profile_id === selectedProfile?.id;

  return <div className="space-y-5">
    <PageHeader title="MCP profiles" subtitle="Create reusable MCP upstreams. Agents inherit a profile through their Agent Group." actions={enabled && profiles.kind === "ready" && profiles.data.length > 0 ? createButton : undefined} />
    <AgentsTabRail />
    {!enabled && <Card className="max-w-2xl"><h2 className="text-sm font-semibold text-ink-heading">MCP management is turned off</h2><p className="mt-2 text-cell text-ink-tertiary">Enable the organization opt-in to create reusable profiles. Profile assignment remains group-owned, never direct to an agent.</p><div className="mt-4"><Button disabled={busy} onClick={() => void enable()}>{busy ? "Enabling…" : "Enable MCP management"}</Button></div><ErrorText>{error}</ErrorText></Card>}
    {enabled && profiles.kind === "loading" && <Card><Loading label="Loading MCP profiles…" /></Card>}
    {enabled && denied && <Card className="max-w-2xl"><h2 className="text-sm font-semibold text-ink-heading">You do not have permission to view MCP profiles</h2><p className="mt-2 text-cell text-ink-tertiary">No profile, group, assignment, or plan information is shown without the required permission.</p></Card>}
    {enabled && transportError && !denied && <Card className="max-w-2xl"><h2 className="text-sm font-semibold text-ink-heading">MCP profiles could not be loaded</h2><p className="mt-2 text-cell text-ink-tertiary">No empty inventory is shown because the current API response failed. Refresh to retry.</p><ErrorText>{transportError}</ErrorText></Card>}
    {enabled && profiles.kind === "ready" && groups.kind === "ready" && profiles.data.length === 0 && <Card className="max-w-2xl"><EmptyState action={createButton}><strong className="block text-sm text-ink-heading">Create a reusable MCP profile</strong><span className="mt-1 block">Create a credential-free upstream, assign it to an Agent Group, then agents inherit it through group membership.</span><span className="mt-3 block">{groupLink}</span></EmptyState></Card>}
    {enabled && profiles.kind === "ready" && groups.kind === "ready" && assignments.kind === "ready" && profiles.data.length > 0 && <>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(22rem,.8fr)]">
        <Card><DataTable caption="MCP profile inventory" rows={profiles.data} rowKey={(profile) => profile.id} failed={false} filterable={false} pageSize={0} empty={<>No MCP profiles.</>} columns={[
          { key: "name", header: "Profile", cell: (profile) => <button type="button" onClick={() => select({ profile: profile.id })} className="font-medium text-ink-heading hover:underline">{profile.name}</button> },
          { key: "endpoint", header: "Endpoint", cell: (profile) => <span className="break-all text-xs text-ink-tertiary">{profile.endpoint}</span> },
          { key: "status", header: "Lifecycle", cell: (profile) => profile.archived_at ? "Archived" : "Available" },
          { key: "assignments", header: "Group assignments", cell: (profile) => assignments.data.filter((assignment) => assignment.profile_id === profile.id && assignment.state === "active").length },
        ]} /></Card>
        <Card>{!selectedProfile ? <EmptyState>Select a profile to review its lifecycle and shared group assignment.</EmptyState> : <div className="space-y-4"><div className="flex flex-wrap items-start justify-between gap-2"><div><h2 className="text-sm font-semibold text-ink-heading">{selectedProfile.name}</h2><p className="mt-1 break-all text-xs text-ink-tertiary">{selectedProfile.endpoint}</p></div>{!selectedProfile.archived_at && <Button size="sm" variant="danger" onClick={() => setDialog("archive")}>Archive</Button>}</div><div className="border-t border-white/10 pt-3"><h3 className="text-sm font-medium text-ink-heading">Assign through an Agent Group</h3><p className="mt-1 text-cell text-ink-tertiary">Groups are selected here, but membership and lifecycle are managed only in Access.</p><div className="mt-2">{groupLink}</div>{groups.data.length === 0 ? <p className="mt-3 text-cell text-ink-tertiary">Create an Agent Group before assigning this profile.</p> : <Select aria-label="Assignment group context" className="mt-3" value={groupId} onChange={(event) => select({ group: event.target.value || null })}><option value="">Select group</option>{groups.data.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</Select>}</div><div className="border-t border-white/10 pt-3"><h3 className="text-sm font-medium text-ink-heading">Assignment history</h3>{assignments.data.filter((assignment) => assignment.profile_id === selectedProfile.id).length === 0 ? <p className="mt-2 text-cell text-ink-tertiary">No group assignment history yet.</p> : <ul className="mt-2 space-y-1 text-cell text-ink-tertiary">{assignments.data.filter((assignment) => assignment.profile_id === selectedProfile.id).map((assignment) => <li key={assignment.id}>{assignment.group_name} · {assignment.state}{assignment.quarantine_reason ? ` · ${assignment.quarantine_reason}` : ""}</li>)}</ul>}</div></div>}</Card>
      </div>
      {selectedGroup && selectedProfile && <Card><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-sm font-semibold text-ink-heading">Shared assignment impact</h2><p className="mt-1 text-cell text-ink-tertiary">{selectedProfileAlreadyActive ? <><strong>{selectedProfile.name}</strong> is already active for <strong>{selectedGroup.name}</strong>.</> : activeAssignment ? <><strong>{selectedProfile.name}</strong> can replace <strong>{activeAssignment.profile_name}</strong> for <strong>{selectedGroup.name}</strong>. Preview the exact shared impact before changing the active profile.</> : <><strong>{selectedProfile.name}</strong> can be assigned to <strong>{selectedGroup.name}</strong>. Preview the exact shared impact before the first assignment.</>}</p></div><div className="flex flex-wrap gap-2">{selectedProfileAlreadyActive ? <span className="text-cell text-ink-tertiary">This profile is already active for the group.</span> : <Button size="sm" disabled={busy || Boolean(selectedProfile.archived_at)} onClick={() => void preview(selectedGroup, selectedProfile, "replace")}>{activeAssignment ? "Preview replacement" : "Preview assignment"}</Button>}{activeAssignment && <Button size="sm" variant="danger" disabled={busy} onClick={() => void preview(selectedGroup, null, "unassign")}>Preview unassign</Button>}</div></div>{members.kind === "loading" ? <Loading label="Loading group membership…" /> : members.kind === "error" ? <ErrorText>{members.message}</ErrorText> : members.data.length === 0 ? <p className="mt-3 text-cell text-ink-tertiary">No agents are currently affected by this group.</p> : <p className="mt-3 text-cell"><strong>{members.data.length}</strong> agents currently inherit through this group. Runtime application is separately observed.</p>}{activeAssignment && <p className="mt-2 text-xs text-ink-tertiary">Current active profile: {activeAssignment.profile_name}.{selectedProfileAlreadyActive ? " This selection matches the active assignment." : " Replacing preserves the prior assignment as history."}</p>}</Card>}
      {!selectedGroup || !selectedProfile ? <p className="text-cell text-ink-tertiary">Select both a profile and an Agent Group to preview the exact shared impact.</p> : null}
    </>}
    {notice && <p role="status" className="text-sm text-ok">{notice}</p>}<ErrorText>{error}</ErrorText>
    {createOpen && <Modal title="Create reusable MCP profile" onDismiss={() => setCreateOpen(false)} actions={<><Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button><Button disabled={busy || !profileName.trim() || !endpoint.trim()} onClick={() => void createProfile().then((created) => { if (created) setCreateOpen(false); })}>Create profile</Button></>}><p className="mb-3 text-cell text-ink-tertiary">Creation is non-disruptive. Use a credential-free absolute endpoint. Next, select an Agent Group to understand the shared assignment context.</p><div className="space-y-3"><Field label="Profile name"><Input autoFocus value={profileName} onChange={(event) => setProfileName(event.target.value)} /></Field><Field label="MCP endpoint"><Input value={endpoint} placeholder="https://mcp.example" onChange={(event) => setEndpoint(event.target.value)} /></Field></div></Modal>}
    {dialog === "replace" && impact && selectedGroup && selectedProfile && <Modal title={activeAssignment ? "Replace group MCP profile" : "Assign group MCP profile"} onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !impact.mutation_allowed} onClick={() => void replace()}>{activeAssignment ? "Replace profile" : "Assign profile"}</Button></>}><p className="text-cell text-ink-tertiary">{impact.affected_agent_count} agents will {impact.effective_upstream_changes ? "receive a changed desired MCP upstream" : "keep the same desired MCP upstream"}. {impact.desired_runtime_updates_queued ? "Desired runtime updates will be queued after the transaction commits." : "No runtime update is currently required."}</p>{impact.conflict && <ErrorText>{impact.conflict}</ErrorText>}<p className="mt-3 text-cell text-ink-tertiary">Recovery: select another profile and replace it, or unassign this group. Runtime application remains separately observed.</p></Modal>}
    {dialog === "unassign" && impact && selectedGroup && <Modal title="Unassign group MCP profile" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy || !impact.mutation_allowed} onClick={() => void unassign()}>Unassign profile</Button></>}><p className="text-cell text-ink-tertiary">{impact.affected_agent_count} agents will lose this inherited desired upstream. Assignment history is retained. Recovery: assign a replacement profile to {selectedGroup.name}.</p>{impact.conflict && <ErrorText>{impact.conflict}</ErrorText>}</Modal>}
    {dialog === "archive" && selectedProfile && <Modal title="Archive MCP profile" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void archive()}>Archive profile</Button></>}><p className="text-cell text-ink-tertiary">Archiving preserves historical assignment evidence but refuses while an active group still references this profile. Recovery: unassign it from every active group, then archive.</p></Modal>}
  </div>;
}
