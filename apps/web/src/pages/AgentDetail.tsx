import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { Badge, Button, Card, EmptyState, ErrorText, Field, Loading, Modal, PageHeader, Select, SettingGroup, SettingRow } from "../components/ui";
import { AgentProfileEditor, type AgentProfileEditorValue, type AgentProfileStatus } from "../components/AgentProfileEditor";
import { api, loadOne, type Member, type UserGroup } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import { AgentMCPOAuthPanel, AgentMCPToolApprovalPanel, AgentMCPToolPolicyPanel } from "../components/AgentMCPControls";
import { AgentWorkflowProvenancePanel } from "../components/AgentWorkflowProvenance";

type AgentProfile = components["schemas"]["AgentProfile"];
type Runtime = components["schemas"]["AgentRuntimeStatus"];
type MCPInventory = components["schemas"]["AgentMCPInventory"];
type EffectiveMCP = components["schemas"]["AgentEffectiveMCPProfile"];
type Provenance = components["schemas"]["AgentWorkflowProvenanceRecord"];
type LicenceStatus = components["schemas"]["LicenseStatus"];
type CredentialRotation = components["schemas"]["AgentCredentialRotationStatus"];

const tabs = ["overview", "runtime", "mcp", "access", "activity"] as const;
type Tab = (typeof tabs)[number];
const tabLabel: Record<Tab, string> = {
  overview: "Overview", runtime: "Runtime", mcp: "MCP", access: "Access", activity: "Activity",
};

type State<T> = { kind: "loading" } | { kind: "ready"; data: T } | { kind: "error"; message: string };
const loading = <T,>(): State<T> => ({ kind: "loading" });

/** Development-gallery input only. The route continues to own live reads. */
export type AgentDetailFixture = {
  profile: AgentProfile;
  runtime: Runtime;
  inventory: MCPInventory;
  provenance: Provenance[];
  effectiveMCP: EffectiveMCP;
  licence: LicenceStatus;
};

function readError(result: { ok: boolean; error?: string }): string {
  return result.ok ? "" : (result.error ?? "Could not load this information.");
}

function age(at?: string | null) {
  if (!at) return "never";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(at).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <Card><h2 className="text-sm font-semibold text-ink-heading">{title}</h2><div className="mt-3">{children}</div></Card>;
}

function ReadState<T>({ state, children }: { state: State<T>; children: (data: T) => React.ReactNode }) {
  if (state.kind === "loading") return <Card><Loading label="Loading agent workspace…" /></Card>;
  if (state.kind === "error") return <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-danger/25 bg-danger/5 px-3 py-2.5"><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold text-ink-heading">Information unavailable</h2><p role="alert" className="mt-0.5 text-cell text-danger">{state.message}</p></div><Button size="sm" variant="ghost" onClick={() => window.location.reload()}>Retry</Button></div>;
  return <>{children(state.data)}</>;
}

function AgentAssignment({ profile, members, groups, busy, onSave }: { profile: AgentProfile; members: State<Member[]>; groups: State<UserGroup[]>; busy: boolean; onSave: (body: Record<string, unknown>) => void }) {
  const [ownerID, setOwnerID] = useState(profile.owner_id);
  const [groupID, setGroupID] = useState(profile.managing_group_id ?? "");
  if (members.kind === "loading" || groups.kind === "loading") return <Loading size="inline" label="Loading owners and groups…" />;
  if (members.kind === "error" || groups.kind === "error") return <p role="alert" className="text-cell text-danger">Ownership choices could not be loaded. No change can be submitted.</p>;
  const changed = ownerID !== profile.owner_id || (groupID || null) !== profile.managing_group_id;
  return <div className="space-y-3"><Field label="Accountable owner"><Select value={ownerID} disabled={busy} onChange={(event) => setOwnerID(event.target.value)}>{members.data.filter((member) => member.status === "active").map((member) => <option key={member.user_id} value={member.user_id}>{member.email}</option>)}</Select></Field><Field label="Managing group"><Select value={groupID} disabled={busy} onChange={(event) => setGroupID(event.target.value)}><option value="">No managing group</option>{groups.data.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</Select></Field><p className="text-xs text-ink-tertiary">Changing owner changes accountability only. A managing group may view and manage this agent, but does not gain access-grant or credential-rotation authority.</p><Button size="sm" disabled={busy || !ownerID || !changed} onClick={() => onSave({ ...(ownerID !== profile.owner_id ? { owner_id: ownerID } : {}), ...((groupID || null) !== profile.managing_group_id ? { managing_group_update: { group_id: groupID || null } } : {}) })}>Save ownership</Button></div>;
}

/** The key prevents a prior organization's agent state from rendering during an org switch. */
export default function AgentDetail(props: { fixture?: AgentDetailFixture; agentIdOverride?: string }) {
  const { org } = useOrg();
  return <AgentDetailWorkspace key={org?.id ?? "no-organization"} {...props} />;
}

/** Route workspace only. The index and router are intentionally owned by separate S18 workstreams. */
function AgentDetailWorkspace({ fixture, agentIdOverride }: { fixture?: AgentDetailFixture; agentIdOverride?: string }) {
  const { org } = useOrg();
  const { state: authState } = useAuth();
  const navigate = useNavigate();
  const { agentId: routeAgentId = "" } = useParams();
  const agentId = agentIdOverride ?? routeAgentId;
  const [search, setSearch] = useSearchParams();
  const rawTab = search.get("tab");
  const tab: Tab = tabs.includes(rawTab as Tab) ? rawTab as Tab : "overview";
  const [profile, setProfile] = useState<State<AgentProfile>>(loading);
  const [runtime, setRuntime] = useState<State<Runtime>>(loading);
  const [inventory, setInventory] = useState<State<MCPInventory>>(loading);
  const [provenance, setProvenance] = useState<State<Provenance[]>>(loading);
  const [effectiveMCP, setEffectiveMCP] = useState<State<EffectiveMCP>>(loading);
  const [licence, setLicence] = useState<State<LicenceStatus>>(loading);
  const [rotation, setRotation] = useState<State<CredentialRotation>>(loading);
  const [members, setMembers] = useState<State<Member[]>>(loading);
  const [groups, setGroups] = useState<State<UserGroup[]>>(loading);
  const [mutationError, setMutationError] = useState("");
  const [busy, setBusy] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [profileEditorOpen, setProfileEditorOpen] = useState(false);
  const [assignmentOpen, setAssignmentOpen] = useState(false);
  const myRole = members.kind === "ready" && authState.status === "authed"
    ? members.data.find((member) => member.user_id === authState.user.id)?.role
    : undefined;

  useEffect(() => {
    if (fixture) {
      setProfile({ kind: "ready", data: fixture.profile });
      setRuntime({ kind: "ready", data: fixture.runtime });
      setInventory({ kind: "ready", data: fixture.inventory });
      setProvenance({ kind: "ready", data: fixture.provenance });
      setEffectiveMCP({ kind: "ready", data: fixture.effectiveMCP });
      setLicence({ kind: "ready", data: fixture.licence });
      setRotation({ kind: "error", message: "Credential rotation is not supplied by this specimen." });
      setMembers({ kind: "ready", data: [] });
      setGroups({ kind: "ready", data: [] });
      return;
    }
    if (!org || !agentId) return;
    let cancelled = false;
    setProfile(loading()); setRuntime(loading()); setInventory(loading()); setProvenance(loading()); setEffectiveMCP(loading()); setLicence(loading()); setRotation(loading()); setMembers(loading()); setGroups(loading()); setMutationError("");
    const path = { orgId: org.id, deviceId: agentId };
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}", { params: { path } })).then((r) => {
      if (cancelled) return;
      setProfile(r.ok ? { kind: "ready", data: r.data as AgentProfile } : { kind: "error", message: readError(r) });
      // Only an actor who can read the agent may receive deployment entitlement
      // details. The JIT capability is an additive Access-tab concern; it does
      // not gate the base agent workspace.
      if (r.ok) {
        void loadOne(() => api.GET("/api/v1/license")).then((licenceResult) => !cancelled && setLicence(licenceResult.ok ? { kind: "ready", data: licenceResult.data as LicenceStatus } : { kind: "error", message: readError(licenceResult) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => !cancelled && setMembers(result.ok ? { kind: "ready", data: result.data as Member[] } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/groups", { params: { path: { orgId: org.id } } })).then((result) => !cancelled && setGroups(result.ok ? { kind: "ready", data: result.data as UserGroup[] } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status", { params: { path } })).then((result) => !cancelled && setRuntime(result.ok ? { kind: "ready", data: result.data as Runtime } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/mcp-inventory", { params: { path } })).then((result) => !cancelled && setInventory(result.ok ? { kind: "ready", data: result.data as MCPInventory } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/workflow-provenance", { params: { path } })).then((result) => !cancelled && setProvenance(result.ok ? { kind: "ready", data: result.data as Provenance[] } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/effective-mcp-profile", { params: { path } })).then((result) => !cancelled && setEffectiveMCP(result.ok ? { kind: "ready", data: result.data as EffectiveMCP } : { kind: "error", message: readError(result) }));
        void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", { params: { path } })).then((result) => !cancelled && setRotation(result.ok ? { kind: "ready", data: result.data as CredentialRotation } : { kind: "error", message: readError(result) }));
      }
    });
    return () => { cancelled = true; };
  }, [fixture, org, agentId]);

  const switchTab = (next: Tab) => { const nextSearch = new URLSearchParams(search); if (next === "overview") nextSearch.delete("tab"); else nextSearch.set("tab", next); setSearch(nextSearch); };

  async function updateProfile(body: Record<string, unknown>, failure: string) {
    if (!org || !agentId) return false;
    setBusy(true); setMutationError("");
    const result = await api.PATCH("/api/v1/organizations/{orgId}/agents/{deviceId}", { params: { path: { orgId: org.id, deviceId: agentId } }, body });
    setBusy(false);
    if (result.error || !result.data) { setMutationError(failure); return false; }
    setProfile({ kind: "ready", data: result.data as AgentProfile });
    return true;
  }
  async function rotateCredential() {
    if (!org || !agentId) return;
    setBusy(true); setMutationError("");
    const requested = await api.POST("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", { params: { path: { orgId: org.id, deviceId: agentId } } });
    if (requested.error) { setBusy(false); setMutationError("Could not request credential rotation."); return; }
    const refreshed = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation", { params: { path: { orgId: org.id, deviceId: agentId } } }));
    setBusy(false);
    if (!refreshed.ok) { setMutationError("Rotation was requested but its status could not be refreshed."); return; }
    setRotation({ kind: "ready", data: refreshed.data as CredentialRotation });
  }
  async function removeAgent() {
    if (!org || !agentId) return;
    setBusy(true); setMutationError("");
    const revoked = await api.POST("/api/v1/organizations/{orgId}/devices/{deviceId}/revoke", { params: { path: { orgId: org.id, deviceId: agentId } } });
    if (revoked.error) { setBusy(false); setMutationError("Could not revoke the agent."); return; }
    const removed = await api.DELETE("/api/v1/organizations/{orgId}/devices/{deviceId}", { params: { path: { orgId: org.id, deviceId: agentId } } });
    setBusy(false);
    if (removed.error) { setMutationError("The agent was revoked but could not be removed from the roster."); return; }
    setRemoveOpen(false);
    navigate("/agents");
  }

  if (!org) return <Loading label="Loading organization…" />;
  const detailSubtitle = profile.kind === "ready"
    ? [profile.data.environment, profile.data.runtime].filter(Boolean).join(" · ") || "Managed agent"
    : "Loading agent detail";
  return <div className="space-y-5">
    <div className="text-xs text-ink-tertiary"><Link to="/agents" className="hover:text-ink-heading">AI Agents</Link> <span aria-hidden="true">/</span> {profile.kind === "ready" ? profile.data.name : "Agent"}</div>
    <PageHeader title={profile.kind === "ready" ? profile.data.name : "Agent workspace"} subtitle={detailSubtitle} actions={profile.kind === "ready" ? <Badge tone="neutral">{profile.data.status}</Badge> : undefined} />
    <div role="tablist" aria-label="Agent workspace" className="flex gap-6 overflow-x-auto border-b border-white/[0.08]">
      {tabs.map((item) => <button key={item} type="button" role="tab" aria-selected={tab === item} className={`relative -mb-px whitespace-nowrap px-0.5 py-2.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/35 ${tab === item ? "text-white after:absolute after:inset-x-0 after:bottom-0 after:h-px after:bg-white" : "text-ink-tertiary hover:text-ink-heading"}`} onClick={() => switchTab(item)}>{tabLabel[item]}</button>)}
    </div>
    {tab === "overview" && <ReadState state={profile}>{(data) => <div className="space-y-4">
      <Card><dl className="grid gap-x-6 gap-y-3 text-cell sm:grid-cols-2 lg:grid-cols-4">
        {[['Lifecycle', data.status], ['Owner', data.owner_email || 'Unassigned'], ['Managing group', data.managing_group_name || 'None'], ['Last handshake', age(data.last_handshake_at)]].map(([label, value]) => <div key={label}><dt className="text-micro uppercase tracking-wide text-ink-faint">{label}</dt><dd className="mt-1 truncate text-ink-body" title={value}>{value}</dd></div>)}
      </dl><p className="sr-only">Lifecycle comes from the server-owned agent profile. Handshake freshness is reported separately.</p></Card>
      {(data.permissions.manage || data.permissions.assign || data.permissions.revoke) && <SettingGroup title="Agent settings">
        {data.permissions.manage && <SettingRow label="Profile and lifecycle" description={[data.environment, data.runtime].filter(Boolean).join(" · ") || "No environment or runtime metadata"}><Button size="sm" variant="ghost" onClick={() => setProfileEditorOpen(true)}>Edit profile</Button></SettingRow>}
        {data.permissions.assign && <SettingRow label="Ownership" description={`${data.owner_email || "Unassigned"}${data.managing_group_name ? ` · ${data.managing_group_name}` : ""}`}><Button size="sm" variant="ghost" onClick={() => setAssignmentOpen(true)}>Change</Button></SettingRow>}
        {data.permissions.revoke && <SettingRow label="Remove agent" description="Revoke its tunnel credential, then remove the roster record."><Button size="sm" variant="danger" disabled={busy} onClick={() => setRemoveOpen(true)}>Remove agent</Button></SettingRow>}
      </SettingGroup>}
    </div>}</ReadState>}
    {tab === "runtime" && <ReadState state={runtime}>{(data) => <div className="grid gap-4 lg:grid-cols-2"><Panel title="Managed runtime"><dl className="grid gap-3 text-cell sm:grid-cols-2"><div><dt className="text-ink-tertiary">Connectivity</dt><dd>{data.connectivity}</dd></div><div><dt className="text-ink-tertiary">Health</dt><dd>{data.health}</dd></div><div><dt className="text-ink-tertiary">Last report</dt><dd>{data.last_seen_at ? `${age(data.last_seen_at)}${data.stale ? " (stale)" : ""}` : "Never reported"}</dd></div><div><dt className="text-ink-tertiary">Revision</dt><dd>{data.applied_revision} applied / {data.desired_revision} desired</dd></div></dl><p className="mt-3 text-xs text-ink-tertiary">Source: agent runtime report. {data.stale ? "The server marks this report stale." : "The server considers this report fresh."}</p></Panel><ReadState state={rotation}>{(value) => <Panel title="Credential rotation"><p className="text-cell text-ink-secondary">Runtime credential revision {value.current_revision} · {value.state}. WireGuard key revision {value.wireguard_current_revision} · {value.wireguard_state}.</p>{value.deadline && <p className="mt-2 text-xs text-ink-tertiary">Deadline {value.deadline}</p>}{profile.kind === "ready" && profile.data.permissions.rotate_credentials && <Button className="mt-3" size="sm" disabled={busy || profile.data.status !== "active" || value.state !== "current" || value.wireguard_state !== "current"} onClick={() => void rotateCredential()}>Rotate credential</Button>}</Panel>}</ReadState></div>}</ReadState>}
    {tab === "mcp" && <div className="grid gap-4 lg:grid-cols-2"><ReadState state={effectiveMCP}>{(value) => <Panel title="Effective MCP profile"><p className="text-cell text-ink-secondary">{value.assigned ? <>{value.profile_name ?? "MCP profile"} is inherited from the managing group {value.group_name ?? "source group"}. Changing that shared group profile affects every member of the group.</> : "No MCP profile is inherited through this agent’s groups."}</p>{value.endpoint && <p className="mt-2 break-all text-xs text-ink-tertiary">{value.endpoint}</p>}<p className="mt-3 text-xs"><Link className="text-accent-400 hover:underline" to={`/agents/mcp${value.group_id ? `?group=${value.group_id}` : ""}`}>Manage MCP profiles</Link></p></Panel>}</ReadState><ReadState state={inventory}>{(data) => <><Panel title="Observed MCP inventory"><p className="text-cell text-ink-tertiary">Observed {age(data.observed_at)}. This is a secret-free shadow-mode inventory.</p><pre className="mt-3 max-h-64 overflow-auto rounded bg-ink-900 p-3 text-xs text-slate-300">{JSON.stringify(data.snapshot, null, 2)}</pre></Panel>{profile.kind === "ready" && <Panel title="MCP tool policy"><AgentMCPToolPolicyPanel orgId={org.id} deviceId={agentId} inventory={data} canManage={can(myRole, "agent:mcp_tool_policy:manage")} /></Panel>}{profile.kind === "ready" && <Panel title="MCP OAuth"><AgentMCPOAuthPanel orgId={org.id} deviceId={agentId} inventory={data} canManage={profile.data.permissions.manage} /></Panel>}{profile.kind === "ready" && <Panel title="Step-up approvals"><AgentMCPToolApprovalPanel orgId={org.id} deviceId={agentId} canApprove={can(myRole, "agent:mcp_tool_approval:approve")} /></Panel>}</>}</ReadState></div>}
    {tab === "access" && <ReadState state={profile}>{(data) => <div className="grid gap-4 lg:grid-cols-2"><Panel title="Access posture"><p className="text-cell text-ink-tertiary">Lifecycle: {data.status}. Access policy is evaluated outside this workspace; this tab does not duplicate the Access Policy editor.</p><p className="mt-3 text-xs"><Link className="text-accent-400 hover:underline" to="/access">Open Access Policies</Link></p></Panel><Panel title="Just-in-time access"><ReadState state={licence}>{(status) => status.features.includes("agent_jit_access") ? <>{org.agent_jit_access_enabled ? <p className="text-cell text-ink-secondary">This capability is available in your plan and enabled for this organization.</p> : <><p className="text-cell text-ink-secondary">This capability is included in your plan but is not enabled for this organization.</p><p className="mt-3 text-xs"><Link className="text-accent-400 hover:underline" to="/settings?section=access-security">Review organization settings</Link></p></>}</> : <><p className="text-cell text-ink-secondary">This capability is not included in your current plan.</p><p className="mt-3 text-xs"><Link className="text-accent-400 hover:underline" to="/settings?section=licence">Licence &amp; Plan</Link></p></>}</ReadState></Panel><Panel title="Authority"><dl className="grid grid-cols-2 gap-2 text-cell"><dt className="text-ink-tertiary">Manage</dt><dd>{data.permissions.manage ? "Allowed" : "Not allowed"}</dd><dt className="text-ink-tertiary">Grant access</dt><dd>{data.permissions.grant_access ? "Allowed" : "Not allowed"}</dd><dt className="text-ink-tertiary">Rotate credentials</dt><dd>{data.permissions.rotate_credentials ? "Allowed" : "Not allowed"}</dd></dl></Panel></div>}</ReadState>}
    {tab === "activity" && <ReadState state={provenance}>{(items) => <Panel title="Workflow activity"><p className="text-cell text-ink-tertiary">Source: signed workflow provenance received by the control plane.</p>{items.length === 0 ? <EmptyState>No workflow provenance has been recorded for this agent. Review Access Events or the Audit Log for related control-plane evidence.</EmptyState> : <AgentWorkflowProvenancePanel records={items} />}<p className="mt-3 text-xs"><Link className="text-accent-400 hover:underline" to="/access-events">Access Events</Link><span className="text-ink-tertiary"> / </span><Link className="text-accent-400 hover:underline" to="/audit">Audit Log</Link></p></Panel>}</ReadState>}
    <ErrorText>{mutationError}</ErrorText>
    {profileEditorOpen && profile.kind === "ready" && <Modal title="Edit agent profile" onDismiss={() => setProfileEditorOpen(false)} actions={<Button variant="ghost" onClick={() => setProfileEditorOpen(false)}>Close</Button>}><AgentProfileEditor key={`${profile.data.device_id}:${profile.data.status}:${profile.data.environment}:${profile.data.runtime}:${JSON.stringify(profile.data.labels)}`} value={{ environment: profile.data.environment, runtime: profile.data.runtime, labels: profile.data.labels, status: profile.data.status as AgentProfileStatus }} canManageLifecycle={profile.data.permissions.manage} disabled={busy} onSaveMetadata={(value: AgentProfileEditorValue) => void updateProfile(value, "Could not save agent metadata.").then((saved) => saved && setProfileEditorOpen(false))} onLifecycleChange={(status) => void updateProfile({ status }, "Could not change the agent lifecycle.").then((saved) => saved && setProfileEditorOpen(false))} /></Modal>}
    {assignmentOpen && profile.kind === "ready" && <Modal title="Change agent ownership" onDismiss={() => setAssignmentOpen(false)} actions={<Button variant="ghost" onClick={() => setAssignmentOpen(false)}>Close</Button>}><AgentAssignment key={`${profile.data.device_id}:${profile.data.owner_id}:${profile.data.managing_group_id ?? ""}`} profile={profile.data} members={members} groups={groups} busy={busy} onSave={(body) => void updateProfile(body, "Could not save the agent assignment.").then((saved) => saved && setAssignmentOpen(false))} /></Modal>}
    {removeOpen && profile.kind === "ready" && <Modal title={`Remove ${profile.data.name}?`} danger onDismiss={() => setRemoveOpen(false)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setRemoveOpen(false)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void removeAgent()}>{busy ? "Removing…" : "Revoke and remove"}</Button></>}><p className="text-cell text-ink-tertiary">This first revokes the agent’s tunnel credential, then removes the roster record. Pending credential rotation is cancelled. Access-policy evidence is retained for review; recovery requires enrolling a new agent.</p></Modal>}
  </div>;
}
